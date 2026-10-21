"""Software READ prefix serializer; no P4, timing, or universal-conformance claim.

Input is one complete solicited application response, possibly in multiple link
frames, together with its READ request. Targets count aggregate DNP3 link octets,
not Ethernet bytes or guaranteed TCP packet sizes. Synthetic G1V2 padding points
have flags zero. The caller supplies a reserved index range; it must be reserved
in the deployment profile, not merely absent from one response.

This construction preserves native link-frame boundaries and original object
bytes. A prefix may itself span link frames. Existing transport sequence fields
are advanced, and affected CRCs are regenerated. Reachability is specific to
this serializer, not a proof that no other encoding could attain a size.
"""
from dataclasses import dataclass
import fullread
import dnp3_std as std


class UnsupportedRead(ValueError):
    pass


@dataclass(frozen=True)
class Result:
    status: str  # padded, already_at_target, unreachable
    output: bytes
    target: int | None
    native_bytes: int
    padding_points: int = 0
    first_index: int | None = None
    prefix_frames: int = 0
    reason: str = ''


def split_frames(stream):
    frames = []
    pos = 0
    while pos < len(stream):
        if len(stream) - pos < 10 or stream[pos:pos+2] != b'\x05\x64':
            raise UnsupportedRead('truncated or invalid link header')
        length = stream[pos+2] - 5
        if not 1 <= length <= 250:
            raise UnsupportedRead('invalid link user length')
        size = std.frame_length(length)
        if len(stream) - pos < size:
            raise UnsupportedRead('truncated link frame')
        f = stream[pos:pos+size]
        std.deframe(f)  # independently verify every block CRC, including tail
        frames.append(f)
        pos += size
    if not frames:
        raise UnsupportedRead('empty stream')
    return frames


def one_fragment(stream):
    frames = split_frames(stream)
    headers = [std.deframe(f)[0] for f in frames]
    if any(h[3:8] != headers[0][3:8] for h in headers):
        raise UnsupportedRead('inconsistent link control or addresses')
    fragments, events = std.reassemble(frames)
    if events or len(fragments) != 1:
        raise UnsupportedRead('requires exactly one complete transport-reassembled fragment')
    return frames, fragments[0][0]


def prefix_size(app_octets):
    return sum(std.frame_length(1 + min(249, app_octets-i))
               for i in range(0, app_octets, 249))


def pad_read(request, native, targets, *, pad_start, pad_stop, max_app_bytes=2048):
    """Select the smallest exactly reachable nonshrinking target.

    max_app_bytes is the caller's tested endpoint capacity, NOT a protocol-wide
    maximum. Multiple application fragments, unknown object encodings, and
    control responses are rejected explicitly. No target produces an explicit
    unreachable result with the unchanged input, never a successful padding claim.
    """
    if any(type(x) is not int for x in (pad_start, pad_stop, max_app_bytes)):
        raise ValueError('range and capacity must be integers')
    if not 0 <= pad_start <= pad_stop <= 65535 or max_app_bytes < 4:
        raise ValueError('invalid reserved index range or capacity')
    targets = list(targets)
    if not targets or any(type(t) is not int or t <= 0 for t in targets):
        raise ValueError('targets must be positive integer encoded lengths')
    qframes, q = one_fragment(request)
    frames, app = one_fragment(native)
    if len(q) < 2 or q[1] != 1 or q[0] & 0xc0 != 0xc0:
        raise UnsupportedRead('requires a complete READ request')
    pos = 2
    if len(q) == pos:
        raise UnsupportedRead('READ has no object headers')
    while pos < len(q):
        if len(q)-pos < 3:
            raise UnsupportedRead('truncated READ object header')
        g, v, qualifier = q[pos:pos+3]
        if qualifier not in (0, 1, 6):
            raise UnsupportedRead('READ request qualifier outside this profile')
        width = {0: 1, 1: 2, 6: 0}[qualifier]
        size = 3+2*width
        if len(q)-pos < size:
            raise UnsupportedRead('truncated READ range')
        if g == 60:
            if v not in (1, 2, 3, 4) or qualifier != 6:
                raise UnsupportedRead('invalid class READ header')
        elif (g, v) not in fullread.MEASUREMENT_SIZE and not (v == 0 and g in (1, 2, 10, 20, 22, 30, 32)):
            raise UnsupportedRead('READ group/variation outside this profile')
        if width and int.from_bytes(q[pos+3:pos+3+width], 'little') > int.from_bytes(q[pos+3+width:pos+size], 'little'):
            raise UnsupportedRead('reversed READ range')
        pos += size
    if len(app) < 4 or app[1] != 0x81 or app[0] & 0xc0 != 0xc0 or app[0] & 0x10:
        raise UnsupportedRead('requires a single solicited application response fragment')
    if q[0] & 15 != app[0] & 15:
        raise UnsupportedRead('application request/response sequence mismatch')
    qh = std.deframe(qframes[0])[0]; rh = std.deframe(frames[0])[0]
    if qh[4:6] != rh[6:8] or qh[6:8] != rh[4:6]:
        raise UnsupportedRead('request/response link addresses do not match')
    _, points = std.check_read_response(std.fragment_user(app))
    if any((g, v) not in fullread.MEASUREMENT_SIZE for g, v, _, _ in points):
        raise UnsupportedRead('non-measurement object in READ response')
    if len(app) > max_app_bytes:
        raise UnsupportedRead('native fragment exceeds configured endpoint capacity')
    if len(std.deframe(frames[0])[1]) < 5:
        raise UnsupportedRead('first transport segment must contain the application header')
    occupied = {idx for g, _, idx, _ in points if g in (1, 2)}
    if any(pad_start <= idx <= pad_stop for idx in occupied):
        raise UnsupportedRead('reserved padding range overlaps returned binary points')
    # One synthetic object block; q00 where the whole range fits, else q01.
    # Enumerate point counts bounded by endpoint capacity, not unbounded targets.
    plans = {}
    for n in range(4, min(pad_stop-pad_start+1, max_app_bytes-len(app)) + 1):
        last = pad_start+n-1
        width = 1 if last <= 255 else 2
        obj_len = 3 + 2*width + n
        if len(app) + obj_len > max_app_bytes:
            continue
        size = len(native) + prefix_size(obj_len)
        plans.setdefault(size, (n, width))
    for target in sorted(set(targets)):
        if target == len(native):
            return Result('already_at_target', native, target, len(native))
        if target not in plans:
            continue
        n, width = plans[target]
        obj = (bytes([1, 2, 0 if width == 1 else 1])
               + pad_start.to_bytes(width, 'little')
               + (pad_start+n-1).to_bytes(width, 'little') + bytes(n))
        prefix_app = app[:4] + obj[:-4]
        chunks = [prefix_app[i:i+249] for i in range(0, len(prefix_app), 249)]
        first_header, first_user = std.deframe(frames[0])
        seq = first_user[0] & 63
        out = []
        for i, chunk in enumerate(chunks):
            user = bytes([((seq+i)&63) | (std.FIR if i == 0 else 0)]) + chunk
            out.append(std.frame(first_header[:2]+bytes([5+len(user)])+first_header[3:], user))
        for i, f in enumerate(frames):
            h, u = std.deframe(f)
            th = (u[0] & std.FIN) | (((u[0]&63)+len(chunks))&63)
            body = obj[-4:] + u[5:] if i == 0 else u[1:]
            out.append(std.frame(h, bytes([th])+body))
        output = b''.join(out)
        # Independent reassembly is also a serializer invariant.
        _, encoded_app = one_fragment(output)
        if len(output) != target or encoded_app != app[:4]+obj+app[4:]:
            raise AssertionError('serializer failed exact-length/preservation invariant')
        return Result('padded', output, target, len(native), n, pad_start, len(chunks))
    return Result('unreachable', native, None, len(native), reason=
                  'no target attainable by this prefix encoding within reserved indices and endpoint capacity')

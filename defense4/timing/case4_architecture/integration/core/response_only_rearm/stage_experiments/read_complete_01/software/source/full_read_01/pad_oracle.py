"""Measurement-object padding for READ responses, and request expansion (Dr. Lin, 2026-10-19).

Construction (Case B, response padding): the response keeps every original link frame and object
octet. FIN is cleared on its last transport segment and ONE link frame is appended whose transport
segment (FIR=0, FIN=1, sequence + 1) continues the same application fragment with one added object
block: binary input with flags (g1v2, one octet per point, Table 12-2 response qualifier 00/01),
indices immediately after the outstation's configured binary inputs, flags 0x00 (ONLINE clear: the
point carries no valid value). The master reassembles one fragment (8.2.1 Rules 3-7) and receives
the original points unchanged plus the added points.

Construction (Case A, request expansion): the switch appends range headers for configured, existing
points to a READ request; the outstation returns those real measurements in its own response.

Sizes. A link frame with U user octets (transport octet included, U <= 250) occupies
10 + U + 2*ceil(U/16) octets (9.2.4.2). The padding frame carries U = 1 + header + n points, so the
added octets are 10 + U + 2*ceil(U/16) and only a padding of at least 19 octets is reachable.
"""
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import fullread  # noqa: E402,F401  (widens the oracle's object tables)
import dnp3_std as std  # noqa: E402

PAD_GROUP, PAD_VARIATION = 1, 2
PAD_FLAGS = 0x00
MAX_USER = 250


def frame_octets(user):
    return std.frame_length(user)


def padding_user(points, qualifier):
    """User octets of the padding frame: transport + object header + points."""
    return 1 + fullread.header_octets(qualifier) + points


def plan_padding(add):
    """Smallest (points, qualifier) whose padding frame adds exactly `add` octets, or None."""
    for qualifier in (0x00, 0x01):
        for points in range(1, MAX_USER):
            user = padding_user(points, qualifier)
            if user > MAX_USER:
                break
            if frame_octets(user) == add:
                return points, qualifier
    return None


def reachable(native, target):
    return target == native or plan_padding(target - native) is not None


def choose_target(native, targets):
    """Smallest target the native size can reach; None means the response stays native."""
    for t in sorted(targets):
        if t >= native and reachable(native, t):
            return t
    return None


def buckets(natives, targets):
    """target -> sorted native shapes it holds (k = len). A target holding one shape hides nothing."""
    out = {}
    for n in natives:
        t = choose_target(n, targets)
        if t is not None:
            out.setdefault(t, set()).add(n)
    return {t: sorted(v) for t, v in sorted(out.items())}


def select_targets(natives, t_max, min_gain=0.15):
    """Distribution rule: candidates {T/2, T} and {T/4, T/2, T}, each snapped down to a size every native
    below it can reach (a native size itself qualifies); keep three only if mean added octets drop by
    >= min_gain. An option is admissible only if some bucket merges two or more native shapes. Every option
    reports its buckets: a bucket with k = 1 leaves that shape identifiable by size."""
    def snap(t):
        for s in range(t, 0, -1):
            below = [n for n in natives if n <= s]
            if all(reachable(n, s) for n in below if n < s):
                return s
        return t

    def cost(targets):
        added = [choose_target(n, targets) - n for n in natives if choose_target(n, targets) is not None]
        inel = [n for n in natives if choose_target(n, targets) is None]
        return (sum(added) / len(added) if added else 0.0), inel

    two = [snap(t_max // 2), t_max]
    three = [snap(t_max // 4), snap(t_max // 2), t_max]
    c2, i2 = cost(two)
    c3, i3 = cost(three)
    merges = lambda ts: any(len(v) >= 2 for v in buckets(natives, ts).values())
    # An option in which every bucket holds one shape changes sizes but hides nothing; it is not admissible.
    pick = three if merges(three) and c3 <= c2 * (1 - min_gain) else two if merges(two) else [t_max]
    c1, i1 = cost([t_max])
    return {'one': [t_max], 'one_mean_added': c1, 'one_ineligible': i1, 'one_buckets': buckets(natives, [t_max]),
            'two': two, 'two_mean_added': c2, 'two_ineligible': i2, 'two_buckets': buckets(natives, two),
            'three': three, 'three_mean_added': c3, 'three_ineligible': i3, 'three_buckets': buckets(natives, three),
            'selected': pick}


def _split_frames(stream):
    out, p = [], 0
    while p < len(stream):
        n = std.frame_length(stream[p + 2] - 5)
        out.append(stream[p:p + n])
        p += n
    return out


def pad_response(stream, target, first_pad_index):
    """Pad one complete READ response (all its link frames, as one byte string) to `target` octets.
    Returns (padded bytes, info) or (stream, None) when not eligible/reachable."""
    frames = _split_frames(stream)
    frags, events = std.reassemble(frames)
    if len(frags) != 1 or events:
        return stream, None
    r = std.response(std.fragment_user(frags[0][0]))
    if r['function'] != 0x81:
        return stream, None
    plan = plan_padding(target - len(stream))
    if plan is None:
        return stream, None
    points, qualifier = plan
    header8, last_user = std.deframe(frames[-1])
    th = last_user[0]
    if not th & std.FIN:
        return stream, None
    new_last = std.frame(header8, bytes([th & ~std.FIN & 0xFF]) + last_user[1:])
    seq = ((th & 0x3F) + 1) & 0x3F
    first, last = first_pad_index, first_pad_index + points - 1
    if qualifier == 0x00:
        if last > 0xFF:
            return stream, None
        rng = bytes([first, last])
    else:
        rng = first.to_bytes(2, 'little') + last.to_bytes(2, 'little')
    user = bytes([std.FIN | seq, PAD_GROUP, PAD_VARIATION, qualifier]) + rng + bytes([PAD_FLAGS]) * points
    pad_header = bytes([0x05, 0x64, 5 + len(user)]) + header8[3:8]
    out = b''.join(frames[:-1]) + new_last + std.frame(pad_header, user)
    assert len(out) == target
    return out, {'points': points, 'qualifier': qualifier, 'first_index': first, 'last_index': last,
                 'added_octets': target - len(stream), 'padding_frame_octets': len(out) - len(stream)}


def expand_request(frame, extra_headers):
    """Append object headers (bytes) to a single-frame READ request. Returns the new frame."""
    header8, user = std.deframe(frame)
    th = user[0]
    if not (th & std.FIR and th & std.FIN) or user[2] != 0x01:
        raise std.StdError('not a single-segment READ request')
    new_user = user + b''.join(extra_headers)
    if len(new_user) - 1 > 249:
        raise std.StdError('expanded request exceeds one fragment of 249 octets (Clause 4 Rule 4)')
    return std.frame(bytes([0x05, 0x64, 5 + len(new_user)]) + header8[3:8], new_user)


def range_header(group, variation, first, last):
    if last <= 0xFF:
        return bytes([group, variation, 0x00, first, last])
    return bytes([group, variation, 0x01]) + first.to_bytes(2, 'little') + last.to_bytes(2, 'little')

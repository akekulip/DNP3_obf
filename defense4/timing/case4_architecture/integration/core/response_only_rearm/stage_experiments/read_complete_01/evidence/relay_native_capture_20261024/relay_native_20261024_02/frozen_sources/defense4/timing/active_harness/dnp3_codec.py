#!/usr/bin/env python3
"""DNP3-over-TCP codec with validation: CRCs, reassembly, and response checking.

What this adds over the frozen `implementation/harness/dnp3_wire.py`, which is kept
byte-identical because it is part of the record of what ran:

  * every per-block CRC is verified rather than skipped;
  * frames are reassembled across TCP reads, and bytes past the end of a frame are
    returned to the caller instead of being discarded;
  * a response is parsed with the two-octet IIN in its correct place, so the object
    header and the CROB status octet are read at the right offsets;
  * a response is validated against the request it is supposed to answer, so a stale or
    unrelated response cannot be accepted as a completion.

Frame layout, from the reference response embedded in the frozen `dnp3_wire.py`:

    05 64 LEN CTRL DST DST SRC SRC CRC CRC | [16 bytes user data + CRC CRC] ...

and the reassembled user data of a solicited response is

    transport | app_ctrl | 0x81 | IIN IIN | group var qual [count] [index] CROB(11) ...

Standard library only.
"""
from __future__ import annotations

from dataclasses import dataclass, field

START = b"\x05\x64"
LINK_HEADER = 10                 # start(2) + len + ctrl + dst(2) + src(2) + crc(2)
BLOCK = 16
FUNC_READ, FUNC_SELECT, FUNC_OPERATE, FUNC_RESPONSE = 0x01, 0x03, 0x04, 0x81
TRANSPORT_FIR, TRANSPORT_FIN, TRANSPORT_SEQ = 0x40, 0x80, 0x3F
G12_BINARY_OUTPUT_COMMAND, G12_VAR1, QUAL_COUNT_1BYTE_PREFIX = 0x0C, 0x01, 0x17
# The READ the harness issues is Group 10 Variation 2, binary output status. A response
# carrying anything else does not answer it, however well its sequence number matches.
G10_BINARY_OUTPUT_STATUS, G10_VAR2 = 0x0A, 0x02
CROB_LEN = 11
CROB_STATUS_OFFSET = 10          # within the 11-octet CROB
STATUS_SUCCESS = 0
STATUS_NAMES = {
    0: "SUCCESS", 1: "TIMEOUT", 2: "NO_SELECT", 3: "FORMAT_ERROR", 4: "NOT_SUPPORTED",
    5: "ALREADY_ACTIVE", 6: "HARDWARE_ERROR", 7: "LOCAL", 8: "TOO_MANY_OPS",
    9: "NOT_AUTHORIZED", 10: "AUTOMATION_INHIBIT", 11: "PROCESSING_LIMITED",
    12: "OUT_OF_RANGE",
}


class FrameError(ValueError):
    """The bytes are not a well-formed DNP3 link frame."""


def crc16(data: bytes) -> int:
    """DNP3 link-layer CRC-16. Same polynomial as the frozen implementation."""
    c = 0
    for b in data:
        c ^= b
        for _ in range(8):
            c = (c >> 1) ^ 0xA6BC if (c & 1) else (c >> 1)
    return (c ^ 0xFFFF) & 0xFFFF


def crc_le(data: bytes) -> bytes:
    x = crc16(data)
    return bytes([x & 0xFF, (x >> 8) & 0xFF])


def frame_total_length(link_len: int) -> int:
    """Total on-wire size of a frame whose LEN field is `link_len`."""
    user = link_len - 5
    if user < 0:
        raise FrameError("link LEN %d is below the 5-octet minimum" % link_len)
    blocks = (user + BLOCK - 1) // BLOCK if user else 0
    return LINK_HEADER + user + 2 * blocks


@dataclass
class Frame:
    """One validated link frame."""
    total: int
    control: int
    destination: int
    source: int
    user_data: bytes
    wire: bytes = b""


def parse_frame(buf: bytes, verify_crc: bool = True):
    """Parse one frame from the front of `buf`.

    Returns (Frame, rest) where `rest` is every byte after the frame, or (None, buf) when
    more bytes are needed. Raises FrameError on a CRC failure or a malformed header.
    """
    if len(buf) < 4:
        return None, buf
    if buf[:2] != START:
        raise FrameError("buffer does not start with 05 64")
    link_len = buf[2]
    total = frame_total_length(link_len)
    if len(buf) < total:
        return None, buf
    header = buf[:8]
    if verify_crc and buf[8:10] != crc_le(header):
        raise FrameError("link header CRC mismatch")
    user, i, left = bytearray(), LINK_HEADER, link_len - 5
    while left > 0:
        take = min(BLOCK, left)
        block = buf[i:i + take]
        if verify_crc and buf[i + take:i + take + 2] != crc_le(block):
            raise FrameError("user-data block CRC mismatch at offset %d" % i)
        user += block
        i += take + 2
        left -= take
    return (Frame(total=total, control=header[3],
                  destination=header[4] | (header[5] << 8),
                  source=header[6] | (header[7] << 8),
                  user_data=bytes(user), wire=buf[:total]),
            buf[total:])


class Reassembler:
    """Accumulates TCP bytes and yields complete frames, keeping the remainder.

    Bytes before the first start pattern are dropped and counted, so a mid-stream start
    does not wedge the parser; bytes after a complete frame are retained.
    """

    def __init__(self, verify_crc: bool = True):
        self.buffer = b""
        self.verify_crc = verify_crc
        self.dropped_leading = 0
        self.crc_failures = 0

    def feed(self, chunk: bytes) -> None:
        self.buffer += chunk

    def _align(self) -> bool:
        j = self.buffer.find(START)
        if j < 0:
            # keep at most one byte, which may be the first octet of a split start pattern
            self.dropped_leading += max(0, len(self.buffer) - 1)
            self.buffer = self.buffer[-1:] if self.buffer else b""
            return False
        if j:
            self.dropped_leading += j
            self.buffer = self.buffer[j:]
        return True

    def frames(self):
        """Yield every complete, CRC-valid frame currently buffered."""
        while True:
            if not self._align():
                return
            try:
                frame, rest = parse_frame(self.buffer, self.verify_crc)
            except FrameError:
                self.crc_failures += 1
                self.dropped_leading += 2
                self.buffer = self.buffer[2:]      # step past this start pattern and resync
                continue
            if frame is None:
                return
            self.buffer = rest
            yield frame

    @property
    def pending_bytes(self) -> int:
        return len(self.buffer)


class TransportError(Exception):
    """A DNP3 transport-layer reassembly error (FIR/FIN/sequence), distinct from link framing (FrameError)."""


class TransportAssembler:
    """Reassembles application fragments from link-frame user data (DNP3 transport layer).

    Each link frame's user data begins with a 1-byte transport header: FIR (0x40) on the first segment,
    FIN (0x80) on the last, and a 6-bit rolling sequence. The application data is everything after it.
    This is a DIFFERENT layer from TCP segmentation (which Reassembler handles) and from link framing:
    one application fragment may span several link frames, and a single link frame may carry a whole
    fragment (FIR and FIN both set). Call add() with each frame's user_data in arrival order; it returns
    the completed application fragment when FIN arrives, else None.
    """

    def __init__(self):
        self._parts = []
        self._expect_seq = None

    def reset(self):
        self._parts = []
        self._expect_seq = None

    @property
    def in_progress(self) -> bool:
        return bool(self._parts)

    def add(self, user_data: bytes):
        if not user_data:
            raise TransportError("empty link user data has no transport header")
        th = user_data[0]
        seq = th & TRANSPORT_SEQ
        fir, fin = bool(th & TRANSPORT_FIR), bool(th & TRANSPORT_FIN)
        if fir:
            if self._parts:
                self.reset()
                raise TransportError("new FIR before previous fragment FIN")
            self._expect_seq = seq
        elif not self._parts:
            raise TransportError("transport continuation (FIR clear) with no fragment in progress")
        elif seq != self._expect_seq:
            expected = self._expect_seq
            self.reset()
            raise TransportError("transport sequence %d, expected %d" % (seq, expected))
        self._parts.append(user_data[1:])
        self._expect_seq = (self._expect_seq + 1) & TRANSPORT_SEQ
        if fin:
            fragment = b"".join(self._parts)
            self.reset()
            return fragment
        return None


def reassemble_application(frames):
    """Convenience: list of link Frames (in arrival order) -> list of completed application fragments."""
    asm, fragments = TransportAssembler(), []
    for frame in frames:
        fragment = asm.add(frame.user_data)
        if fragment is not None:
            fragments.append(fragment)
    return fragments


# Supported physical-relay response contracts. Index ranges are inclusive on the wire.
READ_SCHEMAS = {
    "legacy": {(10, 2): range(23)},
    "mixed": {(1, 2): range(16), (30, 1): range(8)},
    "integrity": {(1, 2): range(16), (10, 2): range(32), (30, 4): range(21)},
}
OBJECT_SIZES = {(1, 2): 1, (10, 2): 1, (30, 1): 5, (30, 4): 2, (12, 1): 11}
# IIN1 indications (restart, local control, class data, time required, etc.) are not
# response errors. IIN2 bits 0..5 are function/object/parameter/overflow/execution/config errors.
IIN_ERROR_MASK = 0x3F00


@dataclass
class Response:
    """A complete parsed solicited application fragment, without a transport header."""
    app_seq: int
    function: int
    iin: int
    group: int | None = None
    variation: int | None = None
    qualifier: int | None = None
    count: int | None = None
    points: list = field(default_factory=list)      # (CROB index, status) compatibility view
    objects: list = field(default_factory=list)     # every object, raw point bytes and decoded fields
    problems: list = field(default_factory=list)


def parse_application_response(application: bytes) -> Response:
    """Decode every object in one completed DNP3 application fragment.

    Deliberately supports the relay's fixed measurement/CROB profile, failing closed on
    unknown sizes/qualifiers rather than guessing where a following object begins.
    """
    if len(application) < 4:
        return Response(-1, -1, -1, problems=["application data shorter than a response header"])
    ctrl, func = application[:2]
    r = Response(ctrl & 15, func, int.from_bytes(application[2:4], "little"))
    if ctrl & 0xF0 != 0xC0:
        r.problems.append("application header requires complete solicited FIR/FIN, no CON/UNS")
    if func != FUNC_RESPONSE:
        r.problems.append("function 0x%02x is not a solicited response" % func)
        return r
    p = 4
    while p < len(application):
        if len(application) - p < 3:
            r.problems.append("truncated object header at offset %d" % p)
            break
        group, variation, qualifier = application[p:p+3]
        p += 3
        if r.group is None:
            r.group, r.variation, r.qualifier = group, variation, qualifier
        size = OBJECT_SIZES.get((group, variation))
        if size is None:
            r.problems.append("unsupported object group %d variation %d" % (group, variation))
            break
        width = {0x00: 1, 0x01: 2, 0x17: 1, 0x28: 2}.get(qualifier)
        if width is None:
            r.problems.append("unsupported object qualifier 0x%02x" % qualifier)
            break
        prefixed = qualifier in (0x17, 0x28)
        header_size = width if prefixed else 2 * width
        if p + header_size > len(application):
            r.problems.append("object range/count truncated")
            break
        first = int.from_bytes(application[p:p+width], "little")
        p += width
        if prefixed:
            count, indices = first, None
        else:
            last = int.from_bytes(application[p:p+width], "little")
            p += width
            if last < first:
                r.problems.append("object range ends before it starts")
                break
            count, indices = last - first + 1, range(first, last + 1)
        if r.count is None:
            r.count = count
        obj = dict(group=group, variation=variation, qualifier=qualifier, count=count, points=[])
        r.objects.append(obj)
        if count == 0:
            r.problems.append("empty object block")
        for n in range(count):
            needed = size + (width if prefixed else 0)
            if p + needed > len(application):
                r.problems.append("object block truncated after %d of %d points" % (n, count))
                return r
            index = int.from_bytes(application[p:p+width], "little") if prefixed else indices[n]
            if prefixed:
                p += width
            raw = application[p:p+size]
            p += size
            point = dict(index=index, raw_hex=raw.hex())
            if group == 12:
                point.update(code=raw[0], count=raw[1], on_ms=int.from_bytes(raw[2:6], "little"),
                             off_ms=int.from_bytes(raw[6:10], "little"), status=raw[10])
                r.points.append((index, raw[10]))
            elif (group, variation) in ((1, 2), (10, 2)):
                point.update(flags=raw[0] & 0x7f, value=bool(raw[0] & 0x80))
            elif (group, variation) == (30, 1):
                point.update(flags=raw[0], value=int.from_bytes(raw[1:], "little", signed=True))
            else:
                point.update(value=int.from_bytes(raw, "little", signed=True))
            obj["points"].append(point)
    return r


def parse_response(user_data: bytes) -> Response:
    """Compatibility wrapper for one complete, transport-prefixed response.

    Segmented callers must reassemble first and use parse_application_response(). A FIR
    prefix alone is never accepted through this wrapper.
    """
    r = parse_application_response(user_data[1:])
    if not user_data or user_data[0] & 0xC0 != 0xC0:
        r.problems.append("transport fragment is incomplete; reassemble before parsing")
    return r


def read_workload_for_request(application: bytes) -> str:
    """Recognize the three explicit READ request contracts; reject ambiguous requests."""
    objects = application[2:]
    if objects == bytes([1,2,0,0,15,30,1,0,0,7]):
        return "mixed"
    if objects == bytes([60,2,6,60,3,6,60,4,6,60,1,6]):
        return "integrity"
    if objects == bytes([10,2,0,0,22]):
        return "legacy"
    raise ValueError("READ request is outside the legacy/mixed/integrity contracts")


def validate_response(resp: Response, *, expect_seq: int, expect_function: int,
                      expect_points=None, require_success: bool = False,
                      expect_read_groups=None, expect_read_workload=None) -> list:
    """Validate a complete fragment against the entire requested response contract."""
    problems = list(resp.problems)
    if resp.function != FUNC_RESPONSE:
        problems.append("function 0x%02x, expected 0x81" % resp.function)
    if resp.app_seq != (expect_seq & 15):
        problems.append("application sequence %d, expected %d" % (resp.app_seq, expect_seq & 15))
    if resp.iin >= 0 and resp.iin & IIN_ERROR_MASK:
        problems.append("IIN response error bits 0x%04x" % (resp.iin & IIN_ERROR_MASK))
    if expect_function == FUNC_READ:
        workload = expect_read_workload
        if workload is None:
            groups = set(expect_read_groups) if expect_read_groups is not None else {(10, 2)}
            workload = next((name for name, schema in READ_SCHEMAS.items() if set(schema) == groups), None)
        if workload not in READ_SCHEMAS:
            problems.append("unknown READ workload/schema")
            return problems
        schema = READ_SCHEMAS[workload]
        actual, padding = {}, []
        for obj in resp.objects:
            key = (obj["group"], obj["variation"])
            for point in obj["points"]:
                index = point["index"]
                if key == (1, 2) and index >= 1024:
                    padding.append(index)
                    if point["raw_hex"] != "00":
                        problems.append("padding point %d flags/value are not zero" % index)
                else:
                    indices = actual.setdefault(key, [])
                    if index in indices:
                        problems.append("duplicate object point %r index %d" % (key, index))
                    indices.append(index)
        if set(actual) != set(schema):
            problems.append("object group/variation set %r, expected %r" % (sorted(actual), sorted(schema)))
        for key, indices in schema.items():
            if sorted(actual.get(key, [])) != list(indices):
                problems.append("object group %d variation %d indices %r, expected %r" %
                                (key[0], key[1], actual.get(key, []), list(indices)))
        if padding:
            count = {"mixed": 26, "integrity": 4}.get(workload, 0)
            if padding != list(range(1024, 1024+count)):
                problems.append("padding indices %r do not match selected %s contract" % (padding, workload))
    elif expect_function in (FUNC_SELECT, FUNC_OPERATE):
        if resp.group != 12:
            problems.append("object group %r, expected 12" % resp.group)
        if resp.variation != 1:
            problems.append("variation %r, expected 1" % resp.variation)
        if resp.qualifier != 0x17:
            problems.append("qualifier %r, expected 0x17" % resp.qualifier)
        if len(resp.objects) != 1:
            problems.append("control response requires exactly one CROB object block")
        if expect_points is not None and [i for i, _ in resp.points] != list(expect_points):
            problems.append("points %r, expected %r" % ([i for i, _ in resp.points], list(expect_points)))
        for obj in resp.objects:
            if (obj["group"], obj["variation"]) != (12, 1):
                problems.append("unexpected object in control response")
                continue
            for point in obj["points"]:
                if (point["code"], point["count"], point["on_ms"], point["off_ms"]) != (1,1,200,0):
                    problems.append("point %d CROB parameters differ from guarded request" % point["index"])
                if require_success and point["status"] != STATUS_SUCCESS:
                    problems.append("point %d status %s" % (point["index"], STATUS_NAMES.get(point["status"], point["status"])))
    else:
        problems.append("unsupported request function 0x%02x" % expect_function)
    return problems

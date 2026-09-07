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
G12_BINARY_OUTPUT_COMMAND, G12_VAR1, QUAL_COUNT_1BYTE_PREFIX = 0x0C, 0x01, 0x17
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
                  user_data=bytes(user)),
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


@dataclass
class Response:
    """A parsed solicited application response."""
    app_seq: int
    function: int
    iin: int
    group: int | None = None
    variation: int | None = None
    qualifier: int | None = None
    count: int | None = None
    points: list = field(default_factory=list)      # (index, status) pairs
    problems: list = field(default_factory=list)


def parse_response(user_data: bytes) -> Response:
    """Parse the user data of a response, with the IIN in its correct position."""
    if len(user_data) < 5:
        return Response(app_seq=-1, function=-1, iin=-1,
                        problems=["user data shorter than an application header"])
    app_seq = user_data[1] & 0x0F
    func = user_data[2]
    iin = user_data[3] | (user_data[4] << 8)
    r = Response(app_seq=app_seq, function=func, iin=iin)
    if func != FUNC_RESPONSE:
        r.problems.append("function 0x%02x is not a solicited response" % func)
        return r
    obj = user_data[5:]                              # the object header starts after the IIN
    if len(obj) < 3:
        return r                                     # a response with no object block
    r.group, r.variation, r.qualifier = obj[0], obj[1], obj[2]
    if r.qualifier != QUAL_COUNT_1BYTE_PREFIX:
        return r
    if len(obj) < 4:
        r.problems.append("qualifier 0x17 with no count octet")
        return r
    r.count = obj[3]
    p = 4
    for _ in range(r.count):
        if p + 1 + CROB_LEN > len(obj):
            r.problems.append("object block truncated after %d of %d points"
                              % (len(r.points), r.count))
            break
        index = obj[p]
        status = obj[p + 1 + CROB_STATUS_OFFSET]
        r.points.append((index, status))
        p += 1 + CROB_LEN
    return r


def validate_response(resp: Response, *, expect_seq: int, expect_function: int,
                      expect_points=None, require_success: bool = False) -> list:
    """Return the list of reasons this response does not answer that request. Empty means valid.

    `expect_function` is the *request* function; a solicited response answers it with 0x81, so
    only the sequence number and the object content tie the two together.
    """
    problems = list(resp.problems)
    if resp.function != FUNC_RESPONSE:
        problems.append("function 0x%02x, expected 0x81" % resp.function)
    if resp.app_seq != (expect_seq & 0x0F):
        problems.append("application sequence %d, expected %d"
                        % (resp.app_seq, expect_seq & 0x0F))
    if expect_function in (FUNC_SELECT, FUNC_OPERATE):
        if resp.group != G12_BINARY_OUTPUT_COMMAND:
            problems.append("object group %r, expected 12" % resp.group)
        if resp.variation != G12_VAR1:
            problems.append("variation %r, expected 1" % resp.variation)
        if resp.qualifier != QUAL_COUNT_1BYTE_PREFIX:
            problems.append("qualifier %r, expected 0x17" % resp.qualifier)
        if expect_points is not None:
            got = [i for i, _ in resp.points]
            if got != list(expect_points):
                problems.append("points %r, expected %r" % (got, list(expect_points)))
        if require_success:
            for index, status in resp.points:
                if status != STATUS_SUCCESS:
                    problems.append("point %d status %s"
                                    % (index, STATUS_NAMES.get(status, status)))
    return problems

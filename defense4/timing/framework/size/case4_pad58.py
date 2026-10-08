"""Strict software wire model for Case 4's Option B (uniform 58-byte) pattern.

`SELECTED_PATTERN.md`'s 2026-10-08 update makes Option B -- a single uniform
58-byte TCP-payload pad on READ, SELECT and OPERATE responses, no splitting --
the active size pattern. Option A's carve/qualifier-rewrite construction
(`case4_padding.py`, `case4_qualifier_rewrite.py`) is retained unmodified as
the superseded candidate's reference; this is a new sibling codec, not an
edit to either.

Byte arithmetic (TCP payload = 10 + user + 2*ceil(user/16),
`HARDWARE_FEASIBILITY_ANALYSIS.md` SS1.2):

- READ response: native user 33 bytes (49 TCP payload) -> target user 42
  bytes (58 TCP payload). Both land in the same 3-block bracket (33-48
  bytes -> 3 CRC blocks), so the add is a flat +9 user bytes with no extra
  CRC block crossed.
- SELECT/OPERATE response: native user 23 bytes (37 TCP payload) -> target
  user 42 bytes (58 TCP payload). This crosses from the 2-block bracket
  (17-32) into the 3-block bracket (33-48), so the add is +19 user bytes,
  not the +18 of `case4_padding`'s existing separate-header CROB
  construction (which lands at user 41 / TCP 57, one byte short of 58).

Both targets land on the same final 42-byte user payload because both reach
the same 58-byte TCP-payload target in the same 3-block bracket. The filler
that supplies the +9 and +19 bytes is one G41V2 (16-bit Analog Output Block)
object under qualifier 0x27 (prefix code 2 = 2-byte index, range code 7 =
1-byte count -- a real IEEE 1815 qualifier combination, just a less common
one than 0x28's 2-byte count): a 4-byte header (group, variation, qualifier,
1-byte count) plus `count` points of 5 bytes each (2-byte index, 2-byte
value, 1-byte status). One point is exactly 9 bytes (4 + 5); three points
are exactly 19 bytes (4 + 15) -- the two counts this module uses for READ
and for SELECT/OPERATE respectively, and nothing else. No G12V1 CROB
encoding (0x17/0x18/0x27/0x28, any count) lands on either 9 or 19 alone;
this is why the filler is a different object type, not a variant of the
existing CROB decoy.

An inert filler point is an externally verified profile prerequisite, not a
property this byte codec can infer from an index or a value.
"""
from dataclasses import dataclass
import struct
from case4_padding import build_frame, decode_frame

GROUP41_VAR2_QUAL27 = bytes([0x29, 0x02, 0x27])
HEADER_READ23 = bytes.fromhex('0a02000016')   # G10V2, qualifier 0x00, range 0..22 (23 points)
HEADER_CROB28 = bytes.fromhex('0c01280100')   # G12V1, qualifier 0x28, count 1 -- shared with case4_padding

READ_FILLER_POINTS = 1
CONTROL_FILLER_POINTS = 3

READ_NATIVE_LEN = 33
CONTROL_NATIVE_LEN = 23
PADDED_LEN = 42


@dataclass(frozen=True)
class AnalogPoint:
    index: int
    value: int
    status: int

    def __post_init__(self):
        if not 0 <= self.index <= 0xffff:
            raise ValueError('G41V2 qualifier 0x27 index prefix is a uint16')
        if not 0 <= self.value <= 0xffff:
            raise ValueError('G41V2 variation 2 analog value is a uint16')
        if not 0 <= self.status <= 0xff:
            raise ValueError('G41V2 status/flags is one byte')

    @property
    def packed(self):
        return struct.pack('<HHB', self.index, self.value, self.status)


def _analog_object(points):
    """Build one G41V2/qualifier-0x27 object: 4-byte header + count*5 bytes."""
    if not 1 <= len(points) <= 0xff:
        raise ValueError('G41V2 qualifier 0x27 count field is one unsigned byte, at least 1 point')
    for p in points:
        if not isinstance(p, AnalogPoint):
            raise ValueError('filler must be a sequence of AnalogPoint')
    return GROUP41_VAR2_QUAL27 + bytes([len(points)]) + b''.join(p.packed for p in points)


def pad_read_response(frame, points):
    """Return (image, delta); unsupported input passes unchanged.

    Eligible only for the one supported READ profile this effort covers: a
    complete, CRC-valid frame holding a 23-point G10V2 response (qualifier
    0x00, range 0..22), one transport/application fragment, response
    function code 0x81. `points` must be exactly one AnalogPoint -- the only
    count that lands the native 33-byte user payload on the shared 58-byte
    TCP-payload target -- so a different count is a caller contract
    violation, not an ineligible frame, and raises rather than silently
    refusing. The native object bytes are never reconstructed; only the
    filler is appended.
    """
    if len(points) != READ_FILLER_POINTS:
        raise ValueError('READ filler must carry exactly one analog point to reach 58 bytes')
    try:
        head, user = decode_frame(frame)
    except ValueError:
        return frame, 0
    if (len(user) != READ_NATIVE_LEN or user[0] & 0xc0 != 0xc0 or
            user[1] & 0xf0 != 0xc0 or user[2] != 0x81 or
            user[5:10] != HEADER_READ23):
        return frame, 0
    image = build_frame(head, user + _analog_object(points))
    return image, len(image) - len(frame)


def unpad_read_response(image):
    """Pure structural inverse of pad_read_response.

    Raises ValueError on any image that is not itself a READ/qualifier-0x27
    one-point padded construction, instead of silently returning a guess.
    """
    head, user = decode_frame(image)
    if (len(user) != PADDED_LEN or user[0] & 0xc0 != 0xc0 or
            user[1] & 0xf0 != 0xc0 or user[2] != 0x81 or
            user[5:10] != HEADER_READ23 or
            user[READ_NATIVE_LEN:READ_NATIVE_LEN + 4] != GROUP41_VAR2_QUAL27 + bytes([READ_FILLER_POINTS])):
        raise ValueError('not a case4_pad58 READ image')
    return build_frame(head, user[:READ_NATIVE_LEN])


def pad_control_response(frame, points):
    """Return (image, delta); unsupported input passes unchanged.

    Eligible for a complete, CRC-valid native SELECT/OPERATE echo: response
    function code 0x81 and the single native G12V1 CROB echo at qualifier
    0x28, count 1 (`case4_padding`'s own control-response shape; function
    code, SELECT vs OPERATE, is not recoverable from the response alone and
    is not required -- both echo the same shape). `points` must be exactly
    three AnalogPoints: the existing separate-header 18-byte CROB
    construction lands the native 23-byte response at user 41 / TCP 57, one
    byte short of 58 (`SELECTED_PATTERN.md`'s 2026-10-08 update); three
    G41V2 qualifier-0x27 points add the needed 19 bytes instead. A different
    count is a caller contract violation, not an ineligible frame.
    """
    if len(points) != CONTROL_FILLER_POINTS:
        raise ValueError('control filler must carry exactly three analog points to reach 58 bytes')
    try:
        head, user = decode_frame(frame)
    except ValueError:
        return frame, 0
    if (len(user) != CONTROL_NATIVE_LEN or user[0] & 0xc0 != 0xc0 or
            user[1] & 0xf0 != 0xc0 or user[2] != 0x81 or
            user[5:10] != HEADER_CROB28 or user[-1] != 0):
        return frame, 0
    image = build_frame(head, user + _analog_object(points))
    return image, len(image) - len(frame)


def unpad_control_response(image):
    """Pure structural inverse of pad_control_response.

    Raises ValueError on any image that is not itself a control/qualifier-
    0x27 three-point padded construction, instead of silently returning a
    guess.
    """
    head, user = decode_frame(image)
    if (len(user) != PADDED_LEN or user[0] & 0xc0 != 0xc0 or
            user[1] & 0xf0 != 0xc0 or user[2] != 0x81 or
            user[5:10] != HEADER_CROB28 or user[22] != 0 or
            user[CONTROL_NATIVE_LEN:CONTROL_NATIVE_LEN + 4] != GROUP41_VAR2_QUAL27 + bytes([CONTROL_FILLER_POINTS])):
        raise ValueError('not a case4_pad58 control image')
    return build_frame(head, user[:CONTROL_NATIVE_LEN])

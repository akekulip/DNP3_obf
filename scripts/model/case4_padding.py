"""Strict software wire model for Case 4. No endpoint/hardware acceptance claim.

An inert point is an externally verified profile prerequisite, not a property
that this byte codec can infer from a control code or an index.
"""
from dataclasses import dataclass
import struct
import rrc


@dataclass(frozen=True)
class Decoy:
    index: int
    body: bytes

    def __post_init__(self):
        if not 0 <= self.index <= 0xffff or len(self.body) != 11 or self.body[-1] != 0:
            raise ValueError('decoy requires a uint16 index and 11-byte request CROB with zero status')


def build_frame(header, user):
    """Recompute length and all link CRCs, preserving addresses/control."""
    if len(header) != 8 or not 0 <= len(user) <= 250:
        raise ValueError('one bounded DNP3 link frame required')
    h = bytearray(header)
    h[2] = len(user) + 5
    out = bytes(h) + struct.pack('<H', rrc.dnp3_crc(h))
    for i in range(0, len(user), 16):
        block = user[i:i + 16]
        out += block + struct.pack('<H', rrc.dnp3_crc(block))
    return out


def decode_frame(frame):
    if not rrc.dnp3_frame_ok(frame) or frame[2] < 5:
        raise ValueError('invalid complete DNP3 frame')
    size = frame[2] - 5
    user, i = bytearray(), 10
    while size:
        n = min(16, size)
        user += frame[i:i + n]
        i += n + 2
        size -= n
    return frame[:8], bytes(user)


def expand_control(frame, decoy):
    """Return (image, delta); unsupported input passes unchanged.

    Only one complete transport/application fragment, SELECT/OPERATE, one
    G12V1 object with uint16 count/index qualifier 0x28 is eligible. The
    original object is never reconstructed from its index or default values.
    A separate header preserves the native object's exact bytes.
    """
    try:
        head, user = decode_frame(frame)
    except ValueError:
        return frame, 0
    if (len(user) != 21 or user[0] & 0xc0 != 0xc0 or
            user[1] & 0xf0 != 0xc0 or user[2] not in (3, 4) or
            user[3:8] != bytes.fromhex('0c01280100') or user[-1] != 0):
        return frame, 0
    if int.from_bytes(user[8:10], 'little') == decoy.index:
        return frame, 0
    trailing = bytes.fromhex('0c01280100') + struct.pack('<H', decoy.index) + decoy.body
    image = build_frame(head, user + trailing)
    return image, len(image) - len(frame)

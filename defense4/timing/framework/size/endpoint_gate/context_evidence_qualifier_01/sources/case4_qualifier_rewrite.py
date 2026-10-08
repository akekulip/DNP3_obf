"""Strict software wire model for Case 4's qualifier-rewrite construction.

`case4_padding.expand_control` reaches a common response size by appending a
separate G12V1 header object; the smallest it can reach is 52-57 TCP-payload
bytes, never exactly 49 (`HARDWARE_FEASIBILITY_ANALYSIS.md` SS1.3). This sibling
codec instead rewrites the native single-CROB object's own header in place
(qualifier 0x28 -> 0x17, count 1 -> 2) and appends one 12-byte (1-byte index +
CROB11) decoy object, landing the request at exactly 45 bytes -> a 49-byte
response, matching READ's native response and the proven RRC [28,21] carve
(`SELECTED_PATTERN.md`). The index-prefix narrowing (2 bytes under 0x28, 1
byte under 0x17) is lossless only while the point index is below 256; any
wider index is refused and passed through unchanged, never truncated.

An inert decoy point is an externally verified profile prerequisite, not a
property this byte codec can infer from a control code or an index.
"""
import struct
from case4_padding import Decoy, build_frame, decode_frame

HEADER28 = bytes.fromhex('0c01280100')
HEADER17 = bytes.fromhex('0c011702')


def rewrite_qualifier(frame, decoy):
    """Return (image, delta); unsupported input passes unchanged.

    Only one complete transport/application fragment, SELECT/OPERATE, one
    G12V1 object with uint16 count/index qualifier 0x28 is eligible, and
    only while both its index and the decoy's index are below 256 (qualifier
    0x17's index prefix is one byte each; a wider index cannot be
    represented losslessly and is refused rather than truncated). The
    native object's own bytes (control code, count, on/off-time, status)
    are carried through exactly; only the shared header (qualifier, count)
    and the index width change, and the original object is never
    reconstructed from its index or default values.
    """
    try:
        head, user = decode_frame(frame)
    except ValueError:
        return frame, 0
    if (len(user) != 21 or user[0] & 0xc0 != 0xc0 or
            user[1] & 0xf0 != 0xc0 or user[2] not in (3, 4) or
            user[3:8] != HEADER28 or user[-1] != 0):
        return frame, 0
    index = int.from_bytes(user[8:10], 'little')
    if index > 0xff or decoy.index > 0xff or index == decoy.index:
        return frame, 0
    crob = user[10:21]
    rewritten = (user[:3] + HEADER17 + bytes([index]) + crob +
                 bytes([decoy.index]) + decoy.body)
    image = build_frame(head, rewritten)
    return image, len(image) - len(frame)


def collapse_qualifier(image):
    """Recover the exact native single-CROB frame a rewritten image came from.

    Pure structural inverse of rewrite_qualifier: it extracts the first
    object's exact bytes and reassembles the original 2-byte-index header
    around them rather than reconstructing anything from an index or
    defaults. Raises ValueError on any image that is not itself a
    qualifier-0x17/count-2 construction with a sub-256 first index, instead
    of silently returning a guess.
    """
    head, user = decode_frame(image)
    if (len(user) != 31 or user[0] & 0xc0 != 0xc0 or
            user[1] & 0xf0 != 0xc0 or user[2] not in (3, 4) or
            user[3:7] != HEADER17 or user[18] != 0 or user[-1] != 0):
        raise ValueError('not a qualifier-rewrite image')
    index, crob = user[7], user[8:19]
    native = user[:3] + HEADER28 + struct.pack('<H', index) + crob
    return build_frame(head, native)

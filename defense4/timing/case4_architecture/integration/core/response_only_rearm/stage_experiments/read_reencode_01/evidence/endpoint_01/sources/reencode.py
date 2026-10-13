"""Software reference for the READ re-encoding: the same G10V2 points 0-22, two start/stop ranges.

Native user data:     H | 0a 02 00 00 16 | P0..P22                          (33 octets, 49-octet frame)
Re-encoded user data: H | 0a 02 01 00 00 03 00 | P0..P3
                        | 0a 02 01 04 00 16 00 | P4..P22                    (42 octets, 58-octet frame)

H (transport, app control, function, IIN) and every status octet are unchanged. Only the range
representation changes: qualifier 0x01 (2-octet start/stop) is legal in a G10V2 response
(4.2.2.7.3.3-.5, pp.33-35; Tables 12-6 and 14-2). The 0-3 split puts H, the first header and
P0-P3 exactly in the first 16-octet user block.

Any other shape returns None: it stays native. This module is the oracle for the P4 transform.
"""
import struct

import dnp3_std as std

NATIVE_HEADER = bytes([0x0a, 0x02, 0x00, 0x00, 0x16])
HEADER_A = bytes([0x0a, 0x02, 0x01, 0x00, 0x00, 0x03, 0x00])
HEADER_B = bytes([0x0a, 0x02, 0x01, 0x04, 0x00, 0x16, 0x00])
SPLIT = 4          # points 0..3 in the first range
POINTS = 23


def eligible(user):
    """True only for the one profile this transform supports: a single-fragment READ response
    (FIR|FIN in the transport and application headers) carrying exactly G10V2 points 0-22."""
    if len(user) != 5 + len(NATIVE_HEADER) + POINTS:
        return False
    if user[0] & 0xC0 != 0xC0 or user[1] & 0xC0 != 0xC0 or user[2] != 0x81:
        return False
    return user[5:10] == NATIVE_HEADER


def reencode_user(user):
    if not eligible(user):
        return None
    h, p = user[:5], user[10:]
    return h + HEADER_A + p[:SPLIT] + HEADER_B + p[SPLIT:]


def reencode_frame(data):
    """Native link frame in, 58-octet re-encoded frame out (or None when not eligible)."""
    header8, user = std.deframe(data)
    new = reencode_user(user)
    if new is None:
        return None
    return std.frame(header8[:2] + bytes([5 + len(new)]) + header8[3:], new)


def semantically_equal(native, encoded):
    """Both frames decode under the response rules to the identical ordered point list, with the
    link header (other than LEN), H, and the function unchanged."""
    nh, nu = std.deframe(native)
    eh, eu = std.deframe(encoded)
    if nh[:2] + nh[3:] != eh[:2] + eh[3:] or nu[:5] != eu[:5]:
        return False
    _, npts = std.check_read_response(nu)
    std.check_read_response(eu, expect=npts)
    return [i for _, _, i, _ in npts] == list(range(POINTS))


if __name__ == '__main__':
    import sys
    for h in sys.argv[1:]:
        out = reencode_frame(bytes.fromhex(h))
        print(out.hex() if out else 'not eligible', len(out) if out else '')

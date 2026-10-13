"""Independent IEEE 1815-2012 checker for the 58-byte response profile.

Shares no code with framework/size (rrc.py, case4_padding.py) or the P4 sources, so it can serve
as an oracle for both. Printed page numbers refer to IEEE Std 1815-2012 (PDF page = printed + 42).

Scope is deliberately narrow: the object groups and qualifiers this profile emits or receives.
Anything outside that scope raises StdError instead of being skipped, so a frame is accepted
only when every object byte is consumed by a legal header.
"""
import struct


class StdError(ValueError):
    """The bytes violate a rule this checker enforces (or fall outside its declared scope)."""


def crc(data):
    """DNP3 link CRC (Annex E, pp.773-775): polynomial 0x3D65, reflected 0xA6BC, init 0, complemented."""
    c = 0
    for b in data:
        c ^= b
        for _ in range(8):
            c = (c >> 1) ^ 0xA6BC if c & 1 else c >> 1
    return (~c) & 0xFFFF


def frame(header8, user):
    """Build a link frame: header CRC, then a CRC after each <=16-byte user block (9.2.4.1.2, p.277)."""
    assert len(header8) == 8 and header8[2] == 5 + len(user)
    out = header8 + struct.pack('<H', crc(header8))
    for i in range(0, len(user), 16):
        blk = user[i:i + 16]
        out += blk + struct.pack('<H', crc(blk))
    return out


def deframe(data):
    """Return (header8, user) after checking start octets, LEN and every CRC. LEN counts the five
    non-CRC header octets after LEN plus the user octets (9.2.4.3, pp.280-281)."""
    if len(data) < 10 or data[:2] != b'\x05\x64':
        raise StdError('no link start octets')
    length = data[2]
    if length < 5:
        raise StdError('LEN %d < 5' % length)
    if crc(data[:8]) != struct.unpack('<H', data[8:10])[0]:
        raise StdError('header CRC')
    n, p, user = length - 5, 10, b''
    while n:
        k = min(16, n)
        blk = data[p:p + k]
        if len(blk) != k or crc(blk) != struct.unpack('<H', data[p + k:p + k + 2] or b'\0\0')[0]:
            raise StdError('user block CRC at %d' % p)
        user, p, n = user + blk, p + k + 2, n - k
    if p != len(data):
        raise StdError('%d trailing octets after LEN' % (len(data) - p))
    return data[:8], user


def frame_length(user_len):
    """Complete link-frame octets for a given number of user octets."""
    return 10 + user_len + 2 * (-(-user_len // 16))


# Fixed object sizes in octets, for the groups this profile touches.
# G12V1 CROB (A.8); G41 analog output block (A.20, pp.615-619): V1 INT32+status, V2 INT16+status,
# V3 FLT32+status, V4 FLT64+status; G10V2 binary output status with flags, one octet (A.6).
OBJECT_SIZE = {(10, 2): 1, (12, 1): 11, (41, 1): 5, (41, 2): 3, (41, 3): 5, (41, 4): 9}

# Qualifiers permitted in a RESPONSE, per object. G10V2: 00/01 only (Table 12-6, p.354; Table 14-2, p.398;
# Table 4-8, p.35 "static objects"). G12V1 and G41 responses echo the request (Table 12-8, p.354), whose
# qualifiers are 17/28. 0x06 (all objects) is "Not permitted in a response" (Table 4-8, p.35).
RESPONSE_QUALIFIERS = {(10, 2): {0x00, 0x01}, (12, 1): {0x17, 0x28}, (41, 1): {0x17, 0x28},
                       (41, 2): {0x17, 0x28}, (41, 3): {0x17, 0x28}, (41, 4): {0x17, 0x28}}
REQUEST_QUALIFIERS = {0x00, 0x01, 0x06, 0x17, 0x28}


def _range(q, b, p):
    """Parse a range field; return (points, prefix_octets, new_p). points is a list of indexes when
    known from the range, or a count for index-prefixed qualifiers."""
    if q == 0x00 or q == 0x01:
        w = 1 if q == 0x00 else 2
        if p + 2 * w > len(b):
            raise StdError('truncated start/stop')
        fmt = '<B' if w == 1 else '<H'
        start, stop = struct.unpack(fmt, b[p:p + w])[0], struct.unpack(fmt, b[p + w:p + 2 * w])[0]
        if stop < start:
            raise StdError('stop %d < start %d' % (stop, start))
        return list(range(start, stop + 1)), 0, p + 2 * w
    if q == 0x17 or q == 0x28:
        w = 1 if q == 0x17 else 2
        if p + w > len(b):
            raise StdError('truncated count')
        count = b[p] if w == 1 else struct.unpack('<H', b[p:p + 2])[0]
        if count == 0:
            raise StdError('zero count')
        return count, w, p + w
    if q == 0x06:
        return [], 0, p
    raise StdError('qualifier 0x%02x outside scope' % q)


def parse_objects(b, response):
    """Parse every object header in b. Returns a list of (group, var, qualifier, [(index, bytes)]).
    Raises StdError unless every octet is consumed by a legal header and its complete objects."""
    out, p = [], 0
    while p < len(b):
        if p + 3 > len(b):
            raise StdError('truncated object header at %d' % p)
        g, v, q = b[p], b[p + 1], b[p + 2]
        allowed = RESPONSE_QUALIFIERS.get((g, v), set()) if response else REQUEST_QUALIFIERS
        if q not in allowed:
            raise StdError('qualifier 0x%02x not permitted in a %s (Table 4-8)'
                           % (q, 'response' if response else 'request'))
        points, prefix, p = _range(q, b, p + 3)
        if q == 0x06:
            out.append((g, v, q, []))
            continue
        size = OBJECT_SIZE.get((g, v))
        if size is None:
            raise StdError('object g%dv%d outside scope' % (g, v))
        objs = []
        if prefix:
            for _ in range(points):
                if p + prefix + size > len(b):
                    raise StdError('truncated prefixed object')
                idx = b[p] if prefix == 1 else struct.unpack('<H', b[p:p + 2])[0]
                objs.append((idx, b[p + prefix:p + prefix + size]))
                p += prefix + size
        else:
            if p + size * len(points) > len(b):
                raise StdError('range of %d objects overruns the fragment' % len(points))
            for idx in points:
                objs.append((idx, b[p:p + size]))
                p += size
        out.append((g, v, q, objs))
    return out


def response(user):
    """Split response user data: transport, app control, function, IIN (2 octets), object bytes."""
    if len(user) < 5:
        raise StdError('response shorter than its header')
    th, ac, fc = user[0], user[1], user[2]
    if fc not in (0x81, 0x82, 0x83):
        raise StdError('function 0x%02x is not a response' % fc)
    return {'transport': th, 'app_ctrl': ac, 'function': fc, 'iin': user[3:5], 'objects': user[5:]}


def request(user):
    """Split request user data: transport, app control, function, object bytes."""
    if len(user) < 3:
        raise StdError('request shorter than its header')
    return {'transport': user[0], 'app_ctrl': user[1], 'function': user[2], 'objects': user[3:]}


def points(objs):
    """Ordered (group, var, index, object bytes) for every object, across all headers."""
    return [(g, v, i, d) for g, v, _q, lst in objs for i, d in lst]


def check_read_response(user, expect=None):
    """Accept a READ response only if every header is legal and every octet is consumed, indexes
    are unique, and (when expect is given) the ordered point list equals it exactly."""
    r = response(user)
    if r['function'] != 0x81:
        raise StdError('READ response function 0x%02x' % r['function'])
    pts = points(parse_objects(r['objects'], response=True))
    idx = [(g, v, i) for g, v, i, _ in pts]
    if len(set(idx)) != len(idx):
        raise StdError('duplicated point')
    if expect is not None and pts != expect:
        raise StdError('point list differs from the native response')
    return r, pts


def check_control_echo(req_user, rsp_user):
    """Rule 8 of 4.4.4.3 (p.51): the response object octets after IIN equal the request object
    octets after the function code. Raises StdError on any difference, including a longer echo."""
    q, r = request(req_user), response(rsp_user)
    if r['objects'] != q['objects']:
        raise StdError('control echo differs: request %d octets, response %d octets'
                       % (len(q['objects']), len(r['objects'])))
    return True

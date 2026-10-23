"""RTT per echo from one capture on Vision's NIC: request (transmit tap) -> reply (receive tap), software timestamps."""
import struct
import sys


def records(path):
    b = open(path, 'rb').read()
    nano = b[:4] in (b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d')
    off, out = 24, []
    while off + 16 <= len(b):
        sec, frac, incl, _ = struct.unpack('<IIII', b[off:off + 16])
        frame = b[off + 16:off + 16 + incl]
        off += 16 + incl
        if len(frame) < 42 or frame[12:14] != b'\x08\x00' or frame[23] != 1:
            continue
        ihl = (frame[14] & 15) * 4
        icmp = frame[14 + ihl:]
        typ, ident, seq = icmp[0], *struct.unpack('!HH', icmp[4:8])
        out.append((sec + (frac if nano else frac * 1000) / 1e9, typ, ident, seq))
    return out


recs = records(sys.argv[1])
req = {(i, q): t for t, typ, i, q in recs if typ == 8}
rep = {(i, q): t for t, typ, i, q in recs if typ == 0}
rtt = {k: (rep[k] - req[k]) * 1e6 for k in req if k in rep}
a = sorted(v for (i, q), v in rtt.items() if q % 2 == 0)
b = sorted(v for (i, q), v in rtt.items() if q % 2 == 1)
gap = sorted((rep[(i, q)] - rep[(i, q - 1)]) * 1e6 for (i, q) in rep if q % 2 == 1 and (i, q - 1) in rep)
med = lambda v: v[len(v) // 2] if v else None
p90 = lambda v: v[int(len(v) * 0.9)] if v else None
print('pairs answered A %d B %d of 60' % (len(a), len(b)))
print('A (after idle) RTT us: median %s p90 %s min %s' % (med(a), p90(a), a[0] if a else None))
print('B (~100 us behind A) RTT us: median %s p90 %s min %s' % (med(b), p90(b), b[0] if b else None))
print('reply B - reply A spacing at the receive tap, us: median %s' % med(gap))

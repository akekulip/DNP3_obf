"""Which side does the idle-dependent transit delay follow? For every Vision->switch->Vision transit in a block's
two captures (out = transmit tap, in = receive tap, both software timestamps on enp59s0f0np0): idle on the transmit
tap before this packet left, idle on the receive tap before it arrived, and the transit."""
import glob
import json
import struct
import sys


def stamps(path):
    b = open(path, 'rb').read()
    nano = b[:4] in (b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d')
    off, out = 24, []
    while off + 16 <= len(b):
        s, f, incl, _ = struct.unpack('<IIII', b[off:off + 16])
        out.append(s * 10**9 + (f if nano else f * 1000))
        off += 16 + incl
    return sorted(out)


def idle_before(ts_list, t):
    prev = [x for x in ts_list if x < t]
    return (t - prev[-1]) / 1e3 if prev else None


for arm_dir in sys.argv[1:]:
    d = glob.glob(arm_dir + '/*/')[0]
    tx, rx = stamps(d + 'out.pcap'), stamps(d + 'in.pcap')
    rows = []
    for e in json.load(open(d + 'timing.json'))['exchanges']:
        o = e.get('observation') or {}
        for a, b in (('request', 'request_delivered'), ('response_available', 'response')):
            try:
                ta, tb = o[a]['timestamp_ns'], o[b]['timestamp_ns']
            except (KeyError, TypeError):
                continue
            rows.append((idle_before(tx, ta), idle_before(rx, tb), (tb - ta) / 1e3))
    rows = [r for r in rows if None not in r]
    med = lambda v: sorted(v)[len(v) // 2] if v else None
    cells = {}
    for itx, irx, tr in rows:
        key = ('tx-idle<0.5' if itx < 500 else 'tx-idle>=2' if itx >= 2000 else 'tx-mid',
               'rx-idle<0.5' if irx < 500 else 'rx-idle>=2' if irx >= 2000 else 'rx-mid')
        cells.setdefault(key, []).append(tr)
    print('==', arm_dir, 'transits', len(rows))
    for key in sorted(cells):
        print('  %-12s %-12s n %3d  transit median %6.0f us' % (key[0], key[1], len(cells[key]), med(cells[key])))

"""Wire frames of one contention point from a model log: every port-9 ingress (sent by the test) and every
'Tx Pkt to port 9' (sent by the switch), in log order, for the connection whose client ISN is given.

  python3 extract_wire_frames.py RUN_DIR TAG OUT.json

Used to build tests/fixtures/shared_port_frames_m10_03_06.json (relay and master share dev port 9)."""
import glob
import json
import re
import sys

LINE = re.compile(r'^:\d\d-\d\d (\d\d:\d\d:\d\d\.\d+):\s+:(?:0x[0-9a-f]+|-):(?:0x[0-9a-f]+|-):<\d+,[-\d]+,[-\d]+>:(.*)$')
HEX = re.compile(r'^(?:[0-9a-f]{2} )*[0-9a-f]{2} ?$')


def frames(log):
    out, cur, state = [], None, None
    for raw in log:
        m = LINE.match(raw.rstrip('\n'))
        if not m:
            continue
        wall, text = m.group(1), m.group(2).strip()
        if text.startswith('=========='):
            cur = None
            if 'Ingress Pkt from port 9 ' in text or 'Tx Pkt to port 9 ' in text:
                cur = dict(wall=wall, dir='in' if 'Ingress' in text else 'tx', hex='')
                out.append(cur)
            state = 'header' if cur else None
            continue
        if text == 'Packet :' and state == 'header':
            state = 'dump'
            continue
        if state == 'dump' and HEX.match(text):
            cur['hex'] += text.replace(' ', '')
            continue
        state = None
    return out


def main(run_dir, tag, out):
    res = json.load(open(glob.glob(run_dir + '/*_results.json')[0]))
    syn = next(c for c in res['cases'] if c['name'] == tag + '_SYN')
    isn = int.from_bytes(bytes.fromhex(next(iter(syn['received'].values()))[0])[38:42], 'big')
    with open(glob.glob(run_dir + '/model_*.log')[0], errors='replace') as log:
        allf = frames(log)
    keep = []
    for f in allf:
        b = bytes.fromhex(f['hex'])
        if len(b) < 54:
            continue
        seq, ack = int.from_bytes(b[38:42], 'big'), int.from_bytes(b[42:46], 'big')
        if isn <= seq < isn + 2000 or isn <= ack < isn + 2000:
            keep.append(f)
    json.dump(dict(source=run_dir, tag=tag, client_isn=isn, frames=keep), open(out, 'w'), indent=1)
    print(len(keep), 'frames')


if __name__ == '__main__':
    main(*sys.argv[1:4])

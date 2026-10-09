#!/usr/bin/env python3
"""T2-CLK-XPIPE on the local Tofino-1 model (read/clk_xpipe_probe.p4): do pipe 0 (N) and pipe 2 (T) read one
global_tstamp time base, and what is T.now - N.t0q for N's real pass count?

Runs inside integration/core/launch_model.sh. Every pass of the probe writes {ingress_port, global_tstamp} into
the next slot of the frame, so one captured frame carries every hop's timestamp. Paths (one fwd entry per hop):

  1 same0  pipe0 9  -> pipe0 68 (recirc)            -> out 64     one same-pipe hop in pipe 0
  2 x02    pipe0 9  -> pipe2 325 (T_IN)             -> out 64     one cross-pipe hop 0 -> 2 (N -> T)
  3 same2  pipe2 257-> pipe2 325                    -> out 64     one same-pipe hop in pipe 2
  4 x20    pipe2 257-> pipe0 68                     -> out 64     one cross-pipe hop 2 -> 0
  5 nlike  pipe0 9  -> 68 -> 68 -> 68 -> pipe2 325  -> out 64     N's pass count: pass 0, three recirculations, T_IN
  6 x01    pipe0 9  -> pipe1 196 (M port)           -> out 64     one cross-pipe hop 0 -> 1

If the pipes shared nothing, x02 and x20 would differ by twice the offset; if they share one base, both match the
same-pipe hops. Model time is not silicon time: the result transfers as "one time base on the model", not as a
silicon transit bound. Writes OUT/clk.json with every frame's raw slots.
"""
import json
import os
import statistics
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(os.path.dirname(HERE), 'core')]
from model_driver import Model, Report, gc  # noqa: E402

m = Model(ports=[], enable=False)
rep = Report(os.environ['PROG'])
REPS = int(os.environ.get('CLK_REPS', '40'))
ALL = gc.Target(device_id=0, pipe_id=0xffff)

PATHS = {
    1: ('same0', 9, [(0, 9, 0, 68), (0, 68, 1, 64)]),
    2: ('x02', 9, [(0, 9, 0, 325), (2, 325, 1, 64)]),
    3: ('same2', 257, [(2, 257, 0, 325), (2, 325, 1, 64)]),
    4: ('x20', 257, [(2, 257, 0, 68), (0, 68, 1, 64)]),
    5: ('nlike', 9, [(0, 9, 0, 68), (0, 68, 1, 68), (0, 68, 2, 68), (0, 68, 3, 325), (2, 325, 4, 64)]),
    6: ('x01', 9, [(0, 9, 0, 196), (1, 196, 1, 64)]),
}


def port_add(d):
    t = m.table('$PORT', raw=True)
    data = [gc.DataTuple('$SPEED', str_val='BF_SPEED_10G'), gc.DataTuple('$FEC', str_val='BF_FEC_TYP_NONE'),
            gc.DataTuple('$PORT_ENABLE', bool_val=True)]
    try:
        t.entry_add(ALL, [t.make_key([gc.KeyTuple('$DEV_PORT', d)])], [t.make_data(data)])
        return 'ok'
    except Exception as exc:  # recorded, not fatal: recirculation ports are refused and still work (model_28)
        return 'REFUSED: ' + str(exc).replace('\n', ' ')[:120]


def install():
    for path, (_, _, hops) in PATHS.items():
        for pipe, port, hop, nxt in hops:
            t = m.table('p%d.Ingress.fwd' % pipe)
            key = t.make_key([gc.KeyTuple('ig.ingress_port', port), gc.KeyTuple('hdr.st.path', path),
                              gc.KeyTuple('hdr.st.hop', hop)])
            t.entry_add(ALL, [key], [t.make_data([gc.DataTuple('port', nxt)], 'Ingress.go')])


def frame(path):
    return bytes.fromhex('0a00000000020a0000000001') + b'\x88\xb6' + bytes([path, 0, 0, 0]) + bytes(64)


def slots(raw):
    body = raw[14:]
    path, hop = body[0], body[1]
    out = []
    for k in range(hop):
        port, hi, lo = struct.unpack('>HHI', body[4 + 8 * k: 12 + 8 * k])
        out.append((port, (hi << 32) | lo))
    return path, hop, out


enabled = {d: port_add(d) for d in (9, 64, 257, 68, 196, 324, 325)}
time.sleep(2.0)
install()
rep.add('setup/ports_and_paths', 'recorded', 'recorded', ok=True, enable=enabled)

record = {'paths': {}, 'enable': enabled}
for path, (name, inject, hops) in PATHS.items():
    rows = []
    for _ in range(REPS):
        out = m.exchange(inject, frame(path), [64], timeout=1.0, quiet=0.2)
        got = out.get(64, [])
        if len(got) != 1:
            rows.append({'error': 'frames on 64: %d' % len(got)})
            continue
        p, hop, s = slots(got[0])
        rows.append({'path': p, 'hop': hop, 'slots': s, 'raw': got[0].hex()})
    good = [r for r in rows if 'slots' in r and r['hop'] == len(hops)]
    ports_ok = all([port for port, _ in r['slots']] == [h[1] for h in hops] for r in good)
    steps = [[r['slots'][k + 1][1] - r['slots'][k][1] for k in range(len(hops) - 1)] for r in good]
    total = [r['slots'][-1][1] - r['slots'][0][1] for r in good]
    summary = {'n': len(good), 'of': REPS, 'ports_ok': ports_ok}
    if total:
        summary.update(total_min=min(total), total_median=statistics.median(total), total_max=max(total),
                       per_hop_min=[min(c) for c in zip(*steps)], per_hop_max=[max(c) for c in zip(*steps)],
                       negative_steps=sum(1 for s in steps for d in s if d < 0))
    record['paths'][name] = {'hops': hops, 'summary': summary, 'rows': rows}
    rep.add('path/%s' % name, 'all %d stamped' % REPS,
            'all %d stamped' % REPS if summary['n'] == REPS and ports_ok else '%d stamped, ports_ok=%s' % (summary['n'], ports_ok),
            summary=summary)
    print('  %-6s %s' % (name, json.dumps(summary)))

# Model time scale: two same0 frames one wall-clock second apart.
scale = []
for _ in range(3):
    a = m.exchange(9, frame(1), [64], timeout=1.0, quiet=0.2).get(64, [])
    w0 = time.time()
    time.sleep(1.0)
    b = m.exchange(9, frame(1), [64], timeout=1.0, quiet=0.2).get(64, [])
    w1 = time.time()
    if a and b:
        scale.append({'tstamp_delta': slots(b[0])[2][0][1] - slots(a[0])[2][0][1], 'wall_delta_ns': int((w1 - w0) * 1e9)})
record['time_scale'] = scale
rep.add('model/time_scale', 'recorded', 'recorded', ok=bool(scale), scale=scale)
print('  time scale', scale)

with open(os.path.join(os.environ['OUT'], 'clk.json'), 'w') as f:
    json.dump(record, f, indent=1)
sys.exit(0 if rep.finish(os.path.join(os.environ['OUT'], 'cases.json')) else 1)

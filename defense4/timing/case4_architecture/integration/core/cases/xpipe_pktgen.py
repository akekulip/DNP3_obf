#!/usr/bin/env python3
"""(d) detail: does the model ever generate packet-generator traffic? Waits up to 15 s, nudging model time with probe traffic."""
import os, sys, time, struct
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path[:0] = [os.path.dirname(HERE)]
from model_driver import Model, Report, gc
m = Model(ports=[], enable=False); rep = Report(os.environ['PROG'])
def reg(p, n, i=0):
    r = m.register_read('p%d.%s' % (p, n), i); v = r[[k for k in r if k.endswith('.f1')][0]]; return v[p] if len(v) > 1 else v[0]
frame = bytes.fromhex('0a0000000002' '0a0000000001') + b'\x88\xb5' + struct.pack('>IIIHH', 1, 2, 3, 0x0105, 0) + b'pktgen-payload----'
t = m.table('p0.Ingress.fwd')
for p in range(4):
    dev = (p << 7) | 68
    t.entry_add(gc.Target(device_id=0, pipe_id=0xffff), [t.make_key([gc.KeyTuple('ig.ingress_port', dev)])], [t.make_data([gc.DataTuple('port', 64), gc.DataTuple('do_mir', 0), gc.DataTuple('sid', 0)], 'Ingress.go_egress')]) if p == 0 else None
pc, pb, pa = m.table('pktgen.port_cfg', raw=True), m.table('pktgen.pkt_buffer', raw=True), m.table('pktgen.app_cfg', raw=True)
T = gc.Target(device_id=0)
log = {}
for dev in (68, 196, 324, 452):
    pc.entry_mod(T, [pc.make_key([gc.KeyTuple('dev_port', dev)])], [pc.make_data([gc.DataTuple('pktgen_enable', bool_val=True)])])
buf = frame.ljust(64, b'\0')
pb.entry_mod(T, [pb.make_key([gc.KeyTuple('pkt_buffer_offset', 0), gc.KeyTuple('pkt_buffer_size', 64)])], [pb.make_data([gc.DataTuple('buffer', bytearray(buf))])])
for trig, nsec in (('trigger_timer_one_shot', 1000), ('trigger_timer_periodic', 100000)):
    flds = [gc.DataTuple('timer_nanosec', nsec), gc.DataTuple('pkt_len', 64), gc.DataTuple('pkt_buffer_offset', 0), gc.DataTuple('batch_count_cfg', 0),
            gc.DataTuple('packets_per_batch_cfg', 2), gc.DataTuple('ipg', 0), gc.DataTuple('ibg', 0), gc.DataTuple('trigger_counter', 0),
            gc.DataTuple('batch_counter', 0), gc.DataTuple('pkt_counter', 0)]
    if trig.endswith('periodic'): flds.append(gc.DataTuple('ibg_jitter', 0)) if False else None
    try:
        pa.entry_mod(T, [pa.make_key([gc.KeyTuple('app_id', 0)])], [pa.make_data(flds + [gc.DataTuple('app_enable', bool_val=False)], trig)])
        pa.entry_mod(T, [pa.make_key([gc.KeyTuple('app_id', 0)])], [pa.make_data(flds + [gc.DataTuple('app_enable', bool_val=True)], trig)])
        cfg = 'ok'
    except Exception as exc:
        cfg = 'REFUSED ' + str(exc).replace('\n', ' ')[:160]
    seen = 0
    for i in range(15):
        time.sleep(1.0)
        m.send(64 if False else 1 if False else 64, frame) if False else None
        seen = sum(reg(p, 'Ingress.pgen_arr') for p in range(4))
        if seen: break
    try:
        rd = next(iter(pa.entry_get(T, [pa.make_key([gc.KeyTuple('app_id', 0)])], {'from_hw': True})))[0].to_dict()
    except Exception as exc: rd = 'get failed ' + str(exc)[:80]
    rep.add('pktgen_%s' % trig, 'packets', 'cfg=%s pgen_arr_total=%d after up to 15 s; app readback=%s' % (cfg, seen, {k: rd[k] for k in ('trigger_counter', 'batch_counter', 'pkt_counter', 'app_enable') if isinstance(rd, dict) and k in rd} if isinstance(rd, dict) else rd), ok=seen > 0)
    try: pa.entry_mod(T, [pa.make_key([gc.KeyTuple('app_id', 0)])], [pa.make_data(flds + [gc.DataTuple('app_enable', bool_val=False)], trig)])
    except Exception: pass
sys.exit(0 if rep.finish(os.path.join(os.environ['OUT'], 'cases.json')) else 1)

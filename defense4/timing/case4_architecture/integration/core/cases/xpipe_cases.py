#!/usr/bin/env python3
"""S3-0 / gate G-XPIPE on the local model: cross-pipe forwarding, mirror return, pktgen, port legality (xpipe_probe.p4).
Every experiment records refusals (exception text) instead of aborting."""
import os, struct, sys, time
HERE = os.path.dirname(os.path.abspath(__file__)); CORE = os.path.dirname(HERE)
sys.path[:0] = [CORE]
from model_driver import Model, Report, same_frame, gc, veth_for

m = Model(ports=[], enable=False)
rep = Report(os.environ['PROG'])
PORTS = [int(x) for x in os.environ.get('DEV_PORTS', '').split()]
def local(d): return d & 0x7f
def pipe_of(d): return d >> 7

def frame(epoch=0x11111111, gen=0x22222222, expected=0x00050001, event=0x0105, payload=b'xpipe-probe-0123456789'):
    return (bytes.fromhex('0a0000000002' '0a0000000001') + b'\x88\xb5' + struct.pack('>IIIHH', epoch, gen, expected, event, 0) + payload)
PFX = lambda f: f[14:30]

def tgt(p): return gc.Target(device_id=0, pipe_id=0xffff)     # per-pipe-program tables only accept the all-pipes target here (p0.Ingress.fwd refuses pipe_id 0: INVALID_ARGUMENT)
def table(n): return m.table(n, raw=True) if n.startswith('$') or n.startswith('pktgen.') else m.table(n)
def reg(p, name, idx=0, field=None):
    r = m.register_read('p%d.%s' % (p, name), idx)
    key = [k for k in r if k.endswith('.f1')][0]
    vals = r[key]
    return vals[p] if len(vals) > 1 else vals[0]
def fwd_set(p, ig, action, **data):
    t = m.table('p%d.Ingress.fwd' % p); key = t.make_key([gc.KeyTuple('ig.ingress_port', ig)])
    d = t.make_data([gc.DataTuple(k, v) for k, v in data.items()], 'Ingress.%s' % action)
    try: t.entry_del(tgt(p), [key])
    except Exception: pass
    t.entry_add(tgt(p), [key], [d])
def fwd_clear(): 
    for p in range(4):
        try: m.table('p%d.Ingress.fwd' % p).entry_del(tgt(p), [])
        except Exception: pass
def port_add(d, speed='BF_SPEED_10G', lpbk=None):
    t = m.table('$PORT', raw=True)
    data = [gc.DataTuple('$SPEED', str_val=speed), gc.DataTuple('$FEC', str_val='BF_FEC_TYP_NONE'), gc.DataTuple('$PORT_ENABLE', bool_val=True)]
    if lpbk: data.append(gc.DataTuple('$LOOPBACK_MODE', str_val=lpbk))
    try:
        t.entry_add(tgt(0xffff), [t.make_key([gc.KeyTuple('$DEV_PORT', d)])], [t.make_data(data)]); return 'ok'
    except Exception as exc:
        return 'REFUSED: ' + str(exc).replace('\n', ' ')[:140]
def counters(items):
    return {k: reg(*k) for k in items}
def watch(ports): return {p: p for p in ports}

# ---- port enable sweep (also the legality table for (e)) ----------------------------------------------------------------
legal = {}
for d in PORTS:
    legal[d] = port_add(d)
time.sleep(2.0)
rep.add('ports/enable_sweep', 'recorded', 'recorded', ok=True, enable_result={str(k): v for k, v in legal.items()})
for d, r in legal.items(): print('  $PORT dev %d (pipe %d local %d): %s' % (d, pipe_of(d), local(d), r))

LISTEN = [p for p in PORTS]
def run(name, expect, setup, send_port, fr, watch_regs, expect_out, timeout=1.2, extra=None):
    fwd_clear(); setup()
    before = counters(watch_regs)
    out = m.exchange(send_port, fr, [p for p in LISTEN if p != send_port], timeout=timeout, quiet=0.4)
    time.sleep(0.4)
    after = counters(watch_regs)
    delta = {'p%d.%s[%d]' % (k[0], k[1], k[2]): after[k] - before[k] for k in watch_regs}
    frames = {p: [x for x in v] for p, v in out.items() if v}
    ok = expect(delta, frames)
    rep.add(name, 'expected', 'as-expected' if ok else 'DIFFERENT', ok=ok, delta=delta, out={str(p): [x.hex() for x in v] for p, v in frames.items()},
            frame=fr, extra=extra)
    return delta, frames

F = frame()
# (a) pipe0 ingress -> pipe1 ingress through the pipe-1 recirculation port 196 (bypass egress), then pipe1 -> pipe0 egress port 64
def setup_a():
    fwd_set(0, 9, 'go_bypass', port=196)
    fwd_set(1, 196, 'go_egress', port=64, do_mir=0, sid=0)
regs_a = [(0, 'Ingress.arr_ig', 9), (1, 'Ingress.arr_ig', 68), (0, 'Egress.arr_eg', 64), (1, 'Egress.arr_eg', 68)]
d, f = run('a_pipe0_to_pipe1_ingress_then_pipe0_egress64', None, setup_a, 9, F, regs_a,
           None) if False else (None, None)
def check_a(delta, frames):
    return (delta['p0.Ingress.arr_ig[9]'] == 1 and delta['p1.Ingress.arr_ig[68]'] == 1 and delta['p0.Egress.arr_eg[64]'] == 1
            and 64 in frames and len(frames[64]) == 1 and same_frame(frames[64][0], F))
run('a_pipe0_to_pipe1_ingress_then_pipe0_egress64', check_a, setup_a, 9, F, regs_a, None)
seen = {n: reg(1, 'Ingress.seen_' + n) for n in ('epoch', 'gen', 'expected', 'event')}
want = struct.unpack('>IIIHH', PFX(F)); wantv = dict(epoch=want[0], gen=want[1], expected=want[2], event=(want[3] << 16) | want[4])
rep.add('a_prefix_preserved_at_pipe1_ingress', wantv, seen, ok=(seen == wantv))

# (b) pipe1 -> pipe0 egress at 64 and at 9, direct (no loopback hop): pipe 1 recirc ingress port 196 entered by pktgen-free injection is not possible,
#     so use pipe0 -> 196 -> pipe1 -> {64, 9}
for port in (64, 9):
    def setup_b(port=port):
        fwd_set(0, 9 if port != 9 else 64, 'go_bypass', port=196); fwd_set(1, 196, 'go_egress', port=port, do_mir=0, sid=0)
    ingress = 9 if port != 9 else 64
    def check_b(delta, frames, port=port, ingress=ingress):
        return (delta['p1.Ingress.arr_ig[68]'] == 1 and delta['p0.Egress.arr_eg[%d]' % port] == 1 and port in frames and len(frames[port]) == 1 and same_frame(frames[port][0], F))
    run('b_pipe1_to_pipe0_egress_port%d' % port, check_b, setup_b, ingress, F, [(1, 'Ingress.arr_ig', 68), (0, 'Egress.arr_eg', port)], None)

# (c) e2e mirror from pipe0 egress -> session dest port 68 (recirc) -> pipe0 ingress port 68
mc = m.table('$mirror.cfg', raw=True)
try:
    mc.entry_add(tgt(0), [mc.make_key([gc.KeyTuple('$sid', 5)])],
                 [mc.make_data([gc.DataTuple('$direction', str_val='EGRESS'), gc.DataTuple('$ucast_egress_port', 68),
                                gc.DataTuple('$ucast_egress_port_valid', bool_val=True), gc.DataTuple('$session_enable', bool_val=True)], '$normal')])
    mres = 'ok'
except Exception as exc:
    mres = 'REFUSED: ' + str(exc).replace('\n', ' ')[:200]
rep.add('c_mirror_session_cfg', 'ok', mres, ok=(mres == 'ok'))
def setup_c():
    fwd_set(0, 9, 'go_bypass', port=196); fwd_set(1, 196, 'go_egress', port=64, do_mir=1, sid=5)
    fwd_set(0, 68, 'deny') if False else None
regs_c = [(1, 'Ingress.arr_ig', 68), (0, 'Egress.arr_eg', 64), (0, 'Egress.arr_mir', 68), (0, 'Ingress.arr_ig', 68)]
def check_c(delta, frames):
    return (delta['p0.Egress.arr_eg[64]'] == 1 and delta['p0.Egress.arr_mir[68]'] == 1 and delta['p0.Ingress.arr_ig[68]'] == 1
            and 64 in frames and same_frame(frames[64][0], F))
run('c_e2e_mirror_returns_to_port68_recirc', check_c, setup_c, 9, F, regs_c, None)
seen0 = {n: reg(0, 'Ingress.seen_' + n) for n in ('epoch', 'gen', 'expected', 'event')}
rep.add('c_mirror_copy_prefix_at_pipe0_ingress68', wantv, seen0, ok=(seen0 == wantv))


# (f) N-to-T style handoff: pipe0 ingress -> pipe2 recirc-type port 325 (local 69) -> pipe0 egress 64 / 9;  (g) three hops pipe0 -> pipe2 -> pipe1 -> pipe0 egress
for port in (64, 9):
    def setup_f(port=port):
        fwd_set(0, 9 if port != 9 else 64, 'go_bypass', port=325); fwd_set(2, 325, 'go_egress', port=port, do_mir=0, sid=0)
    ing = 9 if port != 9 else 64
    def check_f(delta, frames, port=port):
        return delta['p2.Ingress.arr_ig[69]'] == 1 and port in frames and len(frames[port]) == 1 and same_frame(frames[port][0], F)
    run('f_pipe0_to_pipe2_port325_then_egress%d' % port, check_f, setup_f, ing, F, [(2, 'Ingress.arr_ig', 69), (0, 'Egress.arr_eg', port)], None)
seen2 = {n: reg(2, 'Ingress.seen_' + n) for n in ('epoch', 'gen', 'expected', 'event')}
rep.add('f_prefix_preserved_at_pipe2_ingress', wantv, seen2, ok=(seen2 == wantv))
def setup_g():
    fwd_set(0, 9, 'go_bypass', port=325); fwd_set(2, 325, 'go_bypass', port=196); fwd_set(1, 196, 'go_egress', port=64, do_mir=0, sid=0)
def check_g(delta, frames):
    return delta['p2.Ingress.arr_ig[69]'] == 1 and delta['p1.Ingress.arr_ig[68]'] == 1 and 64 in frames and len(frames[64]) == 1 and same_frame(frames[64][0], F)
run('g_three_hops_pipe0_pipe2_pipe1_then_pipe0_egress64', check_g, setup_g, 9, F, [(2, 'Ingress.arr_ig', 69), (1, 'Ingress.arr_ig', 68)], None)

# (d) pktgen on the model, one app per pipe, pipe-local source port 68 (dev 68/196/324/452)
PG = {}
try:
    pc = m.table('pktgen.port_cfg', raw=True); pb = m.table('pktgen.pkt_buffer', raw=True); pa = m.table('pktgen.app_cfg', raw=True)
    for p in range(4):
        dev = (p << 7) | 68
        res = {}
        try:
            pc.entry_mod(gc.Target(device_id=0), [pc.make_key([gc.KeyTuple('dev_port', dev)])], [pc.make_data([gc.DataTuple('pktgen_enable', bool_val=True)])]); res['port_cfg'] = 'ok'
        except Exception as exc: res['port_cfg'] = 'REFUSED: ' + str(exc).replace('\n', ' ')[:140]
        buf = bytes(F).ljust(64, b'\0')[:64]
        try:
            pb.entry_mod(gc.Target(device_id=0), [pb.make_key([gc.KeyTuple('pkt_buffer_offset', 0), gc.KeyTuple('pkt_buffer_size', len(buf))])], [pb.make_data([gc.DataTuple('buffer', bytearray(buf))])]); res['buffer'] = 'ok'
        except Exception as exc: res['buffer'] = 'REFUSED: ' + str(exc).replace('\n', ' ')[:140]
        PG[p] = res
    rep.add('d_pktgen_tables_present', 'tables', 'tables', ok=True, per_pipe=PG)
except Exception as exc:
    rep.add('d_pktgen_tables_present', 'tables', 'REFUSED: ' + str(exc).replace('\n', ' ')[:200], ok=False)
fwd_clear()
for p in range(4): fwd_set(p, 0, 'go_egress', port=64, do_mir=0, sid=0)   # model reports ingress_port 0 for generator packets
bef = {p: (reg(p, 'Ingress.pgen_arr'), reg(p, 'Ingress.arr_ig', 0)) for p in range(4)}
m.drain([64])
flds = [gc.DataTuple('timer_nanosec', 1000), gc.DataTuple('pkt_len', 64), gc.DataTuple('pkt_buffer_offset', 0),
        gc.DataTuple('batch_count_cfg', 0), gc.DataTuple('packets_per_batch_cfg', 2), gc.DataTuple('ipg', 0), gc.DataTuple('ibg', 0),
        gc.DataTuple('trigger_counter', 0), gc.DataTuple('batch_counter', 0), gc.DataTuple('pkt_counter', 0), gc.DataTuple('app_enable', bool_val=False)]
try:
    pa.entry_mod(gc.Target(device_id=0), [pa.make_key([gc.KeyTuple('app_id', 0)])], [pa.make_data(flds, 'trigger_timer_one_shot')])
    flds[-1] = gc.DataTuple('app_enable', bool_val=True)
    pa.entry_mod(gc.Target(device_id=0), [pa.make_key([gc.KeyTuple('app_id', 0)])], [pa.make_data(flds, 'trigger_timer_one_shot')])
    err = 'ok'
except Exception as exc:
    err = 'REFUSED: ' + str(exc).replace('\n', ' ')[:200]
got = m.capture([64], timeout=2.0, quiet=0.6).get(64, []) if err == 'ok' else []
time.sleep(0.5)
for p in range(4):
    a = (reg(p, 'Ingress.pgen_arr'), reg(p, 'Ingress.arr_ig', 0))
    rep.add('d_pktgen_pipe%d_port%d' % (p, (p << 7) | 68), 'timer packets reach ingress (3 expected)', 'pgen_arr +%d, arr_ig[port0] +%d' % (a[0] - bef[p][0], a[1] - bef[p][1]) if err == 'ok' else err,
            ok=(err == 'ok' and a[0] - bef[p][0] >= 1), app_cfg=err)
rep.add('d_pktgen_frames_at_port64', 'frames', '%d frames, first=%s' % (len(got), (got[0].hex() if got else '')), ok=bool(got), frames=[x.hex() for x in got])
try: pa.entry_mod(gc.Target(device_id=0), [pa.make_key([gc.KeyTuple('app_id', 0)])], [pa.make_data(flds[:-1] + [gc.DataTuple('app_enable', bool_val=False)], 'trigger_timer_one_shot')])
except Exception: pass

# (e) which device ports are usable as private hops: send pipe0 port 9 -> D (bypass) and (egress) and see where it goes
fwd_clear()
sweep = {}
cands = [(p << 7) | l for p in range(4) for l in range(64, 72)] + [129, 257, 385]
for D in cands:
    row = {}
    for mode in ('go_bypass', 'go_egress'):
        fwd_clear()
        try:
            if mode == 'go_bypass': fwd_set(0, 9, 'go_bypass', port=D)
            else: fwd_set(0, 9, 'go_egress', port=D, do_mir=0, sid=0)
        except Exception as exc:
            row[mode] = 'ENTRY REFUSED: ' + str(exc).replace('\n', ' ')[:100]; continue
        pi, li = pipe_of(D), local(D)
        b_ig = reg(pi, 'Ingress.arr_ig', li); b_eg = reg(pi, 'Egress.arr_eg', li)
        listen = [p for p in LISTEN if p != 9]
        out = m.exchange(9, F, listen, timeout=0.8, quiet=0.3)
        time.sleep(0.2)
        a_ig = reg(pi, 'Ingress.arr_ig', li); a_eg = reg(pi, 'Egress.arr_eg', li)
        leaves = {p: len(v) for p, v in out.items() if v}
        row[mode] = dict(arrives_at_ingress_of_that_port=a_ig - b_ig, egress_traversals=a_eg - b_eg, leaves_on_veth=leaves,
                         verdict=('RECIRCULATES to ingress %d' % D if a_ig - b_ig else ('LEAVES %s' % leaves if leaves else 'DROPPED/consumed')))
    sweep[D] = row
    print('  dev %d (pipe %d local %d): bypass=%s | egress=%s' % (D, pipe_of(D), local(D), row.get('go_bypass', {}).get('verdict', row.get('go_bypass')), row.get('go_egress', {}).get('verdict', row.get('go_egress'))))
rep.add('e_port_sweep', 'recorded', 'recorded', ok=True, sweep={str(k): v for k, v in sweep.items()})
ok = rep.finish(os.path.join(os.environ['OUT'], 'cases.json'))
sys.exit(0 if ok else 1)

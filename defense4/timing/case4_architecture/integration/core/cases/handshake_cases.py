#!/usr/bin/env python3
"""handshake.p4 (multi-pass through recirculation port 68) vs the independent Connection oracle
(integration/connection/reference.py). Each scenario starts from a register reset."""
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__)); CORE = os.path.dirname(HERE)
sys.path.insert(0, CORE); sys.path.insert(0, os.path.join(CORE, '..', 'connection'))
import frames as F
import reference as R
from model_driver import Model, Report, same_frame

CL, SV = F.CLIENT, F.SERVER
FLOW = (CL[0], SV[0], CL[1], SV[1])
CP, SP = 9, 1                                   # client-side / server-side device ports

def syn(seq=1000, **kw): return F.tcp_frame(CL, SV, 2, seq, kw.pop('ack', 0), mss=kw.pop('mss', 1460), **kw)
def synack(seq=5000, ack=1001, **kw): return F.tcp_frame(SV, CL, 18, seq, ack, mss=kw.pop('mss', 1460), **kw)
def ack(seq=1001, a=5001, **kw): return F.tcp_frame(CL, SV, 16, seq, a, **kw)
def fin_c(seq=1001, a=5001, **kw): return F.tcp_frame(CL, SV, 17, seq, a, **kw)
def fin_s(seq=5001, a=1001, **kw): return F.tcp_frame(SV, CL, 17, seq, a, **kw)
def rst_c(seq=1001, **kw): return F.tcp_frame(CL, SV, 4, seq, 0, **kw)

m = Model(ports=[1, 9, 2])      # 68 is the internal recirculation port: no $PORT entry (enable refused, not needed)
rep = Report(os.environ['PROG'], ports=m.ports, port_errors=m.port_errors)
for p, o in ((9, 1), (1, 9), (68, 1)):
    m.add('Ingress.ports', {'ig.ingress_port': p}, 'Ingress.route', {'port': o})
m.add('Ingress.connection', {'hdr.ip.src': CL[0], 'hdr.ip.dst': SV[0], 'hdr.tcp.sport': CL[1], 'hdr.tcp.dport': SV[1]}, 'Ingress.forward_flow', {'port': SP})
m.add('Ingress.connection', {'hdr.ip.src': SV[0], 'hdr.ip.dst': CL[0], 'hdr.tcp.sport': SV[1], 'hdr.tcp.dport': CL[1]}, 'Ingress.reverse_flow', {'port': CP})

REGS = (('counter', 'Ingress.counter', 'Ingress.counter.f1'), ('owner', 'Ingress.owner', 'Ingress.owner.f1'),
        ('epoch', 'Ingress.epoch', 'Ingress.epoch.f1'), ('client', 'Ingress.client', 'Ingress.client.f1'),
        ('server', 'Ingress.server', 'Ingress.server.f1'))

def reset():
    for _, r, f in REGS:
        m.register_write(r, 0, {f: 0})
    m.register_write('Ingress.work.work', 0, {'Ingress.work.work.generation': 0, 'Ingress.work.work.phase': 4})

def state():
    s = {k: m.register_total(r, 0, f) for k, r, f in REGS}
    w = m.register_read('Ingress.work.work', 0)
    s['work_phase'] = w['Ingress.work.work.phase'][0]; s['work_gen'] = w['Ingress.work.work.generation'][0]
    return s

def oracle_state(o):
    s = o.snapshot()
    return {'counter': s['work_counter'], 'owner': s['cell'], 'epoch': s['epoch'], 'client': s['client_next'],
            'server': s['server_next'], 'work_phase': 4 if o.work is None else 'busy'}

def oracle_step(o, frame, port):
    e = o.begin(frame, port)
    if e is None: return 'refused-at-start'
    for _ in range(3):
        e = o.advance(e)
        if e.outcome is not None: break
    return 'forward' if e.outcome == 'forward' else e.outcome

def scenario(name, steps):
    if os.environ.get('ONLY') and os.environ['ONLY'] not in name: return True
    reset(); o = R.Connection(FLOW, allowed_ports={CP, SP}); all_ok = True
    for i, (label, port, frame) in enumerate(steps):
        out = m.exchange(port, frame, [1, 9, 2, 68], timeout=1.0, quiet=0.2)
        out = {p: v for p, v in out.items() if v}
        leak = [f.hex() for v in out.values() for f in v if not same_frame(f, frame)]
        fwd = 'forwarded-original' if any(same_frame(f, frame) for v in out.values() for f in v) else 'dropped'
        exp = oracle_step(o, frame, port)
        s_p4, s_or = state(), oracle_state(o)
        diffs = {k: (s_p4[k], s_or[k]) for k in s_or if s_or[k] != s_p4[k] and not (k == 'work_phase' and s_or[k] == 'busy' and s_p4[k] != 4)}
        burn = diffs.pop('counter', None)            # P4 mints a generation before validating (see RESULT)
        # forwarding contract of the P4: untracked packets pass through untouched; tracked-but-refused ones are dropped
        klass = ('LEAK_PRIVATE_PREFIX' if leak else 'STATE_DIVERGES' if diffs else
                 'MATCH_COUNTER_BURN' if burn else 'MATCH')
        ok = klass.startswith('MATCH')
        rep.add('%s/%d:%s' % (name, i, label), 'MATCH', klass, ok=ok, oracle_outcome=exp, forwarding=fwd, port=port, frame=frame,
                out=out, p4_state=s_p4, oracle_state=s_or, state_diffs=diffs, counter_burn=burn, leaked_frames=leak)
        all_ok &= ok
    return all_ok

HS = lambda: [('syn', CP, syn()), ('synack', SP, synack()), ('ack', CP, ack())]
scenario('happy', HS())
scenario('happy_then_fin_client', HS() + [('fin', CP, fin_c())])
scenario('happy_then_fin_server', HS() + [('fin_s', SP, fin_s())])
scenario('happy_then_rst', HS() + [('rst', CP, rst_c())])
scenario('close_after_syn', [('syn', CP, syn()), ('rst', CP, rst_c(1001))])
scenario('close_after_synack', HS()[:2] + [('fin_client', CP, fin_c())])
# malformed envelope on the first packet
for nm, kw in (('bad_ip_csum', dict(bad_ip=True)), ('bad_tcp_csum', dict(bad_tcp=True)), ('ttl0', dict(ttl=0)),
               ('mss56', dict(mss=56)), ('mss57', dict(mss=57)), ('mss65535', dict(mss=65535)), ('df_off_mf', dict(ip_flags_frag=0x2000)),
               ('urgent', dict(urgent=1)), ('ack_nonzero', dict(ack=5))):
    scenario('syn_' + nm, [('syn', CP, syn(**kw))])
scenario('syn_no_mss', [('syn', CP, F.tcp_frame(CL, SV, 2, 1000, 0))])
scenario('syn_with_payload', [('syn', CP, F.tcp_frame(CL, SV, 2, 1000, 0, b'x', mss=1460))])
scenario('syn_wrong_sport', [('syn', CP, F.tcp_frame((CL[0], CL[1] + 1), SV, 2, 1000, 0, mss=1460))])
scenario('syn_on_unlisted_port', [('syn', 2, syn())])
scenario('syn_from_server_side', [('syn', SP, F.tcp_frame(SV, CL, 2, 1000, 0, mss=1460))])
scenario('syn_syn_fin_flags', [('synfin', CP, F.tcp_frame(CL, SV, 3, 1000, 0, mss=1460))])
# order / replay / sequence
scenario('synack_first', [('synack', SP, synack())])
scenario('ack_first', [('ack', CP, ack())])
scenario('duplicate_syn', [('syn', CP, syn()), ('syn_again', CP, syn())])
scenario('syn_after_established', HS() + [('syn_again', CP, syn(seq=9000))])
scenario('duplicate_synack', HS()[:2] + [('synack_again', SP, synack())])
scenario('duplicate_ack', HS() + [('ack_again', CP, ack())])
scenario('synack_wrong_ack', [('syn', CP, syn()), ('synack_bad_ack', SP, synack(ack=1002))])
scenario('ack_wrong_seq', HS()[:2] + [('ack_bad_seq', CP, ack(seq=1002))])
scenario('ack_wrong_ack', HS()[:2] + [('ack_bad_ack', CP, ack(a=5002))])
scenario('ack_bad_tcp_csum', HS()[:2] + [('ack_bad', CP, ack(bad_tcp=True))])
scenario('synack_bad_ip_csum', [('syn', CP, syn()), ('synack_bad', SP, synack(bad_ip=True))])
scenario('ack_on_server_side', HS()[:2] + [('ack_from_wrong_dir', SP, F.tcp_frame(SV, CL, 16, 1001, 5001))])
scenario('ack_with_payload_unsupported', HS()[:2] + [('ack_payload', CP, ack(payload=b'abc'))])
scenario('rst_wrong_seq', HS() + [('rst_bad_seq', CP, rst_c(seq=777))])
scenario('reconnect_after_close', HS() + [('fin', CP, fin_c()), ('syn_new', CP, syn(seq=7000))])
ok = rep.finish(os.path.join(os.environ['OUT'], 'cases.json'))
sys.exit(0 if ok else 1)

#!/usr/bin/env python3
"""H2: remove a controller table entry while a packet is mid-flight (between recirculation passes) over gRPC.
The control plane cannot pause the model, so the removal is raced against the packet: after the frame is sent we
wait `delay` and delete one entry; delays sweep 0..40 ms so the delete lands in every pass. Per trial: what leaves
which port (front port 1/2/9 or the READ handoff port), whether a front-port frame is anything but the original
(private envelope leak), and whether the WorkRecord is free afterwards."""
import os, sys, time, itertools
HERE = os.path.dirname(os.path.abspath(__file__)); CORE = os.path.dirname(HERE)
ARCH = os.path.abspath(os.path.join(CORE, '..', '..'))
sys.path[:0] = [os.path.join(CORE, 'harness'), os.path.join(CORE, 'harness', 'tests'), CORE, HERE, os.path.join(ARCH, 'framework', 'size'),
                os.path.join(ARCH, '..', 'framework', 'size'), os.path.join(ARCH, 'integration', 'connection'),
                os.path.join(ARCH, 'protocol', 'tests'), os.path.join(ARCH, 'protocol', 'egress'), os.path.join(ARCH, 'protocol', 'egress', 'tests'),
                os.path.join(ARCH, 'tests'), os.path.join(ARCH, 'integration', 'connection', 'binding', 'tests')]
import vectors as V
import read_support as RS
from model_driver import Model, Report, same_frame, gc

HANDOFF = 66
m = Model(ports=[1, 2, 9, HANDOFF])
rep = Report(os.environ['PROG'], ports=m.ports)
T = V.topology()
def tup(a, b, sp, dp): return {'hdr.ip.src': a, 'hdr.ip.dst': b, 'hdr.tcp.sport': sp, 'hdr.tcp.dport': dp}
CF = tup(V.CLIENT, V.SERVER, V.CLIENT_PORT, V.SERVER_PORT); CR = tup(V.SERVER, V.CLIENT, V.SERVER_PORT, V.CLIENT_PORT)
def install():
    for ing, eg in ((1, 2), (2, 1), (68, 68)):
        try: m.add('Ingress.ports', {'ig.ingress_port': ing}, 'Ingress.route', {'port': eg})
        except Exception: pass
    for k, kind, port in ((CF, 'forward', 2), (CR, 'reverse', 1)):
        try: m.add('Ingress.connection', k, 'Ingress.%s_flow' % kind, {'port': port})
        except Exception: pass
    for k in (CF,):
        try: m.add('Ingress.data_connection', k, 'Ingress.configure', {'index': 1, 'code': 3, 'repeat': 1, 'on': 100, 'off': 200})
        except Exception: pass
    for k, dst, src in ((CF, 0x0000, 0x0100), (CR, 0x0100, 0x0000)):
        try: m.add('Ingress.read_connection', k, 'Ingress.read_configure', {'dst': dst, 'src': src})
        except Exception: pass
def delete(table, key):
    t = m.table(table)
    try: t.entry_del(m.target, [m._key(t, key)])
    except Exception as exc: return str(exc).splitlines()[0][:60]
REGS = (('counter', 'Ingress.counter', 'Ingress.counter.f1'), ('owner', 'Ingress.owner', 'Ingress.owner.f1'), ('epoch', 'Ingress.epoch', 'Ingress.epoch.f1'),
        ('client', 'Ingress.client', 'Ingress.client.f1'), ('server', 'Ingress.server', 'Ingress.server.f1'), ('read_app', 'Ingress.read_app', 'Ingress.read_app.f1'))
def preset(owner, client, server, epoch=17, app=0):
    vals = dict(counter=0, owner=owner, epoch=epoch, client=client, server=server, read_app=app)
    for k, r, f in REGS: m.register_write(r, 0, {f: vals[k]})
    m.register_write('Ingress.work.work', 0, {'Ingress.work.work.generation': 0, 'Ingress.work.work.phase': 4})
def work_phase(): return m.register_read('Ingress.work.work', 0)['Ingress.work.work.phase'][0]
install()

def trial(label, table, key, preset_args, port, frame, delay):
    install(); preset(**preset_args)
    m.drain([1, 2, 9, HANDOFF])
    m.send(port, frame)
    t_end = time.perf_counter() + delay
    while time.perf_counter() < t_end: pass
    err = delete(table, key)
    out = m.capture([1, 2, 9, HANDOFF], timeout=1.0, quiet=0.3)
    time.sleep(0.3)
    frames = [(p, x) for p, v in out.items() for x in v]
    leak = [(p, x.hex()) for p, x in frames if p != HANDOFF and not same_frame(x, frame)]
    front = [p for p, x in frames if p != HANDOFF]
    handoff = [p for p, x in frames if p == HANDOFF]
    phase = work_phase()
    kind = 'LEAK' if leak else ('forwarded' if front else ('handoff' if handoff else 'dropped'))
    rep.add('%s/delay%.1fms' % (label, delay * 1000), 'no-leak,work-free', kind + ',work%s' % ('-free' if phase == 4 else '-PINNED(%d)' % phase),
            ok=(not leak and phase == 4), delete_error=err, in_port=port, frame=frame, out=[(p, x.hex()) for p, x in frames], work_phase=phase)
    install()

SEL = V.packet(24, 101, 901, payload=V.native_select())
SELP = dict(owner=0x40001, client=101, server=901)
EST = dict(owner=0x90001, client=136, server=958)
RQ = RS.request_packet(app=0xc3)
delays = [0, 0.0005, 0.001, 0.002, 0.003, 0.004, 0.006, 0.008, 0.012, 0.016, 0.024, 0.04]
for d in delays:
    for rep_i in range(2):
        trial('select_del_connection', 'Ingress.connection', CF, SELP, 1, SEL, d)
        trial('select_del_data_connection', 'Ingress.data_connection', CF, SELP, 1, SEL, d)
        trial('ack_del_connection', 'Ingress.connection', CF, EST, 1, V.packet(16, 136, 958), d)
        trial('read_req_del_read_connection', 'Ingress.read_connection', CF, dict(owner=0x50001, client=1000, server=2000), 1, RQ, d)
        trial('read_req_del_connection', 'Ingress.connection', CF, dict(owner=0x50001, client=1000, server=2000), 1, RQ, d)
ok = rep.finish(os.path.join(os.environ['OUT'], 'cases.json'))
sys.exit(0 if ok else 1)

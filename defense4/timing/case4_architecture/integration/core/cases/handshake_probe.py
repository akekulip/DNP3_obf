#!/usr/bin/env python3
import os, sys, time
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, os.path.dirname(HERE))
import frames as F
from model_driver import Model
m = Model(ports=[1, 9, 68, 64])
print('port_errors', m.port_errors)
for t in ('$PORT',):
    tb = m.table(t, raw=True)
    import bfrt_grpc.client as gc
    for p in (1, 9, 64, 68):
        try:
            for d, k in tb.entry_get(m.target, [tb.make_key([gc.KeyTuple('$DEV_PORT', p)])], {'from_hw': True}):
                x = d.to_dict(); print(p, {k: x[k] for k in ('$PORT_UP', '$LOOPBACK_MODE', '$SPEED') if k in x})
        except Exception as e: print(p, 'get failed', str(e).splitlines()[0][:120])
for r, f in (('Ingress.counter', 'Ingress.counter.f1'), ('Ingress.owner', 'Ingress.owner.f1'), ('Ingress.work.work', None)):
    print(r, m.register_read(r, 0, f))
m.add('Ingress.ports', {'ig.ingress_port': 9}, 'Ingress.route', {'port': 1})
m.add('Ingress.ports', {'ig.ingress_port': 1}, 'Ingress.route', {'port': 9})
m.add('Ingress.ports', {'ig.ingress_port': 68}, 'Ingress.route', {'port': 1})
CL, SV = F.CLIENT, F.SERVER
m.add('Ingress.connection', {'hdr.ip.src': CL[0], 'hdr.ip.dst': SV[0], 'hdr.tcp.sport': CL[1], 'hdr.tcp.dport': SV[1]}, 'Ingress.forward_flow', {'port': 1})
m.add('Ingress.connection', {'hdr.ip.src': SV[0], 'hdr.ip.dst': CL[0], 'hdr.tcp.sport': SV[1], 'hdr.tcp.dport': CL[1]}, 'Ingress.reverse_flow', {'port': 9})
syn = F.tcp_frame(CL, SV, 2, 100, 0, mss=1460)
out = m.exchange(9, syn, [1, 9, 68], timeout=2.0)
print('out', {p: [x.hex() for x in v] for p, v in out.items()})
print('syn identical:', any(x == syn for v in out.values() for x in v))
for r, f in (('Ingress.counter', 'Ingress.counter.f1'), ('Ingress.owner', 'Ingress.owner.f1'), ('Ingress.epoch', 'Ingress.epoch.f1'), ('Ingress.client', 'Ingress.client.f1'), ('Ingress.work.work', None)):
    print(r, m.register_read(r, 0, f))

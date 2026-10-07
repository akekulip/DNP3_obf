import os, sys
HERE = os.path.dirname(os.path.abspath(__file__)); CORE = os.path.dirname(HERE); ARCH = os.path.abspath(os.path.join(CORE, '..', '..'))
sys.path[:0] = [HERE, CORE, os.path.join(ARCH, 'protocol/payload_mapping/tests'), os.path.join(ARCH, 'protocol/egress/tests'), os.path.join(ARCH, 'protocol/egress'), os.path.join(ARCH, 'protocol/tests'), os.path.join(ARCH, 'tests')]
from model_driver import Model
import test_mapping as TM
m = Model(ports=[1, 9, 64]); MASK = 0xffffffff
TUP = {'hdr.ip.src': 0x0a000001, 'hdr.ip.dst': 0x0a000002, 'hdr.tcp.sport': 42000, 'hdr.tcp.dport': 20000}
m.add('Ingress.forward.forwarding', {'ig.ingress_port': 9}, 'Ingress.forward.route', {'port': 1})
base = 1000
m.add('Ingress.forward.connection', TUP, 'Ingress.forward.configure', {'first': base, 'second': base + 35, 'valid': 3, 'direction': 1})
fr = TM.packet(b'', base + 36, 123456)
print('len', len(fr))
out = m.exchange(9, fr, [1], timeout=1.0)
print({p: [x.hex() for x in v] for p, v in out.items()})
print('exp seq', hex(TM.forward(base + 36, base, 3)))

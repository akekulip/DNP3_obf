#!/usr/bin/env python3
"""payload_mapping forward_03 / reverse_12 (private-pass SEQ / ACK+window rewrite) on the model.
Replays the 204 sealed vectors (inputs + independently computed expected packets) at private port 68,
then mutated frames that the README says must be refused (expected: no output)."""
import json, os, struct, sys
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, os.path.dirname(HERE))
import frames as F
from model_driver import Model, Report, same_frame

ARCH = os.path.abspath(os.path.join(HERE, '..', '..', '..'))
VEC = os.path.join(ARCH, 'protocol/payload_mapping/evidence/verification_01/exact_vectors.json')
DIRECTION = int(os.environ['DIRECTION'])
MASK = 0xffffffff
vectors = [v for v in json.load(open(VEC)) if v['direction'] == DIRECTION]
m = Model(ports=[1], enable=True)   # 68 is the pipe-local port the model maps to veth136/137: no $PORT entry
rep = Report(os.environ['PROG'], direction=DIRECTION, vector_file=VEC, vectors=len(vectors))
IN, OUT = 68, 1
KEYS = {'hdr.ip.src': 0x0a000001, 'hdr.ip.dst': 0x0a000002, 'hdr.tcp.sport': 42000, 'hdr.tcp.dport': 20000, 'hdr.work.epoch': 7}

def route(on=True):
    try: m.clear('Ingress.forwarding')
    except Exception: pass
    m.add('Ingress.forwarding', {'ig.ingress_port': IN}, 'Ingress.route' if on else 'Ingress.deny', {'port': OUT} if on else {})

def configure(base, valid, second=None, keys=KEYS):
    try: m.clear('Ingress.connection')
    except Exception: pass
    m.add('Ingress.connection', keys, 'Ingress.configure',
          {'first': base, 'second': (base + 35) & MASK if second is None else second, 'valid': valid, 'direction': DIRECTION})

def send(frame):
    out = m.exchange(IN, frame, [OUT, 9], timeout=0.8, quiet=0.15)
    return [x for v in out.values() for x in v]

route()
for v in vectors:
    configure(v['base'], v['valid'])
    got = send(bytes.fromhex(v['input_packet']))
    exp = bytes.fromhex(v['independent_expected_packet'])
    ok = len(got) == 1 and same_frame(got[0], exp)
    rep.add('%s/base%d/valid%d' % (v['case'], v['base'], v['valid']), 'expected-packet', 'expected-packet' if ok else ('none' if not got else 'different'),
            ok=ok, input=bytes.fromhex(v['input_packet']), expected_packet=exp, got=got[0] if got else b'')

# mutated frames: must not produce output
sel = [v for v in vectors if v['case'] == 'native35' and v['base'] == 1000][0]
base_frame = bytes.fromhex(sel['input_packet'])
def mut(off, xor=1):
    b = bytearray(base_frame); b[off] ^= xor; return bytes(b)
P, IPO, TCP = 16, 30, 50
cases = [('bad_ip_checksum', mut(IPO + 10)), ('ip_version5', mut(IPO, 0x10)), ('ip_ihl6', mut(IPO, 0x03)),
         ('ip_proto_udp', mut(IPO + 9, 0x06 ^ 0x11)), ('ip_fragment', mut(IPO + 6, 0x20)), ('tcp_fin_flag', mut(TCP + 13, 0x01)),
         ('tcp_urgent_nonzero', mut(TCP + 18)), ('tcp_offset6', mut(TCP + 12, 0x10)), ('wrong_epoch', mut(3)),
         ('zero_generation', bytes(base_frame[:4]) + b'\0\0\0\0' + base_frame[8:]), ('reserved_nonzero', mut(15)),
         ('wrong_src_ip', mut(IPO + 15)), ('wrong_sport', mut(TCP + 1)), ('wrong_dport', mut(TCP + 3)),
         ('ethertype_arp', mut(P + 13, 0x06 ^ 0x00))]
configure(sel['base'], sel['valid'])
for name, f in cases:
    got = send(f)
    rep.add('refused/' + name, 'none', 'none' if not got else 'output', input=f, got=got[0] if got else b'')
route(False); configure(sel['base'], sel['valid'])
got = send(base_frame); rep.add('refused/route_denied', 'none', 'none' if not got else 'output', got=got[0] if got else b'')
route(True)
for nm, valid, second in (('valid3_second_wrong_geometry', 3, (sel['base'] + 36) & MASK), ('valid2_invalid_bits', 2, None)):
    configure(sel['base'], valid, second); got = send(base_frame)
    rep.add('refused/' + nm, 'none', 'none' if not got else 'output', got=got[0] if got else b'')
# wrong ingress port must not be accepted at all (port 9 not 68)
configure(sel['base'], sel['valid']); route(True)
m.add('Ingress.forwarding', {'ig.ingress_port': 9}, 'Ingress.route', {'port': OUT})
m.enable_ports([9]); m.ports.append(9)
import time; time.sleep(1.5)
got = [x for v in m.exchange(9, base_frame, [OUT], timeout=0.8).values() for x in v]
rep.add('refused/wrong_ingress_port_9', 'none', 'none' if not got else 'output', got=got[0] if got else b'')
ok = rep.finish(os.path.join(os.environ['OUT'], 'cases.json'))
sys.exit(0 if ok else 1)

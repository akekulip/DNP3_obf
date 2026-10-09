"""Diagnostic only: remove early-stage table sets to test whether logical-table pressure is the wall."""
import sys
from pathlib import Path
sys.path.insert(0, '/home/philip/Projects/DNP3/defense4/timing/case4_architecture/integration/read')
from make_operate_slice import balanced
src = Path(sys.argv[1]).read_text(); out = Path(sys.argv[2]); out.mkdir(parents=True, exist_ok=True)
def stub(text, header, body):
    s = text.index(header); b = text.index('{', s); e = balanced(text, b)
    return text[:b] + '{ ' + body + ' }' + text[e:]
P0 = lambda t: stub(t, 'if (ig_intr_md.ingress_port == 0) {', 'ig_dprsr_md.drop_ctl = 1;')
PK = lambda t: stub(t, 'if (ig_intr_md.ingress_port == PKTGEN_RETURN) {', 'ig_dprsr_md.drop_ctl = 1;')
OFF = lambda t: stub(t, '            if (md.enabled == 0) {', 'ig_dprsr_md.drop_ctl = 1;')
V = {'x1_port0': [P0], 'x2_pktgen': [PK], 'x3_off': [OFF], 'x4_port0_off': [P0, OFF], 'x5_port0_pktgen_off': [P0, PK, OFF]}
for n, fs in V.items():
    t = src
    for f in fs: t = f(t)
    (out / (n + '.p4')).write_text(t); print(n)

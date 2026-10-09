"""Diagnostic-only variants of read_queue_timing.p4 (never production): stub one branch body each."""
import sys
from pathlib import Path
sys.path.insert(0, '/home/philip/Projects/DNP3/defense4/timing/case4_architecture/integration/read')
from make_operate_slice import balanced
src = Path(sys.argv[1]).read_text(); out = Path(sys.argv[2]); out.mkdir(parents=True, exist_ok=True)
def stub(text, header, body='unmatched();'):
    s = text.index(header); b = text.index('{', s); e = balanced(text, s)
    return text[:b] + '{ ' + body + ' }' + text[e:]
V = {
 'v1_tin_resp_no_done_check': lambda t: t.replace(
   """                    md.resp_done_g = resp_done_read.execute(0);
                    if (md.resp_done_g == md.cur_gen) { passthrough_tev_forward(); }
                    else {""", """                    {"""),
 'v2_stub_held_return': lambda t: stub(t, 'if (ig_intr_md.ingress_port == HELD_RETURN) {'),
 'v3_stub_hb_return': lambda t: stub(t, 'if (ig_intr_md.ingress_port == HB_RETURN) {'),
 'v4_stub_t_in': lambda t: stub(t, 'if (ig_intr_md.ingress_port == T_IN) {'),
 'v5_stub_port0': lambda t: stub(t, 'if (ig_intr_md.ingress_port == 0) {'),
 'v7_stub_port0_and_tin_resp_no_done_check': lambda t: V['v1_tin_resp_no_done_check'](V['v5_stub_port0'](t)),
 'v6_stub_pktgen_return': lambda t: stub(t, 'if (ig_intr_md.ingress_port == PKTGEN_RETURN) {'),
}
for n, f in V.items():
    t = f(src); assert t != src, n
    (out / (n + '.p4')).write_text(t)
    print(n)

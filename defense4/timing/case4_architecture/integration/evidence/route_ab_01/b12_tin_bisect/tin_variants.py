"""Diagnostic-only: on top of a port-0-stubbed source, stub one T_IN arm at a time."""
import sys
from pathlib import Path
sys.path.insert(0, '/home/philip/Projects/DNP3/defense4/timing/case4_architecture/integration/read')
from make_operate_slice import balanced
src = Path(sys.argv[1]).read_text(); out = Path(sys.argv[2]); out.mkdir(parents=True, exist_ok=True)
def stub(text, header, body='ig_dprsr_md.drop_ctl = 1;'):
    s = text.index(header); b = text.index('{', s + 1 if text[s] == '}' else s); e = balanced(text, b)
    return text[:b] + '{ ' + body + ' }' + text[e:]
V = {
 't1_req': '} else if (hdr.tev.kind == KIND_REQUEST) {',
 't2_reset': '} else if (hdr.tev.kind == KIND_RESET) {',
 't3_ack': '} else if (hdr.tev.kind == KIND_ACK) {',
 't4_resp': '} else if (hdr.tev.kind == KIND_RESPONSE) {',
 't5_operate': '} else if (hdr.tev.kind == KIND_OPERATE) {',
 't6_off': 'if (md.enabled == 0) {',
}
for n, h in V.items():
    (out / (n + '.p4')).write_text(stub(src, h)); print(n)
# t7: everything in T_IN except the q_reset/epoch/quarantine prologue
t = src
for h in ['} else if (hdr.tev.kind == KIND_REQUEST) {', '} else if (hdr.tev.kind == KIND_RESET) {',
          '} else if (hdr.tev.kind == KIND_ACK) {', '} else if (hdr.tev.kind == KIND_RESPONSE) {',
          '} else if (hdr.tev.kind == KIND_OPERATE) {', 'if (md.enabled == 0) {']:
    t = stub(t, h)
(out / 't7_prologue_only.p4').write_text(t); print('t7_prologue_only')

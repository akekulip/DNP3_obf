"""SCRATCH prototype of the proposed close-path fix. Patches make_n's output in memory; no tracked file changes."""
import sys
from pathlib import Path
INTEG = Path('/home/philip/Projects/DNP3/defense4/timing/case4_architecture/integration')
sys.path[:0] = [str(INTEG / 'core/response_only')]
import make_n, compose, port_map as pm
orig = make_n.generate
CF_OLD = 'm.emit_loop=8w0;tm.ucast_egress_port=m.output_port;}'
CF_NEW = 'm.emit_loop=8w0;tm.ucast_egress_port=m.output_port;tm.bypass_egress=1w0;}'
ACK7_ANCHOR = '(8w3,8w1,8w0,32w0xc0000&&&32w0xffff0000):forward_original();'
ACK7_NEW = ACK7_ANCHOR + '(8w3,8w5,8w0,32w0x70000&&&32w0xffff0000):forward_original();'
SG_OLD = 'actions={seq_ok;seq_resent;seq_replay;NoAction;}size=3;const entries={(32w0,32w0):seq_ok();'
SG_NEW = 'actions={seq_ok;seq_resent;seq_replay;seq_fin;NoAction;}size=5;const entries={(32w0,32w0):seq_ok();(32w1,32w1):seq_fin();(32w1,32w0):seq_fin();'
ACT_OLD = 'action seq_replay(){m.sequence_valid=8w4;}'
ACT_NEW = ACT_OLD + '\naction seq_fin(){m.sequence_valid=8w5;}'
def patched():
    t = orig()
    assert t.count(CF_OLD) == 1 and t.count(ACK7_ANCHOR) == 1 and t.count(SG_OLD) == 1 and t.count(ACT_OLD) == 1
    return t.replace(CF_OLD, CF_NEW).replace(ACK7_ANCHOR, ACK7_NEW).replace(SG_OLD, SG_NEW).replace(ACT_OLD, ACT_NEW)
make_n.generate = patched
mode, out = sys.argv[1], Path(sys.argv[2])
ports = pm.HARDWARE_SHARED_PORT if mode == 'hw' else pm.DEFAULT
src, meta = compose.generate(ports=ports) if mode == 'hw' else compose.generate()
out.write_text(src)
import json; out.with_suffix('.inputs.json').write_text(json.dumps(meta, indent=2) + '\n')
print('wrote', out, mode)

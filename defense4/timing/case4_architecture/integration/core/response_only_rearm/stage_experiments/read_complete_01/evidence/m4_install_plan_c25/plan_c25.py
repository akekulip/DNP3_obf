"""Offline installer plan for m12p_c25 (no hardware): the rows bringup_composite would write for the reference
block's padded and unpadded arms, from the exact 9.13.2 artifacts, plus the compiled pipe-1 READ profile entries.

  python3 plan_c25.py > plan_c25.json
"""
import importlib.util
import json
import re
import sys
from pathlib import Path

REARM = Path(__file__).resolve().parents[4]
OUT = REARM / 'stage_experiments/ctl_timing_01/evidence/m12p_c25/compile_switch_9132/out'
sys.path.insert(0, str(REARM.parent / 'response_only' / 'hw' / 'tests'))
import fixture as fx  # noqa: E402
spec = importlib.util.spec_from_file_location('rearm_bringup_composite', REARM / 'hw' / 'bringup_composite.py')
rbc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rbc)

# the reference block's installer arguments (candidate_campaign plan rc01dry_c25_reference_01), pad-enable per arm
ARGS = ['--master-ip', '192.168.10.61', '--master-port', '60000', '--master-dev', '9', '--relay-ip', '192.168.10.62',
        '--relay-port', '20000', '--relay-dev', '9', '--read-dst', '0x0a00', '--read-src', '0x0100']
rbc.configure(str(OUT))
result = {'build_out': str(OUT.relative_to(REARM)), 'p1_padder_detected': rbc.P1_PAD['enabled'], 'arms': {}}
for pad in (1, 0):
    a = fx.args(*ARGS, '--pad-enable', str(pad))
    ops = rbc.installer.plan(a, fx.PORTS)
    tables = [op.get('table') for op in ops]
    first_n = min(i for i, t in enumerate(tables) if t and t.startswith('p0.n_'))
    p1 = [op for op in ops if op.get('table') == 'p1.x_Egress.p1_conn']
    result['arms']['pad_enable_%d' % pad] = dict(
        rows=len(ops), p1_conn_rows=p1, p1_before_first_n=all(tables.index(op['table']) < first_n for op in p1),
        tables=sorted(set(t for t in tables if t)))
p4pp = (OUT / 'response_only.p4pp').read_text()
block = re.search(r'table read_profile \{.*?\n    \}', p4pp, re.S)
result['p1_read_profile_table'] = block.group(0) if block else None
print(json.dumps(result, indent=1))

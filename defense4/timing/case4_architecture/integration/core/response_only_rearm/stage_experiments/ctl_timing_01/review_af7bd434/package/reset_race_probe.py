"""Deterministic source-interpreter RST/response spacing probe; no SDK or hardware."""
import json,sys
from pathlib import Path
ct=Path(sys.argv[1]).resolve()/'defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/ctl_timing_01'
sys.path.insert(0,str(ct/'tests'))
import test_m6_lifecycle as l
import contention_source as cs
rows=[]
for kind in ('READ','SELECT'):
 for lap in range(-4,5):
  p,frames,_=l.held(ct/'evidence/m9_01/response_only.p4',kind,rst=l.RST[kind],rst_laps=lap)
  reset=[x for x in p.wire if x[1]==cs.RELAY_PORT and len(x[2])>=48 and x[2][47]&4]
  stage1=l.loop_frames(p,0x0104)
  rows.append(dict(kind=kind,rst_offset_laps=lap,relayed_resets=len(reset),owner_state=l.owner_state(p),
                   reset_stage1_passes=len(stage1),reset_wait_max=max([int.from_bytes(f[14:16],'big') for f in stage1] or [0])))
print(json.dumps(rows,indent=2))

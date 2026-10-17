"""Verify the specialized T refuses unsupported child events at its parser."""
import copy
import json
from pathlib import Path
import sys

repo, generated = map(lambda p: Path(p).resolve(), sys.argv[1:])
ct=repo/'defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/ctl_timing_01'
sys.path.insert(0,str(ct/'tests'))
import contention_source as cs
results=[]
for stage in (1,2,255):
    p=cs.LapPipeline(generated/'t_single_child.p4').handshake()
    p.settle()
    before=copy.deepcopy(p.t.src.cells)
    emitted=len(p.t.emitted); dropped=len(p.t.drops)
    _,_,response=cs.transaction('READ')
    p.t.event(p.now+1000,11,response,epoch=p.t.cell('cur_epoch_reg'),stage=stage)
    p.t.run(p.now+2000)
    assert p.t.src.cells==before, stage
    assert len(p.t.emitted)==emitted, stage
    assert len(p.t.drops)==dropped+1, stage
    results.append({'child':stage,'pass':True,'reason':str(p.t.drops[-1])})
(generated/'single_child_negatives.json').write_text(json.dumps(results,indent=2)+'\n')
print('3 negative child-event checks passed')

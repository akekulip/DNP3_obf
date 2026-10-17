"""Counterexamples for incomplete required coverage; temporary copies only."""
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile

repo=Path(sys.argv[1]).resolve()
base=repo/'defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments'
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);return mod
fixtures=load('review_model_fixtures',base/'ctl_timing_01/tests/test_model_summary.py')
iso=load('review_iso',base/'seg61_02/analysis/isolation_v3.py')
out={}
with tempfile.TemporaryDirectory() as temp:
    root=Path(temp)
    b,sha=fixtures.make_build(root)
    fixtures.all_pass_v2(root,b,sha,points=fixtures.NEG[:1])
    result=fixtures.ms.summarize_v2(b)
    out['three_missing_abort_negatives']=dict(actual=result['qualification'],
       expected='blocked: required READ/SELECT x 48/50 matrix is incomplete', reasons=result['blocked_reasons'])
with tempfile.TemporaryDirectory() as temp:
    src=base/'seg61_02/evidence/hw_campaigns/ctl_m9_iso20_poll_950_01'
    dst=Path(temp)/src.name
    shutil.copytree(src,dst,ignore=shutil.ignore_patterns('*.pcap','*.log'))
    vp=next(dst.glob('*/*/*/isolation_verdict.json'))
    data=json.loads(vp.read_text());data['connections']={'c1':data['connections']['c1']}
    vp.write_text(json.dumps(data))
    result=iso.recompute(dst)
    out['missing_c2_c3']=dict(actual=result['traffic_correct']['verdict'],
       expected='FAIL: new-connection evidence absent',detail=result['traffic_correct'])
print(json.dumps(out,indent=2))

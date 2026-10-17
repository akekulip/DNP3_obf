"""Differential SOURCE-INTERPRETER tests only; not bf-p4c or compiled-model evidence."""
import hashlib
import json
from pathlib import Path
import sys
import time

repo, generated = map(lambda x: Path(x).resolve(), sys.argv[1:])
ct = repo/'defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/ctl_timing_01'
sys.path.insert(0, str(ct/'tests'))
import contention_source as cs

baseline = ct/'evidence/m9_01/response_only.p4'
results = []
started = time.time()
for kind in ('READ','SELECT','OPERATE'):
    for offset in (0,1,3,6):
        ref = cs.contended(baseline,kind,offset)
        assert cs.delivered_once_after_ack(ref), (kind,offset,'reference not delivered')
        for name in ('n_bank_diffs','t_single_child','n_zero_unused_timestamp'):
            cand = cs.contended(generated/(name+'.p4'),kind,offset)
            for key in ('master','busy','outcomes','owner_state'):
                assert cand[key] == ref[key], (name,kind,offset,key)
            assert cs.delivered_once_after_ack(cand)
            # N/E state must match exactly. T may omit precisely the two removed banks.
            for role in ('n','e','t'):
                a_obj = getattr(ref['pipeline'],role)
                a = dict((a_obj if role == 'e' else a_obj.src).cells)
                b_obj = getattr(cand['pipeline'],role)
                b = dict((b_obj if role == 'e' else b_obj.src).cells)
                if role == 't' and name == 't_single_child':
                    for bank in ('child_seen1_reg','child_seen2_reg'): a.pop(('',bank),None)
                assert a == b, (name,kind,offset,role,'state')
            results.append({'probe':name,'kind':kind,'ack_response_spacing_laps':offset,'pass':True})
        print(kind,offset,'all three pass',flush=True)
report = {'instrument':'repository source interpreter; not compiler/model/silicon',
          'baseline_sha256':hashlib.sha256(baseline.read_bytes()).hexdigest(),
          'elapsed_seconds':time.time()-started,'passed':len(results),'cases':results}
(generated/'differential_results.json').write_text(json.dumps(report,indent=2)+'\n')

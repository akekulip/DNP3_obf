import csv
import json
from pathlib import Path
import re
import shutil

import pytest
from defense4.timing.latency_search import summarize_random as s

SOURCE = Path(__file__).resolve().parents[1] / 'evidence/randomized/random_pilot_20260926T181059Z'

@pytest.fixture
def run(tmp_path):
    path=tmp_path/'run'
    shutil.copytree(SOURCE,path)
    return path


def protected(run):
    return next((run/'collected_blocks').glob('*joint*'))


def test_actual_captures_join_selected_values_and_hash_raw_inputs(run,tmp_path):
    result=s.summarize_run(run,out_dir=tmp_path/'out')
    assert result['status']=='ok' and result['row_count']==60
    rows=list(csv.DictReader((tmp_path/'out/primarytransactions.csv').open()))
    assert {r['arm'] for r in rows}=={'native','obfuscated'}
    assert {r['session'] for r in rows}=={'replicate_00'}
    assert sum(r['arm']=='obfuscated' for r in rows)==30
    assert {r['policy_name'] for r in rows}=={'OFF','da12_gap4_joint_amp0p5'}
    digests={s._request_key(r):r for r in s._read_jsonl(protected(run)/'digests.jsonl')}
    for row in rows:
        if row['arm']=='native':
            assert row['selected_da_ms']==''
            continue
        key=(int(row['tcp_src_port']),int(row['tcp_seq']),int(row['func']))
        assert float(row['selected_da_ms'])==digests[key]['selected_d_ticks']/1e6
        assert float(row['selected_r_ms'])==digests[key]['selected_da_dr_ticks']/1e6
    assert any(k.endswith('.pcapng') for k in result['inputs_sha256'])
    assert all(x['safety_polls']==2 for x in result['blocks'].values())


def test_missing_digest_rejected(run,tmp_path):
    p=protected(run)/'digests.jsonl';lines=p.read_text().splitlines();p.write_text('\n'.join(lines[:-1])+'\n')
    with pytest.raises(s.RandomSummaryError,match='missing digest'):
        s.summarize_run(run,out_dir=tmp_path/'out')


def test_wrong_fixed_readback_rejected(run,tmp_path):
    p=next(run.glob('*joint*_fixed_readback.json'));d=json.loads(p.read_text());d['tbl_params']['d_ticks']=256;p.write_text(json.dumps(d))
    with pytest.raises(s.RandomSummaryError,match='fixed readback'):
        s.summarize_run(run,out_dir=tmp_path/'out')


def test_capture_loss_rejected(run,tmp_path):
    p=protected(run)/'logs/capture.log'
    p.write_text(re.sub(r'(Packets received/dropped on interface .*?:\s*\d+/)0',r'\g<1>1',p.read_text()))
    with pytest.raises(s.RandomSummaryError,match='capture loss'):
        s.summarize_run(run,out_dir=tmp_path/'out')


def test_failed_and_unrestored_runs_cannot_be_complete(run,tmp_path):
    (run/'final_status.json').unlink()
    with pytest.raises(s.RandomSummaryError,match='complete'):
        s.summarize_run(run,out_dir=tmp_path/'out')
    result=s.summarize_run(run,out_dir=tmp_path/'partial',allow_partial=True)
    assert result['status']=='partial'
    (run/'failure.json').write_text('{"error":"failed"}')
    with pytest.raises(s.RandomSummaryError,match='failed run'):
        s.summarize_run(run,out_dir=tmp_path/'out')


def test_selection_corruption_rejected_and_requests_rederived_from_capture(run,tmp_path):
    b=protected(run)
    (b/'requests.jsonl').write_text('{"forged":true}\n')
    assert s.summarize_run(run,out_dir=tmp_path/'out')['row_count']==60
    p=b/'digests.jsonl';d=s._read_jsonl(p);d[0]['selected_d_ticks']+=256
    p.write_text(''.join(json.dumps(x)+'\n' for x in d))
    with pytest.raises(s.RandomSummaryError,match='selected ticks'):
        s.summarize_run(run,out_dir=tmp_path/'bad')

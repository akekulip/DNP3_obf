import hashlib
import re
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('split_generate', HERE / 'generate.py')
gen = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gen)


def generated(tmp_path):
    gen.write(tmp_path)
    return (tmp_path / 'response_only.p4').read_text(), json.loads((tmp_path / 'counter_semantics.json').read_text())


def test_frozen_input_pin():
    raw = gen.SOURCE.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == gen.SOURCE_SHA256


def test_split_banks_replace_single_sink(tmp_path):
    text, proof = generated(tmp_path)
    assert 'table outcome_count' not in text
    assert 'outcome_count.apply()' not in text
    for bank in gen.BANKS:
        assert f'Register<bit<32>, bit<5>>(25, 0) outcomes_{bank};' in text
        assert f'action count_{bank}(bit<5> idx)' in text
    assert proof['control_plane_sum_rule'] == 'logical_outcome[i] = outcomes_tin[i] + outcomes_token[i] + outcomes_held[i] + outcomes_hb[i]'


def test_all_25_counter_meanings_preserved(tmp_path):
    _, proof = generated(tmp_path)
    meanings = proof['counter_meanings']
    assert set(meanings) == {str(i) for i in range(25)}
    assert meanings['0'] == 't_OUT_UNMATCHED'
    assert meanings['15'] == 't_OUT_GEN_EXHAUSTED'
    assert meanings['23'] == 't_OUT_RAW_OP_STALE'
    assert meanings['24'] == 't_OUT_RAW_READ_STALE'
    for idx in range(25):
        assert set(proof['bank_inverse'][str(idx)]) == set(gen.BANKS)
        assert set(proof['bank_inverse'][str(idx)].values()) == {meanings[str(idx)]}


def test_no_generic_t_count_calls_remain(tmp_path):
    text, _ = generated(tmp_path)
    assert 'count(t_OUT_' not in text
    assert 'count((bit<32>)index)' not in text
    assert 'action count(bit<32> code)' not in text


def test_shared_actions_are_table_specific(tmp_path):
    text, proof = generated(tmp_path)
    for action, bank in proof['action_bank'].items():
        assert f'action {action}' in text
        assert action in sum((actions for actions in proof['table_actions'].values()), []) or action in {'bypass_request', 'drop_duplicate_response'}
    assert not re.search(r'(?<![A-Za-z0-9_])stop_blocking_stale;', text)
    assert not re.search(r'(?<![A-Za-z0-9_])stop_blocking_tmo;', text)
    assert not re.search(r'(?<![A-Za-z0-9_])stop_blocking_off;', text)
    assert 'unmatched; drop_old_epoch' not in text
    assert 'action rewait_operate() {\n        ig_tm_md.ucast_egress_port = t_HB_RETURN; ig_tm_md.qid = 2;\n        count_hb((bit<5>)t_OUT_HELD_REWAIT);' in text
    assert 'action flush_operate_stale() {\n        export_held(); ig_tm_md.ucast_egress_port = t_RELAY_PORT;\n        count_hb((bit<5>)t_OUT_HELD_STALE_FLUSH);' in text
    assert 'action flush_operate_off() {\n        export_held(); ig_tm_md.ucast_egress_port = t_RELAY_PORT;\n        count_hb((bit<5>)t_OUT_HELD_OFF_FLUSH);' in text

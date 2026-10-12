import importlib.util
import json
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location('delay_read_tokens', Path(__file__).resolve().parents[1] / 'delay_read_tokens.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def fresh():
    return dict(module.EXPECTED, ipg=0, trigger_counter=0, batch_counter=0, pkt_counter=0)


def test_only_fresh_expected_read_app_can_be_delayed():
    module.check_app(fresh())
    for key, value in [('pattern_value', 0xe1010000), ('app_enable', False),
                       ('trigger_counter', 1), ('packets_per_batch_cfg', 7)]:
        wrong = fresh(); wrong[key] = value
        with pytest.raises(ValueError):
            module.check_app(wrong)


def test_restore_waits_for_single_complete_old_batch():
    entry = fresh(); entry.update(trigger_counter=1, batch_counter=1, pkt_counter=4, ipg=3_000_000_000)
    module.check_app(entry, restore=True)
    for key, value in [('pkt_counter', 3), ('trigger_counter', 2), ('batch_counter', 0)]:
        wrong = dict(entry); wrong[key] = value
        with pytest.raises(ValueError, match='exactly one completed'):
            module.check_app(wrong, restore=True)


def test_ipg_readback_cannot_mask_counter_or_config_reset():
    before = fresh(); after = dict(before, ipg=3_000_000_000)
    module.check_change(before, after, 3_000_000_000)
    after['app_enable'] = False
    with pytest.raises(ValueError, match='beyond IPG'):
        module.check_change(before, after, 3_000_000_000)


def test_live_bfrt_must_match_whole_pinned_schema():
    schema = {'tables': [{'name': 'p0.r_Egress.epoch', 'id': 123}], 'learn_filters': []}
    assert len(module.compare_schema(schema, json.dumps(schema, indent=2).encode())) == 64
    wrong = {'tables': [{'name': 'p0.r_Egress.epoch', 'id': 124}], 'learn_filters': []}
    with pytest.raises(ValueError, match='differs from pinned'):
        module.compare_schema(schema, json.dumps(wrong).encode())


def test_ipg_configuration_has_trigger_action_and_replays_config_without_counters_or_enable():
    before = dict(fresh(), ibg=0, ibg_jitter=0, ipg_jitter=0,
                  increment_source_port=False, pkt_buffer_offset=0, pkt_len=60)
    op = module.ipg_operation(before, 2_500_000_000)
    assert op['kind'] == 'pktgen_app' and op['action'] == 'trigger_recirc_pattern'
    fields = dict(op['data'])
    assert fields['ipg'] == 2_500_000_000
    assert not set(fields) & (set(module.COUNTERS) | {'app_enable', 'action_name', 'is_default_entry'})
    assert {key: value for key, value in fields.items() if key != 'ipg'} == {
        key: value for key, value in before.items()
        if key not in set(module.COUNTERS) | {'ipg', 'app_enable', 'action_name', 'is_default_entry'}}
    del before['pkt_len']
    with pytest.raises(ValueError, match='missing'):
        module.ipg_operation(before, 2_500_000_000)


def test_ipg_change_disables_only_the_idle_app_and_preserves_counters_when_reenabled():
    before = dict(fresh(), ibg=0, ibg_jitter=0, ipg_jitter=0,
                  increment_source_port=False, pkt_buffer_offset=0, pkt_len=60)
    class Switch:
        def __init__(self):
            self.current = dict(before)
            self.operations = []

        def write(self, op):
            fields = dict(op['data'])
            if op['kind'] == 'pktgen_app':
                assert self.current['app_enable'] is False
                assert not set(fields) & set(module.COUNTERS)
            else:
                assert set(fields) == {'app_enable'}
            self.operations.append(op)
            self.current.update(fields)

        def must_get(self, *args):
            return dict(self.current)
    sw = Switch()
    after = module.change_ipg(sw, before, 2_500_000_000)
    assert len(sw.operations) == 3
    assert after == dict(before, ipg=2_500_000_000)

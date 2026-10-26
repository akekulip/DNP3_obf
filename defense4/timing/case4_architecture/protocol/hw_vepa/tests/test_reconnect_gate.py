"""Reconnect verdicts require complete independent endpoint and extractor evidence."""
import copy
import json
from pathlib import Path

import pytest

from test_checks import evidence
from test_campaign_bindings import cfg_for
import test_campaign_run  # noqa: F401  # installs campaign standards checker fakes for direct verdict tests
import campaign as cp


class Extractors:
    dry = False
    def __init__(self, entries, wire_rc=0, clrt_rc=0):
        self.entries, self.wire_rc, self.clrt_rc = entries, wire_rc, clrt_rc
    def run(self, where, cmd, **kw):
        path = Path(cmd.split('--json ')[1].strip("'"))
        entry = self.entries[path.parent.name]
        kind = 'wire' if path.name == 'wire.json' else 'timing'
        path.write_text(json.dumps(entry[kind]))
        return cp.Result(self.wire_rc if kind == 'wire' else self.clrt_rc, '', '')


def verdict(tmp_path, padding=1, policy='characterize', mutate=None, wire_rc=0, clrt_rc=0, switch_mutate=None, fixture='separate_ack', T=1):
    cfg = cfg_for(tmp_path / 'build', 'match')
    cfg['scenarios']['reconnect']['policy'] = policy
    entries = {'c1': evidence(padding, T, fixture, reads=20), 'c2': evidence(0, T, fixture, reads=20),
               'c3': evidence(padding, T, fixture, reads=20)}
    if mutate:
        mutate(entries)
    dest = tmp_path / 'trial'
    for name, entry in entries.items():
        d = dest / name
        d.mkdir(parents=True)
        for kind in ('master', 'outstation'):
            (d / (kind + '.json')).write_text(json.dumps(entry[kind]))
        for name in ('out.pcap', 'in.pcap'):
            (d / name).write_bytes(b'synthetic capture')
    switch = evidence(padding, T, fixture, reads=40)
    if T:
        switch['after']['outcomes']['OUT_OP_RELEASE'] += 1
        switch['after']['pktgen']['OPERATE']['trigger_counter'] += 1
        switch['after']['pktgen']['OPERATE']['pkt_counter'] += 4
    if switch_mutate:
        switch_mutate(switch)
    (dest / 'snapshots').mkdir()
    for name in ('before', 'after'):
        (dest / 'snapshots' / ('one_' + name + '.json')).write_text(json.dumps(switch[name]))
    runner = Extractors(entries, wire_rc, clrt_rc)
    c = cp.Campaign(cfg, runner, 'one', scenario='reconnect')
    trial = {'label': 'one', 'reads': 20, 'fixture': fixture}
    vision = {'ok': True, 'connections': {name: {'ok': True, 'master_rc': 0} for name in entries}}
    c.verdict_scenario(trial, 'one', str(dest), cp.Result(0, json.dumps(vision), ''), {'name': 'combined', 'padding': padding, 'T': T, 'build': cfg['arms'][0]['build']})
    return trial


@pytest.mark.parametrize('padding', [0, 1])
def test_full_sbo_is_valid_per_function_on_native_and_padded_connections(tmp_path, padding):
    trial = verdict(tmp_path, padding=padding)
    assert trial['ok'], trial['failures']


@pytest.mark.parametrize('extractor', ['wire', 'clrt'])
def test_extractor_nonzero_exit_cannot_be_overridden_by_good_json(tmp_path, extractor):
    trial = verdict(tmp_path, **{extractor + '_rc': 1})
    assert not trial['ok']
    assert any(extractor in failure for failure in trial['failures'])


@pytest.mark.parametrize('field,value', [('points_received', 22), ('matches_seed', False)])
def test_each_read_must_return_all_23_correct_seed_points(tmp_path, field, value):
    def mutate(entries):
        entries['c1']['master']['reads'] = copy.deepcopy(entries['c1']['master']['reads'])
        entries['c1']['master']['reads'][4][field] = value
    trial = verdict(tmp_path, mutate=mutate)
    assert not trial['ok']
    assert any('seed' in failure for failure in trial['failures'])


@pytest.mark.parametrize('key,value', [('operate_real', 2), ('select_decoy', 1), ('operate_decoy', 1)])
def test_sbo_is_exactly_once_real_and_zero_decoy(tmp_path, key, value):
    trial = verdict(tmp_path, mutate=lambda entries: entries['c1']['outstation'].update({key: value}))
    assert not trial['ok']
    assert any(key in failure for failure in trial['failures'])


@pytest.mark.parametrize('kind', ['master', 'outstation', 'wire', 'timing'])
def test_malformed_evidence_fails_without_crashing(tmp_path, kind):
    trial = verdict(tmp_path, mutate=lambda entries: entries['c1'].update({kind: []}))
    assert not trial['ok']
    assert any(kind in failure for failure in trial['failures'])


def test_protected_c3_native_bypass_fails(tmp_path):
    trial = verdict(tmp_path, policy='protected', mutate=lambda entries: entries.update(c3=evidence(0, reads=20)))
    assert not trial['ok']
    assert any('c3' in failure for failure in trial['failures'])


def test_protected_c3_uses_the_selected_arm_padding_policy(tmp_path):
    trial = verdict(tmp_path, policy='protected')
    assert trial['ok'], trial['failures']
    assert trial['scenario']['policy'] == 'protected'


def test_protected_c3_clrt_far_from_the_gap_is_reported_never_failed(tmp_path):
    def mutate(entries):
        for row in entries['c3']['timing']['exchanges']:
            if row['kind'] == 'READ':
                row['clrt_us'] = 5000
    trial = verdict(tmp_path, padding=0, policy='protected', mutate=mutate)
    assert trial['ok'], trial['failures']
    c3 = trial['scenario']['connections']['c3']
    assert 'read_precision' not in c3
    assert set(c3['visible_clrt']['READ']['values_us']) == {5000}


def test_reconnect_policy_cli_is_exposed():
    with pytest.raises(SystemExit) as exc:
        cp.main(['validate', '--reconnect-policy', 'bad'])
    assert exc.value.code == 2


@pytest.mark.parametrize('malformed', [{'summary': []}, {'summary': {'READ': []}},
                                     {'summary': {'READ': {'resp_len': [None, 'bad']}}}])
def test_malformed_nested_timing_is_reported_without_crashing(tmp_path, malformed):
    trial = verdict(tmp_path, mutate=lambda entries: entries['c1'].update(timing=malformed))
    assert not trial['ok']


@pytest.mark.parametrize('snapshot', ['before', 'after'])
def test_protected_reconnect_requires_readable_switch_snapshots(tmp_path, snapshot):
    trial = verdict(tmp_path, policy='protected', switch_mutate=lambda ev: ev.update({snapshot: None}))
    assert not trial['ok']
    assert any(snapshot + ' snapshot' in f for f in trial['failures'])


def test_protected_reconnect_checks_both_installed_connections_in_switch_counters(tmp_path):
    trial = verdict(tmp_path, policy='protected')
    assert trial['ok'], trial['failures']
    observed = trial['scenario']['switch_observed']
    assert observed['pktgen']['READ'] == {'triggers': 40, 'pkts': 160}
    assert observed['pktgen']['OPERATE'] == {'triggers': 2, 'pkts': 8}
    assert observed['outcomes']['OUT_OP_RELEASE'] == 2


@pytest.mark.parametrize('fault', ['stale', 'one_connection_counts', 'pktgen', 'loop'])
def test_protected_reconnect_rejects_switch_faults_with_good_endpoint_json(tmp_path, fault):
    def mutate(ev):
        if fault == 'stale':
            ev['after']['outcomes']['OUT_TOKEN_STALE'] += 1
        elif fault == 'one_connection_counts':
            ev['after']['outcomes']['OUT_ACK_COMMIT'] -= 20
        elif fault == 'pktgen':
            ev['after']['pktgen']['OPERATE']['trigger_counter'] -= 1
        else:
            ev['after']['loop_ports']['t_in']['$OctetsReceived'] += 1
    trial = verdict(tmp_path, policy='protected', switch_mutate=mutate)
    assert not trial['ok']
    assert any('switch:' in f for f in trial['failures'])


def test_failed_native_connection_makes_c3_not_comparable(tmp_path):
    trial = verdict(tmp_path, policy='protected', mutate=lambda entries: entries['c2']['master'].update(success=False))
    assert not trial['ok']
    assert trial['scenario']['connections']['c3']['comparable'] is False


def test_protected_piggyback_counts_only_installed_complete_reads_and_fallbacks(tmp_path):
    trial = verdict(tmp_path, policy='protected', fixture='piggyback')
    assert trial['ok'], trial['failures']
    delta = trial['scenario']['switch_observed']['outcomes']
    assert delta['OUT_ACK_COMMIT'] == delta['OUT_RESP_RELEASE'] == 0
    assert delta['OUT_ACK_FALLBACK'] == 0
    assert delta['OUT_RESP_FALLBACK'] == 40


def test_protected_toff_requires_zero_switch_activity(tmp_path):
    trial = verdict(tmp_path, policy='protected', T=0)
    assert trial['ok'], trial['failures']
    assert trial['scenario']['switch_observed']['pktgen']['READ'] == {'triggers': 0, 'pkts': 0}
    assert trial['scenario']['switch_observed']['outcomes']['OUT_OP_RELEASE'] == 0


@pytest.mark.parametrize('field', ['complete', 'piggyback'])
def test_malformed_protected_summary_count_fails_without_crashing(tmp_path, field):
    trial = verdict(tmp_path, policy='protected',
                    mutate=lambda entries: entries['c3']['timing']['summary']['READ'].update({field: 'bad'}))
    assert not trial['ok']

"""The candidate61 profile verdict as the campaign writes and validates it: bound to the same run, trial,
build, configuration and captures as standards.json, and failing closed on any mismatch or mutation."""
import copy
import json
import shutil
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE.parent), str(HERE)]
import campaign as cp  # noqa: E402
import standards  # noqa: E402

C4 = HERE.parents[2]
READ_REENCODE = C4 / 'integration/core/response_only_rearm/stage_experiments/read_reencode_01'
SMOKE = (C4 / 'integration/core/response_only_rearm/stage_experiments/seg61_02/evidence/hw_campaigns/'
         'candidate61_fourarm_smoke_03/separate_ack')
CHECKER = READ_REENCODE / 'profile_check.py'
pytestmark = pytest.mark.skipif(
    not (SMOKE / 'combined/candidate61_fourarm_smoke_03_separate_ack_combined_t0/in.pcap').is_file(),
    reason='retained candidate61 smoke captures absent (source-only export)')
sys.path.insert(0, str(READ_REENCODE / 'tests'))


def trial_dir(arm):
    return SMOKE / arm / ('candidate61_fourarm_smoke_03_separate_ack_%s_t0' % arm)


def context_for(arm='combined', label='t0', bfrt='b' * 64):
    padding = 1 if arm in ('size_only', 'combined') else 0
    cfg = {'arms': [{'name': arm, 'padding': padding, 'T': int(arm in ('timing_only', 'combined')),
                     'build': 'rearm_61_full04'}],
           'builds': {'rearm_61_full04': {'image_len': 61, 'control_padding': True, 'profile': 'candidate61',
                                          'hashes': {'bfrt.json': bfrt}}},
           'traffic': {'run_sbo': True}}
    return {'config': cfg, 'run_record': {'run_id': 'run-a', 'builds': {}}, 'trial': {'label': label, 'reads': 20},
            'connection_id': None, 'arm': cfg['arms'][0], 'checker_files': [], 'candidate_source_sha256': 'a' * 64}


def staged(tmp_path, arm='combined'):
    for name in ('in.pcap', 'out.pcap'):
        shutil.copy(trial_dir(arm) / name, tmp_path / name)
    port = json.load(open(trial_dir(arm) / 'standards.json'))['observed']['checker_result']['master_port']
    return {'in': {'path': str(tmp_path / 'in.pcap')}, 'out': {'path': str(tmp_path / 'out.pcap')}}, port


def campaign():
    c = cp.Campaign.__new__(cp.Campaign)
    c.cfg = {'endpoints': {'outstation_port': 20000}}
    return c


def lengths(context):
    return standards.expected_identity(context)['expected']['lengths']


@pytest.mark.parametrize('arm', ['off', 'timing_only', 'size_only', 'combined'])
def test_retained_arm_passes_and_binds(tmp_path, arm):
    context = context_for(arm)
    captures, port = staged(tmp_path, arm)
    result = campaign().validate_profile_file(str(tmp_path), context, captures, lengths(context), port)
    assert result['ok'] is True, result['failures']
    art = json.load(open(tmp_path / 'profile_verdict.json'))
    assert art['run']['trial'] == 't0' and art['identity']['profile'] == 'candidate61'
    assert art['result']['attempts'] == 22


def test_alternate_legal_read_layout_in_the_capture_is_rejected(tmp_path):
    from test_profile_check import alt_read
    import capture
    context = context_for()
    captures, port = staged(tmp_path)
    natives = [r['payload'] for r in capture.tcp_records(str(tmp_path / 'out.pcap'))
               if r['payload'] and r['src'][1] == 20000]
    data = (tmp_path / 'in.pcap').read_bytes()
    wire = [r['payload'] for r in capture.tcp_records(str(tmp_path / 'in.pcap')) if r['payload'] and r['src'][1] == 20000]
    mutated = alt_read(natives[0])
    assert len(mutated) == len(wire[0]) == 61 and data.count(wire[0]) == 1
    (tmp_path / 'in.pcap').write_bytes(data.replace(wire[0], mutated))
    result = campaign().validate_profile_file(str(tmp_path), context, captures, lengths(context), port)
    assert result['ok'] is False
    assert any('profile not conformant' in f for f in result['failures'])


def test_native_lengths_on_a_padded_arm_are_rejected(tmp_path):
    context = context_for('combined')
    captures, port = staged(tmp_path, 'off')                 # native 49/37 captures under a 61/61/61 claim
    result = campaign().validate_profile_file(str(tmp_path), context, captures, lengths(context), port)
    assert result['ok'] is False


@pytest.mark.parametrize('field, other', [('trial', context_for(label='t1')),
                                          ('build', context_for(bfrt='c' * 64)),
                                          ('arm', context_for('size_only'))])
def test_copied_verdict_from_another_trial_or_build_is_rejected(tmp_path, field, other):
    context = context_for()
    captures, port = staged(tmp_path)
    assert campaign().validate_profile_file(str(tmp_path), context, captures, lengths(context), port)['ok']
    result = standards.validate_profile(str(tmp_path / 'profile_verdict.json'), other, captures, CHECKER)
    assert result['ok'] is False, field
    assert any('mismatch' in f for f in result['failures'])


def test_capture_replaced_after_the_verdict_is_rejected(tmp_path):
    context = context_for()
    captures, port = staged(tmp_path)
    campaign().validate_profile_file(str(tmp_path), context, captures, lengths(context), port)
    with open(tmp_path / 'in.pcap', 'ab') as f:
        f.write(b'\0')
    result = standards.validate_profile(str(tmp_path / 'profile_verdict.json'), context, captures, CHECKER)
    assert any('captures.in.sha256' in f for f in result['failures'])


@pytest.mark.parametrize('mutate', ['missing', 'failed', 'counts'])
def test_missing_failed_or_altered_verdicts_are_rejected(tmp_path, mutate):
    context = context_for()
    captures, port = staged(tmp_path)
    campaign().validate_profile_file(str(tmp_path), context, captures, lengths(context), port)
    path = tmp_path / 'profile_verdict.json'
    art = json.load(open(path))
    if mutate == 'missing':
        path.unlink()
    elif mutate == 'failed':
        art['result']['conformant'] = False
        path.write_text(json.dumps(art))
    else:
        art['result']['counts'] = {'READ': 19, 'SELECT': 1, 'OPERATE': 1}
        path.write_text(json.dumps(art))
    assert standards.validate_profile(str(path), context, captures, CHECKER)['ok'] is False


def test_wrong_master_port_or_missing_capture_fails_closed(tmp_path):
    context = context_for()
    captures, port = staged(tmp_path)
    assert campaign().validate_profile_file(str(tmp_path), context, captures, lengths(context), port + 1)['ok'] is False
    (tmp_path / 'out.pcap').unlink()
    assert campaign().validate_profile_file(str(tmp_path), context, captures, lengths(context), port)['ok'] is False


def test_profile_is_required_only_for_candidate61_builds():
    assert standards.profile_required(context_for())
    strict = copy.deepcopy(context_for())
    strict['config']['builds']['rearm_61_full04'].update(profile='strict_comparison', image_len=58)
    assert not standards.profile_required(strict)


def test_every_runner_inherits_the_profile_gate():
    sys.path.insert(0, str(C4 / 'integration/evidence/rearm_01/hw'))
    import candidate_campaign, candidate_series, candidate_isolation, candidate_external  # noqa: E401
    for cls in (candidate_campaign.CandidateCampaign, candidate_series.CandidateSeriesCampaign,
                candidate_isolation.TokenIsolationCampaign, candidate_external.ExternalIsolationCampaign):
        assert cls.validate_standards_file is cp.Campaign.validate_standards_file, cls
        assert cls.validate_profile_file is cp.Campaign.validate_profile_file, cls


def test_profile_verdict_is_bound_to_the_commanded_master_port(tmp_path):
    context = context_for()
    captures, port = staged(tmp_path)
    context['master_port'] = port
    assert campaign().validate_profile_file(str(tmp_path), context, captures, lengths(context), port)['ok']
    other = dict(context, master_port=port + 7)
    result = standards.validate_profile(str(tmp_path / 'profile_verdict.json'), other, captures, CHECKER)
    assert any('result.master_port' in f for f in result['failures'])

"""m5_summary --strict: the aggregate gate exits nonzero and names every reason; report-only mode stays exit 0."""
import hashlib
import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE / 'analysis'))
import m5_summary as ms  # noqa: E402

M5 = ['ctl_m5_char_repeat_sbo_950_b1', 'ctl_m5_held_operate_350_01', 'ctl_m5_held_operate_350_02',
      'ctl_m5_loss_core_950_01', 'ctl_m5_persistence_graceful_950_01', 'ctl_m5_persistence_rst_950_01',
      'ctl_m5_qual_piggyback_950_b1', 'ctl_m5_qual_piggyback_950_b2', 'ctl_m5_qual_piggyback_950_b3',
      'ctl_m5_qual_repeat_sbo_950_b1', 'ctl_m5_qual_repeat_sbo_950_b2', 'ctl_m5_qual_repeat_sbo_950_b3',
      'ctl_m5_reconnect_950_01']
PIGGYBACK = ['ctl_m5_qual_piggyback_950_b1', 'ctl_m5_qual_piggyback_950_b2', 'ctl_m5_qual_piggyback_950_b3']
MEASUREMENT_ONLY = ['ctl_m5_loss_core_950_01', 'ctl_m5_persistence_rst_950_01', 'ctl_m5_persistence_graceful_950_01',
                    'ctl_m5_held_operate_350_02', 'ctl_m5_reconnect_950_01']
ZERO = {'count_busy': [0] * 8, 'count_term': [0] * 4}
THRESHOLDS = {'gap_us': 950.0, 'maximum_p99_absolute_error_us': 100, 'minimum_eligible': 20,
              'p99_convention': 'nearest rank: ceil(0.99 n)-th smallest absolute error'}


def wj(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value))


def write_artifacts(d, qualification):
    """standards_verdict, standards (one required timed objective, one not applicable) and profile_verdict."""
    wj(d / 'standards_verdict.json', {'ok': True, 'failures': [], 'qualification': qualification})
    wj(d / 'standards.json', {'observed': {'objectives': {
        'select_precision': {'required': True, 'status': 'pass', 'evidence': dict(THRESHOLDS, p99=29.0)},
        'piggyback_latency': {'required': False, 'status': 'not_applicable', 'evidence': None}}}})
    wj(d / 'profile_verdict.json', {'result': {'conformant': True, 'failures': []}})


def make_run(runs, name, arm_order=('off', 'combined'), recorded=None, purpose='qualification',
             qualification='qualified', after=None, record_order=True, scenario=False, observed=None):
    root = runs / name
    arms = []
    for arm in (recorded if recorded is not None else arm_order):
        label = '%s_fx_%s_t0' % (name, arm)
        d = root / 'fx' / arm / label
        trial = {'ok': True, 'failures': [], 'qualification': {'trial': qualification}}
        if scenario:
            trial['scenario'] = {}
            trial['qualification'] = {'c1': qualification}
            wj(d / 'scenario.json', {'ok': True, 'connections': [{'name': 'c1', 'ok': True, 'failures': []}]})
            write_artifacts(d / 'c1', qualification)
        else:
            write_artifacts(d, qualification)
        if observed is not None:
            trial['observed'] = observed
        wj(d / 'trial.json', trial)
        wj(d / 'snapshots' / ('%s_before.json' % label), {'n_counters': ZERO})
        wj(d / 'snapshots' / ('%s_after.json' % label), {'n_counters': after or ZERO})
        arms.append({'fixture': 'fx', 'arm': arm, 'trials': [{'label': label, 'ok': True}]})
    evaluation = {'purpose': purpose}
    if record_order:
        evaluation['arm_order'] = list(arm_order)
    wj(root / 'campaign_run.json', {'run_id': name, 'ok': True, 'failure': None, 'arms': arms,
                                    'restore': [{'ok': True}],
                                    'effective': {'evaluation': evaluation, 'fixture': {'modes': ['fx']},
                                                  'trials': {'trials_per_arm': 1}}})
    wj(root / 'restore_verify.json', {'ok': True, 'failures': [], 'run_root': str(root)})
    return root


def edit(path, fn):
    value = json.loads(path.read_text())
    fn(value)
    path.write_text(json.dumps(value))


def strict(tmp_path, *runs, stale=(), extra=()):
    out = tmp_path / 'out.json'
    argv = ['--strict', '--runs-dir', str(tmp_path / 'runs'), '--config-dir', str(tmp_path / 'config'),
            '-o', str(out), '--require', *runs] + (['--expect-stale', *stale] if stale else []) + list(extra)
    rc = ms.main(argv)
    report = json.loads(out.read_text())
    assert report['ok'] is (rc == 0)
    return rc, [r['reason'] for r in report['reasons']]


def test_clean_synthetic_run_passes(tmp_path):
    make_run(tmp_path / 'runs', 'r')
    assert strict(tmp_path, 'r') == (0, [])


def test_missing_run_fails(tmp_path):
    make_run(tmp_path / 'runs', 'r')
    rc, reasons = strict(tmp_path, 'r', 'absent')
    assert rc == 1 and reasons == ['missing run']


def test_missing_artifacts_fail(tmp_path):
    root = make_run(tmp_path / 'runs', 'r')
    (root / 'restore_verify.json').unlink()
    (root / 'fx/off/r_fx_off_t0/standards.json').unlink()
    rc, reasons = strict(tmp_path, 'r')
    assert rc == 1
    assert 'missing artifact restore_verify.json' in reasons
    assert 'r_fx_off_t0: missing artifact standards.json' in reasons


def test_missing_scenario_artifact_fails(tmp_path):
    root = make_run(tmp_path / 'runs', 'r', arm_order=('combined',), scenario=True)
    assert strict(tmp_path, 'r') == (0, [])
    (root / 'fx/combined/r_fx_combined_t0/scenario.json').unlink()
    assert strict(tmp_path, 'r') == (1, ['r_fx_combined_t0: missing artifact scenario.json'])


def test_failed_restore_fails(tmp_path):
    root = make_run(tmp_path / 'runs', 'r')
    wj(root / 'restore_verify.json', {'ok': False, 'failures': ['ping'], 'run_root': str(root)})
    rc, reasons = strict(tmp_path, 'r')
    assert rc == 1 and reasons == ["restore_verify ok=False: ['ping']"]


def test_arm_order_mismatch_and_missing_arm_fail(tmp_path):
    make_run(tmp_path / 'runs', 'swapped', recorded=('combined', 'off'))
    make_run(tmp_path / 'runs', 'short', arm_order=('off', 'timing_only', 'combined'), recorded=('off',))
    rc, reasons = strict(tmp_path, 'swapped', 'short')
    assert rc == 1 and sorted(reasons) == sorted([
        "incomplete block: fixture fx arms ['combined', 'off'], expected ['off', 'combined']",
        "incomplete block: fixture fx arms ['off'], expected ['off', 'timing_only', 'combined']"])


def test_arm_order_from_block_config_when_not_recorded(tmp_path):
    root = make_run(tmp_path / 'runs', 'blk_01', recorded=('combined', 'off'), record_order=False)
    cfg = tmp_path / 'config' / 'blk.json'
    wj(cfg, {'arms': [{'name': 'off'}, {'name': 'combined'}]})
    rec = json.loads((root / 'campaign_run.json').read_text())
    rec['config_file_sha256'] = hashlib.sha256(cfg.read_bytes()).hexdigest()
    wj(root / 'campaign_run.json', rec)
    assert strict(tmp_path, 'blk_01') == (
        1, ["incomplete block: fixture fx arms ['combined', 'off'], expected ['off', 'combined']"])


def test_rejected_qualification_fails(tmp_path):
    make_run(tmp_path / 'runs', 'r', qualification='rejected')
    rc, reasons = strict(tmp_path, 'r')
    assert rc == 1
    assert ("r_fx_off_t0: qualification rejected: trial.json trial='rejected' (accepted: qualified, measurement_only)"
            in reasons)
    assert 'qualification run has no qualified verdict (not named in --measurement-only)' in reasons
    # no purpose exempts a rejected verdict any longer
    make_run(tmp_path / 'runs', 'c', qualification='rejected', purpose='timing_precision_characterization')
    rc, reasons = strict(tmp_path, 'c')
    assert rc == 1 and sorted(set(reasons)) == sorted({
        "c_fx_off_t0: qualification rejected: trial.json trial='rejected' (accepted: qualified, measurement_only)",
        "c_fx_off_t0: qualification rejected: standards_verdict.json='rejected' (accepted: qualified, measurement_only)",
        "c_fx_combined_t0: qualification rejected: trial.json trial='rejected' (accepted: qualified, measurement_only)",
        "c_fx_combined_t0: qualification rejected: standards_verdict.json='rejected' "
        "(accepted: qualified, measurement_only)"})


def test_trial_not_ok_fails(tmp_path):
    root = make_run(tmp_path / 'runs', 'r')
    wj(root / 'fx/off/r_fx_off_t0/trial.json', {'ok': False, 'failures': ['x'], 'qualification': {'trial': 'qualified'}})
    assert strict(tmp_path, 'r') == (1, ["r_fx_off_t0: trial ok=False: ['x']"])


def test_missing_n_counters_fails(tmp_path):
    root = make_run(tmp_path / 'runs', 'r')
    wj(root / 'fx/off/r_fx_off_t0/snapshots/r_fx_off_t0_after.json', {'outcomes': {}})
    assert strict(tmp_path, 'r') == (1, ['r_fx_off_t0: snapshot after lacks n_counters'])


def test_invalid_n_counters_fail(tmp_path):
    root = make_run(tmp_path / 'runs', 'r')
    wj(root / 'fx/off/r_fx_off_t0/snapshots/r_fx_off_t0_after.json',
       {'n_counters': {'count_busy': [0, 0, 0, 0, None], 'count_term': [0]}})
    rc, reasons = strict(tmp_path, 'r')
    assert rc == 1 and reasons[0].startswith('r_fx_off_t0: snapshot after n_counters.count_busy invalid')


def test_nonzero_busy_drop_fails(tmp_path):
    make_run(tmp_path / 'runs', 'r', arm_order=('off',), after={'count_busy': [1, 0, 0, 0, 0, 0, 0, 0],
                                                                'count_term': [0] * 4})
    assert strict(tmp_path, 'r') == (1, ['r_fx_off_t0: busy_drop delta 1 (expected 0)'])


STALE_OK = {'bank_isolation': {'ok': True}, 'old_token_window': {'ok': True}, 'old_rejection_delta': 1}


def test_stale_retry_allowed_only_on_stale_token_trials(tmp_path):
    after = {'count_busy': [0, 0, 0, 0, 2, 0, 0, 0], 'count_term': [0] * 4}
    make_run(tmp_path / 'runs', 's', arm_order=('combined',), after=after, scenario=True, observed=STALE_OK,
             purpose=ms.STALE_PURPOSE)
    assert strict(tmp_path, 's', stale=['s']) == (0, [])
    make_run(tmp_path / 'runs', 'q', arm_order=('combined',), after=after, scenario=True, observed=STALE_OK)
    assert strict(tmp_path, 'q') == (1, ['q_fx_combined_t0: stale_retry delta 2 (expected 0)'])


def test_stale_token_trial_still_gates_busy_drop_exhaustion_and_window(tmp_path):
    after = {'count_busy': [1, 0, 0, 1, 0, 0, 0, 0], 'count_term': [0] * 4}
    make_run(tmp_path / 'runs', 's', arm_order=('combined',), after=after, scenario=True, purpose=ms.STALE_PURPOSE,
             observed={'bank_isolation': {'ok': True}, 'old_token_window': {'ok': False, 'failures': ['w']}})
    rc, reasons = strict(tmp_path, 's', stale=['s'])
    assert rc == 1 and sorted(reasons) == sorted([
        "s_fx_combined_t0: stale-token gate old_token_window not ok: ['w']",
        's_fx_combined_t0: stale-token old_rejection_delta missing',
        's_fx_combined_t0: busy_drop delta 1 (expected 0, stale-token trial)',
        's_fx_combined_t0: retry_exhaustion delta 1 (expected 0, stale-token trial)'])


def test_report_only_mode_exits_zero_on_failures(tmp_path):
    make_run(tmp_path / 'runs', 'ctl_m5_x', qualification='rejected')
    out = tmp_path / 'report.json'
    assert ms.main(['--runs-dir', str(tmp_path / 'runs'), '-o', str(out)]) == 0
    assert isinstance(json.loads(out.read_text()), list)


# ---------------------------------------------------------------- 1. the required set is explicit

def _argv(tmp_path, *extra):
    return ['--strict', '--runs-dir', str(tmp_path / 'runs'), '--config-dir', str(tmp_path / 'config'),
            '-o', str(tmp_path / 'out.json'), *extra]


def test_strict_needs_require_and_a_given_prefix_must_agree(tmp_path):
    make_run(tmp_path / 'runs', 'ctl_m6_x')
    with pytest.raises(SystemExit) as exc:
        ms.main(_argv(tmp_path, '--prefix', 'ctl_m6_'))
    assert exc.value.code == 2
    with pytest.raises(SystemExit):
        ms.main(_argv(tmp_path))
    with pytest.raises(SystemExit):
        ms.main(_argv(tmp_path, '--prefix', 'ctl_m5_', '--require', 'ctl_m6_x'))
    assert not (tmp_path / 'out.json').exists()
    assert ms.main(_argv(tmp_path, '--prefix', 'ctl_m6_', '--require', 'ctl_m6_x')) == 0


# ---------------------------------------------------------------- 2. block completeness

def test_fixture_modes_missing_or_empty_fail_and_are_never_derived(tmp_path):
    root = make_run(tmp_path / 'runs', 'r')
    edit(root / 'campaign_run.json', lambda d: d['effective'].pop('fixture'))
    assert strict(tmp_path, 'r') == (1, ['effective.fixture.modes missing or empty: None'])
    edit(root / 'campaign_run.json', lambda d: d['effective'].__setitem__('fixture', {'modes': []}))
    assert strict(tmp_path, 'r') == (1, ['effective.fixture.modes missing or empty: []'])


def test_configured_fixture_without_recorded_arms_fails(tmp_path):
    root = make_run(tmp_path / 'runs', 'r')
    edit(root / 'campaign_run.json', lambda d: d['effective']['fixture'].__setitem__('modes', ['fx', 'piggy']))
    assert strict(tmp_path, 'r') == (
        1, ["incomplete block: fixture piggy arms [], expected ['off', 'combined']"])


def test_empty_recorded_arm_order_fails(tmp_path):
    root = make_run(tmp_path / 'runs', 'r')
    edit(root / 'campaign_run.json', lambda d: d['effective']['evaluation'].__setitem__('arm_order', []))
    assert strict(tmp_path, 'r') == (1, ['recorded effective.evaluation.arm_order invalid or empty: []'])


def _config_run(tmp_path, cfg, record_sha=True, name='blk_01'):
    root = make_run(tmp_path / 'runs', name, record_order=False)
    path = tmp_path / 'config' / 'blk.json'
    wj(path, cfg)
    if record_sha:
        edit(root / 'campaign_run.json',
             lambda d: d.__setitem__('config_file_sha256', hashlib.sha256(path.read_bytes()).hexdigest()))
    return root, path


def test_empty_config_arms_and_missing_config_sha_fail(tmp_path):
    _config_run(tmp_path, {'arms': []})
    assert strict(tmp_path, 'blk_01') == (1, ['block config blk.json arms invalid or empty: []'])
    _config_run(tmp_path, {'arms': [{'name': 'off'}, {'name': 'combined'}]}, record_sha=False, name='blk_02')
    assert strict(tmp_path, 'blk_02') == (
        1, ['arm order from block config blk.json but campaign_run.json lacks config_file_sha256'])


def test_config_sha_mismatch_fails_and_nn_suffix_is_stripped(tmp_path):
    root, path = _config_run(tmp_path, {'arms': [{'name': 'off'}, {'name': 'combined'}]})
    assert strict(tmp_path, 'blk_01') == (0, [])          # blk_01 found its config as blk.json
    wj(path, {'arms': [{'name': 'off'}, {'name': 'combined'}], 'note': 'edited after the run'})
    assert strict(tmp_path, 'blk_01') == (
        1, ['block config blk.json changed since the run (sha256 differs from config_file_sha256)'])


def test_trials_per_arm_must_be_an_int_of_at_least_one(tmp_path):
    root = make_run(tmp_path / 'runs', 'r')
    edit(root / 'campaign_run.json', lambda d: d['effective'].pop('trials'))
    assert strict(tmp_path, 'r') == (
        1, ['effective.trials.trials_per_arm missing or invalid: None (expected an integer >= 1)'])
    for bad in (0, True, '1'):
        edit(root / 'campaign_run.json', lambda d: d['effective'].__setitem__('trials', {'trials_per_arm': bad}))
        assert strict(tmp_path, 'r') == (
            1, ['effective.trials.trials_per_arm missing or invalid: %r (expected an integer >= 1)' % (bad,)])


def test_arm_without_trials_fails_even_when_trials_per_arm_is_zero(tmp_path):
    root = make_run(tmp_path / 'runs', 'r', arm_order=('off',))

    def strip(d):
        d['effective']['trials']['trials_per_arm'] = 0
        d['arms'][0]['trials'] = []
    edit(root / 'campaign_run.json', strip)
    rc, reasons = strict(tmp_path, 'r')
    assert rc == 1
    assert 'incomplete arm fx/off: 0 trials, expected at least 1' in reasons
    assert 'effective.trials.trials_per_arm missing or invalid: 0 (expected an integer >= 1)' in reasons


def test_trial_without_label_fails(tmp_path):
    root = make_run(tmp_path / 'runs', 'r', arm_order=('off',))
    edit(root / 'campaign_run.json', lambda d: d['arms'][0]['trials'][0].__setitem__('label', None))
    rc, reasons = strict(tmp_path, 'r')
    assert rc == 1 and reasons[0].startswith('arm fx/off records a trial without a label')


# ---------------------------------------------------------------- 3. objectives and thresholds

def _objectives(root, trial, objectives):
    wj(root / 'fx' / trial.split('_fx_')[1].rsplit('_t', 1)[0] / trial / 'standards.json',
       {'observed': {'objectives': objectives}})


def test_required_objective_must_pass_and_others_pass_or_not_applicable(tmp_path):
    root = make_run(tmp_path / 'runs', 'r')
    _objectives(root, 'r_fx_off_t0', {
        'select_precision': {'required': True, 'status': 'deferred', 'evidence': dict(THRESHOLDS, p99=922.0)},
        'operate_hold': {'required': False, 'status': 'fail'},
        'piggyback_latency': {'required': False, 'status': 'unknown'},
        'read_order': {'status': 'pass'}})
    rc, reasons = strict(tmp_path, 'r')
    assert rc == 1 and sorted(reasons) == sorted([
        "r_fx_off_t0: required objective select_precision status 'deferred' (expected pass)",
        "r_fx_off_t0: objective operate_hold status 'fail' (not required: expected pass or not_applicable)",
        "r_fx_off_t0: objective piggyback_latency status 'unknown' (not required: expected pass or not_applicable)",
        'r_fx_off_t0: objective read_order required=None (expected true or false)'])


def test_standards_without_objectives_fail(tmp_path):
    root = make_run(tmp_path / 'runs', 'r', arm_order=('off',))
    wj(root / 'fx/off/r_fx_off_t0/standards.json', {})
    assert strict(tmp_path, 'r') == (1, ['r_fx_off_t0: standards.json has no objectives mapping'])
    wj(root / 'fx/off/r_fx_off_t0/standards.json', {'observed': {'objectives': {}}})
    assert strict(tmp_path, 'r') == (1, ['r_fx_off_t0: standards.json has no objectives mapping'])


def test_timed_objective_needs_its_threshold_record(tmp_path):
    root = make_run(tmp_path / 'runs', 'r', arm_order=('off',))
    _objectives(root, 'r_fx_off_t0', {'select_precision': {'required': True, 'status': 'pass',
                                                           'evidence': {'p99': 29.0, 'gap_us': 950.0}}})
    assert strict(tmp_path, 'r') == (1, [
        'r_fx_off_t0: timed objective select_precision lacks threshold record '
        'maximum_p99_absolute_error_us, minimum_eligible, p99_convention'])


def test_recorded_thresholds_must_be_the_m5_ones(tmp_path):
    root = make_run(tmp_path / 'runs', 'r', arm_order=('off',))
    bad = dict(THRESHOLDS, gap_us=800.0, maximum_p99_absolute_error_us=150, minimum_eligible=10,
               p99_convention='linear interpolation')
    _objectives(root, 'r_fx_off_t0', {'select_precision': {'required': True, 'status': 'pass', 'evidence': bad}})
    edit(root / 'fx/off/r_fx_off_t0/trial.json',
         lambda d: d.__setitem__('observed', {'read_precision': {'gap_us': 900.0, 'minimum_eligible': 20}}))
    rc, reasons = strict(tmp_path, 'r')
    ev = 'r_fx_off_t0: threshold standards.json.observed.objectives.select_precision.evidence'
    assert rc == 1 and sorted(reasons) == sorted([
        'r_fx_off_t0: threshold trial.json.observed.read_precision.gap_us=900.0 (expected 950)',
        ev + '.gap_us=800.0 (expected 950)',
        ev + '.maximum_p99_absolute_error_us=150 (expected 100)',
        ev + '.minimum_eligible=10 (expected 20)',
        ev + ".p99_convention='linear interpolation' (expected 'nearest rank: ceil(0.99 n)-th smallest'...)"])


def test_declared_expected_gap_replaces_950_for_that_run_only(tmp_path):
    root = make_run(tmp_path / 'runs', 'r', arm_order=('off',))
    _objectives(root, 'r_fx_off_t0', {'select_precision': {'required': True, 'status': 'pass',
                                                           'evidence': dict(THRESHOLDS, gap_us=800.0)}})
    assert strict(tmp_path, 'r')[0] == 1                            # undeclared: 800 is a threshold failure
    out = tmp_path / 'o.json'
    args = ['--strict', '--require', 'r', '--runs-dir', str(tmp_path / 'runs'), '--config-dir', str(tmp_path),
            '-o', str(out)]
    assert ms.main(args + ['--expected-gap', 'r=800']) == 0
    assert ms.main(args + ['--expected-gap', 'r=900']) == 1         # a declared gap is still checked exactly


@pytest.mark.parametrize('value', ['r', 'r=', '=800', 'r=0', 'r=-1', 'r=8x'])
def test_expected_gap_argument_is_strict(tmp_path, value):
    with pytest.raises(SystemExit):
        ms.main(['--strict', '--require', 'r', '--expected-gap', value, '-o', str(tmp_path / 'o.json')])


def test_expected_gap_for_an_unrequired_run_is_an_error(tmp_path):
    with pytest.raises(SystemExit):
        ms.main(['--strict', '--require', 'r', '--expected-gap', 'other=800', '-o', str(tmp_path / 'o.json')])


# ---------------------------------------------------------------- 4. scenario trials

def test_scenario_needs_ok_true_and_every_connection_ok(tmp_path):
    root = make_run(tmp_path / 'runs', 'r', arm_order=('combined',), scenario=True)
    sc = root / 'fx/combined/r_fx_combined_t0/scenario.json'
    wj(sc, {'connections': [{'name': 'c1', 'ok': False, 'failures': ['drop']}]})
    assert strict(tmp_path, 'r') == (1, ['r_fx_combined_t0: scenario ok=None',
                                         "r_fx_combined_t0: scenario connection c1 ok=False: ['drop']"])
    wj(sc, {'ok': True, 'connections': {'c1': {'ok': True}, 'c2': {'ok': None}}})
    assert strict(tmp_path, 'r') == (1, ['r_fx_combined_t0: scenario connection c2 ok=None: None'])
    sc.write_text('[]')
    assert strict(tmp_path, 'r') == (1, ['r_fx_combined_t0: artifact scenario.json is not a JSON object (list)'])


def test_scenario_connection_directories_get_the_ordinary_checks(tmp_path):
    root = make_run(tmp_path / 'runs', 'r', arm_order=('combined',), scenario=True)
    c1 = root / 'fx/combined/r_fx_combined_t0/c1'
    wj(c1 / 'standards_verdict.json', {'ok': False, 'failures': ['f'], 'qualification': 'qualified'})
    wj(c1 / 'profile_verdict.json', {'result': {'conformant': False, 'failures': ['p']}})
    wj(c1 / 'standards.json', {'observed': {'objectives': {'operate_hold': {'required': True,
                                                                             'status': 'deferred'}}}})
    rc, reasons = strict(tmp_path, 'r')
    assert rc == 1 and sorted(reasons) == sorted([
        "r_fx_combined_t0: c1/standards verdict ok=False: ['f']",
        "r_fx_combined_t0: c1/profile verdict not conformant: ['p']",
        "r_fx_combined_t0: c1/required objective operate_hold status 'deferred' (expected pass)"])


def test_scenario_without_connection_directories_fails(tmp_path):
    root = make_run(tmp_path / 'runs', 'r', arm_order=('combined',), scenario=True)
    for f in (root / 'fx/combined/r_fx_combined_t0/c1').iterdir():
        f.unlink()
    (root / 'fx/combined/r_fx_combined_t0/c1').rmdir()
    assert strict(tmp_path, 'r') == (1, ['r_fx_combined_t0: scenario trial has no c*/ connection directory'])


# ---------------------------------------------------------------- 5. qualification values and purpose

def test_qualification_verdicts_are_whitelisted(tmp_path):
    root = make_run(tmp_path / 'runs', 'r')
    edit(root / 'fx/off/r_fx_off_t0/trial.json', lambda d: d.__setitem__('qualification', {'trial': None}))
    edit(root / 'fx/off/r_fx_off_t0/standards_verdict.json', lambda d: d.__setitem__('qualification', 'qualifed'))
    edit(root / 'fx/combined/r_fx_combined_t0/trial.json', lambda d: d.pop('qualification'))
    rc, reasons = strict(tmp_path, 'r')
    assert rc == 1 and sorted(reasons) == sorted([
        'r_fx_off_t0: qualification not accepted: trial.json trial=None (accepted: qualified, measurement_only)',
        "r_fx_off_t0: qualification not accepted: standards_verdict.json='qualifed' "
        '(accepted: qualified, measurement_only)',
        'r_fx_combined_t0: trial.json lacks a qualification verdict'])


def test_missing_verdict_is_allowed_only_outside_qualification_purpose(tmp_path):
    root = make_run(tmp_path / 'runs', 'r', arm_order=('off',), purpose='timing_precision_characterization',
                    qualification='measurement_only')
    edit(root / 'fx/off/r_fx_off_t0/trial.json', lambda d: d.pop('qualification'))
    assert strict(tmp_path, 'r') == (0, [])


def test_evaluation_purpose_must_be_known(tmp_path):
    root = make_run(tmp_path / 'runs', 'r', arm_order=('off',))
    edit(root / 'campaign_run.json', lambda d: d['effective']['evaluation'].pop('purpose'))
    assert strict(tmp_path, 'r') == (1, [
        'evaluation purpose None not one of qualification, timing_precision_characterization, '
        'stale_source_characterization'])
    edit(root / 'campaign_run.json', lambda d: d['effective']['evaluation'].__setitem__('purpose', 'qual'))
    assert strict(tmp_path, 'r')[1][0].startswith("evaluation purpose 'qual' not one of")


def test_qualification_run_needs_a_qualified_verdict_unless_measurement_only(tmp_path):
    make_run(tmp_path / 'runs', 'r', qualification='measurement_only')
    assert strict(tmp_path, 'r') == (
        1, ['qualification run has no qualified verdict (not named in --measurement-only)'])
    assert strict(tmp_path, 'r', extra=['--measurement-only', 'r']) == (0, [])
    with pytest.raises(SystemExit):
        strict(tmp_path, 'r', extra=['--measurement-only', 'other'])


# ---------------------------------------------------------------- 6. stale expectations

def test_stale_purpose_and_expect_stale_must_agree(tmp_path):
    after = {'count_busy': [0, 0, 0, 0, 7, 0, 0, 0], 'count_term': [0] * 4}
    make_run(tmp_path / 'runs', 'p', after=after, observed=STALE_OK, purpose=ms.STALE_PURPOSE)
    rc, reasons = strict(tmp_path, 'p')
    assert rc == 1 and sorted(reasons) == sorted([
        'purpose stale_source_characterization but the run is not named in --expect-stale',
        'p_fx_off_t0: stale_retry delta 7 (expected 0)', 'p_fx_combined_t0: stale_retry delta 7 (expected 0)'])
    make_run(tmp_path / 'runs', 'n', observed=STALE_OK)
    assert strict(tmp_path, 'n', stale=['n']) == (1, ["named in --expect-stale but purpose is 'qualification'"])


def test_expect_stale_name_outside_required_set_is_an_argument_error(tmp_path):
    make_run(tmp_path / 'runs', 'r')
    with pytest.raises(SystemExit) as exc:
        strict(tmp_path, 'r', stale=['typo_run'])
    assert exc.value.code == 2


def test_old_rejection_delta_must_be_positive(tmp_path):
    make_run(tmp_path / 'runs', 's', arm_order=('combined',), scenario=True, purpose=ms.STALE_PURPOSE,
             observed=dict(STALE_OK, old_rejection_delta=0))
    assert strict(tmp_path, 's', stale=['s']) == (
        1, ['s_fx_combined_t0: stale-token old_rejection_delta 0 (expected > 0)'])


# ---------------------------------------------------------------- 7. restore_verify belongs to the run

def test_run_root_in_another_checkout_is_the_same_run_only_below_defense4():
    run = '/home/u/repo/defense4/timing/x/hw_campaigns/r1'
    assert ms._same_run(run, Path(run))
    assert ms._same_run('/tmp/wt_ab/defense4/timing/x/hw_campaigns/r1', Path(run))
    assert not ms._same_run('/tmp/wt_ab/defense4/timing/x/hw_campaigns/r2', Path(run))
    assert not ms._same_run('/elsewhere/timing/x/hw_campaigns/r1', Path(run))


def test_restore_verify_run_root_must_be_this_run(tmp_path):
    root = make_run(tmp_path / 'runs', 'r')
    wj(root / 'restore_verify.json', {'ok': True, 'run_root': '/elsewhere/other'})
    assert strict(tmp_path, 'r') == (1, ['restore_verify run_root /elsewhere/other is not this run'])
    wj(root / 'restore_verify.json', {'ok': True})
    assert strict(tmp_path, 'r') == (1, ['restore_verify.json lacks run_root'])
    wj(root / 'restore_verify.json', {'ok': True, 'run_root': str(tmp_path / 'runs' / '.' / 'r')})
    assert strict(tmp_path, 'r') == (0, [])


# ---------------------------------------------------------------- 8. non-object JSON is a reason, never a crash

def test_non_object_json_is_a_recorded_reason(tmp_path):
    root = make_run(tmp_path / 'runs', 'r')
    (root / 'restore_verify.json').write_text('[]')
    (root / 'fx/off/r_fx_off_t0/trial.json').write_text('"x"')
    (root / 'fx/combined/r_fx_combined_t0/snapshots/r_fx_combined_t0_after.json').write_text('7')
    rc, reasons = strict(tmp_path, 'r')
    assert rc == 1
    assert 'artifact restore_verify.json is not a JSON object (list)' in reasons
    assert 'r_fx_off_t0: artifact trial.json is not a JSON object (str)' in reasons
    assert 'r_fx_combined_t0: snapshot: artifact r_fx_combined_t0_after.json is not a JSON object (int)' in reasons
    root2 = make_run(tmp_path / 'runs', 'q')
    (root2 / 'campaign_run.json').write_text('[1]')
    assert strict(tmp_path, 'q') == (1, ['artifact campaign_run.json is not a JSON object (list)'])


# ---------------------------------------------------------------- 9. unrecorded trial directories

def test_unrecorded_trial_directory_on_disk_fails(tmp_path):
    root = make_run(tmp_path / 'runs', 'r')
    wj(root / 'fx/off/r_fx_off_t1/trial.json', {'ok': False, 'failures': ['tail 1142 us']})
    assert strict(tmp_path, 'r') == (
        1, ['trial directory on disk not recorded in campaign_run.json: fx/off/r_fx_off_t1'])


# ---------------------------------------------------------------- previously untested branches

def test_campaign_run_missing_or_unreadable_fails(tmp_path):
    root = make_run(tmp_path / 'runs', 'r')
    (root / 'campaign_run.json').write_text('{not json')
    rc, reasons = strict(tmp_path, 'r')
    assert rc == 1 and len(reasons) == 1 and reasons[0].startswith('unreadable artifact campaign_run.json')
    (root / 'campaign_run.json').unlink()
    assert strict(tmp_path, 'r') == (1, ['missing artifact campaign_run.json'])


def test_runner_block_not_ok_and_restore_step_failure_fail(tmp_path):
    root = make_run(tmp_path / 'runs', 'r')
    edit(root / 'campaign_run.json', lambda d: d.update(ok=False, failure='boom'))
    assert strict(tmp_path, 'r') == (1, ['runner block ok=False: boom'])
    edit(root / 'campaign_run.json', lambda d: d.update(ok=True, restore=[{'ok': True}, {'ok': False}]))
    assert strict(tmp_path, 'r') == (1, ['runner restore step failed or absent'])
    edit(root / 'campaign_run.json', lambda d: d.update(restore=[]))
    assert strict(tmp_path, 'r') == (1, ['runner restore step failed or absent'])


def test_standards_verdict_not_ok_and_profile_not_conformant_fail(tmp_path):
    root = make_run(tmp_path / 'runs', 'r', arm_order=('off',))
    d = root / 'fx/off/r_fx_off_t0'
    edit(d / 'standards_verdict.json', lambda v: v.update(ok=False, failures=['sv']))
    wj(d / 'profile_verdict.json', {'result': {'conformant': False, 'failures': ['pv']}})
    assert sorted(strict(tmp_path, 'r')[1]) == sorted([
        "r_fx_off_t0: standards verdict ok=False: ['sv']", "r_fx_off_t0: profile verdict not conformant: ['pv']"])


def test_counter_length_mismatch_fails(tmp_path):
    make_run(tmp_path / 'runs', 'r', arm_order=('off',), after={'count_busy': [0] * 5, 'count_term': [0] * 4})
    assert strict(tmp_path, 'r') == (
        1, ['r_fx_off_t0: n_counters.count_busy length differs before/after (8/5)'])


# ---------------------------------------------------------------- retained m5 evidence

def test_retained_m5_full_set_fails_naming_rejected_incomplete_and_failed_attempt(tmp_path):
    out = tmp_path / 'm5.json'
    assert ms.main(['--strict', '--require', *M5, '--measurement-only', *MEASUREMENT_ONLY, '-o', str(out)]) == 1
    reasons = json.loads(out.read_text())['reasons']
    by_run = {}
    for r in reasons:
        by_run.setdefault(r['run'], []).append(r['reason'])
    for b in ('ctl_m5_qual_repeat_sbo_950_b2', 'ctl_m5_qual_repeat_sbo_950_b3'):
        assert any(x.startswith('incomplete block') for x in by_run[b])
        assert any('qualification rejected' in x for x in by_run[b])
        assert any("required objective select_precision status 'fail'" in x for x in by_run[b])
    assert any('trial ok=False' in x and 'lifecycle' in x for x in by_run['ctl_m5_held_operate_350_01'])
    # held_operate_350 ran with the block config's 800 us read gap (hw/config/ctl_m5_held_operate_350.json
    # "gap": 800000); undeclared, every reason is that threshold; declared with --expected-gap, it passes.
    assert by_run['ctl_m5_held_operate_350_02'] and all(
        'gap_us=800.0 (expected 950)' in x for x in by_run['ctl_m5_held_operate_350_02'])
    declared = tmp_path / 'declared.json'
    assert ms.main(['--strict', '--require', *M5, '--measurement-only', *MEASUREMENT_ONLY, '--expected-gap',
                    'ctl_m5_held_operate_350_01=800', 'ctl_m5_held_operate_350_02=800', '-o', str(declared)]) == 1
    runs = {r['run'] for r in json.loads(declared.read_text())['reasons']}
    assert 'ctl_m5_held_operate_350_02' not in runs and 'ctl_m5_held_operate_350_01' in runs
    for passing in PIGGYBACK + ['ctl_m5_qual_repeat_sbo_950_b1', 'ctl_m5_char_repeat_sbo_950_b1',
                                'ctl_m5_loss_core_950_01', 'ctl_m5_persistence_graceful_950_01',
                                'ctl_m5_persistence_rst_950_01', 'ctl_m5_reconnect_950_01']:
        assert passing not in by_run


def test_retained_m5_measurement_only_runs_need_the_flag(tmp_path):
    out = tmp_path / 'm5.json'
    assert ms.main(['--strict', '--require', 'ctl_m5_loss_core_950_01', '-o', str(out)]) == 1
    assert [r['reason'] for r in json.loads(out.read_text())['reasons']] == [
        'qualification run has no qualified verdict (not named in --measurement-only)']


def test_retained_m5_piggyback_family_passes(tmp_path):
    assert ms.main(['--strict', '--require', *PIGGYBACK, '-o', str(tmp_path / 'pb.json')]) == 0

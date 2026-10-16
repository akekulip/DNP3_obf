"""m5_summary --strict: the aggregate gate exits nonzero and names every reason; report-only mode stays exit 0."""
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE / 'analysis'))
import m5_summary as ms  # noqa: E402

M5 = ['ctl_m5_char_repeat_sbo_950_b1', 'ctl_m5_held_operate_350_01', 'ctl_m5_held_operate_350_02',
      'ctl_m5_loss_core_950_01', 'ctl_m5_persistence_graceful_950_01', 'ctl_m5_persistence_rst_950_01',
      'ctl_m5_qual_piggyback_950_b1', 'ctl_m5_qual_piggyback_950_b2', 'ctl_m5_qual_piggyback_950_b3',
      'ctl_m5_qual_repeat_sbo_950_b1', 'ctl_m5_qual_repeat_sbo_950_b2', 'ctl_m5_qual_repeat_sbo_950_b3',
      'ctl_m5_reconnect_950_01']
PIGGYBACK = ['ctl_m5_qual_piggyback_950_b1', 'ctl_m5_qual_piggyback_950_b2', 'ctl_m5_qual_piggyback_950_b3']
ZERO = {'count_busy': [0] * 8, 'count_term': [0] * 4}


def wj(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value))


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
            wj(d / 'scenario.json', {'ok': True})
        else:
            wj(d / 'standards_verdict.json', {'ok': True, 'failures': [], 'qualification': qualification})
            wj(d / 'standards.json', {'observed': {'objectives': {'select_precision': {'status': 'pass'}}}})
            wj(d / 'profile_verdict.json', {'result': {'conformant': True, 'failures': []}})
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
    wj(root / 'restore_verify.json', {'ok': True, 'failures': []})
    return root


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
    wj(root / 'restore_verify.json', {'ok': False, 'failures': ['ping']})
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
    assert "r_fx_off_t0: qualification rejected: {'trial': 'rejected'}" in reasons
    make_run(tmp_path / 'runs', 'c', qualification='rejected', purpose='timing_precision_characterization')
    assert strict(tmp_path, 'c') == (0, [])


def test_trial_not_ok_fails(tmp_path):
    root = make_run(tmp_path / 'runs', 'r')
    wj(root / 'fx/off/r_fx_off_t0/trial.json', {'ok': False, 'failures': ['x'], 'qualification': {}})
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
    make_run(tmp_path / 'runs', 's', arm_order=('combined',), after=after, scenario=True, observed=STALE_OK)
    assert strict(tmp_path, 's') == (1, ['s_fx_combined_t0: stale_retry delta 2 (expected 0)'])
    assert strict(tmp_path, 's', stale=['s']) == (0, [])
    make_run(tmp_path / 'runs', 'p', arm_order=('combined',), after=after, scenario=True, observed=STALE_OK,
             purpose=ms.STALE_PURPOSE)
    assert strict(tmp_path, 'p') == (0, [])


def test_stale_token_trial_still_gates_busy_drop_exhaustion_and_window(tmp_path):
    after = {'count_busy': [1, 0, 0, 1, 0, 0, 0, 0], 'count_term': [0] * 4}
    make_run(tmp_path / 'runs', 's', arm_order=('combined',), after=after, scenario=True,
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


# ---------------------------------------------------------------- retained m5 evidence

def test_retained_m5_full_set_fails_naming_rejected_incomplete_and_failed_attempt(tmp_path):
    out = tmp_path / 'm5.json'
    assert ms.main(['--strict', '--require', *M5, '-o', str(out)]) == 1
    reasons = json.loads(out.read_text())['reasons']
    by_run = {}
    for r in reasons:
        by_run.setdefault(r['run'], []).append(r['reason'])
    for b in ('ctl_m5_qual_repeat_sbo_950_b2', 'ctl_m5_qual_repeat_sbo_950_b3'):
        assert any(x.startswith('incomplete block') for x in by_run[b])
        assert any('qualification rejected' in x for x in by_run[b])
    assert any('trial ok=False' in x and 'lifecycle' in x for x in by_run['ctl_m5_held_operate_350_01'])
    for passing in PIGGYBACK + ['ctl_m5_qual_repeat_sbo_950_b1', 'ctl_m5_held_operate_350_02']:
        assert passing not in by_run


def test_retained_m5_piggyback_family_passes(tmp_path):
    assert ms.main(['--strict', '--require', *PIGGYBACK, '-o', str(tmp_path / 'pb.json')]) == 0

"""W2: the opt-in 20 s isolation endpoint capability, its planner, the endpoint-local permit and its fail-safes.

No hardware. Planning uses the real retained allowances in token_window and the real
ctl_m5_stale_iso20_950 config; the monitor tests drive TokenIsolationCampaign.monitor with retained m4
counters (the m5 population is the m4 population) and synthetic Vision ticks (MODEL-ONLY), and run the REAL
vision_isolation.grant_permit / abort_c2 helpers against a temporary runs directory and a fake /proc.
"""
import copy
import json
import os
from pathlib import Path
import shlex
import sys
import threading
import time
from unittest.mock import patch

import pytest

HW = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HW))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import token_window as tw
import test_stale_isolation_s3 as s3

ISO20 = HW.parent / 'config/ctl_m5_stale_iso20_950.json'
CAP20 = tw.ENDPOINT_CAPABILITIES['isolation_20s']
READY = 1_000_000_000_000
LABEL = 'lbl'


def m5_population():
    import candidate_isolation as ci
    cfg = ci.base.load_config(str(ISO20))
    return s3.population(cfg)


# ---------------------------------------------------------------- planning with the real retained allowances

def test_capability_table_and_config_selection():
    assert tw.ENDPOINT_CAPABILITIES == {'barrier_10s': dict(max_pause_ms=10000, permit=False),
                                        'isolation_20s': dict(max_pause_ms=20000, permit=True)}
    assert tw.endpoint_capability({}) == ('barrier_10s', dict(max_pause_ms=10000, permit=False))
    assert tw.endpoint_capability(dict(max_pause_ms=20000, permit=True))[0] == 'isolation_20s'
    for bad in (dict(max_pause_ms=20000), dict(permit=True), dict(max_pause_ms=15000, permit=True),
                dict(max_pause_ms='20000', permit=True), dict(max_pause_ms=20000, permit=1)):
        with pytest.raises(ValueError):
            tw.endpoint_capability(bad)
    # the legacy constants (10 s barrier path) are unchanged
    assert (tw.PRE_READ_GRACE_MS, tw.PAUSE_MAX_MS, tw.PRE_READ_GRACE_NS) == (10000, 10000, 10_000_000_000)


def test_20s_plan_for_m5_matches_an_independent_recomputation():
    pop = m5_population()
    assert (pop['READ']['triggers'], pop['READ']['tokens'], pop['OPERATE']['tokens']) == (2, 8, 4)
    plan = tw.plan_isolation(pop, 0, capability=CAP20)
    # independent arithmetic from the stated allowances (not the module's helpers)
    ipg = 2_500_000_000
    span = 2 * (2 * 2 - 1) * ipg                                     # triggers x (2k-1) x IPG = 15 s
    bound = span + 1_000_000 + 3_000_000_000                         # + trigger latency + snapshot allowance
    required = bound + 4_000_000_000 + 1_500_000_000 - 5_399_073_266  # + restore + abort margin - min c1->c2
    derived_ms = -(-required // 1_000_000)
    floor = 5_515_418_587 + 1_000_000_000 + 500_000_000
    assert (span, bound, required, derived_ms, floor) == (15_000_000_000, 18_001_000_000, 18_101_926_734, 18_102,
                                                          7_015_418_587)
    assert plan['delay_ipg_ns'] == ipg and plan['bound']['bound_ns'] == bound
    assert (plan['pause']['derived_pause_ms'], plan['pause']['pause_ms']) == (derived_ms, 20_000)
    assert plan['pause']['planned_slack_ns'] == 20_000_000_000 - required == 1_898_073_266
    assert plan['pause']['fits'] and plan['pause']['lower_margin_over_floor_ns'] == span - floor
    assert plan['capability'] == CAP20 and plan['activation'] is True
    assert plan['pause']['upper_ok'] is True and plan['pause']['maximum_ms'] == 20000
    assert plan['pause']['upper_margin_ns'] == 20_000_000_000 - derived_ms * 1_000_000


def test_the_same_m5_workload_stays_refused_on_the_10s_barrier():
    with pytest.raises(ValueError, match='no delay IPG'):
        tw.plan_isolation(m5_population(), 0)
    with pytest.raises(ValueError, match='no delay IPG'):
        tw.plan_isolation(m5_population(), 0, capability=tw.LEGACY_CAPABILITY)


def test_both_bound_failures_on_the_20s_capability():
    pop = m5_population()
    # upper: 4 s IPG -> span 24 s, required 27.1 s > 20 s
    with pytest.raises(ValueError, match='27102 ms c2 pause, above the endpoint maximum 20000 ms'):
        tw.plan_isolation(pop, 0, 4_000_000_000, capability=CAP20)
    # lower: 1 s IPG -> span 6 s, not after the 7.015 s c2-ready snapshot floor
    with pytest.raises(ValueError, match='before the c2-ready snapshot'):
        tw.plan_isolation(pop, 0, 1_000_000_000, capability=CAP20)
    # lower at every IPG (k = 1: two tokens per trigger)
    with pytest.raises(ValueError, match='no delay IPG'):
        tw.plan_isolation(tw.old_token_population(1, 1, 1, True), 0, capability=CAP20)
    req = tw.pause_requirement(tw.cleanup_bound(pop, {'READ': 4_000_000_000, 'OPERATE': 0}), maximum_ms=20000)
    assert (req['upper_ok'], req['lower_ok'], req['fits'], req['maximum_ms']) == (False, True, False, 20000)


def test_legacy_candidate61_parameters_fit_20s_but_are_refused_on_10s():
    legacy_pop = tw.LEGACY_POPULATION
    plan = tw.plan_isolation(legacy_pop, 0, legacy=True, capability=CAP20)
    assert plan['pause']['fits'] and (plan['pause']['pause_ms'], plan['pause']['derived_pause_ms']) == (20_000, 10_602)
    with pytest.raises(ValueError, match='new activation refused'):
        tw.plan_isolation(legacy_pop, 0, legacy=True)
    with pytest.raises(ValueError, match='integer max_pause_ms'):
        tw.plan_isolation(legacy_pop, 0, legacy=True, capability=dict(max_pause_ms='20000', permit=True))


def test_campaign_from_the_iso20_config_plans_and_commands_the_permit_endpoint():
    ci, run = s3.campaign('iso20')
    assert (run.endpoint_name, run.capability, run.delay_ipg_ns, run.pause_ms) == \
        ('isolation_20s', CAP20, 2_500_000_000, 20_000)
    assert run.record['isolation_endpoint'] == dict(name='isolation_20s', capability=CAP20, analysis_only=False)
    assert run.cfg['hosts']['vision_run_dir'] == ci.ISOLATION_DIRECTORY
    assert run.cfg['endpoint']['binary_sha256'] == ci.ISOLATION_BINARY
    run.active_unit = (run.units()[0], 0, 'x'); run._series_padding = 1
    command = run.series_vision_cmd('fixed', 59412, 1, 8, 0)
    assert '--pre-read-grace-ms 20000 --endpoint isolation_20s' in command
    assert '--ipg-ns 2500000000' in run.delay_command('/r.json', '/d.json')


def test_iso20_config_differs_from_the_m5_config_only_in_endpoint_identity():
    m5 = json.loads((s3.SEG / 'hw/config/ctl_m5_stale_tokens_950.json').read_text())
    iso = json.loads(ISO20.read_text())
    assert {key for key in set(m5) | set(iso) if m5.get(key) != iso.get(key)} == {'_notes', 'hosts', 'endpoint'}
    assert {k for k in m5['hosts'] if m5['hosts'][k] != iso['hosts'][k]} == {'vision_run_dir'}
    manifest = json.loads((HW.parent / 'endpoint_isolation_20s/manifest/build_manifest.json').read_text())
    assert iso['endpoint']['binary_sha256'] == manifest['binary_sha256']
    assert iso['endpoint']['lib_sha256'] == manifest['library_directory_sha256']
    assert iso['endpoint']['source_files'] == manifest['source_hashes']


# ---------------------------------------------------------------- permit conditions (harness side)

@pytest.fixture(scope='module')
def m4():
    return s3.run(s3.M4)


def snapshots(m4):
    before, mid, drain = s3.m4_monitor_snapshots(m4)
    s3.set_raw(drain, '24', 7)          # every old READ token after the consumed first one rejected
    return before, mid, drain


def conditions(m4, **change):
    before, mid, drain = snapshots(m4)
    args = dict(before=before, polls=[mid, drain], population=m5_population(), drained_tick_ns=READY + 5_000_000_000,
                restored_ns=READY + 6_000_000_000, pause_deadline_ns=READY + 20_000_000_000)
    args.update(change)
    return tw.permit_conditions(**args)


def test_permit_conditions_hold_for_drained_rejected_unchanged_and_restored(m4):
    assert conditions(m4) == []


def test_permit_conditions_refuse_each_missing_proof(m4):
    before, mid, drain = snapshots(m4)
    undrained = copy.deepcopy(drain); s3.set_app(undrained, 'read', pkt_counter=7); s3.set_raw(undrained, '24', 6)
    assert any('not drained' in f for f in conditions(m4, polls=[mid, undrained]))
    unrejected = copy.deepcopy(drain); s3.set_raw(unrejected, '24', 6)
    assert any('READ timer rejections' in f for f in conditions(m4, polls=[mid, unrejected]))
    no_arrival = copy.deepcopy(before); s3.set_app(no_arrival, 'read', pkt_counter=8)
    assert any('no old READ token arrived' in f for f in conditions(m4, before=no_arrival))
    op = copy.deepcopy(drain); s3.set_app(op, 'operate', pkt_counter=3)
    assert conditions(m4, polls=[mid, op])
    moved = copy.deepcopy(mid); s3.set_register(moved, 'p1.t_Ingress.gen_alloc_reg', 99)
    assert any('authority changed at poll00' in f for f in conditions(m4, polls=[moved, drain]))
    assert any('restore took' in f for f in conditions(m4, restored_ns=READY + 9_000_000_001))
    assert any('restore' in f for f in conditions(m4, restored_ns=None))
    assert any('before the c2 pause deadline' in f for f in
               conditions(m4, restored_ns=READY + 6_000_000_000, pause_deadline_ns=READY + 6_000_000_000))
    assert conditions(m4, polls=[]) == ['permit: no quiet poll observed']


# ---------------------------------------------------------------- monitor(): permit grant and fail-safes

class PermitVision(s3.FakeVision):
    """FakeVision plus the REAL grant-permit helper over a temporary runs directory. vision_clock supplies the
    Vision monotonic reading the helper takes; grant_rc forces an ssh-level failure instead."""

    def __init__(self, *args, runs, vision_clock=None, grant_rc=None, marker_on_vision=None, forced_report=None,
                 **kwargs):
        super().__init__(*args, **kwargs)
        self.runs, self.vision_clock, self.grant_rc, self.grants = runs, vision_clock, grant_rc, []
        self.forced_report = forced_report
        c2 = Path(runs) / LABEL / 'c2'; c2.mkdir(parents=True)
        (c2 / 'pre_read_ready.json').write_text(json.dumps(marker_on_vision or self.marker))

    def run(self, where, cmd, cwd=None, timeout=None, label=None):
        if label != 'grant c2 pre-READ permit on the Vision clock':
            return super().run(where, cmd, cwd, timeout, label)
        import candidate_isolation as ci
        import vision_isolation as vi
        self.calls.append((where, label, cmd, time.monotonic()))
        argv = shlex.split(cmd)
        assert argv[:3] == ['sudo', '-n', 'python3'] and argv[-8:-6] == ['grant-permit', LABEL]
        self.grants.append(dict(argv=argv[-8:], timeout=timeout))
        if self.grant_rc is not None:
            return ci.base.Result(self.grant_rc, '', 'ssh: connect to host vision: Connection timed out')
        if self.forced_report is not None:
            return ci.base.Result(0, json.dumps(self.forced_report), '')
        values = dict(zip(argv[-6::2], (int(value) for value in argv[-5::2])))
        report = vi.grant_permit(LABEL, values['--ready-ns'], values['--opens'], values['--deadline-ns'],
                                 runs=self.runs, clock=self.vision_clock)
        return ci.base.Result(0 if report['written'] else 1, json.dumps(report), '')


def monitor20(m4, tmp_path, polls, ticks, restore=None, snapshot=None, **vision_kwargs):
    ci, run = s3.campaign('iso20')
    assert run.pause_ms == 20_000 and run.capability['permit'] is True
    marker = dict(tcp_open=True, opens=1, pre_read_grace_ms=run.pause_ms, pre_read_ready_ns=READY,
                  first_read_issued_ns=0)
    done = threading.Event()
    vision = PermitVision(marker, READY - tw.C1_TO_C2_READY_MIN_NS, [None if t is None else READY + t for t in ticks],
                          tmp_path / 'proc', done, runs=tmp_path / 'runs', **vision_kwargs)
    run.rn, run.root, run.active_unit = vision, str(tmp_path), (run.units()[0], 0, LABEL)
    run.window.update(delay_remote='/snap/delay.json', delay_time=1.0)
    queue = list(polls)

    def queued(label, suffix):
        vision.calls.append(('switch', 'quiet snapshot ' + suffix, '', 0))
        return queue.pop(0)
    run.quiet_snapshot = snapshot or queued
    steps = []

    def step(where, label, cmd, cwd=None, check=True, timeout=3600):
        steps.append((where, label, cmd, timeout))
        if restore and label.startswith('restore READ IPG'):
            return restore(timeout)
        return vision.run(where, cmd, label=label)
    run.step = step
    run.monitor(done)
    permit = tmp_path / 'runs' / LABEL / 'c2' / 'pre_read_permit.json'
    return run, vision, steps, permit


def vision_clock(at):
    return lambda: READY + at


def test_monitor_grants_a_bound_permit_only_after_drain_rejection_authority_and_restore(m4, tmp_path):
    before, mid, drain = snapshots(m4)
    run, vision, steps, permit = monitor20(m4, tmp_path, [before, mid, drain],
                                           [3_000_000_000, 5_000_000_000, 6_000_000_000],
                                           vision_clock=vision_clock(6_500_000_000))
    assert run.window['monitor_ok'] is True, run.window.get('error')
    assert run.window['permit_conditions'] == dict(ok=True, failures=[])
    body = json.loads(permit.read_text())
    assert body == dict(run=LABEL + '_c2', ready_ns=READY, opens=1, grant=True, granted_ns=READY + 6_500_000_000)
    assert run.window['permit_granted_vision_ns'] == READY + 6_500_000_000
    grant = vision.grants[0]['argv']
    assert grant == ['grant-permit', LABEL, '--ready-ns', str(READY), '--opens', '1', '--deadline-ns',
                     str(READY + 20_000_000_000)]
    order = [call[1] for call in vision.calls]
    assert order.index('confirm IPG restore completion on Vision clock') < \
        order.index('grant c2 pre-READ permit on the Vision clock')
    assert 13.0 < vision.grants[0]['timeout'] <= 15.0          # local image of the scheduled READ after drain
    assert vision.aborts == [] and 'c2_abort' not in run.window
    # 20 s pause: restore gate 20 - 4 - 1.5 = 14.5 s after readiness, drained at 5 s
    assert run.window['runtime_slack_ns'] == 9_500_000_000


@pytest.mark.parametrize('drain_tick', [20_000_000_000 - tw.RESTORE_ALLOWANCE_NS - tw.ABORT_MARGIN_NS, None])
def test_late_or_unobserved_drain_never_restores_or_grants_and_aborts(m4, tmp_path, drain_tick):
    before, mid, drain = snapshots(m4)
    run, vision, steps, permit = monitor20(m4, tmp_path, [before, mid, drain], [3_000_000_000, drain_tick])
    assert run.window['monitor_ok'] is False and 'did not drain with time to restore' in run.window['error']
    assert not permit.exists() and vision.grants == [] and s3.restores(steps) == []
    assert run.window['c2_abort_confirmed'] is True


def test_stalled_quiet_snapshot_fires_the_watchdog_and_never_grants(m4, tmp_path, monkeypatch):
    import candidate_isolation as ci
    monkeypatch.setattr(ci, 'ABORT_MARGIN_S', 19.7)            # abort point 0.3 s after the marker
    before, _, _ = snapshots(m4)
    returned = []

    def hung(label, suffix):
        if suffix != 'before':
            time.sleep(0.8); returned.append(time.monotonic())
            raise ci.base.StepFailed('quiet snapshot timed out')
        return before
    run, vision, steps, permit = monitor20(m4, tmp_path, [], [], snapshot=hung, stop_after_aborts=2)
    assert vision.aborts[0] < returned[0] and run.window['watchdog_fired_local'] >= run.window['abort_at_local'] - 0.01
    assert not permit.exists() and vision.grants == [] and run.window['c2_abort_confirmed'] is True


def test_stalled_restore_fires_the_watchdog_and_never_grants(m4, tmp_path, monkeypatch):
    import candidate_isolation as ci
    monkeypatch.setattr(ci, 'ABORT_MARGIN_S', 14.4)            # abort point ~0.6 s after the drained poll (5 s)

    def hang(timeout):
        time.sleep(timeout + 0.1)
        raise ci.base.StepFailed('restore step timed out after %.3f s' % timeout)
    before, mid, drain = snapshots(m4)
    run, vision, steps, permit = monitor20(m4, tmp_path, [before, mid, drain], [3_000_000_000, 5_000_000_000],
                                           restore=hang)
    assert run.window['monitor_ok'] is False and run.window['c2_abort_confirmed'] is True
    assert run.window['watchdog_fired_local'] >= run.window['abort_at_local'] - 0.01
    assert not permit.exists() and vision.grants == []


@pytest.mark.parametrize('rc', [255, 124])
def test_ssh_failure_or_timeout_on_the_grant_withholds_the_permit_and_aborts(m4, tmp_path, rc):
    before, mid, drain = snapshots(m4)
    run, vision, steps, permit = monitor20(m4, tmp_path, [before, mid, drain],
                                           [3_000_000_000, 5_000_000_000, 6_000_000_000], grant_rc=rc)
    assert run.window['monitor_ok'] is False and 'c2 permit not granted (rc %d' % rc in run.window['error']
    assert not permit.exists() and run.window['permit']['rc'] == rc
    assert run.window['c2_abort_confirmed'] is True and run.window['c2_abort']['aborted'] is True


@pytest.mark.parametrize('kwargs,reason', [
    (dict(vision_clock=vision_clock(20_000_000_000)), 'late'),                       # Vision clock at the deadline
    (dict(vision_clock=vision_clock(6_500_000_000),
          marker_on_vision=dict(tcp_open=True, opens=1, pre_read_grace_ms=20000, pre_read_ready_ns=READY + 1,
                                first_read_issued_ns=0)), 'does not bind')])         # another readiness instance
def test_vision_helper_refuses_a_late_or_wrongly_bound_grant(m4, tmp_path, kwargs, reason):
    before, mid, drain = snapshots(m4)
    run, vision, steps, permit = monitor20(m4, tmp_path, [before, mid, drain],
                                           [3_000_000_000, 5_000_000_000, 6_000_000_000], **kwargs)
    assert run.window['monitor_ok'] is False and reason in run.window['error']
    assert not permit.exists() and run.window['c2_abort_confirmed'] is True


def test_a_zero_exit_without_a_written_in_window_permit_is_not_a_grant(m4, tmp_path):
    before, mid, drain = snapshots(m4)
    for index, report in enumerate((dict(written=False, granted_ns=READY + 6_500_000_000, reason='refused'),
                                    dict(written=True, granted_ns=READY + 20_000_000_000),
                                    dict(written=True, granted_ns=READY), dict(written=True))):
        run, vision, steps, permit = monitor20(m4, tmp_path / str(index), [before, mid, drain],
                                               [3_000_000_000, 5_000_000_000, 6_000_000_000], forced_report=report)
        assert run.window['monitor_ok'] is False and 'c2 permit not granted (rc 0' in run.window['error']
        assert 'permit_granted_vision_ns' not in run.window and run.window['c2_abort_confirmed'] is True


def test_changed_authority_withholds_the_permit_without_calling_vision(m4, tmp_path):
    before, mid, drain = snapshots(m4)
    s3.set_register(mid, 'p0.n_Ingress.owner', (5 << 16) | 3)
    run, vision, steps, permit = monitor20(m4, tmp_path, [before, mid, drain],
                                           [3_000_000_000, 5_000_000_000, 6_000_000_000],
                                           vision_clock=vision_clock(6_500_000_000))
    assert run.window['monitor_ok'] is False and 'c2 permit withheld' in run.window['error']
    assert vision.grants == [] and not permit.exists()


@pytest.mark.parametrize('kwargs', [dict(sudo_refused=True), dict(unkillable=True)])
def test_abort_failure_after_a_withheld_permit_is_recorded_unconfirmed(m4, tmp_path, kwargs):
    """The permit is never written, so the endpoint itself exits 75 without a READ at scheduled + 2 s (see
    endpoint_isolation_20s tests); the harness still records the failed remote abort as NOT CONFIRMED."""
    before, mid, drain = snapshots(m4)
    run, vision, steps, permit = monitor20(m4, tmp_path, [before, mid, drain],
                                           [3_000_000_000, 5_000_000_000, 6_000_000_000], grant_rc=255,
                                           stop_after_aborts=2, **kwargs)
    assert not permit.exists() and run.window['c2_abort_confirmed'] is False
    assert 'ABORT NOT CONFIRMED' in run.window['c2_abort']['note']


# ---------------------------------------------------------------- Vision helper and scenario plumbing

def write_marker(runs, ready=READY, opens=1):
    c2 = Path(runs) / LABEL / 'c2'; c2.mkdir(parents=True, exist_ok=True)
    (c2 / 'pre_read_ready.json').write_text(json.dumps(dict(pre_read_grace_ms=20000, pre_read_ready_ns=ready,
                                                            first_read_issued_ns=0, tcp_open=True, opens=opens)))
    return c2


def test_grant_permit_writes_once_atomically_and_refuses_everything_else(tmp_path):
    import vision_isolation as vi
    c2 = write_marker(tmp_path)
    deadline = READY + 20_000_000_000
    assert vi.grant_permit(LABEL, READY, 1, deadline, runs=tmp_path, clock=vision_clock(1))['reason'] == 'granted'
    assert json.loads((c2 / 'pre_read_permit.json').read_text())['granted_ns'] == READY + 1
    again = vi.grant_permit(LABEL, READY, 1, deadline, runs=tmp_path, clock=vision_clock(2))
    assert again['written'] is False and again['reason'] == 'permit already exists'
    assert json.loads((c2 / 'pre_read_permit.json').read_text())['granted_ns'] == READY + 1    # never overwritten
    assert {p.name for p in c2.iterdir()} == {'pre_read_ready.json', 'pre_read_permit.json'}   # no temp left
    fresh = tmp_path / 'fresh'
    write_marker(fresh)
    for args, reason in (((LABEL, READY + 1, 1, deadline), 'does not bind'), ((LABEL, READY, 2, deadline), 'does not bind'),
                         ((LABEL, READY, 1, READY + 1), 'late'), ((LABEL, READY, 1, deadline), 'late'),
                         ((LABEL, READY, 1, deadline), 'stale')):
        clock = {'late': vision_clock(1) if args[3] != deadline else vision_clock(20_000_000_000),
                 'stale': vision_clock(0)}.get(reason, vision_clock(1))
        report = vi.grant_permit(*args, runs=fresh, clock=clock)
        assert report['written'] is False and reason in report['reason']
    assert not (fresh / LABEL / 'c2' / 'pre_read_permit.json').exists()
    assert vi.grant_permit(LABEL, READY, 1, deadline, runs=tmp_path / 'none', clock=vision_clock(1))['reason'] == \
        'c2 marker missing or incomplete'
    for bad in ((LABEL + ';x', READY, 1, deadline), (LABEL, READY, 1, READY), (LABEL, READY, True, deadline)):
        with pytest.raises(ValueError):
            vi.grant_permit(*bad, runs=fresh, clock=vision_clock(1))


def test_grant_cli_requires_authorization(tmp_path, monkeypatch):
    import vision_isolation as vi
    monkeypatch.delenv('DEFENSE4_HW_AUTHORIZED', raising=False)
    with pytest.raises(ValueError, match='DEFENSE4_HW_AUTHORIZED'):
        vi.grant_main([LABEL, '--ready-ns', '1', '--opens', '1', '--deadline-ns', '2'])


def run_scenario(tmp_path, endpoint, grace, permit_ok=True):
    import vision_isolation as vi
    calls = []

    def connect(dest, label, port, *args, **kwargs):
        dest = Path(dest); dest.mkdir()
        grace_now = int(os.environ['CASE4_PRE_READ_GRACE_MS'])
        calls.append(dict(grace=grace_now, permit=os.environ.get('CASE4_PRE_READ_PERMIT'),
                          run=os.environ.get('CASE4_PRE_READ_RUN'), label=label))
        master = dict(pre_read_grace_ms=grace_now, pre_read_ready_ns=10, first_read_issued_ns=10 + grace_now * 10 ** 6)
        if calls[-1]['permit']:
            granted = 11 if permit_ok else 10
            master['pre_read_permit'] = dict(run=calls[-1]['run'], granted_ns=granted, accepted_ns=12)
            Path(calls[-1]['permit']).write_text(json.dumps(dict(run=calls[-1]['run'], ready_ns=10, opens=1, grant=True,
                                                                 granted_ns=granted)))
        (dest / 'master.json').write_text(json.dumps(master))
        return dict(ok=True)
    with patch.dict(os.environ, {'DEFENSE4_HW_AUTHORIZED': '1', 'CASE4_PRE_READ_PERMIT': '/caller/p',
                                 'CASE4_PRE_READ_RUN': 'caller'}), \
            patch.object(vi.vc.vr, 'RUNS', str(tmp_path)), patch.object(vi.vc, 'preflight', return_value=[]), \
            patch.object(vi.vc.vr, 'run_connection', side_effect=connect), \
            patch.object(vi.vc, 'evaluate', return_value=[]), patch.object(vi.vc, 'observe', return_value={'ok': True}):
        record = vi.scenario('scn', 59412, 1, apply=True, pre_read_grace_ms=grace, endpoint=endpoint)
        assert (os.environ['CASE4_PRE_READ_PERMIT'], os.environ['CASE4_PRE_READ_RUN']) == ('/caller/p', 'caller')
    return record, calls


def test_permit_controls_reach_only_c2_and_only_on_the_isolation_endpoint(tmp_path):
    record, calls = run_scenario(tmp_path / 'iso', 'isolation_20s', 20000)
    assert record['ok'] is True, record
    assert [c['permit'] for c in calls] == [None, str(tmp_path / 'iso/scn/c2/pre_read_permit.json'), None]
    assert [c['run'] for c in calls] == [None, 'scn_c2', None] and calls[1]['label'] == 'scn_c2'
    assert [c['grace'] for c in calls] == [0, 20000, 0]
    assert record['endpoint'] == 'isolation_20s' and record['plan'][1]['permit_run'] == 'scn_c2'
    legacy, calls = run_scenario(tmp_path / 'barrier', 'barrier_10s', 10000)
    assert legacy['ok'] is True and [c['permit'] for c in calls] == [None, None, None]
    assert 'endpoint' not in legacy and 'permit_run' not in legacy['plan'][1]
    bad, _ = run_scenario(tmp_path / 'bad', 'isolation_20s', 20000, permit_ok=False)
    assert bad['ok'] is False and any('bind c2 readiness' in f for f in bad['connections'][1]['failures'])


def test_scenario_caps_come_from_the_selected_capability(tmp_path):
    import vision_isolation as vi
    assert vi.scenario('a', 59412, 1, pre_read_grace_ms=20000, endpoint='isolation_20s')['ok']
    for grace, endpoint in ((20001, 'isolation_20s'), (10001, 'barrier_10s'), (20000, 'barrier_10s'), (0, 'isolation_20s')):
        with pytest.raises(ValueError, match='pre-READ pause'):
            vi.scenario('a', 59412, 1, pre_read_grace_ms=grace, endpoint=endpoint)
    with pytest.raises(ValueError, match='unknown isolation endpoint'):
        vi.scenario('a', 59412, 1, endpoint='isolation_30s')
    # the vision_run master timeout (36 s) covers the worst c2 path: 5 + 20 + 2 + 3 + 0.025 + 3 + 1 = 34.025 s
    assert vi.master_budget(20000, True) == dict(worst_s=34.025, budget_s=36, ok=True)
    assert vi.master_budget(23000, True)['ok'] is False
    with patch.object(vi, 'MASTER_BUDGET_S', 34):
        with pytest.raises(ValueError, match='exceeds the master timeout'):
            vi.scenario('a', 59412, 1, pre_read_grace_ms=20000, endpoint='isolation_20s')


def test_ordinary_campaigns_are_unchanged():
    """vision_candidate (ordinary campaigns) keeps its 10 s cap and never sets the permit controls."""
    import vision_candidate as vc
    assert vc.PRE_READ_GRACE_MS == 10000
    source = (HW / 'vision_candidate.py').read_text()
    assert 'CASE4_PRE_READ_PERMIT' not in source and 'CASE4_PRE_READ_RUN' not in source
    for value in (10001, 20000):
        with pytest.raises(ValueError, match='0..10000'):
            vc.scenario('x', 59412, 'rst', 1, pre_read_grace_ms=value)
    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop('CASE4_PRE_READ_PERMIT', None)
        with vc.pre_read_controls('/tmp/x', 10000):
            assert 'CASE4_PRE_READ_PERMIT' not in os.environ and 'CASE4_PRE_READ_RUN' not in os.environ

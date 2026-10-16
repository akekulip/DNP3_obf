"""Stale-token isolation on the retained m4 (control-timed) and candidate61 silicon evidence (PLAN_m5 S3).

Read-only: every fixture is loaded from the retained campaign directories and mutated in memory only. Tests
marked MODEL-ONLY combine retained counters with synthetic timestamps; the retained m4 block has no
token_delay.json, no poll ticks and never drained, so no m4 silicon result is claimed by them.
"""
import copy
import importlib.util
import json
from pathlib import Path
import sys

import pytest

HW = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HW))
import token_window as tw
from isolation_gate import compare_quiet_generation

SEG = HW.parents[3] / 'integration/core/response_only_rearm/stage_experiments/seg61_02'
CAMPAIGNS = SEG / 'evidence/hw_campaigns'
M4, C61 = 'ctl_m4_stale_tokens_950_01', 'candidate61_stale_tokens_950_02'


def load(path):
    return json.loads(Path(path).read_text())


def run(name):
    root = CAMPAIGNS / name
    trial = root / 'separate_ack/combined' / (name + '_separate_ack_combined_t0')
    snaps = trial / 'snapshots'
    snap = lambda side: load(snaps / ('%s_separate_ack_combined_t0_%s.json' % (name, side)))
    return dict(observer=load(root / 'token_window_observer.json'),
                full={side: snap(side) for side in ('before', 'after')},
                lifecycle={side: snap(side + '_lifecycle') for side in ('before', 'after')},
                master=load(trial / 'c2/master.json'), c1=load(trial / 'c1/master.json'),
                trial=load(trial / 'trial.json'),
                cfg=load(SEG / 'hw/config' / (name.rsplit('_', 1)[0] + '.json')), root=root)


def population(cfg):
    build = cfg['builds'][cfg['arms'][0]['build']]
    return tw.old_token_population(cfg['service']['k'], 1, 1 if cfg['traffic']['run_sbo'] else 0,
                                   bool(build.get('control_timed')))


def generations(cfg):
    import candidate_campaign as cc
    build = cfg['builds'][cfg['arms'][0]['build']]
    _, reserve = cc.HEADROOM.workload_reserve(1, 1, 1, bool(build.get('control_timed')))
    return tw.expected_generations(reserve['read_lane_per_connection'], reserve['operate_per_connection'],
                                   reserve['open_close_per_connection'])


@pytest.fixture(scope='module')
def m4():
    return run(M4)


@pytest.fixture(scope='module')
def c61():
    return run(C61)


def set_raw(snapshot, index, value):
    for suffix in ('before', 'after'):
        snapshot['old_reject_' + suffix][index]['t_Ingress.outcomes.f1'] = [value]


def set_register(snapshot, name, value):
    entry = snapshot['registers'][name]
    key = next(k for k in entry if k not in ('action_name', 'is_default_entry'))
    entry[key] = [value]


def set_app(snapshot, prefix, **values):
    for suffix in ('before', 'after'):
        snapshot['%s_app_%s' % (prefix, suffix)].update(values)


# ---------------------------------------------------------------- (a) m4: retained counters and the old failure

def test_m4_population_matches_retained_counters(m4, c61):
    pm = population(m4['cfg'])
    assert (pm['READ']['triggers'], pm['READ']['tokens'], pm['READ']['expected_raw_stale']) == (2, 8, 7)
    assert (pm['OPERATE']['triggers'], pm['OPERATE']['tokens']) == (1, 4)
    assert population(c61['cfg']) == tw.LEGACY_POPULATION
    obs = m4['observer']
    # trigger_counter is 1 at c2 readiness and 2 only from poll 0 on
    assert obs['before']['read_app_after']['trigger_counter'] == 1
    assert [p['read_app_after']['trigger_counter'] for p in obs['polls']] == [2, 2, 2]
    for snap in [obs['before']] + obs['polls']:            # first token consumed, every later one rejected
        assert tw.raw_counts(snap, 'after')['24'] == snap['read_app_after']['pkt_counter'] - 1
    assert pm['READ']['tokens'] - obs['polls'][-1]['read_app_after']['pkt_counter'] == 1


def test_m4_reproduces_old_fixed_window_failure(m4):
    obs = m4['observer']
    assert obs['monitor_ok'] is False and 'did not finish' in obs['error']
    assert not any(tw.legacy_drained(p) for p in obs['polls'])
    assert not tw.window_proof(obs['marker_observation']['marker'], m4['master'], obs['before'], obs['polls'][-1],
                               None)['ok']
    pop = population(m4['cfg'])
    assert not any(tw.drained(p, pop) or tw.overran(p, pop) for p in obs['polls'])


def test_drain_before_c2_rationale_cites_the_retained_m4_counters(m4):
    pktgen = m4['trial']['observed']['switch']['pktgen']['READ']
    assert (pktgen['triggers'], pktgen['pkts']) == (4, 13)
    assert 'T on: READ trigger delta 4, expected 6' in ' '.join(m4['trial']['failures'])
    assert 'generated READ packets delta 13, expected 24' in ' '.join(m4['trial']['failures'])
    assert 'trigger delta 4 against 6' in tw.DRAIN_BEFORE_C2_RATIONALE
    assert 'packets 13 against 24' in tw.DRAIN_BEFORE_C2_RATIONALE


def test_c1_to_c2_ready_bounds_are_the_retained_minimum_and_maximum(m4, c61):
    measured = [r['master']['pre_read_ready_ns'] - r['c1']['first_read_issued_ns'] for r in (m4, c61)]
    assert measured == [5_399_073_266, 5_515_418_587]
    assert (tw.C1_TO_C2_READY_MIN_NS, tw.C1_TO_C2_READY_MAX_NS) == (min(measured), max(measured))


HYPOTHETICAL = dict(FIRST_SNAPSHOT_NS=400_000_000, LOWER_MARGIN_NS=0)


def hypothetical(mp):
    """MODEL-ONLY allowances (first snapshot 0.4 s, no lower margin) under which a control-timed plan exists:
    they let the monitor and window logic be exercised on a control-timed run; they are NOT the shipped values."""
    for name, value in HYPOTHETICAL.items():
        mp.setattr(tw, name, value)


def test_bound_and_pause_against_hand_computed_numbers(m4, c61):
    floor = 5_515_418_587 + 1_000_000_000 + 500_000_000       # maximum c1->c2 ready + first snapshot + margin
    # m4 at the retained 2.5 s: READ span 2*3*2.5 s = 15 s (OPERATE IPG 0, paced inside it);
    # bound = 15 s + 1 ms trigger latency + 3 s snapshot = 18.001 s;
    # pause = 18.001 + 4 restore + 1.5 abort margin - 5.399073266 s -> 18102 ms
    bound = tw.cleanup_bound(population(m4['cfg']), {'READ': 2_500_000_000, 'OPERATE': 0})
    assert (bound['emission_ns'], bound['bound_ns']) == (15_000_000_000, 18_001_000_000)
    assert tw.pause_requirement(bound)['pause_ms'] == 18_102
    with pytest.raises(ValueError, match='18102 ms'):
        tw.plan_isolation(population(m4['cfg']), 0, 2_500_000_000)
    # upper uses the minimum c1->c2 ready (5.399073266 s) and now the 1.5 s abort margin, lower the maximum
    # (floor 7.015418587 s): 1.25 s: pause 10.501 + 5.5 - 5.399 -> 10602 ms (too long); 1.0 s: pause 9102 ms
    # but span 6 s < 7.015 s (too short). Continuous: upper needs span <= 6.898 s, lower span > 7.015 s.
    for ipg, pause_ms, upper, lower in ((1_500_000_000, 12_102, False, True), (1_250_000_000, 10_602, False, True),
                                        (1_000_000_000, 9_102, True, False)):
        req = tw.pause_requirement(tw.cleanup_bound(population(m4['cfg']), {'READ': ipg, 'OPERATE': 0}))
        assert (req['pause_ms'], req['upper_ok'], req['lower_ok']) == (pause_ms, upper, lower)
        assert req['lower_floor_ns'] == floor
    with pytest.raises(ValueError, match='no delay IPG'):    # the control-timed plan is now infeasible
        tw.plan_isolation(population(m4['cfg']), 0)
    with pytest.raises(ValueError, match='above the endpoint maximum'):
        tw.plan_isolation(population(m4['cfg']), 0, 1_250_000_000)
    with pytest.raises(ValueError, match='before the c2-ready snapshot'):
        tw.plan_isolation(population(m4['cfg']), 0, 1_000_000_000)
    # candidate61 keeps its retained 2.5 s / 10000 ms; its derived requirement (7.5 + 3.001 + 4 + 1.5 - 5.399 s
    # = 10.602 s) no longer fits, which is recorded (fits False, slack -0.602 s), not used to refuse
    legacy = tw.plan_isolation(population(c61['cfg']), 0, legacy=True)
    assert (legacy['delay_ipg_ns'], legacy['pause']['pause_ms'], legacy['pause']['derived_pause_ms']) == \
        (2_500_000_000, 10_000, 10_602)
    assert legacy['pause']['fits'] is False and legacy['pause']['planned_slack_ns'] == -601_926_734
    with pytest.raises(ValueError, match='no delay IPG'):    # two SBO cycles cannot fit at any IPG
        tw.plan_isolation(tw.old_token_population(2, 1, 2, True), 0)


def test_model_only_allowances_give_a_control_timed_plan(m4, monkeypatch):
    hypothetical(monkeypatch)
    plan = tw.plan_isolation(population(m4['cfg']), 0)
    # floor 5.515 + 0.4 + 0 = 5.915 s < 6 s span at 1.0 s; pause 9102 ms -> 10000 ms with 898 ms slack
    assert (plan['delay_ipg_ns'], plan['pause']['pause_ms'], plan['pause']['derived_pause_ms'],
            plan['pause']['planned_slack_ns']) == (1_000_000_000, 10_000, 9_102, 898_073_266)


def test_retained_lifecycle_generations_equal_the_configured_workload(m4, c61):
    for r in (m4, c61):
        expected = generations(r['cfg'])
        assert tw.post_traffic_authority(r['lifecycle']['before'], r['lifecycle']['after'],
                                         expected['after_c3'])['ok']
        start = tw.authority(r['observer']['before'])
        assert {k: start[k] for k in expected['at_c2_ready']} == expected['at_c2_ready']
    assert generations(m4['cfg'])['after_c3'] == dict(T_read_generation=15, T_operate_generation=9)


# ---------------------------------------------------------------- (b) candidate61 accepted exactly as before

def test_candidate61_accepted_as_before(c61):
    obs = c61['observer']
    pop = population(c61['cfg'])
    marker, master, recorded = obs['marker_observation']['marker'], c61['master'], c61['trial']['observed']
    legacy = tw.window_proof(marker, master, obs['before'], obs['after'], obs['restored_vision_ns'])
    derived = tw.window_proof(marker, master, obs['before'], obs['after'], obs['restored_vision_ns'], population=pop)
    assert legacy == derived == recorded['old_token_window']
    assert tw.drained(obs['after'], pop) and tw.legacy_drained(obs['after'])
    assert tw.rejection_delta(obs['before'], obs['after']) == recorded['old_rejection_delta'] == 1
    full = tw.full_run_rejections(c61['full']['before'], c61['full']['after'], obs['after'], pop)
    assert full == {k: recorded['switch'][k] for k in full}
    assert tw.operate_rejection_proof(obs['before'], obs['after'], c61['full']['before'], pop) == \
        recorded['switch']['operate_cohort']
    server = c61['trial']['scenario']['connections']['c2']['fresh_mapping']['server_isn']
    assert compare_quiet_generation(obs['before'], obs['after'], 2, server) == recorded['bank_isolation']
    # the restore tick follows poll 0, so it witnesses poll 0 as quiet (before c2's first READ)
    quiet = tw.quiet_poll_proof(obs['before'], obs['polls'], [obs['restored_vision_ns']],
                                master['first_read_issued_ns'], generations(c61['cfg'])['at_c2_ready'])
    assert quiet['ok'], quiet['failures']


# ---------------------------------------------------------------- MODEL-ONLY m4 completion under the derived plan

def m4_model(m4):
    """MODEL-ONLY: retained m4 counters with the eighth old READ token emitted and rejected in a drain poll;
    every timestamp below is synthetic, anchored on c1's retained first READ issue."""
    obs = copy.deepcopy(m4['observer'])
    drain = copy.deepcopy(obs['polls'][-1])
    set_app(drain, 'read', pkt_counter=8)
    set_raw(drain, '24', 7)
    anchor = m4['c1']['first_read_issued_ns']
    issued = m4['master']['first_read_issued_ns']
    ticks = [issued - 4_000_000_000, issued - 3_500_000_000, issued - 3_000_000_000, issued - 2_500_000_000]
    full_after = copy.deepcopy(m4['full']['after'])
    full_after['outcomes'].update(RAW_READ_TIMER_STALE=7, RAW_OPERATE_TIMER_STALE=4, STALE_BLOCKER=0,
                                  OUT_TOKEN_STALE=11)
    return dict(obs=obs, drain=drain, polls=obs['polls'] + [drain], ticks=ticks, full_after=full_after,
                anchor=anchor, restored=ticks[-1] + 1_000_000_000)


def m4_verdict(m4, model, pop=None):
    pop = pop or population(m4['cfg'])
    obs, drain = model['obs'], model['drain']
    bound = tw.cleanup_bound(pop, {'READ': 2_500_000_000, 'OPERATE': 0})
    cleanup = tw.cleanup_proof(model['anchor'], model['ticks'][-1], bound)
    window = tw.window_proof(obs['marker_observation']['marker'], m4['master'], obs['before'], drain,
                             model['restored'], population=pop, cleanup=cleanup)
    quiet = tw.quiet_poll_proof(obs['before'], model['polls'], model['ticks'], m4['master']['first_read_issued_ns'],
                                generations(m4['cfg'])['at_c2_ready'])
    restore = tw.restore_proof(model['ticks'][-1], model['restored'])
    full = tw.full_run_rejections(m4['full']['before'], model['full_after'], drain, pop)
    operate = tw.operate_rejection_proof(obs['before'], drain, m4['full']['before'], pop)
    return dict(window=window, quiet=quiet, restore=restore, full=full, operate=operate, cleanup=cleanup,
                delta=tw.rejection_delta(obs['before'], drain))


def test_model_only_m4_drained_before_c2_is_accepted(m4):
    result = m4_verdict(m4, m4_model(m4))
    assert result['window']['ok'], result['window']['failures']
    assert result['window']['old_packets_during_pause'] == result['delta'] == 5
    assert result['quiet']['ok'] and result['restore']['ok'] and result['cleanup']['ok']
    assert (result['full']['raw_timer_rejections'], result['full']['raw_operate_rejections']) == (7, 4)


def test_model_only_m4_with_the_old_single_batch_population_is_rejected(m4):
    with pytest.raises(ValueError):
        m4_verdict(m4, m4_model(m4), pop=tw.LEGACY_POPULATION)


# ---------------------------------------------------------------- (c) realistic c2 overlap: both gates refuse

spec = importlib.util.spec_from_file_location('delay_read_tokens_s3', HW / 'delay_read_tokens.py')
delay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(delay)


def test_c2_overlap_state_is_refused_by_window_and_restore_guard(m4):
    model = m4_model(m4)
    set_app(model['drain'], 'read', trigger_counter=3, batch_counter=3, pkt_counter=9)
    pop = population(m4['cfg'])
    assert tw.overran(model['drain'], pop) and not tw.drained(model['drain'], pop)
    assert not m4_verdict(m4, model)['window']['ok']
    entry = dict(model['drain']['read_app_before'])
    with pytest.raises(ValueError, match='exactly the 2 completed old batches'):
        delay.check_app(entry, restore=True, old_triggers=2)
    delay.check_app(dict(entry, trigger_counter=2, batch_counter=2, pkt_counter=8), restore=True, old_triggers=2)


def test_restore_guard_counts_only_the_derived_batches():
    entry = dict(delay.EXPECTED, ipg=1_000_000_000, trigger_counter=2, batch_counter=2, pkt_counter=8)
    delay.check_app(entry, restore=True, old_triggers=2)
    for counters in ((2, 2, 7), (1, 1, 4), (3, 3, 12)):
        with pytest.raises(ValueError):
            delay.check_app(dict(entry, **dict(zip(delay.COUNTERS, counters))), restore=True, old_triggers=2)
    with pytest.raises(ValueError, match='exactly one completed'):
        delay.check_app(entry, restore=True)


# ---------------------------------------------------------------- (d) mutated inputs are rejected

def test_extra_unexpected_old_token_is_rejected(m4, c61):
    obs, pop = c61['observer'], population(c61['cfg'])
    after = copy.deepcopy(obs['after']); set_raw(after, '24', 4)
    full_after = copy.deepcopy(c61['full']['after'])
    full_after['outcomes'].update(RAW_READ_TIMER_STALE=4, OUT_TOKEN_STALE=8)
    with pytest.raises(ValueError, match='exactly the 3 delayed'):
        tw.full_run_rejections(c61['full']['before'], full_after, after, pop)
    extra = copy.deepcopy(obs['after']); set_app(extra, 'read', pkt_counter=5)
    assert not tw.window_proof(obs['marker_observation']['marker'], c61['master'], obs['before'], extra,
                               obs['restored_vision_ns'], population=pop)['ok']
    model = m4_model(m4)
    model['full_after']['outcomes'].update(RAW_READ_TIMER_STALE=8, OUT_TOKEN_STALE=12)
    set_raw(model['drain'], '24', 8)
    with pytest.raises(ValueError, match='exactly the 7 delayed'):
        m4_verdict(m4, model)


def test_old_token_accepted_as_current_is_rejected(m4, c61):
    obs, pop = c61['observer'], population(c61['cfg'])
    after = copy.deepcopy(obs['after']); set_raw(after, '24', 2)
    assert tw.rejection_delta(obs['before'], after) != 1
    full_after = copy.deepcopy(c61['full']['after'])
    full_after['outcomes'].update(RAW_READ_TIMER_STALE=2, OUT_TOKEN_STALE=6)
    with pytest.raises(ValueError, match='exactly the 3 delayed'):
        tw.full_run_rejections(c61['full']['before'], full_after, after, pop)
    op = copy.deepcopy(obs['after']); set_raw(op, '23', 3)
    with pytest.raises(ValueError, match='all 4 tokens'):
        tw.operate_rejection_proof(obs['before'], op, c61['full']['before'], pop)
    model = m4_model(m4)
    model['full_after']['outcomes'].update(RAW_READ_TIMER_STALE=6, OUT_TOKEN_STALE=10)
    set_raw(model['drain'], '24', 6)
    with pytest.raises(ValueError, match='exactly the 7 delayed'):
        m4_verdict(m4, model)


@pytest.mark.parametrize('register,value', [('p0.n_Ingress.owner', (5 << 16) | 3),
                                            ('p1.t_Ingress.gen_alloc_reg', 5),
                                            ('p1.t_Ingress.op_gen_alloc_reg', 5),
                                            ('p1.t_Ingress.cur_epoch_reg', 16)])
def test_changed_owner_or_generation_is_rejected(m4, c61, register, value):
    obs = c61['observer']
    after = copy.deepcopy(obs['after']); set_register(after, register, value)
    quiet = tw.quiet_poll_proof(obs['before'], [after], [obs['restored_vision_ns']],
                                c61['master']['first_read_issued_ns'])
    assert not quiet['ok'] and any('authority changed' in f for f in quiet['failures'])
    model = m4_model(m4)
    set_register(model['polls'][0], register, value + 2)
    assert not m4_verdict(m4, model)['quiet']['ok']


@pytest.mark.parametrize('register,delta', [('p1.t_Ingress.gen_alloc_reg', 1), ('p1.t_Ingress.op_gen_alloc_reg', -1),
                                            ('p0.n_Ingress.owner', 1)])
def test_post_traffic_generation_or_owner_off_workload_is_rejected(m4, register, delta):
    after = copy.deepcopy(m4['lifecycle']['after'])
    entry = after['registers'][register]
    key = next(k for k in entry if k not in ('action_name', 'is_default_entry'))
    entry[key] = [entry[key][0] + delta]
    assert not tw.post_traffic_authority(m4['lifecycle']['before'], after,
                                         generations(m4['cfg'])['after_c3'])['ok']
    before = copy.deepcopy(m4['observer']['before'])
    set_register(before, 'p1.t_Ingress.gen_alloc_reg', 7)
    assert not tw.quiet_poll_proof(before, [before], [0], 1, generations(m4['cfg'])['at_c2_ready'])['ok']


def test_cleanup_bound_exceeded_or_slow_restore_or_unquiet_poll_is_rejected(m4):
    model = m4_model(m4)
    bound_ns = tw.cleanup_bound(population(m4['cfg']), {'READ': 2_500_000_000, 'OPERATE': 0})['bound_ns']
    model['anchor'] = model['ticks'][-1] - bound_ns - 1
    result = m4_verdict(m4, model)
    assert not result['window']['ok'] and any('cleanup bound exceeded' in f for f in result['window']['failures'])
    model = m4_model(m4); model['anchor'] = None
    assert not m4_verdict(m4, model)['window']['ok']
    model = m4_model(m4); model['restored'] = model['ticks'][-1] + tw.RESTORE_ALLOWANCE_NS + 1
    assert not m4_verdict(m4, model)['restore']['ok']
    model = m4_model(m4); model['ticks'][-1] = m4['master']['first_read_issued_ns']
    assert not m4_verdict(m4, model)['quiet']['ok']


# ---------------------------------------------------------------- harness wiring

def campaign(name, model_only=False, **isolation):
    import candidate_isolation as ci
    cfg = ci.base.load_config(str(SEG / 'hw/config' / (name.rsplit('_', 1)[0] + '.json')))
    if isolation:
        cfg['isolation'] = isolation
    with pytest.MonkeyPatch.context() as mp:
        if model_only:
            hypothetical(mp)
        return ci, ci.TokenIsolationCampaign(cfg, ci.base.DryRunner(), 'token_s3', arms=['combined'],
                                             fixtures=['separate_ack'])


def test_harness_derives_population_ipg_pause_and_restore_from_configured_workload():
    with pytest.raises(ValueError, match='no delay IPG'):      # shipped allowances: the m4/m5 block is refused
        campaign(M4)
    ci, m4run = campaign(M4, model_only=True)
    assert m4run.population['READ']['triggers'] == 2 and m4run.installed_ipg == {'READ': 0, 'OPERATE': 0}
    assert (m4run.delay_ipg_ns, m4run.pause_ms) == (1_000_000_000, 10_000)
    _, c61run = campaign(C61)
    assert c61run.population == tw.LEGACY_POPULATION and (c61run.delay_ipg_ns, c61run.pause_ms) == (2_500_000_000,
                                                                                                   10_000)
    for run_, triggers, ipg, pause in ((m4run, 2, 1_000_000_000, 10_000), (c61run, 1, 2_500_000_000, 10_000)):
        run_.active_unit = (run_.units()[0], 0, 'x')
        command = run_.delay_command('/r.json', '/d.json')
        assert '--ipg-ns %d' % ipg in command and '--old-triggers %d' % triggers in command
        run_._series_padding = 1
        assert '--pre-read-grace-ms %d' % pause in run_.series_vision_cmd('fixed', 59412, 1, 8, 0)
    with pytest.raises(ValueError, match='above the endpoint maximum'):
        campaign(M4, delay_ipg_ns=2_500_000_000)
    with pytest.raises(ValueError, match='1..4 seconds'):
        campaign(M4, delay_ipg_ns=500_000_000)


def test_operate_cohort_beyond_population_is_rejected(c61):
    obs, pop = c61['observer'], population(c61['cfg'])
    after = copy.deepcopy(obs['after']); set_app(after, 'operate', pkt_counter=5); set_raw(after, '23', 5)
    with pytest.raises(ValueError, match='all 4 tokens'):
        tw.operate_rejection_proof(obs['before'], after, c61['full']['before'], pop)


def test_extra_trigger_at_drain_is_rejected_even_with_exact_packets(m4):
    model = m4_model(m4)
    set_app(model['drain'], 'read', trigger_counter=3, batch_counter=3)
    window = m4_verdict(m4, model)['window']
    assert not window['ok'] and any('old READ-lane batches' in f for f in window['failures'])


# ---------------------------------------------------------------- the derived control-timed plan, end to end

def test_model_only_derived_m4_plan_passes_window_and_cleanup(m4, monkeypatch):
    """MODEL-ONLY: m4's derived plan (1.25 s delay, 10000 ms c2 pause) with retained m4 counts; timestamps are
    synthetic but placed by the plan: c2 ready at the measured minimum after c1's first READ, last old READ
    token at 7.5 s, drained poll observed within the bound, restore inside its allowance, c2 READ at the pause."""
    hypothetical(monkeypatch)
    pop, plan = population(m4['cfg']), tw.plan_isolation(population(m4['cfg']), 0)
    ipg, pause_ms = plan['delay_ipg_ns'], plan['pause']['pause_ms']
    span = plan['bound']['last_old_read_token_ns']
    anchor = m4['c1']['first_read_issued_ns']
    ready = anchor + tw.C1_TO_C2_READY_MIN_NS
    marker = dict(m4['observer']['marker_observation']['marker'], pre_read_grace_ms=pause_ms, pre_read_ready_ns=ready)
    master = dict(m4['master'], pre_read_grace_ms=pause_ms, pre_read_ready_ns=ready,
                  first_read_issued_ns=ready + pause_ms * 1_000_000 + 300_000)
    before = copy.deepcopy(m4['observer']['before'])
    drain = copy.deepcopy(m4['observer']['polls'][-1])
    for snap in (before, drain):
        set_app(snap, 'read', ipg=ipg)
    set_app(drain, 'read', pkt_counter=8); set_raw(drain, '24', 7)
    drained_tick = anchor + span + 2_600_000_000                        # last old token + one poll period
    assert drained_tick < ready + pause_ms * 1_000_000 - tw.RESTORE_ALLOWANCE_NS - tw.ABORT_MARGIN_NS
    restored = drained_tick + 3_500_000_000
    cleanup = tw.cleanup_proof(anchor, drained_tick, plan['bound'])
    assert cleanup['ok'] and cleanup['elapsed_ns'] <= plan['bound']['bound_ns'] == 9_001_000_000
    window = tw.window_proof(marker, master, before, drain, restored, population=pop, cleanup=cleanup,
                             delay_ipg_ns=ipg, pause_ms=pause_ms)
    assert window['ok'], window['failures']
    assert tw.restore_proof(drained_tick, restored)['ok']
    assert restored < ready + pause_ms * 1_000_000
    # the same evidence judged against another pause (the minimum 9102 ms) or the retained 2.5 s delay is refused
    assert not tw.window_proof(marker, master, before, drain, restored, population=pop, cleanup=cleanup,
                               delay_ipg_ns=ipg, pause_ms=plan['pause']['derived_pause_ms'])['ok']
    assert not tw.window_proof(marker, master, before, drain, restored, population=pop, cleanup=cleanup,
                               pause_ms=pause_ms)['ok']


# ---------------------------------------------------------------- monitor(): derived-pause marker, fail-safe

RUNS = '/home/decps/run/runs'


def fake_proc(root, processes):
    """A /proc stand-in: one numbered directory per process with a NUL-separated cmdline."""
    for pid, argv in processes.items():
        (root / str(pid)).mkdir(parents=True)
        (root / str(pid) / 'cmdline').write_bytes(b'\0'.join(a.encode() for a in argv) + b'\0')
    (root / 'self').mkdir(parents=True, exist_ok=True)
    return root


def c2_master(label='lbl'):
    return ['/opt/case4/socket_gate', 'master', '192.168.10.62', '20000', '%s/%s/c2/stop.master' % (RUNS, label), '1']


class FakeVision:
    """Vision stand-in. The abort command runs the REAL vision_isolation.abort_c2 over a fake /proc; os.kill is
    replaced so a killed process disappears (or, unkillable, survives). sudo_refused models `sudo -n` refusal.
    done is set after stop_after_aborts abort calls, as the Vision series would end."""
    dry = False

    def __init__(self, marker, c1_first, ticks, proc, done, sudo_refused=False, unkillable=False,
                 marker_failures=0, stop_after_aborts=1, processes=None, kill_error=False):
        self.marker, self.c1_first, self.ticks, self.calls = marker, c1_first, list(ticks), []
        self.proc, self.done = proc, done
        self.sudo_refused, self.unkillable, self.marker_failures = sudo_refused, unkillable, marker_failures
        self.stop_after_aborts, self.aborts, self.kill_error = stop_after_aborts, [], kill_error
        fake_proc(proc, {4242: c2_master()} if processes is None else processes)

    def kill(self, pid, sig):
        if not self.unkillable:
            import shutil
            shutil.rmtree(self.proc / str(pid))
        if self.kill_error:                         # the process went away, but the kill itself reported an error
            raise PermissionError(1, 'Operation not permitted')

    def run(self, where, cmd, cwd=None, timeout=None, label=None):
        import time as clock
        import candidate_isolation as ci
        self.calls.append((where, label, cmd, clock.monotonic()))
        if label == 'wait for c2 marker':
            if self.marker_failures:
                self.marker_failures -= 1
                return ci.base.Result(255, '', 'ssh: connect to host vision: Connection timed out')
            return ci.base.Result(0, json.dumps(dict(marker=self.marker, marker_status='complete',
                                                     vision_ns=self.marker['pre_read_ready_ns'] + 1)), '')
        if label == 'read c1 first READ issue':
            return ci.base.Result(0, json.dumps(dict(marker=dict(first_read_issued_ns=self.c1_first))), '')
        if label in ('observe bounded pause', 'confirm IPG restore completion on Vision clock'):
            tick = self.ticks.pop(0)
            if tick is None:
                return ci.base.Result(1, '', 'marker read failed')
            return ci.base.Result(0, json.dumps(dict(vision_ns=tick)), '')
        if 'abort-c2' in cmd:
            assert cmd.startswith('sudo -n python3 -c ') and cmd.endswith(' abort-c2 lbl')
            self.aborts.append(clock.monotonic())
            if len(self.aborts) >= self.stop_after_aborts:
                self.done.set()
            if self.sudo_refused:
                return ci.base.Result(1, '', 'sudo: a password is required')
            import os
            import vision_isolation as vi
            real = os.kill
            os.kill = self.kill
            try:
                result = vi.abort_c2('lbl', runs=RUNS, proc=str(self.proc), settle_s=0)
            finally:
                os.kill = real
            return ci.base.Result(vi.abort_exit_code(result), json.dumps(result), '')
        return ci.base.Result(0, '', '')


def monitor_run(m4, tmp_path, snapshots, ticks, restore=None, snapshot=None, **vision_kwargs):
    import threading
    ci, run = campaign(M4, model_only=True)
    ready = 1_000_000_000_000
    marker = dict(tcp_open=True, opens=1, pre_read_grace_ms=run.pause_ms, pre_read_ready_ns=ready,
                  first_read_issued_ns=0)
    done = threading.Event()
    vision = FakeVision(marker, ready - tw.C1_TO_C2_READY_MIN_NS, [None if t is None else ready + t for t in ticks],
                        tmp_path / 'proc', done, **vision_kwargs)
    run.rn = vision
    run.root = str(tmp_path)
    run.active_unit = (run.units()[0], 0, 'lbl')
    run.window.update(delay_remote='/snap/delay.json', delay_time=1.0)
    queue = list(snapshots)

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
    return run, vision, steps


def m4_monitor_snapshots(m4):
    before = copy.deepcopy(m4['observer']['before'])
    mid = copy.deepcopy(m4['observer']['polls'][0])
    drain = copy.deepcopy(m4['observer']['polls'][-1]); set_app(drain, 'read', pkt_counter=8)
    return before, mid, drain


def restores(steps):
    return [s for s in steps if s[1].startswith('restore READ IPG')]


def test_monitor_accepts_the_endpoint_maximum_pause_and_restores_before_c2_read(m4, tmp_path):
    before, mid, drain = m4_monitor_snapshots(m4)
    run, vision, steps = monitor_run(m4, tmp_path, [before, mid, drain], [3_000_000_000, 4_000_000_000,
                                                                          5_000_000_000])
    assert run.pause_ms == 10_000
    assert run.window['monitor_ok'] is True, run.window.get('error')
    restore = restores(steps)
    assert len(restore) == 1 and '--old-triggers 2' in restore[0][2] and '--budget-s ' in restore[0][2]
    # 10 s pause - 4 s drained tick - 1.5 s abort margin, measured on the local monotonic clock
    assert 4.0 < restore[0][3] <= 4.5
    # restore gate (10 - 4 - 1.5 = 4.5 s) - drained tick 4 s
    assert run.window['runtime_slack_ns'] == 500_000_000
    assert vision.aborts == [] and 'c2_abort' not in run.window
    order = [call[1] for call in vision.calls]
    assert order.index('read c1 first READ issue') > order.index('quiet snapshot before')   # no added latency
    assert json.loads((tmp_path / 'token_window_observer.json').read_text())['monitor_ok'] is True


@pytest.mark.parametrize('drain_tick', [10_000_000_000 - tw.RESTORE_ALLOWANCE_NS - tw.ABORT_MARGIN_NS, 6_000_000_000, None])
def test_drained_poll_with_a_late_or_missing_tick_aborts_and_never_restores(m4, tmp_path, drain_tick):
    before, mid, drain = m4_monitor_snapshots(m4)
    run, vision, steps = monitor_run(m4, tmp_path, [before, mid, drain], [3_000_000_000, drain_tick])
    assert run.window['monitor_ok'] is False and 'did not drain with time to restore' in run.window['error']
    assert restores(steps) == [] and not any(s[0] == 'switch' for s in steps)
    assert run.window['c2_abort']['aborted'] is True and run.window['c2_abort_confirmed'] is True


def test_monitor_without_drain_before_the_deadline_aborts_c2_and_never_restores(m4, tmp_path):
    before, mid, _ = m4_monitor_snapshots(m4)
    late = 10_000_000_000 - tw.RESTORE_ALLOWANCE_NS - tw.ABORT_MARGIN_NS
    run, vision, steps = monitor_run(m4, tmp_path, [before, mid, copy.deepcopy(mid)], [3_000_000_000, late])
    assert run.window['monitor_ok'] is False and 'did not drain' in run.window['error']
    assert restores(steps) == []
    abort = run.window['c2_abort']
    assert (abort['rc'], abort['aborted'], abort['report']['matched'], abort['report']['remaining']) == \
        (0, True, [4242], [])
    assert not (tmp_path / 'proc' / '4242').exists()


@pytest.mark.parametrize('kwargs,meaning', [(dict(sudo_refused=True), 'sudo refused the permitted helper'),
                                            (dict(unkillable=True), 'a c2 master remains or a kill failed'),
                                            (dict(processes={}), 'no c2 master process matched'),
                                            (dict(kill_error=True), 'a c2 master remains or a kill failed')])
def test_abort_that_does_not_kill_a_c2_master_is_recorded_as_not_aborted(m4, tmp_path, kwargs, meaning):
    before, mid, _ = m4_monitor_snapshots(m4)
    run, vision, steps = monitor_run(m4, tmp_path, [before, mid, copy.deepcopy(mid)],
                                     [3_000_000_000, 10_000_000_000], stop_after_aborts=2, **kwargs)
    abort = run.window['c2_abort']
    assert abort['aborted'] is False and run.window['c2_abort_history'][0]['meaning'] == meaning
    assert run.window['c2_abort_confirmed'] is False and run.window['c2_abort_attempts'] == 2
    assert 'ABORT NOT CONFIRMED' in abort['note']
    assert abort['sudo_refused'] is bool(kwargs.get('sudo_refused'))
    # the last attempt finds nothing left when the first already removed the master (kill_error) or none existed
    assert abort['c2_already_exited'] is ('processes' in kwargs or 'kill_error' in kwargs)


def test_monitor_with_a_wrong_pause_marker_fails_and_aborts_c2(m4, tmp_path):
    import threading
    ci, run = campaign(M4, model_only=True)
    marker = dict(tcp_open=True, opens=1, pre_read_grace_ms=tw.PRE_READ_GRACE_MS - 1, pre_read_ready_ns=10 ** 12,
                  first_read_issued_ns=0)
    done = threading.Event()
    vision = FakeVision(marker, 1, [], tmp_path / 'proc', done)
    run.rn, run.root, run.active_unit = vision, str(tmp_path), (run.units()[0], 0, 'lbl')
    run.monitor(done)
    assert run.window['monitor_ok'] is False and 'bounded%dms pause' % run.pause_ms in run.window['error']
    assert run.window['c2_abort_confirmed'] is True


def test_marker_reads_are_retried_and_a_lost_observer_keeps_aborting_until_the_series_ends(m4, tmp_path):
    before, mid, drain = m4_monitor_snapshots(m4)
    ok, *_ = monitor_run(m4, tmp_path / 'ok', [before, mid, drain], [3_000_000_000, 4_000_000_000, 5_000_000_000],
                         marker_failures=2)
    assert ok.window['monitor_ok'] is True, ok.window.get('error')
    lost, vision, steps = monitor_run(m4, tmp_path / 'lost', [], [], marker_failures=3, stop_after_aborts=3,
                                      processes={})
    assert lost.window['monitor_ok'] is False and '3 consecutive' in lost.window['error']
    assert 'marker_observation' not in lost.window                # aborts start before the marker is seen
    assert len(vision.aborts) == 3 and lost.window['c2_abort_attempts'] == 3
    assert lost.window['c2_abort']['c2_already_exited'] is True


def test_restore_timeout_aborts_c2_before_the_pause_deadline(m4, tmp_path, monkeypatch):
    import time as clock
    import candidate_isolation as ci
    monkeypatch.setattr(ci, 'ABORT_MARGIN_S', 5.0)      # keep the test short: abort point ~0.6 s after drain

    def hang(timeout):
        clock.sleep(timeout + 0.1)
        raise ci.base.StepFailed('restore step timed out after %.3f s' % timeout)
    before, mid, drain = m4_monitor_snapshots(m4)
    run, vision, steps = monitor_run(m4, tmp_path, [before, mid, drain],
                                     [3_000_000_000, 4_400_000_000], restore=hang, stop_after_aborts=1)
    assert run.window['monitor_ok'] is False
    assert vision.aborts and vision.aborts[0] < run.window['pause_deadline_local']
    assert run.window['watchdog_fired_local'] >= run.window['abort_at_local'] - 0.01
    assert run.window['c2_abort_confirmed'] is True and restores(steps)[0][3] <= 0.6     # 10 - 4.4 - 5.0 s


def test_vision_abort_kills_only_the_exact_c2_master_and_never_itself(tmp_path, monkeypatch):
    import os
    import vision_isolation as vi
    proc = fake_proc(tmp_path / 'proc', {
        4242: c2_master(),
        4243: c2_master('other'),                                              # another label's c2
        4244: ['sudo', '-n', 'python3', '-c', 'x', '/v/vision_isolation.py', 'abort-c2', 'lbl'],  # the helper
        4245: ['/opt/case4/socket_gate', 'master', '%s/lbl/c1/stop.master' % RUNS]})        # c1, not c2
    killed = []

    def kill(pid, sig):
        killed.append(pid)
        import shutil
        shutil.rmtree(proc / str(pid))
    monkeypatch.setattr(os, 'kill', kill)
    result = vi.abort_c2('lbl', runs=RUNS, proc=str(proc), settle_s=0)
    assert (result['matched'], killed, result['remaining']) == ([4242], [4242], [])
    assert vi.abort_exit_code(result) == 0
    assert vi.abort_exit_code(vi.abort_c2('lbl', runs=RUNS, proc=str(proc), settle_s=0)) == 1
    with pytest.raises(ValueError):
        vi.abort_c2('lbl;rm', runs=RUNS, proc=str(proc))


def test_restore_budget_refuses_late_writes():
    delay.check_budget(10.0, None, 99.0)
    delay.check_budget(10.0, 2.0, 11.4)
    with pytest.raises(ValueError, match='budget'):
        delay.check_budget(10.0, 2.0, 11.6)


# ---------------------------------------------------------------- verdict(): real proofs on retained candidate61

def _c61_verdict_inprocess(tmp_path, failing=(), refresh_pins=True, inject_lifecycle=False, abort_unconfirmed=False):
    """Runs TokenIsolationCampaign.verdict on a copy of the retained candidate61 trial with every proof real.
    Only three inputs are not retained: the Vision source pins are refreshed to the current helper hashes (the
    retained run pinned the helpers of its day), the drained-poll Vision tick is the switch->Vision mapped
    completion time of poll 0 (estimate), and the independent wire/clrt script exit codes come from the runner."""
    import shutil
    import candidate_isolation as ci
    name, label = C61, C61 + '_separate_ack_combined_t0'
    dest = tmp_path / label
    shutil.copytree(CAMPAIGNS / name / 'separate_ack/combined' / label, dest)

    class Runner:
        dry = False

        def run(self, where, cmd, cwd=None, timeout=None, label=None):
            rc = int(any(key in (label or '') for key in failing))
            return ci.base.Result(rc, '', '')
    _, run = campaign(C61)
    run.rn = Runner()
    run.out = lambda *a, **k: None
    scenario = load(dest / 'scenario.json')
    pins = {run.V + '/' + n: ci.base.sha256_file(p) for n, p in ci.cs.VISION_EXTRA.items()}
    pins.update({run.V + '/vision_isolation.py': ci.base.sha256_file(HW / 'vision_isolation.py'),
                 run.V + '/vision_run.py': ci.base.sha256_file(ci.ARCH / 'protocol/hw_vepa/vision_run.py'),
                 run.V + '/token_window.py': ci.base.sha256_file(HW / 'token_window.py'),
                 run.V + '/snapshot_lifecycle.py': ci.base.sha256_file(HW / 'snapshot_lifecycle.py')})
    if refresh_pins:
        scenario['source_sha256'] = pins
    if inject_lifecycle:
        ci.cs.lifecycle_gate = lambda *a, **k: (['injected lifecycle failure'], {})
    (dest / 'scenario.json').write_text(json.dumps(scenario))
    obs = load(CAMPAIGNS / name / 'token_window_observer.json')
    tick = obs['marker_observation']['vision_ns'] + int(round((obs['polls'][0]['completed_time'] -
                                                                obs['before']['time']) * 1e9))
    run.window.update(obs)
    run.window.update(c1_first_read_issued_ns=load(dest / 'c1/master.json')['first_read_issued_ns'],
                      poll_vision_ns=[tick], drained_vision_ns=tick)
    if abort_unconfirmed:
        run.window['c2_abort'] = dict(aborted=False, note='ABORT NOT CONFIRMED: test')
    retained = load(dest / 'trial.json')
    trial = {k: v for k, v in retained.items() if k not in ('ok', 'failures', 'observed', 'scenario')}
    try:
        run.verdict(trial, {}, label, str(dest), ci.base.Result(0, '', ''), run.arms[0], 'separate_ack')
    except ci.base.StepFailed:
        pass
    return trial, load(dest / 'isolation_verdict.json')


def c61_verdict(tmp_path, failing=(), refresh_pins=True, inject_lifecycle=False, abort_unconfirmed=False):
    """Run the real verdict in a fresh interpreter: the standards capture checker it loads is sensitive to
    modules other test files leave in sys.modules, so an in-process run depends on test order."""
    import subprocess
    Path(tmp_path).mkdir(parents=True, exist_ok=True)
    code = ('import json,sys; sys.path.insert(0,%r); import test_stale_isolation_s3 as t; from pathlib import Path; '
            'print(json.dumps(t._c61_verdict_inprocess(Path(%r),%r,%r,%r,%r)))'
            % (str(Path(__file__).parent), str(tmp_path), tuple(failing), refresh_pins, inject_lifecycle,
               abort_unconfirmed))
    result = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True,
                            env=dict(__import__('os').environ, PYTHONDONTWRITEBYTECODE='1'), timeout=300)
    assert result.returncode == 0, result.stderr[-3000:]
    trial, isolation = json.loads(result.stdout.strip().splitlines()[-1])
    return trial, isolation


def test_retained_candidate61_passes_the_full_isolation_verdict_with_real_proofs(tmp_path):
    trial, isolation = c61_verdict(tmp_path)
    assert isolation['failures'] == [] and isolation['ok'] is True and trial['ok'] is True, \
        (isolation['failures'], trial['failures'])
    assert isolation['cleanup']['ok'] and isolation['restore']['ok'] and isolation['quiet_polls']['ok']
    assert isolation['post_traffic_authority']['ok'] and isolation['plan']['legacy'] is True


@pytest.mark.parametrize('failing,expected', [(('clrt_check',), 'c1: clrt_check.py failed rc1'),
                                              (('c2 wire_check',), 'c2: wire_check.py failed rc1')])
def test_a_failing_independent_check_makes_isolation_fail(tmp_path, failing, expected):
    trial, isolation = c61_verdict(tmp_path, failing)
    assert isolation['ok'] is False and expected in isolation['failures'] and trial['ok'] is False
    if 'wire' in expected:      # transport_ok now sees the wire_check failure (it never did before)
        assert any('c2: standards' in f for f in isolation['failures'])


def test_stale_pins_and_lifecycle_failures_are_part_of_the_isolation_verdict(tmp_path):
    _, isolation = c61_verdict(tmp_path / 'pins', refresh_pins=False)
    assert not isolation['ok'] and 'collected Vision scenario source pins differ from deployed helpers' in \
        isolation['failures']
    _, isolation = c61_verdict(tmp_path / 'life', inject_lifecycle=True)
    assert not isolation['ok'] and 'lifecycle: injected lifecycle failure' in isolation['failures']


def test_planner_refuses_when_only_the_lower_bound_fails():
    # k = 1: two tokens per trigger, so even 2.5 s gives a 5 s READ span, below the 7.015 s floor, while the
    # pause (5 + 3.001 + 4 - 5.399 s = 6.602 s) would fit
    pop = tw.old_token_population(1, 1, 1, True)
    req = tw.pause_requirement(tw.cleanup_bound(pop, {'READ': 2_500_000_000, 'OPERATE': 0}))
    assert req['upper_ok'] and not req['lower_ok']
    with pytest.raises(ValueError, match='no delay IPG'):
        tw.plan_isolation(pop, 0)


def test_an_unconfirmed_c2_abort_fails_the_isolation_verdict(tmp_path):
    _, isolation = c61_verdict(tmp_path, abort_unconfirmed=True)
    assert not isolation['ok'] and any(f.startswith('c2 fail-safe abort not confirmed') for f in isolation['failures'])


# ---------------------------------------------------------------- W2: abort-path preflight before any traffic

class PreflightRunner:
    dry = False

    def __init__(self, rc, out, delay=0.0, err=''):
        self.rc, self.out, self.delay, self.err, self.calls = rc, out, delay, err, []

    def run(self, where, cmd, cwd=None, timeout=None, label=None):
        import time as clock
        import candidate_isolation as ci
        self.calls.append(cmd)
        clock.sleep(self.delay)
        return ci.base.Result(self.rc, self.out, self.err)


NO_MASTER = json.dumps(dict(target='x', matched=[], killed=[], remaining=[], errors=[], c2_already_exited=True))


def test_abort_preflight_accepts_a_fast_no_master_answer():
    ci, run = campaign(C61)
    run.rn = PreflightRunner(1, NO_MASTER)
    run.abort_preflight()
    record = run.record['abort_preflight']
    assert record['ok'] is True and record['wall_s'] < ci.ABORT_PREFLIGHT_MAX_S
    assert run.rn.calls[0].startswith('sudo -n python3 -c ') and ' abort-c2 abortpreflighttokens3' in run.rn.calls[0]


@pytest.mark.parametrize('rc,out,delay,err', [(1, NO_MASTER, 0.85, ''),                       # too slow
                                              (0, NO_MASTER, 0.0, ''),                        # wrong exit
                                              (1, '', 0.0, 'sudo: a password is required'),   # refused
                                              (1, json.dumps(dict(matched=[7], c2_already_exited=False)), 0.0, '')])
def test_abort_preflight_refuses_the_block(rc, out, delay, err):
    ci, run = campaign(C61)
    run.rn = PreflightRunner(rc, out, delay, err)
    with pytest.raises(ci.base.StepFailed, match='block refused'):
        run.abort_preflight()
    assert run.record['abort_preflight']['ok'] is False


# ---------------------------------------------------------------- W4/W5: watchdog armed at the marker, lock

def test_watchdog_armed_at_the_marker_aborts_c2_during_a_hung_quiet_poll(m4, tmp_path, monkeypatch):
    import time as clock
    import candidate_isolation as ci
    monkeypatch.setattr(ci, 'ABORT_MARGIN_S', 9.7)     # abort point 0.3 s after the marker, for a short test
    before, mid, _ = m4_monitor_snapshots(m4)
    order = []

    def hung_poll(label, suffix):
        if suffix != 'before':
            clock.sleep(0.8)                             # a poll that hangs past the abort point
            order.append(('poll returned', clock.monotonic()))
            raise ci.base.StepFailed('quiet snapshot timed out')
        return before
    run, vision, steps = monitor_run(m4, tmp_path, [], [], stop_after_aborts=2, snapshot=hung_poll)
    assert vision.aborts[0] < order[0][1] and vision.aborts[0] < run.window['pause_deadline_local']
    assert run.window['watchdog_fired_local'] >= run.window['abort_at_local'] - 0.01
    assert restores(steps) == [] and run.window['monitor_ok'] is False
    assert run.window['c2_abort_confirmed'] is True


def test_watchdog_lock_makes_fired_and_confirmed_exclusive():
    import time as clock
    import candidate_isolation as ci
    aborts = []
    dog = ci.Watchdog(lambda: aborts.append(clock.monotonic()))
    dog.arm(clock.monotonic())                       # fires at once
    clock.sleep(0.2)
    assert aborts and dog.fired_at is not None
    assert dog.confirm() is False                    # a restore confirmed just after the watchdog fired is refused
    dog = ci.Watchdog(lambda: aborts.append('late'))
    dog.arm(clock.monotonic() + 0.3)
    assert dog.confirm() is True and dog.timer is None
    clock.sleep(0.4)
    assert 'late' not in aborts                      # cancelled and joined: it never fires after confirmation


def test_restore_that_succeeds_just_after_the_watchdog_fired_fails_the_monitor(m4, tmp_path, monkeypatch):
    import time as clock
    import candidate_isolation as ci
    monkeypatch.setattr(ci, 'ABORT_MARGIN_S', 5.2)   # abort point ~0.4 s after the drained poll

    def slow_but_ok(timeout):
        clock.sleep(timeout + 0.1)                   # finishes just after the watchdog fired
        return ci.base.Result(0, '', '')
    before, mid, drain = m4_monitor_snapshots(m4)
    run, vision, steps = monitor_run(m4, tmp_path, [before, mid, drain], [3_000_000_000, 4_400_000_000,
                                                                          4_600_000_000],
                                     restore=slow_but_ok, stop_after_aborts=1)
    assert run.window['monitor_ok'] is False and 'c2 was aborted' in run.window['error']
    assert 'restored_vision_ns' not in run.window and run.window['c2_abort_confirmed'] is True


# ---------------------------------------------------------------- S2/S4: helper matching and the restore CLI

@pytest.mark.parametrize('argv', [['/opt/case4/socket_gate', 'outstation', '192.168.10.62', '20000',
                                   RUNS + '/lbl/c2/stop', '60'],
                                  ['/opt/case4/socket_gate', 'master', RUNS + '/lbl/c2/stop.master.x']])
def test_vision_abort_ignores_the_outstation_and_suffixed_paths(tmp_path, monkeypatch, argv):
    import os
    import vision_isolation as vi
    proc = fake_proc(tmp_path / 'proc', {5000: argv})
    monkeypatch.setattr(os, 'kill', lambda *a: pytest.fail('nothing may be killed'))
    result = vi.abort_c2('lbl', runs=RUNS, proc=str(proc), settle_s=0)
    assert result['matched'] == [] and vi.abort_exit_code(result) == 1


def test_restore_cli_checks_the_budget_before_writing_and_rejects_budget_without_restore(tmp_path):
    import inspect
    import subprocess
    body = inspect.getsource(delay.main)
    assert body.index('check_budget(started') < body.index('change_ipg(sw')
    result = subprocess.run([sys.executable, str(HW / 'delay_read_tokens.py'), '--build-out', str(tmp_path),
                             '--expected-bfrt-sha256', '0' * 64, '--switch-tools', str(tmp_path),
                             '--record', str(tmp_path / 'r.json'), '--budget-s', '1'],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 2 and 'requires --restore' in result.stderr


def test_watchdog_never_aborts_after_confirmation_and_cancel_waits_for_a_running_abort():
    import time as clock
    import candidate_isolation as ci
    aborts = []
    dog = ci.Watchdog(lambda: aborts.append('fired'))
    dog.arm(clock.monotonic() + 5)
    assert dog.confirm() is True
    dog._fire()                                      # a timer callback that raced the confirmation
    assert aborts == []
    finished = []

    def slow_abort():
        clock.sleep(0.3)
        finished.append(clock.monotonic())
    dog = ci.Watchdog(slow_abort)
    dog.arm(clock.monotonic())
    clock.sleep(0.05)                                # the abort is running inside the timer thread
    dog.cancel()
    assert finished, 'cancel() returned before the running abort finished (no join)'


def test_vision_identity_runs_the_abort_preflight_before_any_traffic(monkeypatch):
    import candidate_isolation as ci
    _, run = campaign(C61)
    calls = []
    monkeypatch.setattr(ci.cs.CandidateSeriesCampaign, 'vision_identity', lambda self: calls.append('series'))
    monkeypatch.setattr(run, '_copy_verify', lambda *a: calls.append('copy'))
    monkeypatch.setattr(run, 'abort_preflight', lambda: calls.append('preflight'))
    run.rn = PreflightRunner(1, NO_MASTER)
    run.vision_identity()
    assert calls == ['series', 'copy', 'preflight']

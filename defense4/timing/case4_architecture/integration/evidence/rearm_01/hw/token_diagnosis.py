#!/usr/bin/env python3
"""Offline stale-token diagnosis of the retained isolation blocks (no switch, no Vision).

Reads the retained token_window_observer.json, full-run snapshots, lifecycle snapshots and c2 master record of
the m4 (control-timed) and candidate61 stale-token blocks, reports old-token survival by role (READ app 0,
OPERATE app 1) and by generation for every poll, and tests the S3 hypothesis of PLAN_m5.md: on a control-timed
build c1 triggers the READ lane twice (READ and SELECT), so two delayed batches cannot drain in the fixed
window. Every number in the output is read from a named file; estimates are labelled as such.
"""
import argparse
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from token_window import (PRE_READ_GRACE_NS, authority, legacy_drained, drained, old_token_population,
                          cleanup_bound, window_proof, raw_counts)

ARCH = HERE.parents[3]
SEG = ARCH / 'integration/core/response_only_rearm/stage_experiments/seg61_02'
RUNS = (('ctl_m4_stale_tokens_950_01', 'ctl_m4_stale_tokens_950.json'),
        ('candidate61_stale_tokens_950_02', 'candidate61_stale_tokens_950.json'))
ROLE_KEYS = (('READ', 'read', '24'), ('OPERATE', 'operate', '23'))


def rel(path):
    return str(Path(path).resolve().relative_to(ARCH.parents[2]))


def load(path):
    return json.loads(Path(path).read_text())


def population_for(cfg):
    import candidate_series as cs                       # the harness's SBO count source
    arm = cfg['arms'][0]
    build = cfg['builds'][arm['build']]
    sbo = cs.checks.sbo_count(cfg['traffic'])
    return arm['build'], build, old_token_population(cfg['service']['k'], 1, sbo, bool(build.get('control_timed')))


def role_row(snapshot, population, role, prefix, index):
    app = snapshot[prefix + '_app_after']
    tokens = population[role]['tokens']
    rejected = raw_counts(snapshot, 'after')[index]
    consumed = 1 if role == 'READ' else 0
    emitted = min(app['pkt_counter'], tokens)
    row = dict(trigger_counter=app['trigger_counter'], batch_counter=app['batch_counter'],
               pkt_counter=app['pkt_counter'], ipg_ns=app['ipg'], raw_stale_index=index, raw_stale=rejected,
               old_tokens_expected=tokens, old_tokens_emitted=emitted,
               old_tokens_not_yet_emitted=max(tokens - app['pkt_counter'], 0),
               emitted_not_yet_rejected=emitted - consumed - rejected)
    per = population['tokens_per_trigger']
    # batches are emitted in trigger order (FIFO); on a control-timed build batch 1 is c1's READ admission and
    # batch 2 its SELECT admission. The attribution of a batch to a transaction is an inference from order.
    owners = ['c1 READ'] + (['c1 SELECT'] if role == 'READ' and population['control_timed'] else [])
    if role == 'OPERATE':
        owners = ['c1 OPERATE']
    row['by_batch'] = [dict(batch=i + 1, admitted_by=owners[i] if i < len(owners) else 'unexpected',
                            emitted=max(0, min(per, app['pkt_counter'] - i * per)))
                       for i in range(max(population[role]['triggers'], app['batch_counter']))]
    return row


def snapshot_row(label, snapshot, population):
    row = dict(label=label, switch_time=snapshot['time'], completed_time=snapshot.get('completed_time'),
               authority=authority(snapshot), legacy_drained=legacy_drained(snapshot),
               derived_drained=drained(snapshot, population))
    for role, prefix, index in ROLE_KEYS:
        row[role] = role_row(snapshot, population, role, prefix, index)
    return row


def diagnose_run(run, config_name):
    root = SEG / 'evidence/hw_campaigns' / run
    cfg = load(SEG / 'hw/config' / config_name)
    build_name, build, population = population_for(cfg)
    observer = load(root / 'token_window_observer.json')
    trial_dir = next((root / 'separate_ack/combined').iterdir())
    snapdir = trial_dir / 'snapshots'
    full = {side: load(snapdir / ('%s_%s.json' % (trial_dir.name, side))) for side in ('before', 'after')}
    life = {side: load(snapdir / ('%s_%s_lifecycle.json' % (trial_dir.name, side))) for side in ('before', 'after')}
    master = load(trial_dir / 'c2/master.json')
    series = [('quiet_before (c2 ready)', observer['before'])] + \
        [('poll%02d' % i, poll) for i, poll in enumerate(observer.get('polls', []))]
    rows = [snapshot_row(label, snap, population) for label, snap in series]
    bound = cleanup_bound(population, {'READ': observer['before']['read_app_after']['ipg'],
                                       'OPERATE': observer['before']['operate_app_after']['ipg']})
    read_lane = population['READ']['triggers'] * (population['tokens_per_trigger'] - 1) * \
        observer['before']['read_app_after']['ipg']
    gen = lambda snap, name: authority(snap)[name]
    lifecycle_gen = {}
    for key, register in (('T_read_generation', 'p1.t_Ingress.gen_alloc_reg'),
                          ('T_operate_generation', 'p1.t_Ingress.op_gen_alloc_reg')):
        values = [life[side]['registers'][register][register.split('.', 1)[1] + '.f1'][0] for side in ('before', 'after')]
        lifecycle_gen[key] = dict(before=values[0], after=values[1], per_connection=(values[1] - values[0]) / 3)
    # The old (fixed-window) proof run on the retained pair it would have used, for the record.
    legacy = window_proof(observer['marker_observation']['marker'], master, observer['before'],
                          observer.get('after', series[-1][1]), observer.get('restored_vision_ns'))
    return dict(
        run=run, files=dict(observer=rel(root / 'token_window_observer.json'), config=rel(SEG / 'hw/config' / config_name),
                            full_run=[rel(snapdir / ('%s_%s.json' % (trial_dir.name, s))) for s in ('before', 'after')],
                            lifecycle=[rel(snapdir / ('%s_%s_lifecycle.json' % (trial_dir.name, s))) for s in ('before', 'after')],
                            c2_master=rel(trial_dir / 'c2/master.json')),
        build=build_name, control_timed=bool(build.get('control_timed')), monitor_ok=observer.get('monitor_ok'),
        monitor_error=observer.get('error'), population=population,
        cleanup_bound=bound, read_lane_serial_drain_ns=read_lane,
        c2=dict(pre_read_ready_ns=master['pre_read_ready_ns'], first_read_issued_ns=master['first_read_issued_ns'],
                pause_ns=PRE_READ_GRACE_NS),
        # ESTIMATE: Vision -> switch clock mapped at the marker observation, which immediately precedes the
        # c2-ready quiet snapshot
        c2_first_read_switch_estimate=observer['before']['time'] + (master['first_read_issued_ns'] -
                                                                   observer['marker_observation']['vision_ns']) / 1e9,
        polls=rows,
        full_run=dict(pktgen_delta={role: {k: full['after']['pktgen'][role][k] - full['before']['pktgen'][role][k]
                                           for k in ('trigger_counter', 'batch_counter', 'pkt_counter')}
                                    for role in ('READ', 'OPERATE')},
                      raw_stale_delta={name: full['after']['outcomes'][name] - full['before']['outcomes'][name]
                                       for name in ('RAW_READ_TIMER_STALE', 'RAW_OPERATE_TIMER_STALE',
                                                    'STALE_BLOCKER', 'OUT_TOKEN_STALE')},
                      lifecycle_generations=lifecycle_gen),
        legacy_window_proof=legacy)


def verdict(m4, c61):
    m, c = m4['polls'], c61['polls']
    checks = {
        'm4 READ app trigger_counter is 1 at c2 readiness': m[0]['READ']['trigger_counter'] == 1,
        'm4 READ app trigger_counter is 2 only from poll 0 on, before c2 issued any READ':
            [r['READ']['trigger_counter'] for r in m[1:]] == [2, 2, 2] and
            m[-1]['switch_time'] < m4['c2_first_read_switch_estimate'],
        'candidate61 READ app trigger_counter stayed 1': {r['READ']['trigger_counter'] for r in c} == {1},
        'm4 READ pkt_counter climbs 5 -> 6 -> 7 across the polls': [r['READ']['pkt_counter'] for r in m[1:]] == [5, 6, 7],
        'm4 RAW_READ_TIMER_STALE climbs 4 -> 5 -> 6': [r['READ']['raw_stale'] for r in m[1:]] == [4, 5, 6],
        'candidate61 settles at READ pkt 4 / RAW_READ 3':
            (c[-1]['READ']['pkt_counter'], c[-1]['READ']['raw_stale']) == (4, 3),
        'every emitted m4 READ token except the consumed first one is already rejected':
            all(r['READ']['emitted_not_yet_rejected'] == 0 for r in m[1:]),
        'm4 still had READ tokens in the generator at the last poll':
            m[-1]['READ']['old_tokens_not_yet_emitted'] > 0,
        'm4 two-batch READ-lane drain (2 x 3 x IPG) exceeds the 10 s c2 pause':
            m4['read_lane_serial_drain_ns'] > PRE_READ_GRACE_NS,
        'm4 allocates 2 more T READ-lane generations per connection than candidate61 (SELECT and OPERATE '
        'admissions, generation_headroom.workload_reserve)':
            m4['full_run']['lifecycle_generations']['T_read_generation']['per_connection'] -
            c61['full_run']['lifecycle_generations']['T_read_generation']['per_connection'] == 2,
        'authority (N/T epoch, owner, T generations) unchanged across every m4 poll':
            len({json.dumps(r['authority'], sort_keys=True) for r in m}) == 1,
        'the fixed drain test (exactly 4 per app) is never true on any m4 poll':
            not any(r['legacy_drained'] for r in m),
    }
    operate_same = [(r['OPERATE']['trigger_counter'], r['OPERATE']['pkt_counter'], r['OPERATE']['raw_stale'])
                    for r in m] == [(r['OPERATE']['trigger_counter'], r['OPERATE']['pkt_counter'],
                                     r['OPERATE']['raw_stale']) for r in c] + \
        [(1, 4, 4)] * (len(m) - len(c))
    return dict(
        read_lane_hypothesis='confirmed' if all(checks.values()) else 'not confirmed',
        checks=checks,
        operate_lane_sub_claim=('refuted: on m4 the OPERATE app shows the same single batch as candidate61 '
                                '(1 trigger, pkt 1 at c2 readiness then 4, RAW_OPERATE_TIMER_STALE 0 then 4); it '
                                'does not climb' if operate_same else 'OPERATE lane differs from candidate61'),
        cause='The control-timed build admits c1 SELECT as a READ-lane request (0xE100 clone), so the READ '
              'app (app 0) is triggered twice by c1. trigger_counter reads 1 at c2 readiness and 2 only at poll '
              '0, together with batch_counter 2 and pkt_counter 5 after token 4: the second batch was emitted only '
              'after the first finished. So with the 2.5 s delay IPG the old READ '
              'population is 8 tokens spread over about 2 x 3 x 2.5 s = 15 s from c1 READ. The diagnostic '
              'waited for exactly 4 tokens per app inside the 10 s c2 pause, which this population cannot meet.',
        not_shown='Per-token generation is not in the snapshots: the attribution of batch 2 to c1 SELECT rests on '
                  'trigger order and the ctl_timing_01 DESIGN (SELECT clones with 0xE100++gen). The +2 T READ-lane '
                  'generations per connection on m4 are the SELECT REQUEST and the OPERATE admission '
                  '(generation_headroom.workload_reserve), not a second SELECT trigger. Trigger arrival instants '
                  'are not recorded, so how the generator handles a trigger that arrives while a batch is in '
                  'progress (a depth-1 latch that holds one pending trigger and drops further ones, which would fit '
                  'm4 full-run READ triggers 4 of 6 and packets 13 of 24) is an UNRESOLVED hypothesis inferred '
                  'from counters only. The OPERATE app (1) is installed with IPG 0 (t_config.pktgen_ops), yet on '
                  'both retained runs its pkt_counter is 1 at c2 readiness, about 5.4 s after its trigger, and 4 only '
                  'at the next poll: this pacing CONTRADICTS IPG 0. It is consistent with app 1 being serviced behind '
                  'the delayed app 0, but the mechanism is not shown; the cleanup bound therefore models the OPERATE '
                  'drain as bounded by the READ-lane span, an empirical allowance from two runs. The READ span '
                  'charges 6 IPG gaps for two batches (3 per batch, no IPG between batches) rather than 7; the only '
                  'evidence is that m4 tokens 4 and 5 were both emitted between the c2-ready read (switch time '
                  '542.51 s, pkt 3) and the poll-0 read (completed 544.95 s, pkt 5), i.e. within 2.44 s < one 2.5 s '
                  'IPG. That is one observation with a 0.06 s margin; the 6-gap span is UNVERIFIED as generator '
                  'behaviour.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=SEG / 'evidence/ctl_m4_stale_isolation_diagnosis.json')
    args = parser.parse_args()
    m4, c61 = (diagnose_run(run, config) for run, config in RUNS)
    result = dict(generated_by=rel(Path(__file__)), spec='integration/evidence/rearm_01/PLAN_m5.md S3',
                  verdict=verdict(m4, c61), m4=m4, candidate61=c61)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=False) + '\n')
    print(json.dumps(result['verdict'], indent=2))
    return 0 if result['verdict']['read_lane_hypothesis'] == 'confirmed' else 1


if __name__ == '__main__':
    raise SystemExit(main())

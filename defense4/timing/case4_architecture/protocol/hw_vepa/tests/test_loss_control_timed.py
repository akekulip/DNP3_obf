"""Loss trials on a control-timed build keep the build's stranded-SELECT-token bound (2k per SBO cycle).

ctl_m4_loss_core_950_01 (silicon, 2026-10-15): t0, t1 and t5 failed only on OUT_TOKEN_STALE 2 against bound 0,
because the loss path evaluated the switch as if READ alone were timed. With the build's control_timed passed,
every one of the seven retained loss trials has no infrastructure failure."""
import json
import os
import sys
from pathlib import Path

import pytest

HV = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HV))
import checks  # noqa: E402

BASE = HV.parents[1] / 'integration/core/response_only_rearm/stage_experiments/seg61_02'
RUN = BASE / 'evidence/hw_campaigns/ctl_m4_loss_core_950_01/separate_ack/combined'
pytestmark = pytest.mark.skipif(not RUN.is_dir(), reason='retained m4 loss evidence absent')


def infrastructure(control_timed):
    c = json.loads((BASE / 'hw/config/ctl_m4_loss_core_950.json').read_text())
    arm = next(a for a in c['arms'] if a['name'] == 'combined')
    build = c['builds'][arm['build']]
    out = {}
    for d in sorted(RUN.glob('*_t*')):
        label = d.name
        ev = checks.load_evidence_files(
            before=str(d / 'snapshots' / ('%s_before.json' % label)), after=str(d / 'snapshots' / ('%s_after.json' % label)),
            master=str(d / 'master.json'), outstation=str(d / 'outstation.json'), wire=str(d / 'wire.json'),
            timing=str(d / 'timing.json'))
        reads = json.loads((d / 'trial.json').read_text())['reads']
        fails, _ = checks.evaluate(c['expectations'], arm, 'separate_ack', reads, ev, checks.allowed_gap(build),
                                   c['service']['k'], checks.max_token_stale(build),
                                   run_sbo=checks.sbo_count(c['traffic']), control_timed=control_timed,
                                   piggyback_bound=control_timed, gen_exhausted_outcome=15)
        out[label[-2:]] = [f for f in fails if f.startswith(('loop port', 'generation exhausted'))
                           or 'OUT_TOKEN_STALE' in f]
    return out


def test_control_timed_loss_trials_have_no_infrastructure_failure():
    assert infrastructure(True) == {'t%d' % i: [] for i in range(7)}
    readonly = infrastructure(False)
    assert all(any('OUT_TOKEN_STALE' in f for f in readonly[t]) for t in ('t0', 't1', 't5'))


RECONNECT = BASE / 'evidence/hw_campaigns/ctl_m4_reconnect_950_01/separate_ack/combined'


@pytest.mark.skipif(not RECONNECT.is_dir(), reason='retained m4 reconnect evidence absent')
def test_control_timed_reconnect_switch_counts_c1_and_c3_controls():
    """ctl_m4_reconnect_950_01: 44 commits/releases = 40 READs + 2 connections x (SELECT, OPERATE), 42 triggers and
    2 stranded tokens; with control_timed the protected-reconnect switch gate passes, without it it fails."""
    c = json.loads((BASE / 'hw/config/ctl_m4_reconnect_950.json').read_text())
    arm = next(a for a in c['arms'] if a['name'] == 'combined')
    build = c['builds'][arm['build']]
    d = next(RECONNECT.glob('*_t0'))
    label = d.name
    trial = json.loads((d / 'trial.json').read_text())
    out = trial['scenario']['connections']
    ev = checks.load_evidence_files(before=str(d / 'snapshots' / ('%s_before.json' % label)),
                                    after=str(d / 'snapshots' / ('%s_after.json' % label)))
    assert [f for f in trial['failures'] if not f.startswith('switch:')] == []

    def gate(control_timed):
        return checks.evaluate_switch(
            c['expectations'], arm, 2 * trial['reads'], ev, checks.allowed_gap(build), c['service']['k'],
            checks.max_token_stale(build), sbo_count=2 * checks.sbo_count(c['traffic']), gen_exhausted_outcome=15,
            complete_reads=sum(out[cn]['complete'] for cn in ('c1', 'c3')),
            piggyback_reads=sum(out[cn]['piggyback'] for cn in ('c1', 'c3')),
            control_timed=control_timed, piggyback_bound=control_timed)[0]
    assert gate(True) == []
    assert any('OUT_ACK_COMMIT=44' in f for f in gate(False))

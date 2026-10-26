"""evaluate_switch on a build without switch telemetry (c68): outcome expectations skipped, the generator,
loop-port and snapshot-presence checks still gate."""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
import checks  # noqa: E402

CONFIG = HERE.parents[1] / ('integration/core/response_only_rearm/stage_experiments/read_complete_01/hw/config/'
                            'rc01_m12p_c68_sdk9132_sel751_d10oc_reference_rest.json')
EXP = json.loads(CONFIG.read_text())['expectations']


def snapshot(read_triggers=0, operate_triggers=0, k=2, bad_octets=0):
    ports = {role: {checks.RX: 1000 + bad_octets, checks.RX_GOOD: 1000} for role in checks.LOOP_ROLES}
    return dict(pktgen={'READ': dict(trigger_counter=read_triggers, pkt_counter=2 * k * read_triggers),
                        'OPERATE': dict(trigger_counter=operate_triggers, pkt_counter=2 * k * operate_triggers)},
                loop_ports=ports)


def run(arm_t, before, after, reads=65, sbo=64):
    return checks.evaluate_switch(EXP, dict(T=arm_t), reads, dict(before=before, after=after), mirror_k=2,
                                  sbo_count=sbo, control_timed=True, timing_contract='response_ready_ack_d_v2',
                                  gen_exhausted_outcome=15, telemetry=False)


def test_timed_arm_passes_on_generator_evidence_alone():
    fails, obs = run(1, snapshot(), snapshot(read_triggers=65 + 64, operate_triggers=64))
    assert fails == [], fails
    assert obs['outcomes'] == 'no switch telemetry in this build'
    assert obs['token_stale_bound'].startswith('unknown')


def test_off_arm_still_fails_if_the_generator_fired():
    fails, _ = run(0, snapshot(), snapshot(read_triggers=3))
    assert any('T off: READ trigger delta 3' in f for f in fails)


def test_timed_arm_still_fails_on_a_missed_generator_trigger():
    fails, _ = run(1, snapshot(), snapshot(read_triggers=65 + 63, operate_triggers=64))
    assert any('READ trigger delta' in f for f in fails)


def test_bad_loop_octets_and_missing_snapshot_still_fail():
    fails, _ = run(0, snapshot(), snapshot(bad_octets=64))
    assert any('not in good frames' in f for f in fails)
    fails, _ = run(0, None, snapshot())
    assert any('missing evidence: before snapshot' in f for f in fails)

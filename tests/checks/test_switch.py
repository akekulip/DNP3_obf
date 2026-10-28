"""Current switch acceptance has synthetic counters and no historical capture dependency."""
import pytest
from scripts.checks import checks

NO_J=checks.NO_J_CONTRACT
K=2
ROLES_NO_J=("n_ack_return","t_in","held_return")
EXP={"mirror_fix":{"T0":{"zero_triggers":["READ","OPERATE"]}}}

def loop(roles, extra=0):
    return {r: {'dev_port': 48, '$OctetsReceived': 1000 + extra, '$OctetsReceivedinGoodFrames': 1000} for r in roles}


def snap(read_trig, read_pkts, operate=None, roles=ROLES_NO_J):
    pg = {'READ': {'trigger_counter': read_trig, 'batch_counter': read_trig, 'pkt_counter': read_pkts}}
    if operate is not None:
        pg['OPERATE'] = {'trigger_counter': operate[0], 'batch_counter': operate[0], 'pkt_counter': operate[1]}
    return {'outcomes': {}, 'loop_ports': loop(roles), 'pktgen': pg}


def gate(before, after, T=1, reads=2, sbo=1, contract=NO_J):
    return checks.evaluate_switch(EXP, {'T': T, 'padding': 1}, reads, {'before': before, 'after': after},
                                  mirror_k=K, sbo_count=sbo, control_timed=True, timing_contract=contract,
                                  telemetry=False)


@pytest.mark.parametrize('reads,sbo', [(2, 1), (65, 64), (20, 1), (0, 1)])
def test_no_j_read_lane_counts_reads_selects_and_operates(reads, sbo):
    lane = reads + 2 * sbo
    fails, obs = gate(snap(3, 12), snap(3 + lane, 12 + 2 * K * lane), reads=reads, sbo=sbo)
    assert fails == [], fails
    assert obs['pktgen'] == {'READ': {'triggers': lane, 'pkts': 2 * K * lane}}
    assert 'hb_return' not in obs['loop_octet_gap']


@pytest.mark.parametrize('delta', [-1, 1])
def test_no_j_wrong_read_lane_trigger_count_fails(delta):
    lane = 2 + 2 * 1 + delta
    fails, _ = gate(snap(0, 0), snap(lane, 2 * K * lane))
    assert any('READ trigger delta %d, expected 4' % lane in f for f in fails), fails


def test_no_j_wrong_packet_count_fails():
    fails, _ = gate(snap(0, 0), snap(4, 4 * 2 * K - 1))
    assert any('generated READ packets delta 15, expected 16' in f for f in fails), fails


def test_no_j_reported_app1_must_stay_idle():
    assert gate(snap(0, 0, operate=(5, 20)), snap(4, 16, operate=(5, 20)))[0] == []
    fails, _ = gate(snap(0, 0, operate=(5, 20)), snap(4, 16, operate=(6, 24)))
    assert any('OPERATE trigger delta 1, expected 0' in f for f in fails), fails


def test_no_j_app1_appearing_in_one_snapshot_only_fails_closed():
    fails, _ = gate(snap(0, 0), snap(4, 16, operate=(0, 0)))
    assert 'no-J build: retired generator app1 (OPERATE) reported in only one snapshot' in fails


def test_no_j_missing_read_generator_still_fails():
    before, after = snap(0, 0), snap(4, 16)
    del after['pktgen']['READ']
    assert 'mirror_fix build: the snapshots carry no pktgen trigger/packet counters' in gate(before, after)[0]


def test_no_j_installed_loop_ports_still_gate():
    before, after = snap(0, 0), snap(4, 16)
    after['loop_ports']['held_return']['$OctetsReceived'] += 7
    assert any('loop port held_return: 7 received octets' in f for f in gate(before, after)[0])
    del after['loop_ports']['t_in']
    assert 'loop-port counters for t_in are missing or unreadable' in gate(before, after)[0]


def test_no_j_t_off_generator_must_be_idle():
    assert gate(snap(3, 12), snap(3, 12), T=0)[0] == []
    fails, _ = gate(snap(3, 12), snap(4, 16), T=0)
    assert any('T off: READ trigger delta 1' in f for f in fails), fails

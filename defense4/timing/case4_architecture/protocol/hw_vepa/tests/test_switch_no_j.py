"""Switch gate under the c69 no-J contract (response_ready_ack_d_no_j_v3): generator app1 and the hb_return loop
port are retired, and every admitted READ, SELECT and OPERATE triggers app0 once (strip_operate_hold.py,
build_ports.loop_names). Earlier contracts keep their rules unchanged."""
import glob
import json
import re
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import checks  # noqa: E402

NO_J = checks.NO_J_CONTRACT
ARCH = HERE.parents[2]
BASE_HW = ARCH / 'integration/core/response_only/hw'
C69_P4 = (ARCH / 'integration/core/response_only_rearm/stage_experiments/ctl_timing_01/evidence/m12p_c69_sdk9132'
          / 'response_only.p4')
EXP = json.load(open(HERE.parent / 'campaign.json'))['expectations']
K = 2
SMOKE = (HERE.parents[2] / 'integration/core/response_only_rearm/stage_experiments/read_complete_01/evidence/hw_blocks'
         / 'rc01_hw_c69_20261026_01_smoke/physical_relay/combined/rc01_hw_c69_20261026_01_smoke_physical_relay_combined_t0')
ROLES_NO_J = ('n_ack_return', 't_in', 'held_return')


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


def test_loop_roles_follow_the_installed_ports():
    assert checks.loop_roles(NO_J) == ROLES_NO_J
    assert checks.loop_roles('response_ready_ack_d_v2') == checks.LOOP_ROLES
    assert checks.loop_roles(None) == checks.LOOP_ROLES


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


def test_earlier_contract_keeps_requiring_app1_and_hb_return():
    fails, _ = gate(snap(0, 0), snap(4, 16), contract='response_ready_ack_d_v2')
    assert 'mirror_fix build: the snapshots carry no pktgen trigger/packet counters' in fails
    assert 'loop-port counters for hb_return are missing or unreadable' in fails


@pytest.mark.skipif(not SMOKE.is_dir(), reason='retained c69 smoke evidence absent')
def test_retained_c69_smoke_snapshots():
    """The first c69 smoke (2 READ + 1 SBO, combined, T on): failed under the J-era rule, passes the no-J rule."""
    before = json.loads(open(glob.glob(str(SMOKE / 'snapshots/*_before.json'))[0]).read())
    after = json.loads(open(glob.glob(str(SMOKE / 'snapshots/*_after.json'))[0]).read())
    fails, obs = gate(before, after)
    assert fails == [], fails
    assert obs['pktgen'] == {'READ': {'triggers': 4, 'pkts': 16}}
    old, _ = gate(before, after, contract='response_ready_ack_d_v2')
    assert 'mirror_fix build: the snapshots carry no pktgen trigger/packet counters' in old


def _base_hw(name):
    sys.path.insert(0, str(BASE_HW))
    try:
        return __import__(name)
    finally:
        sys.path.remove(str(BASE_HW))


@pytest.mark.parametrize('contract', [NO_J, 'response_ready_ack_d_v2', None])
def test_loop_roles_agree_with_the_installer_port_plan(contract):
    build_ports = _base_hw('build_ports')
    assert set(checks.loop_roles(contract)) == set(build_ports.loop_names(contract)) - {'return_port', 'pktgen_return'}
    assert checks.NO_J_CONTRACT == _base_hw('t_config').RESPONSE_READY_NO_J_CONTRACT


def test_no_j_rule_is_pinned_to_the_c69_source():
    """The rule's premises, read from the compiled c69 source and the installer: only admit_request clones (the
    E100 app0 trigger), only first-copy REQUEST and OPERATE reach it, and the installer configures app0 alone."""
    src = C69_P4.read_text()
    setters = [m.start() for m in re.finditer(r'md\.clone_ses\s*=\s*t_CLONE_SESSION_ID', src)]
    assert len(setters) == 1
    action = src.rfind('action ', 0, setters[0])
    assert src[action:].startswith('action admit_request()')
    assert '16w0xE100 ++ md.cur_gen' in src[action:src.index('}', action)]
    kinds = re.findall(r'\((t_KIND_[A-Z_]+), [^)]*\) : admit_request\(\);', src)
    assert sorted(kinds) == ['t_KIND_OPERATE', 't_KIND_REQUEST']
    assert _base_hw('t_config').pktgen_apps(NO_J) == (('READ', 0, 0xE1000000),)

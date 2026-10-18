"""contention_rules.py (failure analysis of m10_03, 2026-10-17; code review of the corrections)."""
import importlib.util
import re
from pathlib import Path

CT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('contention_rules', CT / 'contention_rules.py')
rules = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rules)

# T units of the model runs (t_params_written.json of model_contention_m10_03_01): gap 50 ms, readiness 2 s model
GAP, READINESS = 195315, 7812502


def test_fallback_is_due_once_commit_plus_gap_reaches_readiness():
    assert rules.readiness_reached_before_release(0, READINESS - GAP, GAP, READINESS) is True
    assert rules.readiness_reached_before_release(0, READINESS - GAP - 1, GAP, READINESS) is False


def test_fallback_rule_follows_t_across_the_32_bit_wrap():
    t0 = 0xffffff00
    assert rules.readiness_reached_before_release(t0, (t0 + READINESS) & 0xffffffff, GAP, READINESS) is True
    assert rules.readiness_reached_before_release(t0, (t0 + 1000) & 0xffffffff, GAP, READINESS) is False


def test_a_commit_not_after_t0_is_an_invalid_read_never_a_verdict():
    """Code review: modulo arithmetic made a_commit = 0 (initial value) or a_commit < t0 look like a huge elapsed
    time, which quietly excused the fallback."""
    assert rules.readiness_reached_before_release(542983397, 0, GAP, READINESS) is None
    assert rules.readiness_reached_before_release(1000, 999, GAP, READINESS) is None


def test_the_recorded_operate_point_values():
    """model_contention_m10_03_01 sweep_OPERATE_030ms, T clock in ns from the model log: t0 139003749888, a_commit
    141406249984 (2402.5 ms); as T units (/256) the fallback was due. m9_01's response reached T at 1536.2 ms."""
    t0, commit = 139003749888 // 256 & 0xffffffff, 141406249984 // 256 & 0xffffffff
    assert rules.readiness_reached_before_release(t0, commit, GAP, READINESS) is True
    m9_commit = (t0 + int(1536.2e6 / 256)) & 0xffffffff
    assert rules.readiness_reached_before_release(t0, m9_commit, GAP, READINESS) is False


def test_abort_order_is_decided_only_before_the_rst_is_sent():
    assert rules.abort_branch_outcome(True, False) == 'released'
    assert rules.abort_branch_outcome(True, True) == 'released'
    assert rules.abort_branch_outcome(False, False) == 'held'


def test_a_release_after_the_send_is_inconclusive_never_excused():
    """Code review, critical: a response released after the RST was sent may have escaped after T applied the
    reset; the driver's evidence cannot separate that from a benign race, so it is never passed."""
    assert rules.abort_branch_outcome(False, True) == 'inconclusive'


def test_operate_keeps_its_duplicate_window_unless_the_caller_watches_later():
    """Option a: only point() OPERATE exchanges, which watch the relay port through the response capture, drop the
    0.9 s quiet; every other OPERATE path keeps it, and READ/SELECT are unchanged."""
    assert rules.request_quiet('OPERATE', False, 0.9) == 0.9
    assert rules.request_quiet('OPERATE', True, 0.9) == 0.2
    assert rules.request_quiet('READ', False, 0.9) == rules.request_quiet('SELECT', True, 0.9) == 0.2


ETH = bytes.fromhex('001122334455aabbccddeeff0800')


def tcp_frame(sport, dport, payload=b''):
    ip = bytes.fromhex('4500') + (40 + len(payload)).to_bytes(2, 'big') + bytes.fromhex('000140004006') + bytes(2) \
        + bytes([10, 0, 0, 1 if dport == 20000 else 2, 10, 0, 0, 2 if dport == 20000 else 1])
    return ETH + ip + sport.to_bytes(2, 'big') + dport.to_bytes(2, 'big') + bytes(8) + bytes.fromhex('5018') \
        + bytes(6) + payload


def test_only_outstation_bound_frames_count_as_copies_whatever_the_port_tag():
    """model_contention_m10_03_06: relay and master share dev port 9 in the model, so the master-bound ACK (60) and
    response (115) were counted as copies. Direction must come from the frame."""
    ack, rsp = tcp_frame(20000, 30001), tcp_frame(20000, 30001, bytes(61))
    copy = tcp_frame(30001, 20000, bytes(35))
    frames = [(1.5, 9, ack), (1.55, 9, rsp)]
    assert rules.late_relay_copies(frames, 9, 20000) == []
    assert rules.late_relay_copies(frames + [(2.0, 9, copy)], 9, 20000) == [(2.0, len(copy))]
    assert rules.late_relay_copies([(2.0, 48, copy)], 9, 20000) == []          # another device port: not watched


def test_an_unreadable_frame_on_the_relay_port_counts_as_a_copy():
    """Code review W1: fail closed. A VLAN-tagged, non-IP, non-TCP or truncated frame is not proven master-bound."""
    copy = tcp_frame(30001, 20000, bytes(35))
    vlan = copy[:12] + bytes.fromhex('81000001') + copy[12:]
    udp = copy[:23] + bytes([17]) + copy[24:]
    for odd in (vlan, udp, copy[:30], b'short'):
        assert rules.late_relay_copies([(1.0, 9, odd)], 9, 20000) == [(1.0, len(odd))]
        assert not rules.outstation_bound(odd, 20000)          # but never counts as an RST 'relayed'


def test_ip_options_are_parsed_through_ihl():
    copy = tcp_frame(30001, 20000, bytes(35))
    opts = copy[:14] + bytes([0x46]) + copy[15:34] + bytes(4) + copy[34:]
    assert rules.outstation_bound(opts, 20000) and not rules.master_bound(opts, 20000)


def test_the_rst_relayed_checks_take_direction_from_the_frame():
    """Code review W2: a master-bound RST on the shared device port must not make a missing relay pass."""
    text = (Path(__file__).resolve().parents[1] / 'model_contention.py').read_text()
    assert len(re.findall(r'p == RELAY\.dev_port and rules\.outstation_bound\(f, RELAY\.port\)', text)) == 3
    assert not re.search(r'p == RELAY\.dev_port and f\[47\] & 0x04', text)


def test_the_driver_watches_only_where_nothing_relay_bound_is_sent():
    """Source check: watch mode is OPERATE with no during() callback, and it reads queued frames instead of draining
    them unseen."""
    text = (Path(__file__).resolve().parents[1] / 'model_contention.py').read_text()
    assert "watch = kind == 'OPERATE' and during is None" in text
    assert "st['queued'] = capture(0.02, 0.01)" in text
    assert "late = rules.late_relay_copies(st.pop('queued') + got, RELAY.dev_port, RELAY.port)" in text
    # code review: the only keep_queued argument is the watch flag; drain only in respond's else branch; only point()
    # passes watch_later
    assert re.findall(r'(?<!def )respond\([^)]*keep_queued=(\w+)', text) == ['watch']
    respond = text[text.index('def respond('):text.index('def judge(')]
    assert respond.count('m.drain(ports)') == 1 and respond.index('else:') < respond.index('m.drain(ports)')
    assert re.findall(r'(?<!def )request\([^)]*watch_later=(\w+)', text) == ['watch']

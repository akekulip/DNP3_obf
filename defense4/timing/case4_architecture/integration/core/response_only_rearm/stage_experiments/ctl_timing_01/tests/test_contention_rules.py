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


def test_any_relay_bound_frame_after_the_request_capture_is_a_copy():
    frames = [(1.00001, 9, b'm' * 60), (1.5, 48, b'r' * 101), (2.0, 48, b'r' * 101)]
    assert rules.late_relay_copies(frames, 48) == [(1.5, 101), (2.0, 101)]
    assert rules.late_relay_copies(frames[:1], 48) == []


def test_the_driver_watches_only_where_nothing_relay_bound_is_sent():
    """Source check: watch mode is OPERATE with no during() callback, and it reads queued frames instead of draining
    them unseen."""
    text = (Path(__file__).resolve().parents[1] / 'model_contention.py').read_text()
    assert "watch = kind == 'OPERATE' and during is None" in text
    assert "st['queued'] = capture(0.02, 0.01)" in text
    assert "late = rules.late_relay_copies(st.pop('queued') + got, RELAY.dev_port)" in text
    # code review: the only keep_queued argument is the watch flag; drain only in respond's else branch; only point()
    # passes watch_later
    assert re.findall(r'(?<!def )respond\([^)]*keep_queued=(\w+)', text) == ['watch']
    respond = text[text.index('def respond('):text.index('def judge(')]
    assert respond.count('m.drain(ports)') == 1 and respond.index('else:') < respond.index('m.drain(ports)')
    assert re.findall(r'(?<!def )request\([^)]*watch_later=(\w+)', text) == ['watch']

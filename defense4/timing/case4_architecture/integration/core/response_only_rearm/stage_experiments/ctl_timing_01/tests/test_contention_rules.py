"""contention_rules.py (failure analysis of m10_03, 2026-10-17; code review of the corrections)."""
import importlib.util
import json
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


FIXTURE = json.loads((Path(__file__).resolve().parent / 'fixtures' / 'shared_port_frames_m10_03_06.json').read_text())
WIRE = [(f['dir'], bytes.fromhex(f['hex'])) for f in FIXTURE['frames']]


def wire(direction, sport, flags, payload_len, nth=0):
    """The nth retained frame of attempt 06's sweep_OPERATE_030ms (shared dev port 9) matching the description."""
    hits = [b for d, b in WIRE if d == direction and rules.tcp_view(b)[0] == sport and b[47] == flags
            and len(rules.tcp_view(b)[3]) == payload_len]
    return hits[nth]


OP_SENT = wire('in', 30001, 0x18, 35, nth=1)        # the master's OPERATE (nth 0 is the setup SELECT)
OP_FWD = wire('tx', 30001, 0x18, 35, nth=1)         # the switch's forwarded OPERATE
ACK = wire('tx', 20000, 0x10, 0, nth=1)             # master-bound ACK and padded response of the OPERATE exchange
RSP = wire('tx', 20000, 0x18, 61, nth=1)
RST = wire('tx', 30001, 0x14, 0)
SEL_FWD = wire('tx', 30001, 0x18, 35, nth=0)


def watch(*frames, port=9):
    return rules.classify_watch_frames([(1.0 + i, port, f) for i, f in enumerate(frames)], 9, OP_SENT, 20000)


def test_retained_shared_port_ack_and_response_are_master_bound_not_copies():
    """model_contention_m10_03_06: these two frames failed all nine OPERATE watch cases."""
    r = watch(ACK, RSP)
    assert r['ok'] and r['master_bound'] == 2 and r['confirmed_duplicates'] == r['unclassified'] == 0


def test_a_second_forwarded_operate_is_a_confirmed_duplicate():
    """The switch's own forwarded OPERATE frame carries the request's direction, sequence and command payload."""
    r = watch(ACK, OP_FWD, RSP)
    assert not r['ok'] and r['confirmed_duplicates'] == 1 and r['unclassified'] == 0


def test_other_outstation_bound_frames_are_unclassified_not_duplicates():
    """An RST or a different command (the setup SELECT) toward the outstation is not this OPERATE; it still fails."""
    for odd in (RST, SEL_FWD):
        r = watch(ACK, odd, RSP)
        assert not r['ok'] and r['confirmed_duplicates'] == 0 and r['unclassified'] == 1


def test_an_unreadable_frame_is_unclassified_and_fails():
    """Code review W1: fail closed. VLAN-tagged, non-TCP or truncated frames are not proven master-bound."""
    vlan = OP_FWD[:12] + bytes.fromhex('81000001') + OP_FWD[12:]
    udp = OP_FWD[:23] + bytes([17]) + OP_FWD[24:]
    for odd in (vlan, udp, OP_FWD[:40], b'short'):
        r = watch(odd)
        assert not r['ok'] and r['unclassified'] == 1
        assert not rules.outstation_bound(odd, 20000)          # never counts as an RST 'relayed'


def test_frames_on_another_device_port_are_not_watched():
    assert watch(OP_FWD, port=48)['ok']


def test_ip_options_are_parsed_through_ihl():
    opts = OP_FWD[:14] + bytes([0x46]) + OP_FWD[15:16] + (int.from_bytes(OP_FWD[16:18], 'big') + 4).to_bytes(2, 'big') \
        + OP_FWD[18:34] + bytes(4) + OP_FWD[34:]
    assert rules.outstation_bound(opts, 20000)
    assert rules.tcp_view(opts)[3] == rules.tcp_view(OP_FWD)[3]


def test_the_rst_relayed_checks_take_direction_from_the_frame():
    """Code review W2: a master-bound RST on the shared device port must not make a missing relay pass."""
    text = (Path(__file__).resolve().parents[1] / 'model_contention.py').read_text()
    assert len(re.findall(r'p == RELAY\.dev_port and rules\.outstation_bound\(f, RELAY\.port\)', text)) == 4      # + the targeted restart
    assert not re.search(r'p == RELAY\.dev_port and f\[47\] & 0x04', text)


def test_the_driver_watches_only_where_nothing_relay_bound_is_sent():
    """Source check: watch mode is OPERATE with no during() callback, and it reads queued frames instead of draining
    them unseen."""
    text = (Path(__file__).resolve().parents[1] / 'model_contention.py').read_text()
    assert "watch = kind == 'OPERATE' and during is None" in text
    assert "st['queued'] = capture(0.02, 0.01)" in text
    assert "watched = rules.classify_watch_frames(st.pop('queued') + got, RELAY.dev_port, st['request_sent']," in text
    # code review: the only keep_queued argument is the watch flag; drain only in respond's else branch; only point()
    # passes watch_later
    assert re.findall(r'(?<!def )respond\([^)]*keep_queued=(\w+)', text) == ['watch']
    respond = text[text.index('def respond('):text.index('def judge(')]
    assert respond.count('m.drain(ports)') == 1 and respond.index('else:') < respond.index('m.drain(ports)')
    assert re.findall(r'(?<!def )request\([^)]*watch_later=(\w+)', text) == ['watch']


def test_abort_order_from_t_passes():
    """Harness fix 2: when the pre-send read is inconclusive, T's release pass against its reset-application pass
    decides; anything T's passes cannot establish stays inconclusive (and fails)."""
    assert rules.abort_log_order(dict(verdict='PASS', released_before=['t1'])) == 'released'
    assert rules.abort_log_order(dict(verdict='FAIL', released_after=['t2'])) == 'released_after_reset'
    for d in (dict(verdict='PASS', released_before=[]), dict(verdict='no reset applied'),
              dict(verdict='unattributed'), {}):
        assert rules.abort_log_order(d) == 'inconclusive'


DRIVER = (Path(__file__).resolve().parents[1] / 'model_contention.py').read_text()


def test_restart_coverage_is_the_targeted_section_not_the_ordinary_recovery_points():
    """Harness fix 3: the ordinary restart points no longer carry the coverage case; the targeted section sends the
    response on the model log's stage-0 pass and counts a try only when count_busy[5] advanced."""
    assert "report.add('restart_%s_path_exercised'" not in DRIVER
    assert "report.add('restart_targeted_%s_path_exercised' % kind" in DRIVER
    targeted = DRIVER[DRIVER.index("section_on('restart_targeted')"):]
    assert "pos, idle = view.wait_idle(log) if log is not None else (None, None)" in targeted
    assert targeted.index("r'Ingress Pkt from port %d ' % MASTER.dev_port") < targeted.index(
        "r'Execute Action: n_Ingress\\.first_close\\b'")                   # this RST's ingress, then its stage 0
    assert 'fast.send(sent_rsp)' in targeted and "if restarts >= 1 and row['stage0_seen']:" in targeted
    assert "judge('%s_new_READ' % tag, 'READ', native2, ack2, got2, before2, busy2, sent_rsp=r2)" in targeted  # H1
    assert 'RESTART_TRIES = 3' in DRIVER


def test_an_inconclusive_abort_order_is_decided_by_t_passes_and_a_late_release_fails():
    """Harness fix 2: the pre-send register read stays first; only an inconclusive read consults T's passes."""
    i = DRIVER.index("if order == 'inconclusive' and milestone == 'm10':")
    assert DRIVER.index("order = rules.abort_branch_outcome(") < i < DRIVER.index('order = rules.abort_log_order(decision)')
    assert "order == 'released_after_reset':\n                    exact = False" in DRIVER


def test_a_zero_frame_handshake_step_stops_the_run_with_evidence():
    """Harness fix 4: the step's verdict stands, evidence is kept, and PointInterrupted stops the run."""
    step = DRIVER[DRIVER.index('def step('):DRIVER.index('st = {')]
    assert "report.add(name, 'one exact frame'" in step
    assert step.index("report.add(name, 'one exact frame'") < step.index('raise PointInterrupted(')
    assert "report.record['meta']['interrupted'] = evidence" in step
    assert 'class PointInterrupted(Exception)' in DRIVER


def test_a_held_abort_requires_t_to_have_admitted_the_response():
    """Code review H2: without an observed admission the response may reach T only after the reset (old-epoch drop),
    which is not 'held, then flushed'; the log decision is limited to m10, where the summary blocks unmeasured."""
    assert 'held_ok = admitted[0] is not None and not released_before_send' in DRIVER
    assert "if order == 'inconclusive' and milestone == 'm10':" in DRIVER
    assert "else:                                            # no log to observe: the old fixed wait" in DRIVER
    # no observed admission (including no log): held_ok is False and the point is recorded as not established
    held = DRIVER[DRIVER.index('held_ok = admitted[0] is not None'):]
    assert held.index("setdefault('abort_held_not_established', [])") < held.index('m.send(RELAY.dev_port, rst)')
    nolog = DRIVER[DRIVER.index('if pos is not None:\n                    admitted = view.wait_for('):]
    assert nolog.index('admitted = (None, None)') < nolog.index('got += capture(0.3, 0.3)')

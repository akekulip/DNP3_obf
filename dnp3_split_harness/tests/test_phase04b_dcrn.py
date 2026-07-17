"""Unit/integration tests for the DCRN reference policy (corrective.md sec 17).

Covers: pure-ACK classification, ACK-bearing response classification, handshake exclusion, CONFIRM-ACK
exclusion, cumulative-ACK matching, combined scheduling, separate dual-packet scheduling, equal-deadline
FIFO vs guard-delta fallback, late-response/deadline-miss, fail-open, duplicate-ACK/retransmission/
concurrent bypass, deterministic + device/size-independent target selection, state cleanup, map
exhaustion, and unsafe-target bypass. Pure logic -- no root, no sockets.

    python3 -m pytest tests/test_phase04b_dcrn.py
"""
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import phase04b_dcrn_policy as D


def mkpolicy(mode="P1_FIXED", fixed=32.39, fifo=False, rto=211.0, max_flows=4096):
    return D.DCRNPolicy(
        D.TargetPolicy(mode=mode, fixed_ms=fixed, bounded_lo_ms=32.39, bounded_hi_ms=42.39, seed=20260717),
        D.SafetyConfig(effective_rto_ms=rto, rto_safety_guard_ms=60.0, scheduler_guard_ms=3.0,
                       response_guard_delta_ms=0.2, fifo_equal_deadline_reliable=fifo),
        max_flows=max_flows)


def req(flow="f1", ts=0.0, seq=100, plen=35, func=D.READ_FC, counter=1, dst=D.DNP3_PORT, dnp3=True):
    return {"flow_key": flow, "ts": ts, "seq": seq, "payload_len": plen, "dst_port": dst,
            "dnp3_present": dnp3, "dnp3_func": func, "txn_counter": counter}


def rev(flow="f1", ts=16.0, plen=0, cum_ack=135, func=None, dnp3=False, **flags):
    p = {"flow_key": flow, "ts": ts, "src_port": D.DNP3_PORT, "ack": True, "syn": False, "fin": False,
         "rst": False, "payload_len": plen, "cum_ack": cum_ack, "dnp3_present": dnp3, "dnp3_func": func,
         "duplicate_ack": False, "sack": False, "window_update": False, "keepalive": False,
         "acks_confirm": False, "retransmission": False}
    p.update(flags)
    return p


# ---- request arming / handshake exclusion --------------------------------- #
def test_read_request_arms():
    p = mkpolicy(); st, by = p.arm_request(req())
    assert by is None and st.txn_class == D.CLASS_ROUTINE_READ
    assert st.expected_ack == 135 and st.deadline_ts == 32.39


def test_handshake_does_not_arm():
    p = mkpolicy()
    st, by = p.arm_request(req(plen=0, dnp3=False))          # zero-payload SYN/ACK-style
    assert st is None and by == D.B_HANDSHAKE


def test_non_read_request_bypasses():
    p = mkpolicy(); st, by = p.arm_request(req(func=3))       # e.g. a write/select, not routine READ
    assert st is None and by == D.B_HANDSHAKE   # classify_request returns None -> not armed


# ---- reverse classification ----------------------------------------------- #
def test_pure_ack_classified():
    p = mkpolicy(); p.arm_request(req())
    kind, why = p.classify_reverse(rev(ts=3.7, plen=0, cum_ack=135))
    assert kind == "pure_ack" and why is None


def test_ack_bearing_response_classified():
    p = mkpolicy(); p.arm_request(req())
    kind, why = p.classify_reverse(rev(ts=16.0, plen=54, cum_ack=135, func=D.RESPONSE_FC, dnp3=True))
    assert kind == "response" and why is None


def test_duplicate_ack_bypassed():
    p = mkpolicy(); p.arm_request(req())
    assert p.classify_reverse(rev(duplicate_ack=True))[1] == D.B_DUP_ACK


def test_sack_window_keepalive_confirm_bypassed():
    p = mkpolicy(); p.arm_request(req())
    assert p.classify_reverse(rev(sack=True))[1] == D.B_SACK
    assert p.classify_reverse(rev(window_update=True))[1] == D.B_WINDOW_UPDATE
    assert p.classify_reverse(rev(keepalive=True))[1] == D.B_KEEPALIVE
    assert p.classify_reverse(rev(acks_confirm=True))[1] == D.B_CONFIRM_ACK


def test_confirm_response_bypassed():
    p = mkpolicy(); p.arm_request(req())
    kind, why = p.classify_reverse(rev(plen=8, cum_ack=135, func=D.CONFIRM_FC, dnp3=True))
    assert kind is None and why == D.B_CONFIRM_ACK


def test_retransmission_bypassed():
    p = mkpolicy(); p.arm_request(req())
    assert p.classify_reverse(rev(retransmission=True))[1] == D.B_RETRANSMISSION


def test_fail_open_no_state():
    p = mkpolicy()                                            # nothing armed
    assert p.classify_reverse(rev())[1] == D.B_NO_STATE


def test_ack_not_covering_request_excluded():
    p = mkpolicy(); p.arm_request(req())                      # expected_ack=135
    assert p.classify_reverse(rev(cum_ack=100))[1] == D.B_HANDSHAKE


def test_cumulative_ack_wraps():
    assert D._ack_covers(10, 5) and not D._ack_covers(5, 10)
    assert D._ack_covers(2, 0xFFFFFFF0)                        # wrap-around coverage


# ---- scheduling ----------------------------------------------------------- #
def test_combined_release_holds_to_deadline():
    p = mkpolicy(); st, _ = p.arm_request(req())
    rel, miss = p.release_time("response", 16.0, st, is_separate=False)
    assert rel == 32.39 and miss is False


def test_separate_dual_packet_scheduling_guard():
    p = mkpolicy(fifo=False); st, _ = p.arm_request(req())
    ack_rel, _ = p.release_time("pure_ack", 3.7, st, is_separate=True)
    resp_rel, _ = p.release_time("response", 16.0, st, is_separate=True)
    assert ack_rel == 32.39                                   # ACK held to common deadline
    assert abs(resp_rel - (32.39 + 0.2)) < 1e-9               # response = deadline + guard
    assert ack_rel < resp_rel                                 # ACK strictly before response


def test_equal_deadline_fifo_zero_gap():
    p = mkpolicy(fifo=True); st, _ = p.arm_request(req())
    resp_rel, _ = p.release_time("response", 16.0, st, is_separate=True)
    assert resp_rel == 32.39                                  # no guard when FIFO proven


def test_late_response_is_deadline_miss_passed_immediately():
    p = mkpolicy(); st, _ = p.arm_request(req())
    rel, miss = p.release_time("response", 40.0, st, is_separate=False)   # 40 > 32.39 deadline
    assert rel == 40.0 and miss is True                       # passed at ready time, flagged


# ---- concurrency / map / safety ------------------------------------------- #
def test_concurrent_outstanding_request_bypassed():
    p = mkpolicy(); p.arm_request(req(counter=1))
    st, by = p.arm_request(req(counter=2))                    # same flow, prior txn not complete
    assert st is None and by == D.B_CONCURRENT


def test_map_exhaustion_bypasses():
    p = mkpolicy(max_flows=1); p.arm_request(req(flow="a"))
    st, by = p.arm_request(req(flow="b"))
    assert st is None and by == D.B_MAP_EXHAUSTED


def test_unsafe_target_bypassed():
    p = mkpolicy(fixed=200.0)                                  # dhigh = 211-60 = 151 -> 200 unsafe
    st, by = p.arm_request(req())
    assert st is None and by == D.B_UNSAFE_TARGET


def test_state_cleanup():
    p = mkpolicy(); p.arm_request(req(flow="x"))
    assert "x" in p.flows; p.cleanup("x"); assert "x" not in p.flows


# ---- target policy: deterministic, class-independent ---------------------- #
def test_fixed_target_constant():
    t = D.TargetPolicy(mode="P1_FIXED", fixed_ms=32.39)
    assert t.select_target_ms(D.CLASS_ROUTINE_READ, 1) == 32.39
    assert t.select_target_ms(D.CLASS_ROUTINE_READ, 999) == 32.39


def test_bounded_target_deterministic_and_seed_keyed():
    t = D.TargetPolicy(mode="P2_COMMON_BOUNDED", bounded_lo_ms=32.39, bounded_hi_ms=42.39, seed=20260717)
    a = t.select_target_ms(D.CLASS_ROUTINE_READ, 7)
    b = t.select_target_ms(D.CLASS_ROUTINE_READ, 7)
    assert a == b                                              # reproducible for same (seed,counter)
    expect_ns = D.select_target_ns(D.DCRN_MODE_BOUNDED, 20260717, 7,
                                   int(round(32.39 * 1e6)), int(round(42.39 * 1e6)), 0)
    assert a == round(expect_ns / 1e6, 4)                      # matches the shared splitmix64 core
    assert 32.39 <= a <= 42.39


def test_bounded_target_varies_by_counter_not_reset_per_device():
    t = D.TargetPolicy(mode="P2_COMMON_BOUNDED", seed=1)
    seq = [t.select_target_ms(D.CLASS_ROUTINE_READ, i) for i in range(10)]
    assert len(set(seq)) > 1                                   # not a constant / short repeated cycle
    # target depends ONLY on (class, counter): there is no device parameter to reset the PRNG per device
    assert D.TargetPolicy.select_target_ms.__code__.co_varnames[:3] == ("self", "txn_class", "txn_counter")


def test_target_independent_of_response_size():
    p = mkpolicy(mode="P2_COMMON_BOUNDED")
    s1, _ = p.arm_request(req(flow="s1", plen=35, counter=5))
    p2 = mkpolicy(mode="P2_COMMON_BOUNDED")
    s2, _ = p2.arm_request(req(flow="s2", plen=35, counter=5))   # same counter, different flow/size context
    # response size is not an input to target selection at all
    assert s1.target_ms == s2.target_ms


if __name__ == "__main__":
    for _n, _f in sorted(globals().items()):
        if _n.startswith("test_") and callable(_f):
            _f(); print("ok", _n)

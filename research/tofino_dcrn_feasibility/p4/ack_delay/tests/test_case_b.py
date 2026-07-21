#!/usr/bin/env python3
"""test_case_b.py — Case-B reference-model invariants (the gate for hardware authorization).

Proves the six properties the PI requires before the next Case-B hardware window:
  1. ACK forwarded immediately
  2. response held until the ACK-RELATIVE deadline
  3. response released unchanged (byte-preserving)
  4. state returns to IDLE
  5. zero response reordering (ACK egresses before response)
  6. MAX_PASS used only as fail-open (normal release is the deadline)
Plus: the deadline is ACK-relative (NOT request-relative); CLRT collapses to a constant G_i
independent of the device's response readiness; and the honest max(ready,deadline) edge.

Run: python3 tests/test_case_b.py   (or pytest)
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "refmodel"))
from case_b_state_machine import simulate_case_b, measured_clrt_ms  # noqa: E402

G = 60.0                      # calibrated B1_FIXED target (ms): > rig readiness tail 40ms, < RTO 207ms
# device profiles (readiness relative to the prompt ACK): rig dev1 ~17ms, dev2 ~35ms
REQ, ACK = 0.0, 0.2           # request at 0, prompt ACK at 0.2ms


def _txn(readiness, g_i=G, clock=True, t_ack=ACK):
    return simulate_case_b(g_i_ms=g_i, t_request_ms=REQ, t_ack_ms=t_ack,
                           t_resp_ready_ms=t_ack + readiness, clock_refreshes=clock)


# ---- 1. ACK forwarded immediately ----
def test_ack_forwarded_immediately():
    r = _txn(17.0)
    assert r.ack_held is False
    assert abs(r.ack_egress_ms - ACK) < 1e-9        # ACK leaves on arrival, not held

# ---- 2. response held until the ACK-relative deadline ----
def test_response_held_until_ack_relative_deadline():
    r = _txn(17.0)                                    # readiness 17ms < G 60ms -> held to deadline
    deadline = ACK + G
    assert abs(r.resp_egress_ms - deadline) <= 0.11   # within one recirc pass of the deadline
    assert r.resp_egress_ms > ACK + 17.0              # strictly later than native readiness

# ---- 3. response released unchanged ----
def test_response_released_unchanged():
    assert _txn(35.0).resp_bytes_unchanged is True

# ---- 4. state returns to IDLE ----
def test_state_returns_to_idle():
    assert _txn(17.0).final_state == "IDLE"
    assert _txn(35.0).final_state == "IDLE"

# ---- 5. zero response reordering (ACK before response) ----
def test_zero_response_reordering():
    r = _txn(17.0)
    assert r.ack_egress_ms < r.resp_egress_ms
    assert [k for k, _ in r.egress_order] == ["ack", "response"]

# ---- 6. MAX_PASS used only as fail-open ----
def test_maxpass_only_failopen():
    ok = _txn(17.0, clock=True)
    assert ok.resp_release_reason == "deadline" and ok.max_pass_used is False
    broke = _txn(17.0, clock=False)                   # recirc-clock bug -> deadline never matures
    assert broke.resp_release_reason == "max_pass_fail_open" and broke.max_pass_used is True


# ---- ACK-relative (NOT request-relative) ----
def test_deadline_is_ack_relative_not_request_relative():
    # same readiness, different ACK time -> release shifts by exactly the ACK shift (ACK-relative)
    a = simulate_case_b(G, 0.0, 0.2, 0.2 + 17.0)
    b = simulate_case_b(G, 0.0, 5.2, 5.2 + 17.0)      # ACK 5ms later
    assert abs((b.resp_egress_ms - a.resp_egress_ms) - 5.0) <= 0.11   # tracks the ACK, not the request

# ---- CLRT collapses to a constant G_i, device-independent ----
def test_clrt_is_constant_gi_across_devices():
    for readiness in (2.0, 10.0, 17.0, 26.6, 35.0, 40.0):             # rig dev1 + dev2 span, all < G
        r = _txn(readiness)
        assert abs(measured_clrt_ms(r) - G) <= 0.11, "readiness %s -> CLRT %.3f != G" % (readiness, measured_clrt_ms(r))

# ---- honest max(ready, deadline): readiness beyond G leaks at readiness (not a hold) ----
def test_readiness_beyond_target_passes_at_readiness():
    r = _txn(80.0)                                    # readiness 80ms > G 60ms -> deadline already passed
    assert r.resp_release_reason == "ready_after_deadline"
    assert abs(measured_clrt_ms(r) - 80.0) <= 0.11    # CLRT = readiness (documented leak; drives G calibration)

# ---- Case B INCREASES the ACK->response gap (vs native) ----
def test_case_b_increases_gap():
    native_gap = 17.0
    r = _txn(native_gap)
    assert measured_clrt_ms(r) > native_gap          # ACK->response increased (Case B objective)
    assert abs(r.ack_egress_ms - ACK) < 1e-9         # request->ACK unchanged


def _run_all():
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn(); print("  PASS %s" % fn.__name__)
    print("== %d/%d Case-B invariant tests passed ==" % (len(fns), len(fns)))


if __name__ == "__main__":
    _run_all()

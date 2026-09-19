"""Single parameter-safety authority for Case A Defense 3 (CORRECTIONS.md §3).

BOTH the general setup (`setup/…_setup.py::config_params`) and the campaign block
setter (`harness/setarm.py`) must go through this module. Before this module existed
there were two disagreeing authorities: the setup enforced a stale `a_worst = 22 ms`
guard (which would have rejected the real D = 16 ms campaign, since H = 30.8 < 22+16)
and a fixed `D_MAX = 40 ms` clamp that the report proves is impossible (H ≈ 30.8 ms, so
D = 40 ms lets the budget expire before the deadline even with an instantaneous ACK);
meanwhile the campaign wrote `tbl_params` directly with no D-max, horizon, RTO or
poll-rate/wrap check at all.

This module computes the admissible range from the fail-open horizon H rather than a
fixed clamp, enforces the generation-wrap (poll-rate) bound R2's safety depends on, and
is the ONE place allowed to write `tbl_params`. Pure computation (`evaluate`) has no
bfrt dependency so it runs off-switch and in the self-test; `write_params` is the thin
gated writer.

Formulae (CORRECTIONS.md §3.1, §3.3):
    H      = B * K / rate_dp8                         (fail-open horizon)
    D_max  = H - a_bound - t_detect - t_drain - t_tail - M
    admissible: D_realized <= D_max
    RTO:        H < RTO_min - M_rto
    wrap:       16 * T_poll,min  >  H + t_drain + M    (R2 generation-reuse safety)

The value substitutions reproduce the report's "D_MAX ≈ H − a_max − ε ≈ 24 ms"
(REPORT.md §7 / open-work): with a_bound = 3 ms and M = 3 ms, D_max ≈ 24.8 ms, so the
D = 16 ms campaign passes and D = 40 ms is refused.
"""
from __future__ import annotations
import argparse
import json
import math

# ---- hardware / reservoir constants (match setup + P4) ----------------------
TICK_NS = 256                 # deadline word carries 24 bits of 256 ns ticks
K_TOKENS = 64                 # validated reservoir depth (NOT claimed minimal)
RATE_DP8_PPS = 37.4e6         # measured dp8 loop rate, 25G, 64 B frames
BUDGET_DEFAULT = 18000        # CONSENSUS §6.1
READ_LEN_DEFAULT = 18         # Class-0 integrity-poll TCP payload length

# ---- measured sub-millisecond timing terms (evidence-cited) -----------------
# CHECK 2, 100 clean silicon trials, 2026-07-29
# (evidence/defense3/CHECK2_PRODUCTION_BLOCKER_START_LATENCY.md)
T_DETECT_NS = 1217.0          # READ -> full 64-token reservoir admitted (max)
T_DRAIN_NS = 1736.0           # reservoir drain / release tail (measured)
T_TAIL_NS = 1736.0            # release tail after the deadline (measured ~1.72 us)

# ---- policy knobs (operator-tunable; documented defaults) -------------------
# a_bound: a conservative UPPER bound on the outstation's ACK latency for the
# protected session. The physical SEL-751 measures ~1.4-1.9 ms median in steady
# state; connection-cold first polls run far higher (~25 ms) and are excluded from
# the steady-state campaign. 3 ms sits above the steady-state median with headroom.
# Operators on a different device/session MUST override with their measured worst case.
ACK_BOUND_MS_DEFAULT = 3.0
# M: safety margin folded into D_max and the wrap bound.
SAFETY_MARGIN_MS_DEFAULT = 3.0
# RTO floor: the master's minimum retransmission timeout. H must stay clear of it so a
# late fail-open pre-empts, not collides with, the master's retransmission.
RTO_MIN_MS_DEFAULT = 200.0
RTO_MARGIN_MS_DEFAULT = 20.0
# Generation wrap: the 4-bit DNP3 app sequence reuses a value every 16 polls, so R2's
# note can only be stale-safe if a token cannot outlive its generation until reuse:
#   16 * T_poll,min > H + t_drain + M.
POLL_MIN_MS_DEFAULT = 200.0   # the campaign's poll interval


def quantize_d(d_ms: float) -> dict:
    """Quantize D onto the 256 ns tick grid with a ZERO low byte.

    D rides in the same 32-bit word as the ARMED marker (bit 0), so the addend's low
    byte MUST be zero or the carry corrupts the marker. Rounds DOWN (never overshoots).
    Note: this NO LONGER clamps at a fixed 40 ms — admissibility is decided by evaluate()
    against the computed D_max, which is the whole point of §3.1.
    """
    if d_ms < 0:
        raise ValueError("D must be non-negative (got %r ms)" % (d_ms,))
    req_ns = d_ms * 1e6
    ticks = int(req_ns // TICK_NS)
    if ticks > 0xFFFFFF:
        raise ValueError("D = %.6f ms overflows the 24-bit tick field" % (d_ms,))
    word = (ticks << 8) & 0xFFFFFFFF
    realized_ns = ticks * TICK_NS
    assert (word & 0xFF) == 0, "quantized D word must have a zero low byte"
    return {
        "requested_ms": d_ms,
        "ticks": ticks,
        "word": word,
        "word_hex": "0x%08X" % word,
        "realized_ns": realized_ns,
        "realized_ms": realized_ns / 1e6,
        "quantization_error_ns": req_ns - realized_ns,
        "low_byte_zero": (word & 0xFF) == 0,
    }


def horizon_ms(budget: int, k: int = K_TOKENS, rate_pps: float = RATE_DP8_PPS) -> float:
    """H = B * K / rate_dp8, in milliseconds. Scales with dp8 port speed."""
    tau_s = float(k) / float(rate_pps)
    return budget * tau_s * 1e3


def d_max_ms(h_ms: float, ack_bound_ms: float, margin_ms: float) -> float:
    """D_max = H - a_bound - t_detect - t_drain - t_tail - M   (CORRECTIONS §3.1)."""
    sub_ms = (T_DETECT_NS + T_DRAIN_NS + T_TAIL_NS) / 1e6
    return h_ms - ack_bound_ms - sub_ms - margin_ms


def evaluate(d_ms: float,
             budget: int = BUDGET_DEFAULT,
             k: int = K_TOKENS,
             rate_pps: float = RATE_DP8_PPS,
             read_len: int = READ_LEN_DEFAULT,
             ack_bound_ms: float = ACK_BOUND_MS_DEFAULT,
             margin_ms: float = SAFETY_MARGIN_MS_DEFAULT,
             rto_min_ms: float = RTO_MIN_MS_DEFAULT,
             rto_margin_ms: float = RTO_MARGIN_MS_DEFAULT,
             poll_min_ms: float = POLL_MIN_MS_DEFAULT,
             read_only_trial: bool = False) -> dict:
    """The single admissibility decision. Returns a dict with a boolean `ok` verdict
    and a list of `reasons` for any rejection. Never writes anything.
    """
    reasons: list[str] = []
    qd = quantize_d(d_ms)
    h = horizon_ms(budget, k, rate_pps)
    dmax = d_max_ms(h, ack_bound_ms, margin_ms)
    d_real = qd["realized_ms"]
    t_drain_ms = T_DRAIN_NS / 1e6

    # 1. D within the horizon-derived admissible range (replaces the fixed 40 ms clamp).
    #    A READ-ONLY trial receives no ACK, arms no deadline, and has no hold to protect,
    #    so the budget is SUPPOSED to be the only terminator and a small H is the point.
    if read_only_trial:
        d_ok = True
    else:
        d_ok = d_real <= dmax
        if not d_ok:
            reasons.append(
                "D = %.3f ms exceeds D_max = %.3f ms (= H %.3f - a_bound %.3f - "
                "sub-ms %.3f - M %.3f): the budget would expire before the deadline."
                % (d_real, dmax, h, ack_bound_ms,
                   (T_DETECT_NS + T_DRAIN_NS + T_TAIL_NS) / 1e6, margin_ms))

    # 2. RTO floor: H must stay clear of the master's retransmission timeout.
    rto_ok = h < (rto_min_ms - rto_margin_ms)
    if not rto_ok:
        reasons.append(
            "H = %.3f ms is not below RTO_min - margin = %.3f ms: a late fail-open "
            "would collide with the master's retransmission." % (h, rto_min_ms - rto_margin_ms))

    # 3. Generation-wrap (R2 safety): 16 * T_poll,min > H + t_drain + M.
    wrap_bound = h + t_drain_ms + margin_ms
    wrap_ok = (16.0 * poll_min_ms) > wrap_bound
    if not wrap_ok:
        reasons.append(
            "generation wrap: 16 * T_poll,min = %.1f ms <= H + t_drain + M = %.3f ms: "
            "a fail-open note could outlive its generation until the 4-bit DNP3 sequence "
            "reuses its value. Raise --min-poll-interval-ms." % (16.0 * poll_min_ms, wrap_bound))

    ok = qd["low_byte_zero"] and (read_only_trial or d_ok) and rto_ok and wrap_ok
    return {
        "ok": ok,
        "reasons": reasons,
        "d_requested_ms": d_ms,
        "d_realized_ms": d_real,
        "d_word": qd["word"],
        "d_word_hex": qd["word_hex"],
        "d_quant_error_ns": qd["quantization_error_ns"],
        "read_len": read_len,
        "budget": budget,
        "k": k,
        "H_ms": h,
        "D_max_ms": dmax,
        "ack_bound_ms": ack_bound_ms,
        "margin_ms": margin_ms,
        "rto_min_ms": rto_min_ms,
        "poll_min_ms": poll_min_ms,
        "wrap_bound_ms": wrap_bound,
        "read_only_trial": read_only_trial,
    }


def write_params(table, tgt, result: dict, gc):
    """The ONLY sanctioned writer of tbl_params (CORRECTIONS §3.2). Refuses on a bad
    verdict so a harness cannot bypass the policy by writing the table itself.

    `table` is a bfrt table handle for tbl_params, `tgt` a Target, `gc` the
    bfrt_grpc.client module. Tries both action-name spellings. Returns the action used.
    """
    if not result.get("ok"):
        raise ValueError("parameter policy REJECTED the configuration: %s"
                         % "; ".join(result.get("reasons", ["<no reason>"])))
    last = ""
    for act in ("Ingress.set_params", "set_params"):
        try:
            table.default_entry_set(tgt, table.make_data([
                gc.DataTuple("d_ticks", result["d_word"]),
                gc.DataTuple("read_len", result["read_len"]),
                gc.DataTuple("budget", result["budget"]),
            ], act))
            return act
        except Exception as e:  # noqa: BLE001
            last = str(e)[:120]
    raise RuntimeError("tbl_params write failed for both action names: %s" % last)


def _selftest() -> int:
    fails = 0

    def check(name, cond):
        nonlocal fails
        print(("  PASS " if cond else "  FAIL ") + name)
        if not cond:
            fails += 1

    h = horizon_ms(BUDGET_DEFAULT)
    check("H = 30.802 ms for B=18000,K=64", abs(h - 30.802) < 0.05)

    r16 = evaluate(16.0)
    check("D = 16 ms is admissible", r16["ok"])
    check("D_max ~ 24 ms (report target)", 23.0 <= r16["D_max_ms"] <= 26.0)

    r40 = evaluate(40.0)
    check("D = 40 ms is REFUSED (H < 40)", not r40["ok"])
    check("D = 40 ms rejection cites D_max", any("D_max" in x for x in r40["reasons"]))

    # a READ-only trial with a tiny budget must pass (small H is the point)
    rro = evaluate(2.0, budget=500, read_only_trial=True)
    check("READ-only shrunk-budget trial passes", rro["ok"])

    # wrap guard: a fast poll (e.g. 2 ms) must be refused
    rfast = evaluate(16.0, poll_min_ms=2.0)
    check("2 ms poll interval REFUSED by wrap guard",
          (not rfast["ok"]) and any("wrap" in x for x in rfast["reasons"]))

    # low-byte-zero invariant across a sweep
    lb = all(quantize_d(d)["low_byte_zero"] for d in (0.5, 1, 2, 3, 7, 12, 16, 22))
    check("quantized D always has a zero low byte", lb)

    print("parameter_policy self-test: %d failure(s)" % fails)
    return fails


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Case A Defense 3 parameter-safety policy")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--d-ms", type=float, default=16.0)
    ap.add_argument("--budget", type=int, default=BUDGET_DEFAULT)
    ap.add_argument("--k", type=int, default=K_TOKENS)
    ap.add_argument("--read-len", type=int, default=READ_LEN_DEFAULT)
    ap.add_argument("--ack-bound-ms", type=float, default=ACK_BOUND_MS_DEFAULT)
    ap.add_argument("--margin-ms", type=float, default=SAFETY_MARGIN_MS_DEFAULT)
    ap.add_argument("--min-poll-interval-ms", type=float, default=POLL_MIN_MS_DEFAULT)
    ap.add_argument("--read-only-trial", action="store_true")
    a = ap.parse_args(argv)
    if a.selftest:
        return _selftest()
    r = evaluate(a.d_ms, budget=a.budget, k=a.k, read_len=a.read_len,
                 ack_bound_ms=a.ack_bound_ms, margin_ms=a.margin_ms,
                 poll_min_ms=a.min_poll_interval_ms, read_only_trial=a.read_only_trial)
    print(json.dumps(r, indent=2))
    return 0 if r["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

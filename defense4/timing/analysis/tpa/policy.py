"""Deadline-policy model, Pareto table, and the common-policy selector.

Model (all times relative to the switch-observed native ACK arrival t_A):
  read-to-ack           a        = t_A - t_Q            (t_Q = master request time)
  native CLRT           C        = t_R - t_A
  hold horizon          H        = D_A + D_R            (response deadline from t_A)
  ACK released at       t_A + D_A
  response released at   max(t_R, t_A + H)              (held to deadline, or late-safe)
  master-facing CLRT    CLRT_out = max(C - D_A, D_R)    (pre release-error)

A transaction with C <= H is normalized to exactly D_R (the visible target); one
with C > H is a late-safe release visible at C - D_A > D_R. Release error
eps = (eps_R - eps_A) is the tiny scheduling/tick residual measured from defended
evidence and, when known, added to the prediction.

Master-visible request->response latency (AUDIT CORRECTION 2):

    L_master = a + max(C, H) + eps

is NOT bounded by H. When the native response is late (C > H) the switch performs a
late-safe release at the true arrival, so the master waits a + C, exceeding a + H.
The added *response* hold beyond native arrival is ΔL_response = max(0, H - C).
The ACK-delay term the observer/stack sees is D_A alone, so ACK-delay risk is
governed by D_A, not by H (AUDIT CORRECTION 3).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import numpy as np

from . import repo, stats

logger = logging.getLogger(__name__)


def _row_valid(r: dict) -> bool:
    """A scorer-valid transaction: ACK precedes response, no reset, ordering
    conclusive. A clean block-end FIN (response already completed) is kept, matching
    the accepted campaigns' n."""
    if r.get("rst"):
        return False
    if not r.get("ack_before_resp", True):
        return False
    if r.get("order_inconclusive"):
        return False
    return True


def load_series(reg: dict, dataset_id: str, repo_root: Path) -> dict:
    """Concatenate a dataset's per-transaction series across its blocks.

    ``values`` is C for native datasets and the master-facing CLRT_out for defended
    datasets. ``a_values`` is the per-row read-to-ack interval a = t_A - t_Q
    (``read_to_ack_ms``); for native datasets this is the native request->ACK, the
    quantity that enters L_master. Rows failing ``_row_valid`` are excluded/counted.
    """
    ds = next(d for d in reg["datasets"] if d["id"] == dataset_id)
    vals, a_vals, polls, labels = [], [], [], []
    excluded = 0
    a_available = True
    for blk in ds["blocks"]:
        d = json.loads(repo.resolve(repo_root, blk["path"]).read_text())
        for r in d["rows"]:
            if not _row_valid(r):
                excluded += 1
                continue
            vals.append(float(r["clrt_ms"]))
            if "read_to_ack_ms" in r:
                a_vals.append(float(r["read_to_ack_ms"]))
            else:
                a_available = False
            polls.append(int(r["poll"]))
            labels.append(d["label"])
    return {
        "id": dataset_id,
        "measures": ds["measures"],
        "d_a_ms": ds.get("d_a_ms"),
        "d_r_ms": ds.get("d_r_ms"),
        "budget": ds.get("budget"),
        "values": np.array(vals, dtype=float),
        "a_values": np.array(a_vals, dtype=float) if a_available else None,
        "a_available": a_available,
        "polls": polls,
        "labels": labels,
        "n_excluded": excluded,
    }


def pool_native_pairs(
    reg: dict, member_ids: list[str], repo_root: Path
) -> tuple[np.ndarray | None, np.ndarray]:
    """Return (a, C) paired native arrays across a native pool group.

    a is the request->ACK interval (read_to_ack_ms) and C the native CLRT, aligned
    per transaction. a is None (UNKNOWN) if any member lacks read_to_ack_ms or the
    two lengths do not align. Raises if a member is not native.
    """
    a_arr, c_arr = [], []
    a_ok = True
    for mid in member_ids:
        s = load_series(reg, mid, repo_root)
        if s["measures"] != "native_clrt":
            raise ValueError(f"pool_native_pairs got non-native dataset {mid}")
        c_arr.append(s["values"])
        if s["a_available"] and s["a_values"] is not None:
            a_arr.append(s["a_values"])
        else:
            a_ok = False
    C = np.concatenate(c_arr) if c_arr else np.array([])
    a = np.concatenate(a_arr) if (a_ok and a_arr) else None
    if a is not None and a.size != C.size:
        a = None  # misaligned -> refuse to guess
    return a, C


def pool_native_C(reg: dict, member_ids: list[str], repo_root: Path) -> np.ndarray:
    """Concatenate native C across a validated pool group (must all be native)."""
    _, C = pool_native_pairs(reg, member_ids, repo_root)
    return C


def measured_release_error(defended_out: np.ndarray, D_R: float, band_ms: float = 1.0) -> float | None:
    """Estimate eps = (eps_R - eps_A) from a defended stratum as median(CLRT_out)-D_R
    over the normalized band (values within ``band_ms`` of D_R). None if no band
    samples."""
    band = defended_out[np.abs(defended_out - D_R) <= band_ms]
    if band.size == 0:
        return None
    return float(np.median(band) - D_R)


def target_band_tolerance(
    reg: dict, repo_root: Path, quantile: float = 95.0, band_ms: float = 1.0
) -> tuple[float, dict]:
    """Symmetric target-band tolerance from actual covered-transaction errors.

    AUDIT CORRECTION 7: the tolerance is an explicitly reported quantile of the
    empirical |eps_R - eps_A| = |CLRT_out - D_R| over covered (normalized-band)
    transactions pooled across the *measured* defended policies. It is NOT the
    p5-p95 spread of any single defended distribution.
    """
    per_pair, pooled = {}, []
    for ds in reg["datasets"]:
        da, dr = ds["d_a_ms"], ds["d_r_ms"]
        if not (isinstance(da, (int, float)) and isinstance(dr, (int, float))):
            continue
        if dr <= 0 or ds["measures"] != "defended_clrt_out":
            continue
        v = load_series(reg, ds["id"], repo_root)["values"]
        band = v[np.abs(v - dr) <= band_ms]
        if band.size == 0:
            continue
        res = np.abs(band - dr)
        pooled.append(res)
        per_pair[ds["id"]] = {
            "D_A_ms": da, "D_R_ms": dr, "n_covered": int(band.size),
            f"abs_err_p{quantile:g}_ms": stats.pct(res, quantile),
        }
    pool = np.concatenate(pooled) if pooled else np.array([0.0])
    tol = stats.pct(pool, quantile)
    meta = {
        "tol_ms": tol,
        "quantile": quantile,
        "n_covered_transactions": int(pool.size),
        "band_ms": band_ms,
        "definition": (
            f"p{quantile:g} of |CLRT_out - D_R| over covered defended transactions "
            "(measured policies), symmetric target-band tolerance"
        ),
        "per_dataset": per_pair,
    }
    return tol, meta


def _margin(limit: float | None, quantity: float | None):
    """limit - quantity, or the string 'UNKNOWN' if either side is unavailable."""
    if limit is None or quantity is None:
        return "UNKNOWN"
    return float(limit - quantity)


def eval_policy(
    C: np.ndarray,
    D_A: float,
    D_R: float,
    tol_ms: float,
    a: np.ndarray | None = None,
    eps_ms: float = 0.0,
    eps_source: str = "assumed_zero",
    hardware_measured: bool = False,
    measured_datasets: list[str] | None = None,
    response_timeout_ms: float | None = None,
    poll_period_ms: float | None = None,
    tcp_rto_ms: float | None = None,
    fail_open_horizon_ms: float | None = None,
    reservoir_horizon_ms: float | None = None,
    coverage_alpha: float = 0.05,
) -> dict:
    """Evaluate one (D_A, D_R) policy against the native C distribution.

    ``a`` is the per-transaction request->ACK interval paired with ``C``; when given,
    the master-visible latency L_master = a + max(C, H) + eps is computed exactly and
    the response-timeout / poll-period margins use its worst case. When ``a`` is None
    those quantities are reported UNKNOWN rather than approximated by H.
    """
    C = np.asarray(C, dtype=float)
    n = C.size
    H = D_A + D_R
    covered = C <= H
    k = int(covered.sum())
    coverage = float(covered.mean()) if n else 0.0
    coverage_ci = stats.wilson_ci(k, n, coverage_alpha) if n else None

    predicted = np.maximum(C - D_A, D_R) + eps_ms            # master-facing CLRT_out
    added_resp = np.maximum(0.0, H - C)                      # ΔL_response hold
    in_band = np.abs(predicted - D_R) <= tol_ms
    tail = predicted > (D_R + tol_ms)

    # L_master = a + max(C, H) + eps  (NOT bounded by H when C > H).
    if a is not None:
        a = np.asarray(a, dtype=float)
        if a.size != n:
            raise ValueError(f"a and C misaligned: {a.size} vs {n}")
        Lm = a + np.maximum(C, H) + eps_ms
        L_master_max = float(Lm.max()) if n else None
        L_master_median = float(np.median(Lm)) if n else None
        L_master_p95 = stats.pct(Lm, 95) if n else None
        a_median = float(np.median(a)) if n else None
        a_max = float(a.max()) if n else None
        a_source = "measured:read_to_ack_ms (native pool)"
    else:
        L_master_max = L_master_median = L_master_p95 = "UNKNOWN"
        a_median = a_max = "UNKNOWN"
        a_source = "UNKNOWN (no request timestamp for this pool)"

    lm_worst = L_master_max if isinstance(L_master_max, (int, float)) else None

    return {
        "D_A_ms": D_A,
        "D_R_ms": D_R,
        "H_ms": H,
        "n_native": n,
        "hardware_measured": bool(hardware_measured),
        "policy_status": ("hardware-measured" if hardware_measured
                          else "analysis-selected, hardware-unmeasured"),
        "measured_datasets": measured_datasets or [],
        # ---- coverage ----
        "native_tail_coverage": coverage,          # P(C <= H)
        "native_tail_coverage_ci": coverage_ci,
        "n_covered": k,
        "n_late_safe_release": int((~covered).sum()),
        # ---- observable ----
        "visible_clrt_target_ms": D_R,             # what the observer reads for covered txns
        "target_band_tol_ms": tol_ms,
        "target_band_coverage": float(in_band.mean()) if n else 0.0,
        "release_error_eps_ms": eps_ms,
        "release_error_source": eps_source,
        # ---- latency ----
        "ack_delay_ms": D_A,                       # master-facing added ACK delay (governs ACK risk)
        "added_resp_latency_max_ms": float(added_resp.max()) if n else None,
        "added_resp_latency_median_ms": float(np.median(added_resp)) if n else None,
        "added_resp_latency_mean_ms": float(added_resp.mean()) if n else None,
        "a_read_to_ack_median_ms": a_median,
        "a_read_to_ack_max_ms": a_max,
        "a_source": a_source,
        "L_master_median_ms": L_master_median,     # a + max(C,H) + eps
        "L_master_p95_ms": L_master_p95,
        "L_master_max_ms": L_master_max,
        # ---- residual observable spread ----
        "residual_p5_p95_spread_ms": stats.pct(predicted, 95) - stats.pct(predicted, 5) if n else None,
        "residual_entropy_bits": stats.entropy_bits(predicted)[0] if n else None,
        "residual_effective_states": stats.entropy_bits(predicted)[1] if n else None,
        "residual_tail_fraction": float(tail.mean()) if n else 0.0,
        # ---- constraint margins (AUDIT CORRECTION 3) ----
        # response timeout & poll period compare with request->completion a+max(C,H):
        "margin_response_timeout_ms": _margin(response_timeout_ms, lm_worst),
        "margin_poll_period_ms": _margin(poll_period_ms, lm_worst),
        # ACK-delay risk compares with D_A (NOT H):
        "margin_ack_delay_vs_rto_ms": _margin(tcp_rto_ms, float(D_A)),
        # fail-open horizon vs H ONLY if the horizon is t_A-anchored & evidenced:
        "margin_fail_open_ms": _margin(fail_open_horizon_ms, float(H)),
        "margin_reservoir_ms": _margin(reservoir_horizon_ms, float(H)),
        "response_timeout_ms": response_timeout_ms if response_timeout_ms is not None else "UNKNOWN",
        "poll_period_ms": poll_period_ms if poll_period_ms is not None else "UNKNOWN",
        "tcp_rto_ms": tcp_rto_ms if tcp_rto_ms is not None else "UNKNOWN",
        "fail_open_horizon_ms": fail_open_horizon_ms if fail_open_horizon_ms is not None else "UNKNOWN",
        "reservoir_horizon_ms": reservoir_horizon_ms if reservoir_horizon_ms is not None else "UNKNOWN",
    }


def _fmt(v, nd=3):
    return f"{v:.{nd}f}" if isinstance(v, (int, float)) else str(v)


def pareto_row(ev: dict) -> dict:
    """The Pareto columns for one evaluated policy, honest about UNKNOWN margins."""
    cov_ci = ev.get("native_tail_coverage_ci")
    cov_ci_s = (f"[{cov_ci['ci_lo']:.4f},{cov_ci['ci_hi']:.4f}]" if cov_ci else "n/a")
    return {
        "policy": f"D_A={ev['D_A_ms']:g},D_R={ev['D_R_ms']:g}",
        "status": ev["policy_status"],
        "H_ms": ev["H_ms"],
        "native_tail_coverage": round(ev["native_tail_coverage"], 4),
        "coverage_wilson95": cov_ci_s,
        "visible_clrt_target_ms": ev["visible_clrt_target_ms"],
        "target_band_coverage": round(ev["target_band_coverage"], 4),
        "ack_delay_ms": ev["ack_delay_ms"],
        "L_master_max_ms": _fmt(ev["L_master_max_ms"]),
        "added_resp_latency_max_ms": (round(ev["added_resp_latency_max_ms"], 3)
                                      if ev["added_resp_latency_max_ms"] is not None else None),
        "margin_response_timeout_ms": _fmt(ev["margin_response_timeout_ms"], 1),
        "margin_poll_period_ms": _fmt(ev["margin_poll_period_ms"], 1),
        "margin_fail_open_ms": _fmt(ev["margin_fail_open_ms"], 3),
    }


class SelectorError(Exception):
    """Raised when selection is attempted per-device instead of domain-common."""


def select_common_policy(
    domain_native_C: np.ndarray,
    evaluations: list[dict],
    coverage_min: float,
    require_fail_open_margin_ms: float = 0.0,
    require_dr_positive: bool = True,
) -> dict:
    """Pick ONE policy for the whole protection domain.

    ``domain_native_C`` must be a single pooled native array for the domain, never
    a per-dataset mapping; passing a dict raises SelectorError to make the
    domain-common contract explicit and un-bypassable (AUDIT CORRECTION 8: never
    per-device).

    Admissibility (selected and tested under declared constraints, not 'optimal'):
      coverage >= coverage_min
      AND D_R > 0 (if required)
      AND every *KNOWN* margin satisfies its bound; an UNKNOWN margin is NOT a gate
          (AUDIT CORRECTION 3: the fail-open horizon is UNKNOWN because it is not
          established as t_A-anchored, so it cannot admit or reject a policy here).
    Objective: minimize total horizon H; tie-break smaller D_A then smaller D_R.
    All policies sharing the winning H are reported co-optimal, with their
    hardware-measured status, so an equal-H measured policy is not hidden behind the
    tie-break.
    """
    if isinstance(domain_native_C, dict):
        raise SelectorError(
            "common-policy selection is domain-level; got a per-device/per-dataset "
            "mapping. Pool the domain's native evidence into one array first."
        )
    admissible = []
    for ev in evaluations:
        if require_dr_positive and ev["D_R_ms"] <= 0:
            continue
        if ev["native_tail_coverage"] < coverage_min:
            continue
        mfo = ev["margin_fail_open_ms"]
        if isinstance(mfo, (int, float)) and mfo < require_fail_open_margin_ms:
            continue
        mrt = ev["margin_response_timeout_ms"]
        if isinstance(mrt, (int, float)) and mrt < 0:
            continue
        mpp = ev["margin_poll_period_ms"]
        if isinstance(mpp, (int, float)) and mpp < 0:
            continue
        admissible.append((ev["H_ms"], ev["ack_delay_ms"], ev["D_R_ms"], ev))
    admissible.sort(key=lambda t: (t[0], t[1], t[2]))
    selected = admissible[0][3] if admissible else None
    co_optimal = (
        [t[3] for t in admissible if t[0] == admissible[0][0]] if admissible else []
    )
    measured_co_optimal = [e for e in co_optimal if e["hardware_measured"]]
    return {
        "coverage_min": coverage_min,
        "require_fail_open_margin_ms": require_fail_open_margin_ms,
        "objective": "min total horizon H, tie-break min D_A then min D_R",
        "n_admissible": len(admissible),
        "selected": selected,
        "selected_is_hardware_measured": bool(selected["hardware_measured"]) if selected else None,
        "co_optimal_at_min_H": co_optimal,
        "measured_co_optimal_at_min_H": measured_co_optimal,
        "ranked_admissible": [t[3] for t in admissible],
        "note": (
            "selected and tested under declared constraints; not claimed optimal. "
            "Fail-open horizon is UNKNOWN (not t_A-anchored in committed raw) so it "
            "gates nothing here."
        ),
    }

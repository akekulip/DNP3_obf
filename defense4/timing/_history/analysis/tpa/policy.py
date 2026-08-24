"""Deadline-policy model, Pareto table, and the common-policy selector.

Model (all times relative to the switch-observed native ACK arrival t_A):
  read-to-ack           a        = t_A - t_Q            (t_Q = master request time)
  native CLRT           C        = t_R - t_A
  hold horizon          H        = D_A + D_R            (response deadline from t_A)
  ACK released at       t_A + D_A
  response released at   max(t_R, t_A + H)              (held to deadline, or late-safe)
  master-facing CLRT    CLRT_out = max(C - D_A, D_R)    (pre release-error)

A transaction with C <= H is normalized to exactly D_R (the visible target); one
with C > H is a late-safe release visible at C - D_A > D_R. The observer-visible
CLRT_out carries a DIFFERENTIAL release error eps = (eps_R - eps_A): the ACK and the
response both incur their own tiny scheduling/tick residual and only the DIFFERENCE
survives in CLRT_out = t_resp_released - t_ack_released. Keep that differential in
the observer-visible prediction (audit-mandated).

Master-visible request->response latency L_master (FIX 1, audit M3):

  * For a MEASURED policy L_master is taken DIRECTLY from the raw per-row
    ``read_to_resp_ms = (t_resp - t_read)`` of the defended dataset that ran this
    exact (D_A, D_R). No model, no epsilon: it is what a master actually observed.
  * For an ANALYSIS-ONLY policy (never run) L_master is the MODELLED FLOOR
    ``a + max(C, H)``; the ABSOLUTE response release error eps_R is left UNKNOWN.
    The differential eps = (eps_R - eps_A) is NEVER added here -- it is not an
    absolute latency correction (it only cancels inside the observer-visible
    CLRT_out). Using a differential as an absolute was the M3 defect.

L_master is NOT bounded by H: when the native response is late (C > H) the switch
performs a late-safe release at the true arrival, so the master waits ~a + C. The
added *response* hold beyond native arrival is dL_response = max(0, H - C). The
ACK-delay term the observer/stack sees is D_A alone, so ACK-delay risk is governed
by D_A, not by H (audit correction 3).
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
    quantity that enters L_master. ``lm_values`` is the per-row DIRECTLY OBSERVED
    master-visible request->response latency L_master = t_resp - t_read
    (``read_to_resp_ms``); for a defended dataset this is the exact quantity a master
    saw under that policy, needed by FIX 1 so L_master is measured, not modelled from
    a differential release error. Rows failing ``_row_valid`` are excluded/counted.
    """
    ds = next(d for d in reg["datasets"] if d["id"] == dataset_id)
    vals, a_vals, lm_vals, polls, labels = [], [], [], [], []
    excluded = 0
    a_available = True
    lm_available = True
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
            if "read_to_resp_ms" in r:
                lm_vals.append(float(r["read_to_resp_ms"]))
            else:
                lm_available = False
            polls.append(int(r["poll"]))
            labels.append(d["label"])
    return {
        "id": dataset_id,
        "measures": ds["measures"],
        "d_a_ms": ds.get("d_a_ms"),
        "d_r_ms": ds.get("d_r_ms"),
        "budget": ds.get("budget"),
        "role": ds.get("role"),
        "values": np.array(vals, dtype=float),
        "a_values": np.array(a_vals, dtype=float) if a_available else None,
        "a_available": a_available,
        "lm_values": np.array(lm_vals, dtype=float) if lm_available else None,
        "lm_available": lm_available,
        "polls": polls,
        "labels": labels,
        "n_excluded": excluded,
    }


def observed_l_master(
    reg: dict,
    repo_root: Path,
    d_a: float,
    d_r: float,
    roles: tuple[str, ...] = ("paper_accepted",),
    fallback_roles: tuple[str, ...] = ("policy_probe",),
) -> tuple[np.ndarray | None, list[str]]:
    """Directly observed L_master (read_to_resp_ms) for one measured (D_A, D_R).

    FIX 1: pools ``read_to_resp_ms = t_resp - t_read`` across the ``defended_clrt_out``
    datasets that ran this exact policy, preferring one coherent stratum -- ``roles``
    first (e.g. the paper-accepted defended campaigns) and, only if none match,
    ``fallback_roles`` (e.g. the d4recal single-block probes). Strata are never mixed
    and the fail-open regime is never used. Returns (values, source_ids), or (None, [])
    if the policy was never run in these strata.
    """
    def _collect(role_set: tuple[str, ...]):
        vals, ids = [], []
        for ds in reg["datasets"]:
            if ds.get("measures") != "defended_clrt_out":
                continue
            if ds.get("role") not in role_set:
                continue
            da, dr = ds.get("d_a_ms"), ds.get("d_r_ms")
            if not (isinstance(da, (int, float)) and isinstance(dr, (int, float))):
                continue
            if float(da) != float(d_a) or float(dr) != float(d_r):
                continue
            s = load_series(reg, ds["id"], repo_root)
            if s["lm_values"] is None or s["lm_values"].size == 0:
                continue
            vals.append(s["lm_values"])
            ids.append(ds["id"])
        return (np.concatenate(vals) if vals else None), ids

    v, ids = _collect(roles)
    if v is None:
        v, ids = _collect(fallback_roles)
    return v, ids


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
    """Estimate the DIFFERENTIAL eps = (eps_R - eps_A) from a defended stratum as
    median(CLRT_out) - D_R over the normalized band (values within ``band_ms`` of
    D_R). None if no band samples. This differential is used ONLY in the observer-
    visible CLRT_out prediction; it is NEVER used as an absolute L_master term."""
    band = defended_out[np.abs(defended_out - D_R) <= band_ms]
    if band.size == 0:
        return None
    return float(np.median(band) - D_R)


def target_band_tolerance(
    reg: dict,
    repo_root: Path,
    quantile: float = 95.0,
    band_ms: float = 1.0,
    native_C: np.ndarray | None = None,
) -> tuple[float, dict]:
    """Release-timing jitter and, alongside it, the PAIRED untruncated coverage.

    FIX 2 (audit M4): the previous version kept only defended values within +/-band_ms
    of D_R and then quantiled the error INSIDE that pre-selected band -- excluding the
    very tail errors it should summarize and never pairing with the native C<=H
    normalization population. This version reports, per measured defended policy:

      * ``abs_err_p{q}_ms_conditional``  -- p{q} of |CLRT_out - D_R| over the normalized
        band only. Explicitly a CONDITIONAL jitter statistic; ``is_total_coverage`` is
        False and it must NEVER be read as coverage.
      * ``abs_err_p{q}_ms_untruncated``  -- p{q} of |CLRT_out - D_R| over ALL valid
        defended transactions (the excluded tail is now included, not hidden).
      * ``frac_outside_normalized_band`` -- the fraction the conditional statistic drops.
      * ``native_covered_fraction``      -- PAIRED native P(C <= H) for this exact
        (D_A, D_R) when ``native_C`` is supplied, so the jitter is read next to the
        real normalization population rather than in isolation.

    The returned scalar ``tol`` is the pooled CONDITIONAL jitter (band half-width used
    for the secondary ``target_band_coverage`` observable). It is labelled conditional
    and is not the selection coverage: selection uses native P(C <= H).
    """
    per_pair, pooled_cond, pooled_untrunc = {}, [], []
    n_out_total = n_all_total = 0
    for ds in reg["datasets"]:
        da, dr = ds["d_a_ms"], ds["d_r_ms"]
        if not (isinstance(da, (int, float)) and isinstance(dr, (int, float))):
            continue
        if dr <= 0 or ds["measures"] != "defended_clrt_out":
            continue
        v = load_series(reg, ds["id"], repo_root)["values"]
        if v.size == 0:
            continue
        res_all = np.abs(v - dr)                       # UNTRUNCATED
        band = v[np.abs(v - dr) <= band_ms]            # normalized band
        res_cond = np.abs(band - dr)
        pooled_untrunc.append(res_all)
        n_all_total += int(v.size)
        n_out_total += int(v.size - band.size)
        if res_cond.size:
            pooled_cond.append(res_cond)
        native_cov = None
        if native_C is not None and native_C.size:
            H = float(da) + float(dr)
            native_cov = float((np.asarray(native_C, dtype=float) <= H).mean())
        per_pair[ds["id"]] = {
            "D_A_ms": da,
            "D_R_ms": dr,
            "n_total": int(v.size),
            "n_in_normalized_band": int(band.size),
            "frac_outside_normalized_band": float(1.0 - band.size / v.size),
            f"abs_err_p{quantile:g}_ms_conditional": (stats.pct(res_cond, quantile)
                                                      if res_cond.size else None),
            f"abs_err_p{quantile:g}_ms_untruncated": stats.pct(res_all, quantile),
            "native_covered_fraction": native_cov,
        }
    pool_cond = np.concatenate(pooled_cond) if pooled_cond else np.array([0.0])
    pool_untrunc = np.concatenate(pooled_untrunc) if pooled_untrunc else np.array([0.0])
    tol = stats.pct(pool_cond, quantile)
    meta = {
        "tol_ms": tol,
        "quantile": quantile,
        "band_ms": band_ms,
        "is_total_coverage": False,
        "conditional": True,
        "n_covered_transactions": int(pool_cond.size),         # in-band (conditional)
        "n_all_transactions": int(n_all_total),
        "frac_outside_normalized_band_pooled": (float(n_out_total / n_all_total)
                                                if n_all_total else 0.0),
        f"abs_err_p{quantile:g}_ms_untruncated_pooled": stats.pct(pool_untrunc, quantile),
        "definition": (
            f"CONDITIONAL jitter: p{quantile:g} of |CLRT_out - D_R| over the normalized "
            "band of covered defended transactions (measured policies). NOT total "
            "coverage; the untruncated pooled quantile and the dropped-tail fraction "
            "are reported alongside, and native P(C<=H) pairs each policy."
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
    observed_l_master: np.ndarray | None = None,
    hardware_measured: bool = False,
    measured_datasets: list[str] | None = None,
    response_timeout_ms: float | None = None,
    master_recv_timeout_ms: float | None = None,
    poll_period_ms: float | None = None,
    tcp_rto_ms: float | None = None,
    fail_open_horizon_ms: float | None = None,
    reservoir_horizon_ms: float | None = None,
    coverage_alpha: float = 0.05,
) -> dict:
    """Evaluate one (D_A, D_R) policy against the native C distribution.

    L_master (FIX 1) is taken from ``observed_l_master`` (the directly observed
    per-row request->response latency of the defended dataset for this exact policy)
    when supplied; otherwise from the MODELLED FLOOR ``a + max(C, H)`` with the
    absolute release error eps_R left UNKNOWN. The differential ``eps_ms`` is used only
    in the observer-visible CLRT_out and is NEVER added to L_master. When neither an
    observation nor ``a`` is available the latency-dependent quantities are UNKNOWN.
    """
    C = np.asarray(C, dtype=float)
    n = C.size
    H = D_A + D_R
    covered = C <= H
    k = int(covered.sum())
    coverage = float(covered.mean()) if n else 0.0
    coverage_ci = stats.wilson_ci(k, n, coverage_alpha) if n else None

    predicted = np.maximum(C - D_A, D_R) + eps_ms            # master-facing CLRT_out
    added_resp = np.maximum(0.0, H - C)                      # dL_response hold
    in_band = np.abs(predicted - D_R) <= tol_ms
    tail = predicted > (D_R + tol_ms)

    # ---- request->ACK descriptor a (native pool), reported independently ----
    if a is not None:
        a = np.asarray(a, dtype=float)
        if a.size != n:
            raise ValueError(f"a and C misaligned: {a.size} vs {n}")
        a_median = float(np.median(a)) if n else None
        a_max = float(a.max()) if n else None
        a_source = "measured:read_to_ack_ms (native pool)"
    else:
        a_median = a_max = "UNKNOWN"
        a_source = "UNKNOWN (no request timestamp for this pool)"

    # ---- L_master = master-visible request->response latency (FIX 1) ----
    # Directly observed for a measured policy; modelled FLOOR a+max(C,H) otherwise.
    # The differential eps is NEVER added here (M3 defect).
    if observed_l_master is not None and np.asarray(observed_l_master).size:
        Lm = np.asarray(observed_l_master, dtype=float)
        L_master_median = float(np.median(Lm))
        L_master_p95 = stats.pct(Lm, 95)
        L_master_max = float(Lm.max())
        L_master_n = int(Lm.size)
        L_master_is_floor = False
        L_master_source = ("measured_direct: read_to_resp_ms = (t_resp - t_read) of the "
                           "defended dataset for this exact (D_A,D_R)")
        L_master_release_error_ms = "included_in_direct_observation"
    elif a is not None:
        Lm = a + np.maximum(C, H)                            # NO eps: modelled floor
        L_master_median = float(np.median(Lm)) if n else None
        L_master_p95 = stats.pct(Lm, 95) if n else None
        L_master_max = float(Lm.max()) if n else None
        L_master_n = n
        L_master_is_floor = True
        L_master_source = ("modeled_floor: a + max(C,H) (native pool); absolute release "
                           "error eps_R UNKNOWN (differential eps_R-eps_A is NOT an "
                           "absolute correction)")
        L_master_release_error_ms = "UNKNOWN (absolute eps_R not isolable from committed raw)"
    else:
        L_master_median = L_master_p95 = L_master_max = "UNKNOWN"
        L_master_n = 0
        L_master_is_floor = False
        L_master_source = "UNKNOWN (no direct observation and no request timestamp)"
        L_master_release_error_ms = "UNKNOWN"

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
        "L_master_median_ms": L_master_median,     # measured-direct OR modelled floor
        "L_master_p95_ms": L_master_p95,
        "L_master_max_ms": L_master_max,
        "L_master_n": L_master_n,
        "L_master_is_floor": L_master_is_floor,
        "L_master_source": L_master_source,
        "L_master_release_error_ms": L_master_release_error_ms,
        # ---- residual observable spread ----
        "residual_p5_p95_spread_ms": stats.pct(predicted, 95) - stats.pct(predicted, 5) if n else None,
        "residual_entropy_bits": stats.entropy_bits(predicted)[0] if n else None,
        "residual_effective_states": stats.entropy_bits(predicted)[1] if n else None,
        "residual_tail_fraction": float(tail.mean()) if n else 0.0,
        # ---- constraint margins (audit correction 3; FIX 4 provenance) ----
        # DNP3 application response timeout is UNKNOWN in the evidence path (raw-socket
        # driver), so its margin is UNKNOWN; the EVIDENCED master socket recv timeout
        # (campaign_driver.py) is a separate, cited ceiling.
        "margin_response_timeout_ms": _margin(response_timeout_ms, lm_worst),
        "margin_master_recv_timeout_ms": _margin(master_recv_timeout_ms, lm_worst),
        "margin_poll_period_ms": _margin(poll_period_ms, lm_worst),
        # ACK-delay risk compares with D_A (NOT H):
        "margin_ack_delay_vs_rto_ms": _margin(tcp_rto_ms, float(D_A)),
        # fail-open horizon vs H ONLY if the horizon is t_A-anchored & evidenced:
        "margin_fail_open_ms": _margin(fail_open_horizon_ms, float(H)),
        "margin_reservoir_ms": _margin(reservoir_horizon_ms, float(H)),
        "response_timeout_ms": response_timeout_ms if response_timeout_ms is not None else "UNKNOWN",
        "master_recv_timeout_ms": master_recv_timeout_ms if master_recv_timeout_ms is not None else "UNKNOWN",
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
        "L_master_kind": ("floor" if ev["L_master_is_floor"]
                          else ("measured" if ev["hardware_measured"] else "n/a")),
        "added_resp_latency_max_ms": (round(ev["added_resp_latency_max_ms"], 3)
                                      if ev["added_resp_latency_max_ms"] is not None else None),
        "margin_response_timeout_ms": _fmt(ev["margin_response_timeout_ms"], 1),
        "margin_master_recv_timeout_ms": _fmt(ev["margin_master_recv_timeout_ms"], 1),
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
    coverage_confidence_alpha: float = 0.05,
) -> dict:
    """Pick a common-domain policy CANDIDATE under a declared coverage rule.

    ``domain_native_C`` must be a single pooled native array for the domain, never a
    per-dataset mapping; passing a dict raises SelectorError to make the domain-common
    contract explicit and un-bypassable (audit correction 8: never per-device).

    Two admissibility strata are reported (FIX 3, audit M4):

      * POINT-ESTIMATE admissible: coverage point estimate >= coverage_min AND D_R > 0
        AND every KNOWN margin satisfies its bound. The min-H winner here is an ANALYSIS
        CANDIDATE only -- it is NOT confidence-qualified merely by clearing the point
        estimate.
      * CONFIDENCE-QUALIFIED: additionally the Wilson score LOWER bound (at
        ``coverage_confidence_alpha``) on the selection-stratum coverage is
        >= coverage_min. Only such a policy establishes >= coverage_min at confidence.

    An UNKNOWN margin never gates (the fail-open horizon is UNKNOWN -> gates nothing).
    Objective: minimize H; tie-break smaller D_A then smaller D_R. If NO candidate is
    confidence-qualified the verdict says so; more samples or a larger H are required.
    """
    if isinstance(domain_native_C, dict):
        raise SelectorError(
            "common-policy selection is domain-level; got a per-device/per-dataset "
            "mapping. Pool the domain's native evidence into one array first."
        )
    conf = 100.0 * (1.0 - coverage_confidence_alpha)
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
        ci = ev.get("native_tail_coverage_ci") or {}
        ci_lo = ci.get("ci_lo")
        conf_ok = ci_lo is not None and ci_lo >= coverage_min
        admissible.append((ev["H_ms"], ev["ack_delay_ms"], ev["D_R_ms"], ev, conf_ok, ci_lo))
    admissible.sort(key=lambda t: (t[0], t[1], t[2]))

    selected = admissible[0][3] if admissible else None            # point-estimate candidate
    selected_conf_ok = bool(admissible[0][4]) if admissible else None
    co_optimal = (
        [t[3] for t in admissible if t[0] == admissible[0][0]] if admissible else []
    )
    measured_co_optimal = [e for e in co_optimal if e["hardware_measured"]]

    qualified = [t for t in admissible if t[4]]
    qualified.sort(key=lambda t: (t[0], t[1], t[2]))
    confidence_selected = qualified[0][3] if qualified else None
    best_ci_lo = max((t[5] for t in admissible if t[5] is not None), default=None)

    if confidence_selected is not None:
        cs = confidence_selected
        verdict = (
            f"CONFIDENCE-QUALIFIED: policy (D_A={cs['D_A_ms']:g},D_R={cs['D_R_ms']:g}) "
            f"establishes coverage >= {coverage_min:g} at {conf:.0f}% confidence "
            f"(Wilson lower {cs['native_tail_coverage_ci']['ci_lo']:.4f})."
        )
    else:
        best_s = (f"{best_ci_lo:.4f}" if best_ci_lo is not None else "n/a")
        verdict = (
            f"NO candidate establishes coverage >= {coverage_min:g} at {conf:.0f}% "
            f"confidence (max Wilson lower bound {best_s} over point-admissible "
            f"candidates). The min-H point-estimate winner is an ANALYSIS CANDIDATE "
            f"only; more samples or a larger H are required to qualify at confidence."
        )
    return {
        "coverage_min": coverage_min,
        "coverage_confidence_alpha": coverage_confidence_alpha,
        "coverage_confidence_pct": conf,
        "require_fail_open_margin_ms": require_fail_open_margin_ms,
        "objective": ("min total horizon H, tie-break min D_A then min D_R; "
                      "POINT-ESTIMATE admissibility (coverage point >= min)"),
        "n_admissible": len(admissible),
        "n_confidence_qualified": len(qualified),
        "max_wilson_lower_over_admissible": best_ci_lo,
        # point-estimate analysis candidate (NOT confidence-qualified by itself):
        "selected": selected,
        "selected_is_hardware_measured": bool(selected["hardware_measured"]) if selected else None,
        "selected_confidence_qualified": selected_conf_ok,
        # the confidence-qualified selection (None when nothing qualifies):
        "confidence_qualified_selected": confidence_selected,
        "co_optimal_at_min_H": co_optimal,
        "measured_co_optimal_at_min_H": measured_co_optimal,
        "ranked_admissible": [t[3] for t in admissible],
        "coverage_verdict": verdict,
        "note": (
            "ANALYSIS CANDIDATE under a declared POINT-ESTIMATE coverage>=min rule; "
            "NOT confidence-qualified unless the Wilson lower bound >= min; NOT claimed "
            "optimal; NOT hardware-selected. Fail-open horizon is UNKNOWN (not "
            "t_A-anchored in committed raw) so it gates nothing here."
        ),
    }

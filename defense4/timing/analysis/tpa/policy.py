"""Deadline-policy model, Pareto table, and the common-policy selector.

Model (master-facing, all times relative to the switch-observed ACK arrival t_A):
  native CLRT           C        = t_R - t_A
  hold horizon          H        = D_A + D_R           (absolute response deadline from t_A)
  ACK released at       t_A + D_A
  response released at   max(t_R, t_A + H)             (held to deadline, or late-safe)
  master-facing output  CLRT_out = max(C - D_A, D_R)   (pre release-error)

A transaction with C <= H is normalized to exactly D_R (the visible target); one
with C > H is a late-safe release visible at C - D_A > D_R. Release error
eps = (eps_R - eps_A) is the tiny scheduling/tick residual measured from defended
evidence and, when known, added to the prediction.

Total master-visible response latency is a + H (a = native read-to-ack), governed
by H alone; the split of H between D_A (ACK delay) and D_R (visible CLRT target) is
a secondary design choice among equal-H policies.
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
    """Concatenate a dataset's per-transaction CLRT series across its blocks.

    For native datasets the series is C; for defended datasets it is the
    master-facing CLRT_out. Rows failing ``_row_valid`` are excluded and counted.
    """
    ds = next(d for d in reg["datasets"] if d["id"] == dataset_id)
    vals, polls, labels = [], [], []
    excluded = 0
    for blk in ds["blocks"]:
        d = json.loads(repo.resolve(repo_root, blk["path"]).read_text())
        for r in d["rows"]:
            if not _row_valid(r):
                excluded += 1
                continue
            vals.append(float(r["clrt_ms"]))
            polls.append(int(r["poll"]))
            labels.append(d["label"])
    return {
        "id": dataset_id,
        "measures": ds["measures"],
        "d_a_ms": ds.get("d_a_ms"),
        "d_r_ms": ds.get("d_r_ms"),
        "budget": ds.get("budget"),
        "values": np.array(vals, dtype=float),
        "polls": polls,
        "labels": labels,
        "n_excluded": excluded,
    }


def pool_native_C(reg: dict, member_ids: list[str], repo_root: Path) -> np.ndarray:
    """Concatenate native C across a validated pool group (must all be native)."""
    arr = []
    for mid in member_ids:
        s = load_series(reg, mid, repo_root)
        if s["measures"] != "native_clrt":
            raise ValueError(f"pool_native_C got non-native dataset {mid}")
        arr.append(s["values"])
    return np.concatenate(arr) if arr else np.array([])


def measured_release_error(defended_out: np.ndarray, D_R: float) -> float | None:
    """Estimate eps = (eps_R - eps_A) from a defended stratum as median(CLRT_out)-D_R
    over the normalized band (values within 1 ms of D_R). None if no band samples."""
    band = defended_out[np.abs(defended_out - D_R) <= 1.0]
    if band.size == 0:
        return None
    return float(np.median(band) - D_R)


def eval_policy(
    C: np.ndarray,
    D_A: float,
    D_R: float,
    tol_ms: float,
    eps_ms: float = 0.0,
    eps_source: str = "assumed_zero",
    fail_open_horizon_ms: float | None = None,
    poll_period_ms: float | None = None,
    response_timeout_ms: float | None = None,
    tcp_rto_ms: float | None = None,
    reservoir_horizon_ms: float | None = None,
) -> dict:
    """Evaluate one (D_A, D_R) policy against the native C distribution."""
    C = np.asarray(C, dtype=float)
    n = C.size
    H = D_A + D_R
    covered = C <= H
    coverage = float(covered.mean())
    predicted = np.maximum(C - D_A, D_R) + eps_ms          # master-facing CLRT_out
    added_resp = np.maximum(0.0, H - C)                     # response hold beyond arrival
    in_band = np.abs(predicted - D_R) <= tol_ms
    tail = predicted > (D_R + tol_ms)

    def margin(limit):
        return None if limit is None else float(limit - H)

    return {
        "D_A_ms": D_A,
        "D_R_ms": D_R,
        "H_ms": H,
        "n_native": n,
        "native_tail_coverage": coverage,          # P(C <= H)
        "n_late_safe_release": int((~covered).sum()),
        "visible_clrt_target_ms": D_R,             # what the observer reads for covered txns
        "target_band_tol_ms": tol_ms,
        "target_band_coverage": float(in_band.mean()),
        "release_error_eps_ms": eps_ms,
        "release_error_source": eps_source,
        "ack_delay_ms": D_A,                       # master-facing added ACK delay
        "added_resp_latency_max_ms": float(added_resp.max()) if n else None,
        "added_resp_latency_median_ms": float(np.median(added_resp)) if n else None,
        "added_resp_latency_mean_ms": float(added_resp.mean()) if n else None,
        "total_master_latency_max_ms": H,          # a + H bound; H is the governing term
        "residual_p5_p95_spread_ms": stats.pct(predicted, 95) - stats.pct(predicted, 5),
        "residual_entropy_bits": stats.entropy_bits(predicted)[0],
        "residual_effective_states": stats.entropy_bits(predicted)[1],
        "residual_tail_fraction": float(tail.mean()),
        "margin_fail_open_ms": margin(fail_open_horizon_ms),
        "margin_poll_period_ms": margin(poll_period_ms),
        "margin_response_timeout_ms": margin(response_timeout_ms),
        "margin_tcp_rto_ms": margin(tcp_rto_ms),
        "margin_reservoir_ms": margin(reservoir_horizon_ms),
        "fail_open_horizon_ms": fail_open_horizon_ms,
        "reservoir_horizon_ms": reservoir_horizon_ms
        if reservoir_horizon_ms is not None
        else "UNKNOWN",
        "tcp_rto_ms": tcp_rto_ms if tcp_rto_ms is not None else "UNKNOWN",
    }


def pareto_row(ev: dict) -> dict:
    """The task-specified Pareto columns for one evaluated policy."""
    return {
        "policy": f"D_A={ev['D_A_ms']:g},D_R={ev['D_R_ms']:g}",
        "H_ms": ev["H_ms"],
        "native_tail_coverage": round(ev["native_tail_coverage"], 4),
        "visible_clrt_target_ms": ev["visible_clrt_target_ms"],
        "target_band_coverage": round(ev["target_band_coverage"], 4),
        "ack_delay_ms": ev["ack_delay_ms"],
        "added_resp_latency_max_ms": round(ev["added_resp_latency_max_ms"], 3)
        if ev["added_resp_latency_max_ms"] is not None
        else None,
        "margin_fail_open_ms": round(ev["margin_fail_open_ms"], 3)
        if ev["margin_fail_open_ms"] is not None
        else None,
        "margin_response_timeout_ms": round(ev["margin_response_timeout_ms"], 1)
        if ev["margin_response_timeout_ms"] is not None
        else None,
        "reservoir_requirement": "H_ms < fail_open_horizon; "
        + (
            f"{ev['H_ms']:g} < {ev['fail_open_horizon_ms']:g} OK"
            if ev["fail_open_horizon_ms"] is not None
            and ev["H_ms"] < ev["fail_open_horizon_ms"]
            else "UNSAFE_or_UNKNOWN"
        ),
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
    domain-common contract explicit and un-bypassable.

    Selection is 'selected and tested under declared constraints', not 'optimal':
      admissible = coverage >= coverage_min AND H < fail_open_horizon (with margin)
                   AND (D_R > 0 if require_dr_positive)
      objective  = minimize total master latency H (smaller = less delay); tie-break
                   by smaller ACK delay D_A, then smaller D_R.
    All policies sharing the winning (minimal admissible) H are reported as
    co-optimal on coverage+latency, so an equal-coverage tested policy is not hidden
    behind an arbitrary tie-break.
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
        m = ev["margin_fail_open_ms"]
        if m is None or m < require_fail_open_margin_ms:
            continue
        admissible.append((ev["H_ms"], ev["ack_delay_ms"], ev["D_R_ms"], ev))
    admissible.sort(key=lambda t: (t[0], t[1], t[2]))
    selected = admissible[0][3] if admissible else None
    co_optimal = (
        [t[3] for t in admissible if t[0] == admissible[0][0]] if admissible else []
    )
    return {
        "coverage_min": coverage_min,
        "require_fail_open_margin_ms": require_fail_open_margin_ms,
        "objective": "min total latency H, tie-break min D_A then min D_R",
        "n_admissible": len(admissible),
        "selected": selected,
        "co_optimal_at_min_H": co_optimal,
        "ranked_admissible": [t[3] for t in admissible],
        "note": "selected and tested under declared constraints; not claimed optimal",
    }

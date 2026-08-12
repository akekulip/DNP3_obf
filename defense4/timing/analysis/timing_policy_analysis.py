#!/usr/bin/env python
"""Timing-policy characterization CLI for the DNP3 Defense-4 timing engine.

Loads the baseline registry, validates it against the committed raw evidence
(paths, sha256, per-transaction schema, units, timing definitions on EVERY row),
computes per-stratum distributions with bootstrap/Wilson CIs, evaluates candidate
(D_A, D_R) deadline policies against the evidenced native CLRT distribution, and
reports one common-domain policy CANDIDATE under a declared coverage rule.

FIX 1 (audit M3): the master-visible latency L_master is taken DIRECTLY from the
observed per-row request->response latency (read_to_resp_ms = t_resp - t_read) of the
defended dataset that ran a measured policy; for analysis-only policies it is the
MODELLED FLOOR a + max(C, H) with the absolute release error eps_R left UNKNOWN. The
differential eps = (eps_R - eps_A) is kept ONLY in the observer-visible CLRT_out and
is never used as an absolute latency term.

FIX 3 (audit M4): selection is confidence-aware. A policy is an ANALYSIS CANDIDATE if
its point-estimate coverage clears the threshold; it is CONFIDENCE-QUALIFIED only if
the Wilson lower bound clears it. No auto-promotion without confidence.

FIX 4 (audit M5): every timing ceiling is a separate, provenance-tagged constraint.
The DNP3 application response timeout is UNKNOWN (the evidence came from a raw-socket
driver); the evidenced ceiling is that driver's socket recv timeout.

Software/analysis only; no hardware. Every candidate is labelled hardware-measured
vs analysis-only, and every unavailable constraint is left UNKNOWN, never invented.

Usage:
  $RESEARCH_PYTHON timing_policy_analysis.py \
      [--registry registry.yaml] [--out-json results.json] [--out-md REPORT.md] \
      [--coverage-min 0.99] [--tol-quantile 95] [--tol-ms auto] \
      [--bootstrap 2000] [--seed 20260807] [--no-verify-sha]
"""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

import numpy as np

from tpa import policy, registry, repo, stats

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger("tpa.cli")

# Candidate (D_A, D_R) grid evaluated against the native design distribution.
# Hardware-measured pairs are (0,10) D2, (4,10) D4, and the d4recal probes
# (2,10),(2,4),(4,12),(6,8); every other pair is analysis-only. (4,10) is
# evaluated but never auto-selected by the min-H tie-break.
CANDIDATE_GRID = [
    (0, 10), (2, 4), (2, 10), (2, 12), (3, 11), (4, 8), (4, 10), (4, 12),
    (4, 14), (5, 10), (5, 11), (6, 8), (6, 10), (8, 8), (4, 16), (2, 14),
]

QGRID = [0, 1, 2, 5, 10, 25, 50, 75, 90, 95, 99, 100]


def quantile_grid(x: np.ndarray) -> dict:
    a = np.asarray(x, dtype=float)
    return {f"q{q}": stats.pct(a, q) for q in QGRID}


def stratum_stats(reg, repo_root, boot_B, seed):
    """Per pool-group and per-dataset summaries with bootstrap CIs where n permits."""
    groups = registry.pool_groups(reg)
    by_id = {d["id"]: d for d in reg["datasets"]}
    out = {"groups": {}, "datasets": {}}
    for rep, members in groups.items():
        vals = np.concatenate(
            [policy.load_series(reg, m, repo_root)["values"] for m in members]
        )
        s = stats.summary(vals)
        s["members"] = members
        s["measures"] = by_id[rep]["measures"]
        s["role"] = by_id[rep]["role"]
        s["d_a_ms"] = by_id[rep]["d_a_ms"]
        s["d_r_ms"] = by_id[rep]["d_r_ms"]
        s["quantiles"] = quantile_grid(vals)
        s["median_ci"] = stats.bootstrap_ci(vals, np.median, B=boot_B, seed=seed)
        s["p95_ci"] = stats.bootstrap_ci(
            vals, lambda z: stats.pct(z, 95), B=boot_B, seed=seed, n_min=40
        )
        out["groups"][rep] = s
    total_excluded = 0
    for ds in reg["datasets"]:
        v = policy.load_series(reg, ds["id"], repo_root)
        d = stats.summary(v["values"])
        d["n_excluded"] = v["n_excluded"]
        total_excluded += v["n_excluded"]
        out["datasets"][ds["id"]] = d
    out["total_excluded"] = total_excluded
    return out


def measured_release_errors(reg, repo_root):
    """eps=(eps_R-eps_A) per defended stratum with a numeric (D_A,D_R), D_R>0."""
    est = {}
    for ds in reg["datasets"]:
        da, dr = ds["d_a_ms"], ds["d_r_ms"]
        if not (isinstance(da, (int, float)) and isinstance(dr, (int, float))) or dr <= 0:
            continue
        if ds["measures"] != "defended_clrt_out":
            continue
        v = policy.load_series(reg, ds["id"], repo_root)["values"]
        eps = policy.measured_release_error(v, float(dr))
        if eps is not None:
            est.setdefault((float(da), float(dr)), []).append((ds["id"], eps, len(v)))
    return est


def build_eps_lookup(est):
    """Map (D_A,D_R) -> (eps_ms, source, dataset_ids). Pooled median for the estimate.

    NOTE: this DIFFERENTIAL eps enters ONLY the observer-visible CLRT_out prediction;
    it is never added to the absolute L_master (FIX 1)."""
    all_eps = [e for lst in est.values() for (_, e, _) in lst]
    pooled = float(np.median(all_eps)) if all_eps else 0.0
    lookup = {}
    for key, lst in est.items():
        w = np.array([n for (_, _, n) in lst], dtype=float)
        e = np.array([e for (_, e, _) in lst], dtype=float)
        ids = [i for i, _, _ in lst]
        # AUDIT CORRECTION 6: 'measured' only for the exact measured (D_A,D_R) pair.
        lookup[key] = (float((e * w).sum() / w.sum()), "measured:" + ",".join(ids), ids)
    return lookup, pooled


def build_observed_lm(reg, repo_root, grid, roles, fallback_roles):
    """Map (D_A,D_R) -> directly observed L_master (read_to_resp_ms) for a stratum."""
    out = {}
    for da, dr in grid:
        v, _ids = policy.observed_l_master(
            reg, repo_root, float(da), float(dr),
            roles=roles, fallback_roles=fallback_roles,
        )
        if v is not None and v.size:
            out[(float(da), float(dr))] = v
    return out


def evaluate_grid(C_design, grid, eps_lookup, pooled_eps, obs_lm_design, tol_ms,
                  a_design, constraints):
    evals = []
    for da, dr in grid:
        entry = eps_lookup.get((float(da), float(dr)))
        if entry is not None:
            eps, src, ids = entry
            measured = True
        else:
            # AUDIT CORRECTION 6: borrowed value is an ESTIMATE, labelled as such.
            eps, src, ids = pooled_eps, "estimate:pooled_median_of_measured_band_eps", []
            measured = False
        obs = obs_lm_design.get((float(da), float(dr)))     # FIX 1: direct L_master
        ev = policy.eval_policy(
            C_design, da, dr, a=a_design, tol_ms=tol_ms, eps_ms=eps,
            eps_source=src, observed_l_master=obs,
            hardware_measured=measured, measured_datasets=ids,
            **constraints,
        )
        evals.append(ev)
    return evals


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    here = Path(__file__).resolve().parent
    ap.add_argument("--registry", default=str(here / "registry.yaml"))
    ap.add_argument("--out-json", default=str(here / "results.json"))
    ap.add_argument("--out-md", default=str(here / "REPORT.md"))
    ap.add_argument("--coverage-min", type=float, default=0.99)
    ap.add_argument("--coverage-confidence-alpha", type=float, default=0.05,
                    help="alpha for the Wilson-bound confidence qualification")
    ap.add_argument("--tol-quantile", type=float, default=95.0,
                    help="quantile of |eps_R-eps_A| used as symmetric target-band tol")
    ap.add_argument("--tol-ms", default="auto",
                    help="target-band tolerance; 'auto' = tol-quantile of |eps_R-eps_A|")
    ap.add_argument("--fail-open-margin-ms", type=float, default=5.0,
                    help="INERT: fail-open horizon is UNKNOWN (not t_A-anchored)")
    ap.add_argument("--bootstrap", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=20260807)
    ap.add_argument("--no-verify-sha", action="store_true")
    args = ap.parse_args()

    repo_root = repo.find_repo_root(Path(args.registry).resolve().parent)
    reg = registry.load_registry(Path(args.registry))
    warnings = registry.validate(reg, repo_root, verify_sha=not args.no_verify_sha)
    unpinned = registry.collect_unpinned(reg)
    log.info("registry validated: %d datasets, %d warnings, %d UNPINNED fields",
             len(reg["datasets"]), len(warnings), len(unpinned))

    # Parse evidenced constraints; UNKNOWN strings resolve to None (not a bound).
    ec = reg["evidenced_constraints"]
    nc = registry.numeric_constraint
    constraints = dict(
        # DNP3 application response timeout: UNKNOWN in the evidence path (FIX 4).
        response_timeout_ms=nc(ec.get("dnp3_response_timeout_ms")),         # UNKNOWN
        # Evidenced master socket recv timeout that DID govern the campaign (FIX 4).
        master_recv_timeout_ms=nc(ec.get("master_socket_recv_timeout_ms")),
        poll_period_ms=nc(ec.get("poll_period_ms")),
        tcp_rto_ms=nc(ec.get("tcp_rto_ms")),                       # UNKNOWN
        # fail-open horizon is UNKNOWN: NOT established as t_A-anchored in raw.
        fail_open_horizon_ms=nc(ec.get("fail_open_horizon_ms_at_budget_18000")),
        reservoir_horizon_ms=nc(ec.get("reservoir_horizon_ms")),   # R11 OPEN
    )

    def _eff(key, unknown="UNKNOWN"):
        return constraints[key] if constraints[key] is not None else unknown

    constraints_effective = {
        "dnp3_response_timeout_ms": _eff(
            "response_timeout_ms",
            "UNKNOWN (no OpenDNP3 master in evidence path; raw-socket driver, no DNP3 app timeout)"),
        "master_socket_recv_timeout_ms": _eff("master_recv_timeout_ms"),
        "poll_period_ms": _eff("poll_period_ms"),
        "tcp_rto_ms": _eff("tcp_rto_ms"),
        "fail_open_horizon_ms": _eff(
            "fail_open_horizon_ms", "UNKNOWN (not t_A-anchored in committed raw)"),
        "reservoir_horizon_ms": _eff("reservoir_horizon_ms", "UNKNOWN (R11 OPEN)"),
    }

    st = stratum_stats(reg, repo_root, args.bootstrap, args.seed)

    # Native design pool paired (a, C); validation pool likewise.
    design_members = registry.pool_groups(reg)["nat_off_frA"]
    a_design, C_design = policy.pool_native_pairs(reg, design_members, repo_root)
    valid_members = registry.pool_groups(reg)["nat_off_fixA"]
    a_valid, C_valid = policy.pool_native_pairs(reg, valid_members, repo_root)
    a_available = a_design is not None

    # Target-band tolerance from actual covered-transaction |eps_R-eps_A|, now PAIRED
    # with native P(C<=H) and reported UNTRUNCATED alongside the conditional value.
    tol_ms, tol_meta = policy.target_band_tolerance(
        reg, repo_root, quantile=args.tol_quantile, native_C=C_design)
    if args.tol_ms != "auto":
        tol_ms = float(args.tol_ms)
        tol_meta = {"tol_ms": tol_ms, "definition": "user override", "quantile": None,
                    "is_total_coverage": False, "conditional": True, "per_dataset": {}}

    est = measured_release_errors(reg, repo_root)
    eps_lookup, pooled_eps = build_eps_lookup(est)

    # FIX 1: directly observed L_master per measured policy (design + validation strata).
    obs_lm_design = build_observed_lm(reg, repo_root, CANDIDATE_GRID,
                                      roles=("paper_accepted",),
                                      fallback_roles=("policy_probe",))
    obs_lm_validation = build_observed_lm(reg, repo_root, CANDIDATE_GRID,
                                          roles=("validation",),
                                          fallback_roles=())

    evals = evaluate_grid(C_design, CANDIDATE_GRID, eps_lookup, pooled_eps,
                          obs_lm_design, tol_ms, a_design, constraints)
    for ev in evals:
        da, dr, H = ev["D_A_ms"], ev["D_R_ms"], ev["H_ms"]
        ev["native_tail_coverage_validation_pool"] = float((C_valid <= H).mean())
        kv = int((C_valid <= H).sum())
        ev["native_tail_coverage_validation_ci"] = stats.wilson_ci(kv, C_valid.size)
        obs_v = obs_lm_validation.get((float(da), float(dr)))
        if obs_v is not None and obs_v.size:
            ev["L_master_max_validation_ms"] = float(obs_v.max())
            ev["L_master_validation_source"] = "measured_direct:read_to_resp_ms (validation defended)"
        elif a_valid is not None:
            Lmv = a_valid + np.maximum(C_valid, H)          # modelled floor, NO eps
            ev["L_master_max_validation_ms"] = float(Lmv.max())
            ev["L_master_validation_source"] = "modeled_floor:a+max(C,H) (validation native); eps_R UNKNOWN"
        else:
            ev["L_master_max_validation_ms"] = "UNKNOWN"
            ev["L_master_validation_source"] = "UNKNOWN"
    pareto = [policy.pareto_row(ev) for ev in evals]

    sel = policy.select_common_policy(
        C_design, evals, coverage_min=args.coverage_min,
        require_fail_open_margin_ms=args.fail_open_margin_ms,
        coverage_confidence_alpha=args.coverage_confidence_alpha,
    )
    tested_410 = next(e for e in evals if (e["D_A_ms"], e["D_R_ms"]) == (4, 10))

    results = {
        "meta": {
            "registry": str(Path(args.registry).name),
            "protection_domain": reg["protection_domain"],
            "n_datasets": len(reg["datasets"]),
            "percentile_convention": stats.PCT_METHOD,
            "entropy_bin_width_ms": stats.BIN_WIDTH_MS,
            "a_read_to_ack_available": a_available,
            "a_read_to_ack_source": ("read_to_ack_ms per row (t_ack-t_read); present in every native row"
                                     if a_available else "UNKNOWN"),
            "latency_model": (
                "L_master(measured) = directly observed read_to_resp_ms (t_resp-t_read); "
                "L_master(analysis-only) = a + max(C,H) MODELLED FLOOR, absolute release "
                "error eps_R UNKNOWN. CLRT_out = max(C-D_A,D_R) + (eps_R-eps_A) differential."),
            "L_master_fix": ("FIX 1: differential eps is NEVER added to L_master; measured "
                             "policies use the direct observation, analysis-only a floor."),
            "target_band_tol_ms": tol_ms,
            "target_band_tol_meta": tol_meta,
            "coverage_min": args.coverage_min,
            "coverage_confidence_alpha": args.coverage_confidence_alpha,
            "bootstrap_B": args.bootstrap,
            "seed": args.seed,
            "verify_sha": not args.no_verify_sha,
            "native_rows_excluded_total": st["total_excluded"],
        },
        "evidenced_constraints": ec,
        "evidenced_constraints_effective": constraints_effective,
        "validation_warnings": warnings,
        "unpinned_fields": unpinned,
        "hardware_measured_pairs": {
            f"D_A={k[0]:g},D_R={k[1]:g}": v[2] for k, v in eps_lookup.items()
        },
        "observed_l_master_pairs": {
            f"D_A={k[0]:g},D_R={k[1]:g}": {
                "n": int(v.size), "median_ms": float(np.median(v)),
                "p95_ms": stats.pct(v, 95), "max_ms": float(v.max()),
                "source": "measured_direct:read_to_resp_ms",
            } for k, v in sorted(obs_lm_design.items())
        },
        "native_design_pool": {
            "members": design_members, "n": int(C_design.size),
            "summary": stats.summary(C_design),
            "a_summary": stats.summary(a_design) if a_available else "UNKNOWN",
            "ecdf_sorted_ms": sorted(round(float(x), 6) for x in C_design),
        },
        "native_validation_pool": {
            "members": valid_members, "n": int(C_valid.size),
            "summary": stats.summary(C_valid),
            "a_summary": stats.summary(a_valid) if a_valid is not None else "UNKNOWN",
        },
        "stratum_stats": st,
        "release_error_estimates": {
            f"D_A={k[0]:g},D_R={k[1]:g}": {"eps_ms": v[0], "source": v[1], "datasets": v[2]}
            for k, v in eps_lookup.items()
        },
        "release_error_pooled_median_ms": pooled_eps,
        "release_error_note": ("DIFFERENTIAL (eps_R-eps_A); used ONLY in the observer-visible "
                               "CLRT_out. NEVER added to the absolute L_master (FIX 1)."),
        "policy_evaluations": evals,
        "pareto_table": pareto,
        "selector": {
            "coverage_min": args.coverage_min,
            "coverage_confidence_alpha": sel["coverage_confidence_alpha"],
            "coverage_confidence_pct": sel["coverage_confidence_pct"],
            "fail_open_margin_ms_flag": args.fail_open_margin_ms,
            "fail_open_gate_active": False,
            "objective": sel["objective"],
            "n_admissible_point_estimate": sel["n_admissible"],
            "n_confidence_qualified": sel["n_confidence_qualified"],
            "max_wilson_lower_over_admissible": sel["max_wilson_lower_over_admissible"],
            "coverage_verdict": sel["coverage_verdict"],
            "analysis_candidate_point_estimate": _slim(sel["selected"]),
            "analysis_candidate_is_hardware_measured": sel["selected_is_hardware_measured"],
            "analysis_candidate_confidence_qualified": sel["selected_confidence_qualified"],
            "confidence_qualified_selected": _slim(sel["confidence_qualified_selected"]),
            "co_optimal_at_min_H": [_slim(e) for e in sel["co_optimal_at_min_H"]],
            "measured_co_optimal_at_min_H": [_slim(e) for e in sel["measured_co_optimal_at_min_H"]],
            "ranked_admissible": [_slim(e) for e in sel["ranked_admissible"]],
            "note": sel["note"],
        },
        "tested_policy_4_10": _slim(tested_410),
    }

    Path(args.out_json).write_text(json.dumps(results, indent=2, default=_json_default))
    Path(args.out_md).write_text(render_markdown(results))
    log.info("wrote %s and %s", Path(args.out_json).name, Path(args.out_md).name)
    _print_console(results)
    return 0


def _json_default(o):
    if isinstance(o, (np.floating,)):
        return float(o)
    if isinstance(o, (np.integer,)):
        return int(o)
    if isinstance(o, np.ndarray):
        return o.tolist()
    return float(o)


def _slim(ev):
    if ev is None:
        return None
    keep = ("D_A_ms", "D_R_ms", "H_ms", "policy_status", "hardware_measured",
            "measured_datasets", "native_tail_coverage", "native_tail_coverage_ci",
            "native_tail_coverage_validation_pool", "native_tail_coverage_validation_ci",
            "visible_clrt_target_ms", "target_band_coverage", "ack_delay_ms",
            "a_read_to_ack_max_ms", "added_resp_latency_max_ms",
            "L_master_median_ms", "L_master_p95_ms", "L_master_max_ms",
            "L_master_max_validation_ms", "L_master_is_floor", "L_master_source",
            "L_master_release_error_ms", "release_error_eps_ms", "release_error_source",
            "residual_tail_fraction", "residual_entropy_bits", "residual_effective_states",
            "margin_response_timeout_ms", "margin_master_recv_timeout_ms",
            "margin_poll_period_ms", "margin_ack_delay_vs_rto_ms", "margin_fail_open_ms",
            "margin_reservoir_ms")
    return {k: ev[k] for k in keep if k in ev}


def _print_console(r):
    m = r["meta"]
    print("\n=== INPUTS ===")
    print(f"  a (request->ACK) available: {m['a_read_to_ack_available']}")
    print(f"  latency model: {m['latency_model']}")
    print(f"  target-band tol (CONDITIONAL, not coverage): {m['target_band_tol_ms']:.4f} ms")
    s = r["native_design_pool"]["summary"]
    asum = r["native_design_pool"]["a_summary"]
    print("=== NATIVE DESIGN POOL (paper) ===")
    print(f"  C: n={s['n']} median={s['median']:.3f} p95={s['p95']:.3f} "
          f"p99={s['p99']:.3f} max={s['max']:.3f} ms")
    if isinstance(asum, dict):
        print(f"  a: median={asum['median']:.3f} p95={asum['p95']:.3f} max={asum['max']:.3f} ms")
    print("=== PARETO (all candidates) ===")
    hdr = ("policy", "status", "H", "cov", "wilson95", "Lmax", "Lkind", "recvTOm", "POmar")
    print("  " + " ".join(f"{h:>10}" for h in hdr))
    for ev in r["policy_evaluations"]:
        ci = ev["native_tail_coverage_ci"]
        stt = "meas" if ev["hardware_measured"] else "anal"
        lk = "floor" if ev["L_master_is_floor"] else ("meas" if ev["hardware_measured"] else "n/a")
        print("  " + " ".join(f"{v:>10}" for v in (
            f"{ev['D_A_ms']:g},{ev['D_R_ms']:g}", stt, f"{ev['H_ms']:g}",
            f"{ev['native_tail_coverage']:.3f}",
            f"{ci['ci_lo']:.3f}-{ci['ci_hi']:.3f}",
            policy._fmt(ev["L_master_max_ms"], 2), lk,
            policy._fmt(ev["margin_master_recv_timeout_ms"], 0),
            policy._fmt(ev["margin_poll_period_ms"], 0))))
    selm = r["selector"]
    print("=== COVERAGE VERDICT (confidence-aware) ===")
    print("  " + selm["coverage_verdict"])
    ac = selm["analysis_candidate_point_estimate"]
    print("=== ANALYSIS CANDIDATE (point-estimate rule; NOT confidence-qualified) ===")
    if ac:
        co = ", ".join(f"({e['D_A_ms']:g},{e['D_R_ms']:g})[{'M' if e['hardware_measured'] else 'A'}]"
                       for e in selm["co_optimal_at_min_H"])
        print(f"  D_A={ac['D_A_ms']:g} D_R={ac['D_R_ms']:g} H={ac['H_ms']:g} "
              f"[{ac['policy_status']}] cov={ac['native_tail_coverage']:.4f} "
              f"wilson95=[{ac['native_tail_coverage_ci']['ci_lo']:.4f},"
              f"{ac['native_tail_coverage_ci']['ci_hi']:.4f}] "
              f"conf_qualified={selm['analysis_candidate_confidence_qualified']}")
        print(f"  L_master ({'floor' if ac['L_master_is_floor'] else 'measured-direct'}): "
              f"median={policy._fmt(ac['L_master_median_ms'],2)} "
              f"p95={policy._fmt(ac['L_master_p95_ms'],2)} "
              f"max={policy._fmt(ac['L_master_max_ms'],2)} ms")
        print(f"  co-optimal at H={ac['H_ms']:g} [M=measured, A=analysis]: {co}")
    cqs = selm["confidence_qualified_selected"]
    if cqs is None:
        print(f"  confidence-qualified selection: NONE "
              f"({selm['n_confidence_qualified']} qualify)")
    else:
        print(f"  confidence-qualified selection: ({cqs['D_A_ms']:g},{cqs['D_R_ms']:g})")


def render_markdown(r) -> str:
    m = r["meta"]
    s = r["native_design_pool"]["summary"]
    asum = r["native_design_pool"]["a_summary"]
    tm = m["target_band_tol_meta"]
    q = tm.get("quantile")
    qk = 95 if q is None else q
    ck = f"abs_err_p{qk:g}_ms_conditional"
    uk = f"abs_err_p{qk:g}_ms_untruncated"
    upk = f"abs_err_p{qk:g}_ms_untruncated_pooled"
    L = []
    L.append("# Defense-4 timing-policy characterization\n")
    L.append("Reports one common-domain policy **analysis candidate** under a declared "
             "**point-estimate** coverage rule. It is **NOT** confidence-qualified merely "
             "by clearing the point estimate, **NOT** claimed optimal, and **NOT** "
             "hardware-selected. Software/analysis only over committed raw evidence. Every "
             "candidate is labelled DEMONSTRATED (hardware-measured) vs ANALYSIS-ONLY, and "
             "every unavailable constraint is left UNKNOWN.\n")
    L.append(f"- Protection domain: {m['protection_domain']}")
    L.append(f"- Latency model (FIX 1): `{m['latency_model']}`")
    L.append(f"- `a` = t_A - t_Q (request->ACK): **{'AVAILABLE' if m['a_read_to_ack_available'] else 'UNKNOWN'}** "
             f"({m['a_read_to_ack_source']})")
    L.append(f"- Percentile convention: `{m['percentile_convention']}`; entropy bin "
             f"width: {m['entropy_bin_width_ms']} ms")
    L.append(f"- Target-band tol: {m['target_band_tol_ms']:.4f} ms "
             f"(**CONDITIONAL jitter, NOT total coverage**; {tm.get('definition','')})")
    L.append(f"- Bootstrap B={m['bootstrap_B']}, seed={m['seed']}, sha256 verify={m['verify_sha']}; "
             f"native rows excluded {m['native_rows_excluded_total']} "
             "(clean block-end FIN / reset / inconclusive), validated on EVERY row\n")

    L.append("## Master-visible latency L_master (FIX 1)")
    L.append("- Measured policies use the **directly observed** per-row request->response "
             "latency `read_to_resp_ms = t_resp - t_read` (provenance-checked against the raw "
             "timestamps on every row).")
    L.append("- Analysis-only policies use the **modelled floor** `a + max(C, H)`; the absolute "
             "response release error eps_R is **UNKNOWN**. The differential eps = (eps_R - eps_A) "
             "is kept ONLY in the observer-visible CLRT_out and is **never** added to L_master.")
    if r["observed_l_master_pairs"]:
        L.append("- Directly observed L_master (measured policies):")
        for k, v in r["observed_l_master_pairs"].items():
            L.append(f"  - {k}: n={v['n']}, median {v['median_ms']:.3f}, p95 {v['p95_ms']:.3f}, "
                     f"max {v['max_ms']:.3f} ms")
    L.append("")

    L.append("## Constraints: evidenced vs UNKNOWN (FIX 4 provenance)")
    for k, v in r["evidenced_constraints_effective"].items():
        L.append(f"- `{k}`: {v}")
    L.append("- The timing evidence was produced by the **raw-socket** driver "
             "`defense4/timing/control/deploy/campaign_driver.py` (hand-crafted DNP3 READ over "
             "`socket.SOCK_STREAM`). Its **socket recv timeout of 4000 ms** (line 80) is the "
             "evidenced response-wait ceiling; the **DNP3 application response timeout is "
             "UNKNOWN** (no OpenDNP3 master in this path; 2000 ms is neither a DNP3 protocol "
             "constant nor the OpenDNP3 3.1.2 default).")
    L.append("- ACK-delay risk is governed by **D_A** (not H); response-wait and poll-period "
             "margins compare against **a + max(C, H)** / the directly observed L_master (not H).")
    L.append("- Fail-open horizon: a 30.8 ms figure was asserted at budget 18000, but it "
             "is **NOT anchored to t_A in the committed raw** (the failopen blocks show normal "
             "~10 ms normalization at budget 18000). It is UNKNOWN and gates nothing.\n")

    L.append("## Native design distribution (C = t_R - t_A), paper pool [DEMONSTRATED]")
    L.append(f"- members: {', '.join(r['native_design_pool']['members'])} (n={s['n']})")
    L.append(f"- C: median {s['median']:.3f}, p95 {s['p95']:.3f}, p99 {s['p99']:.3f}, "
             f"max {s['max']:.3f} ms; p5-p95 spread {s['p5_p95_spread_ms']:.3f} ms; "
             f"entropy {s['entropy_bits']:.2f} bits ({s['effective_states']:.1f} states)")
    if isinstance(asum, dict):
        L.append(f"- a (request->ACK): median {asum['median']:.3f}, p95 {asum['p95']:.3f}, "
                 f"max {asum['max']:.3f} ms")
    vp = r["native_validation_pool"]["summary"]
    L.append(f"- validation pool (fixA+fixB, n={vp['n']}): C median {vp['median']:.3f}, "
             f"p95 {vp['p95']:.3f}, max {vp['max']:.3f} ms (heavier tail; see threats)\n")

    L.append("## Release error (eps_R - eps_A) [DIFFERENTIAL, observer-visible only]")
    L.append("- `measured` values are from the exact hardware-measured (D_A,D_R) pair; any "
             "other policy uses the pooled-median ESTIMATE, labelled `estimate:*`. Used ONLY in "
             "the observer-visible CLRT_out; **never** added to the absolute L_master (FIX 1).")
    for k, v in r["release_error_estimates"].items():
        L.append(f"- {k}: eps={v['eps_ms']:.4f} ms  [{v['source']}]")
    L.append(f"- pooled-median estimate (unmeasured policies) = "
             f"{r['release_error_pooled_median_ms']:.4f} ms\n")

    L.append("## Target-band jitter (FIX 2): conditional vs untruncated, paired with native P(C<=H)")
    L.append(f"- pooled CONDITIONAL |CLRT_out - D_R| p{qk:g}: "
             f"{policy._fmt(tm.get('tol_ms'),4)} ms over {tm.get('n_covered_transactions','?')} "
             "in-band transactions (this is the band half-width; NOT coverage).")
    if upk in tm:
        L.append(f"- pooled UNTRUNCATED |CLRT_out - D_R| p{qk:g}: "
                 f"{policy._fmt(tm[upk],4)} ms over {tm.get('n_all_transactions','?')} "
                 f"transactions (dropped-tail fraction "
                 f"{policy._fmt(tm.get('frac_outside_normalized_band_pooled'),4)}).")
    for dsid, pv in tm.get("per_dataset", {}).items():
        ncv = pv.get("native_covered_fraction")
        ncov = f"{ncv:.4f}" if isinstance(ncv, (int, float)) else "n/a"
        L.append(f"  - {dsid} (D_A={pv['D_A_ms']:g},D_R={pv['D_R_ms']:g}): "
                 f"cond p{qk:g}={policy._fmt(pv.get(ck),4)} ms, "
                 f"untrunc p{qk:g}={policy._fmt(pv.get(uk),4)} ms, "
                 f"out-of-band {policy._fmt(pv.get('frac_outside_normalized_band'),4)}, "
                 f"paired native P(C<=H)={ncov}")
    L.append("")

    L.append("## Pareto table (DEMONSTRATED = hardware-measured; ANALYSIS = hardware-unmeasured)")
    cols = ["policy", "status", "H_ms", "native_tail_coverage", "coverage_wilson95",
            "visible_clrt_target_ms", "target_band_coverage", "ack_delay_ms",
            "L_master_max_ms", "L_master_kind", "margin_master_recv_timeout_ms",
            "margin_poll_period_ms", "margin_fail_open_ms"]
    L.append("| " + " | ".join(cols) + " |")
    L.append("|" + "|".join(["---"] * len(cols)) + "|")
    for row in r["pareto_table"]:
        L.append("| " + " | ".join(str(row[c]) for c in cols) + " |")
    L.append("")

    L.append("## Coverage verdict and analysis candidate (FIX 3: confidence-aware)")
    selm = r["selector"]
    ac = selm["analysis_candidate_point_estimate"]
    L.append(f"- objective: {selm['objective']}")
    L.append(f"- point-estimate admissible: {selm['n_admissible_point_estimate']}; "
             f"confidence-qualified (Wilson lower >= {selm['coverage_min']} at "
             f"{selm['coverage_confidence_pct']:.0f}%): {selm['n_confidence_qualified']}; "
             f"max Wilson lower over admissible = "
             f"{policy._fmt(selm['max_wilson_lower_over_admissible'],4)}")
    L.append(f"- **coverage verdict**: {selm['coverage_verdict']}")
    if selm["confidence_qualified_selected"] is None:
        L.append("- confidence-qualified selection: **NONE** — no candidate establishes the "
                 "threshold at confidence; more samples or a larger H are required.")
    else:
        cqs = selm["confidence_qualified_selected"]
        L.append(f"- confidence-qualified selection: D_A={cqs['D_A_ms']:g}, D_R={cqs['D_R_ms']:g} "
                 f"(H={cqs['H_ms']:g}), Wilson lower {cqs['native_tail_coverage_ci']['ci_lo']:.4f}")
    if ac:
        ci = ac["native_tail_coverage_ci"]
        co = ", ".join(f"({e['D_A_ms']:g},{e['D_R_ms']:g}) [{'DEMONSTRATED' if e['hardware_measured'] else 'ANALYSIS'}]"
                       for e in selm["co_optimal_at_min_H"])
        L.append(f"- **analysis candidate under the point-estimate coverage >= {selm['coverage_min']} "
                 f"rule**: D_A={ac['D_A_ms']:g} ms, D_R={ac['D_R_ms']:g} ms (H={ac['H_ms']:g} ms) "
                 f"— **{ac['policy_status'].upper()}**, confidence-qualified="
                 f"{selm['analysis_candidate_confidence_qualified']}")
        L.append(f"  - native coverage {ac['native_tail_coverage']:.4f} "
                 f"(Wilson95 [{ci['ci_lo']:.4f},{ci['ci_hi']:.4f}]; validation pool "
                 f"{ac['native_tail_coverage_validation_pool']:.4f}) — the Wilson lower bound is "
                 f"the promotion gate, not the point estimate")
        lk = "modelled floor" if ac["L_master_is_floor"] else "measured-direct"
        L.append(f"  - L_master ({lk}): median "
                 f"{policy._fmt(ac['L_master_median_ms'],3)} ms, p95 "
                 f"{policy._fmt(ac['L_master_p95_ms'],3)} ms, max "
                 f"{policy._fmt(ac['L_master_max_ms'],3)} ms (validation-pool max "
                 f"{policy._fmt(ac['L_master_max_validation_ms'],3)} ms); "
                 f"release error: {ac['L_master_release_error_ms']}")
        L.append(f"  - visible target {ac['visible_clrt_target_ms']:g} ms, ACK delay "
                 f"{ac['ack_delay_ms']:g} ms, differential eps {ac['release_error_eps_ms']:.4f} ms "
                 f"[{ac['release_error_source']}] (CLRT_out only)")
        L.append(f"  - master-recv-timeout margin {policy._fmt(ac['margin_master_recv_timeout_ms'],1)} ms "
                 f"(DNP3 app-timeout margin {ac['margin_response_timeout_ms']}), "
                 f"poll-period margin {policy._fmt(ac['margin_poll_period_ms'],1)} ms, "
                 f"ACK-vs-RTO margin {ac['margin_ack_delay_vs_rto_ms']}, "
                 f"fail-open margin {ac['margin_fail_open_ms']}")
        L.append(f"- co-optimal at H={ac['H_ms']:g} ms (equal coverage and horizon): {co}.")
        mc = selm["measured_co_optimal_at_min_H"]
        if mc:
            names = ", ".join(f"({e['D_A_ms']:g},{e['D_R_ms']:g})" for e in mc)
            L.append(f"  - **The point-estimate candidate {ac['D_A_ms']:g},{ac['D_R_ms']:g} is "
                     f"HARDWARE-UNMEASURED.** Hardware-measured co-optimal alternative(s) at the "
                     f"same H exist: {names}. These are DEMONSTRATED and should be preferred if a "
                     "hardware-attested policy is required; the min-D_A tie-break alone picks the "
                     "unmeasured point.")
    t = r["tested_policy_4_10"]
    lk4 = "measured-direct" if not t["L_master_is_floor"] else "floor"
    L.append(f"- (4,10) D4 [DEMONSTRATED, evaluated, not auto-selected]: H={t['H_ms']:g} ms, "
             f"coverage {t['native_tail_coverage']:.4f}, L_master max "
             f"{policy._fmt(t['L_master_max_ms'],3)} ms ({lk4}), "
             f"differential eps {t['release_error_eps_ms']:.4f} ms [{t['release_error_source']}], "
             f"residual tail {t['residual_tail_fraction']:.4f}\n")

    L.append("## UNKNOWN (not invented)")
    L.append("- `a` (request->ACK): AVAILABLE — this is NOT unknown; loaded per row.")
    L.append("- DNP3 application response timeout: UNKNOWN (raw-socket driver produced the "
             "evidence; the evidenced ceiling is the 4000 ms socket recv timeout instead).")
    L.append("- Absolute response release error eps_R (for analysis-only L_master): UNKNOWN "
             "(only the differential eps_R-eps_A is measurable, and it is not an absolute term).")
    L.append("- TCP RTO: UNKNOWN (not in committed raw; 0 retransmits observed). ACK-vs-RTO "
             "margin is therefore UNKNOWN and would compare against D_A, not H.")
    L.append("- Fail-open horizon: UNKNOWN (not t_A-anchored in committed raw).")
    L.append("- Reservoir horizon (R11): UNKNOWN (carried OPEN in the evidence freeze).")
    L.append(f"- UNPINNED registry fields: {len(r['unpinned_fields'])} "
             f"(all `firmware`: relay firmware/config revision not in raw evidence).\n")
    return "\n".join(L)


if __name__ == "__main__":
    raise SystemExit(main())

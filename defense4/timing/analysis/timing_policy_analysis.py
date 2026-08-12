#!/usr/bin/env python
"""Timing-policy characterization CLI for the DNP3 Defense-4 timing engine.

Loads the baseline registry, validates it against the committed raw evidence
(paths, sha256, per-transaction schema, units, timing definitions on EVERY row),
computes per-stratum distributions with bootstrap/Wilson CIs, evaluates candidate
(D_A, D_R) deadline policies against the evidenced native CLRT distribution using
the master-visible latency L_master = a + max(C, H) + eps_R, emits a Pareto table,
and provisionally selects ONE common policy for the whole protection domain under
declared constraints. Software/analysis only; no hardware.

Every candidate is labelled hardware-measured vs analysis-selected/hardware-
unmeasured. Unavailable constraints (TCP RTO, reservoir horizon, and the fail-open
horizon which is NOT established as t_A-anchored) are left UNKNOWN, never invented.

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
    """Map (D_A,D_R) -> (eps_ms, source, dataset_ids). Pooled median for the estimate."""
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


def evaluate_grid(a_design, C_design, grid, eps_lookup, pooled_eps, tol_ms, constraints):
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
        ev = policy.eval_policy(
            C_design, da, dr, a=a_design, tol_ms=tol_ms, eps_ms=eps,
            eps_source=src, hardware_measured=measured, measured_datasets=ids,
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
        response_timeout_ms=nc(ec.get("dnp3_response_timeout_ms")),
        poll_period_ms=nc(ec.get("poll_period_ms")),
        tcp_rto_ms=nc(ec.get("tcp_rto_ms")),                       # UNKNOWN
        # fail-open horizon is UNKNOWN: NOT established as t_A-anchored in raw.
        fail_open_horizon_ms=nc(ec.get("fail_open_horizon_ms_at_budget_18000")),
        reservoir_horizon_ms=nc(ec.get("reservoir_horizon_ms")),   # R11 OPEN
    )
    constraints_effective = {
        "response_timeout_ms": constraints["response_timeout_ms"] if constraints["response_timeout_ms"] is not None else "UNKNOWN",
        "poll_period_ms": constraints["poll_period_ms"] if constraints["poll_period_ms"] is not None else "UNKNOWN",
        "tcp_rto_ms": constraints["tcp_rto_ms"] if constraints["tcp_rto_ms"] is not None else "UNKNOWN",
        "fail_open_horizon_ms": constraints["fail_open_horizon_ms"] if constraints["fail_open_horizon_ms"] is not None else "UNKNOWN (not t_A-anchored in committed raw)",
        "reservoir_horizon_ms": constraints["reservoir_horizon_ms"] if constraints["reservoir_horizon_ms"] is not None else "UNKNOWN (R11 OPEN)",
    }

    st = stratum_stats(reg, repo_root, args.bootstrap, args.seed)

    # Target-band tolerance from actual covered-transaction |eps_R-eps_A|.
    tol_ms, tol_meta = policy.target_band_tolerance(reg, repo_root, quantile=args.tol_quantile)
    if args.tol_ms != "auto":
        tol_ms = float(args.tol_ms)
        tol_meta = {"tol_ms": tol_ms, "definition": "user override", "quantile": None}

    # Native design pool paired (a, C); validation pool likewise.
    design_members = registry.pool_groups(reg)["nat_off_frA"]
    a_design, C_design = policy.pool_native_pairs(reg, design_members, repo_root)
    valid_members = registry.pool_groups(reg)["nat_off_fixA"]
    a_valid, C_valid = policy.pool_native_pairs(reg, valid_members, repo_root)
    a_available = a_design is not None

    est = measured_release_errors(reg, repo_root)
    eps_lookup, pooled_eps = build_eps_lookup(est)

    evals = evaluate_grid(a_design, C_design, CANDIDATE_GRID, eps_lookup, pooled_eps,
                          tol_ms, constraints)
    for ev in evals:
        H = ev["H_ms"]
        ev["native_tail_coverage_validation_pool"] = float((C_valid <= H).mean())
        kv = int((C_valid <= H).sum())
        ev["native_tail_coverage_validation_ci"] = stats.wilson_ci(kv, C_valid.size)
        if a_valid is not None:
            Lmv = a_valid + np.maximum(C_valid, H) + ev["release_error_eps_ms"]
            ev["L_master_max_validation_ms"] = float(Lmv.max())
        else:
            ev["L_master_max_validation_ms"] = "UNKNOWN"
    pareto = [policy.pareto_row(ev) for ev in evals]

    sel = policy.select_common_policy(
        C_design, evals, coverage_min=args.coverage_min,
        require_fail_open_margin_ms=args.fail_open_margin_ms,
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
            "latency_model": "L_master = a + max(C, H) + eps_R  (NOT bounded by H when C>H)",
            "target_band_tol_ms": tol_ms,
            "target_band_tol_meta": tol_meta,
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
        "policy_evaluations": evals,
        "pareto_table": pareto,
        "selector": {
            "coverage_min": args.coverage_min,
            "fail_open_margin_ms_flag": args.fail_open_margin_ms,
            "fail_open_gate_active": False,
            "objective": sel["objective"],
            "n_admissible": sel["n_admissible"],
            "selected": _slim(sel["selected"]),
            "selected_is_hardware_measured": sel["selected_is_hardware_measured"],
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
            "L_master_max_validation_ms", "release_error_eps_ms", "release_error_source",
            "residual_tail_fraction", "residual_entropy_bits", "residual_effective_states",
            "margin_response_timeout_ms", "margin_poll_period_ms",
            "margin_ack_delay_vs_rto_ms", "margin_fail_open_ms", "margin_reservoir_ms")
    return {k: ev[k] for k in keep if k in ev}


def _print_console(r):
    m = r["meta"]
    print("\n=== INPUTS ===")
    print(f"  a (request->ACK) available: {m['a_read_to_ack_available']}  |  "
          f"latency model: {m['latency_model']}")
    print(f"  target-band tol: {m['target_band_tol_ms']:.4f} ms "
          f"({r['meta']['target_band_tol_meta'].get('definition','')})")
    s = r["native_design_pool"]["summary"]
    asum = r["native_design_pool"]["a_summary"]
    print("=== NATIVE DESIGN POOL (paper) ===")
    print(f"  C: n={s['n']} median={s['median']:.3f} p95={s['p95']:.3f} "
          f"p99={s['p99']:.3f} max={s['max']:.3f} ms")
    if isinstance(asum, dict):
        print(f"  a: median={asum['median']:.3f} p95={asum['p95']:.3f} max={asum['max']:.3f} ms")
    print("=== PARETO (all candidates) ===")
    hdr = ("policy", "status", "H", "cov", "wilson95", "Lmax", "addL", "TOmar", "POmar", "FOmar")
    print("  " + " ".join(f"{h:>10}" for h in hdr))
    for ev in r["policy_evaluations"]:
        ci = ev["native_tail_coverage_ci"]
        st = "meas" if ev["hardware_measured"] else "anal"
        print("  " + " ".join(f"{v:>10}" for v in (
            f"{ev['D_A_ms']:g},{ev['D_R_ms']:g}", st, f"{ev['H_ms']:g}",
            f"{ev['native_tail_coverage']:.3f}",
            f"{ci['ci_lo']:.3f}-{ci['ci_hi']:.3f}",
            policy._fmt(ev["L_master_max_ms"], 2),
            f"{ev['added_resp_latency_max_ms']:.2f}",
            policy._fmt(ev["margin_response_timeout_ms"], 0),
            policy._fmt(ev["margin_poll_period_ms"], 0),
            policy._fmt(ev["margin_fail_open_ms"], 1))))
    selm = r["selector"]
    sel = selm["selected"]
    print("=== SELECTED (declared constraints; not claimed optimal) ===")
    if sel:
        co = ", ".join(f"({e['D_A_ms']:g},{e['D_R_ms']:g})[{'M' if e['hardware_measured'] else 'A'}]"
                       for e in selm["co_optimal_at_min_H"])
        print(f"  D_A={sel['D_A_ms']:g} D_R={sel['D_R_ms']:g} H={sel['H_ms']:g} "
              f"[{sel['policy_status']}] cov={sel['native_tail_coverage']:.4f} "
              f"wilson95=[{sel['native_tail_coverage_ci']['ci_lo']:.4f},"
              f"{sel['native_tail_coverage_ci']['ci_hi']:.4f}]")
        print(f"  L_master: median={policy._fmt(sel['L_master_median_ms'],2)} "
              f"p95={policy._fmt(sel['L_master_p95_ms'],2)} "
              f"max={policy._fmt(sel['L_master_max_ms'],2)} ms "
              f"(validation-pool max={policy._fmt(sel['L_master_max_validation_ms'],2)})")
        print(f"  co-optimal at H={sel['H_ms']:g} [M=hardware-measured, A=analysis-only]: {co}")
        mc = selm["measured_co_optimal_at_min_H"]
        if mc:
            print(f"  hardware-measured co-optimal alternative(s): " +
                  ", ".join(f"({e['D_A_ms']:g},{e['D_R_ms']:g})" for e in mc))
    else:
        print("  none admissible under constraints")


def render_markdown(r) -> str:
    m = r["meta"]
    s = r["native_design_pool"]["summary"]
    asum = r["native_design_pool"]["a_summary"]
    L = []
    L.append("# Defense-4 timing-policy characterization\n")
    L.append("Selected and tested under declared constraints; **not** claimed optimal. "
             "Software/analysis only over committed raw evidence. Every candidate is "
             "labelled DEMONSTRATED (hardware-measured) vs ANALYSIS-ONLY, and every "
             "unavailable constraint is left UNKNOWN.\n")
    L.append(f"- Protection domain: {m['protection_domain']}")
    L.append(f"- Latency model (AUDIT): `{m['latency_model']}`")
    L.append(f"- `a` = t_A - t_Q (request->ACK): **{'AVAILABLE' if m['a_read_to_ack_available'] else 'UNKNOWN'}** "
             f"({m['a_read_to_ack_source']})")
    L.append(f"- Percentile convention: `{m['percentile_convention']}`; entropy bin "
             f"width: {m['entropy_bin_width_ms']} ms")
    tm = m["target_band_tol_meta"]
    L.append(f"- Target-band tol: {m['target_band_tol_ms']:.4f} ms "
             f"({tm.get('definition','')}; n_covered={tm.get('n_covered_transactions','?')})")
    L.append(f"- Bootstrap B={m['bootstrap_B']}, seed={m['seed']}, sha256 verify={m['verify_sha']}; "
             f"native rows excluded {m['native_rows_excluded_total']} "
             "(clean block-end FIN / reset / inconclusive), validated on EVERY row\n")

    L.append("## Constraints: evidenced vs UNKNOWN")
    for k, v in r["evidenced_constraints_effective"].items():
        L.append(f"- `{k}`: {v}")
    L.append("- ACK-delay risk is governed by **D_A** (not H); response-timeout and "
             "poll-period margins compare against **a + max(C, H)** (not H).")
    L.append("- Fail-open horizon: a 30.8 ms figure was asserted at budget 18000, but it "
             "is **NOT anchored to t_A in the committed raw** (no fail-open release at that "
             "horizon appears in the failopen blocks, which show normal ~10 ms normalization "
             "at budget 18000). It is therefore UNKNOWN and gates nothing.\n")

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

    L.append("## Release error (eps_R - eps_A)")
    L.append("- `measured` values are from the exact hardware-measured (D_A,D_R) pair; "
             "any other policy uses the pooled-median ESTIMATE, labelled `estimate:*`.")
    for k, v in r["release_error_estimates"].items():
        L.append(f"- {k}: eps={v['eps_ms']:.4f} ms  [{v['source']}]")
    L.append(f"- pooled-median estimate (unmeasured policies) = "
             f"{r['release_error_pooled_median_ms']:.4f} ms\n")

    L.append("## Pareto table (DEMONSTRATED = hardware-measured; ANALYSIS = hardware-unmeasured)")
    cols = ["policy", "status", "H_ms", "native_tail_coverage", "coverage_wilson95",
            "visible_clrt_target_ms", "target_band_coverage", "ack_delay_ms",
            "L_master_max_ms", "added_resp_latency_max_ms", "margin_response_timeout_ms",
            "margin_poll_period_ms", "margin_fail_open_ms"]
    L.append("| " + " | ".join(cols) + " |")
    L.append("|" + "|".join(["---"] * len(cols)) + "|")
    for row in r["pareto_table"]:
        L.append("| " + " | ".join(str(row[c]) for c in cols) + " |")
    L.append("")

    L.append("## Provisional selection (declared constraints)")
    selm = r["selector"]
    sel = selm["selected"]
    L.append(f"- objective: {selm['objective']}")
    L.append(f"- constraints: coverage >= {selm['coverage_min']} (point estimate), D_R > 0, "
             "each KNOWN margin >= its bound; fail-open gate ACTIVE = "
             f"{selm['fail_open_gate_active']} (horizon UNKNOWN)")
    L.append(f"- admissible policies: {selm['n_admissible']}")
    if sel:
        ci = sel["native_tail_coverage_ci"]
        co = ", ".join(f"({e['D_A_ms']:g},{e['D_R_ms']:g}) [{'DEMONSTRATED' if e['hardware_measured'] else 'ANALYSIS'}]"
                       for e in selm["co_optimal_at_min_H"])
        L.append(f"- **selected**: D_A={sel['D_A_ms']:g} ms, D_R={sel['D_R_ms']:g} ms "
                 f"(H={sel['H_ms']:g} ms) — **{sel['policy_status'].upper()}**")
        L.append(f"  - native coverage {sel['native_tail_coverage']:.4f} "
                 f"(Wilson95 [{ci['ci_lo']:.4f},{ci['ci_hi']:.4f}]; validation pool "
                 f"{sel['native_tail_coverage_validation_pool']:.4f})")
        L.append(f"  - L_master = a + max(C,H) + eps: median "
                 f"{policy._fmt(sel['L_master_median_ms'],3)} ms, p95 "
                 f"{policy._fmt(sel['L_master_p95_ms'],3)} ms, max "
                 f"{policy._fmt(sel['L_master_max_ms'],3)} ms (validation-pool max "
                 f"{policy._fmt(sel['L_master_max_validation_ms'],3)} ms) — NOT bounded by H")
        L.append(f"  - visible target {sel['visible_clrt_target_ms']:g} ms, ACK delay "
                 f"{sel['ack_delay_ms']:g} ms, release-error eps {sel['release_error_eps_ms']:.4f} ms "
                 f"[{sel['release_error_source']}]")
        L.append(f"  - response-timeout margin {policy._fmt(sel['margin_response_timeout_ms'],1)} ms, "
                 f"poll-period margin {policy._fmt(sel['margin_poll_period_ms'],1)} ms, "
                 f"ACK-vs-RTO margin {sel['margin_ack_delay_vs_rto_ms']}, "
                 f"fail-open margin {sel['margin_fail_open_ms']}")
        L.append(f"- co-optimal at H={sel['H_ms']:g} ms (equal coverage and horizon): {co}.")
        mc = selm["measured_co_optimal_at_min_H"]
        if mc:
            names = ", ".join(f"({e['D_A_ms']:g},{e['D_R_ms']:g})" for e in mc)
            L.append(f"  - **The auto-selected {sel['D_A_ms']:g},{sel['D_R_ms']:g} is "
                     f"HARDWARE-UNMEASURED.** Hardware-measured co-optimal alternative(s) at "
                     f"the same H exist: {names}. These are DEMONSTRATED and should be preferred "
                     "if a hardware-attested policy is required; the min-D_A tie-break alone "
                     "picks the unmeasured point.")
    t = r["tested_policy_4_10"]
    L.append(f"- (4,10) D4 [DEMONSTRATED, evaluated, not auto-selected]: H={t['H_ms']:g} ms, "
             f"coverage {t['native_tail_coverage']:.4f}, L_master max "
             f"{policy._fmt(t['L_master_max_ms'],3)} ms, eps {t['release_error_eps_ms']:.4f} ms "
             f"[{t['release_error_source']}], residual tail {t['residual_tail_fraction']:.4f}\n")

    L.append("## UNKNOWN (not invented)")
    L.append("- `a` (request->ACK): AVAILABLE — this is NOT unknown; loaded per row.")
    L.append("- TCP RTO: UNKNOWN (not in committed raw; 0 retransmits observed). ACK-vs-RTO "
             "margin is therefore UNKNOWN and would compare against D_A, not H.")
    L.append("- Fail-open horizon: UNKNOWN (not t_A-anchored in committed raw).")
    L.append("- Reservoir horizon (R11): UNKNOWN (carried OPEN in the evidence freeze).")
    L.append(f"- UNPINNED registry fields: {len(r['unpinned_fields'])} "
             f"(all `firmware`: relay firmware/config revision not in raw evidence).\n")
    return "\n".join(L)


if __name__ == "__main__":
    raise SystemExit(main())

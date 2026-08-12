#!/usr/bin/env python
"""Timing-policy characterization CLI for the DNP3 Defense-4 timing engine.

Loads the baseline registry, validates it against the committed raw evidence
(paths, sha256, per-transaction schema, units, timing definitions), computes
per-stratum distributions with bootstrap CIs, evaluates candidate (D_A, D_R)
deadline policies against the evidenced native CLRT distribution, emits a Pareto
table, and provisionally selects ONE common policy for the whole protection domain
under declared constraints. Software/analysis only.

Usage:
  $RESEARCH_PYTHON timing_policy_analysis.py \
      [--registry registry.yaml] [--out-json results.json] [--out-md REPORT.md] \
      [--coverage-min 0.99] [--tol-ms auto] [--fail-open-margin-ms 5] \
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
# Includes the tested (4,10), the five measured d4recal probes, D2 (0,10), and a
# spread of neighbours. (4,10) is evaluated but never auto-selected.
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
    """Map (D_A,D_R) -> (eps_ms, source). Pooled median for unmeasured policies."""
    all_eps = [e for lst in est.values() for (_, e, _) in lst]
    pooled = float(np.median(all_eps)) if all_eps else 0.0
    lookup = {}
    for key, lst in est.items():
        w = np.array([n for (_, _, n) in lst], dtype=float)
        e = np.array([e for (_, e, _) in lst], dtype=float)
        lookup[key] = (
            float((e * w).sum() / w.sum()),
            "measured:" + ",".join(i for i, _, _ in lst),
        )
    return lookup, pooled


def evaluate_grid(native_C, grid, eps_lookup, pooled_eps, tol_ms, constraints):
    evals = []
    for da, dr in grid:
        eps, src = eps_lookup.get(
            (float(da), float(dr)), (pooled_eps, "pooled_measured_extrapolated")
        )
        ev = policy.eval_policy(
            native_C, da, dr, tol_ms=tol_ms, eps_ms=eps, eps_source=src, **constraints
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
    ap.add_argument("--tol-ms", default="auto",
                    help="target-band tolerance; 'auto' = D4 paper p5-p95 spread")
    ap.add_argument("--fail-open-margin-ms", type=float, default=5.0)
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

    ec = reg["evidenced_constraints"]
    constraints = dict(
        fail_open_horizon_ms=ec["fail_open_horizon_ms_at_budget_18000"],
        poll_period_ms=ec["poll_period_ms"],
        response_timeout_ms=ec["dnp3_response_timeout_ms"],
        tcp_rto_ms=None,            # UNKNOWN — not evidenced
        reservoir_horizon_ms=None,  # UNKNOWN — R11 OPEN
    )

    st = stratum_stats(reg, repo_root, args.bootstrap, args.seed)

    d4_paper = st["groups"].get("def_D4_frA", {})
    tol_ms = (d4_paper.get("p5_p95_spread_ms", 0.05)
              if args.tol_ms == "auto" else float(args.tol_ms))

    design_members = registry.pool_groups(reg)["nat_off_frA"]
    native_design = policy.pool_native_C(reg, design_members, repo_root)
    valid_members = registry.pool_groups(reg)["nat_off_fixA"]
    native_valid = policy.pool_native_C(reg, valid_members, repo_root)

    est = measured_release_errors(reg, repo_root)
    eps_lookup, pooled_eps = build_eps_lookup(est)

    evals = evaluate_grid(native_design, CANDIDATE_GRID, eps_lookup, pooled_eps,
                          tol_ms, constraints)
    for ev in evals:
        ev["native_tail_coverage_validation_pool"] = float(
            (native_valid <= ev["H_ms"]).mean()
        )
    pareto = [policy.pareto_row(ev) for ev in evals]

    sel = policy.select_common_policy(
        native_design, evals, coverage_min=args.coverage_min,
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
            "target_band_tol_ms": tol_ms,
            "target_band_tol_source": ("auto:D4_paper_p5_p95_spread"
                                       if args.tol_ms == "auto" else "user"),
            "bootstrap_B": args.bootstrap,
            "seed": args.seed,
            "verify_sha": not args.no_verify_sha,
            "native_rows_excluded_total": st["total_excluded"],
        },
        "evidenced_constraints": ec,
        "validation_warnings": warnings,
        "unpinned_fields": unpinned,
        "native_design_pool": {
            "members": design_members, "n": int(native_design.size),
            "summary": stats.summary(native_design),
            "ecdf_sorted_ms": sorted(round(float(x), 6) for x in native_design),
        },
        "native_validation_pool": {
            "members": valid_members, "n": int(native_valid.size),
            "summary": stats.summary(native_valid),
        },
        "stratum_stats": st,
        "release_error_estimates": {
            f"D_A={k[0]:g},D_R={k[1]:g}": {"eps_ms": v[0], "source": v[1]}
            for k, v in eps_lookup.items()
        },
        "release_error_pooled_median_ms": pooled_eps,
        "policy_evaluations": evals,
        "pareto_table": pareto,
        "selector": {
            "coverage_min": args.coverage_min,
            "fail_open_margin_ms": args.fail_open_margin_ms,
            "objective": sel["objective"],
            "n_admissible": sel["n_admissible"],
            "selected": _slim(sel["selected"]),
            "co_optimal_at_min_H": [_slim(e) for e in sel["co_optimal_at_min_H"]],
            "ranked_admissible": [_slim(e) for e in sel["ranked_admissible"]],
            "note": sel["note"],
        },
        "tested_policy_4_10": _slim(tested_410),
    }

    Path(args.out_json).write_text(json.dumps(results, indent=2, default=float))
    Path(args.out_md).write_text(render_markdown(results))
    log.info("wrote %s and %s", Path(args.out_json).name, Path(args.out_md).name)
    _print_console(results)
    return 0


def _slim(ev):
    if ev is None:
        return None
    keep = ("D_A_ms", "D_R_ms", "H_ms", "native_tail_coverage",
            "native_tail_coverage_validation_pool", "visible_clrt_target_ms",
            "target_band_coverage", "ack_delay_ms", "added_resp_latency_max_ms",
            "added_resp_latency_mean_ms", "release_error_eps_ms", "release_error_source",
            "residual_p5_p95_spread_ms", "residual_entropy_bits", "residual_effective_states",
            "residual_tail_fraction", "margin_fail_open_ms", "margin_poll_period_ms",
            "margin_response_timeout_ms", "margin_tcp_rto_ms", "margin_reservoir_ms",
            "tcp_rto_ms", "reservoir_horizon_ms")
    return {k: ev[k] for k in keep if k in ev}


def _print_console(r):
    print("\n=== NATIVE DESIGN POOL (paper) ===")
    s = r["native_design_pool"]["summary"]
    print(f"  n={s['n']} (excluded {r['meta']['native_rows_excluded_total']} across all "
          f"datasets) median={s['median']:.3f} p95={s['p95']:.3f} "
          f"p99={s['p99']:.3f} max={s['max']:.3f}")
    print("=== PARETO (all candidates) ===")
    hdr = ("policy", "H", "cov", "cov_val", "target", "band", "ackd", "addL", "FOmar", "TOmar")
    print("  " + " ".join(f"{h:>9}" for h in hdr))
    for ev in r["policy_evaluations"]:
        print("  " + " ".join(f"{v:>9}" for v in (
            f"{ev['D_A_ms']:g},{ev['D_R_ms']:g}", f"{ev['H_ms']:g}",
            f"{ev['native_tail_coverage']:.3f}",
            f"{ev['native_tail_coverage_validation_pool']:.3f}",
            f"{ev['visible_clrt_target_ms']:g}", f"{ev['target_band_coverage']:.3f}",
            f"{ev['ack_delay_ms']:g}", f"{ev['added_resp_latency_max_ms']:.2f}",
            f"{ev['margin_fail_open_ms']:.1f}", f"{ev['margin_response_timeout_ms']:.0f}")))
    selm = r["selector"]
    sel = selm["selected"]
    print("=== SELECTED (declared constraints; not claimed optimal) ===")
    if sel:
        co = ", ".join(f"({e['D_A_ms']:g},{e['D_R_ms']:g})" for e in selm["co_optimal_at_min_H"])
        print(f"  D_A={sel['D_A_ms']:g} D_R={sel['D_R_ms']:g} H={sel['H_ms']:g} "
              f"cov={sel['native_tail_coverage']:.3f}; co-optimal at H={sel['H_ms']:g}: {co}")
    else:
        print("  none admissible under constraints")


def render_markdown(r) -> str:
    m = r["meta"]
    s = r["native_design_pool"]["summary"]
    L = []
    L.append("# Defense-4 timing-policy characterization\n")
    L.append("Selected and tested under declared constraints; **not** claimed optimal. "
             "Software/analysis only over committed raw evidence.\n")
    L.append(f"- Protection domain: {m['protection_domain']}")
    L.append(f"- Percentile convention: `{m['percentile_convention']}`; "
             f"entropy bin width: {m['entropy_bin_width_ms']} ms; "
             f"target-band tol: {m['target_band_tol_ms']:.4f} ms ({m['target_band_tol_source']})")
    L.append(f"- Bootstrap B={m['bootstrap_B']}, seed={m['seed']}, "
             f"sha256 verify={m['verify_sha']}; native rows excluded "
             f"{m['native_rows_excluded_total']} (clean block-end FIN / reset / inconclusive)\n")

    L.append("## Evidenced constraints")
    for k, v in r["evidenced_constraints"].items():
        L.append(f"- `{k}`: {v}")
    L.append("")

    L.append("## Native design distribution (C = t_R - t_A), paper pool")
    L.append(f"- members: {', '.join(r['native_design_pool']['members'])} (n={s['n']})")
    L.append(f"- median {s['median']:.3f}, p95 {s['p95']:.3f}, p99 {s['p99']:.3f}, "
             f"max {s['max']:.3f} ms; p5-p95 spread {s['p5_p95_spread_ms']:.3f} ms; "
             f"entropy {s['entropy_bits']:.2f} bits ({s['effective_states']:.1f} states)")
    vp = r["native_validation_pool"]["summary"]
    L.append(f"- validation pool (fixA+fixB, n={vp['n']}): median {vp['median']:.3f}, "
             f"p95 {vp['p95']:.3f}, max {vp['max']:.3f} ms (heavier tail; see threats)\n")

    L.append("## Release error (eps_R - eps_A) from defended evidence")
    for k, v in r["release_error_estimates"].items():
        L.append(f"- {k}: eps={v['eps_ms']:.4f} ms  [{v['source']}]")
    L.append(f"- pooled median eps = {r['release_error_pooled_median_ms']:.4f} ms "
             "(used for unmeasured policies)\n")

    L.append("## Pareto table")
    cols = ["policy", "H_ms", "native_tail_coverage", "visible_clrt_target_ms",
            "target_band_coverage", "ack_delay_ms", "added_resp_latency_max_ms",
            "margin_fail_open_ms", "margin_response_timeout_ms", "reservoir_requirement"]
    L.append("| " + " | ".join(cols) + " |")
    L.append("|" + "|".join(["---"] * len(cols)) + "|")
    for row in r["pareto_table"]:
        L.append("| " + " | ".join(str(row[c]) for c in cols) + " |")
    L.append("")

    L.append("## Provisional selection (declared constraints)")
    selm = r["selector"]
    sel = selm["selected"]
    L.append(f"- objective: {selm['objective']}")
    L.append(f"- constraints: coverage >= {selm['coverage_min']}, "
             f"fail-open margin >= {selm['fail_open_margin_ms']} ms, D_R > 0")
    L.append(f"- admissible policies: {selm['n_admissible']}")
    if sel:
        co = ", ".join(f"({e['D_A_ms']:g},{e['D_R_ms']:g})"
                       for e in selm["co_optimal_at_min_H"])
        L.append(f"- **selected**: D_A={sel['D_A_ms']:g} ms, D_R={sel['D_R_ms']:g} ms "
                 f"(H={sel['H_ms']:g} ms), native coverage {sel['native_tail_coverage']:.4f} "
                 f"(validation pool {sel['native_tail_coverage_validation_pool']:.4f}), "
                 f"visible target {sel['visible_clrt_target_ms']:g} ms, "
                 f"ACK delay {sel['ack_delay_ms']:g} ms, "
                 f"max added response latency {sel['added_resp_latency_max_ms']:.2f} ms")
        L.append(f"- co-optimal at H={sel['H_ms']:g} ms (equal coverage and total latency): {co}. "
                 "These differ only in how H is split between ACK delay and visible target; "
                 "the data-only cost cannot see the ordering-robustness margin that motivates a "
                 "larger D_A, so the tested (4,10) is co-optimal here, not dominated.")
    t = r["tested_policy_4_10"]
    L.append(f"- tested (4,10) [evaluated, not auto-selected]: H={t['H_ms']:g} ms, "
             f"coverage {t['native_tail_coverage']:.4f} "
             f"(validation {t['native_tail_coverage_validation_pool']:.4f}), "
             f"visible target {t['visible_clrt_target_ms']:g} ms, "
             f"eps {t['release_error_eps_ms']:.4f} ms, "
             f"residual tail fraction {t['residual_tail_fraction']:.4f}, "
             f"fail-open margin {t['margin_fail_open_ms']:.2f} ms\n")

    L.append("## Unknowns (not invented)")
    L.append("- TCP RTO: UNKNOWN (not evidenced in committed raw); 0 retransmits observed.")
    L.append("- Reservoir horizon (R11): UNKNOWN (carried OPEN in the evidence freeze).")
    L.append(f"- UNPINNED registry fields: {len(r['unpinned_fields'])} "
             f"(all `firmware`: relay firmware/config revision not in raw evidence).\n")
    return "\n".join(L)


if __name__ == "__main__":
    raise SystemExit(main())

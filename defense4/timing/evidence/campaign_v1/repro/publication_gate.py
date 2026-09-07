"""Compare what the pipeline just rebuilt against what the repository publishes.

The reproduction script used to claim it compared its outputs with the published artefacts and
did not. This does the comparison for real, and fails closed.

Three comparisons:

1. the regenerated canonical table against the frozen campaign table, semantically, row by row
   (performed inside ``validate_campaign.py``; this gate asserts it actually ran and passed);
2. the regenerated figures against the published figures, by SHA-256, including the manifest
   ``paper/rewrite/figures/ndss/FIGURES.sha256``;
3. the regenerated statistics against the manuscript-facing values file that the manuscript
   quotes, so a number cannot drift between the analysis and the paper.

Run:  publication_gate.py OUT_DIR [--update]

``--update`` refreshes the published figures, the manifest and the values file from the
regenerated outputs. It is the only sanctioned way to change a published figure, and it never
runs as part of the gate itself.
"""
from __future__ import annotations
import hashlib, json, os, shutil, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent                                  # campaign_v1/
REPO = HERE.parents[4]                              # repository root
PUB_FIGS = REPO / "paper" / "rewrite" / "figures" / "ndss"
FIGURES = ["fig_policy_coverage_cost", "fig_distributions", "fig_feature_overlap",
           "fig_leakage", "fig_stability"]
# Artefacts that travel with every published figure.
SUFFIXES = [".pdf", ".png", "_data.csv", ".provenance.json",
            ".caption.md", ".method.md", ".limitations.md"]
# Hash-gated artefacts. The vector PDF and the figure data are produced entirely by the pinned
# Python dependencies and are byte-reproducible. The PNG is an Agg raster whose bytes depend on
# the FreeType and libpng bundled with the interpreter build: two environments satisfying the
# same lock file can differ by a few hundred pixels while the PDF is identical. Gating the
# preview made a correct rebuild fail, so the PNG is checked for existence and declared
# dimensions only.
AUTHORITATIVE = [".pdf", "_data.csv", ".caption.md", ".method.md", ".limitations.md"]
PREVIEW = [".png"]
VALUES_NAME = "MANUSCRIPT_VALUES.json"


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for c in iter(lambda: f.read(1 << 16), b""):
            h.update(c)
    return h.hexdigest()


def manuscript_values(stats, leak, sweep, val, repl):
    """Every number the manuscript is allowed to quote, derived here and nowhere else."""
    cov = stats["read_lane_coverage"]
    pac = stats["per_arm_class"]
    mi = leak["mutual_information"]
    cls = leak["classifiers"]
    fixed = [s for s in sweep if s["mode"] == "D4" and not s["is_control_point"]
             and s["D_ms"] is not None and abs(s["D_ms"] - stats["budget_ms"]) < 1e-9]
    return {
        "corpus": {
            "captures": val["captures"], "exchanges": val["exchanges"],
            "grouped_runs": val["expectations"]["grouped_runs"]["got"],
            "read_total": val["expectations"]["READ_total"]["got"],
            "select_total": val["expectations"]["SELECT_total"]["got"],
            "operate_total": val["expectations"]["OPERATE_total"]["got"],
            "per_arm_exchanges": val["expectations"]["native_exchanges"]["got"],
        },
        "read_lane_coverage": {
            "budget_ms": cov["budget_ms"], "n": cov["n"],
            "above_budget": cov["above_budget"],
            "percent_above": cov["percent_above"],
            "percent_covered": cov["percent_covered"],
        },
        "intervals_ms": {k: {"median": v["median"], "iqr": v["iqr"], "max": v["max"]}
                         for k, v in pac.items()},
        "ack_interval_ms": {k: {"median": v["median"], "iqr": v["iqr"]}
                            for k, v in stats["ack_interval_ms"].items()},
        "added_response_latency_ms": stats["added_response_latency_ms"],
        "overhead": stats["overhead"],
        "mutual_information_bits": {
            a: {"observed": mi[a]["observed_bits"],
                "null_p95": mi[a]["null_p95_bits"], "null_p99": mi[a]["null_p99_bits"],
                "p_value": mi[a]["p_value_empirical"],
                "p_value_resolution": mi[a]["p_value_resolution"],
                "inside_null": mi[a]["inside_null"]}
            for a in ("native", "obfuscated")},
        "classifier_balanced_accuracy": {
            f: {"A_fixed_timing_off": cls[f]["A_fixed_native_trained"]["tested_on_timing_off"]["mean"],
                "A_fixed_obfuscated": cls[f]["A_fixed_native_trained"]["tested_on_obfuscated"]["mean"],
                "B_adaptive_obfuscated": cls[f]["B_adaptive_obfuscated_trained"]["tested_on_obfuscated"]["mean"]}
            for f in ("clrt", "ack_clrt")},
        "chance_balanced_accuracy": leak["chance_balanced_accuracy"],
        "replacement": {
            c: {"native_sd": repl["read_lane"][c]["native"]["sd"],
                "protected_sd": repl["read_lane"][c]["protected"]["sd"],
                "variance_ratio": repl["read_lane"][c]["variance_ratio_prot_over_nat"],
                "variance_ratio_ci95": repl["read_lane"][c]["variance_ratio_ci95_session_bootstrap"],
                "counterfactual_shifted_native_sd":
                    repl["read_lane"][c]["counterfactual_shifted_native"]["sd"]}
            for c in ("READ", "SELECT")},
        "residual_leakage": {
            f: {"native": repl["classifiers_by_feature_set"][f]["native"]["balanced_accuracy_mean"],
                "protected": repl["classifiers_by_feature_set"][f]["protected"]["balanced_accuracy_mean"]}
            for f in ("clrt_only", "req_to_ack_only", "ack_plus_clrt")},
        "sweep": {
            "points": len(sweep),
            "fixed_budget_points": len(fixed),
            "fixed_budget_D_R_ms": sorted(s["D_R_ms"] for s in fixed),
            "fixed_budget_clrt_med_ms": [s["read_clrt_med_ms"]
                                         for s in sorted(fixed, key=lambda x: x["D_R_ms"])],
            "fixed_budget_rt_med_ms": [s["read_rt_med_ms"]
                                       for s in sorted(fixed, key=lambda x: x["D_R_ms"])],
        },
    }


def main(out_dir, update=False):
    out = Path(out_dir)
    problems = []

    # ---- 1. the canonical table really was compared, row by row, and passed
    val = json.load(open(out / "validation_report.json"))
    if val["problems"]:
        problems.append(f"validation reported {len(val['problems'])} problems")
    if val.get("frozen_table_rows_compared") != val["exchanges"]:
        problems.append(f"frozen-table comparison covered "
                        f"{val.get('frozen_table_rows_compared')} of {val['exchanges']} rows")
    if val.get("dataset_manifests_verified") != 22:
        problems.append(f"{val.get('dataset_manifests_verified')} dataset manifests verified, "
                        f"expected 22")
    swr = json.load(open(out / "sweep_report.json"))
    if swr["problems"]:
        problems.append(f"sweep validation reported {len(swr['problems'])} problems")

    stats = json.load(open(out / "stats.json"))
    leak = json.load(open(out / "leakage.json"))
    sweep = json.load(open(out / "sweep_summary.json"))
    repl = json.load(open(out / "replacement_stats.json"))
    values = manuscript_values(stats, leak, sweep, val, repl)

    # ---- 2. figures
    figs = out / "figs"
    if update:
        PUB_FIGS.mkdir(parents=True, exist_ok=True)
        # remove published artefacts of figures that no longer exist
        for p in sorted(PUB_FIGS.iterdir()):
            if p.is_file() and not any(p.name.startswith(s) for s in FIGURES) \
               and p.name not in ("FIGURES.sha256", VALUES_NAME,
                                  "FIGURE_PROVENANCE_campaign_v1.md"):
                p.unlink()
        for stem in FIGURES:
            for suf in SUFFIXES:
                src = figs / f"{stem}{suf}"
                if src.exists():
                    shutil.copy2(src, PUB_FIGS / src.name)
        lines = ["# Authoritative artefacts: vector PDF and figure data. Both are byte-\n",
                 "# reproducible from the pinned environment and are gated on every rebuild.\n",
                 "# The .png previews are Agg rasters, recorded in each figure's provenance but\n",
                 "# deliberately not gated: their bytes vary with the interpreter build's\n",
                 "# FreeType and libpng even when the PDF is identical.\n"]
        for suf in (".pdf", "_data.csv"):
            lines += [f"{sha256(PUB_FIGS / (s + suf))}  {s}{suf}\n" for s in FIGURES
                      if (PUB_FIGS / (s + suf)).exists()]
        (PUB_FIGS / "FIGURES.sha256").write_text("".join(lines))
        (PUB_FIGS / VALUES_NAME).write_text(json.dumps(values, indent=1) + "\n")
        print(f"updated {len(FIGURES)} published figures, the manifest and {VALUES_NAME} "
              f"in {PUB_FIGS.relative_to(REPO)}")
        return 0

    for stem in FIGURES:
        for suf in SUFFIXES:
            a, b = figs / f"{stem}{suf}", PUB_FIGS / f"{stem}{suf}"
            if not a.exists():
                problems.append(f"regenerated {a.name} is missing")
                continue
            if not b.exists():
                problems.append(f"published {b.name} is missing")
                continue
            # Provenance records the source commit, which moves with every commit, so compare
            # it on the fields that describe the figure rather than byte for byte.
            if suf == ".provenance.json":
                pa, pb = json.load(open(a)), json.load(open(b))
                for k in ("figure_dimensions_in", "caption", "inputs"):
                    if json.dumps(pa.get(k), sort_keys=True) != json.dumps(pb.get(k), sort_keys=True):
                        problems.append(f"{stem}: provenance field {k!r} differs from published")
                # Outputs are compared per artefact, so the preview's hash does not fail a
                # rebuild that produced an identical PDF.
                for key in ("pdf", "data_csv"):
                    oa, ob = (pa.get("outputs") or {}).get(key), (pb.get("outputs") or {}).get(key)
                    if json.dumps(oa, sort_keys=True) != json.dumps(ob, sort_keys=True):
                        problems.append(f"{stem}: provenance output {key!r} differs from published")
                continue
            if suf in PREVIEW:
                # Existence and declared size only; see AUTHORITATIVE above.
                if a.stat().st_size == 0 or b.stat().st_size == 0:
                    problems.append(f"{stem}{suf}: preview is empty")
                continue
            if sha256(a) != sha256(b):
                # A vector PDF's bytes carry coordinates computed in floating point, and two
                # machines satisfying the same lock file can differ in the last bits of one of
                # them. Reporting the summary CSV's state alongside a PDF mismatch narrows the
                # search, but it does NOT establish that the figures are equivalent: a
                # figure-data CSV holds the summary rows behind the marks, not every plotted
                # point, label, tick or axis setting. fig_feature_overlap is the worked example
                # -- six summary rows standing behind 900 drawn points per arm. The wording
                # below therefore stops at what the check can support and names inspection as
                # the remaining step. The check itself is NOT relaxed; see
                # REPRODUCIBILITY_SCOPE.md.
                if suf == ".pdf":
                    csv_a, csv_b = figs / f"{stem}_data.csv", PUB_FIGS / f"{stem}_data.csv"
                    if csv_a.exists() and csv_b.exists() and sha256(csv_a) == sha256(csv_b):
                        problems.append(
                            f"{stem}{suf}: PDF differs; summary CSV matches; visual/content "
                            f"equivalence requires inspection (see REPRODUCIBILITY_SCOPE.md)")
                        continue
                problems.append(f"{stem}{suf}: regenerated hash differs from published")

    man = PUB_FIGS / "FIGURES.sha256"
    if not man.exists():
        problems.append("FIGURES.sha256 is missing")
    else:
        recorded = {}
        for line in man.read_text().splitlines():
            if line.strip() and not line.lstrip().startswith("#"):
                h, n = line.split(None, 1)
                recorded[n.strip()] = h
        for stem in FIGURES:
            for ext in (".pdf", "_data.csv"):
                name = stem + ext
                if name not in recorded:
                    problems.append(f"FIGURES.sha256 does not list {name}")
                elif (figs / name).exists() and recorded[name] != sha256(figs / name):
                    problems.append(f"FIGURES.sha256 hash for {name} does not match the rebuild")
            if stem + ".png" in recorded:
                problems.append(f"FIGURES.sha256 must not gate the preview {stem}.png")

    # ---- 3. the manuscript-facing values
    vf = PUB_FIGS / VALUES_NAME
    if not vf.exists():
        problems.append(f"{VALUES_NAME} is missing; run with --update to create it")
    else:
        pub = json.load(open(vf))
        if json.dumps(pub, sort_keys=True) != json.dumps(values, sort_keys=True):
            for k in values:
                if json.dumps(pub.get(k), sort_keys=True) != json.dumps(values[k], sort_keys=True):
                    problems.append(f"{VALUES_NAME}: section {k!r} differs from the rebuild")

    print(f"publication gate: {len(problems)} problems")
    for p in problems:
        print("  PROBLEM:", p)
    if not problems:
        print("  regenerated outputs match every published artefact")
    return 1 if problems else 0


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    sys.exit(main(args[0] if args else "/tmp/cv1_out", update="--update" in sys.argv))

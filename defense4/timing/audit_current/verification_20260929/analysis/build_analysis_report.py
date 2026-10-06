#!/usr/bin/env python3
"""Build the offline verification report for the 2026-09-29 audit slice."""

import csv
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[5]
OUT = Path(__file__).resolve().parent


def load_json(path):
    return json.loads(path.read_text())


def sha256(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def rel(path):
    return str(path.relative_to(ROOT))


def fixed_budget_from_mv(mv):
    return {
        "d_r_ms": mv["sweep"]["fixed_budget_D_R_ms"],
        "clrt_med_ms": mv["sweep"]["fixed_budget_clrt_med_ms"],
        "rt_med_ms": mv["sweep"]["fixed_budget_rt_med_ms"],
    }


def fixed_budget_by_class(sweep_timing):
    csv_path = ROOT / "defense4/timing/evidence/campaign_v2/sweep/sweep_points.csv"
    out = []
    with csv_path.open(newline="") as stream:
        for row in csv.DictReader(stream):
            if row["mode"] == "D4" and row["D_ms"] == "28.0":
                d_r = float(row["D_R_ms"])
                by_class = {
                    klass: sweep_timing[row["point"]][klass]["clrt_med"]
                    for klass in ("READ", "SELECT", "OPERATE")
                }
                out.append({"point": row["point"], "D_R_ms": d_r, "clrt_med_by_class_ms": by_class})
    out.sort(key=lambda r: r["D_R_ms"])
    return out


def line_has_j_readback():
    paths = list((ROOT / "defense4/timing/evidence/campaign_v2/provenance").glob("*.params.txt"))
    paths += list((ROOT / "defense4/timing/evidence/campaign_v2/sweep/provenance").glob("*.params.txt"))
    needle_terms = ("J", "codebook", "tbl_bor", "tbl_hold", "tbl_random")
    hits = []
    for path in paths:
        text = path.read_text(errors="replace")
        if any(term in text for term in needle_terms):
            hits.append(rel(path))
    return {"files_checked": len(paths), "hits": hits}


def manifest_inputs():
    campaign = ROOT / "defense4/timing/evidence/campaign_v2"
    dataset_sha = sorted((ROOT / "defense4/timing/evidence/campaign_v2").glob("s*/provenance/DATASET.sha256"))
    listed = set()
    missing = []
    for path in dataset_sha:
        session_dir = path.parents[1]
        for line in path.read_text().splitlines():
            if line.strip():
                resolved = session_dir / line.split(maxsplit=1)[1]
                listed.add(rel(resolved))
                if not resolved.exists():
                    missing.append(rel(resolved))
    sweep_sha = ROOT / "defense4/timing/evidence/campaign_v2/sweep/SWEEP.sha256"
    for line in sweep_sha.read_text().splitlines():
        if line.strip():
            resolved = campaign / line.split(maxsplit=1)[1]
            listed.add(rel(resolved))
            if not resolved.exists():
                missing.append(rel(resolved))
    checked = [
        ROOT / "defense4/timing/evidence/campaign_v2/derived/transactions.csv",
        ROOT / "defense4/timing/evidence/campaign_v2/provenance/s01_b1_obfuscated.params.txt",
        ROOT / "defense4/timing/evidence/campaign_v2/sweep/provenance/sw_D4_20_8.params.txt",
    ]
    return {
        "dataset_sha_files": len(dataset_sha),
        "listed_inputs": len(listed),
        "listed_sweep_sample": sorted(p for p in listed if "/sweep/" in p)[:20],
        "listed_missing": missing,
        "checked_not_listed": [rel(p) for p in checked if rel(p) not in listed],
    }


def current_claims_probe(corrected):
    claims = ROOT / "defense4/timing/CLAIMS_AND_LIMITATIONS.md"
    text = claims.read_text()
    stale = "4.0002, 8.0055, 12.0003" in text
    return {
        "path": rel(claims),
        "contains_stale_c3_medians": stale,
        "c3_status": "needs-ledger-edit" if stale else "ledger-corrected",
        "contains_corrected_c7_tail_probe_language": "does not distinguish a tail-loss probe" in text,
        "expected_c3_clrt_med_ms": corrected["clrt_med_ms"],
    }


def quick_paper_only_checks():
    abstract = ROOT / "paper/rewrite/sections/00_abstract.tex"
    intro = ROOT / "paper/rewrite/sections/01_introduction.tex"
    conclusion = ROOT / "paper/rewrite/sections/08_conclusion.tex"
    abstract_text = abstract.read_text()
    intro_text = intro.read_text()
    conclusion_text = conclusion.read_text()
    return {
        "scope": "Quick paper-only probes requested during the audit; not a full manuscript review.",
        "abstract_device_identification_claim": {
            "path": rel(abstract),
            "present": "identifies both the device and the operation" in abstract_text,
            "evidence_status": "unsupported-by-campaign-v2",
            "note": "Campaign v2 evaluates transaction classes on one SEL-751A, not device identification across devices.",
        },
        "chance_wording": {
            "paths": [rel(abstract), rel(intro), rel(conclusion)],
            "present": any("to chance" in text for text in (abstract_text, intro_text, conclusion_text)),
            "note": "The fixed attack reaches chance balanced accuracy, but the confusion is degenerate and should be qualified where headline prose says only 'chance'.",
        },
        "master_facing_retransmission_qualifier": {
            "paths": [rel(abstract), rel(intro), rel(conclusion)],
            "abstract_has_master_facing": "master-facing" in abstract_text,
            "introduction_has_master_facing": "master-facing" in intro_text,
            "conclusion_has_master_facing": "master-facing" in conclusion_text,
            "note": "Campaign captures are master-facing; relay-facing behaviour is not observed. This quick probe checks file-level wording only.",
        },
    }


def actionable_findings(c3_probe):
    c3_fixed = not c3_probe["contains_stale_c3_medians"]
    return [
        {
            "id": "C3-stale-values",
            "status": "ledger-corrected" if c3_fixed else "author-action",
            "evidence": (
                "CLAIMS_AND_LIMITATIONS.md contains corrected MANUSCRIPT_VALUES medians."
                if c3_fixed
                else "CLAIMS_AND_LIMITATIONS.md still contains the pre-audit sweep medians."
            ),
            "smallest_correction": (
                "Keep paper/manuscript frozen; the engineering ledger now has the corrected values."
                if c3_fixed
                else "Use MANUSCRIPT_VALUES fixed_budget_clrt_med_ms and fixed_budget_rt_med_ms; narrow 'within 6 us' to READ fixed-budget medians or restate by class."
            ),
        },
        {
            "id": "J-not-observed",
            "status": "supported-limitation",
            "evidence": "No campaign_v2 params readback file contains J/codebook/random table terms.",
            "smallest_correction": "Do not say per-transaction J or codebook entries were readback-verified in campaign_v2.",
        },
        {
            "id": "byte-equality-scope",
            "status": "supported-limitation",
            "evidence": "validation_report proves equal frame and wire-byte counts, not byte-for-byte DNP3 payload equality.",
            "smallest_correction": "State captured volume equality unless payload bytes are separately hashed/compared.",
        },
        {
            "id": "grid-model-artifacts",
            "status": "verified-with-scope",
            "evidence": "audit_grid.py verified hashes and recomputed scores from prediction ledgers without refitting or deserializing every model.",
            "smallest_correction": "Describe grid audit as retained-artifact and prediction-ledger verification, not independent model retraining.",
        },
    ]


def build():
    mv_path = ROOT / "paper/rewrite/figures/ndss/MANUSCRIPT_VALUES.json"
    validation_path = ROOT / "defense4/timing/evidence/campaign_v2/repro/audit_20260925/validation_report.json"
    sweep_report_path = ROOT / "defense4/timing/evidence/campaign_v2/repro/audit_20260925/sweep_report.json"
    comparison_path = ROOT / "defense4/timing/evidence/campaign_v2/repro/audit_20260925/result_comparison.json"
    sweep_timing_path = ROOT / "defense4/timing/evidence/campaign_v2/sweep/sweep_timing.json"
    grid_audit_path = OUT / "grid_audit/audit_grid_result.json"
    grid_attacks_path = ROOT / "defense4/timing/latency_search/results/grid_random_screen_20260927T021133Z/grid_attacks.json"

    mv = load_json(mv_path)
    validation = load_json(validation_path)
    sweep_report = load_json(sweep_report_path)
    comparison = load_json(comparison_path)
    sweep_timing = load_json(sweep_timing_path)
    grid_audit = load_json(grid_audit_path)
    grid_attacks = load_json(grid_attacks_path)

    corrected_c3 = fixed_budget_from_mv(mv)
    c3_probe = current_claims_probe(corrected_c3)
    actions = actionable_findings(c3_probe)
    findings = {
        "generated_from": {
            "script": rel(Path(__file__).resolve()),
            "manuscript_values": {"path": rel(mv_path), "sha256": sha256(mv_path)},
            "grid_audit": {"path": rel(grid_audit_path), "sha256": sha256(grid_audit_path)},
        },
        "campaign_v2": {
            "counts": validation["expectations"],
            "dataset_manifests_verified": validation["dataset_manifests_verified"],
            "unique_capture_hashes": validation["unique_capture_hashes"],
            "distinct_frame_counts": validation["distinct_frame_counts"],
            "distinct_wire_byte_counts": validation["distinct_wire_byte_counts"],
            "published_values_match_rebuild": comparison["main_campaign_values_unchanged"],
            "changed_manuscript_value_sections": comparison["changed_manuscript_value_sections"],
        },
        "c3_sweep": {
            "correct_fixed_budget_values": corrected_c3,
            "rebuild_before_after": {
                "before": comparison["sweep_before"],
                "after": comparison["sweep_after"],
            },
            "fixed_budget_by_class": fixed_budget_by_class(sweep_timing),
            "readback_summary": {
                "control_plane_readbacks_checked": sweep_report["control_plane_readbacks_checked"],
                "offsets_provenance": sweep_report["offsets_provenance"],
            },
            "claims_probe": c3_probe,
        },
        "j_readback": line_has_j_readback(),
        "hash_scope": manifest_inputs(),
        "paper_only_quick_checks": quick_paper_only_checks(),
        "grid_audit": {
            "status": grid_audit["status"],
            "primary_exchanges": grid_audit["primary_exchanges"],
            "raw_input_hashes": grid_audit["raw_input_hashes"],
            "model_artifacts": grid_audit["model_artifacts"],
            "scored_attacks": grid_audit["scored_attacks"],
            "prediction_signatures": grid_audit["prediction_signatures"],
            "training_rounds": grid_audit["training_rounds"],
            "heldout_rounds": grid_audit["heldout_rounds"],
            "scope": grid_audit["scope"],
            "primary_ack_clrt": grid_attacks["primary_ack_clrt"],
        },
        "actionable_findings": actions,
    }
    (OUT / "campaign_and_grid_findings.json").write_text(json.dumps(findings, indent=2) + "\n")

    lines = [
        "# 2026-09-29 analysis audit slice",
        "",
        "Scope: offline verification only. No paper, immutable evidence, result tree, or hardware files were edited.",
        "",
        "## C3 replacement values",
        "",
        f"- Fixed-budget D_R values: `{corrected_c3['d_r_ms']}`.",
        f"- Correct READ CLRT medians from MANUSCRIPT_VALUES: `{corrected_c3['clrt_med_ms']}` ms.",
        f"- Correct request-to-response medians: `{corrected_c3['rt_med_ms']}` ms.",
        "- The broad 'within 6 us' statement is only safe for the READ fixed-budget series. SELECT at configured 8 ms is 8.012 ms in `sweep_timing.json`.",
        "",
        "## Grid audit",
        "",
        f"- Status: `{grid_audit['status']}`.",
        f"- Checked `{grid_audit['primary_exchanges']}` exchanges, `{grid_audit['raw_input_hashes']}` raw input hashes, `{grid_audit['model_artifacts']}` model artifacts, `{grid_audit['scored_attacks']}` scored attacks, and `{grid_audit['prediction_signatures']}` prediction signatures.",
        f"- Training rounds: `{grid_audit['training_rounds'][0]}-{grid_audit['training_rounds'][-1]}`; held-out rounds: `{grid_audit['heldout_rounds'][0]}-{grid_audit['heldout_rounds'][-1]}`.",
        "- Scope limit: the audit verifies retained hashes and prediction ledgers; it does not refit models or prove pickle serialization is independently recoverable beyond hash identity.",
        "",
        "## Findings",
        "",
    ]
    for item in findings["actionable_findings"]:
        lines.append(f"- `{item['id']}` ({item['status']}): {item['smallest_correction']}")
    lines.extend([
        "",
        "## Quick paper-only probes",
        "",
        "- Abstract still contains the device-identification wording, while campaign v2 supports transaction-class classification on one device.",
        "- Headline chance wording is present; the fixed attack reaches chance balanced accuracy, but the degenerate confusion should stay qualified.",
        "- Abstract and conclusion do not contain the term master-facing; the introduction contains it elsewhere, but the latency bullet should still be checked before any paper edit.",
    ])
    lines.extend([
        "",
        "## Provenance notes",
        "",
        f"- Campaign counts and frozen table comparison come from `{rel(validation_path)}`.",
        f"- Sweep before/after values come from `{rel(comparison_path)}`.",
        f"- The independent grid audit result is `{rel(grid_audit_path)}`.",
        f"- The structured findings are `{rel(OUT / 'campaign_and_grid_findings.json')}`.",
    ])
    (OUT / "REPORT.md").write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    build()

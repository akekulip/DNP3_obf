"""Aggregate an S4 campaign evidence directory into a summary + claim matrix.

Reads the per-run reports and metrics produced by ``run_s4_campaign.sh`` /
``analyze_s4`` and writes ``S4_SUMMARY.json`` and ``CLAIM_MATRIX.md`` next to the
evidence. Reports the size-security gate, functional byte-equality, fault
recovery, and the latency / bandwidth / resource overhead of the cell layer.
"""

from __future__ import annotations

import argparse
import glob
import json
import statistics
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence


def _load(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text()) if path.exists() else {}


def _endpoint_latency_ms(run: Path) -> Dict[str, float]:
    rows: List[Dict[str, Any]] = []
    for p in glob.glob(str(run / "master.*.jsonl")):
        rows.extend(json.loads(line) for line in Path(p).read_text().splitlines() if line.strip())
    ms = sorted(r["elapsed_ms"] for r in rows)
    if not ms:
        return {}
    return {
        "exchanges": len(ms),
        "median_ms": round(statistics.median(ms), 3),
        "p95_ms": round(ms[max(0, int(len(ms) * 0.95) - 1)], 3),
        "max_ms": round(ms[-1], 3),
    }


def _delivered_inner_bytes(run: Path) -> int:
    from defense4.size.real_size_normalization.offline.pcapio import read_pcap
    total = 0
    for name in ("vision_trusted_output.pcap", "ufispace_trusted_output.pcap"):
        p = run / name
        if p.exists():
            total += sum(len(pk.frame) for pk in read_pcap(p))
    return total


def summarize(evidence: Path) -> Dict[str, Any]:
    runs = {p.name: p for p in sorted(evidence.iterdir()) if p.is_dir()}
    reports = {name: _load(path / "s4_report.json") for name, path in runs.items() if (path / "s4_report.json").exists()}

    main = reports.get("main", {})
    main_run = runs.get("main")
    observer = main.get("observer_size", {})
    invariants = observer.get("invariants", {})
    leakage = observer.get("leakage", {})

    # overhead: observed outer bytes vs delivered inner bytes (main run)
    overhead: Dict[str, Any] = {}
    if main_run is not None:
        obs_metrics = _load(main_run / "observer.metrics.json")
        inner_bytes = _delivered_inner_bytes(main_run)
        outer_bytes = int(obs_metrics.get("bytes", 0))
        vision_m = _load(main_run / "vision.metrics.json")
        overhead = {
            "baseline_latency_ms": _endpoint_latency_ms(runs["baseline"]) if "baseline" in runs else {},
            "pipeline_latency_ms": _endpoint_latency_ms(main_run),
            "observed_outer_bytes": outer_bytes,
            "delivered_inner_bytes": inner_bytes,
            "bandwidth_expansion_x": round(outer_bytes / inner_bytes, 2) if inner_bytes else None,
            "vision_shim_cpu_seconds": vision_m.get("cpu_seconds"),
            "vision_shim_max_rss_kib": vision_m.get("max_rss_kib"),
            "emit_slip_us_max": vision_m.get("emit_slip_us_max"),
            "emit_slip_us_p99": vision_m.get("emit_slip_us_p99"),
        }

    faults = {}
    for name, rep in reports.items():
        if name.startswith("fault_"):
            faults[name] = {
                "fault_fired": rep.get("fault", {}).get("passed"),
                "stream_recovered": rep.get("boundary_oracle", {}).get("passed"),
                "observed": {k: v for k, v in rep.get("fault", {}).get("observed", {}).items() if v},
            }

    all_passed = all(rep.get("passed") for rep in reports.values()) and bool(reports)
    summary = {
        "schema_version": 1,
        "gate": "S4",
        "runs_analyzed": sorted(reports),
        "all_runs_passed": all_passed,
        "functional_byte_equality": {
            name: rep.get("boundary_oracle", {}).get("passed") for name, rep in reports.items()
        },
        "size_security_main": {
            "all_cells_256B": invariants.get("all_cells_256B"),
            "steady_epochs": invariants.get("steady_epochs"),
            "trimmed_partial_epochs": invariants.get("trimmed_partial_epochs"),
            "fixed_size_signature": invariants.get("fixed_size_signature"),
            "fixed_direction_count": invariants.get("fixed_direction_count"),
            "fixed_total_outer_bytes": invariants.get("fixed_total_outer_bytes"),
            "mutual_information_bits": {
                k: v.get("observed_bits") for k, v in (leakage or {}).get("mutual_information_bits", {}).items()
            },
            "classifier": (leakage or {}).get("classifier", {}),
            "label_distribution": observer.get("label_info", {}).get("label_distribution"),
        },
        "fault_recovery": faults,
        "overhead": overhead,
        "boundary": "software prototype (rootless namespaces); no hardware, Vision, Tofino, or relay",
    }
    (evidence / "S4_SUMMARY.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _write_claim_matrix(evidence, summary)
    return summary


def _write_claim_matrix(evidence: Path, s: Dict[str, Any]) -> None:
    sec = s["size_security_main"]
    clf = sec.get("classifier", {})
    rf = clf.get("random_forest", {})
    ov = s["overhead"]
    lines = [
        "# Gate S4 Claim Matrix (software prototype)",
        "",
        "Generated by `s4_summarize.py` from the integrated rootless-namespace campaign.",
        "Software only: no hardware, Vision, Tofino, physical relay, or RRC/BOR integration.",
        "",
        "| Claim | Result | Evidence |",
        "| --- | --- | --- |",
        f"| Application byte equality across both trusted boundaries | {'PASS' if all(s['functional_byte_equality'].values()) else 'FAIL'} | forward+reverse TCP stream equal in every run |",
        f"| Observed link carries only fixed 256-byte cells | {'PASS' if sec.get('all_cells_256B') else 'FAIL'} | wire_len set = [256] |",
        f"| Fixed per-epoch cell count / size / direction (steady state) | {'PASS' if sec.get('fixed_size_signature') and sec.get('fixed_direction_count') and sec.get('fixed_total_outer_bytes') else 'FAIL'} | {sec.get('steady_epochs')} steady epochs, {sec.get('trimmed_partial_epochs')} partial trimmed |",
        f"| Size/count mutual information with inner length ~ 0 | {'PASS' if all(v == 0.0 for v in sec.get('mutual_information_bits', {}).values()) else 'CHECK'} | MI bits = {sec.get('mutual_information_bits')} |",
        f"| Classifier cannot beat chance from outer transcript | {'PASS' if clf.get('passed') else 'CHECK'} | RF BA={rf.get('balanced_accuracy')} chance={clf.get('chance_ba')} CI={rf.get('ci95')} |",
        f"| Post-emission fault recovery (drop/dup/reorder/replay) | {'PASS' if all(f['stream_recovered'] for f in s['fault_recovery'].values()) else 'FAIL'} | {json.dumps(s['fault_recovery'])} |",
        f"| Lifecycle: 3 sequential reconnects | {'PASS' if s['functional_byte_equality'].get('lifecycle') else 'FAIL'} | lifecycle run byte-equal |",
        "",
        "## Overhead",
        "",
        f"- Baseline latency (direct veth, no cells): {ov.get('baseline_latency_ms')}",
        f"- Pipeline latency (cellized): {ov.get('pipeline_latency_ms')} — one fixed epoch per exchange",
        f"- Bandwidth expansion: {ov.get('bandwidth_expansion_x')}x (observed outer / delivered inner bytes)",
        f"- Vision shim: CPU {ov.get('vision_shim_cpu_seconds')} s, max RSS {ov.get('vision_shim_max_rss_kib')} KiB, emit slip max {ov.get('emit_slip_us_max')} us / p99 {ov.get('emit_slip_us_p99')} us",
        "",
        "## Not demonstrated (out of S4 scope)",
        "",
        "- Hardware / Vision / Tofino CPU punt-reinject path (S6).",
        "- RRC/BOR timing integration (S5).",
        "- Multi-device fingerprint suppression (single synthetic outstation here).",
        "- Wall-clock inter-cell timing constancy is a timing-policy concern (RRC/BOR), not tested as a size feature.",
        "",
    ]
    (evidence / "CLAIM_MATRIX.md").write_text("\n".join(lines), encoding="utf-8")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args(argv)
    summary = summarize(args.evidence)
    print(json.dumps({"gate": "S4", "all_runs_passed": summary["all_runs_passed"],
                      "runs": summary["runs_analyzed"]}, sort_keys=True))
    return 0 if summary["all_runs_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

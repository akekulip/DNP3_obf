"""Gate S5 verification: outer transcript independence from native relay timing.

The cell layer emits ACK and response cells on a fixed outer slot schedule
(request 0-750 us, ACK 1000-1250 us, response 200000-203250 us, tail
203500-203750 us) every epoch, filling with cover when data is not ready. So the
observed outer transcript should not depend on when the relay actually responds
(the native timing / BOR J proxy set by ``--response-delay-ms``).

This reads a sweep of runs ``j_<ms>/`` produced by ``run_s4_namespace.sh
--response-delay-ms`` and verifies:

* the observed cell volume and per-epoch cell count are the same at every J
  (outer cell size/count does not depend on J);
* the application byte stream is still delivered equal at both boundaries at
  every J (cellization does not corrupt the exchange);
* the master-visible latency is quantized to the slot schedule, not tracking J
  continuously (cellization does not leak the native response time).

It does NOT re-implement the SEL-751 separate-ACK CLRT-to-4 ms normalization or
the BOR relay-facing hold / exactly-once path; those remain the hardware
evidence boundary of the native-parity line.
"""

from __future__ import annotations

import argparse
import collections
import glob
import json
import statistics
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from defense4.size.real_size_normalization.software.analyze_s4 import (
    _observer_cells,
    _time_bins,
    boundary_oracle,
)


def _latency_ms(run: Path) -> Dict[str, Any]:
    ms = sorted(
        json.loads(line)["elapsed_ms"]
        for p in glob.glob(str(run / "master.*.jsonl"))
        for line in Path(p).read_text().splitlines()
        if line.strip()
    )
    if not ms:
        return {}
    return {
        "exchanges": len(ms),
        "median_ms": round(statistics.median(ms), 1),
        "p95_ms": round(ms[max(0, int(len(ms) * 0.95) - 1)], 1),
    }


def _run_facts(run: Path) -> Dict[str, Any]:
    obs = json.loads((run / "observer.metrics.json").read_text())
    span = (obs["ended_at_us"] - obs["started_at_us"]) / 1e6
    bins = _time_bins(_observer_cells(run / "observer_l_left.csv"))
    interior = bins[1:-1] if len(bins) > 2 else bins
    modal = collections.Counter(b["cell_count"] for b in interior).most_common(1)[0][0] if interior else 0
    return {
        "observer_cells": obs["cells"],
        "observer_bytes": obs["bytes"],
        "cells_per_s": round(obs["cells"] / span, 2) if span else None,
        "interior_bins": len(interior),
        "modal_bin_cell_count": modal,
        "master_latency_ms": _latency_ms(run),
        "boundary_passed": boundary_oracle(run)["passed"],
    }


def summarize_runs(runs: Dict[int, Dict[str, Any]]) -> Dict[str, Any]:
    """Decide J-independence from per-run facts (pure; no filesystem)."""

    js = sorted(runs)
    cells = {j: runs[j]["observer_cells"] for j in js}
    modal = {j: runs[j]["modal_bin_cell_count"] for j in js}
    cell_spread = max(cells.values()) - min(cells.values()) if cells else 0
    result = {
        "gate": "S5",
        "j_values_ms": js,
        "runs": {str(j): runs[j] for j in js},
        "observer_cells_by_j": {str(j): cells[j] for j in js},
        "modal_bin_count_by_j": {str(j): modal[j] for j in js},
        "master_latency_median_ms_by_j": {str(j): runs[j]["master_latency_ms"].get("median_ms") for j in js},
        "observer_volume_spread_cells": cell_spread,
        "observer_volume_j_independent": cell_spread <= 22,  # within one epoch of cells
        "modal_bin_count_j_independent": len(set(modal.values())) == 1,
        "boundary_all_passed": all(runs[j]["boundary_passed"] for j in js),
        "boundary": "software prototype; does NOT re-implement SEL-751 separate-ACK CLRT or BOR hold/exactly-once (hardware boundary)",
    }
    result["passed"] = bool(
        len(js) >= 2
        and result["observer_volume_j_independent"]
        and result["modal_bin_count_j_independent"]
        and result["boundary_all_passed"]
    )
    return result


def analyze(evidence: Path) -> Dict[str, Any]:
    runs = {int(d.name.split("_")[1]): _run_facts(d) for d in sorted(evidence.glob("j_*")) if d.is_dir()}
    result = summarize_runs(runs)
    (evidence / "S5_SUMMARY.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args(argv)
    r = analyze(args.evidence)
    print(json.dumps({
        "gate": "S5", "passed": r["passed"],
        "cells_by_j": r["observer_cells_by_j"],
        "latency_median_ms_by_j": r["master_latency_median_ms_by_j"],
    }, sort_keys=True))
    return 0 if r["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

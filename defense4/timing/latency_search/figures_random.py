#!/usr/bin/env python3
"""Plot selected and observed timing from validated randomized acquisitions."""
import argparse
import csv
import json
from pathlib import Path

import figures as shared
from matplotlib.ticker import LogLocator, FuncFormatter

plt = shared.plt
np = shared.np
OPS = shared.OPS
METRICS = (("selected_da_ms", "ack_ms", "ACK delay (ms)"),
           ("selected_gap_ms", "clrt_ms", "ACK-to-response gap (ms)"))


def load_inputs(measurements, transactions, policy, preview=False):
    doc = json.loads(measurements.read_text())
    if doc.get("status") != "ok" and not preview:
        raise ValueError("incomplete acquisition requires --preview")
    if shared.sha256_file(transactions) != doc.get("primary_csv_sha256"):
        raise ValueError("transaction CSV does not match validated measurements")
    with transactions.open(newline="") as handle:
        all_rows = list(csv.DictReader(handle))
    if len(all_rows) != doc["row_count"]:
        raise ValueError("transaction count differs from measurements")
    rows = [r for r in all_rows if r["policy_name"] == policy and r["arm"] == "obfuscated"]
    if not rows or policy not in doc["policies"]:
        raise ValueError("policy missing from validated primary exchanges")
    if not preview and len({r["session"] for r in rows}) < 5:
        raise ValueError("fewer than five repetitions requires --preview")
    if len(rows) != doc["policies"][policy]["n_exchanges"]:
        raise ValueError("policy exchange count mismatch")
    for op in OPS:
        subset = [r for r in rows if r["txn_class"] == op]
        if len(subset) < 2:
            raise ValueError("missing operation or insufficient variance samples: " + op)
        for row in subset:
            for key in ("selected_da_ms", "selected_gap_ms", "selected_r_ms",
                        "ack_ms", "clrt_ms", "rt_ms"):
                if not np.isfinite(float(row[key])):
                    raise ValueError("nonfinite or missing timing: " + key)
    return doc, rows


def ecdf(values):
    values = np.sort(np.asarray(values, dtype=float))
    # Repeated x coordinates preserve the jump at the smallest observed value.
    return np.r_[values[0], values], np.r_[0., np.arange(1, len(values)+1)/len(values)]


def stats_rows(rows):
    result = []
    for op in OPS:
        subset = [r for r in rows if r["txn_class"] == op]
        for key in ("selected_da_ms", "selected_gap_ms", "selected_r_ms",
                    "ack_ms", "clrt_ms", "rt_ms"):
            values = np.array([float(r[key]) for r in subset])
            result.append(dict(operation=op, metric=key, n=len(values),
                               mean_ms=float(np.mean(values)), median_ms=float(np.median(values)),
                               p99_ms=float(np.percentile(values, 99)),
                               min_ms=float(np.min(values)), max_ms=float(np.max(values)),
                               sample_variance_ms2=float(np.var(values, ddof=1))))
    return result


def check(outdir):
    provenance = json.loads((outdir/"timing_realization.provenance.json").read_text())
    problems = []
    for name, expected in provenance["inputs_and_code"].items():
        path = Path(name)
        if not path.is_file() or shared.sha256_file(path) != expected:
            problems.append("changed/missing source: " + name)
    for line in (outdir/"FIGURES.sha256").read_text().splitlines():
        expected, name = line.split("  ", 1)
        path = outdir/name
        if not path.is_file() or shared.sha256_file(path) != expected:
            problems.append("changed/missing output: " + name)
    return problems


def generate(measurements, transactions, policy, outdir, preview=False):
    doc, rows = load_inputs(measurements, transactions, policy, preview)
    outdir.mkdir(parents=True, exist_ok=True)
    shared.set_style()
    fig, axes = plt.subplots(2, 3, figsize=(7.16, 3.65), sharey=True)
    for i, (selected, observed, label) in enumerate(METRICS):
        all_values = [float(r[k]) for r in rows for k in (selected, observed)]
        lo, hi = min(all_values), max(all_values)
        pad = max((hi-lo)*.035, .05)
        for j, op in enumerate(OPS):
            ax = axes[i, j]
            subset = [r for r in rows if r["txn_class"] == op]
            for key, color, linestyle in ((selected, "#666666", "--"),
                                           (observed, "#0072B2", "-")):
                x, y = ecdf([float(r[key]) for r in subset])
                ax.step(x, y, where="post", color=color, linestyle=linestyle, linewidth=1.)
            if i == 1 and lo > 0:
                ax.set_xscale("log")
                ax.set_xlim(lo/1.12, hi*1.12)
                ax.xaxis.set_major_locator(LogLocator(base=10, subs=(1, 2, 5)))
                ax.xaxis.set_major_formatter(FuncFormatter(lambda value, _: f"{value:g}"))
                ax.minorticks_off()
            else:
                ax.set_xlim(lo-pad, hi+pad)
            ax.set_ylim(0, 1.025)
            ax.set_yticks([0, .5, 1])
            ax.set_xlabel("CLRT (ms; log scale)" if i == 1 and lo > 0 else label)
            if i == 0:
                ax.set_title(op)
            if j == 0:
                ax.set_ylabel("Cumulative fraction")
            ax.spines[["top", "right"]].set_visible(False)
            ax.grid(axis="y", color=".88", linewidth=.5)
    fig.subplots_adjust(left=.075, right=.985, bottom=.13, top=.83,
                        wspace=.23, hspace=.52)
    # Key lives in reserved figure margin, never over observations.
    fig.text(.5, .94, ("PREVIEW — " if preview else "") + "Selected and observed timing",
             ha="center", fontsize=9)
    fig.text(.5, .875, "Solid: observed packet timing     Dashed: selected deadline or gap",
             ha="center", fontsize=8.5)
    stem = "timing_realization"
    outputs = []
    for ext in ("pdf", "png"):
        path = outdir/(stem+"."+ext)
        fig.savefig(path, dpi=300)
        outputs.append(path)
    plt.close(fig)
    raw = outdir/(stem+".exchanges.csv")
    shared._write_csv(raw, rows, list(rows[0]))
    outputs.append(raw)
    stats = stats_rows(rows)
    path = outdir/(stem+".statistics.csv")
    shared._write_csv(path, stats, list(stats[0]))
    outputs.append(path)
    n = {op: sum(r["txn_class"] == op for r in rows) for op in OPS}
    texts = {
        "caption": (f"Selected and observed timing for {policy}. Each column is one operation; "
                    "the rows show request-to-ACK delay and ACK-to-response gap. "
                    "Dashed curves use the actual per-request hardware selections, not the "
                    "nominal uniform distribution. Solid curves use master-side packet timestamps. "
                    "Axes within each row share the full observed range, including late responses. "
                    "The gap axis is logarithmic when all gaps are positive. "
                    f"Primary exchange counts: {n}."),
        "method": ("Input CSV is hash-matched to the acquisition summary. Only primary protected "
                   "exchanges of the named policy enter the empirical CDFs and sample statistics; "
                   "safety polls are absent from the primary CSV. Sample variance uses n−1; "
                   "p99 uses NumPy's linear percentile interpolation. Selected offsets and observed "
                   "packet timings use distinct columns and are never substituted for one another. "
                   "The policy is explicitly supplied by the caller; this plot performs no selection."),
        "limitations": ("This figure does not establish resistance to fixed or adaptive classification. "
                        "Timing variance can include native response variability and queueing effects; "
                        "it is not all intentionally added variance. The selected deadline and blocker J "
                        "share the hardware random byte. These CDFs do not assert independent draws. "
                        + ("PREVIEW: pilot or incomplete acquisition; not a final study result." if preview
                           else "This is development acquisition; independent confirmation is separate."))}
    outputs.extend(shared._write_text_sidecars(outdir, stem, texts))
    sources = [measurements.resolve(), transactions.resolve(), Path(__file__).resolve(),
               Path(shared.__file__).resolve()]
    outputs.append(shared._write_provenance(outdir, stem, dict(
        policy=policy, preview=preview, summary_status=doc["status"], counts=n,
        matplotlib_version=shared.matplotlib.__version__, numpy_version=np.__version__,
        inputs_and_code={str(p):shared.sha256_file(p) for p in sources})))
    shared.write_figures_sha256(outdir, outputs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--measurements", type=Path)
    parser.add_argument("--transactions", type=Path)
    parser.add_argument("--policy")
    parser.add_argument("--outdir", type=Path, required=True)
    parser.add_argument("--preview", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        problems = check(args.outdir)
        print(json.dumps({"status":"mismatch" if problems else "ok", "problems":problems}))
        raise SystemExit(bool(problems))
    if not all((args.measurements, args.transactions, args.policy)):
        parser.error("generation requires --measurements, --transactions, and --policy")
    generate(args.measurements, args.transactions, args.policy, args.outdir, args.preview)


if __name__ == "__main__":
    main()

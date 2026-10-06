"""Per-transaction table, statistics, per-bin CSV, figure and provenance for the BMv2 CLRT populations.

CLRT is read from the master-facing capture: response arrival minus ACK arrival at the master port, per transaction, paired by the
TCP acknowledgment number. Software (BMv2) timing; not Tofino line-rate evidence. Usage: clrt_figure.py RESULTS_DIR OUT_DIR
"""
import csv
import hashlib
import json
import platform
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent))
import stats  # noqa: E402

ARMS = [("timing_off", "Timing OFF"), ("response_ready", "Response-ready")]
EDGES = [i * 0.25 for i in range(0, 49)]            # declared once: 0.25 ms bins, 0 to 12 ms, identical in every panel
TARGET = (0.7, 1.3)                                  # configured CLRT_new 1.0 ms +/- 0.3 ms, the software tolerance in the tests


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load(res, arm):
    d = json.loads((Path(res) / (arm + ".json")).read_text())
    rows = []
    for i, t in enumerate(d["txns"]):
        ok = d["outcomes"][i] == "OK" and t["e_A"] and t["e_R"]
        rows.append({"index": i, "outcome": d["outcomes"][i], "clrt_ms": (t["e_R"] - t["e_A"]) / 1e6 if ok else "",
                     "request_to_ack_ms": (t["e_A"] - t["t_req"]) / 1e6 if ok else "",
                     "native_response_ms": (t["t_R"] - t["t_req"]) / 1e6 if t["t_R"] else ""})
    return d, rows


def main(res, out):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    plt.rcParams.update({"font.family": "serif", "font.serif": ["Times New Roman", "DejaVu Serif"], "font.size": 8,
                         "axes.linewidth": 0.6, "pdf.fonttype": 42})
    fig, axes = plt.subplots(len(ARMS), 1, figsize=(3.5, 3.0), sharex=True, sharey=True)
    summary, hist_rows, prov_in, sigs = {}, [], {}, {}
    for ax, (arm, label) in zip(axes, ARMS):
        d, rows = load(res, arm)
        prov_in[arm] = sha(Path(res) / (arm + ".json"))
        with open(out / (arm + "_transactions.csv"), "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0]))
            w.writeheader()
            w.writerows(rows)
        vals = [r["clrt_ms"] for r in rows if r["clrt_ms"] != ""]
        attempted = len(rows)
        s = stats.summarize(vals, attempted=attempted)
        s["window"] = stats.window_fraction(vals, TARGET[0], TARGET[1], attempted)
        s["window"]["lo_ms"], s["window"]["hi_ms"] = TARGET
        s["outcomes"] = {o: d["outcomes"].count(o) for o in set(d["outcomes"])}
        s["variance_unit"] = "ms^2"; s["clrt_unit"] = "ms"
        summary[arm] = s
        h = stats.histogram(vals, EDGES, attempted)
        for i, (c, p) in enumerate(zip(h["counts"], h["percent"])):
            hist_rows.append({"arm": arm, "bin_lo_ms": EDGES[i], "bin_hi_ms": EDGES[i + 1], "count": c, "percent_of_attempted": p})
        sig = stats.formby_signature(vals, H=15.0, B=200)
        s["formby_signature"] = {k: sig[k] for k in ("bin_width", "H", "B", "exactly_H_uncounted")}
        sigs[arm] = sig["signature"]
        s["outside_plotted_range"] = {"below": h["below"], "above": h["above"]}
        ax.bar(EDGES[:-1], h["percent"], width=0.25, align="edge", color="0.25", edgecolor="white", linewidth=0.2)
        ax.set_ylim(0, 100)
        ax.text(0.98, 0.9, label, transform=ax.transAxes, ha="right", va="top", fontsize=8)
        ax.set_ylabel("Transactions (%)")
        for side in ("top", "right"):
            ax.spines[side].set_visible(False)
    axes[-1].set_xlim(EDGES[0], EDGES[-1])
    axes[-1].set_xlabel("CLRT (ms)")
    fig.tight_layout(pad=0.4)
    fig.savefig(out / "fig_bmv2_clrt.pdf")
    fig.savefig(out / "fig_bmv2_clrt.png", dpi=600)
    with open(out / "fig_bmv2_clrt_bins.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(hist_rows[0]))
        w.writeheader()
        w.writerows(hist_rows)
    with open(out / "formby_signature_B200_H15.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["element"] + list(sigs))
        for j in range(200):
            w.writerow([j + 1] + [sigs[a][j] for a in sigs])
    (out / "stats.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    prov = {"figure": "fig_bmv2_clrt", "software_timing_note": "BMv2 software timing; not Tofino line-rate evidence",
            "inputs_sha256": prov_in, "bin_edges_ms": [EDGES[0], EDGES[-1], 0.25], "denominator": "all attempted transactions per arm",
            "target_window_ms": list(TARGET), "display_bins": "0.25 ms, a display choice for a readable figure", "formby_feature_vector": "B=200, H=15 ms declared (the paper leaves H a heuristic), Eq. (1) of Formby et al. NDSS 2016: B-1 bins of width H/(B-1) plus an overflow element for m > H", "width_in": 3.5, "environment": {"python": platform.python_version(),
            "matplotlib": matplotlib.__version__}, "outputs_sha256": {p.name: sha(p) for p in sorted(out.iterdir()) if p.suffix in (".csv", ".json", ".pdf") and p.name != "provenance.json"}}
    (out / "provenance.json").write_text(json.dumps(prov, indent=2, sort_keys=True) + "\n")
    return summary


if __name__ == "__main__":
    s = main(sys.argv[1], sys.argv[2])
    for arm, v in s.items():
        print(arm, {k: (round(x, 3) if isinstance(x, float) else x) for k, x in v.items() if k in ("n", "median", "iqr", "sd_sample", "variance_sample", "p99", "max", "completion_rate")}, "window", v["window"]["inside"], "/", v["window"]["denominator"])

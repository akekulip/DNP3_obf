#!/usr/bin/env python3
"""Compare randomized-policy latency with complete grouped attack results."""
import argparse
import json
from pathlib import Path

import figures as shared
import figures_random
import evaluate_random

plt, np = shared.plt, shared.np
TASKS = ("three_class", "read_select")
KINDS = ("gap", "joint", "control")


def build_rows(measurements, transactions, attacks_path):
    doc = json.loads(measurements.read_text())
    attacks = json.loads(attacks_path.read_text())
    source_hash = shared.sha256_file(transactions)
    if doc.get("status") != "ok" or doc.get("primary_csv_sha256") != source_hash:
        raise ValueError("requires completed, hash-matched acquisition")
    if (attacks.get("source_sha256") != source_hash or
            attacks.get("measurements_sha256") != shared.sha256_file(measurements)):
        raise ValueError("attack results do not match measurement inputs")
    if attacks.get("quick") or not attacks.get("complete_attack_coverage"):
        raise ValueError("requires full attack evaluation")
    raw = evaluate_random.base.read_rows(transactions)
    if len(raw) != doc["row_count"]:
        raise ValueError("transaction count mismatch")
    names = {r["policy_name"] for r in raw if r["arm"] == "obfuscated"}
    if names != set(attacks["per_policy"]):
        raise ValueError("attack-policy coverage mismatch")
    result = []
    for name in sorted(names):
        entry = attacks["per_policy"][name]
        if entry.get("quick") or not entry.get("complete_attack_coverage"):
            raise ValueError("partial policy attack results: " + name)
        paired, chosen = evaluate_random.paired_rows(raw, name)
        if chosen != attacks["off_pairing"][name]:
            raise ValueError("OFF pairing differs from evaluated comparison")
        if len(chosen) != 5:
            raise ValueError("random screen requires five paired repetitions")
        # Read the installed plan from its hash-bound acquisition inputs.
        matches = [Path(p) for p in doc["inputs_sha256"]
                   if Path(p).parent.name == "plans" and Path(p).stem == name]
        if len(matches) != 1:
            raise ValueError("missing or ambiguous installed plan for " + name)
        plan_path = matches[0]
        if shared.sha256_file(plan_path) != doc["inputs_sha256"][str(plan_path)]:
            raise ValueError("installed plan changed")
        plan = json.loads(plan_path.read_text())
        kind = "control" if plan["amplitude_ms"] == 0 else plan["mode"]
        if kind not in KINDS:
            raise ValueError("unknown policy kind")
        for task in TASKS:
            operations = shared.OPS if task == "three_class" else ("READ", "SELECT")
            medians = {}
            for op in operations:
                native = [r["rt_ms"] for r in paired if r["arm"] == "native" and r["txn_class"] == op]
                protected = [r["rt_ms"] for r in paired if r["arm"] == "obfuscated" and r["txn_class"] == op]
                if len(native) != 500 or len(protected) != 500:
                    raise ValueError("incomplete operation counts")
                medians[op] = dict(added=float(np.median(protected)-np.median(native)),
                                   total=float(np.median(protected)),
                                   p99=float(np.percentile(protected, 99)),
                                   off=float(np.median(native)))
            worst = max(medians, key=lambda op:medians[op]["added"])
            data = entry["tasks"][task]
            for family in ("ack_response", "all_timing"):
                envelope = data["envelopes"][family]
                accuracy, upper = envelope["max_accuracy"], envelope["upper_bound"]
                if not 0 <= accuracy <= upper <= 1:
                    raise ValueError("invalid accuracy/bound")
                result.append(dict(policy=name, kind=kind, task=task, family=family,
                    da_center_ms=plan["center_da_ms"], gap_center_ms=plan["center_gap_ms"],
                    amplitude_ms=plan["amplitude_ms"], added_median_ms=medians[worst]["added"],
                    added_operation=worst, protected_median_at_added_operation_ms=medians[worst]["total"],
                    off_median_at_added_operation_ms=medians[worst]["off"],
                    worst_total_median_ms=max(m["total"] for m in medians.values()),
                    worst_p99_ms=max(m["p99"] for m in medians.values()),
                    max_accuracy=accuracy, upper_bound=upper, chance=data["chance"],
                    threshold=data["threshold"], passes_family=envelope["passes_screen"],
                    qualifies_for_selection=entry["qualifies_for_selection"]))
    return result


def plot(rows, family, outdir):
    shared.set_style()
    fig, axes = plt.subplots(2, 3, figsize=(7.16, 4.4), sharex=True, sharey=True)
    selected = [r for r in rows if r["family"] == family]
    xmin = min(r["added_median_ms"] for r in selected)
    xmax = max(r["added_median_ms"] for r in selected)
    pad = max(.5, (xmax-xmin)*.05)
    for i, task in enumerate(TASKS):
        for j, kind in enumerate(KINDS):
            ax = axes[i, j]
            subset = [r for r in selected if r["task"] == task and r["kind"] == kind]
            task_rows = [r for r in selected if r["task"] == task]
            for key, style in (("chance", ":"), ("threshold", "--")):
                ax.axhline(task_rows[0][key], color=".5", linewidth=.7, linestyle=style)
            for row in subset:
                ax.errorbar(row["added_median_ms"], row["max_accuracy"],
                    yerr=[[0], [row["upper_bound"]-row["max_accuracy"]]],
                    fmt="o", color="#0072B2", markersize=3.2, capsize=1.5,
                    elinewidth=.65, markeredgewidth=.6, alpha=.8)
            if i == 0:
                ax.set_title({"gap":"Gap only", "joint":"Joint ACK and gap", "control":"Fixed controls"}[kind])
            if j == 0:
                ax.set_ylabel(("Three classes" if task == "three_class" else "READ / SELECT")+
                              "\nMaximum balanced accuracy")
            if i == 1:
                ax.set_xlabel("Added median latency (ms)")
            ax.set_xlim(xmin-pad, xmax+pad)
            ax.set_ylim(0, 1.035)
            ax.set_yticks([0, .25, .5, .75, 1])
            ax.spines[["top", "right"]].set_visible(False)
            ax.grid(axis="y", color=".9", linewidth=.5)
    fig.suptitle("ACK/CLRT attacks" if family == "ack_response" else "Attacks including request spacing",
                 fontsize=10, y=.97)
    fig.subplots_adjust(left=.11, right=.99, bottom=.12, top=.865, wspace=.18, hspace=.22)
    stem = "random_tradeoff_" + family
    outputs = []
    for ext in ("pdf", "png"):
        path = outdir/(stem+"."+ext)
        fig.savefig(path, dpi=300)
        outputs.append(path)
    plt.close(fig)
    return outputs


def generate(measurements, transactions, attacks, outdir):
    rows = build_rows(measurements, transactions, attacks)
    outdir.mkdir(parents=True, exist_ok=True)
    outputs = []
    for family in ("ack_response", "all_timing"):
        outputs.extend(plot(rows, family, outdir))
    path = outdir/"random_tradeoffs.csv"
    shared._write_csv(path, rows, list(rows[0]))
    outputs.append(path)
    outputs.extend(shared._write_text_sidecars(outdir, "random_tradeoffs", {
        "caption": "Latency and classifier accuracy for randomized policies and zero-amplitude controls. "
        "Each point is the maximum balanced accuracy over the declared fixed and adaptive attacks; "
        "its upward bar reaches the simultaneous development upper bound. Dotted lines mark chance "
        "and dashed lines mark chance plus 0.05. ACK/CLRT and all-timing attacks appear in separate figures.",
        "method": "For each policy, select the same nearest OFF block per repetition used by the attack "
        "evaluation. For each operation, subtract the median of those pooled OFF exchanges from the "
        "protected median; plot the largest difference over the task's operations. The table separately "
        "records worst-operation total median and p99. All five repetitions and all evaluated policies "
        "must be present. Input hashes, installed plans and OFF pairings are checked before plotting.",
        "limitations": "Five same-session repetitions provide approximate development uncertainty. "
        "A bound exceeding the threshold does not itself establish reliable classification. Selection "
        "requires the full timing criterion in both tasks; passing only ACK/CLRT is insufficient. "
        "No independent confirmation or guarantee against all attackers is implied."}))
    sources = [measurements.resolve(), transactions.resolve(), attacks.resolve(),
               Path(__file__).resolve(), Path(shared.__file__).resolve(),
               Path(evaluate_random.__file__).resolve(), Path(figures_random.__file__).resolve(),
               Path(evaluate_random.base.__file__).resolve()]
    sources.extend(Path(p).resolve() for p in json.loads(measurements.read_text())["inputs_sha256"]
                   if Path(p).parent.name == "plans")
    outputs.append(shared._write_provenance(outdir, "random_tradeoffs", dict(
        inputs_and_code={str(p):shared.sha256_file(p) for p in sources},
        matplotlib_version=shared.matplotlib.__version__, numpy_version=np.__version__)))
    shared.write_figures_sha256(outdir, outputs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("measurements", "transactions", "attacks"):
        parser.add_argument("--"+name, type=Path)
    parser.add_argument("--outdir", type=Path, required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        problems = figures_random.check(args.outdir, "random_tradeoffs")
        print(json.dumps({"problems":problems}))
        raise SystemExit(bool(problems))
    if not all((args.measurements, args.transactions, args.attacks)):
        parser.error("requires all three input files")
    generate(args.measurements, args.transactions, args.attacks, args.outdir)


if __name__ == "__main__":
    main()

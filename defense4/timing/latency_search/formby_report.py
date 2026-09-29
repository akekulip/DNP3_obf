#!/usr/bin/env python3
"""Render the Formby-classifier evaluation as plots and a short explainer PDF."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import sys

os.environ.setdefault("MPLCONFIGDIR", "/tmp/dnp3_formby_mplconfig")
Path(os.environ["MPLCONFIGDIR"]).mkdir(parents=True, exist_ok=True)
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.lines import Line2D
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import letter, landscape
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (Image, PageBreak, Paragraph, SimpleDocTemplate,
                                Spacer, Table, TableStyle)

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
import formby_evaluation as evaluation  # noqa: E402
import formby_tutorial as tutorial  # noqa: E402

COLORS = {"READ": "#0072B2", "SELECT": "#D55E00", "OPERATE": "#009E73"}
MODEL_LABEL = {"ff_ann": "One-hidden-layer FF-ANN", "multinomial_nb": "Multinomial naïve Bayes"}
MODEL_SHORT = {"ff_ann": "FF-ANN", "multinomial_nb": "Naïve Bayes"}
MODEL_COLORS = {"ff_ann": "#0072B2", "multinomial_nb": "#D55E00"}
FEATURE_LABEL = {"ack_clrt": "ACK + CLRT summaries", "formby_histogram": "200-bin CLRT histogram"}
SCENARIO_LABEL = {"static_before": "Static, unobfuscated test",
                  "static_after": "Static, protected test",
                  "adaptive": "Adaptive, protected-only training"}


def _index(summary):
    return {(r["task"], r["feature"], r["model"], r["scenario"], r["policy"], r["pool_size"]): r
            for r in summary["results"]}


def round_metric_tables(summary):
    records = _index(summary)
    overall = [["Classifier", "D_A", "Evaluation", "Mean accuracy", "Min accuracy",
                "Mean recall", "Min recall"]]
    by_class = [["Classifier", "D_A", "Evaluation", "READ recall mean/min",
                 "SBO recall mean/min"]]

    cases = [(None, "native", "static_before", "Native control")]
    cases.extend((policy, policy, scenario, label)
                 for policy in evaluation.POLICIES
                 for scenario, label in (("static_after", "Static on protected"),
                                         ("adaptive", "Adaptive on protected")))
    for policy, result_policy, scenario, label in cases:
        for model in evaluation.MODELS:
            result = records[("read_sbo", "formby_histogram", model, scenario,
                              result_policy, 20)]
            da = "—" if policy is None else policy[2:].split("_", 1)[0]
            overall.append([MODEL_SHORT[model], da, label,
                f"{result['round_mean_accuracy']:.3f}", f"{result['round_min_accuracy']:.3f}",
                f"{result['round_mean_recall']:.3f}", f"{result['round_min_recall']:.3f}"])
            recall_mean = result["round_mean_recall_by_class"]
            recall_min = result["round_min_recall_by_class"]
            by_class.append([MODEL_SHORT[model], da, label,
                f"{recall_mean['READ']:.3f} / {recall_min['READ']:.3f}",
                f"{recall_mean['SBO']:.3f} / {recall_min['SBO']:.3f}"])
    return overall, by_class


def plot_performance(summary, out):
    records = _index(summary)
    policies = evaluation.POLICIES
    delays = [int(policy[2:].split("_", 1)[0]) for policy in policies]
    fig, axes = plt.subplots(2, 2, figsize=(7.1, 4.75), sharex=True, sharey=True)
    task_titles = {"read_sbo": "READ vs SBO", "three_class": "Three operation phases"}
    for row, task in enumerate(("read_sbo", "three_class")):
        for col, feature in enumerate(evaluation.FEATURES):
            ax = axes[row, col]
            for model in evaluation.MODELS:
                color = MODEL_COLORS[model]
                baseline = records[(task, feature, model, "static_before", "native", 20)]
                ax.axhline(baseline["balanced_accuracy"], color=color, linestyle=":",
                           linewidth=1.0, alpha=.75)
                for scenario, linestyle, marker in (("static_after", "--", "o"),
                                                     ("adaptive", "-", "s")):
                    scores = [records[(task, feature, model, scenario, policy, 20)]
                              for policy in policies]
                    y = [r["balanced_accuracy"] for r in scores]
                    lower = [max(0, yv - (r["round_balanced_accuracy_ci95"][0] or yv))
                             for yv, r in zip(y, scores)]
                    upper = [max(0, (r["round_balanced_accuracy_ci95"][1] or yv) - yv)
                             for yv, r in zip(y, scores)]
                    ax.errorbar(delays, y, yerr=[lower, upper], color=color, linestyle=linestyle,
                                marker=marker, markersize=4, linewidth=1.25, capsize=2,
                                label=f"{MODEL_LABEL[model]} · {scenario}")
            classes = evaluation.CLASSES[task]
            ax.axhline(1 / len(classes), color="#555555", linestyle="-.", linewidth=.8)
            ax.set_title(f"{task_titles[task]} · {FEATURE_LABEL[feature]}", fontsize=7.5)
            ax.set_xticks(delays)
            ax.set_ylim(0, 1.02)
            ax.grid(axis="y", color="#dddddd", linewidth=.5)
            ax.spines[["top", "right"]].set_visible(False)
            if row == 1:
                ax.set_xlabel("Configured $D_A$ center (ms)")
            if col == 0:
                ax.set_ylabel("Balanced accuracy")
    legend_handles = [
        Line2D([0], [0], color=MODEL_COLORS["ff_ann"], lw=2, label="FF-ANN"),
        Line2D([0], [0], color=MODEL_COLORS["multinomial_nb"], lw=2, label="Naïve Bayes"),
        Line2D([0], [0], color="#333333", lw=1.2, ls=":", label="Timing OFF baseline"),
        Line2D([0], [0], color="#333333", lw=1.2, ls="--", marker="o", ms=4,
               label="Static: trained OFF, tested protected"),
        Line2D([0], [0], color="#333333", lw=1.2, ls="-", marker="s", ms=4,
               label="Adaptive: trained and tested protected"),
        Line2D([0], [0], color="#555555", lw=.8, ls="-.", label="Chance level"),
    ]
    fig.legend(handles=legend_handles, loc="lower center", ncol=3, frameon=False,
               bbox_to_anchor=(.5, -.015), fontsize=6.5)
    fig.suptitle("Held-out operation classification (pool size 20)", y=.99, fontsize=9)
    fig.tight_layout(rect=(0, .14, 1, .96))
    for ext in ("png", "pdf"):
        fig.savefig(out / f"performance_by_delay.{ext}", dpi=300, bbox_inches="tight")
    plt.close(fig)


def plot_attacker_metrics(summary, out):
    """Render Formby-style mean/min accuracy, precision, and recall by D_A."""
    records = _index(summary)
    policies = evaluation.POLICIES
    x = np.arange(len(policies) + 1)
    tick_labels = ["Native\nreference"] + [
        f"{int(policy[2:].split('_', 1)[0])} ms" for policy in policies]
    metrics = (
        ("accuracy", "Accuracy", "#0072B2", "o"),
        ("precision", "Precision", "#D55E00", "s"),
        ("recall", "Recall", "#009E73", "^"),
    )
    fig, axes = plt.subplots(2, 2, figsize=(7.15, 5.45), sharex=True, sharey=True)
    for row, model in enumerate(evaluation.MODELS):
        for col, (scenario, title) in enumerate((
                ("static_after", "Static: native-trained model"),
                ("adaptive", "Adaptive: protected-only training"))):
            ax = axes[row, col]
            baseline = records[("read_sbo", "formby_histogram", model,
                                "static_before", "native", 20)]
            for metric, label, color, marker in metrics:
                mean_field, min_field = f"round_mean_{metric}", f"round_min_{metric}"
                mean = [baseline[mean_field]]
                minimum = [baseline[min_field]]
                for policy in policies:
                    result = records[("read_sbo", "formby_histogram", model,
                                      scenario, policy, 20)]
                    mean.append(result[mean_field])
                    minimum.append(result[min_field])
                ax.plot(x, np.asarray(mean, dtype=float) * 100, color=color,
                        linestyle="-", marker=marker, markersize=3.5, linewidth=1.1)
                ax.plot(x, np.asarray(minimum, dtype=float) * 100, color=color,
                        linestyle="--", marker=marker, markersize=3.2, linewidth=.95)
            ax.set_title(f"{MODEL_SHORT[model]} · {title}", fontsize=8)
            ax.set_xticks(x, tick_labels)
            ax.set_ylim(0, 103)
            ax.grid(axis="y", color="#dddddd", linewidth=.5)
            ax.spines[["top", "right"]].set_visible(False)
            if row == 1:
                ax.set_xlabel("Configured $D_A$ (native point is shared baseline)", fontsize=7)
            if col == 0:
                ax.set_ylabel("Held-out score (%)", fontsize=8)
    handles = []
    for _, label, color, marker in metrics:
        handles.extend((
            Line2D([0], [0], color=color, lw=1.2, ls="-", marker=marker,
                   ms=3.5, label=f"Mean {label}"),
            Line2D([0], [0], color=color, lw=1.0, ls="--", marker=marker,
                   ms=3.2, label=f"Minimum {label}"),
        ))
    fig.legend(handles=handles, loc="lower center", ncol=3, frameon=False,
               bbox_to_anchor=(.5, -.005), fontsize=6.8)
    fig.suptitle("Held-out READ-versus-SBO classification (Formby-style metrics, pool 20)",
                 y=.995, fontsize=9)
    fig.tight_layout(rect=(0, .12, 1, .96), h_pad=1.0, w_pad=.8)
    for ext in ("png", "pdf"):
        fig.savefig(out / f"attacker_metrics_by_da.{ext}", dpi=300, bbox_inches="tight")
    plt.close(fig)


def plot_attacker_metrics_by_scenario(summary, out):
    """Render larger static-only and adaptive-only Formby-style score figures."""
    records = _index(summary)
    policies = evaluation.POLICIES
    x = np.arange(len(policies) + 1)
    tick_labels = ["Timing OFF\nref."] + [
        f"{int(policy[2:].split('_', 1)[0])} ms" for policy in policies]
    metrics = (
        ("accuracy", "Accuracy", "#0072B2", "o"),
        ("precision", "Precision", "#D55E00", "s"),
        ("recall", "Recall", "#009E73", "^"),
    )
    scenarios = (
        ("static_after", "static", "Static attacker: trained on Timing OFF, tested on protected traffic"),
        ("adaptive", "adaptive", "Adaptive attacker: trained and tested on protected traffic"),
    )
    for scenario, slug, title in scenarios:
        fig, axes = plt.subplots(1, 2, figsize=(12.0, 4.7), sharex=True, sharey=True)
        for ax, model in zip(axes, evaluation.MODELS):
            baseline = records[("read_sbo", "formby_histogram", model,
                                "static_before", "native", 20)]
            ax.axvspan(-.28, .28, color="#f1f4f8", zorder=0)
            for metric, label, color, marker in metrics:
                mean_field, min_field = f"round_mean_{metric}", f"round_min_{metric}"
                mean = [baseline[mean_field]]
                minimum = [baseline[min_field]]
                for policy in policies:
                    result = records[("read_sbo", "formby_histogram", model,
                                      scenario, policy, 20)]
                    mean.append(result[mean_field])
                    minimum.append(result[min_field])
                ax.plot(x, np.asarray(mean, dtype=float) * 100, color=color,
                        linestyle="-", marker=marker, markersize=6.0, linewidth=2.1,
                        label=f"Mean {label}")
                ax.plot(x, np.asarray(minimum, dtype=float) * 100, color=color,
                        linestyle="--", marker=marker, markersize=5.5, linewidth=1.6,
                        label=f"Minimum {label}")
            ax.set_title(MODEL_SHORT[model], fontsize=14)
            ax.set_xticks(x, tick_labels)
            ax.set_ylim(0, 103)
            ax.grid(axis="y", color="#dddddd", linewidth=.55)
            ax.spines[["top", "right"]].set_visible(False)
            ax.tick_params(axis="x", labelsize=14)
            ax.tick_params(axis="y", labelsize=14, labelleft=True)
            ax.set_ylabel("Held-out score (%)", fontsize=14)
        fig.supxlabel("Configured $D_A$ center (ms), code $D_R$ center = 1 ms",
                      fontsize=14, y=.135)
        handles = []
        for _, label, color, marker in metrics:
            handles.extend((
                Line2D([0], [0], color=color, lw=2.1, ls="-", marker=marker,
                       ms=6.0, label=f"Mean {label}"),
                Line2D([0], [0], color=color, lw=1.6, ls="--", marker=marker,
                       ms=5.5, label=f"Minimum {label}"),
            ))
        handles.extend((
            Line2D([0], [0], color="#b8c2cc", lw=7, alpha=.7,
                   label="Timing OFF reference point"),
        ))
        fig.legend(handles=handles, loc="lower center", ncol=4, frameon=False,
                   bbox_to_anchor=(.5, .0), fontsize=12)
        fig.suptitle(f"{title}\nREAD versus SBO, Formby-style CLRT histograms, pool 20",
                     y=.965, fontsize=14)
        fig.subplots_adjust(left=.07, right=.99, bottom=.33, top=.80, wspace=.25)
        for ext in ("png", "pdf"):
            fig.savefig(out / f"attacker_metrics_{slug}.{ext}", dpi=300,
                        bbox_inches="tight")
        plt.close(fig)


def plot_distributions(csv_path, out):
    selected = {"native": {name: [] for name in evaluation.CLASSES["read_sbo"]}}
    for policy in evaluation.POLICIES:
        selected[policy] = {name: [] for name in evaluation.CLASSES["read_sbo"]}
    with Path(csv_path).open() as stream:
        for row in csv.DictReader(stream):
            if int(row["replicate"]) < 40:
                continue
            if row["arm"] == "native":
                key = "native"
            elif row["policy_name"] in evaluation.POLICIES:
                key = row["policy_name"]
            else:
                continue
            task_row = evaluation.rows_for_task([row], "read_sbo")
            if task_row:
                selected[key][task_row[0]["txn_class"]].append(float(row["clrt_ms"]))
    fig, axes = plt.subplots(2, 4, figsize=(7.15, 3.75), sharex=True, sharey="row")
    edges = np.linspace(0, 20, 66)
    bin_width = edges[1] - edges[0]
    maximum_tail = (0.0, None)
    for col, policy in enumerate(evaluation.POLICIES):
        for row, operation in enumerate(evaluation.CLASSES["read_sbo"]):
            ax = axes[row, col]
            native = np.asarray(selected["native"][operation], dtype=float)
            protected = np.asarray(selected[policy][operation], dtype=float)
            for label, values in (("Timing OFF", native), ("Protected", protected)):
                fraction = float(np.count_nonzero(values > 20) / len(values))
                if fraction > maximum_tail[0]:
                    maximum_tail = (fraction, (label, operation, policy))
            for values, color, linestyle in ((native, "#0072B2", "--"),
                                             (protected, "#D55E00", "-")):
                weights = np.full(len(values), 1 / (len(values) * bin_width))
                ax.hist(values, bins=edges, weights=weights, histtype="step",
                        color=color, linewidth=1.0 if linestyle == "--" else 1.2,
                        linestyle=linestyle)
            ax.grid(axis="y", color="#e4e4e4", linewidth=.45)
            ax.spines[["top", "right"]].set_visible(False)
            ax.set_xlim(0, 20)
            if row == 0:
                da = policy[2:].split("_", 1)[0]
                ax.set_title(f"$D_A$ = {da} ms", fontsize=9)
            if col == 0:
                label = "READ" if operation == "READ" else "SBO\n(SELECT + OPERATE responses)"
                ax.set_ylabel(f"{label}\nDensity", fontsize=8)
    fig.legend(handles=[
        Line2D([0], [0], color="#0072B2", lw=1.2, ls="--", label="Timing OFF"),
        Line2D([0], [0], color="#D55E00", lw=1.2, ls="-", label="Protected"),
    ], loc="upper center", ncol=2, frameon=False, bbox_to_anchor=(.5, .93), fontsize=8)
    fig.supxlabel("Measured response CLRT (ms)", fontsize=8, y=.035)
    fig.suptitle("Held-out per-response CLRT distributions (x-axis shown from 0 to 20 ms)",
                 y=.99, fontsize=9)
    fig.tight_layout(rect=(0, .10, 1, .88))
    for ext in ("png", "pdf"):
        fig.savefig(out / f"clrt_distributions.{ext}", dpi=300, bbox_inches="tight")
    plt.close(fig)
    return {"max_fraction_above_20ms": maximum_tail[0],
            "max_group_above_20ms": maximum_tail[1]}


def timing_summary_table(csv_path, heldout_rounds=range(40, 100)):
    values = {}
    with Path(csv_path).open() as stream:
        for row in csv.DictReader(stream):
            if int(row["replicate"]) not in heldout_rounds:
                continue
            task_row = evaluation.rows_for_task([row], "read_sbo")
            if not task_row:
                continue
            operation = task_row[0]["txn_class"]
            if row["arm"] == "native":
                policies = evaluation.POLICIES
            elif row["policy_name"] in evaluation.POLICIES:
                policies = (row["policy_name"],)
            else:
                continue
            for policy in policies:
                values.setdefault((policy, operation, row["arm"]), []).append(
                    float(row["clrt_ms"]))
    rows = [["D_A (ms)", "Physical function", "Traffic", "N responses",
             "Mean CLRT (ms)", "SD CLRT (ms)", "CLRT variance (ms²)"]]
    for policy in evaluation.POLICIES:
        da = policy[2:].split("_", 1)[0]
        for operation in evaluation.CLASSES["read_sbo"]:
            for arm, label in (("native", "Timing OFF"), ("obfuscated", "Protected")):
                data = values[(policy, operation, arm)]
                rows.append([da, operation, label, f"{len(data):,}",
                             f"{np.mean(data):.3f}", f"{np.std(data, ddof=1):.3f}",
                             f"{np.var(data, ddof=1):.3f}"])
    return rows


def plot_confusions(summary, out):
    records = _index(summary)
    paths = []
    for policy in evaluation.POLICIES:
        da = policy[2:].split("_", 1)[0]
        fig, axes = plt.subplots(2, 3, figsize=(7.15, 4.3))
        for row, task in enumerate(("read_sbo", "three_class")):
            classes = evaluation.CLASSES[task]
            scenarios = (("static_before", "native", "Static before"),
                         ("static_after", policy, "Frozen static on protected"),
                         ("adaptive", policy, "Adaptive on protected"))
            for col, (scenario, result_policy, title) in enumerate(scenarios):
                result = records[(task, "formby_histogram", "ff_ann", scenario,
                                  result_policy, 20)]
                cm = np.asarray(result["confusion_matrix"], dtype=float)
                normalized = cm / np.maximum(cm.sum(axis=1, keepdims=True), 1)
                ax = axes[row, col]
                ax.imshow(normalized, cmap="Blues", vmin=0, vmax=1)
                ax.set_xticks(range(len(classes)), classes, rotation=25, ha="right", fontsize=7)
                ax.set_yticks(range(len(classes)), classes, fontsize=7)
                ax.set_xlabel("Predicted class", fontsize=7)
                if col == 0:
                    task_label = "READ vs SBO" if task == "read_sbo" else "Three operation phases"
                    ax.set_ylabel(f"{task_label}\nTrue class", fontsize=7)
                ax.set_title(title, fontsize=8)
                for i in range(len(classes)):
                    for j in range(len(classes)):
                        ax.text(j, i, f"{int(cm[i,j])}\n{normalized[i,j]:.0%}",
                                ha="center", va="center", fontsize=6,
                                color="white" if normalized[i, j] > .55 else "#111111")
        fig.suptitle(f"FF-ANN with Formby-style CLRT histograms, pool 20 · $D_A$={da} ms",
                     fontsize=10, y=.99)
        fig.tight_layout(rect=(0, 0, 1, .94))
        path = out / f"confusion_da{da}.png"
        fig.savefig(path, dpi=300, bbox_inches="tight")
        plt.close(fig)
        paths.append(path)
    return paths


def _styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="CoverTitle", parent=styles["Title"], fontName="Helvetica-Bold",
                              fontSize=22, leading=27, alignment=TA_CENTER, spaceAfter=14))
    styles.add(ParagraphStyle(name="Section", parent=styles["Heading1"], fontSize=15,
                              leading=19, spaceBefore=8, spaceAfter=7))
    styles.add(ParagraphStyle(name="Subsection", parent=styles["Heading2"], fontSize=11,
                              leading=14, spaceBefore=7, spaceAfter=4))
    styles.add(ParagraphStyle(name="BodySmall", parent=styles["BodyText"], fontSize=9,
                              leading=12, spaceAfter=6))
    styles.add(ParagraphStyle(name="CaptionSmall", parent=styles["BodyText"], fontSize=8,
                              leading=10, textColor=colors.HexColor("#444444"), spaceBefore=4))
    return styles


def _table(data, widths, font=8):
    table = Table(data, colWidths=widths, repeatRows=1, hAlign="LEFT")
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e8edf2")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#172b3a")),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), font),
        ("LEADING", (0, 0), (-1, -1), font + 2),
        ("GRID", (0, 0), (-1, -1), .35, colors.HexColor("#b8c2cc")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return table


def build_pdf(summary_path, csv_path, out):
    summary = json.loads(Path(summary_path).read_text())
    if hashlib.sha256(Path(csv_path).read_bytes()).hexdigest() != summary["source"]["csv_sha256"]:
        raise ValueError("tutorial transaction table differs from the classifier evidence")
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    quality_path = evaluation.RESULTS / "grid_report.json"
    quality = json.loads(quality_path.read_text())
    quality_hash = hashlib.sha256(quality_path.read_bytes()).hexdigest()
    if summary["source"].get("quality_report_sha256", quality_hash) != quality_hash:
        raise ValueError("saved quality report differs from classifier report provenance")
    summary["source"]["capture_drops"] = quality["capture_drops"]
    summary["source"]["missing_primary_responses"] = quality["missing_primary_responses"]
    summary["source"]["quality_report_sha256"] = hashlib.sha256(quality_path.read_bytes()).hexdigest()
    run_dir = Path(json.loads((evaluation.RESULTS / "final/measurements.json").read_text())["run_dir"])
    identity = json.loads((run_dir / "program_identity.json").read_text())
    before = json.loads((run_dir / "live_identity_before.json").read_text())
    after = json.loads((run_dir / "live_identity_after.json").read_text())
    if identity.get("ingress_stages") != 7 or before.get("artifact_sha256") != identity.get("artifact_sha256") or \
       after.get("artifact_sha256") != identity.get("artifact_sha256"):
        raise ValueError("long-run hardware identity does not match the verified seven-stage program")
    summary["source"]["tofino_ingress_stages"] = identity["ingress_stages"]
    summary["source"]["hardware_program"] = identity["program"]
    summary["source"]["hardware_artifact_sha256"] = identity["artifact_sha256"]
    for key, source_path in (("analysis_script_sha256", HERE / "formby_evaluation.py"),
                             ("report_script_sha256", HERE / "formby_report.py"),
                             ("tutorial_script_sha256", HERE / "formby_tutorial.py")):
        summary["source"][key] = hashlib.sha256(source_path.read_bytes()).hexdigest()
    Path(summary_path).write_text(json.dumps(summary, indent=2, allow_nan=False) + "\n")
    plot_performance(summary, out)
    plot_attacker_metrics(summary, out)
    plot_attacker_metrics_by_scenario(summary, out)
    distribution_tail = plot_distributions(csv_path, out)
    confusion = plot_confusions(summary, out)
    with (out / "per_class_metrics.csv").open("w", newline="") as stream:
        columns = ["task", "feature", "model", "scenario", "policy", "da_ms", "pool_size",
                   "class", "precision", "recall", "round_mean_precision", "round_min_precision",
                   "round_mean_recall", "round_min_recall",
                   "f1", "support"]
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        for result in summary["results"]:
            if not result.get("per_class"):
                continue
            for operation, metrics in result["per_class"].items():
                writer.writerow({"task": result["task"], "feature": result["feature"],
                    "model": result["model"], "scenario": result["scenario"],
                    "policy": result["policy"], "da_ms": result["da_ms"],
                    "pool_size": result["pool_size"], "class": operation,
                    "round_mean_precision": result.get("round_mean_precision_by_class", {}).get(operation),
                    "round_min_precision": result.get("round_min_precision_by_class", {}).get(operation),
                    "round_mean_recall": result.get("round_mean_recall_by_class", {}).get(operation),
                    "round_min_recall": result.get("round_min_recall_by_class", {}).get(operation),
                    **metrics})
    with (out / "round_metrics.csv").open("w", newline="") as stream:
        columns = ["task", "feature", "model", "scenario", "policy", "da_ms", "pool_size",
                   "round", "accuracy", "balanced_accuracy", "mean_precision",
                   "per_class_precision", "per_class_recall"]
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        for result in summary["results"]:
            for round_score in result.get("round_scores", []):
                if "accuracy" not in round_score:
                    continue
                writer.writerow({"task": result["task"], "feature": result["feature"],
                    "model": result["model"], "scenario": result["scenario"],
                    "policy": result["policy"], "da_ms": result["da_ms"],
                    "pool_size": result["pool_size"], "round": round_score["round"],
                    "accuracy": round_score["accuracy"],
                    "balanced_accuracy": round_score["balanced_accuracy"],
                    "mean_precision": round_score["mean_precision"],
                    "per_class_precision": json.dumps(round_score["per_class_precision"], sort_keys=True),
                    "per_class_recall": json.dumps(round_score["per_class_recall"], sort_keys=True)})
    (out / "README.md").write_text(
        "# Formby classifier evaluation\n\n"
        "This directory contains a reproducible offline evaluation of the completed 100-round delay-grid run. "
        "It does not modify the P4 source or deployed switch program.\n\n"
        "Run from the repository root:\n\n"
        "```sh\n"
        "python3 defense4/timing/latency_search/formby_evaluation.py\n"
        "python3 defense4/timing/latency_search/formby_report.py\n"
        "```\n\n"
        "`results.json` stores the full metrics, confusion matrices, held-out round scores, selected model "
        "parameters, data hashes, and protocol notes. `metrics.csv` is the result-level table; "
        "`round_metrics.csv` contains held-out round accuracy and per-class precision and recall; "
        "`per_class_metrics.csv` contains pooled precision, recall, F1, support, and per-class round mean/min precision and recall. "
        "Round minima are observed worst cases, not confidence bounds. The primary task "
        "labels both SBO response phases as one SBO physical-function class; the PDF also retains the "
        "three-phase task as a secondary diagnostic. `tutorial_timing_statistics.csv` contains held-out timing summaries. The PDF is a detailed plain-English tutorial with a glossary and worked examples. Plot PDFs/PNGs are derived "
        "from held-out or explicitly labeled descriptive data.\n\n"
        "## Explanation corrections\n\n"
        "- The grid used request anchoring (anchor_req=1 in all 800 fixed readbacks). "
        "Older adaptive-explainer prose describing ACK anchoring does not describe this run.\n"
        "- At pool 20, native test rounds contain 20 READ/40 SBO signatures; each protected "
        "setting contains 5 READ/10 SBO. Their minimum scores have different sample supports.\n"
        "- Zero precision can mean a class was never predicted; below-chance binary scores "
        "can retain information under label inversion. The tutorial explains both cases.\n"
        "- Late-subset balanced accuracy pools all retained late samples; complete-class "
        "rounds control round summaries and the reporting gate.\n")
    styles = _styles()
    pdf_path = out / "formby_attacker_evaluation.pdf"
    doc = SimpleDocTemplate(str(pdf_path), pagesize=letter, rightMargin=.65*inch,
                            leftMargin=.65*inch, topMargin=.6*inch, bottomMargin=.6*inch,
                            title="Static and Adaptive Attacker Evaluation")
    story = tutorial.build_story(summary, quality, csv_path, out, styles,
                                 evaluation.POLICIES, distribution_tail, confusion)

    def bookmark(flowable):
        if isinstance(flowable, Paragraph) and flowable.style.name == "Section":
            key = f"tutorial-page-{doc.page}"
            doc.canv.bookmarkPage(key)
            doc.canv.addOutlineEntry(flowable.getPlainText(), key, level=0)

    doc.afterFlowable = bookmark

    def footer(canvas, document):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#52606d"))
        canvas.drawString(.65 * inch, .3 * inch, "Timing obfuscation and attacker classification")
        canvas.drawRightString(7.85 * inch, .3 * inch, str(document.page))
        canvas.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return pdf_path


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--summary", type=Path, default=evaluation.DEFAULT_OUTPUT / "results.json")
    parser.add_argument("--transactions", type=Path, default=evaluation.RESULTS / "final/primarytransactions.csv")
    parser.add_argument("--out", type=Path, default=evaluation.DEFAULT_OUTPUT)
    args = parser.parse_args()
    print(build_pdf(args.summary, args.transactions, args.out))


if __name__ == "__main__":
    main()

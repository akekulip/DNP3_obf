#!/usr/bin/env python3
"""
ack_fingerprint_eval.py -- can an attacker use the TCP-ACK behaviour to fingerprint
(cluster / identify) the DNP3 device, and what does the ACK-delay defense do to that?

This is the ACK-centric companion to ``attacker_eval.py``. It focuses on the
ACK-derived observables an eavesdropper sees and answers two questions, BEFORE the
defense (native, measured from the six real PCAPs) and AFTER it (the same
transactions with the shipped timing/ACK-delay policy applied to their timing):

  1. Supervised fingerprinting -- train a classifier to name the device from its
     ACK/timing/size features (capture-level split: train each device's base PCAP,
     test its disjoint larger "L" PCAP). Reported per feature family.

  2. Unsupervised clustering -- k-means / agglomerative on standardized features,
     with no labels, then score how well the clusters recover the true device
     (Adjusted Rand Index, Normalized Mutual Information, cluster purity). This is
     the "the attacker doesn't even need labels" view.

Feature families:
  ack_only : is_separate, req_to_ack_ms, ack_to_resp_ms   (the ACK channel alone)
  timing   : req_to_resp_ms                                (request->response only)
  size     : req_size, resp_size                           (payload sizes)
  all      : union of the above

Defense scenarios (applied to the per-transaction timing, never to the bytes):
  native            : measured, no defense.
  timing_gap_norm   : the IMPLEMENTED defense -- Phase-1 request->response
                      normalization (constant target) for every device, plus
                      Phase-2 gap-normalization of the SEL-751 separate ACK. Closes
                      the timing + ACK-gap channels; leaves ACK MODE and SIZE.
  plus_ackmode      : what-if upper bound -- additionally hide the ACK MODE
                      (make every device look combined-ACK, gap 0). NOT byte-
                      preserving / not implemented here; shown to expose the residual
                      that an ACK-mode primitive (Phase-2A socket induction) targets.

Outputs (overwritten each run):
  reports/ack_fingerprint_eval.json
  reports/ack_fingerprint_eval.md
  reports/ack_fingerprint_clusters.png   (native vs defended cluster scatter)
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd

try:  # scikit-learn is optional; guard the import so a missing dep gives a precise message
    from sklearn.preprocessing import StandardScaler
    from sklearn.linear_model import LogisticRegression
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.cluster import KMeans, AgglomerativeClustering
    from sklearn.metrics import (adjusted_rand_score, normalized_mutual_info_score,
                                 accuracy_score, f1_score, confusion_matrix)
    _HAVE_SKLEARN = True
    _SKLEARN_IMPORT_ERROR = None
except ImportError as exc:  # pragma: no cover - exercised only without scikit-learn
    StandardScaler = LogisticRegression = RandomForestClassifier = None
    KMeans = AgglomerativeClustering = None
    adjusted_rand_score = normalized_mutual_info_score = None
    accuracy_score = f1_score = confusion_matrix = None
    _HAVE_SKLEARN = False
    _SKLEARN_IMPORT_ERROR = exc

HERE = os.path.dirname(os.path.abspath(__file__))
CSV = os.path.join(HERE, "reports", "ack_trace_characterization.csv")
OUT = os.path.join(HERE, "reports")

DEVICE_IPS = {"SEL751": "10.0.0.1", "AB1400": "10.0.0.12", "ION7550": "10.0.0.11"}
DEVICES = ["AB1400", "ION7550", "SEL751"]

FEATURES = {
    "ack_only": ["is_separate", "req_to_ack_ms", "ack_to_resp_ms"],
    "timing": ["req_to_resp_ms"],
    "size": ["req_size", "resp_size"],
    "all": ["is_separate", "req_to_ack_ms", "ack_to_resp_ms", "req_to_resp_ms",
            "req_size", "resp_size"],
}

# Phase-1 constant target (ms), above the ~16 ms native floor; and the Phase-2
# ACK->response gap target (ms) for the separate-ACK device.
TARGET_MS = 25.0
GAP_TARGET_MS = 20.0

# Phase-4 eBPF EDT prototype targets (ms): the loaded tc-egress program pins the existing
# pure ACK to request+EBPF_ACK_TARGET_MS and the response to request+EBPF_RESP_TARGET_MS.
EBPF_ACK_TARGET_MS = 20.0
EBPF_RESP_TARGET_MS = 40.0


def load() -> pd.DataFrame:
    df = pd.read_csv(CSV)
    keep = []
    for dev, ip in DEVICE_IPS.items():
        keep.append(df[(df.device_label == dev) & (df.outstation_ip == ip)])
    d = pd.concat(keep, ignore_index=True)
    d["is_separate"] = (d["first_rev_is_pure_ack"].astype(str).str.lower() == "true").astype(int)
    d["is_L"] = d["pcap"].str.contains("L.pcap")
    for c in ["req_to_ack_ms", "ack_to_resp_ms", "req_to_resp_ms", "req_size", "resp_size"]:
        d[c] = pd.to_numeric(d[c], errors="coerce")
    return d.dropna(subset=["req_to_ack_ms", "ack_to_resp_ms", "req_to_resp_ms"]).reset_index(drop=True)


def apply_defense(d: pd.DataFrame, scenario: str) -> pd.DataFrame:
    """Return a copy of d with the timing/ACK features transformed by the defense.

    Bytes/sizes are never changed by the real defense; only 'plus_ackmode' (a
    what-if) rewrites ACK mode and gap to expose the residual channel.
    """
    x = d.copy()
    if scenario == "native":
        return x
    if scenario == "ebpf_edt":
        # The Phase-4 eBPF EDT prototype, modelled faithfully (delay-only: a native time already
        # past a target fails open and stays native -- np.maximum). It can only reschedule EXISTING
        # packets; it does NOT change the ACK mode (is_separate) or any byte/size (capability
        # boundary: a combined ACK-bearing packet cannot be split without synthesis).
        sep = x["is_separate"] == 1
        # separate-mode flows: pure ACK -> req+20 ms, response -> req+40 ms.
        x.loc[sep, "req_to_ack_ms"] = np.maximum(x.loc[sep, "req_to_ack_ms"], EBPF_ACK_TARGET_MS)
        x.loc[sep, "req_to_resp_ms"] = np.maximum(x.loc[sep, "req_to_resp_ms"], EBPF_RESP_TARGET_MS)
        x.loc[sep, "ack_to_resp_ms"] = x.loc[sep, "req_to_resp_ms"] - x.loc[sep, "req_to_ack_ms"]
        # combined-mode flows: the single ACK-bearing packet -> req+40 ms; ACK stays piggybacked.
        comb = x["is_separate"] == 0
        x.loc[comb, "req_to_resp_ms"] = np.maximum(x.loc[comb, "req_to_resp_ms"], EBPF_RESP_TARGET_MS)
        x.loc[comb, "req_to_ack_ms"] = x.loc[comb, "req_to_resp_ms"]
        x.loc[comb, "ack_to_resp_ms"] = 0.0
        return x
    if scenario == "ebpf_edt_aligned":
        # Ablation: ACK target = response target = EBPF_RESP_TARGET_MS, so the mechanism does NOT
        # introduce a device-correlated request->ACK cue (separate 20 vs combined 40). is_separate
        # (a distinct pure-ACK packet still exists) and sizes are unchanged.
        sep = x["is_separate"] == 1
        x.loc[sep, "req_to_ack_ms"] = np.maximum(x.loc[sep, "req_to_ack_ms"], EBPF_RESP_TARGET_MS)
        x.loc[sep, "req_to_resp_ms"] = np.maximum(x.loc[sep, "req_to_resp_ms"], EBPF_RESP_TARGET_MS)
        x.loc[sep, "ack_to_resp_ms"] = x.loc[sep, "req_to_resp_ms"] - x.loc[sep, "req_to_ack_ms"]
        comb = x["is_separate"] == 0
        x.loc[comb, "req_to_resp_ms"] = np.maximum(x.loc[comb, "req_to_resp_ms"], EBPF_RESP_TARGET_MS)
        x.loc[comb, "req_to_ack_ms"] = x.loc[comb, "req_to_resp_ms"]
        x.loc[comb, "ack_to_resp_ms"] = 0.0
        return x
    # Phase-1: every device's request->response held to the constant target,
    # release = max(native_ready, target). target (25 ms) > native median (~16 ms)
    # so it normally binds; the rare native tail above target fails open (honest).
    x["req_to_resp_ms"] = np.maximum(x["req_to_resp_ms"], TARGET_MS)
    # Phase-2: separate-ACK device gap pinned to the gap target; req_to_ack kept
    # (it is the transport ACK arrival), req_to_resp = req_to_ack + gap for those.
    sep = x["is_separate"] == 1
    x.loc[sep, "ack_to_resp_ms"] = GAP_TARGET_MS
    x.loc[sep, "req_to_resp_ms"] = x.loc[sep, "req_to_ack_ms"] + GAP_TARGET_MS
    if scenario == "timing_gap_norm":
        return x
    if scenario == "plus_ackmode":
        # what-if: also hide ACK mode -> make every device look like a combined-ACK
        # device answering at the common target (gap 0, ACK piggybacked, one segment).
        # NOT implemented / not byte-preserving; upper bound only. Every ACK/timing
        # feature becomes identical across devices, so only SIZE can still leak.
        x["is_separate"] = 0
        x["req_to_resp_ms"] = TARGET_MS
        x["req_to_ack_ms"] = TARGET_MS
        x["ack_to_resp_ms"] = 0.0
        return x
    raise ValueError("unknown scenario %r" % scenario)


# ------------------------------------------------------------------ #
# Supervised fingerprinting (capture-level split)
# ------------------------------------------------------------------ #

def supervised(d: pd.DataFrame, scenario: str) -> dict:
    x = apply_defense(d, scenario)
    tr, te = x[~x.is_L], x[x.is_L]
    y_tr = tr["device_label"].values
    y_te = te["device_label"].values
    out = {}
    for fam, cols in FEATURES.items():
        sc = StandardScaler().fit(tr[cols].values)
        xtr, xte = sc.transform(tr[cols].values), sc.transform(te[cols].values)
        res = {}
        for name, clf in (("logreg", LogisticRegression(max_iter=2000, multi_class="auto")),
                          ("rf", RandomForestClassifier(n_estimators=200, random_state=0))):
            clf.fit(xtr, y_tr)
            pred = clf.predict(xte)
            res[name] = {
                "accuracy": round(float(accuracy_score(y_te, pred)), 4),
                "macro_f1": round(float(f1_score(y_te, pred, average="macro")), 4),
            }
            if name == "rf" and fam == "all":
                cm = confusion_matrix(y_te, pred, labels=DEVICES)
                res["confusion_all_rf"] = {"labels": DEVICES, "matrix": cm.tolist()}
        out[fam] = res
    out["chance"] = round(float(max(np.bincount([DEVICES.index(v) for v in y_te])) / len(y_te)), 4)
    out["n_train"], out["n_test"] = int(len(tr)), int(len(te))
    return out


# ------------------------------------------------------------------ #
# Unsupervised clustering (no labels)
# ------------------------------------------------------------------ #

def clustering(d: pd.DataFrame, scenario: str, k: int = 3) -> dict:
    x = apply_defense(d, scenario)
    y = x["device_label"].values
    y_idx = np.array([DEVICES.index(v) for v in y])
    out = {}
    for fam, cols in FEATURES.items():
        feats = StandardScaler().fit_transform(x[cols].values)
        fam_res = {}
        for name, algo in (("kmeans", KMeans(n_clusters=k, n_init=10, random_state=0)),
                           ("agglom", AgglomerativeClustering(n_clusters=k))):
            lab = algo.fit_predict(feats)
            # cluster purity: each cluster votes its majority true device
            purity = 0.0
            for c in set(lab):
                mask = lab == c
                purity += np.bincount(y_idx[mask], minlength=len(DEVICES)).max()
            purity /= len(lab)
            fam_res[name] = {
                "ARI": round(float(adjusted_rand_score(y, lab)), 4),
                "NMI": round(float(normalized_mutual_info_score(y, lab)), 4),
                "purity": round(float(purity), 4),
            }
        out[fam] = fam_res
    return out


# ------------------------------------------------------------------ #
# Cluster scatter figure (native vs defended)
# ------------------------------------------------------------------ #

def figure(d: pd.DataFrame, path: str) -> str:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    scenarios = [("native", "BEFORE — native (measured)"),
                 ("timing_gap_norm", "AFTER — timing + ACK-gap normalized"),
                 ("plus_ackmode", "AFTER (what-if) — + ACK-mode hidden")]
    colors = {"AB1400": "#c4632a", "ION7550": "#0e9488", "SEL751": "#c53f51"}
    fig, axes = plt.subplots(1, 3, figsize=(15, 4.8))
    # deterministic jitter for overlapping discrete points
    rng = np.random.RandomState(0)
    for ax, (scen, title) in zip(axes, scenarios):
        x = apply_defense(d, scen)
        jx = rng.uniform(-0.4, 0.4, len(x))
        jy = rng.uniform(-0.4, 0.4, len(x))
        for dev in DEVICES:
            m = x["device_label"] == dev
            ax.scatter(x.loc[m, "req_to_ack_ms"] + jx[m.values],
                       x.loc[m, "ack_to_resp_ms"] + jy[m.values],
                       s=6, alpha=0.35, color=colors[dev], label=dev, edgecolors="none")
        ax.set_title(title, fontsize=10)
        ax.set_xlabel("request→ACK (ms)")
        ax.set_ylabel("ACK→response gap (ms)")
        ax.set_xlim(-1, 26)
        ax.set_ylim(-2, 26)
        ax.grid(alpha=0.2)
        ax.legend(fontsize=8, markerscale=2, loc="upper right")
    fig.suptitle("ACK-based device fingerprint in the (request→ACK, ACK→response gap) plane",
                 fontsize=12)
    fig.tight_layout(rect=(0, 0, 1, 0.95))
    fig.savefig(path, dpi=130)
    plt.close(fig)
    return path


def write_md(result: dict, path: str) -> None:
    L = ["# ACK-Based Device Fingerprinting — Before vs After the ACK-Delay Defense\n"]
    L.append("_Companion to `attacker_eval.md`, focused on the TCP-ACK channel. "
             "Data: device-specific transactions from the six real PCAPs "
             "(`ack_trace_characterization.csv`). Supervised = capture-level split "
             "(train base PCAP → test disjoint L PCAP); unsupervised = k-means / "
             "agglomerative on standardized features, scored against the true device. "
             "The defense transforms only per-transaction **timing**; response bytes "
             "and sizes are never touched._\n")
    L.append("Scenarios: **native** (before) · **timing_gap_norm** (the implemented "
             "defense: request→response pinned to %g ms + SEL-751 ACK→response gap "
             "pinned to %g ms) · **plus_ackmode** (what-if upper bound that also hides "
             "the ACK mode — not byte-preserving, shown only to expose the residual).\n"
             % (TARGET_MS, GAP_TARGET_MS))

    # Supervised table
    L.append("## 1. Supervised fingerprinting — accuracy (Random Forest, capture-level split)\n")
    L.append("Chance (majority class) ≈ %.3f. Higher = attacker identifies the device "
             "better.\n" % result["chance"])
    L.append("| feature family | native | timing_gap_norm | plus_ackmode |")
    L.append("|---|---:|---:|---:|")
    for fam in ["ack_only", "timing", "size", "all"]:
        row = [fam]
        for scen in ["native", "timing_gap_norm", "plus_ackmode"]:
            row.append("%.3f" % result["supervised"][scen][fam]["rf"]["accuracy"])
        L.append("| %s | %s | %s | %s |" % tuple(row))
    L.append("")
    cm = result["supervised"]["native"]["all"]["confusion_all_rf"]
    L.append("Native all-features confusion (rows=true, cols=pred; %s):\n" % ", ".join(cm["labels"]))
    L.append("```")
    for lbl, r in zip(cm["labels"], cm["matrix"]):
        L.append("%8s " % lbl + " ".join("%6d" % v for v in r))
    L.append("```\n")

    # Clustering table
    L.append("## 2. Unsupervised clustering — Adjusted Rand Index (no labels, k=3)\n")
    L.append("ARI = 1.0 means the clusters perfectly recover the devices; 0.0 means "
             "no better than random. NMI and purity in the JSON.\n")
    L.append("| feature family | native | timing_gap_norm | plus_ackmode |")
    L.append("|---|---:|---:|---:|")
    for fam in ["ack_only", "timing", "size", "all"]:
        row = [fam]
        for scen in ["native", "timing_gap_norm", "plus_ackmode"]:
            row.append("%.3f" % result["clustering"][scen][fam]["kmeans"]["ARI"])
        L.append("| %s | %s | %s | %s |" % tuple(row))
    L.append("")

    L.append("## 3. Reading\n")
    sup = result["supervised"]
    L.append("- **ACK alone is a strong fingerprint natively.** `ack_only` random-forest "
             "accuracy is **%.3f** (chance %.3f): the SEL-751 is perfectly isolated by "
             "the mere presence of a pure TCP ACK before its response, and its "
             "request→ACK / gap values pin it further.\n"
             % (sup["native"]["ack_only"]["rf"]["accuracy"], result["chance"]))
    L.append("- **The implemented defense closes the ACK-*gap* magnitude but not the ACK "
             "*mode*.** Under `timing_gap_norm`, `timing`-family accuracy collapses "
             "(from %.3f to %.3f) and clustering on timing loses the devices, but "
             "`ack_only` stays high (%.3f → %.3f) because a separate ACK still *exists* "
             "for the SEL-751 — normalizing its gap to a constant does not make it look "
             "combined.\n"
             % (sup["native"]["timing"]["rf"]["accuracy"],
                sup["timing_gap_norm"]["timing"]["rf"]["accuracy"],
                sup["native"]["ack_only"]["rf"]["accuracy"],
                sup["timing_gap_norm"]["ack_only"]["rf"]["accuracy"]))
    L.append("- **Only when ACK mode is also hidden does the ACK fingerprint fall.** The "
             "`plus_ackmode` what-if drops `ack_only` accuracy to %.3f and its clustering "
             "ARI toward 0 — but that step is **not byte-preserving** and is not "
             "implemented; it is exactly what a Phase-2A socket-induced ACK-mode "
             "primitive would have to achieve. **Size still leaks** (ION7550's 61 B "
             "response) so `all`-features identity never reaches chance here.\n"
             % sup["plus_ackmode"]["ack_only"]["rf"]["accuracy"])
    L.append("- **Honest scope:** a distributional simulation on measured native "
             "timings, not a live capture of a defended device. It shows which channel "
             "each attacker relies on and precisely what the timing/ACK-delay defense "
             "removes versus leaves.\n")
    with open(path, "w") as fh:
        fh.write("\n".join(L) + "\n")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--no-figure", action="store_true")
    args = ap.parse_args()
    if not _HAVE_SKLEARN:
        sys.stderr.write(
            "ack_fingerprint_eval requires scikit-learn, which is not installed.\n"
            "  reason : {}\n"
            "  install: pip install 'scikit-learn>=1.3,<1.4'   (Python 3.8)\n"
            "  check  : python3 check_env.py\n".format(_SKLEARN_IMPORT_ERROR))
        sys.exit(2)
    d = load()
    scenarios = ["native", "timing_gap_norm", "plus_ackmode"]
    result = {
        "meta": {
            "n": int(len(d)),
            "per_device": {k: int(v) for k, v in d["device_label"].value_counts().items()},
            "target_ms": TARGET_MS, "gap_target_ms": GAP_TARGET_MS,
            "split": "capture-level (train base pcap, test L pcap)",
            "features": FEATURES,
        },
        "chance": None,
        "supervised": {}, "clustering": {},
    }
    for scen in scenarios:
        result["supervised"][scen] = supervised(d, scen)
        result["clustering"][scen] = clustering(d, scen)
    result["chance"] = result["supervised"]["native"]["chance"]

    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "ack_fingerprint_eval.json"), "w") as fh:
        json.dump(result, fh, indent=2)
    write_md(result, os.path.join(OUT, "ack_fingerprint_eval.md"))
    fig = None
    if not args.no_figure:
        fig = figure(d, os.path.join(OUT, "ack_fingerprint_clusters.png"))

    print("n=%d  per-device=%s" % (result["meta"]["n"], result["meta"]["per_device"]))
    for scen in scenarios:
        print("[%s] ack_only rf acc=%.3f  kmeans ARI(ack_only)=%.3f  all rf acc=%.3f" % (
            scen,
            result["supervised"][scen]["ack_only"]["rf"]["accuracy"],
            result["clustering"][scen]["ack_only"]["kmeans"]["ARI"],
            result["supervised"][scen]["all"]["rf"]["accuracy"]))
    print("Wrote reports/ack_fingerprint_eval.{json,md}" + (" + .png" if fig else ""))


if __name__ == "__main__":
    main()

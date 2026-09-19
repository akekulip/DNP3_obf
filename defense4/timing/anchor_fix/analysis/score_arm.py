"""Score one arm of the validation the way the reviewer's finding was raised.

The reviewer's C2 objection is about the REQUEST-TO-ACKNOWLEDGMENT interval alone: undefended it
carries almost nothing (0.479 balanced accuracy on three classes), and the framework as evaluated
raised it to 0.809. ``leakage_campaign.FEATURES`` has no acknowledgment-only entry, so this script
adds that one feature set and otherwise reuses the campaign's own forest, fold construction and
scoring by importing them. Nothing about the attacker is re-specified here.

    python3 score_arm.py canonical_A0.csv canonical_A1.csv
"""
from __future__ import annotations
import json, pathlib, sys
import numpy as np

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "evidence" / "campaign_v1" / "repro"))
import leakage_campaign as L                                       # noqa: E402

FEATS = {"ack_only": [0], "clrt_only": [1], "ack_clrt": [0, 1]}


def report(path):
    runs, arms, cls, X = L.load(path)
    out = {"file": pathlib.Path(path).name, "n": int(len(cls)),
           "n_folds": len(set(runs)), "chance": round(1 / 3, 4),
           "classifier": "RandomForest " + json.dumps(L.RF), "features": {}}
    for name, idx in FEATS.items():
        f, cmA_off, cmA_obf, cmB = L.folds(runs, arms, cls, X, idx)
        out["features"][name] = {
            "A_fixed_tested_on_timing_off": L.spread(f["A_fixed"]["off"]),
            "A_fixed_tested_on_obfuscated": L.spread(f["A_fixed"]["obf"]),
            "B_adaptive_tested_on_obfuscated": L.spread(f["B_adaptive"]["obf"]),
            "confusion_B_obf_rownorm": (cmB / cmB.sum(axis=1, keepdims=True)).round(4).tolist()}
    # Mutual information against the campaign's own within-run permutation null, on the
    # request-to-acknowledgment interval -- the channel the reviewer's objection is about --
    # and on the released CLRT. A forest score above chance means little on its own; the null
    # says whether the association is there at all.
    rng = np.random.default_rng(L.SEED)
    out["mutual_information"] = {}
    for arm in ("native", "obfuscated"):
        m = arms == arm
        for fname, col in (("ack_ms", 0), ("clrt_ms", 1)):
            d = L.mi_block(X[m][:, [col]], cls[m], runs[m], rng)
            out["mutual_information"]["%s/%s" % (arm, fname)] = {
                k: d[k] for k in ("observed_bits", "null_p95_bits", "null_p99_bits",
                                  "p_value_empirical", "inside_null")}

    # class medians of each interval, per arm: the mechanism behind whatever the forest finds
    med = {}
    for a in ("native", "obfuscated"):
        m = arms == a
        med[a] = {c: {"ack_ms": round(float(np.median(X[m & (cls == c)][:, 0])), 4),
                      "clrt_ms": round(float(np.median(X[m & (cls == c)][:, 1])), 4),
                      "n": int((m & (cls == c)).sum())} for c in L.CLASSES}
        acks = [med[a][c]["ack_ms"] for c in L.CLASSES]
        med[a]["ack_spread_ms"] = round(max(acks) - min(acks), 4)
    out["class_medians"] = med
    return out


def main(argv):
    res = [report(p) for p in argv]
    txt = json.dumps(res, indent=2)
    (HERE / "scores.json").write_text(txt + "\n")
    for r in res:
        print("\n===", r["file"], " n=%d folds=%d" % (r["n"], r["n_folds"]))
        for a in ("native", "obfuscated"):
            m = r["class_medians"][a]
            print("   %-11s ack medians  READ %.4f  SELECT %.4f  OPERATE %.4f   spread %.4f ms"
                  % (a, m["READ"]["ack_ms"], m["SELECT"]["ack_ms"],
                     m["OPERATE"]["ack_ms"], m["ack_spread_ms"]))
        for k, d in r["mutual_information"].items():
            print("   MI %-22s %.5f bits   null p95 %.5f   p=%.5f   inside null: %s"
                  % (k, d["observed_bits"], d["null_p95_bits"],
                     d["p_value_empirical"], d["inside_null"]))
        for name in FEATS:
            d = r["features"][name]
            print("   %-10s  A/OFF %.4f   A/obf %.4f   B adaptive/obf %.4f"
                  % (name, d["A_fixed_tested_on_timing_off"]["mean"],
                     d["A_fixed_tested_on_obfuscated"]["mean"],
                     d["B_adaptive_tested_on_obfuscated"]["mean"]))
    print("\nwrote", HERE / "scores.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

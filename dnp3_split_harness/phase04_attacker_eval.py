"""phase04_attacker_eval.py -- does the Phase-4 eBPF EDT mechanism reduce device fingerprinting?

TRACE-TRANSFORMATION evaluation (NOT a defended-wire capture): it takes the measured *native*
per-transaction features from the six real device PCAPs and applies the eBPF EDT transformation
(`apply_defense(..., "ebpf_edt")` in ack_fingerprint_eval.py -- a faithful model of what the loaded
`ack_edt.o` does: pin the existing pure ACK to req+20 ms and the response to req+40 ms, delay-only,
ACK mode and sizes unchanged), then re-runs the same attacker as ack_fingerprint_eval:
  * supervised random forest (capture-level split, no leakage), accuracy per feature family;
  * unsupervised k-means, Adjusted Rand Index per family.
Compared: native (before) vs ebpf_edt (the mechanism) vs plus_ackmode (non-byte-preserving upper
bound that also hides the ACK mode).

    python3 phase04_attacker_eval.py
"""

from __future__ import annotations

import json
import os
import sys

import ack_fingerprint_eval as A   # reuse the validated load/transform/classify machinery

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports", "phases", "phase_04")
SCENARIOS = ["native", "ebpf_edt", "plus_ackmode"]
FAMS = ["ack_only", "timing", "size", "all"]


def main() -> int:
    if not A._HAVE_SKLEARN:
        sys.stderr.write("needs scikit-learn (pip install 'scikit-learn>=1.3,<1.4')\n")
        return 2
    d = A.load()
    res = {"meta": {"n": int(len(d)),
                    "per_device": {k: int(v) for k, v in d["device_label"].value_counts().items()},
                    "ebpf_ack_target_ms": A.EBPF_ACK_TARGET_MS,
                    "ebpf_resp_target_ms": A.EBPF_RESP_TARGET_MS,
                    "eval_type": "trace-transformation (native traces transformed; NOT defended-wire)",
                    "split": "capture-level (train base pcap, test L pcap)"},
           "supervised": {}, "clustering": {}}
    for s in SCENARIOS:
        res["supervised"][s] = A.supervised(d, s)
        res["clustering"][s] = A.clustering(d, s)
    res["chance"] = res["supervised"]["native"]["chance"]

    os.makedirs(OUT, exist_ok=True)
    json.dump(res, open(os.path.join(OUT, "attacker_eval.json"), "w"), indent=2)

    def rf(s, f):
        return res["supervised"][s][f]["rf"]["accuracy"]

    def ari(s, f):
        return res["clustering"][s][f]["kmeans"]["ARI"]

    L = ["# Phase 04 — Attacker Evaluation: does the eBPF EDT mechanism reduce fingerprinting?",
         "",
         "**Trace-transformation evaluation** (per the reviewer's labelling rule): the measured "
         "*native* per-transaction features from the six real device PCAPs are transformed by the "
         "eBPF EDT model (pin existing pure ACK to req+%g ms, response to req+%g ms; delay-only; "
         "ACK mode and sizes unchanged) and re-classified. It is **not** a capture of a defended "
         "device on the wire. Chance (majority class) = %.3f; higher = attacker identifies the "
         "device better." % (A.EBPF_ACK_TARGET_MS, A.EBPF_RESP_TARGET_MS, res["chance"]),
         "",
         "## 1. Supervised random forest — accuracy per feature family (capture-level split)",
         "",
         "| feature family | native | ebpf_edt | plus_ackmode |",
         "|---|---:|---:|---:|"]
    for f in FAMS:
        L.append("| %s | %.3f | %.3f | %.3f |" % (f, rf("native", f), rf("ebpf_edt", f),
                                                  rf("plus_ackmode", f)))
    L += ["",
          "## 2. Unsupervised k-means — Adjusted Rand Index per family",
          "",
          "| feature family | native | ebpf_edt | plus_ackmode |",
          "|---|---:|---:|---:|"]
    for f in FAMS:
        L.append("| %s | %.3f | %.3f | %.3f |" % (f, ari("native", f), ari("ebpf_edt", f),
                                                  ari("plus_ackmode", f)))
    L += ["",
          "## 3. Reading",
          "",
          "- **The eBPF EDT closes the TIMING channel cleanly.** `timing` (request→response) "
          "accuracy %.3f → %.3f: every device's response is pinned to the common %g ms target, so "
          "the request→response feature carries no device information — and, unlike a "
          "device-correlated gap normalization, it does not re-encode the ACK mode into timing."
          % (rf("native", "timing"), rf("ebpf_edt", "timing"), A.EBPF_RESP_TARGET_MS),
          "- **It does NOT close the ACK-MODE channel.** `ack_only` accuracy %.3f → %.3f: the "
          "mechanism cannot change `is_separate` (a separate-mode device still emits a standalone "
          "pure ACK; a combined device still piggybacks), and with the prototype's %g/%g ms targets "
          "the request→ACK time itself splits 20 ms (separate) vs 40 ms (combined). Both are "
          "categorical/structural leaks a no-synthesis, byte-preserving mechanism cannot remove."
          % (rf("native", "ack_only"), rf("ebpf_edt", "ack_only"),
             A.EBPF_ACK_TARGET_MS, A.EBPF_RESP_TARGET_MS),
          "- **Only hiding the ACK mode collapses it** — `plus_ackmode` drops `ack_only` to %.3f, "
          "but that is not byte-preserving and requires ACK synthesis / suppression, outside this "
          "mechanism." % rf("plus_ackmode", "ack_only"),
          "- **Size is the irreducible residual.** `size` accuracy is %.3f throughout (byte "
          "preservation forbids touching it)."
          % rf("ebpf_edt", "size"),
          "- **Joint identity does not fall — it edges up (%.3f → %.3f).** The prototype's %g/%g ms "
          "targets make request→ACK itself device-correlated (20 ms for separate, 40 ms for "
          "combined), so the `all` attacker gains a small extra tell rather than losing one. A "
          "design refinement — set the ACK target equal to the response target so request→ACK no "
          "longer splits — would remove *that* artifact, but `is_separate` (a separate device still "
          "emits a distinct pure-ACK packet) and size would still leave `all` above chance."
          % (rf("native", "all"), rf("ebpf_edt", "all"), A.EBPF_ACK_TARGET_MS, A.EBPF_RESP_TARGET_MS),
          "",
          "**Verdict:** the eBPF EDT mechanism is an effective *timing* normalizer (closes the "
          "request→response channel to chance, with no re-encoding), but it does **not** defeat "
          "device fingerprinting — the ACK mode and response size remain, and joint accuracy stays "
          "at %.3f (vs %.3f chance). Closing the mode channel needs ACK suppression "
          "(separate→combined) or synthesis, neither available byte-preservingly in this mode; "
          "size needs a size/padding primitive out of this line's scope. This is the measured "
          "confirmation of the Phase-4 capability boundary: a no-synthesis, byte-preserving "
          "mechanism can normalize *when* packets leave, not *whether a separate ACK exists* or "
          "*how large the response is*."
          % (rf("ebpf_edt", "all"), res["chance"]),
          "",
          "_Scope: trace-transformation on the six device PCAPs (SEL-751 separate; AB1400 / ION7550 "
          "combined). Not a rig/defended-wire capture._"]
    open(os.path.join(OUT, "attacker_eval.md"), "w").write("\n".join(L) + "\n")

    print("n=%d per-device=%s" % (res["meta"]["n"], res["meta"]["per_device"]))
    print("%-13s %8s %8s %8s %8s" % ("scenario", *FAMS))
    for s in SCENARIOS:
        print("%-13s %8.3f %8.3f %8.3f %8.3f" % (s, rf(s, "ack_only"), rf(s, "timing"),
                                                 rf(s, "size"), rf(s, "all")))
    print("wrote reports/phases/phase_04/attacker_eval.{json,md}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

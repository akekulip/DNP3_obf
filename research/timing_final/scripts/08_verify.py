#!/usr/bin/env python3
"""08_verify.py — hardened per-trial verifier for a PROTECTED timing trial.

Runs the validated p13_verify.py (byte-identity + counter deltas + CLRT-vs-G) and
then LAYERS the §4 review gates on top of its result, because p13_verify.py alone
mislabels two failure classes:

  W4  DNP3-port frames present in the capture but unmatched by seq/ack must be a
      FAIL (a real byte mutation is a dataplane fault), not INCONCLUSIVE_CAPTURE.
  W5  the release-cause gate must be strict for hold modes:
        ctr_block_term_timeout delta == 0        (no blocker hit its budget)
        ctr_release_fail_open  delta == 0         (C4: every release deadline-attributed)
        ctr_release_deadline   delta == nresp     (per-release: one deadline release each)
        ctr_block_term_deadline delta == nresp*K  (per-token: whole reservoir drained on deadline)
      Reconciliation of the review's shorthand "ctr_block_term_deadline == nresp":
      the per-RELEASE counter that equals nresp is ctr_release_deadline; the per-TOKEN
      counter ctr_block_term_deadline equals nresp*K (K increments per drain). Both are
      gated here so neither a false pass nor a false fail can occur.
  C4  K (reservoir depth) must be >= 64.
  isolation  ctr/capture: zero blocker tokens (0x88C1) may be visible externally.

Exit 0 = PASS, 1 = FAIL, 2 = INCONCLUSIVE_CAPTURE (only for a genuinely empty capture).
"""
import argparse
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TF_DIR = os.path.dirname(HERE)
REPO_ROOT = os.path.dirname(os.path.dirname(TF_DIR))
P13_VERIFY = os.path.join(REPO_ROOT, "research/ibspg_dnp3_replay/harness/p13_verify.py")


def read_p13read(path):
    """Parse a file containing one 'P13READ {json}' line into its dict."""
    if not path or not os.path.exists(path):
        return None
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line.startswith("P13READ "):
                return json.loads(line[len("P13READ "):])
    return None


def ctr(d, name):
    if not d:
        return None
    v = d.get("counters", {}).get(name)
    return v if isinstance(v, int) else None


def delta(before, after, name):
    a = ctr(after, name)
    if a is None:
        return None
    b = ctr(before, name) or 0
    d = a - b
    return d if d >= 0 else a


def main():
    ap = argparse.ArgumentParser(description="hardened protected-trial verifier (review W4/W5/C4)")
    ap.add_argument("--runid", help="resolve artifacts from the evidence dir by RUNID")
    ap.add_argument("--evid-dir", default=os.environ.get("EVID_DIR", "research/timing_final/evidence/timing_final"))
    ap.add_argument("--plan"); ap.add_argument("--vision-pcap"); ap.add_argument("--hulk-pcap")
    ap.add_argument("--before-json"); ap.add_argument("--after-json")
    ap.add_argument("--mode", default="hold_resp", choices=["bypass", "hold_ack", "hold_resp"])
    ap.add_argument("--g-ms", type=float, default=float(os.environ.get("G_MS", "25")))
    ap.add_argument("--tol-ms", type=float, default=float(os.environ.get("TOL_MS", "5")))
    ap.add_argument("--json", help="write the combined verdict JSON here")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    ed = os.path.join(REPO_ROOT, a.evid_dir)
    if a.runid:
        base = os.path.join(ed, a.runid)
        a.plan = a.plan or base + ".plan.json"
        a.vision_pcap = a.vision_pcap or base + ".pcap"
        a.before_json = a.before_json or base + ".before.json"
        a.after_json = a.after_json or base + ".after.json"
        a.json = a.json or base + ".verify.json"

    print("RUN: p13_verify.py --plan %s --vision-pcap %s --mode %s --g-ms %s --tol-ms %s"
          % (a.plan, a.vision_pcap, a.mode, a.g_ms, a.tol_ms))
    if a.dry_run:
        print("DRYRUN: would run p13_verify.py then apply review gates W4/W5/C4 + isolation.")
        print("        gates: ctr_block_term_timeout==0, ctr_release_fail_open==0,")
        print("               ctr_release_deadline==nresp, ctr_block_term_deadline==nresp*K,")
        print("               unmatched DNP3 frames==0 (FAIL not INCONCLUSIVE), tokens_escaped==0, K>=64.")
        return 0

    for req in (a.plan, a.vision_pcap):
        if not req or not os.path.exists(req):
            sys.exit("FATAL: missing input %s" % req)

    # ---- run the base verifier ---------------------------------------------
    pv_json = (a.json or a.vision_pcap + ".pv.json")
    cmd = ["python3", P13_VERIFY, "--plan", a.plan, "--vision-pcap", a.vision_pcap,
           "--mode", a.mode, "--g-ms", str(a.g_ms), "--tol-ms", str(a.tol_ms), "--json", pv_json]
    if a.hulk_pcap and os.path.exists(a.hulk_pcap):
        cmd += ["--hulk-pcap", a.hulk_pcap]
    if a.before_json and os.path.exists(a.before_json):
        cmd += ["--before-json", a.before_json]
    if a.after_json and os.path.exists(a.after_json):
        cmd += ["--after-json", a.after_json]
    subprocess.run(cmd, capture_output=True, text=True)   # exit code folded into pv["verdict"]
    try:
        pv = json.load(open(pv_json))
    except Exception as e:
        sys.exit("FATAL: p13_verify produced no parseable JSON (%s)" % e)

    # ---- gather inputs for the review gates ---------------------------------
    plan = json.load(open(a.plan))
    k_eff = int(plan.get("k", 0))
    nresp = int(pv.get("nresp", 0))
    before = read_p13read(a.before_json)
    after = read_p13read(a.after_json)
    cap = pv.get("capture", {})

    gates = {}
    reasons = []

    def gate(name, ok, detail):
        gates[name] = {"pass": bool(ok), "detail": detail}
        if not ok:
            reasons.append("%s (%s)" % (name, detail))

    # C4: reservoir depth
    gate("C4_reservoir_depth_ge_64", k_eff >= 64, "K=%d" % k_eff)

    if a.mode == "hold_resp":
        d_timeout = delta(before, after, "ctr_block_term_timeout")
        d_failopen = delta(before, after, "ctr_release_fail_open")
        d_reldl = delta(before, after, "ctr_release_deadline")
        d_blkdl = delta(before, after, "ctr_block_term_deadline")
        d_enq = delta(before, after, "ctr_resp_enq")
        d_rel = delta(before, after, "ctr_resp_release")
        # W5 / C4 — no fail-open in a normal protected trial
        gate("W5_block_term_timeout_zero", d_timeout == 0, "delta=%s" % d_timeout)
        gate("C4_release_fail_open_zero", d_failopen == 0, "delta=%s" % d_failopen)
        # per-release deadline attribution == nresp (the review's "== nresp")
        gate("W5_release_deadline_eq_nresp", d_reldl == nresp, "delta=%s expected=%d" % (d_reldl, nresp))
        # per-token: the whole reservoir drained on the deadline == nresp*K
        gate("W5_block_term_deadline_eq_nresp_times_k",
             d_blkdl == nresp * k_eff, "delta=%s expected=%d (nresp*K)" % (d_blkdl, nresp * k_eff))
        gate("resp_enq_eq_nresp", d_enq == nresp, "delta=%s expected=%d" % (d_enq, nresp))
        gate("resp_release_eq_nresp", d_rel == nresp, "delta=%s expected=%d" % (d_rel, nresp))

    # W4 — unmatched DNP3-port frames are a FAIL, not INCONCLUSIVE
    unmatched = cap.get("unmatched_frames", 0)
    gate("W4_no_unmatched_dnp3_frames", (unmatched == 0), "unmatched=%s" % unmatched)
    # isolation — zero blocker tokens visible externally
    escaped = cap.get("tokens_escaped", 0)
    gate("isolation_no_token_escape", (escaped == 0), "tokens_escaped=%s" % escaped)

    # base verifier's own verdict (byte identity, capture health, CLRT-vs-G live checks)
    base_verdict = pv.get("verdict", "FAIL")
    gate("base_p13_verify", base_verdict == "PASS", "p13_verify verdict=%s" % base_verdict)

    # ---- combine -----------------------------------------------------------
    review_fail = bool(reasons)
    empty_capture = (cap.get("vision_records", 0) == 0)
    if review_fail and not (empty_capture and unmatched == 0 and len(reasons) == 1
                            and "base_p13_verify" in reasons[0]):
        # any genuine review-gate failure (including W4 unmatched>0) -> FAIL
        verdict = "FAIL"
    elif base_verdict == "INCONCLUSIVE_CAPTURE" and unmatched == 0 and empty_capture:
        verdict = "INCONCLUSIVE_CAPTURE"     # legitimate observer failure only
    elif review_fail:
        verdict = "FAIL"
    else:
        verdict = "PASS"

    combined = {
        "verdict": verdict, "runid": a.runid, "mode": a.mode, "nresp": nresp, "k_eff": k_eff,
        "g_ms": a.g_ms, "gates": gates, "reasons": reasons,
        "base_verdict": base_verdict, "capture": cap,
        "clrt": pv.get("clrt", {}),
    }
    if a.json:
        json.dump(combined, open(a.json, "w"), indent=1)

    # ---- §23-style compact summary -----------------------------------------
    clrt = pv.get("clrt", {})
    print("---- verify (runid=%s, mode=%s) ----" % (a.runid, a.mode))
    print("  Transactions:        %s" % pv.get("ntxn"))
    print("  Responses released:  %s" % (delta(before, after, "ctr_resp_release")))
    print("  Mean/median ACK->RESP: %s / %s ms"
          % (clrt.get("mean_ms"), clrt.get("median_ms")))
    print("  CLRT sd:             %s ms" % clrt.get("sd_ms"))
    print("  Unmatched frames:    %s   External blocker frames: %s" % (unmatched, escaped))
    for n, g in gates.items():
        print("  [%s] %s — %s" % ("PASS" if g["pass"] else "FAIL", n, g["detail"]))
    print("  VERIFICATION: %s" % verdict)
    if reasons:
        print("  FAIL reasons: %s" % "; ".join(reasons))
    return {"PASS": 0, "FAIL": 1, "INCONCLUSIVE_CAPTURE": 2}[verdict]


if __name__ == "__main__":
    sys.exit(main())

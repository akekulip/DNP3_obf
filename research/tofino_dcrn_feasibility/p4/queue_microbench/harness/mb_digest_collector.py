#!/usr/bin/env python3.8
"""mb_digest_collector.py — per-release telemetry DIGEST collector (run ON the switch).

Primary per-frame telemetry mechanism (learning digest; frames stay byte-clean, no cloned packets).
Seeds a control-plane run_id (so batched records from different burst/rate configs can never be
mixed), subscribes to the `telem_digest` learn filter, and writes ONE append-only JSONL record per
released real packet. hold_ns is computed here from the two switch timestamps (32-bit wrap-safe).

Digest fields (pipe.IngressDeparser.telem_digest): run_id, seq, target_passes, t_in, t_out,
pass_count, release_reason, size_state.  release_reason is PASS_BUDGET for every normal release
(the deadline is a pass budget: hold_passes==0), NOT a timestamp deadline.

COMPLETENESS (a run is VALID only if): collector_records == ctr_digest_emit == ctr_grad, and there
are no missing or duplicate sequence numbers (for the expected contiguous seq range). This script
reports the check; the caller also compares against the Vision real-packet count.

Usage:  python3.8 mb_digest_collector.py --run-id 7 --out runs/digest_b16384_t10ms.jsonl --seconds 30
        (start BEFORE generating; stop after; then compare counts.)
"""
import sys, json, time, argparse

SDE = "/home/decps/Downloads/bf-sde-9.13.2/install/lib/python3.8/site-packages"
sys.path.insert(0, SDE + "/tofino"); sys.path.insert(0, SDE)
import bfrt_grpc.client as gc

PROG = "queue_microbench"
DIGEST = "pipe.IngressDeparser.telem_digest"
REASON = {1: "PASS_BUDGET"}   # only reason present in the microbench (extend for Defense 2)


def _ctr(bi, tgt, name):
    t = bi.table_get("pipe.Ingress." + name)
    for d, _ in t.entry_get(tgt, [t.make_key([gc.KeyTuple("$COUNTER_INDEX", 0)])], {"from_hw": True}):
        return d.to_dict().get("$COUNTER_SPEC_PKTS", 0)
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-id", type=int, required=True)
    ap.add_argument("--out", required=True, help="append-only JSONL output path")
    ap.add_argument("--seconds", type=float, default=30.0, help="collection window")
    ap.add_argument("--expect", type=int, default=None, help="expected record count (optional)")
    a = ap.parse_args()

    # notifications ENABLED so digests are streamed to this client.
    iface = gc.ClientInterface("localhost:50052", client_id=7, device_id=0,
                               notifications=gc.Notifications(enable_learn=True))
    iface.bind_pipeline_config(PROG)
    bi = iface.bfrt_info_get(PROG)
    tgt = gc.Target(device_id=0, pipe_id=0xffff)

    # seed the run epoch carried in every digest
    rid = bi.table_get("pipe.Ingress.run_id_reg")
    rk = [rid.make_key([gc.KeyTuple("$REGISTER_INDEX", 0)])]
    rd = [rid.make_data([gc.DataTuple("Ingress.run_id_reg.f1", a.run_id)])]
    try:    rid.entry_add(tgt, rk, rd)
    except Exception: rid.entry_mod(tgt, rk, rd)

    g0 = _ctr(bi, tgt, "ctr_grad"); e0 = _ctr(bi, tgt, "ctr_digest_emit")
    learn = bi.learn_get("telem_digest")

    records = []
    seqs = []
    t_end = time.time() + a.seconds
    fout = open(a.out, "a")
    while time.time() < t_end:
        try:
            digest = iface.digest_get(timeout=1)   # blocks up to 1s for a digest list
        except Exception:
            continue
        if digest is None:
            continue
        data_list = learn.make_data_list(digest)
        for d in data_list:
            dd = d.to_dict()
            if int(dd.get("run_id", -1)) != a.run_id:
                continue   # stale batched record from a prior config -> drop (run_id guard)
            t_in = int(dd["t_in"]); t_out = int(dd["t_out"])
            hold_ns = (t_out - t_in) & 0xFFFFFFFF   # 32-bit wrap-safe
            rec = {"run_id": int(dd["run_id"]), "seq": int(dd["seq"]),
                   "target_passes": int(dd["target_passes"]),
                   "t_in": t_in, "t_out": t_out, "hold_ns": hold_ns,
                   "pass_count": int(dd["pass_count"]),
                   "release_reason": REASON.get(int(dd["release_reason"]), int(dd["release_reason"])),
                   "size_state": int(dd["size_state"])}
            fout.write(json.dumps(rec) + "\n")
            records.append(rec); seqs.append(rec["seq"])
    fout.close()

    g1 = _ctr(bi, tgt, "ctr_grad"); e1 = _ctr(bi, tgt, "ctr_digest_emit")
    dg = g1 - g0; de = e1 - e0; nrec = len(records)
    dup = len(seqs) - len(set(seqs))
    missing = (max(seqs) - min(seqs) + 1 - len(set(seqs))) if seqs else 0
    nonpb = sum(1 for r in records if r["release_reason"] != "PASS_BUDGET")
    ok = (dg == de == nrec) and dup == 0 and missing == 0 and nonpb == 0
    print(json.dumps({"run_id": a.run_id, "records": nrec, "ctr_grad_delta": dg,
                      "ctr_digest_emit_delta": de, "dup_seq": dup, "missing_seq": missing,
                      "non_pass_budget": nonpb, "expect": a.expect,
                      "VALID": bool(ok and (a.expect is None or nrec == a.expect))}))


if __name__ == "__main__":
    main()

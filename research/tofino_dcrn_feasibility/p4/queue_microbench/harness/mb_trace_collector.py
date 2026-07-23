#!/usr/bin/env python3.8
"""mb_trace_collector.py — per-release trace DIGEST collector for queue_microbench_trace_v1
(run ON the switch). Mirrors mb_digest_collector.py.

Subscribes to the `telem_digest` learn filter, seeds the control-plane run_id (so batched
records from different runs can never be mixed), and writes ONE append-only JSONL record per
released REAL frame (each frame normalized to 128 B). Then validates COMPLETENESS:

  records == ctr_released delta == ctr_digest_emit delta == receiver count (--expect);
  0 duplicate seq; 0 missing seq (contiguous range);
  every record target_size == 128 and selected_state == STATE_128 (the single state).

Digest fields (pipe.IngressDeparser.telem_digest): run_id, seq, input_size, target_size,
selected_state, device_label, operation_label, direction, transaction_id, ingress_tstamp,
release_tstamp, release_reason, qid.

NOTE: digests emit ONLY when telemetry_enable == 1. Run queue_microbench_trace_setup.py
--telemetry first, or pass --seed-telemetry here to set it from this script.

The bfrt_grpc import is lazy (inside main) so the pure completeness logic below can be unit
tested off-switch. Start this BEFORE generating; stop after; then compare against the receiver.

Usage:  python3.8 mb_trace_collector.py --run-id 1 --out runs/trace_run1.jsonl --seconds 60 --expect 800
"""
import argparse
import json
import sys
import time

SDE = "/home/decps/Downloads/bf-sde-9.13.2/install/lib/python3.8/site-packages"
PROG = "queue_microbench_trace_v1"
DIGEST = "telem_digest"                       # short learn-filter name (full: pipe.IngressDeparser.telem_digest)
TARGET_SIZE = 128
STATE_128 = 1                                 # the single selected_state
REASON = {1: "SIZE_NORM"}                     # REL_SIZE_NORM — only reason in the size microbench


def check_completeness(records, released_delta, digest_emit_delta, expect=None):
    """PURE completeness check (no switch/SDE dependency). `records` is a list of digest dicts
    with at least seq/target_size/selected_state. Returns a result dict incl. a VALID bool.

    A run is VALID iff:
      len(records) == released_delta == digest_emit_delta  (and == expect if given),
      0 duplicate seq, 0 missing seq over [min,max],
      every record target_size == 128 and selected_state == STATE_128.
    """
    nrec = len(records)
    seqs = [int(r["seq"]) for r in records]
    dup = len(seqs) - len(set(seqs))
    missing = (max(seqs) - min(seqs) + 1 - len(set(seqs))) if seqs else 0
    bad_target = sum(1 for r in records if int(r.get("target_size", -1)) != TARGET_SIZE)
    bad_state = sum(1 for r in records if int(r.get("selected_state", -1)) != STATE_128)
    counters_agree = (nrec == released_delta == digest_emit_delta)
    expect_ok = (expect is None) or (nrec == expect)
    valid = bool(counters_agree and expect_ok and dup == 0 and missing == 0
                 and bad_target == 0 and bad_state == 0)
    return {"run_id_records": nrec, "ctr_released_delta": released_delta,
            "ctr_digest_emit_delta": digest_emit_delta, "expect": expect,
            "counters_agree": counters_agree, "dup_seq": dup, "missing_seq": missing,
            "bad_target_size": bad_target, "bad_selected_state": bad_state,
            "seq_min": (min(seqs) if seqs else None), "seq_max": (max(seqs) if seqs else None),
            "VALID": valid}


def _ctr(bi, gc, tgt, name):
    t = bi.table_get("pipe.Ingress." + name)
    for d, _ in t.entry_get(tgt, [t.make_key([gc.KeyTuple("$COUNTER_INDEX", 0)])], {"from_hw": True}):
        return d.to_dict().get("$COUNTER_SPEC_PKTS", 0)
    return 0


def main():
    ap = argparse.ArgumentParser(description="trace digest collector (queue_microbench_trace_v1)")
    ap.add_argument("--run-id", type=int, required=True)
    ap.add_argument("--out", required=True, help="append-only JSONL output path")
    ap.add_argument("--seconds", type=float, default=60.0, help="collection window")
    ap.add_argument("--expect", type=int, default=None, help="receiver frame count (optional completeness pin)")
    ap.add_argument("--seed-telemetry", action="store_true",
                    help="also set telemetry_enable=1 (default: assume setup --telemetry already did)")
    a = ap.parse_args()

    # lazy SDE import (keeps check_completeness importable off-switch)
    sys.path.insert(0, SDE + "/tofino")
    sys.path.insert(0, SDE)
    import bfrt_grpc.client as gc  # noqa: E402  (SDE-only)

    iface = gc.ClientInterface("localhost:50052", client_id=8, device_id=0,
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

    if a.seed_telemetry:
        te = bi.table_get("pipe.Ingress.telemetry_enable")
        tk = [te.make_key([gc.KeyTuple("$REGISTER_INDEX", 0)])]
        td = [te.make_data([gc.DataTuple("Ingress.telemetry_enable.f1", 1)])]
        try:    te.entry_add(tgt, tk, td)
        except Exception: te.entry_mod(tgt, tk, td)

    r0 = _ctr(bi, gc, tgt, "ctr_released")
    e0 = _ctr(bi, gc, tgt, "ctr_digest_emit")
    learn = bi.learn_get(DIGEST)

    records, seqs = [], []
    t_end = time.time() + a.seconds
    fout = open(a.out, "a")
    while time.time() < t_end:
        try:
            digest = iface.digest_get(timeout=1)
        except Exception:
            continue
        if digest is None:
            continue
        for d in learn.make_data_list(digest):
            dd = d.to_dict()
            if int(dd.get("run_id", -1)) != a.run_id:
                continue                                   # stale run -> drop (run_id guard)
            t_in = int(dd["ingress_tstamp"]); t_out = int(dd["release_tstamp"])
            hold_ns = (t_out - t_in) & 0xFFFFFFFF          # 32-bit wrap-safe (single pass -> ~0)
            rec = {"run_id": int(dd["run_id"]), "seq": int(dd["seq"]),
                   "input_size": int(dd["input_size"]), "target_size": int(dd["target_size"]),
                   "selected_state": int(dd["selected_state"]),
                   "device_label": int(dd["device_label"]),
                   "operation_label": int(dd["operation_label"]),
                   "direction": int(dd["direction"]),
                   "transaction_id": int(dd["transaction_id"]),
                   "ingress_tstamp": t_in, "release_tstamp": t_out, "hold_ns": hold_ns,
                   "release_reason": REASON.get(int(dd["release_reason"]), int(dd["release_reason"])),
                   "qid": int(dd["qid"])}
            fout.write(json.dumps(rec) + "\n")
            records.append(rec); seqs.append(rec["seq"])
    fout.close()

    r1 = _ctr(bi, gc, tgt, "ctr_released")
    e1 = _ctr(bi, gc, tgt, "ctr_digest_emit")
    result = check_completeness(records, r1 - r0, e1 - e0, expect=a.expect)
    print(json.dumps(result))


if __name__ == "__main__":
    main()

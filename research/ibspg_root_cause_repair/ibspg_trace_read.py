#!/usr/bin/env python3
"""ibspg_trace_read.py — switch-side TM dequeue-ORDER trace reader.

Reads the on-chip trace written by ibspg_dequeue_oracle.p4 and prints the
recorded dequeue ORDER of the two TM queues on loopback port L
(Q_BLOCK=qid7 vs Q_HOLD=qid1), with per-event timestamp and inter-event delta,
plus a strict-priority verdict. Fails loudly on any integrity violation.

Runs ON THE SWITCH against the loaded program (bfruntime localhost:50052),
python3.8 with the SDE PYTHONPATH, e.g.:
  PYTHONPATH=$SDE/install/lib/python3.8/site-packages:\
$SDE/install/lib/python3.8/site-packages/tofino \
    python3.8 ibspg_trace_read.py --prog ibspg_dequeue_oracle

Register/counter access mirrors ibspg_read.py exactly ($REGISTER_INDEX /
$COUNTER_INDEX keys, data field pulled from entry_get(...).to_dict()).

Exit codes:  0 ok · 2 bind/register-missing · 3 overflow · 4 no events ·
             5 impossible event_ctr · 6 deq-sum != event_ctr
"""
import sys
import argparse
import bfrt_grpc.client as gc

ROLE_NAME = {1: "BLOCK", 2: "HOLD"}   # decode; reserved roles print as R<n>

CTRS = ["ctr_block_enq", "ctr_hold_enq", "ctr_block_deq", "ctr_hold_deq",
        "ctr_trace_overflow", "ctr_nonibspg"]


def die(msg, code):
    print("FAIL: " + msg, file=sys.stderr)
    sys.exit(code)


def _scalar(v):
    """A pipe-scoped read is a scalar; an all-pipes read is a per-pipe list.
    PORT_L (dev_port 8) is on pipe 0, so collapse a list to its live value."""
    if isinstance(v, (list, tuple)):
        return v[0] if len(v) == 1 else max(v)
    return v


def reg_read(bi, tgt, name, idx):
    """Read Register <name> at index <idx>. Mirrors ibspg_read.py's reg idiom."""
    t = bi.table_get("pipe.Ingress." + name)
    k = t.make_key([gc.KeyTuple("$REGISTER_INDEX", idx)])
    val = None
    for d, _ in t.entry_get(tgt, [k], {"from_hw": True}):
        dd = d.to_dict()
        for kk in dd:
            if kk.endswith(".f1") or kk.startswith("Ingress." + name):
                val = dd[kk]
    if val is None:
        return None
    return int(_scalar(val))


def ctr_read(bi, tgt, name, idx=0):
    """Read PACKETS Counter <name> at index <idx>. A Stats-ALU counter needs an
    explicit HW->SW sync before a control-plane read (from_hw alone reads stale
    0), so force SyncCounters first."""
    t = bi.table_get("pipe.Ingress." + name)
    try:
        t.operations_execute(tgt, "SyncCounters")
    except Exception:
        pass  # older SDEs / already-synced: fall back to from_hw read
    k = t.make_key([gc.KeyTuple("$COUNTER_INDEX", idx)])
    v = 0
    for d, _ in t.entry_get(tgt, [k], {"from_hw": True}):
        v = d.to_dict().get("$COUNTER_SPEC_PKTS", 0)
    return int(_scalar(v) or 0)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--prog", default="ibspg_dequeue_oracle",
                    help="loaded p4 program name")
    ap.add_argument("--trace-len", type=int, default=512,
                    help="TRACE_LEN the program was compiled with")
    ap.add_argument("--grpc", default="localhost:50052")
    ap.add_argument("--pipe", type=int, default=0,
                    help="pipe of loopback port L (dev_port 8 -> pipe 0)")
    a = ap.parse_args()

    # ---- bind program (fail loud on failure) ----
    try:
        iface = gc.ClientInterface(a.grpc, client_id=23, device_id=0,
                                   notifications=None)
        iface.bind_pipeline_config(a.prog)
        bi = iface.bfrt_info_get(a.prog)
    except Exception as e:
        die("program bind failed for '%s': %s" % (a.prog, e), 2)

    tgt = gc.Target(device_id=0, pipe_id=a.pipe)

    # ---- headline registers + counters ----
    event_ctr = reg_read(bi, tgt, "reg_event_ctr", 0)
    overflow = reg_read(bi, tgt, "reg_overflow", 0)
    if event_ctr is None:
        die("reg_event_ctr not found / read None — is '%s' really loaded?" % a.prog, 2)
    overflow = overflow or 0
    ctrs = {c: ctr_read(bi, tgt, c) for c in CTRS}

    # ---- integrity gates (fail loud) ----
    if overflow > 0:
        die("reg_overflow=%d (>0): trace overran TRACE_LEN=%d — raise TRACE_LEN "
            "or shorten the run; recorded order is truncated" % (overflow, a.trace_len), 3)
    if event_ctr == 0:
        die("reg_event_ctr=0: no dequeue events recorded (no looped-back traffic "
            "re-entered ingress on PORT_L?)", 4)
    if event_ctr > a.trace_len:
        die("reg_event_ctr=%d > trace_len=%d (impossible; check --trace-len)"
            % (event_ctr, a.trace_len), 5)
    deq_sum = ctrs["ctr_block_deq"] + ctrs["ctr_hold_deq"]
    if deq_sum != event_ctr:
        die("ctr_block_deq+ctr_hold_deq=%d != reg_event_ctr=%d — a dequeued packet "
            "carried a non-BLOCK/HOLD role, or a counter sync failed" % (deq_sum, event_ctr), 6)

    # ---- dump the ordered trace (index 0 dequeued first) ----
    roles, seqs, tss = [], [], []
    for i in range(event_ctr):
        roles.append(reg_read(bi, tgt, "trace_role", i))
        seqs.append(reg_read(bi, tgt, "trace_seq", i))
        tss.append(reg_read(bi, tgt, "trace_ts", i))

    print("event_ctr=%d overflow=%d" % (event_ctr, overflow))
    print("counters: " + " ".join("%s=%d" % (k, ctrs[k]) for k in CTRS))
    print("%5s %6s %12s %16s %10s" % ("idx", "role", "seq", "ts32(ns)", "dt(ns)"))
    prev = None
    for i in range(event_ctr):
        rn = ROLE_NAME.get(roles[i], "R%d" % roles[i])
        dt = "" if prev is None else "%+d" % ((tss[i] - prev) & 0xFFFFFFFF)
        print("%5d %6s %12d %16d %10s" % (i, rn, seqs[i], tss[i], dt))
        prev = tss[i]

    # ---- ordered role string + strict-priority verdict ----
    role_str = " ".join(ROLE_NAME.get(r, "R%d" % r) for r in roles)
    print("ORDER: " + role_str)

    n_block = roles.count(1)
    n_hold = roles.count(2)
    first_hold = next((i for i, r in enumerate(roles) if r == 2), -1)
    last_block = max((i for i, r in enumerate(roles) if r == 1), default=-1)
    # any HOLD before the last BLOCK => a low-priority packet was serviced while
    # high-priority BLOCK packets still remained => strict priority NOT absolute.
    hold_precedes_last_block = (last_block >= 0 and
                                any(roles[i] == 2 for i in range(last_block)))
    print("SUMMARY: n_block=%d n_hold=%d first_hold_idx=%d last_block_idx=%d "
          "hold_precedes_last_block=%s"
          % (n_block, n_hold, first_hold, last_block, hold_precedes_last_block))
    print("strict_priority_clean=%s  (True => every BLOCK dequeued before any HOLD)"
          % (not hold_precedes_last_block))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""ibspg_trace_read2.py — switch-side reader for the RING dequeue-ORDER oracle.

Reads the on-chip trace written by ibspg_ring_oracle.p4 (the self-replenishing
RING variant of ibspg_dequeue_oracle.p4) and, in addition to dumping the recorded
dequeue ORDER (Q_BLOCK=qid7 vs Q_HOLD=qid1 on loopback port L), analyses the
INTER-DEQUEUE TIMESTAMP GAPS. Each RING loop pass is timestamped, so:

  dt[i] = trace_ts[i] - trace_ts[i-1]   (unsigned 32-bit, wrap-safe)

is the time between two consecutive dequeues. A LARGE dt after a BLOCK dequeue
means Q_BLOCK momentarily ran EMPTY while waiting for a token to loop back — an
"empty-gap". A long run of SMALL dt is continuous backlog (the queue stayed hot).

Runs ON THE SWITCH against the loaded program (bfruntime localhost:50052),
python3.8 with the SDE PYTHONPATH, e.g.:
  PYTHONPATH=$SDE/install/lib/python3.8/site-packages:\
$SDE/install/lib/python3.8/site-packages/tofino \
    python3.8 ibspg_trace_read2.py --prog ibspg_ring_oracle

Register/counter reads use an ALL-PIPES target (pipe_id=0xffff) with the
$REGISTER_INDEX / $COUNTER_INDEX keys, extracting the data field robustly. This
FIXES the original reader's counter bug (a pipe-scoped counter target returned
"Entry not found"); an all-pipes read returns a per-pipe list that we collapse.

Exit codes:  0 ok · 2 bind/register-missing · 3 overflow · 4 no events
"""
import sys
import argparse
import bfrt_grpc.client as gc

ROLE_NAME = {1: "BLOCK", 2: "HOLD"}   # decode; reserved roles print as R<n>
ROLE_CH = {1: "B", 2: "H"}

# ring oracle counters (order matters only for the printed line)
CTRS = ["ctr_block_enq", "ctr_hold_enq", "ctr_block_deq", "ctr_hold_deq",
        "ctr_block_loop", "ctr_block_expiry", "ctr_trace_overflow",
        "ctr_nonibspg"]

MASK32 = 0xFFFFFFFF


def die(msg, code):
    print("FAIL: " + msg, file=sys.stderr)
    sys.exit(code)


def _flatten_max(vals):
    """Unwrap any list/tuple values and return the max int (live pipe wins;
    only pipe 0 -- dev_port 8 -- is populated, the rest read 0)."""
    flat = []
    for v in vals:
        if isinstance(v, (list, tuple)):
            flat.extend(v)
        else:
            flat.append(v)
    ints = [int(x) for x in flat if x is not None]
    if not ints:
        return None
    return max(ints)


def _get_table(bi, name):
    """Resolve a bfrt table by short name, tolerant of the pipeline prefix."""
    for cand in ("pipe.Ingress." + name, "Ingress." + name, name):
        try:
            return bi.table_get(cand)
        except Exception:
            continue
    # last resort: scan for any table whose name ends in the short name
    try:
        for tn in bi.table_dict.keys():
            if tn.endswith("." + name) or tn.endswith("Ingress." + name):
                return bi.table_get(tn)
    except Exception:
        pass
    raise KeyError("table not found for '%s'" % name)


def reg_read(bi, tgt, name, idx):
    """Read Register <name> at index <idx> from an all-pipes target. The data
    value lives under a key like 'Ingress.<name>.f1' or '<name>.f1'; take the one
    field that is not $REGISTER_INDEX / action_name / is_* and collapse it."""
    t = _get_table(bi, name)
    k = t.make_key([gc.KeyTuple("$REGISTER_INDEX", idx)])
    vals = []
    for d, _ in t.entry_get(tgt, [k], {"from_hw": True}):
        dd = d.to_dict()
        for kk, vv in dd.items():
            if kk == "$REGISTER_INDEX":
                continue
            if kk == "action_name":
                continue
            if kk.startswith("is_"):
                continue
            vals.append(vv)
    return _flatten_max(vals)


def ctr_read(bi, tgt, name, idx=0):
    """Read PACKETS Counter <name> at index <idx> from an all-pipes target.
    A Stats-ALU counter needs an explicit HW->SW sync before a control-plane
    read (from_hw alone reads stale 0), so force SyncCounters first."""
    t = _get_table(bi, name)
    try:
        t.operations_execute(tgt, "SyncCounters")
    except Exception:
        pass  # older SDEs / already-synced: fall back to from_hw read
    k = t.make_key([gc.KeyTuple("$COUNTER_INDEX", idx)])
    vals = []
    for d, _ in t.entry_get(tgt, [k], {"from_hw": True}):
        dd = d.to_dict()
        if "$COUNTER_SPEC_PKTS" in dd:
            vals.append(dd["$COUNTER_SPEC_PKTS"])
    v = _flatten_max(vals)
    return int(v or 0)


def _median(sorted_xs):
    n = len(sorted_xs)
    if n == 0:
        return 0.0
    if n % 2 == 1:
        return float(sorted_xs[n // 2])
    return (sorted_xs[n // 2 - 1] + sorted_xs[n // 2]) / 2.0


def _pct(sorted_xs, p):
    """Nearest-rank percentile p in [0,100]."""
    n = len(sorted_xs)
    if n == 0:
        return 0
    if n == 1:
        return sorted_xs[0]
    idx = int(round((p / 100.0) * (n - 1)))
    idx = max(0, min(n - 1, idx))
    return sorted_xs[idx]


def _longest_run(flags):
    """Longest contiguous run of True in a bool list."""
    best = 0
    cur = 0
    for f in flags:
        if f:
            cur += 1
            if cur > best:
                best = cur
        else:
            cur = 0
    return best


def analyze_gaps(roles, tss, large_mult):
    """Timestamp-gap analysis over consecutive dequeue events."""
    n = len(tss)
    if n < 2:
        print("gap-analysis: need >=2 events (have %d) — skipping" % n)
        return
    # dt[i] is the gap BEFORE event i (i in 1..n-1), unsigned 32-bit wrap-safe.
    dts = [(tss[i] - tss[i - 1]) & MASK32 for i in range(1, n)]
    s = sorted(dts)
    mn, mx = s[0], s[-1]
    mean = sum(dts) / float(len(dts))
    med = _median(s)
    p95 = _pct(s, 95)

    print("--- inter-dequeue gap analysis (ns; ingress_mac_tstamp is ns on TF1) ---")
    print("events=%d  intervals=%d" % (n, len(dts)))
    print("dt  min=%d  mean=%.1f  median=%.1f  p95=%d  max=%d"
          % (mn, mean, med, p95, mx))

    # large-gap threshold: large_mult x median, with sane fallbacks so a near-zero
    # median does not flag every interval.
    thr = large_mult * med
    if thr <= 0:
        thr = large_mult * mean
    if thr <= 0:
        thr = 1.0

    # compact log-scale histogram of dt
    import math
    buckets = {}
    for dt in dts:
        b = 0 if dt <= 0 else int(math.floor(math.log10(dt)))
        buckets[b] = buckets.get(b, 0) + 1
    print("histogram (log10 dt bucket -> count):")
    for b in sorted(buckets):
        lo = 0 if b == 0 else 10 ** b
        hi = 10 ** (b + 1) - 1
        print("  [%8d .. %8d] : %d" % (lo, hi, buckets[b]))

    # large gaps = empty-gaps; annotate the role transition around each gap
    large = [(i + 1, dts[i]) for i in range(len(dts)) if dts[i] > thr]
    print("large gaps (dt > %.1f = %.1fx median): count=%d"
          % (thr, large_mult, len(large)))
    if large:
        max_gap = max(g for _, g in large)
        print("  max large gap = %d ns" % max_gap)
        show = large if len(large) <= 40 else large[:40]
        for idx, gap in show:
            prev_r = ROLE_NAME.get(roles[idx - 1], "R%d" % roles[idx - 1])
            cur_r = ROLE_NAME.get(roles[idx], "R%d" % roles[idx])
            tag = " (Q_BLOCK went EMPTY)" if roles[idx - 1] == 1 else ""
            print("  idx=%d  dt=%d ns  %s->%s%s"
                  % (idx, gap, prev_r, cur_r, tag))
        if len(large) > 40:
            print("  ... (%d more)" % (len(large) - 40))
    else:
        print("  max large gap = 0 ns (no empty-gaps above threshold)")

    # longest contiguous run of small dt = continuous backlog
    small_flags = [dt <= thr for dt in dts]
    run = _longest_run(small_flags)
    print("longest contiguous small-dt run (<= threshold) = %d intervals "
          "(continuous backlog)" % run)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--prog", default="ibspg_ring_oracle",
                    help="loaded p4 program name")
    ap.add_argument("--trace-len", type=int, default=512,
                    help="TRACE_LEN the program was compiled with")
    ap.add_argument("--grpc", default="localhost:50052")
    ap.add_argument("--large-mult", type=float, default=3.0,
                    help="a dt above this multiple of the median is an empty-gap")
    a = ap.parse_args()

    # ---- bind program (fail loud on failure) ----
    try:
        iface = gc.ClientInterface(a.grpc, client_id=24, device_id=0,
                                   notifications=None)
        iface.bind_pipeline_config(a.prog)
        bi = iface.bfrt_info_get(a.prog)
    except Exception as e:
        die("program bind failed for '%s': %s" % (a.prog, e), 2)

    # all-pipes target for BOTH registers and counters (the fix)
    tgt = gc.Target(device_id=0, pipe_id=0xffff)

    # ---- headline registers + counters ----
    try:
        event_ctr = reg_read(bi, tgt, "reg_event_ctr", 0)
        overflow = reg_read(bi, tgt, "reg_overflow", 0)
    except Exception as e:
        die("register read failed (is '%s' really loaded?): %s" % (a.prog, e), 2)
    if event_ctr is None:
        die("reg_event_ctr not found / read None — is '%s' really loaded?" % a.prog, 2)
    overflow = overflow or 0
    ctrs = {c: ctr_read(bi, tgt, c) for c in CTRS}

    # ---- integrity gates (fail loud) ----
    if overflow > 0:
        die("reg_overflow=%d (>0): trace overran TRACE_LEN=%d — raise TRACE_LEN "
            "or shorten the run; recorded order is truncated"
            % (overflow, a.trace_len), 3)
    if event_ctr == 0:
        die("reg_event_ctr=0: no dequeue events recorded (no looped-back traffic "
            "re-entered ingress on PORT_L?)", 4)
    if event_ctr > a.trace_len:
        # not fatal for the ring reader; clamp and warn (event_ctr saturates at
        # TRACE_LEN by design, but overflow>0 above already catches a real overrun)
        print("WARN: reg_event_ctr=%d clamped to trace_len=%d"
              % (event_ctr, a.trace_len), file=sys.stderr)
        event_ctr = a.trace_len

    # ---- dump the ordered trace (index 0 dequeued first) ----
    roles, seqs, tss = [], [], []
    for i in range(event_ctr):
        roles.append(reg_read(bi, tgt, "trace_role", i) or 0)
        seqs.append(reg_read(bi, tgt, "trace_seq", i) or 0)
        tss.append(reg_read(bi, tgt, "trace_ts", i) or 0)

    print("prog=%s  event_ctr=%d  overflow=%d" % (a.prog, event_ctr, overflow))
    print("counters: " + " ".join("%s=%d" % (k, ctrs[k]) for k in CTRS))
    print("%5s %6s %12s %16s %12s" % ("idx", "role", "seq", "ts32(ns)", "dt(ns)"))
    prev = None
    for i in range(event_ctr):
        rn = ROLE_NAME.get(roles[i], "R%d" % roles[i])
        dt = "" if prev is None else "%+d" % ((tss[i] - prev) & MASK32)
        print("%5d %6s %12d %16d %12s" % (i, rn, seqs[i], tss[i], dt))
        prev = tss[i]

    # ---- ordered role string ----
    role_str = "".join(ROLE_CH.get(r, "?") for r in roles)
    print("ORDER: " + role_str)

    # ---- the point: timestamp-gap / empty-gap analysis ----
    analyze_gaps(roles, tss, a.large_mult)


if __name__ == "__main__":
    main()

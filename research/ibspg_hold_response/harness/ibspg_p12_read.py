#!/usr/bin/env python3
"""ibspg_p12_read.py — evidence reader for the Part 12 HOLD_RESPONSE program.

Runs ON THE SWITCH against the loaded program (bfruntime localhost:50052),
python3.8 with the SDE PYTHONPATH. Read-only: it never actuates a release —
in Part 12 nothing can, the only release causes are the data-plane deadline and
the blocker pass budget.

Prints ONE line:  P12READ {json}

  registers  every named single-entry Register (ns timestamps + state)
  counters   every named Counter's packet count
  tm         Q_BLOCK / Q_RESP strict-priority readback (the load-bearing config)
  derived    the Part 12 result quantities:
               g_observed_ns    = reg_ts_first_resp_release - reg_ts_ack_arm
               deadline_error_ns= g_observed_ns - G            (G from --g-ns/--g-ms)
               release_tail_ns  = reg_ts_first_resp_release - reg_ts_block_term
               block_term_lag_ns= reg_ts_block_term  - reg_ts_ack_arm
             so g_observed_ns == block_term_lag_ns + release_tail_ns: how much of
             the observed interval is the deadline actuating vs the queue draining.

TIMESTAMP WRAP. The on-chip stamps are ingress_mac_tstamp[31:0] — nanoseconds,
32 bits, so they wrap every ~4.295 s. Every difference is taken as an unsigned
32-bit wrap-safe subtraction ((b - a) & 0xFFFFFFFF), which is correct as long as
b really is after a and the true interval is under 4.295 s. G is milliseconds and
the trial is bounded well inside that.

COUNTER SYNC. A Stats-ALU Counter reads stale (typically 0) unless a table-wide
HW->SW sync is forced first; the per-entry {"from_hw": True} flag does NOT force
it. So every counter read is preceded by operations_execute("SyncCounters"),
wrapped in try/except for SDEs that do not expose that op name.

Usage (on switch):
  python3 ibspg_p12_read.py --prog ibspg_hold_response --g-ms 20
  python3 ibspg_p12_read.py --prog ibspg_hold_response --g-ns 20000000 \\
      --regs reg_gen,reg_active,... --counters ctr_arm,...
"""
import argparse
import json
import bfrt_grpc.client as gc

MASK32 = 0xFFFFFFFF

DEFAULT_REGS = ",".join([
    "reg_gen",
    "reg_active",
    "reg_deadline",
    "reg_ts_first_block",
    "reg_ts_ack_arm",
    "reg_ts_block_term",
    "reg_ts_first_resp_release",
])

DEFAULT_CTRS = ",".join([
    "ctr_arm",
    "ctr_block_enq",
    "ctr_block_loop",
    "ctr_block_term_deadline",
    "ctr_block_term_timeout",
    "ctr_block_term_stale",
    "ctr_ack_arm",
    "ctr_ack_bypass",
    "ctr_resp_enq",
    "ctr_resp_release",
    "ctr_nonibspg",
])


def _flatten_max(vals):
    """Collapse an all-pipes read to one int: only pipe 0 (dev_port 8/9/11) is
    populated, the other pipes read 0, so the max is the live value."""
    flat = []
    for v in vals:
        if isinstance(v, (list, tuple)):
            flat.extend(v)
        else:
            flat.append(v)
    ints = []
    for x in flat:
        if x is None:
            continue
        try:
            ints.append(int(x))
        except (TypeError, ValueError):
            continue
    return max(ints) if ints else None


def _get_table(bi, prefix, name):
    """Resolve a bfrt table by short name, tolerant of the pipeline prefix."""
    for cand in (prefix + name, "pipe.Ingress." + name, "Ingress." + name, name):
        try:
            return bi.table_get(cand)
        except Exception:
            continue
    raise KeyError("table not found for '%s'" % name)


def read_register(bi, tgt, prefix, name):
    t = _get_table(bi, prefix, name)
    k = t.make_key([gc.KeyTuple("$REGISTER_INDEX", 0)])
    vals = []
    for d, _ in t.entry_get(tgt, [k], {"from_hw": True}):
        for kk, vv in d.to_dict().items():
            if kk == "$REGISTER_INDEX" or kk == "action_name" or kk.startswith("is_"):
                continue
            vals.append(vv)
    return _flatten_max(vals)


def read_counter(bi, tgt, prefix, name):
    t = _get_table(bi, prefix, name)
    try:
        t.operations_execute(tgt, "SyncCounters")   # blocking HW->SW sync; see docstring
    except Exception:
        pass
    k = t.make_key([gc.KeyTuple("$COUNTER_INDEX", 0)])
    vals = []
    for d, _ in t.entry_get(tgt, [k], {"from_hw": True}):
        dd = d.to_dict()
        if "$COUNTER_SPEC_PKTS" in dd:
            vals.append(dd["$COUNTER_SPEC_PKTS"])
        elif "$COUNTER_SPEC_BYTES" in dd:
            vals.append(dd["$COUNTER_SPEC_BYTES"])
    v = _flatten_max(vals)
    return 0 if v is None else int(v)


def _delta(later, earlier):
    """Wrap-safe unsigned 32-bit interval, or None if either stamp never fired."""
    if not later or not earlier:
        return None
    return (int(later) - int(earlier)) & MASK32


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--prog", default="ibspg_hold_response")
    ap.add_argument("--grpc", default="localhost:50052")
    ap.add_argument("--regs", default=DEFAULT_REGS)
    ap.add_argument("--counters", default=DEFAULT_CTRS)
    ap.add_argument("--g-ms", type=float, default=None, help="guard interval G in ms")
    ap.add_argument("--g-ns", type=int, default=None, help="G in ns; overrides --g-ms")
    ap.add_argument("--pg-l", type=int, default=2, help="port group of the loopback port L (dp8)")
    ap.add_argument("--pg-l-nr", type=int, default=0, help="pg-relative port number of L")
    ap.add_argument("--qb", type=int, default=7, help="Q_BLOCK qid")
    ap.add_argument("--qr", type=int, default=1, help="Q_RESP qid")
    ap.add_argument("--reg-prefix", default="pipe.Ingress.")
    ap.add_argument("--ctr-prefix", default="pipe.Ingress.")
    a = ap.parse_args()

    g_ns = a.g_ns
    if g_ns is None and a.g_ms is not None:
        g_ns = int(round(a.g_ms * 1e6))

    iface = gc.ClientInterface(a.grpc, client_id=61, device_id=0, notifications=None)
    iface.bind_pipeline_config(a.prog)
    bi = iface.bfrt_info_get(a.prog)
    tall = gc.Target(device_id=0, pipe_id=0xffff)
    t0 = gc.Target(device_id=0, pipe_id=0)

    out = {"prog": a.prog, "registers": {}, "counters": {}, "tm": {}, "derived": {}}

    for nm in [x for x in a.regs.split(",") if x]:
        try:
            out["registers"][nm] = read_register(bi, tall, a.reg_prefix, nm)
        except Exception as e:
            out["registers"][nm] = "ERR:" + str(e)[:80]

    for nm in [x for x in a.counters.split(",") if x]:
        try:
            out["counters"][nm] = read_counter(bi, tall, a.ctr_prefix, nm)
        except Exception as e:
            out["counters"][nm] = "ERR:" + str(e)[:80]

    # strict-priority readback: Q_BLOCK (HIGH) must outrank Q_RESP (LOW).
    try:
        q = bi.table_get("tf1.tm.queue.sched_cfg")
        for lbl, qid in (("Q_BLOCK", a.qb), ("Q_RESP", a.qr)):
            pgq = a.pg_l_nr * 8 + qid
            kk = q.make_key([gc.KeyTuple("pg_id", a.pg_l), gc.KeyTuple("pg_queue", pgq)])
            for d, _ in q.entry_get(t0, [kk], {"from_hw": True}):
                dd = d.to_dict()
                out["tm"][lbl] = {"max_priority": dd.get("max_priority"),
                                  "min_priority": dd.get("min_priority"),
                                  "scheduling_enable": dd.get("scheduling_enable"),
                                  "max_rate_enable": dd.get("max_rate_enable"),
                                  "dwrr_weight": dd.get("dwrr_weight")}
    except Exception as e:
        out["tm"]["err"] = str(e)[:120]

    # ---- derived: the Part 12 result --------------------------------------
    r = out["registers"]

    def rv(nm):
        v = r.get(nm)
        return v if isinstance(v, int) else None

    t_ack = rv("reg_ts_ack_arm")
    t_term = rv("reg_ts_block_term")
    t_rel = rv("reg_ts_first_resp_release")

    g_obs = _delta(t_rel, t_ack)
    out["derived"] = {
        "g_ns": g_ns,
        "g_observed_ns": g_obs,
        "deadline_error_ns": (None if (g_obs is None or g_ns is None) else g_obs - g_ns),
        "release_tail_ns": _delta(t_rel, t_term),
        "block_term_lag_ns": _delta(t_term, t_ack),
        "deadline_armed": bool(rv("reg_deadline")),
        "ts_ack_arm": t_ack,
        "ts_block_term": t_term,
        "ts_first_resp_release": t_rel,
    }

    print("P12READ " + json.dumps(out))


if __name__ == "__main__":
    main()

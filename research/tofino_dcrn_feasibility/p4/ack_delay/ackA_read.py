#!/usr/bin/env python3
"""
ackA_read.py — C3 instrumentation reader for dcrn_ackA.p4 (Case A).
Run ON THE SWITCH (decps@10.10.54.15) while bf_switchd is up with the dcrn_ackA program.
Reads the evidence that answers C3 ("can the switch hold a pure ACK until the response event?"):

  1. events Counter        — per-index packet counts (ACK_RELEASED / RESP_RELEASED are the
                             success signals; ACK_MAXPASS / RESP_MAXPASS are the alarms that
                             must stay 0 in a healthy run).
  2. dp68 qid5 TM counters — per-queue pkts/bytes for the QID_HOLD queue (pg_id=17, pg_queue=5).
                             THE pacing evidence: queue-5 counts must rise as the ACK/response
                             recirculate. (Fixed SDE table — discovered at runtime, see below.)
  3. reg_held_count        — the global admission counter (cumulative ACK admits; NO decrement in
                             this build — see the GATE-3 reduction note in dcrn_ackA.p4).
  4. dp8/dp9 port status    — $PORT_UP for Vision (dp8) and Hulk (dp9).

Modes:
  (default)  print a labeled snapshot of all of the above.
  --reset    zero reg_held_count[0] and clear the events Counter (per-index -> 0), so each C3
             interval series (2/5/10/16/20 ms) starts from a known baseline. Prints before/after.
  --json     emit the snapshot as ONE JSON line (for scripted before/after diffing).

Reliability note (C3 0-read fix): the Stats-ALU Counter read 0 for every index on HW even though
  reg_held_count (a Register) read 9 — because a standalone Counter needs a blocking HW->SW sync
  (operations_execute('SyncCounters')) that the per-entry {"from_hw":True} flag did not force.
  read_events() now issues that sync; and the four stop-condition events are ALSO tallied in
  dedicated Registers (evstat_ack/evstat_resp) which are the AUTHORITATIVE source (Registers read
  live, proven by reg_held_count). ACK_RELEASED/RESP_RELEASED/ACK_MAXPASS/RESP_MAXPASS come from
  read_evstat; the Counter is a cross-check.

Name provenance:
  CONFIRMED from build_ackA_9.13.1/bfrt.json (local):
    events   : pipe.DcrnIngress.events        key $COUNTER_INDEX   data $COUNTER_SPEC_PKTS  (PACKETS)
    register : pipe.DcrnIngress.reg_held_count key $REGISTER_INDEX  data DcrnIngress.reg_held_count.f1
    evstat   : pipe.DcrnIngress.evstat_ack  / .evstat_resp  key $REGISTER_INDEX
               data DcrnIngress.evstat_ack.f1 / .evstat_resp.f1   (idx 0=RELEASED, 1=MAXPASS)
  CONFIRM-ON-SWITCH: the operations_execute('SyncCounters') op name (try/except falls back to the
    per-entry from_hw read if the name differs).
  CONFIRMED from dcrn_ackA.p4 (the EV_* index map, EV_NAMES below).
  CONFIRM-ON-SWITCH (fixed SDE tables, not in the program bfrt.json):
    - the TM per-queue counter table name + its key/data fields. This script DISCOVERS it from the
      live bfrt table_dict (candidates TM_Q_CANDIDATES) and, on the discovered table, dumps ALL
      data fields for the (pg_id,pg_queue) entry so the pkts/bytes field is surfaced regardless of
      its exact name. If none is found it lists the available TM/counter tables to lock on-switch.
    - $PORT field $PORT_UP (standard, but read-only status field — confirm if absent).
    - the entry_get `{"from_hw": True}` flag idiom (standard bfrt_grpc; confirm if the API differs).
Author: Philip
"""
import sys
import json
import argparse

SDE_PY = "/home/decps/Downloads/bf-sde-9.13.2/install/lib/python3.8/site-packages"

PROG = "dcrn_ackA"
PORT_VISION, PORT_HULK = 8, 9
PG_ID, PG_QUEUE = 17, 5          # dp68 QID_HOLD queue (PG_PORT_NR*8 + QID_HOLD = 0*8 + 5) per ackA_setup.py

# events Counter index -> name  (CONFIRMED from dcrn_ackA.p4 EV_* constants).
EV_NAMES = {
    0:  "PASSTHRU",
    1:  "ARMED",
    2:  "ACK_HELD",
    3:  "ACK_RELEASED",      # normal event-governed ACK release (success)
    4:  "RESP_HELD",
    5:  "RESP_RELEASED",     # response released after the ACK (success)
    6:  "COMBINED_BYPASS",
    7:  "WATERMARK_BYPASS",
    8:  "STALE_FLUSH",       # DEFINED but NOT incremented in this build (no stale-flush branch)
    9:  "ARM_BYPASS",        # request seen, FC not allowlisted
    10: "ACK_MAXPASS",       # ALARM: ACK fail-open cap hit — must stay 0
    11: "RESP_MAXPASS",      # ALARM: response safety net hit — must stay 0
}
EV_N = 16                    # Counter size in dcrn_ackA.p4

# Candidate fixed TM per-queue counter tables (9.13.x); discovered/confirmed at runtime.
TM_Q_CANDIDATES = ["tf1.tm.counter.queue", "tf1.tm.queue.counter", "tf1.tm.counter.eg_queue"]


def parse_args():
    ap = argparse.ArgumentParser(description="C3 instrumentation reader for dcrn_ackA.")
    ap.add_argument("--reset", action="store_true",
                    help="zero reg_held_count and clear the events Counter (print before/after)")
    ap.add_argument("--json", action="store_true", help="emit the snapshot as one JSON line")
    return ap.parse_args()


# ---- low-level helpers (bfrt_grpc `gc` passed in) -------------------------------------------------

def _get_one(t, tgt, key, from_hw=True):
    """entry_get one row; return the data as a dict (or {}). Tolerates a not-yet-materialized
    counter entry (a zero-valued indexed counter can read as 'Entry not found' before its first
    increment) by returning {} -> the caller treats it as 0."""
    try:
        for data, _k in t.entry_get(tgt, [key], {"from_hw": from_hw}):
            return data.to_dict()
    except Exception:
        return {}
    return {}


def read_events(bi, gc, tgt0):
    """Return {name: pkts} for every events Counter index.
    ROOT CAUSE of the C3 0-read: a standalone Stats-ALU Counter needs a HW->SW SYNC before the
    control plane can read it; the per-entry {"from_hw": True} flag did NOT force that sync on
    9.13.2, so every index read back the stale (0) SW copy — even EV_ACK_HELD, which shares the
    held_check_inc path that drove reg_held_count to 9. Registers read live, so reg_held_count was
    correct. Fix: operations_execute('SyncCounters') (a blocking table-wide sync) BEFORE reading.
    The evstat_* Registers (read_evstat) are the AUTHORITATIVE reliable source regardless."""
    t = bi.table_get("pipe.DcrnIngress.events")
    try:
        t.operations_execute(tgt0, "SyncCounters")     # blocking HW->SW counter sync (confirm op name on-switch)
    except Exception:
        pass                                           # fall back to the per-entry read below
    out = {}
    for idx in range(EV_N):
        name = EV_NAMES.get(idx, "EV_%d" % idx)
        d = _get_one(t, tgt0, t.make_key([gc.KeyTuple("$COUNTER_INDEX", idx)]), from_hw=True)
        out[name] = int(d.get("$COUNTER_SPEC_PKTS", 0))
    return out


# evstat register layout: index 0 = *_RELEASED, index 1 = *_MAXPASS
EVSTAT_REGS = [("evstat_ack",  ["ACK_RELEASED",  "ACK_MAXPASS"]),
               ("evstat_resp", ["RESP_RELEASED", "RESP_MAXPASS"])]


def read_evstat(bi, gc, tgt0):
    """AUTHORITATIVE reliable tallies for the 4 stop-condition events, read via bfrt Registers
    (immune to the Stats-ALU sync issue that zeroed the Counter). Names -> counts."""
    out = {}
    for reg, names in EVSTAT_REGS:
        t = bi.table_get("pipe.DcrnIngress.%s" % reg)
        for idx, nm in enumerate(names):
            d = _get_one(t, tgt0, t.make_key([gc.KeyTuple("$REGISTER_INDEX", idx)]))
            v = d.get("DcrnIngress.%s.f1" % reg, 0)
            out[nm] = int(v[0]) if isinstance(v, (list, tuple)) else int(v)
    return out


def read_held_count(bi, gc, tgt0):
    """Return reg_held_count[0] (pipe-0 value)."""
    t = bi.table_get("pipe.DcrnIngress.reg_held_count")
    d = _get_one(t, tgt0, t.make_key([gc.KeyTuple("$REGISTER_INDEX", 0)]))
    v = d.get("DcrnIngress.reg_held_count.f1", 0)
    return int(v[0]) if isinstance(v, (list, tuple)) else int(v)   # single-pipe read, but be defensive


def read_queue_counters(bi, gc, tgt0):
    """Discover the fixed TM per-queue counter table and dump the qid5 entry's fields.
    Returns {"table":name,"key":{...},"fields":{...}} or {"error":...,"candidates":[...]}"""
    avail = set(bi.table_dict.keys())
    tries = [n for n in TM_Q_CANDIDATES if n in avail]
    # widen: any TM table that looks like a queue counter
    if not tries:
        tries = sorted(n for n in avail
                       if "tm" in n.lower() and "counter" in n.lower()
                       and ("queue" in n.lower() or n.lower().rstrip(".q").endswith("q")))
    for tname in tries:
        try:
            t = bi.table_get(tname)
            key = t.make_key([gc.KeyTuple("pg_id", PG_ID), gc.KeyTuple("pg_queue", PG_QUEUE)])
            d = _get_one(t, tgt0, key)
            if d:
                return {"table": tname, "key": {"pg_id": PG_ID, "pg_queue": PG_QUEUE}, "fields": d}
        except Exception as e:                      # key/field name mismatch on this candidate
            continue
    # nothing worked -> surface what's available for on-switch lock-in
    tm_counter_tables = sorted(n for n in avail if "tm" in n.lower() and "counter" in n.lower())
    return {"error": "no TM per-queue counter table matched (confirm-on-switch)",
            "candidates_tried": tries, "tm_counter_tables_available": tm_counter_tables}


def read_ports(bi, gc, tgt):
    """Return {dev_port: up_bool}."""
    t = bi.table_get("$PORT")
    out = {}
    for dp in (PORT_VISION, PORT_HULK):
        try:
            d = _get_one(t, tgt, t.make_key([gc.KeyTuple("$DEV_PORT", dp)]))
            out[dp] = bool(d.get("$PORT_UP", False))
        except Exception as e:
            out[dp] = "err:%s" % e
    return out


def snapshot(bi, gc, tgt, tgt0):
    return {
        "evstat":      read_evstat(bi, gc, tgt0),       # AUTHORITATIVE reliable event tallies
        "events":      read_events(bi, gc, tgt0),       # Stats-ALU Counter (now SyncCounters'd; cross-check)
        "held_count":  read_held_count(bi, gc, tgt0),
        "queue_qid5":  read_queue_counters(bi, gc, tgt0),
        "ports":       read_ports(bi, gc, tgt),
    }


def do_reset(bi, gc, tgt0):
    """Zero reg_held_count[0] (the important reset). Clearing the events Counter is best-effort — a
    zero-valued indexed counter cannot always be entry_mod'd; a fresh load already reads 0, and the
    C3 series diffs before/after, so an uncleared counter is fine."""
    rt = bi.table_get("pipe.DcrnIngress.reg_held_count")
    rt.entry_mod(tgt0, [rt.make_key([gc.KeyTuple("$REGISTER_INDEX", 0)])],
                 [rt.make_data([gc.DataTuple("DcrnIngress.reg_held_count.f1", 0)])])
    # zero the reliable event registers (both indices) — these are the authoritative C3 tallies
    for reg, _names in EVSTAT_REGS:
        et = bi.table_get("pipe.DcrnIngress.%s" % reg)
        for idx in (0, 1):
            et.entry_mod(tgt0, [et.make_key([gc.KeyTuple("$REGISTER_INDEX", idx)])],
                         [et.make_data([gc.DataTuple("DcrnIngress.%s.f1" % reg, 0)])])
    ev = bi.table_get("pipe.DcrnIngress.events")
    for idx in range(EV_N):
        try:
            ev.entry_mod(tgt0, [ev.make_key([gc.KeyTuple("$COUNTER_INDEX", idx)])],
                         [ev.make_data([gc.DataTuple("$COUNTER_SPEC_PKTS", 0)])])
        except Exception:
            pass   # counter clears only after first increment; diffing handles the rest


# ---- printing ------------------------------------------------------------------------------------

def print_snapshot(snap, header="SNAPSHOT"):
    print("=== ackA_read %s (program=%s) ===" % (header, PROG))
    print("  RELIABLE event registers (AUTHORITATIVE for the C3 stop condition):")
    for nm in ("ACK_RELEASED", "RESP_RELEASED", "ACK_MAXPASS", "RESP_MAXPASS"):
        note = "  <- ALARM (must be 0)" if nm.endswith("MAXPASS") else "  <- success"
        print("      %-14s %d%s" % (nm, snap.get("evstat", {}).get(nm, 0), note))
    print("  events Counter (pkts) [cross-check; SyncCounters'd]:")
    for i in range(EV_N):
        name = EV_NAMES.get(i, "EV_%d" % i)
        note = ""
        if name in ("ACK_RELEASED", "RESP_RELEASED"): note = "  <- success"
        if name in ("ACK_MAXPASS", "RESP_MAXPASS"):   note = "  <- ALARM (must be 0)"
        if name == "STALE_FLUSH":                     note = "  (unused in this build)"
        print("      [%2d] %-16s %d%s" % (i, name, snap["events"].get(name, 0), note))
    print("  reg_held_count[0] : %s   (admission counter — cumulative admits, no decrement in this build)"
          % snap["held_count"])
    q = snap["queue_qid5"]
    if "error" in q:
        print("  dp68 qid5 TM ctrs : CONFIRM-ON-SWITCH — %s" % q["error"])
        print("      tried        : %s" % q.get("candidates_tried"))
        print("      TM counter tables available: %s" % q.get("tm_counter_tables_available"))
    else:
        print("  dp68 qid5 TM ctrs : table=%s key=%s" % (q["table"], q["key"]))
        for k, v in q["fields"].items():
            print("      %-28s %s" % (k, v))
    print("  ports             : dp%d Vision up=%s  dp%d Hulk up=%s"
          % (PORT_VISION, snap["ports"].get(PORT_VISION), PORT_HULK, snap["ports"].get(PORT_HULK)))


def main():
    args = parse_args()
    # Import bfrt only for a real run (keeps py_compile / --help usable off-switch).
    sys.path.insert(0, SDE_PY + "/tofino")
    sys.path.insert(0, SDE_PY)
    import bfrt_grpc.client as gc

    iface = gc.ClientInterface("localhost:50052", client_id=3, device_id=0, notifications=None)
    iface.bind_pipeline_config(PROG)
    bi   = iface.bfrt_info_get(PROG)
    tgt  = gc.Target(device_id=0, pipe_id=0xffff)
    tgt0 = gc.Target(device_id=0, pipe_id=0)        # counters/registers/TM live in workload pipe 0

    if args.reset:
        before = snapshot(bi, gc, tgt, tgt0)
        do_reset(bi, gc, tgt0)
        after = snapshot(bi, gc, tgt, tgt0)
        if args.json:
            print(json.dumps({"before": before, "after": after}))
        else:
            print_snapshot(before, header="BEFORE RESET")
            print_snapshot(after,  header="AFTER RESET")
        return

    snap = snapshot(bi, gc, tgt, tgt0)
    if args.json:
        print(json.dumps(snap))
    else:
        print_snapshot(snap)


if __name__ == "__main__":
    main()

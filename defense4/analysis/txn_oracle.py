#!/usr/bin/env python3
"""Defense 4 offline transaction oracle (v3).

Parses a DNP3-over-TCP capture into COMPLETE bidirectional wire sequences with correct TCP
connection-lifecycle handling, and annotates every DNP3 unit with txn_id, phase, ack_assoc,
fragment, outer_len, expected_slot.

v3 corrections (review of v2):
  * SYN / FIN / RST frames are CONNECTION-CONTROL, never transaction units. They are surfaced per
    transaction as `teardown` / `conn_ctrl` so the per-transaction TCP-teardown LEAK is visible,
    not silently dropped.
  * A pure TCP ACK is resolved against the data it acknowledges: `tcp.ack == seq+len` of a prior
    opposite-direction DNP3 unit. An ACK that acknowledges only a FIN (teardown) or nothing is
    connection-control and is NOT a DNP3 unit — v2 wrongly labelled the teardown ACK `final_ack`.
  * A transaction closes ONLY on an ACK demonstrably acknowledging the TERMINAL response
    (READ-response / OPERATE-response). If the terminal response is instead acknowledged by a FIN
    (per-transaction teardown), the transaction closes with **slot 5 ABSENT** (no clean DNP3 final
    ACK — the connection tears down instead).
  * Piggyback-ACK detection uses the TCP **ACK flag** (+ ack number), NOT the PSH flag.

Read-only. Uses tshark (via `sg wireshark`); no P4, no switch, no relay.

Size layers (directive §5):
  frame_len = observer INNER Ethernet length EXCL FCS (pcap) ; ip_len ; tcp_len (DNP3 payload) ;
  dnp3_len (DNP3 link LENGTH octet) ; outer_len = PUBLIC OUTER on-wire length under FROZEN format (b).

FROZEN outer format (b) — outer Ethernet + Defense-4 header + COMPLETE inner Ethernet frame:
  [ outer Ethernet 14 ][ D4 header 8 (incl 16-bit inner_len) ][ inner frame = frame_len ][ FCS 4 ]
  => outer_len = frame_len + 14 + 8 + 4 = frame_len + 26.
PROVISIONAL until MB-8 implements/verifies it. (Ethernet terms: payload MTU 1500 B; max standard
frame 1514 B excl FCS / 1518 B incl FCS — an oversized unit FAILS OPEN, it is never clamped.)

Usage:
    txn_oracle.py <pcap> ...            summarize
    txn_oracle.py --json <pcap> ...     dump annotated corpus as JSON
    txn_oracle.py --slots <pcap> ...    provisional slot-pattern derivation
"""
import json
import subprocess
import sys
from pathlib import Path

FUNC = {0: "CONFIRM", 1: "READ", 2: "WRITE", 3: "SELECT", 4: "OPERATE",
        5: "DIRECT_OP", 6: "DIRECT_OP_NR", 20: "EN_UNSOL", 21: "DIS_UNSOL",
        129: "RESPONSE", 130: "UNSOL_RESP"}
FIELDS = ["frame.number", "frame.time_relative", "ip.src", "ip.dst",
          "frame.len", "ip.len", "tcp.len", "tcp.flags.str",
          "dnp3.al.func", "dnp3.len", "dnp3.al.seq", "tcp.seq", "tcp.ack"]

OUTER_ETH, D4_HDR, FCS = 14, 8, 4
OUTER_OVERHEAD = OUTER_ETH + D4_HDR + FCS   # = 26

# Corrected 6-slot Candidate-A3 mapping: (op, phase) -> public grid slot.
SLOT_OF_PHASE = {
    ("READ", "read_req"): 0, ("READ", "sep_ack"): 1,
    ("READ", "read_resp"): 4, ("READ", "final_ack"): 5,
    ("SBO", "select"): 0, ("SBO", "select_resp"): 1, ("SBO", "sbo_ack"): 2,
    ("SBO", "operate"): 3, ("SBO", "operate_resp"): 4, ("SBO", "final_ack"): 5,
}


def tshark(pcap):
    fld = " ".join("-e %s" % f for f in FIELDS)
    cmd = ("tshark -r %s -Y 'tcp.port==20000' -T fields %s 2>/dev/null" % (pcap, fld))
    out = subprocess.run(["sg", "wireshark", "-c", cmd], capture_output=True, text=True).stdout
    rows = []
    for line in out.splitlines():
        c = line.split("\t")
        if len(c) < len(FIELDS):
            c += [""] * (len(FIELDS) - len(c))

        def i(x):
            try:
                return int(x)
            except ValueError:
                return None

        def f(x):
            try:
                return float(x)
            except ValueError:
                return None
        rows.append({
            "frame": i(c[0]), "t": f(c[1]), "src": c[2], "dst": c[3],
            "frame_len": i(c[4]), "ip_len": i(c[5]), "tcp_len": i(c[6]) or 0,
            "flags": c[7], "func": i(c[8]), "dnp3_len": i(c[9]), "app_seq": i(c[10]),
            "tcp_seq": i(c[11]), "tcp_ack": i(c[12]),
        })
    return rows


def classify(rows):
    """Direction + role. Connection-control (SYN/FIN/RST) is its own role, never a DNP3 unit."""
    master_ips, out_ips = set(), set()
    for r in rows:
        if r["func"] in (1, 3, 4, 2, 20, 21, 0):
            master_ips.add(r["src"])
        if r["func"] in (129, 130):
            out_ips.add(r["src"])
    master = next(iter(master_ips), None)
    outst = next(iter(out_ips), None)
    ann = []
    for r in rows:
        d = "M->O" if r["src"] == master else ("O->M" if r["src"] == outst else "?")
        f = r["flags"] or ""
        is_conn_ctrl = ("S" in f or "F" in f or "R" in f)     # SYN/FIN/RST => connection-control
        is_pure_ack = (not is_conn_ctrl and r["tcp_len"] == 0 and "A" in f and r["func"] is None)
        is_fragment = (not is_conn_ctrl and r["tcp_len"] > 0 and r["func"] is None)
        role = ("conn_ctrl" if is_conn_ctrl else
                "pure_ACK" if is_pure_ack else
                "tcp_frag" if is_fragment else
                FUNC.get(r["func"], "data:%s" % r["func"]) if r["func"] is not None else
                "tcp_other")
        # piggyback ACK = a DATA frame that also carries a TCP ACK (ACK flag), NOT the PSH flag
        piggyback = (r["func"] is not None and "A" in f and r["tcp_len"] > 0)
        ann.append({**r, "dir": d, "role": role, "flagset": f,
                    "conn_ctrl": is_conn_ctrl, "pure_ack": is_pure_ack,
                    "piggyback_ack": piggyback, "fragment": is_fragment})
    return ann, master, outst


def _seq_end(u):
    if u.get("tcp_seq") is None:
        return None
    return u["tcp_seq"] + u["tcp_len"]


def transactions(ann):
    """Group frames into transactions with correct connection-lifecycle handling (v3)."""
    txns, cur = [], None

    def close():
        nonlocal cur
        if cur is not None:
            txns.append(cur)
            cur = None

    for a in ann:
        role, d = a["role"], a["dir"]

        if role == "conn_ctrl":
            if cur is not None:
                cur.setdefault("conn_ctrl", []).append(
                    "%s %s" % (a["flagset"].replace("·", ""), d))
                if cur.get("terminal_reached") and ("F" in a["flagset"] or "R" in a["flagset"]):
                    cur["closed_by"] = "teardown"      # response acked by FIN -> no clean final ACK
                    close()
            continue

        if role in ("READ", "SELECT") and d == "M->O":
            close()
            cur = {"op": "READ" if role == "READ" else "SBO", "units": [a],
                   "resp_seen": 0, "operate_seen": False, "terminal_reached": False,
                   "closed_by": None, "conn_ctrl": []}
            a["_phase"] = "read_req" if role == "READ" else "select"
            continue

        if cur is None:
            continue

        if role == "pure_ACK":
            acked = None
            for p in reversed(cur["units"]):
                if p["dir"] != d and p["tcp_len"] > 0 and _seq_end(p) == a.get("tcp_ack"):
                    acked = p
                    break
            if acked is None:
                continue                                # acks a FIN / nothing => connection-control
            a["_acks"] = acked.get("_phase")
            cur["units"].append(a)
            if cur["terminal_reached"] and acked.get("_is_terminal"):
                a["_phase"] = "final_ack"
                cur["closed_by"] = "final_ack"
                close()
            elif cur["op"] == "READ" and acked.get("_phase") == "read_req":
                a["_phase"] = "sep_ack"          # outstation's separate ACK of the READ (slot 1)
            elif cur["op"] == "SBO" and acked.get("_phase") == "select_resp":
                a["_phase"] = "sbo_ack"          # master's ACK of the SELECT-response (slot 2)
            else:
                a["_phase"] = "mid_ack"
            continue

        # DNP3 data unit
        cur["units"].append(a)
        if role == "OPERATE" and d == "M->O":
            cur["operate_seen"] = True
            a["_phase"] = "operate"
        elif role == "RESPONSE" and d == "O->M":
            cur["resp_seen"] += 1
            if cur["op"] == "READ":
                a["_phase"] = "read_resp"
            else:
                a["_phase"] = "select_resp" if cur["resp_seen"] == 1 else "operate_resp"
        elif role == "SELECT":
            a["_phase"] = "select"
        elif role == "tcp_frag":
            a["_phase"] = "fragment"
        else:
            a["_phase"] = "other"
        is_term = ((cur["op"] == "READ" and role == "RESPONSE") or
                   (cur["op"] == "SBO" and role == "RESPONSE"
                    and cur["operate_seen"] and cur["resp_seen"] >= 2))
        if is_term:
            a["_is_terminal"] = True
            cur["terminal_reached"] = True
    close()
    return txns


def annotate_units(txn, txn_id):
    seq = []
    for u in txn["units"]:
        phase = u.get("_phase", "other")
        if u["pure_ack"]:
            ack_assoc = {"kind": "pure", "acks_phase": u.get("_acks")}
        elif u["piggyback_ack"]:
            ack_assoc = {"kind": "piggyback", "acks_phase": None}
        else:
            ack_assoc = {"kind": "none", "acks_phase": None}
        outer_len = (u["frame_len"] + OUTER_OVERHEAD) if u["frame_len"] else None
        seq.append({
            "txn_id": txn_id, "op": txn["op"], "phase": phase,
            "dir": u["dir"], "role": u["role"],
            "frame_len": u["frame_len"], "tcp_len": u["tcp_len"],
            "ip_len": u["ip_len"], "dnp3_len": u["dnp3_len"], "outer_len": outer_len,
            "pure_ack": u["pure_ack"], "piggyback_ack": u["piggyback_ack"],
            "ack_assoc": ack_assoc, "fragment": u["fragment"],
            "expected_slot": SLOT_OF_PHASE.get((txn["op"], phase)),
            "t": u["t"], "app_seq": u["app_seq"],
        })
    return seq


def summarize(pcap):
    rows = tshark(pcap)
    ann, master, outst = classify(rows)
    txns = transactions(ann)
    stem = Path(pcap).name
    out = {"pcap": stem, "master": master, "outstation": outst,
           "n_frames": len(rows), "n_txns": 0, "txns": []}
    idx = 0
    for t in txns:
        seq = annotate_units(t, "%s#%d" % (stem, idx))
        roles = [u["role"] for u in seq]
        if not any(r in ("READ", "SELECT", "OPERATE") for r in roles):
            continue
        idx += 1
        slots = [u["expected_slot"] for u in seq]
        out["txns"].append({
            "txn_id": "%s#%d" % (stem, idx - 1), "op": t["op"],
            "closed_by": t.get("closed_by"),
            "slot5_present": 5 in slots,
            "conn_ctrl": t.get("conn_ctrl", []),
            "n_units": len(seq),
            "dir_seq": [u["dir"] for u in seq],
            "role_seq": roles,
            "phase_seq": [u["phase"] for u in seq],
            "slot_seq": slots,
            "frame_lens": [u["frame_len"] for u in seq],
            "outer_lens": [u["outer_len"] for u in seq],
            "fragments": sum(1 for u in seq if u["fragment"]),
            "units": seq,
        })
    out["n_txns"] = len(out["txns"])
    return out


def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return 1
    mode = None
    if args and args[0] in ("--json", "--slots"):
        mode, args = args[0], args[1:]
    results = [summarize(p) for p in args]
    if mode == "--json":
        print(json.dumps(results, indent=1))
    elif mode == "--slots":
        derive_slots(results)
    else:
        for r in results:
            print("=== %s : %d txns ===" % (r["pcap"], r["n_txns"]))
            for t in r["txns"]:
                print("  %-4s units=%d dir=%s closed_by=%s slot5=%s"
                      % (t["op"], t["n_units"],
                         "".join("M" if d == "M->O" else "O" for d in t["dir_seq"]),
                         t["closed_by"], t["slot5_present"]))
                print("       phase=%s" % t["phase_seq"])
                print("       slot =%s  conn_ctrl=%s" % (t["slot_seq"], t["conn_ctrl"]))
    return 0


def derive_slots(results):
    reads = [t for r in results for t in r["txns"] if t["op"] == "READ"]
    sbos = [t for r in results for t in r["txns"] if t["op"] == "SBO"]
    print("## PROVISIONAL slot derivation (NOT frozen — directive §7/§8)\n")
    print("READ txns: %d ; SBO txns: %d" % (len(reads), len(sbos)))
    r_s5 = sum(1 for t in reads if t["slot5_present"])
    s_s5 = sum(1 for t in sbos if t["slot5_present"])
    print("slot-5 (real terminal ACK) present: READ %d/%d ; SBO %d/%d"
          % (r_s5, len(reads), s_s5, len(sbos)))
    td = sum(1 for t in sbos if t["closed_by"] == "teardown")
    print("SBO closed by per-txn TCP teardown (connection-lifecycle LEAK): %d/%d\n" % (td, len(sbos)))
    by_slot = {}
    for t in reads + sbos:
        for u in t["units"]:
            s = u["expected_slot"]
            if s is None or not u["frame_len"]:
                continue
            b = by_slot.setdefault(s, {"dir": set(), "ph": set(), "inner": []})
            b["dir"].add(u["dir"])
            b["ph"].add(u["phase"])
            b["inner"].append(u["frame_len"])
    print("  slot  dir    inner_max  outer_public  phases")
    for s in sorted(by_slot):
        b = by_slot[s]
        im = max(b["inner"])
        print("  %-4d  %-5s  %-9d  %-12d  %s"
              % (s, "/".join(sorted(b["dir"])), im, im + OUTER_OVERHEAD, sorted(b["ph"])))
    print("\nNOTE: if SBO slot-5 is absent (per-txn teardown), a real terminal ACK for SBO requires a "
          "PERSISTENT-connection rerun; the READ slot-5 is real. τ0..τ5 are grid times, provisional "
          "until MB-8 + the grid microbench. Oversized units FAIL OPEN (payload MTU 1500 B; max frame "
          "1514 B excl FCS / 1518 incl), never clamp.")


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Defense 4 offline transaction oracle (v2).

Parses a DNP3-over-TCP capture into COMPLETE bidirectional wire sequences and annotates every
visible unit with the six fields the implementation plan promises: **txn_id, phase, ack_assoc,
fragment, outer_len, expected_slot** — plus direction, role, and layered sizes. It models READ and
full SBO (SELECT / SELECT-RESPONSE / OPERATE / OPERATE-RESPONSE), pure TCP ACKs, piggybacked ACKs,
missing ACKs, and TCP fragmentation of oversized requests.

Read-only. Uses tshark (via `sg wireshark`) for the DNP3 dissection; no P4, no switch, no relay.

TRANSACTION CLOSURE (v2 fix): a transaction closes at its FINAL ACK — the pure M→O ACK that follows
the terminal response (the RESPONSE for READ; the OPERATE-RESPONSE for SBO). Frames between
transactions (TCP keepalive ACKs) belong to no transaction and are dropped, so a READ is exactly its
four units and not "four plus the next keepalive".

Terminology (directive §5): every size is reported at its explicit layer —
  frame_len   = observer-visible INNER Ethernet frame length EXCLUDING the 4-byte FCS (pcap convention)
  ip_len      = IP total length
  tcp_len     = TCP payload length (the DNP3-carrying bytes; the '14.6 B/CROB' layer)
  dnp3_len    = the DNP3 link-layer LENGTH octet
  outer_len   = derived PUBLIC OUTER on-wire Ethernet length under the FROZEN format (b), see below.
Inner on-wire Ethernet = frame_len + 4 (FCS). Constant inner overhead here: frame_len - tcp_len = 66 B
(14 Ethernet + 20 IP + 32 TCP-with-timestamps).

FROZEN outer format (b) — outer Ethernet + Defense-4 header + COMPLETE inner Ethernet frame:
  [ outer Ethernet 14 ][ D4 header 8 ][ complete inner frame = frame_len ][ outer FCS 4 ]
  => outer_len = frame_len + OUTER_ETH(14) + D4_HDR(8) + FCS(4) = frame_len + 26.
This is a candidate for MB-8 to implement/verify; the numbers are PROVISIONAL until MB-8 runs.

Usage:
    txn_oracle.py <pcap> [<pcap> ...]           annotate + summarize each capture
    txn_oracle.py --json <pcap> ...             dump full annotated corpus as JSON
    txn_oracle.py --slots <pcap> ...            derive provisional slot-pattern candidates
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

# FROZEN outer format (b) overhead (bytes). See module docstring.
OUTER_ETH = 14
D4_HDR = 8
FCS = 4
OUTER_OVERHEAD = OUTER_ETH + D4_HDR + FCS   # = 26

# Corrected 6-slot Candidate-A2 mapping: (op, phase) -> public grid slot.
# READ occupies slots 0,1,4,5 (slots 2,3 are filler); SBO fills all six.
SLOT_OF_PHASE = {
    ("READ", "read_req"): 0, ("READ", "sep_ack"): 1,
    ("READ", "read_resp"): 4, ("READ", "final_ack"): 5,
    ("SBO", "select"): 0, ("SBO", "select_resp"): 1, ("SBO", "sbo_ack"): 2,
    ("SBO", "operate"): 3, ("SBO", "operate_resp"): 4, ("SBO", "final_ack"): 5,
}


def tshark(pcap):
    """Return the per-frame table for one TCP/20000 capture, via sg wireshark."""
    fld = " ".join("-e %s" % f for f in FIELDS)
    # tshark's default -T fields separator is already a real TAB; passing
    # -E separator='\t' emits the two literal characters backslash-t instead.
    cmd = ("tshark -r %s -Y 'tcp.port==20000' -T fields %s 2>/dev/null"
           % (pcap, fld))
    out = subprocess.run(["sg", "wireshark", "-c", cmd],
                         capture_output=True, text=True).stdout
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
    """Annotate each frame with direction, role, and pure-ACK status."""
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
        is_syn_fin = ("S" in r["flags"] or "F" in r["flags"] or "R" in r["flags"])
        is_pure_ack = (r["tcp_len"] == 0 and not is_syn_fin and r["func"] is None)
        # a TCP segment carrying payload but no decoded DNP3 func = a mid-message fragment
        is_fragment = (r["tcp_len"] > 0 and r["func"] is None and not is_syn_fin)
        role = ("pure_ACK" if is_pure_ack else
                "handshake" if is_syn_fin and r["tcp_len"] == 0 else
                "tcp_frag" if is_fragment else
                FUNC.get(r["func"], "data:%s" % r["func"]) if r["func"] is not None else
                "tcp_only")
        piggyback = (r["func"] is not None and "P" in r["flags"] and r["tcp_len"] > 0)
        ann.append({**r, "dir": d, "role": role, "pure_ack": is_pure_ack,
                    "piggyback_ack": piggyback, "fragment": is_fragment})
    return ann, master, outst


def transactions(ann):
    """Group annotated frames into DNP3 transactions with CORRECT closure (v2).

    A transaction opens on a master request (READ / SELECT). It closes at its FINAL ACK: the pure
    M→O ACK that follows the terminal response (RESPONSE for READ; OPERATE-RESPONSE for SBO). A new
    request also closes the previous transaction. Frames arriving while no transaction is open
    (inter-transaction TCP keepalives) are dropped, never appended.
    """
    txns, cur = [], None

    def close():
        nonlocal cur
        if cur is not None:
            txns.append(cur)
            cur = None

    for a in ann:
        role, d = a["role"], a["dir"]
        if role in ("READ", "SELECT") and d == "M->O":
            close()
            cur = {"op": "READ" if role == "READ" else "SBO", "units": [a],
                   "resp_seen": 0, "operate_seen": False}
            continue
        if cur is None:
            continue                              # frame outside any transaction — drop
        cur["units"].append(a)
        if role == "OPERATE" and d == "M->O":
            cur["operate_seen"] = True
        if role == "RESPONSE" and d == "O->M":
            cur["resp_seen"] += 1
        terminal = ((cur["op"] == "READ" and cur["resp_seen"] >= 1) or
                    (cur["op"] == "SBO" and cur["operate_seen"] and cur["resp_seen"] >= 2))
        if terminal and a["pure_ack"] and d == "M->O":
            close()                               # final ACK — transaction complete
    close()
    return txns


def phase_of(op, role, dir_, resp_idx, operate_seen):
    """Derive the DNP3 phase label for a unit from its role and position in the transaction."""
    if op == "READ":
        if role == "READ":
            return "read_req"
        if role == "RESPONSE":
            return "read_resp"
        if role == "pure_ACK":
            return "sep_ack" if dir_ == "O->M" else "final_ack"
        return "other"
    # SBO
    if role == "SELECT":
        return "select"
    if role == "OPERATE":
        return "operate"
    if role == "RESPONSE":
        return "select_resp" if resp_idx == 1 else "operate_resp"
    if role == "pure_ACK":
        return "sbo_ack" if not operate_seen else "final_ack"
    return "other"


def annotate_units(txn, txn_id):
    """Attach the six promised fields to every unit and return the observable slot sequence."""
    seq = []
    resp_idx = 0
    operate_seen = False
    prior = []            # for ack-association (opposite-direction data seqs)
    for u in txn["units"]:
        role, d = u["role"], u["dir"]
        if u["role"] == "handshake":
            continue
        if role == "RESPONSE" and d == "O->M":
            resp_idx += 1
        if role == "OPERATE" and d == "M->O":
            operate_seen = True
        phase = phase_of(txn["op"], role, d, resp_idx, operate_seen)

        # ack association: what does this ACK acknowledge? (best-effort tcp.seq+len match)
        if u["pure_ack"]:
            acked = None
            for p in reversed(prior):
                if p["dir"] != d and p["tcp_len"] > 0 and p.get("tcp_seq") is not None \
                        and u.get("tcp_ack") == p["tcp_seq"] + p["tcp_len"]:
                    acked = p.get("_phase")
                    break
            ack_assoc = {"kind": "pure", "acks_phase": acked}
        elif u["piggyback_ack"]:
            ack_assoc = {"kind": "piggyback", "acks_phase": None}
        else:
            ack_assoc = {"kind": "none", "acks_phase": None}

        outer_len = (u["frame_len"] + OUTER_OVERHEAD) if u["frame_len"] else None
        unit = {
            "txn_id": txn_id, "op": txn["op"], "phase": phase,
            "dir": d, "role": role,
            "frame_len": u["frame_len"], "tcp_len": u["tcp_len"],
            "ip_len": u["ip_len"], "dnp3_len": u["dnp3_len"],
            "outer_len": outer_len,
            "pure_ack": u["pure_ack"], "piggyback_ack": u["piggyback_ack"],
            "ack_assoc": ack_assoc, "fragment": u["fragment"],
            "expected_slot": SLOT_OF_PHASE.get((txn["op"], phase)),
            "t": u["t"], "app_seq": u["app_seq"],
        }
        u["_phase"] = phase       # so a later ACK can name what it acks
        prior.append(u)
        seq.append(unit)
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
        out["txns"].append({
            "txn_id": "%s#%d" % (stem, idx - 1),
            "op": t["op"],
            "n_units": len(seq),
            "dir_seq": [u["dir"] for u in seq],
            "role_seq": roles,
            "phase_seq": [u["phase"] for u in seq],
            "slot_seq": [u["expected_slot"] for u in seq],
            "frame_lens": [u["frame_len"] for u in seq],
            "tcp_lens": [u["tcp_len"] for u in seq],
            "outer_lens": [u["outer_len"] for u in seq],
            "pure_acks": sum(1 for u in seq if u["pure_ack"]),
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
        mode = args[0]
        args = args[1:]
    results = [summarize(p) for p in args]
    if mode == "--json":
        print(json.dumps(results, indent=1))
    elif mode == "--slots":
        derive_slots(results)
    else:
        for r in results:
            print("=== %s : master %s outstation %s : %d txns ==="
                  % (r["pcap"], r["master"], r["outstation"], r["n_txns"]))
            for t in r["txns"]:
                print("  %-4s units=%d dir=%s"
                      % (t["op"], t["n_units"],
                         "".join("M" if d == "M->O" else "O" for d in t["dir_seq"])))
                print("       phase=%s" % t["phase_seq"])
                print("       slot =%s" % t["slot_seq"])
                print("       frame_len=%s  outer_len=%s  frag=%d"
                      % (t["frame_lens"], t["outer_lens"], t["fragments"]))
    return 0


def derive_slots(results):
    """Provisional slot-pattern candidates (NOT frozen — directive §7/§8)."""
    reads = [t for r in results for t in r["txns"] if t["op"] == "READ"]
    sbos = [t for r in results for t in r["txns"] if t["op"] == "SBO"]
    print("## PROVISIONAL slot derivation (NOT frozen — directive §7/§8)\n")
    print("READ txns: %d ; SBO txns: %d\n" % (len(reads), len(sbos)))
    # per-slot public target = max INNER frame_len over both operations at that slot
    by_slot = {}
    for t in reads + sbos:
        for u in t["units"]:
            s = u["expected_slot"]
            if s is None or not u["frame_len"]:
                continue
            by_slot.setdefault(s, {"dir": set(), "roles": set(), "inner": []})
            by_slot[s]["dir"].add(u["dir"])
            by_slot[s]["roles"].add(u["phase"])
            by_slot[s]["inner"].append(u["frame_len"])
    print("Corrected 6-slot public pattern (public inner target = max over both ops; "
          "outer = inner + %d):" % OUTER_OVERHEAD)
    print("  slot  dir    inner_max  outer_public  phases")
    for s in sorted(by_slot):
        b = by_slot[s]
        im = max(b["inner"])
        print("  %-4d  %-5s  %-9d  %-12d  %s"
              % (s, "/".join(sorted(b["dir"])), im, im + OUTER_OVERHEAD, sorted(b["roles"])))
    print("\nNOTE: slot 1 (O→M) MUST expose one public size for BOTH the READ separate-ACK and the "
          "SBO SELECT-response; the READ ACK is padded UP to that cell. Slot offsets τ0..τ5 are the "
          "grid times; they are set by the timing substrate (D, grid tick) and are provisional until "
          "MB-8 + the grid microbench. Oversized units (> public target) FAIL OPEN, never clamp.")


if __name__ == "__main__":
    sys.exit(main())

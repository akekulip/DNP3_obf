#!/usr/bin/env python3
"""Defense 4 offline transaction oracle.

Parses a DNP3-over-TCP capture into COMPLETE bidirectional wire sequences and annotates every
visible unit with role, phase, direction, layered sizes, ACK association, fragment, and timing —
the model the public slot pattern must be derived from (directive §7). It handles READ and full
SBO (SELECT / SELECT-RESPONSE / OPERATE / OPERATE-RESPONSE), pure TCP ACKs, piggybacked ACKs,
missing ACKs, optional CONFIRMs, and final ACKs.

Read-only. Uses tshark (via `sg wireshark`) for the DNP3 dissection; no P4, no switch, no relay.

Terminology (directive §5): every size is reported at its explicit layer —
  frame_len   = observer-visible Ethernet frame length EXCLUDING the 4-byte FCS (pcap convention)
  ip_len      = IP total length
  tcp_len     = TCP payload length (the DNP3-carrying bytes; this is the '14.6 B/CROB' layer)
  dnp3_len    = the DNP3 link-layer LENGTH octet
Observer-visible Ethernet ON THE WIRE = frame_len + 4 (FCS). Constant overhead here:
frame_len - tcp_len = 66 B (14 Ethernet + 20 IP + 32 TCP-with-timestamps).

Usage:
    txn_oracle.py <pcap> [<pcap> ...]           annotate + summarize each capture
    txn_oracle.py --slots <pcap-glob>           derive provisional slot-pattern candidates
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
    """Annotate each frame with direction, role, and pure-ACK status.

    Direction is inferred from who first sends a DNP3 request vs a RESPONSE: the master
    sends READ/SELECT/OPERATE/WRITE/EN_UNSOL; the outstation sends RESPONSE.
    """
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
        is_pure_ack = (r["tcp_len"] == 0 and "S" not in r["flags"]
                       and "F" not in r["flags"] and "R" not in r["flags"]
                       and r["func"] is None)
        role = ("pure_ACK" if is_pure_ack else
                "handshake" if ("S" in r["flags"] or "F" in r["flags"] or "R" in r["flags"])
                and r["tcp_len"] == 0 else
                FUNC.get(r["func"], "data:%s" % r["func"]) if r["func"] is not None else
                "tcp_only")
        piggyback = (r["func"] is not None and "P" in r["flags"] and r["tcp_len"] > 0)
        ann.append({**r, "dir": d, "role": role, "pure_ack": is_pure_ack,
                    "piggyback_ack": piggyback})
    return ann, master, outst


def transactions(ann):
    """Group the annotated frames into DNP3 transactions (READ or SBO).

    A transaction opens on a master request (READ / SELECT); a SELECT's transaction absorbs the
    following OPERATE (SBO) as a second phase. Every frame between the opening request and the
    final response/ACK is attached, so the model is the COMPLETE bidirectional wire sequence.
    """
    txns = []
    cur = None
    for a in ann:
        role = a["role"]
        if role in ("READ", "SELECT") and a["dir"] == "M->O":
            if cur and not (role == "SELECT" and cur.get("op") == "SBO"
                            and cur.get("await_operate")):
                txns.append(cur)
            cur = {"op": "READ" if role == "READ" else "SBO", "units": [a],
                   "await_operate": role == "SELECT"}
        elif cur and role == "OPERATE" and a["dir"] == "M->O" and cur.get("await_operate"):
            cur["units"].append(a)
            cur["await_operate"] = False
        elif cur:
            cur["units"].append(a)
            # a SELECT-RESPONSE (func 129, O->M) after a SELECT arms the OPERATE wait
            if a["role"] == "RESPONSE" and cur["op"] == "SBO":
                cur["await_operate"] = True
    if cur:
        txns.append(cur)
    return txns


def wire_sequence(txn):
    """Reduce a transaction to its observer-visible unit sequence (the slot model)."""
    seq = []
    for u in txn["units"]:
        if u["role"] == "handshake":
            continue
        seq.append({
            "dir": u["dir"], "role": u["role"],
            "frame_len": u["frame_len"], "tcp_len": u["tcp_len"],
            "ip_len": u["ip_len"], "dnp3_len": u["dnp3_len"],
            "pure_ack": u["pure_ack"], "piggyback_ack": u["piggyback_ack"],
            "t": u["t"], "app_seq": u["app_seq"],
        })
    return seq


def summarize(pcap):
    rows = tshark(pcap)
    ann, master, outst = classify(rows)
    txns = transactions(ann)
    out = {"pcap": Path(pcap).name, "master": master, "outstation": outst,
           "n_frames": len(rows), "n_txns": len(txns), "txns": []}
    for t in txns:
        seq = wire_sequence(t)
        # keep only READ/SBO transactions that carry a real request+response
        roles = [u["role"] for u in seq]
        if not any(r in ("READ", "SELECT", "OPERATE") for r in roles):
            continue
        out["txns"].append({
            "op": t["op"],
            "n_units": len(seq),
            "dir_seq": [u["dir"] for u in seq],
            "role_seq": roles,
            "frame_lens": [u["frame_len"] for u in seq],
            "tcp_lens": [u["tcp_len"] for u in seq],
            "pure_acks": sum(1 for u in seq if u["pure_ack"]),
            "piggyback_acks": sum(1 for u in seq if u["piggyback_ack"]),
            "units": seq,
        })
    return out


def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return 1
    slots = as_json = False
    if args[0] == "--slots":
        slots = True
        args = args[1:]
    elif args[0] == "--json":
        as_json = True
        args = args[1:]
    results = [summarize(p) for p in args]
    if as_json:
        print(json.dumps(results, indent=1))
    elif slots:
        derive_slots(results)
    else:
        for r in results:
            print("=== %s : master %s outstation %s : %d txns ==="
                  % (r["pcap"], r["master"], r["outstation"], r["n_txns"]))
            for t in r["txns"]:
                print("  %-4s units=%d  dir=%s" % (t["op"], t["n_units"],
                                                   "".join("M" if d == "M->O" else "O"
                                                           for d in t["dir_seq"])))
                print("       roles=%s" % t["role_seq"])
                print("       frame_len=%s  tcp_len=%s  pureACK=%d piggyACK=%d"
                      % (t["frame_lens"], t["tcp_lens"], t["pure_acks"], t["piggyback_acks"]))
    return 0


def derive_slots(results):
    """Provisional slot-pattern candidates from the observed READ and SBO wire sequences.

    PROVISIONAL only (directive §8): these are printed for review and are NOT frozen. The oracle
    must first be run on the CORRECTED (pass-gate-validated) corpus before any freeze.
    """
    reads, sbos = [], []
    for r in results:
        for t in r["txns"]:
            (reads if t["op"] == "READ" else sbos).append(t)
    print("## PROVISIONAL slot-pattern derivation (NOT frozen — directive §7/§8)\n")
    print("Observed READ transactions: %d ; SBO transactions: %d\n" % (len(reads), len(sbos)))
    if sbos:
        # the SBO is the longer operation; the template is sized to it, READ pads up with filler
        maxu = max(t["n_units"] for t in sbos)
        print("SBO max data-unit count (excl pure ACK): %d" % maxu)
        # per-slot max frame_len across all SBO (the padding target per slot)
        print("Per-slot MAX observer Ethernet frame_len (excl FCS) across the SBO corpus:")
        by_slot = {}
        for t in sbos:
            for i, u in enumerate(t["units"]):
                if u["role"] in ("SELECT", "OPERATE", "RESPONSE"):
                    by_slot.setdefault(i, []).append((u["dir"], u["role"], u["frame_len"]))
        for i in sorted(by_slot):
            fl = [x[2] for x in by_slot[i] if x[2]]
            dirs = set(x[0] for x in by_slot[i])
            roles = set(x[1] for x in by_slot[i])
            print("  slot %d  dir=%s role=%s  frame_len max=%s min=%s"
                  % (i, dirs, roles, max(fl) if fl else "-", min(fl) if fl else "-"))
    print("\nNOTE: public OUTER Ethernet sizes must be derived separately = target frame_len + "
          "outer-header overhead, clamped to [Ethernet-min 64 (incl FCS), MTU 1500]; FCS "
          "convention stated explicitly. This oracle reports the INNER observed frame_len only.")


if __name__ == "__main__":
    sys.exit(main())

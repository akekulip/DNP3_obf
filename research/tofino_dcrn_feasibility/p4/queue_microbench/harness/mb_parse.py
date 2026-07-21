#!/usr/bin/env python3
"""
mb_parse.py — parse a Vision-side queue_microbench capture into the QUEUE_MICROBENCH_PLAN §3
metrics. Reads one egress pcap (dp8/Vision) and reports, per the plan:

  configured-vs-actual cadence · output inter-packet gap (IPG) · release jitter · size histogram
  · size-state SEQUENCE · size-state CONFORMITY (drop-robust: state-count ratio + run-length
  histogram, NOT positional equality — GridCloak B5) · ordering (seq inversions) · loss (seq gaps)
  · real-vs-chaff mix. Residence time is reported only with --tx-pcap (a synced Hulk-tx capture).

Frame taxonomy (by Ethernet type / UDP dport, matching queue_microbench.p4):
  ethertype 0x88B6            -> CHAFF/TICK cover frame (carries mb header; size = slot target)
  ethertype 0x0800, dport in
     {20001..20006}           -> REAL (graduated); MAGIC 'MBQ1' + seq + tx_ns in payload tail
  ethertype 0x0800, other     -> BACKGROUND / fail-open (reported separately for load context)

Size -> state: 64 B = base(S0), 128 B = S1, 256 B = S2 (pad targets in the P4).

Usage:
  python3 mb_parse.py --pcap vision.pcap --tau-ms 10 --pattern S1 S2
  python3 mb_parse.py --pcap vision.pcap --tau-ms 10 --pattern S1        # v1 (equal-sized)
"""
import argparse
import struct

from scapy.all import PcapReader, Ether   # scapy (project standard)

MAGIC = b"MBQ1"
CLASSIFIED = set(range(20001, 20007))
SIZE_STATE = {64: "S0", 128: "S1", 256: "S2"}


def pct(xs, p):
    if not xs:
        return float("nan")
    s = sorted(xs)
    k = (len(s) - 1) * (p / 100.0)
    lo = int(k)
    hi = min(lo + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


def stats(xs):
    if not xs:
        return {}
    n = len(xs)
    mean = sum(xs) / n
    var = sum((x - mean) ** 2 for x in xs) / n
    return {"n": n, "mean": mean, "std": var ** 0.5,
            "p50": pct(xs, 50), "p90": pct(xs, 90), "p99": pct(xs, 99),
            "min": min(xs), "max": max(xs)}


def run_lengths(seq):
    if not seq:
        return {}
    hist = {}
    cur, ln = seq[0], 1
    for s in seq[1:]:
        if s == cur:
            ln += 1
        else:
            hist[(cur, ln)] = hist.get((cur, ln), 0) + 1
            cur, ln = s, 1
    hist[(cur, ln)] = hist.get((cur, ln), 0) + 1
    return hist


def classify(pkt):
    """Return (kind, state, dport, seq, tx_ns). kind in {chaff, real, background, other}."""
    raw = bytes(pkt)
    if len(raw) < 14:
        return ("other", None, None, None, None)
    etype = struct.unpack("!H", raw[12:14])[0]
    wire = len(raw)
    state = SIZE_STATE.get(wire, "?%d" % wire)
    if etype == 0x88B6:
        return ("chaff", state, None, None, None)
    if etype == 0x0800 and wire >= 38:
        dport = struct.unpack("!H", raw[36:38])[0]     # eth14 + ipv4 20 + udp dport@[2:4]
        if dport in CLASSIFIED:
            seq = txns = None
            i = raw.find(MAGIC)
            if i >= 0 and i + 16 <= len(raw):
                seq = struct.unpack("!I", raw[i + 4:i + 8])[0]
                txns = struct.unpack("!Q", raw[i + 8:i + 16])[0]
            return ("real", state, dport, seq, txns)
        return ("background", state, dport, None, None)
    return ("other", state, None, None, None)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--tau-ms", type=float, default=None, help="target slot period for cadence/jitter")
    ap.add_argument("--pattern", nargs="+", default=["S1"], help="target size-state list P (e.g. S1 S2)")
    ap.add_argument("--tol-ms", type=float, default=1.0, help="cadence conformity tolerance (ms)")
    args = ap.parse_args()

    ts, kinds, states, seqs = [], [], [], []
    n_chaff = n_real = n_bg = n_other = 0
    out_state_seq = []          # size-state of every OUTPUT frame (real+chaff), in egress order

    with PcapReader(args.pcap) as pr:
        for pkt in pr:
            kind, state, dport, seq, txns = classify(pkt)
            t = float(pkt.time)
            if kind == "chaff":
                n_chaff += 1
                out_state_seq.append(state); ts.append(t)
            elif kind == "real":
                n_real += 1
                out_state_seq.append(state); ts.append(t)
                seqs.append(seq)
            elif kind == "background":
                n_bg += 1
            else:
                n_other += 1

    # ── inter-packet gaps (ms) over the obfuscated output stream ──
    ipg = [(ts[i] - ts[i - 1]) * 1000.0 for i in range(1, len(ts))]
    ipg_stats = stats(ipg)

    # ── cadence conformity + release jitter vs target tau ──
    cad = None
    if args.tau_ms and ipg:
        within = sum(1 for g in ipg if abs(g - args.tau_ms) <= args.tol_ms)
        jitter = [g - args.tau_ms for g in ipg]
        cad = {"target_ms": args.tau_ms, "within_tol_frac": within / len(ipg),
               "jitter_stats_ms": stats([abs(j) for j in jitter])}

    # ── size-state conformity: DROP-ROBUST (count ratio + run-length), not positional (B5) ──
    from collections import Counter
    counts = Counter(s for s in out_state_seq if s in ("S0", "S1", "S2"))
    target = Counter(args.pattern)
    def ratio(c):
        base = c.get(args.pattern[0], 0) or 1
        return {k: round(c.get(k, 0) / base, 3) for k in sorted(set(args.pattern))}
    rl = run_lengths(out_state_seq)

    # ── ordering + loss over REAL seq numbers ──
    real_seqs = [s for s in seqs if s is not None]
    inversions = sum(1 for i in range(1, len(real_seqs)) if real_seqs[i] < real_seqs[i - 1])
    loss = None
    if real_seqs:
        lo, hi = min(real_seqs), max(real_seqs)
        expected = hi - lo + 1
        loss = {"expected_span": expected, "received": len(set(real_seqs)),
                "missing": expected - len(set(real_seqs)),
                "loss_frac": (expected - len(set(real_seqs))) / expected if expected else 0}

    # ── report ──
    print("=== queue_microbench parse: %s ===" % args.pcap)
    print("frames: real=%d chaff=%d background=%d other=%d" % (n_real, n_chaff, n_bg, n_other))
    print("output IPG (ms): %s" % {k: round(v, 4) for k, v in ipg_stats.items()})
    if cad:
        print("cadence vs tau=%.3f ms: within +/-%.2f ms = %.1f%%; |jitter| ms = %s"
              % (args.tau_ms, args.tol_ms, 100 * cad["within_tol_frac"],
                 {k: round(v, 4) for k, v in cad["jitter_stats_ms"].items()}))
    print("size-state counts: %s" % dict(counts))
    print("size-state ratio (norm to %s): observed=%s  target=%s"
          % (args.pattern[0], ratio(counts), ratio(target)))
    print("run-length histogram (state,len)->count: %s"
          % {("%s x%d" % k): v for k, v in sorted(rl.items())})
    print("ordering: real seq inversions = %d" % inversions)
    if loss:
        print("loss: %s" % loss)
    print("NOTE: residence/latency percentiles require a synced Hulk-tx capture (--tx-pcap, "
          "PTP or single-host clock); this Vision-only parse gives cadence/IPG/jitter/size/"
          "order/loss without clock sync.")


if __name__ == "__main__":
    main()

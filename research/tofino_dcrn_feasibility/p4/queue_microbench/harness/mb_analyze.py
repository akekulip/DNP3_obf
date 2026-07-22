#!/usr/bin/env python3
"""mb_analyze.py — LOCAL pcap analyzer (scapy) for the queue_microbench hairpin captures.

Answers the pace-vs-starve question from the OUTPUT side: wire-size histogram, overall output
rate, STEADY-STATE (tail) output rate for the dominant classified size (robust to the shaper's
initial burst-credit transient), and inter-packet-gap percentiles + seq loss/reorder.

Wire size -> state: 64=S0(base/tx-leak), 128=S1, 256=S2.  Classified reals carry MAGIC 'MBQ1'.
Usage: mb_analyze.py --pcap f.pcap [--tail-secs 12] [--expect-size 128]
"""
import argparse, struct
from collections import Counter
from scapy.all import PcapReader

MAGIC = b"MBQ1"

def pct(xs, p):
    if not xs: return float("nan")
    s = sorted(xs); k = (len(s)-1)*(p/100.0); lo=int(k); hi=min(lo+1,len(s)-1)
    return s[lo] + (s[hi]-s[lo])*(k-lo)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--win-lo", type=float, default=5.0, help="steady window start, s after first frame (skip burst transient)")
    ap.add_argument("--win-hi", type=float, default=15.0, help="steady window end, s after first frame (before gen stops)")
    ap.add_argument("--expect-size", type=int, default=None, help="dominant shaped size (auto if unset)")
    a = ap.parse_args()

    recs = []          # (ts, wire, etype, dport, seq)
    sizes = Counter()
    with PcapReader(a.pcap) as pr:
        for pkt in pr:
            raw = bytes(pkt); wire = len(raw)
            if wire < 14: continue
            etype = struct.unpack("!H", raw[12:14])[0]
            dport = seq = None
            if etype == 0x0800 and wire >= 38:
                dport = struct.unpack("!H", raw[36:38])[0]
                i = raw.find(MAGIC)
                if i >= 0 and i+8 <= len(raw):
                    seq = struct.unpack("!I", raw[i+4:i+8])[0]
            recs.append((float(pkt.time), wire, etype, dport, seq))
            sizes[wire] += 1

    if not recs:
        print("pcap %s: EMPTY (no inbound frames captured)" % a.pcap); return
    recs.sort()
    t0, t1 = recs[0][0], recs[-1][0]
    dur = t1 - t0 if t1 > t0 else 1e-9
    n = len(recs)

    # dominant shaped size = expect-size, else the most common size >= 100 (exclude 64B tx leak / small ctrl)
    if a.expect_size:
        dom = a.expect_size
    else:
        big = [(c, s) for s, c in sizes.items() if s >= 100]
        dom = max(big)[1] if big else max(sizes.items(), key=lambda kv: kv[1])[0]

    dom_ts = [r[0] for r in recs if r[1] == dom]
    # STEADY window: [t0+win_lo, t0+win_hi], excludes the initial burst-credit transient and
    # any post-generation drain, so steady_pps directly reflects the shaper's sustained dequeue.
    wlo, whi = t0 + a.win_lo, t0 + a.win_hi
    win = [t for t in dom_ts if wlo <= t <= whi]
    win_secs = a.win_hi - a.win_lo
    dom_ipg = [(dom_ts[i]-dom_ts[i-1])*1000.0 for i in range(1, len(dom_ts))]
    win_ipg = [(win[i]-win[i-1])*1000.0 for i in range(1, len(win))]

    # loss / reorder over dominant-size seq
    seqs = [r[4] for r in recs if r[1] == dom and r[4] is not None]
    inv = sum(1 for i in range(1, len(seqs)) if seqs[i] < seqs[i-1])
    loss = None
    if seqs:
        span = max(seqs)-min(seqs)+1
        loss = {"span": span, "recv_unique": len(set(seqs)), "missing": span-len(set(seqs))}

    print("=== analyze %s ===" % a.pcap)
    print("frames=%d  dur=%.2fs  overall_pps=%.1f" % (n, dur, n/dur))
    print("wire-size histogram: %s" % dict(sorted(sizes.items())))
    print("dominant shaped size = %d B (state %s)" % (dom, {64:"S0",128:"S1",256:"S2"}.get(dom, "?")))
    print("  dominant frames=%d  overall_dom_pps=%.1f" % (len(dom_ts), len(dom_ts)/dur))
    if win:
        print("  STEADY win[%.0f,%.0f]s frames=%d  steady_pps=%.1f"
              % (a.win_lo, a.win_hi, len(win), len(win)/win_secs))
    else:
        print("  STEADY win[%.0f,%.0f]s frames=0  steady_pps=0.0  (no dequeue in window -> STARVED?)"
              % (a.win_lo, a.win_hi))
    if dom_ipg:
        print("  dom IPG ms(all): p50=%.2f p90=%.2f p99=%.2f min=%.2f max=%.2f"
              % (pct(dom_ipg,50), pct(dom_ipg,90), pct(dom_ipg,99), min(dom_ipg), max(dom_ipg)))
    if win_ipg:
        print("  win IPG ms: p50=%.3f p90=%.3f p99=%.3f (1/p50 = %.0f pps)"
              % (pct(win_ipg,50), pct(win_ipg,90), pct(win_ipg,99),
                 1000.0/pct(win_ipg,50) if pct(win_ipg,50)>0 else 0))
    if loss is not None:
        print("  reorder(seq inversions)=%d  loss=%s" % (inv, loss))
    # per-second dominant-size counts (reveals burst->steady transition + low-R clumping).
    from collections import Counter as _C
    persec = _C(int(t - t0) for t in dom_ts)
    span_s = int(t1 - t0) + 1
    nz = sum(1 for s in range(span_s) if persec.get(s, 0) > 0)
    print("  per-sec dom counts: %s" % ", ".join("%d:%d" % (s, persec.get(s, 0)) for s in range(span_s)))
    print("  seconds-with-output: %d / %d  (gaps => clumped/starved release)" % (nz, span_s))

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""clrt.py — measure the Formby CLRT from a capture taken on the master leg, and show how it clusters.

CLRT = time( relay's DNP3 response ) - time( relay's pure TCP ACK ), per transaction.
That is the interval the defense normalizes to G, and the quantity Formby's fingerprint keys on.

The headline is not the median, it is the CLUSTERING: an observer identifies the device by the
SHAPE of this distribution. Native traffic scatters across many values; protected traffic
collapses onto a single one. So this prints, for each capture:

  * a strip plot on a common axis, so both runs are directly comparable by eye;
  * the observer's histogram at 1 ms resolution (what an attacker actually bins);
  * the number of occupied bins and the Shannon entropy in bits -- entropy 0 means every
    transaction looks identical and the channel carries no information.

Usage:
  ./clrt.py native.pcap
  ./clrt.py native.pcap protected.pcap        # side by side, shared axis
"""
import math
import statistics as st
import subprocess
import sys

RELAY = "192.168.10.7"
WIDTH = 62
BIN_MS = 1.0          # an observer binning at 1 ms -- the resolution used in the frozen result
RAMP = " .:-=+*#%@"   # density ramp for the strip plot


def clrt_of(path):
    """Pair each pure ACK from the relay with the DNP3 response that follows it."""
    try:
        out = subprocess.run(
            ["tshark", "-r", path, "-T", "fields",
             "-e", "frame.time_epoch", "-e", "ip.src", "-e", "tcp.len"],
            capture_output=True, text=True, check=True).stdout
    except FileNotFoundError:
        sys.exit("FATAL: tshark not found")
    except subprocess.CalledProcessError as e:
        sys.exit("FATAL: tshark could not read %s (%s)" % (path, e))
    vals, ack = [], None
    for line in out.splitlines():
        p = line.split("\t")
        if len(p) < 3 or not p[0].strip():
            continue
        try:
            t, src, ln = float(p[0]), p[1].strip(), int(p[2] or 0)
        except ValueError:
            continue
        if src != RELAY:
            continue
        if ln == 0:
            ack = t
        elif ack is not None:
            vals.append((t - ack) * 1000.0)
            ack = None
    return vals


def observer_bins(vals, bin_ms=BIN_MS):
    """What an attacker sees after binning: {bin_index: count}."""
    h = {}
    for v in vals:
        k = int(math.floor(v / bin_ms))
        h[k] = h.get(k, 0) + 1
    return h


def entropy_bits(hist):
    n = sum(hist.values())
    if n <= 0:
        return 0.0
    e = 0.0
    for c in hist.values():
        p = c / n
        if p > 0:
            e -= p * math.log2(p)
    return e


def strip(vals, lo, hi, width=WIDTH):
    """One-line density plot of vals on the shared axis [lo, hi]."""
    if hi <= lo:
        hi = lo + 1.0
    cols = [0] * width
    for v in vals:
        i = int((v - lo) / (hi - lo) * (width - 1))
        cols[min(max(i, 0), width - 1)] += 1
    top = max(cols) or 1
    out = ""
    for c in cols:
        if c == 0:
            out += " "
        else:
            out += RAMP[min(len(RAMP) - 1, max(1, int(c / top * (len(RAMP) - 1))))]
    return out


def stats_line(vals):
    return ("n=%-4d median %8.3f  mean %8.3f  min %8.3f  max %8.3f  sd %7.3f ms"
            % (len(vals), st.median(vals), st.mean(vals), min(vals), max(vals),
               st.pstdev(vals)))


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    series = []
    for path in sys.argv[1:]:
        v = clrt_of(path)
        if not v:
            print("=== %s: no complete ACK->response pairs found ===" % path)
            continue
        series.append((path.rsplit("/", 1)[-1], v))
    if not series:
        return 1

    allv = [v for _, vs in series for v in vs]
    lo, hi = min(allv), max(allv)
    pad = max((hi - lo) * 0.04, 0.05)
    lo, hi = lo - pad, hi + pad
    label_w = max(len(n) for n, _ in series)

    print("\nCLRT clustering  (relay pure-ACK -> DNP3 response), shared axis %.2f - %.2f ms\n"
          % (lo, hi))
    for name, vs in series:
        print("  %-*s |%s|" % (label_w, name, strip(vs, lo, hi)))
    axis = "%-.2f" % lo
    print("  %-*s  %s%s%.2f ms" % (label_w, "", axis, " " * max(1, WIDTH - len(axis) - 8), hi))

    print("\nPer-capture detail")
    for name, vs in series:
        h = observer_bins(vs)
        e = entropy_bits(h)
        print("\n  %s" % name)
        print("    %s" % stats_line(vs))
        print("    observer view @ %.0f ms bins: %d occupied, entropy %.3f bits"
              % (BIN_MS, len(h), e))
        for k in sorted(h):
            bar = "#" * min(40, h[k])
            print("      [%5.0f-%5.0f) ms  %-40s %d" % (k * BIN_MS, (k + 1) * BIN_MS, bar, h[k]))

    if len(series) == 2:
        (na, a), (nb, b) = series
        sa, sb = st.pstdev(a), st.pstdev(b)
        ea, eb = entropy_bits(observer_bins(a)), entropy_bits(observer_bins(b))
        print("\n--- %s  ->  %s ---" % (na, nb))
        print("    spread (sd) : %8.3f ms  ->  %8.3f ms%s"
              % (sa, sb, ("   (%.0fx tighter)" % (sa / sb)) if sb > 0 else ""))
        print("    range width : %8.3f ms  ->  %8.3f ms" % (max(a) - min(a), max(b) - min(b)))
        print("    median      : %8.3f ms  ->  %8.3f ms" % (st.median(a), st.median(b)))
        print("    occupied bins: %7d     ->  %8d" % (len(observer_bins(a)), len(observer_bins(b))))
        print("    entropy     : %8.3f b   ->  %8.3f bits%s"
              % (ea, eb, "   <- channel carries no information" if eb == 0 else ""))
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())

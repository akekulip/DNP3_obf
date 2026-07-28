"""WS-0 kill check: does the SEL-751's TCP timestamp option leak native CLRT?

If TSval granularity is fine relative to CLRT (~1-22 ms), then
delta = TSval(RESPONSE) - TSval(ACK) recovers the native CLRT regardless of
when an inline switch releases either packet -- which would defeat Defense 1,
Defense 2 and the proposed fixed-delay ACK hold simultaneously.
"""
import sys
from collections import Counter

RELAY = "192.168.10.7"
MASTER = "192.168.10.1"


def load(path):
    rows = []
    with open(path) as fh:
        for line in fh:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 4 or not parts[0]:
                continue
            t, src, tlen, tsval = parts[0], parts[1], parts[2], parts[3]
            if not tsval:
                continue
            rows.append((float(t), src, int(tlen or 0), int(tsval)))
    return rows


def transactions(rows):
    """Pair each relay pure-ACK with the next relay data RESPONSE."""
    out = []
    pending = None
    for t, src, tlen, tsval in rows:
        if src != RELAY:
            continue
        if tlen == 0:
            pending = (t, tsval)          # pure ACK from relay
        elif tlen > 0 and pending is not None:
            t_ack, ts_ack = pending
            out.append({
                "clrt_ms": (t - t_ack) * 1e3,
                "d_tsval": tsval - ts_ack,
            })
            pending = None
    return out


def tick_granularity(rows):
    """Observable TSval step size and its wall-clock period, relay side."""
    seq = [(t, ts) for t, src, _, ts in rows if src == RELAY]
    steps, periods = [], []
    last_t, last_ts = seq[0]
    for t, ts in seq[1:]:
        if ts != last_ts:
            steps.append(ts - last_ts)
            periods.append((t - last_t) * 1e3)
            last_t, last_ts = t, ts
    return steps, periods


def mutual_information(xs, ys, xbin, ybin):
    """MI in bits between binned xs and ys."""
    import math
    n = len(xs)
    xb = [int(x // xbin) for x in xs]
    yb = [int(y // ybin) for y in ys]
    joint, px, py = Counter(zip(xb, yb)), Counter(xb), Counter(yb)
    mi = 0.0
    for (a, b), c in joint.items():
        p_ab, p_a, p_b = c / n, px[a] / n, py[b] / n
        mi += p_ab * math.log2(p_ab / (p_a * p_b))
    return mi


def main(path):
    rows = load(path)
    steps, periods = tick_granularity(rows)
    txns = transactions(rows)
    clrt = [x["clrt_ms"] for x in txns]
    dts = [x["d_tsval"] for x in txns]

    print(f"file: {path}")
    print(f"relay TSval step sizes (units): {sorted(Counter(steps).items())}")
    if periods:
        periods_sorted = sorted(periods)
        print(f"wall-clock between TSval changes (ms): "
              f"min {periods_sorted[0]:.2f}  median "
              f"{periods_sorted[len(periods_sorted)//2]:.2f}  "
              f"max {periods_sorted[-1]:.2f}")
        gran = sum(periods) / len(periods)
        print(f"=> effective observable TS granularity: ~{gran:.2f} ms")

    print(f"\npaired ACK->RESPONSE transactions: n = {len(txns)}")
    if clrt:
        cs = sorted(clrt)
        print(f"native CLRT (ms): min {cs[0]:.3f}  median "
              f"{cs[len(cs)//2]:.3f}  max {cs[-1]:.3f}")
    print(f"delta TSval (units) distribution: {sorted(Counter(dts).items())}")

    if len(set(dts)) < 2:
        print("\ndelta TSval is CONSTANT across all transactions "
              "-> MI = 0.000 bits: carries NO information about CLRT.")
        return
    mi = mutual_information(clrt, dts, xbin=0.5, ybin=1)
    import math
    h_clrt = 0.0
    n = len(clrt)
    for _, c in Counter(int(x // 0.5) for x in clrt).items():
        p = c / n
        h_clrt -= p * math.log2(p)
    print(f"\nH(CLRT) @0.5ms bins           = {h_clrt:.3f} bits")
    print(f"MI(delta TSval ; CLRT)        = {mi:.3f} bits "
          f"({100*mi/h_clrt:.1f}% of CLRT entropy)")


if __name__ == "__main__":
    main(sys.argv[1])

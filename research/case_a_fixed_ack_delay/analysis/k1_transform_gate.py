"""K1 kill gate: apply the proposed transform offline to real native CLRT data.

Mechanism under test: hold the pure ACK until t_ACK + D, release independent of
the RESPONSE.  Predicted observable:

    CLRT_out = max(CLRT_native - D, delta_release)

Question: does this destroy information an adversary uses, at any proposed D?
Data: the n=100 steady-state native transactions measured on the physical
SEL-751 (evidence/corrected_v2/cwi/out_C3/native_transactions.csv).
"""
import csv
import math
import statistics as st
from collections import Counter

CSV = ("/home/philip/Projects/DNP3/evidence/corrected_v2/cwi/out_C3/"
       "native_transactions.csv")
DELTA = 0.05          # ms, conservative host-visible release separation floor
D_GRID = [0.5, 1.0, 2.0, 3.0, 5.0, 10.0, 22.0, 25.0]


def load_clrt():
    with open(CSV) as fh:
        rdr = csv.DictReader(fh)
        col = next(c for c in rdr.fieldnames if "clrt" in c.lower())
        fh.seek(0)
        rdr = csv.DictReader(fh)
        return [float(r[col]) for r in rdr if r[col] not in ("", None)], col


def entropy(vals, binw, origin=0.0):
    n = len(vals)
    cnt = Counter(int((v - origin) // binw) for v in vals)
    return -sum((c / n) * math.log2(c / n) for c in cnt.values()), len(cnt)


def transform(vals, d, delta=DELTA):
    return [max(v - d, delta) for v in vals]


def auroc(a, b):
    """P(x_a > x_b) + 0.5 P(=) -- 1-D separability of two samples."""
    wins = ties = 0
    for x in a:
        for y in b:
            if x > y:
                wins += 1
            elif x == y:
                ties += 1
    return (wins + 0.5 * ties) / (len(a) * len(b))


def main():
    clrt, col = load_clrt()
    n = len(clrt)
    h_nat, bins_nat = entropy(clrt, 1.0)
    print(f"source: {CSV}")
    print(f"column: {col}   n = {n}")
    print(f"native  CLRT ms: min {min(clrt):.4f}  median {st.median(clrt):.4f} "
          f" mean {st.mean(clrt):.4f}  sd {st.stdev(clrt):.4f}  max {max(clrt):.4f}")
    print(f"native  entropy @1ms bins: {h_nat:.3f} bits over {bins_nat} bins\n")

    hdr = (f"{'D(ms)':>7} {'collapsed':>10} {'sd(ms)':>8} {'sd ratio':>9} "
           f"{'H@1ms':>7} {'dH':>7} {'AUROC vs native':>16} {'added lat mean':>15}")
    print(hdr)
    print("-" * len(hdr))
    for d in D_GRID:
        out = transform(clrt, d)
        collapsed = sum(1 for v in clrt if v <= d)
        h_out, _ = entropy(out, 1.0)
        # latency the RESPONSE additionally incurs (collapse regime only)
        added = [max(0.0, d - v) for v in clrt]
        print(f"{d:>7.1f} {collapsed:>7d}/{n:<3d} {st.stdev(out):>8.3f} "
              f"{st.stdev(out)/st.stdev(clrt):>9.3f} {h_out:>7.3f} "
              f"{h_out - h_nat:>7.3f} {auroc(clrt, out):>16.3f} "
              f"{st.mean(added):>13.3f}ms")

    print("\nInterpretation guide:")
    print("  collapsed = transactions mapped onto the single atom at delta")
    print("              (the ONLY regime where information is destroyed);")
    print("  the rest undergo y = x - D, a bijection: zero information lost.")
    print("  dH near 0.000 => the transform is an information no-op at that D.")

    # What an adaptive adversary recovers: invert the shift where possible.
    print("\nAdaptive adversary (knows D, inverts the shift):")
    for d in [0.5, 1.0, 2.0, 3.0]:
        out = transform(clrt, d)
        recovered = sum(1 for v, o in zip(clrt, out)
                        if o > DELTA and abs((o + d) - v) < 1e-9)
        print(f"  D={d:>4.1f} ms: exactly recovers native CLRT for "
              f"{recovered}/{n} transactions "
              f"({100*recovered/n:.0f}%)")


if __name__ == "__main__":
    main()

"""Where does the timing leak actually live?

For each defense, compute the FULL observable triple a master-side observer
sees, not just CLRT:

    READ->ACK   (a)      ACK->RESPONSE  (CLRT, c)     READ->RESPONSE (a + c)

Native:      a,                 c,                a+c
Defense 1 (hold ACK, release on RESPONSE):   a+c,  delta,  a+c
Defense 2 (hold RESPONSE to t_ACK+G):          a,  max(c,G),  a+max(c,G)
Fixed-D   (hold ACK to t_ACK+D):             a+D,  max(c-D,delta), a+max(c,D+delta)
READ-anchored (hold ACK to t_READ+A,
               hold RESPONSE to t_READ+A+S):   A,   S,       A+S
"""
import csv
import math
import statistics as st
from collections import Counter

CSV = ("/home/philip/Projects/DNP3/evidence/corrected_v2/cwi/out_C3/"
       "native_transactions.csv")
DELTA = 0.05


def entropy(vals, binw=1.0):
    n = len(vals)
    cnt = Counter(int(v // binw) for v in vals)
    return -sum((c / n) * math.log2(c / n) for c in cnt.values())


def describe(name, vals):
    if max(vals) - min(vals) < 1e-9:
        return (f"{name:<34} const {vals[0]:>7.3f}      sd  0.000   "
                f"H 0.000 bits")
    return (f"{name:<34} median {st.median(vals):>6.3f}  sd {st.stdev(vals):>6.3f}   "
            f"H {entropy(vals):.3f} bits")


def main():
    a, c = [], []
    with open(CSV) as fh:
        for r in csv.DictReader(fh):
            if r["read_to_ack_ms"] and r["clrt_ms"]:
                a.append(float(r["read_to_ack_ms"]))
                c.append(float(r["clrt_ms"]))
    n = len(a)
    print(f"n = {n} steady-state transactions, physical SEL-751\n")

    print("=== NATIVE: the three observables ===")
    print(describe("READ->ACK        (a)", a))
    print(describe("ACK->RESPONSE    (c = CLRT)", c))
    print(describe("READ->RESPONSE   (a+c)", [x + y for x, y in zip(a, c)]))

    print("\n=== DEFENSE 1 (hold ACK, release when RESPONSE arrives) ===")
    d1_a = [x + y for x, y in zip(a, c)]
    print(describe("READ->ACK        (a+c)  <-- LEAK", d1_a))
    print(describe("ACK->RESPONSE    (delta)", [DELTA] * n))
    print(describe("READ->RESPONSE   (a+c)  <-- LEAK", d1_a))

    for G in (25.0,):
        print(f"\n=== DEFENSE 2 (hold RESPONSE to t_ACK + G), G = {G} ms ===")
        d2_c = [max(y, G) for y in c]
        print(describe("READ->ACK        (a)    <-- LEAK", a))
        print(describe("ACK->RESPONSE    max(c,G)", d2_c))
        print(describe("READ->RESPONSE   a+max(c,G)", [x + z for x, z in zip(a, d2_c)]))

    for D in (2.0, 3.0):
        print(f"\n=== FIXED-D ACK HOLD (hold ACK to t_ACK + D), D = {D} ms ===")
        fd_a = [x + D for x in a]
        fd_c = [max(y - D, DELTA) for y in c]
        print(describe("READ->ACK        (a+D)  <-- LEAK (shape intact)", fd_a))
        print(describe("ACK->RESPONSE    max(c-D,delta)", fd_c))
        print(describe("READ->RESPONSE   a+max(c,D+delta)",
                       [x + max(y, D + DELTA) for x, y in zip(a, c)]))

    A, S = 3.0, 1.0
    print(f"\n=== READ-ANCHORED (ACK at t_READ+A, RESPONSE at t_READ+A+S), "
          f"A = {A} ms, S = {S} ms ===")
    feasible = sum(1 for x, y in zip(a, c) if x <= A and x + y <= A + S)
    print(describe("READ->ACK        (A)", [A] * n))
    print(describe("ACK->RESPONSE    (S)", [S] * n))
    print(describe("READ->RESPONSE   (A+S)", [A + S] * n))
    print(f"{'':34} covered (a<=A and a+c<=A+S): {feasible}/{n} "
          f"({100*feasible/n:.0f}%)")
    for A2, S2 in ((5.0, 3.0), (10.0, 5.0), (22.0, 3.0), (25.0, 5.0)):
        cov = sum(1 for x, y in zip(a, c) if x <= A2 and x + y <= A2 + S2)
        cost = st.mean([max(0.0, (A2 + S2) - (x + y)) for x, y in zip(a, c)])
        print(f"    A={A2:>5.1f} S={S2:>4.1f} -> covered {cov:>3d}/{n} "
              f"({100*cov/n:>3.0f}%), mean added end-to-end latency {cost:>6.3f} ms")


if __name__ == "__main__":
    main()

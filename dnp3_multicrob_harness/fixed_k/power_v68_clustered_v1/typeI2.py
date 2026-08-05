#!/usr/bin/env python3
"""Type-I inflation of the superseded IID plan vs the frozen scheme (vectorised)."""
import math
import numpy as np
from scipy import stats

NSIM, B = 600, 399


def trimmed(a):
    s = np.sort(a, axis=-1); return s[..., 1:-1].mean(axis=-1)


def gen(rng, K, icc, nR=10, m=6, s_round=1.0, contam=0.02, spike=30.0):
    s_c, s_t = math.sqrt(icc), math.sqrt(1 - icc)
    b = rng.normal(0, s_round, (nR, 1, 1))
    u = rng.normal(0, s_c, (nR, K, 1))
    e = rng.normal(0, s_t, (nR, K, m))
    e += (rng.random((nR, K, m)) < contam) * spike * s_t
    return b + u + e                                   # exact null


def rho_rows(Y, xr):
    """|Spearman| of each row of Y against fixed rank vector xr."""
    ry = stats.rankdata(Y, axis=1)
    ry = ry - ry.mean(1, keepdims=True)
    rx = xr - xr.mean()
    den = np.sqrt((ry ** 2).sum(1) * (rx ** 2).sum())
    return np.abs((ry * rx).sum(1) / np.where(den == 0, 1, den))


print("=" * 92)
print(f"Type-I error at nominal 0.05 under an EXACT null (no R effect anywhere),")
print(f"round sd=1.0, {NSIM} sims, B={B} permutations, 10 rounds x 6 txns")
print("=" * 92)
print(f"  {'K':>3} {'ICC':>5} | {'(1) txn KW':>12} {'(2) txn perm':>14} "
      f"{'(3) conn GLOBAL perm':>21} {'(4) conn WITHIN-round':>22}")
for K in (4, 16):
    for icc in (0.0, 0.3, 0.6):
        rng = np.random.default_rng(60000 + K * 100 + int(icc * 10))
        nR, m = 10, 6
        Rl = np.arange(1, K + 1)
        xt = np.repeat(np.tile(Rl, nR), m).astype(float)
        xc = np.tile(Rl, nR).astype(float)
        rej = np.zeros(4)
        for _ in range(NSIM):
            y = gen(rng, K, icc, nR, m)
            rej[0] += stats.kruskal(*[y[:, j, :].ravel()
                                      for j in range(K)]).pvalue < 0.05
            yt = y.ravel()
            o1 = rho_rows(yt[None, :], xt)[0]
            perm_t = np.argsort(rng.random((B, yt.size)), axis=1)
            n1 = rho_rows(yt[perm_t], xt)
            rej[1] += (1 + (n1 >= o1).sum()) / (B + 1) <= 0.05
            S = trimmed(y)
            Sa = S - np.median(S, axis=1, keepdims=True)
            fl = Sa.ravel()
            o = rho_rows(fl[None, :], xc)[0]
            pg = np.argsort(rng.random((B, fl.size)), axis=1)
            ng = rho_rows(fl[pg], xc)
            rej[2] += (1 + (ng >= o).sum()) / (B + 1) <= 0.05
            pw = np.argsort(rng.random((B, nR, K)), axis=2)          # within round
            Sw = np.take_along_axis(np.broadcast_to(Sa, (B, nR, K)), pw,
                                    axis=2).reshape(B, -1)
            nw = rho_rows(Sw, xc)
            rej[3] += (1 + (nw >= o).sum()) / (B + 1) <= 0.05
        r = rej / NSIM
        print(f"  {K:>3} {icc:>5.1f} | {r[0]:>12.4f} {r[1]:>14.4f} "
              f"{r[2]:>21.4f} {r[3]:>22.4f}")
print()
print("  (1),(2) = superseded IID plan (treats 60 clustered txns as independent)")
print("  (3)     = correct unit, WRONG exchangeability (ignores the round block)")
print("  (4)     = frozen v6.8-clustered-v1 scheme.  Target = 0.050")
print(f"  MC standard error on each cell ~= {math.sqrt(.05*.95/NSIM):.4f}")

#!/usr/bin/env python3
"""Why 0.82/0.83 is not reproducible, and what round count restores it."""
import math
import numpy as np
from scipy import stats

Z95, Z80 = 1.6448536, 0.8416212


def trimmed(a):
    s = np.sort(a, axis=-1)
    return s[..., 1:-1].mean(axis=-1)


def campaign(rng, K, tau, icc, nR, n_txn=6, sigma_round=1.0, contam=0.02, spike=30.0):
    s_c, s_t = math.sqrt(icc), math.sqrt(1 - icc)
    b = rng.normal(0, sigma_round, (nR, 1, 1))
    u = rng.normal(0, s_c, (nR, K, 1))
    e = rng.normal(0, s_t, (nR, K, n_txn))
    e += (rng.random((nR, K, n_txn)) < contam) * spike * s_t
    y = b + u + e + tau * np.arange(1, K + 1).reshape(1, K, 1)
    S = trimmed(y)
    return S - np.median(S, axis=1, keepdims=True)


print("=" * 86)
print("(K) RECONCILIATION: why the archived 0.82/0.83 does not reproduce")
print("=" * 86)
print("   variant                                        K=4     K=8    K=16")
rows = [
    ("pooled unaligned, ONE-SIDED  (archived recipe)", lambda K, nR: (K*nR, False)),
    ("pooled unaligned, TWO-SIDED |rho|",              lambda K, nR: (K*nR, True)),
    ("round-ALIGNED,    ONE-SIDED",                    lambda K, nR: (K*nR-nR, False)),
    ("round-ALIGNED,    TWO-SIDED |rho|  (frozen)",    lambda K, nR: (K*nR-nR, True)),
]
for label, f in rows:
    out = []
    for K in (4, 8, 16):
        Neff, two = f(K, 10)
        se = 1.0 / math.sqrt(Neff - 1)
        need = 0.20 - Z95 * se
        if need <= 0:
            out.append(0.0)
        else:
            p = stats.norm.cdf(need / se)
            out.append(2 * p - 1 if two else p)
    print(f"   {label:<45} " + "".join(f"{v:>7.3f}" for v in out))
print()
print("   -> the archived 0.82/0.83 is recoverable ONLY with an unaligned pooled")
print("      Spearman AND a one-sided (directional) bound.  Adding either the")
print("      round alignment or the two-sidedness drops K=16 below the 0.80 gate.")

print()
print("=" * 86)
print("(L) MC confirmation with the EXACT frozen estimator (trimmed -> align ->")
print("    |rho| -> analytic UCL), tau=0, ICC=0.5, 4000 sims")
print("=" * 86)
print(f"   {'rounds':>7} {'conns':>6} {'scored SBOs':>12} " +
      "".join(f"{f'K={K} 2-sided':>14}" for K in (4, 8, 16)) +
      "".join(f"{f'K={K} 1-sided':>14}" for K in (16,)))
for nR in (10, 12, 15, 20, 25):
    two, one = [], []
    for K in (4, 8, 16):
        rng = np.random.default_rng(31337 + nR * 100 + K)
        Neff = K * nR - nR
        se = 1.0 / math.sqrt(Neff - 1)
        Rl = np.arange(1, K + 1)
        x = np.tile(Rl, nR).astype(float)
        c2 = c1 = 0
        for _ in range(4000):
            S = campaign(rng, K, 0.0, 0.5, nR)
            r = stats.spearmanr(x, S.ravel()).statistic
            c2 += (abs(r) + Z95 * se) < 0.20
            c1 += (r + Z95 * se) < 0.20
        two.append(c2 / 4000)
        if K == 16:
            one.append(c1 / 4000)
    print(f"   {nR:>7} {28*nR:>6} {28*nR*6:>12} " +
          "".join(f"{v:>14.3f}" for v in two) + "".join(f"{v:>14.3f}" for v in one))

print()
print("=" * 86)
print("(M) rounds required for >=0.80 certification power, per arm, K=16")
print("=" * 86)


def need_rounds(K, arm, two_sided=True, sesoi=0.20):
    for nR in range(5, 200):
        if arm == "rho":
            se = 1.0 / math.sqrt(K * nR - nR - 1)
            need = sesoi - Z95 * se
            if need <= 0:
                continue
            p = stats.norm.cdf(need / se)
            pw = 2 * p - 1 if two_sided else p
        elif arm == "eps2":
            N = K * nR
            sd = math.sqrt(2 * (K - 1)) / (N - K)
            pw = stats.norm.cdf((0.04 - Z95 * sd) / sd) if 0.04 - Z95 * sd > 0 else 0.0
        elif arm in ("clf_nb", "clf_naive"):
            p0 = 1.0 / K
            sd_r = math.sqrt(p0 * (1 - p0)) / math.sqrt(K)
            se = sd_r / math.sqrt(nR)
            if arm == "clf_nb":
                se *= math.sqrt(1 + nR / (nR - 1))
            tcrit = stats.t.ppf(0.95, nR - 1)
            need = 0.05 - tcrit * se
            pw = stats.norm.cdf(need / se) if need > 0 else 0.0
        if pw >= 0.80:
            return nR, pw
    return None, None


for K in (4, 8, 16):
    print(f"   --- K={K} ---")
    for arm, lab, ts in [("rho", "|rho| <= 0.20  (two-sided)", True),
                         ("rho", "rho  <= 0.20  (one-sided)", False),
                         ("eps2", "eps2_corr <= 0.04", True),
                         ("clf_naive", "BA-chance <= 0.05 (naive fold SE)", True),
                         ("clf_nb", "BA-chance <= 0.05 (Nadeau-Bengio SE)", True)]:
        nR, pw = need_rounds(K, arm, ts)
        s = f"{nR:>3} rounds (power {pw:.3f})" if nR else "NOT REACHABLE < 200 rounds"
        print(f"      {lab:<38} {s}")

print()
print("=" * 86)
print("(N) empirical check of sd(BA_round) under chance, LORO, K connections/round")
print("=" * 86)
rng = np.random.default_rng(2718)
for K in (4, 8, 16):
    sims = []
    for _ in range(4000):
        # chance-level classifier: each of the K held-out connections gets a
        # uniformly random predicted class; balanced accuracy over K classes
        pred = rng.integers(0, K, size=K)
        truth = np.arange(K)
        sims.append(np.mean(pred == truth))
    emp = float(np.std(sims))
    ana = math.sqrt((1 / K) * (1 - 1 / K)) / math.sqrt(K)
    print(f"   K={K:>2}  empirical sd(BA_r)={emp:.4f}   analytic={ana:.4f}   "
          f"mean={np.mean(sims):.4f} (chance={1/K:.4f})")

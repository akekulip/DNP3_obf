#!/usr/bin/env python3
"""Isolate which absence criterion is failing, and calibrate the block bootstrap."""
import math
import numpy as np
from scipy import stats

Z95 = 1.6448536


def trimmed(a):
    s = np.sort(a, axis=-1)
    return s[..., 1:-1].mean(axis=-1)


def campaign(rng, K, tau, icc, n_round=10, n_txn=6, sigma_round=1.0,
             contam=0.02, spike=30.0):
    s_c, s_t = math.sqrt(icc), math.sqrt(1 - icc)
    b = rng.normal(0, sigma_round, (n_round, 1, 1))
    u = rng.normal(0, s_c, (n_round, K, 1))
    e = rng.normal(0, s_t, (n_round, K, n_txn))
    e += (rng.random((n_round, K, n_txn)) < contam) * spike * s_t
    y = b + u + e + tau * np.arange(1, K + 1).reshape(1, K, 1)
    S = trimmed(y)
    return S - np.median(S, axis=1, keepdims=True)


def boot_ucl(rng, S, Rlab, B=1500):
    nr = S.shape[0]
    idx = rng.integers(0, nr, (B, nr))
    Sb = S[idx].reshape(B, -1)
    xb = np.tile(Rlab, nr)[None, :].repeat(B, 0).astype(float)
    ry = stats.rankdata(Sb, axis=1); rx = stats.rankdata(xb, axis=1)
    ry -= ry.mean(1, keepdims=True); rx -= rx.mean(1, keepdims=True)
    den = np.sqrt((ry ** 2).sum(1) * (rx ** 2).sum(1))
    r = (ry * rx).sum(1) / np.where(den == 0, 1, den)
    return np.percentile(np.abs(r), 95.0)


print("=" * 84)
print("(G) null distribution of the OMNIBUS effect sizes  (tau=0, ICC=0.5, 3000 sims)")
print("=" * 84)
print(f"  {'K':>3} {'N':>5} {'E[eps2_raw]':>12} {'p95':>7} | {'E[eps2_corr]':>13} "
      f"{'sd':>7} {'p95':>7} | {'SESOI 0.04 reachable?':>22}")
for K in (4, 8, 16):
    rng = np.random.default_rng(4242 + K)
    raw, cor = [], []
    for _ in range(3000):
        S = campaign(rng, K, 0.0, 0.5)
        H = stats.kruskal(*[S[:, j] for j in range(K)]).statistic
        N = S.size
        raw.append(H / (N - 1))
        cor.append((H - (K - 1)) / (N - K))
    raw, cor = np.array(raw), np.array(cor)
    ok = "NO - null mean exceeds it" if raw.mean() > 0.04 else "yes"
    print(f"  {K:>3} {10*K:>5} {raw.mean():>12.4f} {np.percentile(raw,95):>7.4f} | "
          f"{cor.mean():>13.4f} {cor.std():>7.4f} {np.percentile(cor,95):>7.4f} | {ok:>22}")
print("  analytic E[eps2_raw | H0] = (K-1)/(N-1):",
      [round((K - 1) / (10 * K - 1), 4) for K in (4, 8, 16)])

print()
print("=" * 84)
print("(H) separated absence-criterion pass rates at tau=0 (ICC=0.5, 1200 sims)")
print("=" * 84)
print(f"  {'K':>3} {'rho:boot UCL<0.20':>18} {'rho:analytic UCL<0.20':>22} "
      f"{'eps2_raw<0.04':>14} {'eps2_corr UCL<0.04':>19}")
res = {}
for K in (4, 8, 16):
    rng = np.random.default_rng(555 + K)
    Rlab = np.arange(1, K + 1)
    a = b_ = c_ = d_ = 0
    n = 1200
    uclb, ucla = [], []
    for _ in range(n):
        S = campaign(rng, K, 0.0, 0.5)
        x = np.tile(Rlab, S.shape[0]).astype(float)
        r = abs(stats.spearmanr(x, S.ravel()).statistic)
        ub = boot_ucl(rng, S, Rlab, B=600)
        se = 1.0 / math.sqrt(S.size - 10 - 1)
        ua = r + Z95 * se
        uclb.append(ub); ucla.append(ua)
        H = stats.kruskal(*[S[:, j] for j in range(K)]).statistic
        e_raw = H / (S.size - 1)
        e_cor = (H - (K - 1)) / (S.size - K)
        sd_cor = math.sqrt(2 * (K - 1)) / (S.size - K)
        a += ub < 0.20
        b_ += ua < 0.20
        c_ += e_raw < 0.04
        d_ += (e_cor + Z95 * sd_cor) < 0.04
    res[K] = (np.mean(uclb), np.mean(ucla))
    print(f"  {K:>3} {a/n:>18.3f} {b_/n:>22.3f} {c_/n:>14.3f} {d_/n:>19.3f}")
print()
print("  mean UCL(rho): block-bootstrap vs analytic  (bootstrap over 10 blocks is wider)")
for K in (4, 8, 16):
    print(f"   K={K:>2}  boot={res[K][0]:.4f}   analytic={res[K][1]:.4f}   "
          f"ratio={res[K][0]/res[K][1]:.2f}")

print()
print("=" * 84)
print("(I) reachable eps2_corrected bound at 80% power  (need (z95+z80)*sd_null)")
print("=" * 84)
for K in (4, 8, 16):
    N = 10 * K
    sd = math.sqrt(2 * (K - 1)) / (N - K)
    print(f"  K={K:>2}  sd(eps2_corr|H0)={sd:.4f}   min certifiable bound "
          f"= {(1.6449+0.8416)*sd:.4f}   (frozen SESOI 0.04 -> "
          f"{'UNREACHABLE' if (1.6449+0.8416)*sd > 0.04 else 'ok'})")

print()
print("=" * 84)
print("(J) rho arm: certification power with the ANALYTIC UCL, ICC sweep (1500 sims)")
print("=" * 84)
print(f"  {'K':>3} " + "".join(f"{f'ICC={i}':>10}" for i in (0.0, 0.2, 0.4, 0.6, 0.8)))
for K in (4, 8, 16):
    row = []
    for icc in (0.0, 0.2, 0.4, 0.6, 0.8):
        rng = np.random.default_rng(880 + K * 10 + int(icc * 10))
        Rlab = np.arange(1, K + 1)
        se = 1.0 / math.sqrt(10 * K - 10 - 1)
        ok = 0
        for _ in range(1500):
            S = campaign(rng, K, 0.0, icc)
            r = abs(stats.spearmanr(np.tile(Rlab, 10).astype(float),
                                    S.ravel()).statistic)
            ok += (r + Z95 * se) < 0.20
        row.append(ok / 1500)
    print(f"  {K:>3} " + "".join(f"{v:>10.3f}" for v in row))

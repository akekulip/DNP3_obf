#!/usr/bin/env python3
"""Read-only verification of the v6.8-clustered-v1 power claims.

Checks:
  (A) scipy API availability for the proposed driver
  (B) smoke-pilot dispersion + contamination (motivates trimmed mean)
  (C) analytic SE of the connection-level estimators per K
  (D) Monte-Carlo power to CERTIFY ABSENCE (tau=0) under the frozen estimator
  (E) Monte-Carlo power to DETECT / minimum detectable per-real-point cost
  (F) equivalence-test size at the SESOI boundary (false certification rate)
"""
import json, math
import numpy as np
from scipy import stats

print("=" * 78)
print("(A) scipy / numpy API availability")
print("=" * 78)
for name in ["false_discovery_control", "permutation_test", "bootstrap",
             "kruskal", "spearmanr", "friedmanchisquare", "wilcoxon",
             "trim_mean", "rankdata"]:
    print(f"  scipy.stats.{name:26s} {'OK' if hasattr(stats, name) else 'MISSING'}")
print(f"  numpy {np.__version__}  scipy {stats.__name__} ok")
# axis support on rankdata (needed for the vectorised bootstrap)
try:
    stats.rankdata(np.zeros((2, 3)), axis=1)
    print("  scipy.stats.rankdata(axis=) OK")
except TypeError:
    print("  scipy.stats.rankdata(axis=) MISSING")

print()
print("=" * 78)
print("(B) smoke pilot: per-transaction SBO latency (K=4,R=2, one connection)")
print("=" * 78)
P = ("/home/philip/Projects/DNP3/defense4/evidence/fixed_k_emulator/"
     "smoke_20260805T140802Z/master.json")
m = json.load(open(P))
lat = np.array([(t["t_complete"] - t["t_issue"]) * 1000.0 for t in m["transactions"]])
print("  sbo_total_ms per txn :", np.round(lat, 3).tolist())
scored = lat[1:]                       # drop the warm-up, as the protocol will
print("  scored (warm-up dropped):", np.round(scored, 3).tolist())
print(f"  mean      = {scored.mean():.3f} ms")
print(f"  median    = {np.median(scored):.3f} ms")
print(f"  trim(1/1) = {np.sort(scored)[1:-1].mean():.3f} ms   <- middle 4 of 6")
mad = stats.median_abs_deviation(scored, scale="normal")
print(f"  MAD-sigma = {mad:.3f} ms ; raw sd = {scored.std(ddof=1):.3f} ms")
print(f"  sd/MAD-sigma inflation factor = {scored.std(ddof=1)/mad:.1f}x  "
      "(single spike dominates the mean)")
print(f"  max/median ratio = {scored.max()/np.median(scored):.1f}x")
CONTAM = float((scored > 10 * np.median(scored)).mean())
print(f"  contamination rate in this pilot = {CONTAM:.3f} (1 of {len(scored)})")

print()
print("=" * 78)
print("(C) analytic SE of the connection-level rho estimator, 10 rounds")
print("=" * 78)
print(f"  {'K':>3} {'N_conn':>7} {'N_eff':>7} {'SE(rho)':>9} {'UCL@rho=0':>10} "
      f"{'certify?':>9} {'analytic power':>15}")
Z95, Z80 = 1.6448536, 0.8416212
for K in (4, 8, 16):
    N = 10 * K
    Neff = N - 10          # one df lost per round to the alignment median
    se = 1.0 / math.sqrt(Neff - 1)
    ucl0 = Z95 * se
    need = 0.20 - ucl0
    pw = stats.norm.cdf(need / se)
    print(f"  {K:>3} {N:>7} {Neff:>7} {se:>9.4f} {ucl0:>10.4f} "
          f"{('YES' if ucl0 < 0.20 else 'NO'):>9} {pw:>15.3f}")
print("  (rho*=0.20; one-sided 95% UCL; power = P(certify | true rho = 0))")

print()
print("  classifier arm, per-round balanced accuracy, LORO, chance = 1/K")
print(f"  {'K':>3} {'chance':>8} {'sd(BA_r)':>9} {'SE naive':>9} {'SE NB':>8} "
      f"{'UCL(NB)':>9} {'bound':>8} {'certify?':>9} {'power(NB)':>10}")
NB = math.sqrt(1.0 / 10 + 1.0 / 9) / math.sqrt(1.0 / 10)   # Nadeau-Bengio infl.
T9 = stats.t.ppf(0.95, 9)
for K in (4, 8, 16):
    p = 1.0 / K
    sd_r = math.sqrt(p * (1 - p)) / math.sqrt(K)   # K indep. connections / round
    se_n = sd_r / math.sqrt(10)
    se_nb = se_n * NB
    ucl = p + T9 * se_nb
    bound = p + 0.05
    need = bound - T9 * se_nb
    pw = stats.norm.cdf((need - p) / se_nb)
    print(f"  {K:>3} {p:>8.4f} {sd_r:>9.4f} {se_n:>9.4f} {se_nb:>8.4f} "
          f"{ucl:>9.4f} {bound:>8.4f} {('YES' if ucl < bound else 'NO'):>9} {pw:>10.3f}")
print(f"  (Nadeau-Bengio SE inflation for J=10 folds = {NB:.3f}x)")

# ---------------------------------------------------------------- simulation
def trimmed(a, axis=-1):
    """Symmetric 1-from-each-end trimmed mean of 6 -> mean of middle 4."""
    s = np.sort(a, axis=axis)
    return s[..., 1:-1].mean(axis=axis)


def simulate_campaign(rng, K, tau, icc, n_round=10, n_txn=6,
                      sigma_round=1.0, contam=0.02, spike=30.0):
    """One campaign for one K stratum. Returns aligned connection summaries
    (n_round, K) and the R labels 1..K."""
    s_conn = math.sqrt(icc)
    s_txn = math.sqrt(1.0 - icc)
    b = rng.normal(0, sigma_round, size=(n_round, 1, 1))
    u = rng.normal(0, s_conn, size=(n_round, K, 1))
    e = rng.normal(0, s_txn, size=(n_round, K, n_txn))
    hit = rng.random((n_round, K, n_txn)) < contam
    e = e + hit * spike * s_txn                      # right-tail scheduler spikes
    Rlab = np.arange(1, K + 1).reshape(1, K, 1)
    y = b + u + e + tau * Rlab
    S = trimmed(y, axis=-1)                          # (n_round, K)
    S = S - np.median(S, axis=1, keepdims=True)      # within-round alignment
    return S


def rho_of(S, Rlab):
    x = np.repeat(Rlab[None, :], S.shape[0], axis=0).ravel()
    return stats.spearmanr(x, S.ravel()).statistic


def rho_boot_ucl(rng, S, Rlab, B=800):
    """One-sided 95% upper confidence limit on |rho| by round-level block
    bootstrap (percentile).  Vectorised: rank along axis 1."""
    n_round = S.shape[0]
    idx = rng.integers(0, n_round, size=(B, n_round))
    Sb = S[idx].reshape(B, -1)                        # (B, n_round*K)
    xb = np.tile(Rlab, n_round)[None, :].repeat(B, 0).astype(float)
    ry = stats.rankdata(Sb, axis=1)
    rx = stats.rankdata(xb, axis=1)
    ry -= ry.mean(1, keepdims=True)
    rx -= rx.mean(1, keepdims=True)
    num = (ry * rx).sum(1)
    den = np.sqrt((ry ** 2).sum(1) * (rx ** 2).sum(1))
    r = np.where(den > 0, num / np.where(den == 0, 1, den), 0.0)
    return np.percentile(np.abs(r), 95.0)


def eps2_of(S, Rlab):
    groups = [S[:, j] for j in range(S.shape[1])]
    H = stats.kruskal(*groups).statistic
    N = S.size
    return H / (N - 1)


def run(K, tau, icc, n_sim, seed, B=800, do_detect=False):
    rng = np.random.default_rng(seed)
    Rlab = np.arange(1, K + 1)
    cert = 0
    det = 0
    rhos = []
    for _ in range(n_sim):
        S = simulate_campaign(rng, K, tau, icc)
        r = rho_of(S, Rlab)
        rhos.append(r)
        ucl = rho_boot_ucl(rng, S, Rlab, B=B)
        e2 = eps2_of(S, Rlab)
        if ucl < 0.20 and e2 < 0.04:
            cert += 1
        if do_detect:
            # asymptotic two-sided p for Spearman on N connections
            N = S.size
            pv = stats.spearmanr(np.tile(Rlab, S.shape[0]), S.ravel()).pvalue
            if pv < 0.05 / 27 * 1.0 and abs(r) >= 0.20:   # conservative BH floor
                det += 1
    return cert / n_sim, det / n_sim, float(np.mean(rhos)), float(np.std(rhos))


print()
print("=" * 78)
print("(D) MC power to CERTIFY ABSENCE at tau=0 (frozen estimator, N_sim=800)")
print("=" * 78)
NSIM = 800
print(f"  {'K':>3} {'ICC':>5} {'P(certify|H0)':>15} {'mean rho':>9} {'sd rho':>8}")
res_cert = {}
for K in (4, 8, 16):
    for icc in (0.2, 0.5, 0.8):
        c, _, mr, sr = run(K, 0.0, icc, NSIM, seed=6801 + K * 100 + int(icc * 10))
        res_cert[(K, icc)] = c
        print(f"  {K:>3} {icc:>5.1f} {c:>15.3f} {mr:>9.4f} {sr:>8.4f}")

print()
print("=" * 78)
print("(E) MC power to DETECT vs per-real-point cost tau (in units of the")
print("    within-connection sd); ICC=0.5, N_sim=400, BH-floor alpha=0.05/27")
print("=" * 78)
print(f"  {'K':>3} " + "".join(f"{t:>9.2f}" for t in (0.05, 0.10, 0.20, 0.35, 0.50)))
for K in (4, 8, 16):
    row = []
    for tau in (0.05, 0.10, 0.20, 0.35, 0.50):
        _, d, _, _ = run(K, tau, 0.5, 400, seed=7000 + K * 10 + int(tau * 100),
                         B=200, do_detect=True)
        row.append(d)
    print(f"  {K:>3} " + "".join(f"{v:>9.3f}" for v in row))

print()
print("=" * 78)
print("(F) false-certification rate at the SESOI boundary (true rho ~ 0.20)")
print("=" * 78)
# calibrate tau that yields population rho ~= 0.20 for each K, then measure
for K in (4, 8, 16):
    lo, hi = 0.0, 2.0
    for _ in range(22):
        mid = (lo + hi) / 2
        _, _, mr, _ = run(K, mid, 0.5, 120, seed=9100 + K)
        if mr < 0.20:
            lo = mid
        else:
            hi = mid
    tau20 = (lo + hi) / 2
    c, _, mr, _ = run(K, tau20, 0.5, 600, seed=9200 + K)
    print(f"  K={K:>2}  tau(rho=0.20) = {tau20:.4f} sd-units  "
          f"realised mean rho = {mr:.3f}  P(false certify) = {c:.4f}")
print()
print("  target: P(false certify) <= 0.05 for a valid one-sided equivalence test")

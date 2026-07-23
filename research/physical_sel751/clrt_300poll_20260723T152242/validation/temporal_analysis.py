#!/usr/bin/env python3
"""
Task 2 + 3: temporal-dependence and bootstrap-validity analysis for the 300-poll CLRT experiment.
Reads the COMMITTED per_poll.csv read-only; writes autocorrelation CSVs, a results JSON, and plots
under validation/. Ljung-Box computed manually (statsmodels absent) via the chi-square distribution.
"""
import os, csv, json
import numpy as np
from scipy import stats

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VAL = os.path.join(BASE, "validation")
PLOTS = os.path.join(VAL, "plots")
PERPOLL = os.path.join(BASE, "per_poll.csv")
SUMMARY = os.path.join(BASE, "summary.json")
RNG = np.random.default_rng(20260723)
SERIES = [("request_to_ack_ms", "request_to_pure_ACK"),
          ("ack_to_response_clrt_ms", "ACK_to_response_CLRT"),
          ("request_to_response_ms", "request_to_response")]


def acf(x, maxlag=10):
    x = np.asarray(x, float); n = len(x); xm = x - x.mean()
    denom = np.sum(xm * xm)
    return [float(np.sum(xm[:n - k] * xm[k:]) / denom) for k in range(0, maxlag + 1)]


def ljung_box(r, n, hs=(5, 10)):
    out = {}
    for h in hs:
        Q = n * (n + 2) * sum((r[k] ** 2) / (n - k) for k in range(1, h + 1))
        p = float(1 - stats.chi2.cdf(Q, h))
        out[h] = {"Q": float(Q), "df": h, "p_value": p}
    return out


def seg(x):
    x = np.asarray(x, float)
    return dict(n=int(len(x)), mean=float(x.mean()), median=float(np.median(x)),
                std=float(x.std(ddof=1)), p95=float(np.percentile(x, 95)),
                min=float(x.min()), max=float(x.max()))


def rolling(x, w, fn):
    x = np.asarray(x, float)
    if len(x) < w:
        return []
    from numpy.lib.stride_tricks import sliding_window_view
    return [float(fn(win)) for win in sliding_window_view(x, w)]


def clusters(x, thr):
    """maximal runs (length>=2) of consecutive observations strictly above thr."""
    x = np.asarray(x, float); runs = []; s = None
    for i, v in enumerate(x):
        if v > thr and s is None:
            s = i
        elif v <= thr and s is not None:
            if i - s >= 2:
                runs.append(dict(start_poll=s + 1, end_poll=i, length=i - s,
                                 max=float(x[s:i].max())))
            s = None
    if s is not None and len(x) - s >= 2:
        runs.append(dict(start_poll=s + 1, end_poll=len(x), length=len(x) - s, max=float(x[s:].max())))
    return runs


def iid_boot(x, fn, n=10000):
    x = np.asarray(x, float); idx = RNG.integers(0, len(x), size=(n, len(x)))
    v = fn(x[idx], axis=1); return [float(np.percentile(v, 2.5)), float(np.percentile(v, 97.5))]


def block_boot(x, fn, L, n=10000):
    """moving-block bootstrap: overlapping blocks of length L, wrap-around, resample ceil(N/L) blocks."""
    x = np.asarray(x, float); N = len(x); nb = int(np.ceil(N / L))
    ext = np.concatenate([x, x[:L]])                      # wrap for overlapping blocks
    starts = RNG.integers(0, N, size=(n, nb))
    samples = np.empty((n, nb * L))
    for j in range(nb):
        s = starts[:, j]
        samples[:, j * L:(j + 1) * L] = np.stack([ext[si:si + L] for si in s])
    samples = samples[:, :N]
    v = fn(samples, axis=1); return [float(np.percentile(v, 2.5)), float(np.percentile(v, 97.5))]


def main():
    os.makedirs(PLOTS, exist_ok=True)
    rows = list(csv.DictReader(open(PERPOLL)))
    poll = np.array([int(r["poll_number"]) for r in rows])
    data = {col: np.array([float(r[col]) for r in rows]) for col, _ in SERIES}

    results = {"n": len(rows), "series": {}}
    # block length from lag-1 ACF of CLRT: L ~ round(n^(1/3)) as a standard default, reported explicitly
    L = int(round(len(rows) ** (1 / 3)))   # = 7 for n=300

    import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
    fig_acf, axes = plt.subplots(3, 1, figsize=(8, 9))

    for ax, (col, name) in zip(axes, SERIES):
        x = data[col]; n = len(x)
        r = acf(x, 10)
        lb = ljung_box(r, n, (5, 10))
        band = 1.96 / np.sqrt(n)
        # linear trend
        lr = stats.linregress(poll, x)
        # segments
        segs = dict(first50=seg(x[:50]), middle200=seg(x[50:250]), final50=seg(x[250:]))
        # clusters above p90
        thr = float(np.percentile(x, 90))
        cl = clusters(x, thr)
        results["series"][name] = dict(
            acf_lag1_to_10=[round(v, 4) for v in r[1:]],
            acf_significance_band_95=round(float(band), 4),
            acf_lags_outside_band=[k for k in range(1, 11) if abs(r[k]) > band],
            ljung_box=lb,
            linear_trend=dict(slope_ms_per_poll=float(lr.slope), intercept=float(lr.intercept),
                              r_squared=float(lr.rvalue ** 2), p_value=float(lr.pvalue),
                              stderr=float(lr.stderr)),
            segments=segs,
            high_latency_threshold_p90_ms=thr,
            high_latency_clusters=cl,
            n_high_latency=int(np.sum(x > thr)))
        # autocorr CSV per series
        with open(os.path.join(VAL, "autocorr_%s.csv" % name), "w", newline="") as f:
            w = csv.writer(f); w.writerow(["lag", "acf", "outside_95_band", "sig_band_+/-"])
            for k in range(1, 11):
                w.writerow([k, round(r[k], 6), int(abs(r[k]) > band), round(band, 6)])
            w.writerow([]); w.writerow(["ljung_box_h5_Q", round(lb[5]["Q"], 4), "p", round(lb[5]["p_value"], 6)])
            w.writerow(["ljung_box_h10_Q", round(lb[10]["Q"], 4), "p", round(lb[10]["p_value"], 6)])
        # ACF plot
        ax.stem(range(1, 11), r[1:11])
        ax.axhline(band, color="r", ls="--", lw=0.8); ax.axhline(-band, color="r", ls="--", lw=0.8)
        ax.axhline(0, color="k", lw=0.6)
        ax.set_title("ACF: %s (95%% band +/-%.3f)" % (name, band)); ax.set_xlabel("lag"); ax.set_ylabel("ACF")
    fig_acf.tight_layout(); fig_acf.savefig(os.path.join(PLOTS, "acf_all_series.png"), dpi=140); plt.close(fig_acf)

    # ---- bootstrap comparison on CLRT (mean + median): IID vs moving-block ----
    clrt = data["ack_to_response_clrt_ms"]
    S = json.load(open(SUMMARY))["latency_ms"]["ack_to_response_clrt_ms"]
    boot = dict(block_length_primary=L, block_rule="round(n^(1/3))=7; sensitivity at 15 and 30",
                iid_from_committed_summary=dict(mean_ci=S["bootstrap_ci95_mean"], median_ci=S["bootstrap_ci95_median"]),
                iid_recomputed=dict(mean_ci=iid_boot(clrt, np.mean), median_ci=iid_boot(clrt, np.median)),
                moving_block={})
    for Lv in (L, 15, 30):
        boot["moving_block"]["L%d" % Lv] = dict(mean_ci=block_boot(clrt, np.mean, Lv),
                                                median_ci=block_boot(clrt, np.median, Lv))
    # decision: meaningful dependence if CLRT Ljung-Box(h=10) p<0.05 or lag-1 outside band
    clrt_res = results["series"]["ACK_to_response_CLRT"]
    dependence = (clrt_res["ljung_box"][10]["p_value"] < 0.05) or (1 in clrt_res["acf_lags_outside_band"])
    boot["clrt_temporal_dependence_meaningful"] = bool(dependence)
    boot["primary_interval"] = ("moving_block_L%d" % L) if dependence else "iid"
    results["bootstrap_assessment"] = boot

    # rolling median / p95 for CLRT
    w = 25
    rm = rolling(clrt, w, np.median); rp = rolling(clrt, w, lambda a: np.percentile(a, 95))
    xr = np.arange(w, len(clrt) + 1)
    fig, ax = plt.subplots(figsize=(8, 4.2))
    ax.plot(range(1, len(clrt) + 1), clrt, color="#c7d3d3", lw=0.7, label="CLRT")
    ax.plot(xr, rm, color="#0e7c86", lw=1.6, label="rolling median (w=25)")
    ax.plot(xr, rp, color="#b0432c", lw=1.4, label="rolling p95 (w=25)")
    ax.set_xlabel("poll number"); ax.set_ylabel("CLRT (ms)"); ax.set_ylim(bottom=0)
    ax.set_title("CLRT rolling median / p95"); ax.legend(); ax.grid(alpha=0.3)
    fig.tight_layout(); fig.savefig(os.path.join(PLOTS, "clrt_rolling.png"), dpi=140); plt.close(fig)
    # trend scatter
    fig, ax = plt.subplots(figsize=(8, 4.2))
    ax.scatter(poll, clrt, s=8, color="#0e7c86")
    lrc = results["series"]["ACK_to_response_CLRT"]["linear_trend"]
    ax.plot(poll, lrc["intercept"] + lrc["slope_ms_per_poll"] * poll, color="#b0432c",
            label="trend %.2e ms/poll (p=%.3f)" % (lrc["slope_ms_per_poll"], lrc["p_value"]))
    ax.set_xlabel("poll number"); ax.set_ylabel("CLRT (ms)"); ax.set_ylim(bottom=0)
    ax.set_title("CLRT vs poll number (linear trend)"); ax.legend(); ax.grid(alpha=0.3)
    fig.tight_layout(); fig.savefig(os.path.join(PLOTS, "clrt_trend.png"), dpi=140); plt.close(fig)

    json.dump(results, open(os.path.join(VAL, "temporal_results.json"), "w"), indent=1)
    print(json.dumps(results, indent=1))


if __name__ == "__main__":
    main()

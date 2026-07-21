#!/usr/bin/env python3
"""S0 (control-response) -- offline smoke test for size-normalization of the STRONG size fingerprint.

Secret here is the CROB count N (control-command complexity), NOT device identity. Response size is a
near-perfect proxy for N (14.6 B/CROB, R^2=0.9999; 16 distinct sizes 37..256 B for N=1..16). This is
the rich many-valued distribution where bucketing has real work. n=1 per N -> a CV classifier is
degenerate, so the metrics are information-theoretic + an analytic best-guess N-recovery accuracy.

Input: s0_results/control_response_sizes.csv (extracted from the multi-CROB SBO pcaps).
Interpreter: python3 (numpy/pandas). No switch, no P4. Deterministic.
"""
import json
import os
import numpy as np
import pandas as pd

HERE = os.path.dirname(__file__)
CSV = os.path.join(HERE, "s0_results", "control_response_sizes.csv")
OUTDIR = os.path.join(HERE, "s0_results")
BUCKETS = [None, 16, 8, 4, 2, 1]     # None = native (== 16 distinct here)
BLOCK_BYTES = 18                     # constant DNP3 filler block on-wire (16 data + 2 CRC)
MSS = 1460


def equal_count_buckets(n_values, sizes, B):
    """Uniform secret over N -> equal-count buckets of consecutive N (== equal-count over sizes,
    since size is monotone in N). Pad each bucket UP to its ceiling. Returns padded sizes."""
    order = np.argsort(n_values)
    padded = sizes.copy().astype(int)
    if B is None or B >= len(sizes):
        return padded
    # split the ordered indices into B nearly-equal contiguous groups
    groups = np.array_split(order, B)
    for g in groups:
        padded[g] = sizes[g].max()
    return padded


def block_quantized(original, padded):
    add = padded - original
    blocks = np.ceil(add / BLOCK_BYTES).astype(int)
    return original + blocks * BLOCK_BYTES


def mi_bits_uniform(padded, n_values):
    """I(padded_size ; N) in bits, N uniform over the observed levels (max-entropy assumption).
    With one sample per N, p(N)=1/L; p(size)=|{N mapping to size}|/L; MI = H(N) - H(N|size)."""
    L = len(n_values)
    df = pd.DataFrame({"s": padded, "n": n_values})
    HN = np.log2(L)
    # H(N|size): within each padded size the surviving N's are equiprobable
    Hcond = 0.0
    for s, g in df.groupby("s"):
        k = len(g)
        Hcond += (k / L) * np.log2(k)   # -(k/L) * sum(1/k log2 1/k) = (k/L) log2 k
    mi = HN - Hcond
    return float(mi), float(HN)


def n_recovery_accuracy(padded, n_values):
    """Best-guess accuracy of recovering N from the padded size (uniform prior). All N sharing a
    padded size are indistinguishable -> best guess wins 1 of them -> acc = (#distinct sizes)/L."""
    L = len(n_values)
    return len(np.unique(padded)) / L, 1.0 / L      # (accuracy, chance)


def anonymity(padded, n_values):
    df = pd.DataFrame({"s": padded, "n": n_values})
    k_by = df.groupby("s")["n"].nunique()
    return {"min_k": int(k_by.min()), "max_k": int(k_by.max()),
            "n_distinct_padded_sizes": int(len(k_by)),
            "n_isolated_k1": int((k_by == 1).sum())}


def main():
    df = pd.read_csv(CSV, comment="#")
    n_values = df["n"].values.astype(int)
    sizes = df["resp_size"].values.astype(int)
    results = {"dataset": {"secret": "CROB_count_N", "n_levels": int(len(n_values)),
                           "sizes_by_N": dict(zip(n_values.tolist(), sizes.tolist())),
                           "slope_B_per_CROB": round(float(np.polyfit(n_values, sizes, 1)[0]), 2),
                           "block_bytes": BLOCK_BYTES},
               "by_bucket": []}

    print("=" * 92)
    print("S0 CONTROL-RESPONSE SMOKE TEST -- size-normalization of the CROB-COUNT fingerprint (14.6 B/CROB)")
    print("=" * 92)
    print("secret = CROB count N in 1..%d ; native sizes 37..256 B ; slope %.1f B/CROB ; H(N)=%.2f bits"
          % (len(n_values), results["dataset"]["slope_B_per_CROB"], np.log2(len(n_values))))
    print("-" * 92)
    print("%-8s | ideal: N-recov  MI_bits | block: N-recov  MI_bits | k(min/max) isolated | add mean/max B"
          % "B")

    for B in BUCKETS:
        padded = equal_count_buckets(n_values, sizes, B)
        padded_q = block_quantized(sizes, padded)

        mi, HN = mi_bits_uniform(padded, n_values)
        acc, chance = n_recovery_accuracy(padded, n_values)
        anon = anonymity(padded, n_values)

        mi_q, _ = mi_bits_uniform(padded_q, n_values)
        acc_q, _ = n_recovery_accuracy(padded_q, n_values)
        anon_q = anonymity(padded_q, n_values)

        add = padded - sizes
        add_q = padded_q - sizes
        g1 = bool(np.all(padded >= sizes))
        g2 = bool(np.all((add_q % BLOCK_BYTES) == 0))
        g9 = bool(np.all(padded_q <= MSS))

        row = {"B": ("native" if B is None else B),
               "ideal": {"n_recovery_acc": round(acc, 4), "mi_bits": round(mi, 4),
                         "anonymity": anon, "padded_sizes": sorted(np.unique(padded).tolist())},
               "constant_block": {"n_recovery_acc": round(acc_q, 4), "mi_bits": round(mi_q, 4),
                                  "anonymity": anon_q, "padded_sizes": sorted(np.unique(padded_q).tolist())},
               "chance_acc": round(chance, 4),
               "overhead_added_bytes": {"mean": round(float(add.mean()), 1),
                                        "max": int(add.max()),
                                        "mean_relative": round(float((add / sizes).mean()), 3)},
               "overhead_block_quantized": {"mean": round(float(add_q.mean()), 1), "max": int(add_q.max())},
               "gates": {"G1_up_only": g1, "G2_constant_block": g2, "G9_no_mss_crossing": g9}}
        results["by_bucket"].append(row)
        print("%-8s | ideal: %.4f    %.3f | block: %.4f    %.3f | %d/%d       %d      | %.1f / %d"
              % (str("native" if B is None else B), acc, mi, acc_q, mi_q,
                 anon["min_k"], anon["max_k"], anon["n_isolated_k1"], add.mean(), int(add.max())))

    print("-" * 92)
    print("chance N-recovery = %.4f (1/%d)" % (1.0 / len(n_values), len(n_values)))
    with open(os.path.join(OUTDIR, "s0_control_results.json"), "w") as f:
        json.dump(results, f, indent=2)
    print("wrote %s" % os.path.join(OUTDIR, "s0_control_results.json"))


if __name__ == "__main__":
    main()

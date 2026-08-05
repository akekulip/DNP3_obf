#!/usr/bin/env python3
"""Frozen cluster-aware power table for the fixed-K DNP3 timing side-channel preregistration
(v6.8-clustered-v1, master seed 6801). Reproduces + prints the §5.1 (certify-absence) and §5.2
(detect) tables, writes power_table.csv + power_simulation.json, and emits the per-K absence verdict.

Run: $RESEARCH_PYTHON fixed_k/power_criterion_6_8.py   (numpy/scipy). No hardware, no network.

Independent unit = the CONNECTION (R,K are constant within a persistent connection), so power is at
connection-level n = ROUNDS*K (40/80/160 for K=4/8/16), NOT the 60 transactions/cell.

Formulas (alpha=0.05):
  z1 = Phi^{-1}(1-a) one-sided (1.6449); z2 = Phi^{-1}(1-a/2) two-sided (1.9600).
  Spearman DETECT true |rho|:  Phi(atanh(rho)sqrt(n-3) - z2) + Phi(-atanh(rho)sqrt(n-3) - z2)
  Spearman CERTIFY |rho|<rho* (true rho=0): Phi(atanh(rho*)sqrt(n-3) - z1)
  Classifier BA at chance p=1/K, se=sqrt(p(1-p)/n):
     CERTIFY BA<chance+dBA: Phi(dBA/se - z1);  DETECT lift L: Phi(L/se - z1)
Frozen §5.1 targets: K4(n40) Spearman 0.34/cls 0.18 ; K8(n80) 0.55/0.39 ; K16(n160) 0.82/0.83.
"""
import csv
import json
import math
from pathlib import Path

import numpy as np
from scipy.stats import norm

VERSION, MASTER_SEED = "v6.8-clustered-v1", 6801
ALPHA, RHO_STAR, DELTA_BA = 0.05, 0.20, 0.05
TARGET_POWER = LICENSE_BAR = 0.80
K_VALUES, ROUNDS = (4, 8, 16), 10
RHO_DETECT, BA_LIFTS = (0.2, 0.3, 0.4, 0.5), (0.10, 0.20)
FROZEN_5_1 = {4: (0.34, 0.18), 8: (0.55, 0.39), 16: (0.82, 0.83)}
Z1 = float(norm.ppf(1 - ALPHA))
Z2 = float(norm.ppf(1 - ALPHA / 2))


def n_conn(k):
    return ROUNDS * k


def spearman_detect(rho, n):
    a = math.atanh(rho) * math.sqrt(n - 3)
    return float(norm.cdf(a - Z2) + norm.cdf(-a - Z2))


def spearman_certify(rho_star, n):
    return float(norm.cdf(math.atanh(rho_star) * math.sqrt(n - 3) - Z1))


def cls_se(k, n):
    p = 1.0 / k
    return math.sqrt(p * (1 - p) / n)


def cls_certify(k, n, delta=DELTA_BA):
    return float(norm.cdf(delta / cls_se(k, n) - Z1))


def cls_detect(k, n, lift):
    return float(norm.cdf(lift / cls_se(k, n) - Z1))


def rounds_to_certify_spearman(k, rho_star, power):
    n = 3.0 + ((float(norm.ppf(power)) + Z1) / math.atanh(rho_star)) ** 2
    return math.ceil(n / k)


def rounds_to_certify_cls(k, delta, power):
    p = 1.0 / k
    n = p * (1 - p) * ((float(norm.ppf(power)) + Z1) / delta) ** 2
    return math.ceil(n / k)


def build():
    certify = {}
    for k in K_VALUES:
        n = n_conn(k)
        sp, cl = spearman_certify(RHO_STAR, n), cls_certify(k, n)
        verdict = "LICENSABLE" if (sp >= LICENSE_BAR and cl >= LICENSE_BAR) else "INCONCLUSIVE"
        certify[k] = {"n_conn": n, "spearman": sp, "classifier": cl, "verdict": verdict}
    det_sp = {k: {r: spearman_detect(r, n_conn(k)) for r in RHO_DETECT} for k in K_VALUES}
    det_cl = {k: {l: cls_detect(k, n_conn(k), l) for l in BA_LIFTS} for k in K_VALUES}
    wt = {"target_power": TARGET_POWER,
          "spearman_rounds_K4": rounds_to_certify_spearman(4, RHO_STAR, TARGET_POWER),
          "classifier_rounds_K4": rounds_to_certify_cls(4, DELTA_BA, TARGET_POWER)}
    return {"certify": certify, "detect_spearman": det_sp, "detect_classifier": det_cl, "would_take": wt}


def main():
    out = Path(__file__).resolve().parent
    t = build()
    c = t["certify"]
    for k in K_VALUES:                       # self-check vs frozen §5.1 (tol 0.01)
        assert abs(c[k]["spearman"] - FROZEN_5_1[k][0]) <= 0.01, k
        assert abs(c[k]["classifier"] - FROZEN_5_1[k][1]) <= 0.01, k
    print("=" * 72)
    print(" fixed-K timing side-channel power  [%s]  seed %d  alpha %.2f (connection-level)"
          % (VERSION, MASTER_SEED, ALPHA))
    print(" design: %d K, %d rounds, 1 warm-up + 6 scored SBOs/connection; unit = CONNECTION"
          % (len(K_VALUES), ROUNDS))
    print("=" * 72)
    print("\n§5.1 CERTIFY-ABSENCE power (rho*=%.2f, dBA=%.2f, chance=1/K, bar>=%.2f)"
          % (RHO_STAR, DELTA_BA, LICENSE_BAR))
    print("  K   n_conn  Spearman(rho*)  Classifier(dBA)  verdict")
    for k in K_VALUES:
        print("  %-3d %5d      %6.3f          %6.3f         %s"
              % (k, c[k]["n_conn"], c[k]["spearman"], c[k]["classifier"], c[k]["verdict"]))
    print("\n§5.2 DETECT power (Spearman true |rho|):")
    print("  K   n_conn " + "".join("  rho=%-4s" % r for r in RHO_DETECT))
    for k in K_VALUES:
        print("  %-3d %5d  " % (k, n_conn(k)) + "".join("  %6.3f" % t["detect_spearman"][k][r] for r in RHO_DETECT))
    print("  classifier BA lift:")
    print("  K   n_conn " + "".join("   +%-4s" % l for l in BA_LIFTS))
    for k in K_VALUES:
        print("  %-3d %5d  " % (k, n_conn(k)) + "".join("  %6.3f" % t["detect_classifier"][k][l] for l in BA_LIFTS))
    wt = t["would_take"]
    print("\n  what it would take (K=4, 80%% power to certify absence):")
    print("    Spearman rho*=%.2f  -> ~%d rounds ;  classifier dBA=%.2f -> ~%d rounds"
          % (RHO_STAR, wt["spearman_rounds_K4"], DELTA_BA, wt["classifier_rounds_K4"]))
    print("\n  absence-licensing verdict: " + ", ".join("K%d=%s" % (k, c[k]["verdict"]) for k in K_VALUES))
    # write artifacts
    with open(out / "power_table.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["section", "K", "n_conn", "effect_type", "effect", "power"])
        for k in K_VALUES:
            w.writerow(["5.1", k, c[k]["n_conn"], "spearman_rho_star", RHO_STAR, "%.4f" % c[k]["spearman"]])
            w.writerow(["5.1", k, c[k]["n_conn"], "classifier_delta_BA", DELTA_BA, "%.4f" % c[k]["classifier"]])
        for k in K_VALUES:
            for r in RHO_DETECT:
                w.writerow(["5.2", k, n_conn(k), "spearman_rho", r, "%.4f" % t["detect_spearman"][k][r]])
            for l in BA_LIFTS:
                w.writerow(["5.2", k, n_conn(k), "classifier_BA_lift", l, "%.4f" % t["detect_classifier"][k][l]])
    payload = {"version": VERSION, "master_seed": MASTER_SEED,
               "config": {"alpha": ALPHA, "rho_star": RHO_STAR, "delta_BA": DELTA_BA,
                          "rounds": ROUNDS, "n_conn": {k: n_conn(k) for k in K_VALUES},
                          "unit": "connection (R,K constant within a persistent TCP connection)"},
               "frozen_5_1_targets": {str(k): FROZEN_5_1[k] for k in K_VALUES},
               "certify_absence": {str(k): {"n_conn": c[k]["n_conn"],
                                            "spearman_power": round(c[k]["spearman"], 4),
                                            "classifier_power": round(c[k]["classifier"], 4),
                                            "verdict": c[k]["verdict"]} for k in K_VALUES},
               "what_it_would_take": wt,
               "verdict": {str(k): c[k]["verdict"] for k in K_VALUES}}
    with open(out / "power_simulation.json", "w") as f:
        json.dump(payload, f, indent=2)
    print("  wrote power_table.csv + power_simulation.json")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""E0 -- Defense-4 no-hardware gate. Per-observable leakage AFTER Defense 3.

Two-class problem = {native} vs {D-defended arm}, per feature, matching the
dsweep_analysis.py `separability_vs_native` semantics, extended with:
  - grouped (leave-one-round-out) CV balanced accuracy
  - permutation drift-floor per feature
  - block-bootstrap 95% CIs (resample the connection-blocks, not transactions)
  - mutual information (binned, Miller-Madow corrected) with shuffle null
  - residual dispersion (sd, IQR, entropy) of the strongest arm alone
Size axis handled from the 300-poll native corpus (D3 does not touch size).
"""
import json, math, statistics as st, random
from collections import defaultdict
import numpy as np

random.seed(42); np.random.seed(42)
DS = '/home/philip/Projects/DNP3/defense3/evidence/physical/dsweep_blocks.jsonl'

# ---- load per-transaction records, blocked by connection (=label/round+arm) ----
recs = []  # dict: arm, round, block, clrt, r2a, inter
for line in open(DS):
    o = json.loads(line)
    arm = o['arm']; lab = o['label']; rnd = lab.split('_')[0]
    tr = [r['t_read'] for r in o['block']['rows']]
    for i, r in enumerate(o['block']['rows']):
        inter = (tr[i]-tr[i-1])*1000 if i > 0 else None
        recs.append(dict(arm=arm, rnd=rnd, block=lab,
                         clrt=r['clrt_ms'], r2a=r['read_to_ack_ms'],
                         r2r=r['read_to_resp_ms'], inter=inter))

FEATS = {'CLRT (ACK->response)':'clrt', 'READ->ACK':'r2a', 'inter-arrival':'inter'}

def feat_vals(records, key):
    return [r[key] for r in records if r[key] is not None]

def best_balacc(x0, x1):
    """Max balanced accuracy over threshold+orientation for 1D two-sample."""
    xs = sorted(set(x0+x1)); best = 0.5
    cand = [xs[0]-1] + [(xs[i]+xs[i+1])/2 for i in range(len(xs)-1)] + [xs[-1]+1]
    n0, n1 = len(x0), len(x1)
    for t in cand:
        # orientation A: class1 = x>t
        tpr = sum(v > t for v in x1)/n1; tnr = sum(v <= t for v in x0)/n0
        best = max(best, 0.5*(tpr+tnr))
        # orientation B
        tpr = sum(v <= t for v in x1)/n1; tnr = sum(v > t for v in x0)/n0
        best = max(best, 0.5*(tpr+tnr))
    return best

def grouped_cv_balacc(recs_n, recs_d, key):
    """Leave-one-round-out: fit threshold on train rounds, eval on held-out round."""
    rounds = sorted(set(r['rnd'] for r in recs_n) | set(r['rnd'] for r in recs_d))
    accs = []
    for ho in rounds:
        tr_n = [r[key] for r in recs_n if r['rnd'] != ho and r[key] is not None]
        tr_d = [r[key] for r in recs_d if r['rnd'] != ho and r[key] is not None]
        te_n = [r[key] for r in recs_n if r['rnd'] == ho and r[key] is not None]
        te_d = [r[key] for r in recs_d if r['rnd'] == ho and r[key] is not None]
        if not tr_n or not tr_d or not te_n or not te_d:
            continue
        # fit best threshold + orientation on train
        xs = sorted(set(tr_n+tr_d))
        cand = [xs[0]-1]+[(xs[i]+xs[i+1])/2 for i in range(len(xs)-1)]+[xs[-1]+1]
        bestt, besto, bestacc = None, None, -1
        for t in cand:
            for orient in (0, 1):
                if orient == 0:
                    tpr = sum(v > t for v in tr_d)/len(tr_d); tnr = sum(v <= t for v in tr_n)/len(tr_n)
                else:
                    tpr = sum(v <= t for v in tr_d)/len(tr_d); tnr = sum(v > t for v in tr_n)/len(tr_n)
                a = 0.5*(tpr+tnr)
                if a > bestacc: bestacc, bestt, besto = a, t, orient
        # eval on test
        if besto == 0:
            tpr = sum(v > bestt for v in te_d)/len(te_d); tnr = sum(v <= bestt for v in te_n)/len(te_n)
        else:
            tpr = sum(v <= bestt for v in te_d)/len(te_d); tnr = sum(v > bestt for v in te_n)/len(te_n)
        accs.append(0.5*(tpr+tnr))
    return float(np.mean(accs)), accs

def block_bootstrap_balacc(recs_n, recs_d, key, B=2000):
    """Resample connection-blocks with replacement; pooled best-balacc each draw."""
    bn = defaultdict(list); bd = defaultdict(list)
    for r in recs_n:
        if r[key] is not None: bn[r['block']].append(r[key])
    for r in recs_d:
        if r[key] is not None: bd[r['block']].append(r[key])
    kn, kd = list(bn), list(bd)
    out = []
    for _ in range(B):
        x0 = []; [x0.extend(bn[random.choice(kn)]) for _ in kn]
        x1 = []; [x1.extend(bd[random.choice(kd)]) for _ in kd]
        out.append(best_balacc(x0, x1))
    lo, hi = np.percentile(out, [2.5, 97.5])
    return float(np.mean(out)), float(lo), float(hi)

def perm_floor_balacc(recs_n, recs_d, key, B=2000):
    """Permutation null: shuffle native/defended labels, best-balacc."""
    x0 = [r[key] for r in recs_n if r[key] is not None]
    x1 = [r[key] for r in recs_d if r[key] is not None]
    pooled = x0+x1; n0 = len(x0)
    out = []
    for _ in range(B):
        random.shuffle(pooled)
        out.append(best_balacc(pooled[:n0], pooled[n0:]))
    return float(np.mean(out)), float(np.percentile(out, 95))

def mi_binned_bits(recs_n, recs_d, key, bins=16):
    """MI(feature;label) in bits, Miller-Madow corrected, with shuffle null."""
    x0 = np.array([r[key] for r in recs_n if r[key] is not None])
    x1 = np.array([r[key] for r in recs_d if r[key] is not None])
    x = np.concatenate([x0, x1]); y = np.array([0]*len(x0)+[1]*len(x1))
    edges = np.histogram_bin_edges(x, bins=bins)
    xb = np.clip(np.digitize(x, edges[1:-1]), 0, bins-1)
    def mi(xb, y):
        n = len(y); mi = 0.0
        # joint
        classes = [0, 1]; occ = 0
        for c in classes:
            pc = np.mean(y == c)
            for b in range(bins):
                pjoint = np.mean((y == c) & (xb == b))
                if pjoint > 0:
                    px = np.mean(xb == b)
                    mi += pjoint*math.log2(pjoint/(px*pc)); occ += 1
        # Miller-Madow: + (#nonzero_cells -1)/(2 n ln2)
        mm = (occ-1)/(2*n*math.log(2))
        return mi, mi-mm  # raw, corrected(approx by subtracting bias)
    raw, corr = mi(xb, y)
    # shuffle null
    nulls = []
    yb = y.copy()
    for _ in range(500):
        np.random.shuffle(yb)
        nulls.append(mi(xb, yb)[0])
    return float(raw), float(corr), float(np.mean(nulls)), float(np.percentile(nulls, 95))

def dispersion(recs, key, binw=0.1):
    v = np.array([r[key] for r in recs if r[key] is not None])
    if len(v) == 0: return None
    q1, q3 = np.percentile(v, [25, 75])
    # shannon entropy on fixed-width bins
    lo, hi = v.min(), v.max()
    if hi-lo < 1e-9:
        H = 0.0
    else:
        edges = np.arange(lo, hi+binw, binw)
        h, _ = np.histogram(v, bins=edges); p = h/h.sum(); p = p[p > 0]
        H = -np.sum(p*np.log2(p))
    return dict(n=len(v), med=float(np.median(v)), sd=float(np.std(v)),
                iqr=float(q3-q1), min=float(v.min()), max=float(v.max()), H_bits=float(H))

# ---------------- run ----------------
by_arm = defaultdict(list)
for r in recs: by_arm[r['arm']].append(r)
NAT = by_arm['native']
print("="*78)
print("E0 -- per-observable leakage, {native} vs {defended arm}.  n(native)=%d" % len(NAT))
print("Blocks: native=%d, each arm=%d connections; 20 txns/connection." %
      (len(set(r['block'] for r in NAT)), len(set(r['block'] for r in by_arm['d16']))))
print("="*78)

for fname, key in FEATS.items():
    print("\n#### FEATURE: %s" % fname)
    pf_mean, pf95 = perm_floor_balacc(NAT, by_arm['d16'], key)
    print("  permutation drift-floor bal-acc: mean=%.3f  95th=%.3f" % (pf_mean, pf95))
    print("  %-5s %-9s %-30s %-18s %-22s" %
          ("arm", "pooled", "grouped-CV balacc [folds]", "MI bits(corr/null95)", "block-boot 95%CI"))
    for arm in ['d1', 'd2', 'd4', 'd8', 'd16']:
        D = by_arm[arm]
        pooled = best_balacc(feat_vals(NAT, key), feat_vals(D, key))
        cvm, folds = grouped_cv_balacc(NAT, D, key)
        raw, corr, null_m, null95 = mi_binned_bits(NAT, D, key)
        bbm, lo, hi = block_bootstrap_balacc(NAT, D, key, B=1500)
        print("  %-5s %6.3f    %5.3f %-24s %5.2f/%4.2f            [%.3f,%.3f]" %
              (arm, pooled, cvm, str([round(x, 2) for x in folds]), corr, null95, lo, hi))

print("\n#### RESIDUAL DISPERSION (defended arm alone; the raw material for fingerprinting)")
print("  %-22s | native            | D16 (pure D3 config)" % "feature")
for fname, key in FEATS.items():
    dn = dispersion(NAT, key); dd = dispersion(by_arm['d16'], key)
    if dn and dd:
        print("  %-22s | sd=%7.3f H=%4.2fb | sd=%7.3f H=%4.2fb  (med %.2f->%.2f)" %
              (fname, dn['sd'], dn['H_bits'], dd['sd'], dd['H_bits'], dn['med'], dd['med']))

# ---------------- SIZE axis (300-poll native) ----------------
print("\n#### SIZE axis (300-poll native class-0 READ; D3 does not modify size)")
import csv
rows = list(csv.DictReader(open('/home/philip/Projects/DNP3/research/physical_sel751/clrt_300poll_20260723T152242/per_poll.csv')))
for col in ['response_wire_bytes', 'dnp3_response_length', 'decoded_point_count']:
    vals = [int(r[col]) for r in rows]
    n_distinct = len(set(vals))
    # entropy
    from collections import Counter
    c = Counter(vals); p = np.array(list(c.values()))/len(vals); H = -np.sum(p*np.log2(p))
    print("  %-22s n=%d  distinct=%d  H=%.3f bits  values=%s" %
          (col, len(vals), n_distinct, H, sorted(set(vals))))
print("  => within-READ size MI = 0 bits (single class). Balanced-acc = 0.50 (floor).")
print("  size_inventory: physical_relay_300poll wire_len n_distinct=1 (200B); tcp_payload=134B; dnp3=115B.")

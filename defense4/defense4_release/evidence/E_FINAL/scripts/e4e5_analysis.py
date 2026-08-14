#!/usr/bin/env python3
"""E4 stats + E5 classifier (audit-corrected).
- JS reported as DISTANCE (scipy.jensenshannon returns distance = sqrt(divergence)); divergence = distance^2.
- MI with COMMON predeclared CLRT bins + permutation 95% CI.
- Classifier is a READ-vs-SELECT TRANSACTION-CLASS classifier (NOT device); split transaction-disjoint,
  NOT session-disjoint (all txns from one capture session) -- stated as a limitation."""
import csv, json, numpy as np
from scipy.spatial.distance import jensenshannon
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import balanced_accuracy_score, mutual_info_score
FIN="defense4/size/native_parity/evidence/E_FINAL"
BINS=np.linspace(0.0,12.0,61)   # predeclared common CLRT bins (ms), used for BOTH JS and MI
def clrt(f, func):
    return np.array([float(r["clrt_ms"]) for r in csv.DictReader(open(f))
                     if r["req_func"]==str(func) and r["clrt_ms"] and r["cold"]=="0"])
nR=clrt(f"{FIN}/csv/native_txn.csv",1); nS=clrt(f"{FIN}/csv/native_txn.csv",3)
dR=clrt(f"{FIN}/csv/defended_read_txn.csv",1); dS=clrt(f"{FIN}/csv/defended_txn.csv",3)
def stats(x): return dict(n=int(len(x)),median=float(np.median(x)),mean=float(np.mean(x)),std=float(np.std(x)),
                          p5=float(np.percentile(x,5)),p95=float(np.percentile(x,95)),p99=float(np.percentile(x,99)),
                          max=float(np.max(x)),n_over_12ms=int(np.sum(x>12.0)))
def boot_ci(x,fn=np.median,B=2000):
    rng=np.random.default_rng(42); bs=[fn(rng.choice(x,len(x))) for _ in range(B)]
    return [float(np.percentile(bs,2.5)),float(np.percentile(bs,97.5))]
def pdf(x): h,_=np.histogram(np.clip(x,BINS[0],BINS[-1]),bins=BINS); return h/h.sum() if h.sum() else h
def jsd(a,b): return float(jensenshannon(pdf(a)+1e-12,pdf(b)+1e-12,base=2))   # DISTANCE
def mi_common(a,b):
    va=np.digitize(np.clip(a,BINS[0],BINS[-1]),BINS); vb=np.digitize(np.clip(b,BINS[0],BINS[-1]),BINS)
    labs=np.concatenate([np.zeros(len(a)),np.ones(len(b))]); vals=np.concatenate([va,vb])
    mi=mutual_info_score(labs,vals)/np.log(2)
    rng=np.random.default_rng(3); null=[]
    for _ in range(1000):
        sl=rng.permutation(labs); null.append(mutual_info_score(sl,vals)/np.log(2))
    return float(mi), [float(np.percentile(null,2.5)),float(np.percentile(null,97.5))]
mi_nat,ci_nat=mi_common(nR,nS); mi_def,ci_def=mi_common(dR,dS)
res={"predeclared_CLRT_bins":"linspace(0,12,61) ms (common for JS + MI)",
 "clrt_stats":{"native_READ":stats(nR),"native_SELECT":stats(nS),"defended_READ":stats(dR),"defended_SELECT":stats(dS)},
 "bootstrap95_median":{"native_READ":boot_ci(nR),"native_SELECT":boot_ci(nS),"defended_READ":boot_ci(dR),"defended_SELECT":boot_ci(dS)},
 "JS_distance_note":"scipy.jensenshannon returns DISTANCE = sqrt(divergence); divergence = distance^2",
 "JS_distance":{"native_READ_vs_SELECT":jsd(nR,nS),"defended_READ_vs_SELECT":jsd(dR,dS),
                "native_vs_defended_READ":jsd(nR,dR),"native_vs_defended_SELECT":jsd(nS,dS)},
 "JS_divergence":{"native_vs_defended_READ":jsd(nR,dR)**2,"native_vs_defended_SELECT":jsd(nS,dS)**2},
 "MI_class_CLRT_bits_commonbins":{"native":mi_nat,"native_perm_null_ci":ci_nat,
                                  "defended":mi_def,"defended_perm_null_ci":ci_def}}
# E5 classifier -- READ vs SELECT transaction-class (NOT device); transaction-disjoint (not session-disjoint)
X=np.concatenate([nR,nS]).reshape(-1,1); y=np.array([0]*len(nR)+[1]*len(nS))
idx=np.random.default_rng(1).permutation(len(X)); tr=idx[:int(.6*len(idx))]; te=idx[int(.6*len(idx)):]
clf=LogisticRegression().fit(X[tr],y[tr])
nat_ba=balanced_accuracy_score(y[te],clf.predict(X[te]))
Xd=np.concatenate([dR,dS]).reshape(-1,1); yd=np.array([0]*len(dR)+[1]*len(dS))
def_ba=balanced_accuracy_score(yd,clf.predict(Xd))
def bci(X,y,B=1000):
    rng=np.random.default_rng(7); v=[balanced_accuracy_score(y[s],clf.predict(X[s])) for s in (rng.integers(0,len(y),len(y)) for _ in range(B))]
    return [float(np.percentile(v,2.5)),float(np.percentile(v,97.5))]
res["classifier"]={"task":"READ vs SELECT transaction-class (NOT device identity)",
 "feature":"CLRT (ms)","split":"transaction-disjoint 60/40; NOT session-disjoint (single capture session) -- limitation",
 "native_balanced_acc":float(nat_ba),"native_ba_ci":bci(X[te],y[te]),
 "defended_balanced_acc":float(def_ba),"defended_ba_ci":bci(Xd,yd),
 "balanced_acc_chance_baseline":0.5}
json.dump(res,open(f"{FIN}/verdict_stats.json","w"),indent=2)
print("JS_distance nat-vs-def READ=%.3f SELECT=%.3f | JS_divergence READ=%.3f SELECT=%.3f"%(
    res["JS_distance"]["native_vs_defended_READ"],res["JS_distance"]["native_vs_defended_SELECT"],
    res["JS_divergence"]["native_vs_defended_READ"],res["JS_divergence"]["native_vs_defended_SELECT"]))
print("MI(class;CLRT) common-bins: native=%.4f (null CI %.4f-%.4f) defended=%.4f (null CI %.4f-%.4f) bits"%(
    mi_nat,ci_nat[0],ci_nat[1],mi_def,ci_def[0],ci_def[1]))
print("classifier READ-vs-SELECT: native BA=%.3f defended BA=%.3f chance=0.5"%(nat_ba,def_ba))

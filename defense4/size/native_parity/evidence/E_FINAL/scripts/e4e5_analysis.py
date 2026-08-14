#!/usr/bin/env python3
import csv, json, numpy as np
from scipy.spatial.distance import jensenshannon
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import balanced_accuracy_score, f1_score
FIN="defense4/size/native_parity/evidence/E_FINAL"
def clrt(f, func):
    out=[]
    for r in csv.DictReader(open(f)):
        if r["req_func"]==str(func) and r["clrt_ms"] and r["cold"]=="0":
            out.append(float(r["clrt_ms"]))
    return np.array(out)
nR=clrt(f"{FIN}/csv/native_txn.csv",1);  nS=clrt(f"{FIN}/csv/native_txn.csv",3)
dR=clrt(f"{FIN}/csv/defended_read_txn.csv",1); dS=clrt(f"{FIN}/csv/defended_txn.csv",3)
def stats(x): 
    return dict(n=len(x),median=float(np.median(x)),mean=float(np.mean(x)),std=float(np.std(x)),
               p5=float(np.percentile(x,5)),p95=float(np.percentile(x,95)),p99=float(np.percentile(x,99)))
def boot_ci(x,fn=np.median,B=2000):
    rng=np.random.default_rng(42); bs=[fn(rng.choice(x,len(x))) for _ in range(B)]
    return [float(np.percentile(bs,2.5)),float(np.percentile(bs,97.5))]
def hist_pdf(x,bins): h,_=np.histogram(x,bins=bins,density=False); return h/ h.sum() if h.sum() else h
def js(a,b):
    lo=min(a.min(),b.min()); hi=max(a.max(),b.max()); bins=np.linspace(lo,hi,50)
    return float(jensenshannon(hist_pdf(a,bins)+1e-12,hist_pdf(b,bins)+1e-12,base=2))
def mi_class_clrt(clist):
    # MI between class label and discretized CLRT
    allv=np.concatenate([c for c in clist]); bins=np.linspace(allv.min(),allv.max(),20)
    labs=np.concatenate([[i]*len(c) for i,c in enumerate(clist)])
    vals=np.concatenate(clist); d=np.digitize(vals,bins)
    from sklearn.metrics import mutual_info_score
    return float(mutual_info_score(labs,d))
res={"clrt_stats":{"native_READ":stats(nR),"native_SELECT":stats(nS),"defended_READ":stats(dR),"defended_SELECT":stats(dS)},
     "bootstrap95_median":{"native_READ":boot_ci(nR),"native_SELECT":boot_ci(nS),"defended_READ":boot_ci(dR),"defended_SELECT":boot_ci(dS)},
     "JS_divergence":{"native_READ_vs_SELECT":js(nR,nS),"defended_READ_vs_SELECT":js(dR,dS),
                      "native_vs_defended_READ":js(nR,dR),"native_vs_defended_SELECT":js(nS,dS)},
     "MI_class_CLRT_bits":{"native":mi_class_clrt([nR,nS])/np.log(2),"defended":mi_class_clrt([dR,dS])/np.log(2)}}
# E5 classifier: train READ-vs-SELECT on NATIVE CLRT, transaction-disjoint, apply to DEFENDED
def split(x,frac=0.6):
    k=int(len(x)*frac); return x[:k],x[k:]
Xn=np.concatenate([nR,nS]).reshape(-1,1); yn=np.array([0]*len(nR)+[1]*len(nS))
idx=np.random.default_rng(1).permutation(len(Xn)); tr=idx[:int(.6*len(idx))]; te=idx[int(.6*len(idx)):]
clf=LogisticRegression().fit(Xn[tr],yn[tr])
nat_ba=balanced_accuracy_score(yn[te],clf.predict(Xn[te]))
Xd=np.concatenate([dR,dS]).reshape(-1,1); yd=np.array([0]*len(dR)+[1]*len(dS))
def_ba=balanced_accuracy_score(yd,clf.predict(Xd))
def boot_ba(X,y,B=1000):
    rng=np.random.default_rng(7); v=[]
    for _ in range(B):
        s=rng.integers(0,len(y),len(y))
        try: v.append(balanced_accuracy_score(y[s],clf.predict(X[s])))
        except: pass
    return [float(np.percentile(v,2.5)),float(np.percentile(v,97.5))]
res["classifier_READ_vs_SELECT"]={
    "trained_on":"native CLRT (transaction-disjoint 60/40)",
    "native_balanced_acc":float(nat_ba),"native_ba_ci":boot_ba(Xn[te],yn[te]),
    "defended_balanced_acc":float(def_ba),"defended_ba_ci":boot_ba(Xd,yd),
    "chance_balanced_acc":0.5,"majority_baseline":float(max(len(dR),len(dS))/(len(dR)+len(dS)))}
open(f"{FIN}/verdict_stats.json","w").write(json.dumps(res,indent=2))
print(json.dumps(res,indent=2))

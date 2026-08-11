import sys
from pathlib import Path
sys.path.insert(0, str(Path.home()/"Projects/Tooling/inkscape_python_figures"))
import numpy as np, matplotlib.pyplot as plt, matplotlib.patches as mp
try:
    import utils_mpl; utils_mpl.set_global()
except Exception as e:
    plt.rcParams.update({"font.size":9,"font.family":"serif","axes.grid":True,"grid.alpha":.3})
OUT=Path.home()/"Projects/DNP3_fixed_transcript/explainer/figures"
C={"sel":"#4C72B0","ion":"#DD8452","ab":"#55A868","norm":"#C44E52","box":"#EAEAF2","edge":"#333"}
dev=["SEL-751","ION7550","AB1400"]; col=[C["sel"],C["ion"],C["ab"]]

# ---- FIG 1: device-signature collapse (before vs after) ----
fig,(a0,a1)=plt.subplots(1,2,figsize=(7.16,2.5)); 
do_before=[11,6,7]; do_after=[6,6,6]; x=np.arange(3)
a0.bar(x,do_before,color=col,edgecolor=C["edge"]); a0.set_title("Before normalization",fontsize=9)
a0.set_ylabel("TCP data_offset"); a0.set_ylim(0,12); a0.set_xticks(x); a0.set_xticklabels(dev,fontsize=8)
opt=["MSS,SAckOK,TS,\nWScale (odd order)","MSS only","MSS,NOP,NOP,\nNOP,EOL"]
for i,(h,o) in enumerate(zip(do_before,opt)): a0.text(i,h+0.15,o,ha="center",va="bottom",fontsize=6.2)
a0.text(0.5,0.93,"3 distinct fingerprints",transform=a0.transAxes,ha="center",fontsize=8,style="italic",color=C["norm"])
a1.bar(x,do_after,color=col,edgecolor=C["edge"]); a1.set_title("After normalization (captured off the ASIC)",fontsize=9)
a1.set_ylim(0,12); a1.set_xticks(x); a1.set_xticklabels(dev,fontsize=8)
for i in range(3): a1.text(i,6.15,"MSS=1460\nwin=8192\nttl=64",ha="center",va="bottom",fontsize=6.2)
a1.text(0.5,0.93,"1 identical packet  (020405b4)",transform=a1.transAxes,ha="center",fontsize=8,weight="bold",color=C["ab"])
for a in (a0,a1): a.grid(axis="y",alpha=.3)
fig.tight_layout(); fig.savefig(OUT/"fig1_collapse.pdf",transparent=True); fig.savefig(OUT/"fig1_collapse.png",dpi=300); plt.close(fig)

# ---- FIG 2: axis scorecard ----
fig,ax=plt.subplots(figsize=(3.5,2.5))
axes=["Handshake header","CLRT magnitude","ACK-mode","READ size","READ segmentation","SBO count","SBO presence"]
stat=[1.0,1.0,1.0,0.5,0.2,0.5,0.0]  # 1 done, .5 partial, .2 early, 0 residual
lab=["byte-level on silicon","Defense 4","silicon 3/3","primitive built","not built","oracle built","class fingerprint"]
cmap={1.0:C["ab"],0.5:C["ion"],0.2:"#CFCFCF",0.0:C["norm"]}
y=np.arange(len(axes))[::-1]
ax.barh(y,[max(s,0.06) for s in stat],color=[cmap[s] for s in stat],edgecolor=C["edge"])
ax.set_yticks(y); ax.set_yticklabels(axes,fontsize=8); ax.set_xlim(0,1.0); ax.set_xticks([])
for yi,(s,l) in zip(y,zip(stat,lab)): ax.text(max(s,0.06)+0.02,yi,l,va="center",fontsize=6.6)
ax.set_title("Obfuscation axis scorecard",fontsize=9)
from matplotlib.patches import Patch
ax.legend(handles=[Patch(color=C["ab"],label="done (HW)"),Patch(color=C["ion"],label="partial"),Patch(color=C["norm"],label="residual")],
          fontsize=6.5,loc="lower right",framealpha=.9)
fig.tight_layout(); fig.savefig(OUT/"fig2_scorecard.pdf",transparent=True); fig.savefig(OUT/"fig2_scorecard.png",dpi=300); plt.close(fig)

# ---- FIG 3: Tofino pipeline schematic ----
fig,ax=plt.subplots(figsize=(7.16,2.3)); ax.set_xlim(0,100); ax.set_ylim(0,32); ax.axis("off")
def box(x,y,w,h,t,fc=C["box"],fs=7):
    ax.add_patch(mp.FancyBboxPatch((x,y),w,h,boxstyle="round,pad=0.3",fc=fc,ec=C["edge"],lw=1))
    ax.text(x+w/2,y+h/2,t,ha="center",va="center",fontsize=fs)
def arr(x0,y0,x1,y1): ax.annotate("",xy=(x1,y1),xytext=(x0,y0),arrowprops=dict(arrowstyle="-|>",color=C["edge"],lw=1.1))
box(1,12,15,9,"Parser\neth / IPv4 / TCP\n+ options (o0..e5)\ncopy total_len")
box(20,20,15,8,"t_exp\ndata_offset->len\n(payload==0)",C["sel"]+"55")
box(20,10,15,8,"t_clamp\nMSS range match\n(>1460)",C["ion"]+"55")
box(38,15,17,10,"classify\nSYN/SYN-ACK\npure-ACK / est.\n(1-bit flags)")
box(59,20,16,9,"t_norm -> canon\nstrip opts, MSS,\ndo=6, win=8192",C["ab"]+"66")
box(59,9,16,8,"drop_ctl\nsuppress pure ACK",C["norm"]+"55")
box(79,13,19,10,"Deparser\nIPv4 + TCP\nChecksum.update()\nemit")
arr(16,16,20,17); arr(35,20,38,20); arr(35,14,38,16); arr(55,20,59,24); arr(55,16,59,13); arr(75,24,79,20); arr(75,13,79,16)
ax.text(50,30.5,"Ingress pipeline (one program: handshake + ACK-mode)",ha="center",fontsize=8,weight="bold")
# harness note
ax.text(50,2.2,"Test harness: in-switch pktgen -> ingress (counters)  |  bf_kpkt CPU netdev 'ens1' loopback (byte capture)",
        ha="center",fontsize=6.3,style="italic",color=C["edge"])
fig.tight_layout(); fig.savefig(OUT/"fig3_pipeline.pdf",transparent=True); fig.savefig(OUT/"fig3_pipeline.png",dpi=300); plt.close(fig)
print("figures written:", [p.name for p in sorted(OUT.glob('*.pdf'))])

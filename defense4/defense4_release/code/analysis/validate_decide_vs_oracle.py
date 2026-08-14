#!/usr/bin/env python3
"""
Faithfulness check for UNIFIED12 change 1 (the risky lever): prove the two ternary decision
tables (tbl_decide_fresh / tbl_decide_deq, D4-only) reproduce the frozen RRC kernel's ACT
branch tree EXACTLY, as a (TM-effect, legacy-counter-slot) function over every reachable
per-packet state tuple. The frozen kernel (defense4_rrc_kernel.p4) is the behavioral oracle;
this transcribes its ACT if/else (restricted to the kept modes OFF and D4) and my decide
entries, then enumerates the state space and asserts equality.

Run: python3 validate_decide_vs_oracle.py   (exit 0 = FAITHFUL; nonzero = mismatch)
"""
import sys, itertools

# ---- constants (mirror the P4) ----
ROLE_BYPASS,ROLE_BLOCK,ROLE_RESP,ROLE_RESP_UNSUP,ROLE_ARM,ROLE_ACK,ROLE_CLONE = 0,1,2,3,6,7,8
CLASS_OTHER,CLASS_ARM,CLASS_ACK,CLASS_BLOCK_DEQ,CLASS_RESP,CLASS_ACK_REL = 0,1,2,3,4,5
V_NONE,V_ARM_FRESH,V_ARM_DUP,V_ARM_BUSY,V_ACK_ARM,V_ACK_REJECT,V_BLOCK_LIVE,V_RESP,V_RESP_BYPASS,V_BLOCK_PENDING = range(10)
MODE_OFF,MODE_D4 = 0,4

# TM effects
DROP,FWD,FWDCLONE,SHAPE,BLK7,RBLK5,HOLD6,RHOLD4 = 'DROP','FWD','FWDCLONE','SHAPE','BLK7','RBLK5','HOLD6','RHOLD4'
# legacy counter slots (names only, for equality)

# ---------- ORACLE: the frozen ACT tree, D4-only-relevant (mode in {OFF,D4}) ----------
def oracle(s):
    d=s; 
    if d['dequeued']==0:
        role=s['role']; pc=s['pkt_class']; v=s['verdict']; ta=s['txn_active']
        mode=s['mode']; isp=s['is_pktgen']; slot=s['pgen_slot']; af=s['ack_first']
        td=s['tag_diff']; dsh=s['do_shape']
        if role==ROLE_CLONE: return (DROP,'CF_CLONE_SEEN')
        if role==ROLE_BLOCK:
            if isp==1:
                if ta==1 and slot==0: return (DROP,'CF_PKTGEN_DROP')   # invalid id
                if ta==1 and slot==1: return (BLK7,'CF_PKTGEN_ADMIT')  # ack
                if ta==1 and slot==2: return (RBLK5,'CF_PKTGEN_ADMIT') # resp
                return (DROP,'CF_PKTGEN_DROP')                          # no active txn
            else:
                return (DROP,'CF_BLOCK_REJECT')
        if pc==CLASS_RESP:
            if v==V_RESP and ta==1 and mode==MODE_OFF: return (FWD,'CF_RESP_HOLD_EARLY')
            if v==V_RESP and ta==1:
                return (RHOLD4, 'CF_RESP_HOLD_LATE' if td==0 else 'CF_RESP_HOLD_EARLY')
            if v==V_RESP and ta==2: return (DROP,'CF_RESP_DUP_SUPP')
            return (SHAPE if dsh==1 else FWD, 'CF_RESP_BYPASS')
        if pc==CLASS_ACK:
            if v==V_ACK_ARM and mode==MODE_OFF: return (FWD,'CF_ACK_REJECT')
            if v==V_ACK_ARM:
                return (HOLD6, 'CF_ACK_HOLD' if af==1 else 'CF_ACK_DUP_HOLD')
            return (FWD,'CF_ACK_REJECT')
        if pc==CLASS_ARM:
            if v==V_ARM_FRESH and mode!=MODE_OFF: return (FWDCLONE,'CF_ARM_FRESH')
            if v==V_ARM_DUP: return (FWD,'CF_ARM_DUP')
            return (FWD,'CF_ARM_BUSY')   # busy, or OFF+fresh
        if role==ROLE_RESP_UNSUP: return (FWD,'CF_UNSUP_SEG')
        return (FWD,'CF_BYPASS_FWD')     # ROLE_BYPASS
    else:
        role=s['role']; rb=s['is_resp_blk']; v=s['verdict']
        exp=s['expired']; expr=s['expired_resp']; bz=s['budget_zero']; dsh=s['do_shape']
        if role==ROLE_BLOCK and rb==1:
            if v not in (V_BLOCK_LIVE,V_BLOCK_PENDING): return (DROP,'CD_BLOCK_TERM_STALE')
            if v==V_BLOCK_PENDING and expr==1: return (DROP,'CD_BLOCK_TERM_DL')
            if bz==1: return (DROP,'CD_BLOCK_TERM_TMO')
            return (RBLK5,'CD_BLOCK_LOOP')
        if role==ROLE_BLOCK:
            if v not in (V_BLOCK_LIVE,V_BLOCK_PENDING): return (DROP,'CD_BLOCK_TERM_STALE')
            # D4: no D1 branch; expired -> DL, budget -> TMO, else loop
            if exp==1: return (DROP,'CD_BLOCK_TERM_DL')
            if bz==1: return (DROP,'CD_BLOCK_TERM_TMO')
            return (BLK7,'CD_BLOCK_LOOP')
        if role==ROLE_ACK:
            # D4 always preserves -> release (never the D1/D3 retire)
            return (FWD,'CD_ACK_RELEASE')
        if role==ROLE_RESP:
            if expr==1: return (SHAPE if dsh==1 else FWD,'CD_RELEASE_DEADLINE')
            return (SHAPE if dsh==1 else FWD,'CD_RELEASE_FAILOPEN')
        return (DROP,'CD_DEQ_DROP')

# ---------- MY DECIDE TABLES: OUT_* -> (tm, slot) ----------
OUT = {  # value: (tm, legacy_slot)
 'BADPORT':(DROP,'CF_BAD_PORT'),'CLONE':(DROP,'CF_CLONE_SEEN'),'PKTGEN_DROP':(DROP,'CF_PKTGEN_DROP'),
 'ADMIT_ACK':(BLK7,'CF_PKTGEN_ADMIT'),'ADMIT_RESP':(RBLK5,'CF_PKTGEN_ADMIT'),'BLOCK_REJECT':(DROP,'CF_BLOCK_REJECT'),
 'RESP_OFF_FWD':(FWD,'CF_RESP_HOLD_EARLY'),'RESP_HOLD_LATE':(RHOLD4,'CF_RESP_HOLD_LATE'),
 'RESP_HOLD_EARLY':(RHOLD4,'CF_RESP_HOLD_EARLY'),'RESP_DUP_SUPP':(DROP,'CF_RESP_DUP_SUPP'),
 'RESP_BYPASS_FWD':(FWD,'CF_RESP_BYPASS'),'RESP_BYPASS_SHAPE':(SHAPE,'CF_RESP_BYPASS'),
 'ACK_REJECT':(FWD,'CF_ACK_REJECT'),'ACK_HOLD':(HOLD6,'CF_ACK_HOLD'),'ACK_DUP_HOLD':(HOLD6,'CF_ACK_DUP_HOLD'),
 'ARM_FRESH':(FWDCLONE,'CF_ARM_FRESH'),'ARM_DUP':(FWD,'CF_ARM_DUP'),'ARM_BUSY':(FWD,'CF_ARM_BUSY'),
 'UNSUP':(FWD,'CF_UNSUP_SEG'),'BYPASS':(FWD,'CF_BYPASS_FWD'),
 'RB_STALE':(DROP,'CD_BLOCK_TERM_STALE'),'RB_DL':(DROP,'CD_BLOCK_TERM_DL'),'RB_TMO':(DROP,'CD_BLOCK_TERM_TMO'),
 'RB_LOOP':(RBLK5,'CD_BLOCK_LOOP'),'AB_STALE':(DROP,'CD_BLOCK_TERM_STALE'),'AB_DL':(DROP,'CD_BLOCK_TERM_DL'),
 'AB_TMO':(DROP,'CD_BLOCK_TERM_TMO'),'AB_LOOP':(BLK7,'CD_BLOCK_LOOP'),
 'ACK_RELEASE':(FWD,'CD_ACK_RELEASE'),'REL_DL_FWD':(FWD,'CD_RELEASE_DEADLINE'),'REL_DL_SHAPE':(SHAPE,'CD_RELEASE_DEADLINE'),
 'REL_FO_FWD':(FWD,'CD_RELEASE_FAILOPEN'),'REL_FO_SHAPE':(SHAPE,'CD_RELEASE_FAILOPEN'),'DEQ_DROP':(DROP,'CD_DEQ_DROP'),
}
def W(v,m): return (v is None) or (v==m)   # wildcard helper: entry field None = don't care

# tbl_decide_fresh entries in PRIORITY order: (role,pc,verdict,ta,isp,mode,slot,af,tag_diff_zero,do_shape) -> OUT
FRESH=[
 ((ROLE_CLONE,None,None,None,None,None,None,None,None,None),'CLONE'),
 ((ROLE_BLOCK,None,None,1,1,None,1,None,None,None),'ADMIT_ACK'),
 ((ROLE_BLOCK,None,None,1,1,None,2,None,None,None),'ADMIT_RESP'),
 ((ROLE_BLOCK,None,None,1,1,None,0,None,None,None),'PKTGEN_DROP'),
 ((ROLE_BLOCK,None,None,None,1,None,None,None,None,None),'PKTGEN_DROP'),
 ((ROLE_BLOCK,None,None,None,0,None,None,None,None,None),'BLOCK_REJECT'),
 ((None,CLASS_RESP,V_RESP,1,None,MODE_OFF,None,None,None,None),'RESP_OFF_FWD'),
 ((None,CLASS_RESP,V_RESP,1,None,None,None,None,'ZERO',None),'RESP_HOLD_LATE'),
 ((None,CLASS_RESP,V_RESP,1,None,None,None,None,None,None),'RESP_HOLD_EARLY'),
 ((None,CLASS_RESP,V_RESP,2,None,None,None,None,None,None),'RESP_DUP_SUPP'),
 ((None,CLASS_RESP,None,None,None,None,None,None,None,1),'RESP_BYPASS_SHAPE'),
 ((None,CLASS_RESP,None,None,None,None,None,None,None,None),'RESP_BYPASS_FWD'),
 ((None,CLASS_ACK,V_ACK_ARM,None,None,MODE_OFF,None,None,None,None),'ACK_REJECT'),
 ((None,CLASS_ACK,V_ACK_ARM,None,None,None,None,1,None,None),'ACK_HOLD'),
 ((None,CLASS_ACK,V_ACK_ARM,None,None,None,None,0,None,None),'ACK_DUP_HOLD'),
 ((None,CLASS_ACK,None,None,None,None,None,None,None,None),'ACK_REJECT'),
 ((None,CLASS_ARM,V_ARM_FRESH,None,None,MODE_D4,None,None,None,None),'ARM_FRESH'),
 ((None,CLASS_ARM,V_ARM_FRESH,None,None,MODE_OFF,None,None,None,None),'ARM_BUSY'),
 ((None,CLASS_ARM,V_ARM_DUP,None,None,None,None,None,None,None),'ARM_DUP'),
 ((None,CLASS_ARM,None,None,None,None,None,None,None,None),'ARM_BUSY'),
 ((ROLE_RESP_UNSUP,None,None,None,None,None,None,None,None,None),'UNSUP'),
]
FRESH_DEFAULT='BYPASS'
# tbl_decide_deq: (role,rb,verdict,expired,expired_resp,budget_zero,do_shape) -> OUT
DEQ=[
 ((ROLE_BLOCK,1,V_BLOCK_PENDING,None,1,None,None),'RB_DL'),
 ((ROLE_BLOCK,1,V_BLOCK_PENDING,None,None,1,None),'RB_TMO'),
 ((ROLE_BLOCK,1,V_BLOCK_PENDING,None,None,None,None),'RB_LOOP'),
 ((ROLE_BLOCK,1,V_BLOCK_LIVE,None,None,1,None),'RB_TMO'),
 ((ROLE_BLOCK,1,V_BLOCK_LIVE,None,None,None,None),'RB_LOOP'),
 ((ROLE_BLOCK,1,None,None,None,None,None),'RB_STALE'),
 ((ROLE_BLOCK,0,V_BLOCK_PENDING,1,None,None,None),'AB_DL'),
 ((ROLE_BLOCK,0,V_BLOCK_PENDING,None,None,1,None),'AB_TMO'),
 ((ROLE_BLOCK,0,V_BLOCK_PENDING,None,None,None,None),'AB_LOOP'),
 ((ROLE_BLOCK,0,V_BLOCK_LIVE,1,None,None,None),'AB_DL'),
 ((ROLE_BLOCK,0,V_BLOCK_LIVE,None,None,1,None),'AB_TMO'),
 ((ROLE_BLOCK,0,V_BLOCK_LIVE,None,None,None,None),'AB_LOOP'),
 ((ROLE_BLOCK,0,None,None,None,None,None),'AB_STALE'),
 ((ROLE_ACK,None,None,None,None,None,None),'ACK_RELEASE'),
 ((ROLE_RESP,None,None,None,1,None,1),'REL_DL_SHAPE'),
 ((ROLE_RESP,None,None,None,1,None,None),'REL_DL_FWD'),
 ((ROLE_RESP,None,None,None,None,None,1),'REL_FO_SHAPE'),
 ((ROLE_RESP,None,None,None,None,None,None),'REL_FO_FWD'),
]
DEQ_DEFAULT='DEQ_DROP'

def match_fresh(s):
    key=(s['role'],s['pkt_class'],s['verdict'],s['txn_active'],s['is_pktgen'],s['mode'],
         s['pgen_slot'],s['ack_first'],('ZERO' if s['tag_diff']==0 else 'NZ'),s['do_shape'])
    for pat,out in FRESH:
        ok=True
        for i,p in enumerate(pat):
            if p is None: continue
            if i==8:  # tag_diff-zero field encoded as 'ZERO'
                if p=='ZERO' and key[8]!='ZERO': ok=False;break
            elif key[i]!=p: ok=False;break
        if ok: return out
    return FRESH_DEFAULT

def match_deq(s):
    key=(s['role'],s['is_resp_blk'],s['verdict'],s['expired'],s['expired_resp'],s['budget_zero'],s['do_shape'])
    for pat,out in DEQ:
        ok=all(p is None or key[i]==p for i,p in enumerate(pat))
        if ok: return out
    return DEQ_DEFAULT

# ---------- enumerate ----------
roles=[ROLE_BYPASS,ROLE_BLOCK,ROLE_RESP,ROLE_RESP_UNSUP,ROLE_ARM,ROLE_ACK,ROLE_CLONE]
pcs=[CLASS_OTHER,CLASS_ARM,CLASS_ACK,CLASS_RESP]
verds=list(range(10))
mism=0; checked=0; samples=[]
for dq in (0,1):
  for role in roles:
   for pc in pcs:
    for v in verds:
     for ta in (0,1,2):
      for isp in (0,1):
       for rb in (0,1):
        for mode in (MODE_OFF,MODE_D4):
         for exp in (0,1):
          for expr in (0,1):
           for bz in (0,1):
            for slot in (0,1,2):
             for af in (0,1):
              for td in (0,1):
               for dsh in (0,1):
                s=dict(dequeued=dq,role=role,pkt_class=pc,verdict=v,txn_active=ta,is_pktgen=isp,
                       is_resp_blk=rb,mode=mode,expired=exp,expired_resp=expr,budget_zero=bz,
                       pgen_slot=slot,ack_first=af,tag_diff=td,do_shape=dsh)
                o_tm=oracle(s)
                out = match_fresh(s) if dq==0 else match_deq(s)
                m_tm=OUT[out]
                checked+=1
                if o_tm!=m_tm:
                    mism+=1
                    if len(samples)<15: samples.append((s,o_tm,m_tm,out))
print(f"enumerated {checked} state tuples")
if mism==0:
    print("FAITHFUL: decision tables reproduce the frozen ACT oracle on EVERY reachable tuple (D4/OFF).")
    sys.exit(0)
else:
    print(f"MISMATCH on {mism} tuples. First samples (state -> oracle vs mine[OUT]):")
    for s,o,m,out in samples:
        rel={k:v for k,v in s.items() if k in ('dequeued','role','pkt_class','verdict','txn_active','is_pktgen','is_resp_blk','mode','expired','expired_resp','budget_zero','pgen_slot','ack_first','tag_diff','do_shape')}
        print(f"  {rel}\n     oracle={o}  mine={m} ({out})")
    sys.exit(1)

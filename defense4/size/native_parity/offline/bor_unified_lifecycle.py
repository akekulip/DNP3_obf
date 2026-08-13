#!/usr/bin/env python3
"""
Single-pipe BOR lifecycle model for defense4_rrc_bor_unified12.p4 (-DU_BOR), with a mutation
suite. Models the register semantics as written in the P4 (reg_bor_epoch self-allocating,
reg_bor_ready, reg_bor_gen, reg_bor_topj) and the bor_pc dispatch, over an event stream, with a
byte-level relay_rx ground truth. Each invariant test asserts a property of the OPERATE lifecycle;
each mutant deliberately breaks ONE invariant and MUST flip the corresponding assertion (non-vacuity).

Run: python3 bor_unified_lifecycle.py   (exit 0 = clean model 100% + all mutants killed).
"""
import sys

EPOCH_NONE=0; GEN_INACTIVE=0
class Switch:
    def __init__(self, mut=None):
        self.mut=mut or set()
        self.epoch=0; self.ready=0; self.gen=0; self.topj=None   # registers
        self.qid3=[]      # OP blocker reservoir tokens (epoch stamped)
        self.qid2=None    # held OPERATE (byte payload, gen, t0, j)
        self.relay_rx=[]  # ground-truth frames the relay receives (byte-level)
        self.commits=0    # count of terminal commits this packet (must be exactly 1)
        self.now=0

    # SELECT: allocate epoch, seed qid3, forward SELECT to relay byte-identically
    def select(self, payload):
        self.commits=0
        self.epoch = self.epoch+1
        if self.epoch==256: self.epoch=1
        self.ready=0; self.gen=0
        # seed qid3 for THIS epoch (K tokens), stamped with the epoch (NOT the DNP3 gen)
        self.qid3 = [self.epoch]*4
        # residency confirm: a live token stamps reg_ready := epoch (BEFORE the OPERATE)
        if self.qid3 and self.qid3[0]==self.epoch and 'ready_without_reservoir' not in self.mut:
            self.ready = self.epoch
        self.relay_rx.append(('SELECT', payload)); self.commits+=1
        return self.commits

    # OPERATE: match epoch + residency, dedup gen, hold in qid2 (arm T0+J), else fail-open forward
    def operate(self, payload, gen, t0, j):
        self.commits=0
        op_matched = 1 if self.epoch!=EPOCH_NONE else 0
        op_ready   = 1 if (self.ready==self.epoch and self.epoch!=EPOCH_NONE) else 0
        # gen dedup
        if self.gen==GEN_INACTIVE: verdict='FRESH'; self.gen=gen
        elif self.gen==gen:        verdict='DUP'
        else:                      verdict='BUSY'
        hold_ok = 1 if (op_matched and op_ready) else 0
        if verdict=='DUP' and 'retransmit_releases_second_copy' not in self.mut:
            # exactly-once: retransmit while held -> drop
            self.commits+=1; return ('DROP_DUP', self.commits)
        if verdict=='FRESH' and hold_ok:
            # HOLD in qid2, arm T0+J. The held frame is the byte-identical original.
            self.qid2 = dict(payload=payload, gen=gen, t0=t0, j=j)
            self.topj = t0 + j
            if 'early_qid2_release' in self.mut:
                # BUG: escape before qid3 drains -> forward now AND leave qid2 armed, so the
                # normal T0+J drain releases a SECOND copy (breaks exactly-once at the relay).
                self.relay_rx.append(('OPERATE', payload))
            self.commits+=1; return ('HOLD', self.commits)
        else:
            # fail-open WITHOUT holding: forward once to relay
            self.relay_rx.append(('OPERATE', payload)); self.commits+=1
            return ('FAILOPEN', self.commits)

    # advance the qid3 reservoir; when T0+J is reached, release the held OPERATE ONCE
    def tick_release(self):
        self.commits=0
        if self.qid2 is None: return ('IDLE',0)
        if self.now >= self.topj:
            pay=self.qid2['payload']
            self.relay_rx.append(('OPERATE', pay))
            if 'duplicate_release' in self.mut:
                self.relay_rx.append(('OPERATE', pay))  # BUG: two copies
            if 'source_copy_leaks_to_relay' in self.mut:
                self.relay_rx.append(('OPERATE_SRC', pay))  # BUG: source copy leaks
            self.qid2=None
            # retire epoch domain (the missing retire IS the stale-ready bug)
            if 'stale_ready_after_seq_wrap' not in self.mut:
                self.epoch=EPOCH_NONE; self.ready=0; self.gen=GEN_INACTIVE
            self.commits+=1; return ('RELEASE', self.commits)
        return ('HELD',0)

# qid3 token touching RRC state? In the real P4 the bor_pc gate keeps qid3 -> reg_bor_* only.
# Model the separation: a token NEVER writes reg_tag-equivalent (here: the RRC 'failopen' shadow).
class Domain:
    def __init__(self, mut): self.mut=mut; self.rrc_failopen=0
    def qid3_token(self, sw, tok_epoch):
        if 'qid3_touches_rrc_failopen' in self.mut:
            self.rrc_failopen += 1  # BUG: OP token perturbs RRC domain
        # correct: only touch reg_bor_ready/epoch (already handled in Switch)

def run(mut=None):
    mut=set(mut or [])
    sw=Switch(mut); dom=Domain(mut)
    res={}
    # ---- clean SBO: SELECT -> OPERATE(first) -> release at T0+J ----
    sw.now=0
    sw.select(b'SEL')
    res['residency_before_operate'] = (sw.ready==sw.epoch and sw.epoch!=0)
    # a qid3 token loops (does NOT touch RRC domain)
    dom.qid3_token(sw, sw.epoch)
    r1=sw.operate(b'OP1', gen=5, t0=1000, j=6)
    res['first_operate_held'] = (r1[0]=='HOLD')
    res['operate_commit_exactly_once'] = (r1[1]==1)
    # retransmit while held -> drop (exactly-once)
    r2=sw.operate(b'OP1', gen=5, t0=1000, j=6)
    res['retransmit_dropped'] = (r2[0]=='DROP_DUP')
    # release at T0+J
    sw.now=1006
    rr=sw.tick_release()
    res['released_at_T0_plus_J'] = (rr[0]=='RELEASE')
    res['relay_gets_operate_once'] = (sum(1 for f in sw.relay_rx if f[0]=='OPERATE')==1)
    res['no_source_copy'] = (not any(f[0]=='OPERATE_SRC' for f in sw.relay_rx))
    res['byte_identical_release'] = (('OPERATE', b'OP1') in sw.relay_rx)
    res['rrc_domain_untouched_by_qid3'] = (dom.rrc_failopen==0)
    # ---- sequence wrap: a stray OPERATE after retire must fail open (epoch retired = 0) ----
    r3=sw.operate(b'OP2', gen=5, t0=2000, j=6)   # no fresh SELECT
    res['stray_operate_fails_open'] = (r3[0]=='FAILOPEN')
    return res

# expected clean model
CLEAN_EXPECT = {k:True for k in
  ['residency_before_operate','first_operate_held','operate_commit_exactly_once','retransmit_dropped',
   'released_at_T0_plus_J','relay_gets_operate_once','no_source_copy','byte_identical_release',
   'rrc_domain_untouched_by_qid3','stray_operate_fails_open']}

MUTANTS = {
 'retransmit_releases_second_copy':'retransmit_dropped',
 'duplicate_release':'relay_gets_operate_once',
 'source_copy_leaks_to_relay':'no_source_copy',
 'qid3_touches_rrc_failopen':'rrc_domain_untouched_by_qid3',
 'early_qid2_release':'relay_gets_operate_once',   # early release -> two OPERATE frames at relay
 'stale_ready_after_seq_wrap':'stray_operate_fails_open',
 'ready_without_reservoir':'first_operate_held',    # no residency -> first OPERATE fails open
}

def main():
    clean=run()
    ok = (clean==CLEAN_EXPECT)
    print(f"CLEAN model: {sum(clean.values())}/{len(clean)} invariants hold ->", "PASS" if ok else "FAIL")
    if not ok:
        for k in clean:
            if clean[k]!=CLEAN_EXPECT[k]: print(f"   FAIL {k}: got {clean[k]}")
    killed=0; total=0
    for m,target in MUTANTS.items():
        total+=1
        r=run([m])
        broke = (r.get(target) != CLEAN_EXPECT[target])
        print(f"  mutant {m:34s} -> target invariant '{target}': {'KILLED' if broke else 'SURVIVED (non-vacuity FAIL)'}")
        if broke: killed+=1
    print(f"mutants killed: {killed}/{total}")
    sys.exit(0 if (ok and killed==total) else 1)

main()

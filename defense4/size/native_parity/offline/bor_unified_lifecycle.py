#!/usr/bin/env python3
"""
Single-pipe BOR lifecycle model for defense4_rrc_bor_unified12.p4 (-DU_BOR), with a mutation
suite. Models the register semantics AS WRITTEN in the corrected P4 (reg_bor_epoch self-allocating,
reg_bor_ready, reg_bor_gen, reg_bor_topj) and the bor_pc dispatch, over an event stream, with a
byte-level relay_rx / master_rx ground truth. Each invariant test asserts a property of the OPERATE
lifecycle; each mutant deliberately breaks ONE invariant and MUST flip the corresponding assertion
(non-vacuity).

This version adds the four corrections proven by the 2026-08-13 implementation-correction pass:
  * blocker 2 : a HELD OPERATE seeds the ACK (qid7) and RESPONSE (qid5) reservoirs, so the relay
                ACK and 49B echo are SUBJECT to the blocker path (held), not escaping unshaped.
  * blocker 3 : the ACK and echo deadlines are T0-ANCHORED (T0+A, T0+R), NOT re-anchored to the
                relay ACK's arrival. echo_release - ack_release == R - A, independent of J
                (the anti-subtraction invariant).
  * blocker 5 : reg_bor_gen is KEPT at release (spent marker), so a post-release retransmit of the
                SAME OPERATE is dropped (exactly-once survives PAST release).
  * blocker 4 : the qid2/qid3 BOR classes never perturb the RRC failopen/tag domain (modelled by
                the Domain shadow; the qid3_touches_rrc_failopen mutant stays killed).

Run: python3 bor_unified_lifecycle.py   (exit 0 = clean model 100% + all mutants killed).
"""
import sys

EPOCH_NONE = 0
GEN_INACTIVE = 0


class Switch:
    def __init__(self, mut=None):
        self.mut = mut or set()
        # registers
        self.epoch = 0
        self.ready = 0
        self.gen = 0
        self.topj = None
        self.ack_deadline = None      # reg_deadline for the OPERATE = T0 + A
        self.echo_deadline = None     # reg_tresp   for the OPERATE = T0 + R
        # reservoirs
        self.qid3 = []                # OP blocker reservoir (epoch stamped)
        self.ack_resv = []            # qid7 ACK blocker reservoir (seeded at OPERATE hold)
        self.resp_resv = []           # qid5 RESP blocker reservoir (seeded at OPERATE hold)
        # held originals / anchoring
        self.qid2 = None              # held OPERATE (payload, gen, t0, j)
        self.t0 = None                # the anchoring OPERATE ingress time
        # ground truth
        self.relay_rx = []            # frames the relay receives (downstream)
        self.master_rx = []           # frames the master receives back (ACK, echo) with release time
        self.ack_release_time = None
        self.echo_release_time = None
        self.commits = 0
        self.now = 0

    # ---- SELECT: allocate epoch, pre-seed qid3, confirm residency BEFORE the OPERATE ----
    def select(self, payload):
        self.commits = 0
        self.epoch = self.epoch + 1
        if self.epoch == 256:
            self.epoch = 1
        self.ready = 0
        self.gen = 0                                  # BPC_PREPARE clears reg_bor_gen
        self.qid3 = [self.epoch] * 4                  # seed qid3 for THIS epoch
        if self.qid3 and self.qid3[0] == self.epoch and 'ready_without_reservoir' not in self.mut:
            self.ready = self.epoch                   # a live qid3 token stamps reg_ready := epoch
        self.relay_rx.append(('SELECT', payload))
        self.commits += 1
        return self.commits

    # ---- OPERATE: match epoch + residency, dedup gen, hold in qid2 (arm T0+J, T0+A, T0+R) ----
    def operate(self, payload, gen, t0, j, a, r):
        self.commits = 0
        op_matched = 1 if self.epoch != EPOCH_NONE else 0
        op_ready = 1 if (self.ready == self.epoch and self.epoch != EPOCH_NONE) else 0
        # gen dedup (reg_bor_gen): FRESH iff inactive; DUP iff equal (held OR spent); else BUSY
        if self.gen == GEN_INACTIVE:
            verdict = 'FRESH'
        elif self.gen == gen:
            verdict = 'DUP'
        else:
            verdict = 'BUSY'
        hold_ok = 1 if (op_matched and op_ready) else 0
        if verdict == 'DUP' and 'retransmit_releases_second_copy' not in self.mut:
            # exactly-once: retransmit while held OR after release (spent gen) -> drop
            self.commits += 1
            return ('DROP_DUP', self.commits)
        if verdict == 'FRESH' and hold_ok:
            # HOLD the original in qid2; arm all THREE deadlines anchored to THIS OPERATE's T0
            self.qid2 = dict(payload=payload, gen=gen, t0=t0, j=j, a=a, r=r)
            self.gen = gen                            # gen_arm stores the held generation
            self.t0 = t0
            self.topj = t0 + j
            # blocker 3: T0-anchored ACK/echo deadlines (unless the ACK-relative mutant defers them)
            if 'ack_relative_deadlines' not in self.mut:
                self.ack_deadline = t0 + a
                self.echo_deadline = t0 + r
            # blocker 2: seed the ACK + RESP reservoirs so the relay ACK/echo are held
            if 'operate_no_seed' not in self.mut:
                self.ack_resv = [gen] * 4
                self.resp_resv = [gen] * 4
            if 'early_qid2_release' in self.mut:
                # BUG: forward now AND leave qid2 armed -> the T0+J drain releases a SECOND copy
                self.relay_rx.append(('OPERATE', payload))
            self.commits += 1
            return ('HOLD', self.commits)
        # fail-open WITHOUT holding: forward once to relay
        self.relay_rx.append(('OPERATE', payload))
        self.commits += 1
        return ('FAILOPEN', self.commits)

    # ---- qid3 drains at T0+J: release the held OPERATE ONCE to the relay ----
    def tick_release(self):
        self.commits = 0
        if self.qid2 is None:
            return ('IDLE', 0)
        if self.now >= self.topj:
            pay = self.qid2['payload']
            self.relay_rx.append(('OPERATE', pay))
            if 'duplicate_release' in self.mut:
                self.relay_rx.append(('OPERATE', pay))
            if 'source_copy_leaks_to_relay' in self.mut:
                self.relay_rx.append(('OPERATE_SRC', pay))
            self.qid2 = None
            # retire the BOR epoch domain: epoch + ready cleared; gen KEPT as a spent marker
            if 'stale_ready_after_seq_wrap' not in self.mut:
                self.epoch = EPOCH_NONE
                self.ready = 0
            # blocker 5: KEEP reg_bor_gen (spent) so a post-release retransmit is suppressed
            if 'clear_gen_at_release' in self.mut:
                self.gen = GEN_INACTIVE           # BUG: forgets the spent generation
            self.commits += 1
            return ('RELEASE', self.commits)
        return ('HELD', 0)

    # ---- relay ACK arrives (after the OPERATE released): held to T0+A, released to master ----
    def relay_ack(self, arrival):
        if not self.ack_resv:
            # reservoir empty -> ACK escapes immediately, UNSHAPED (blocker 2 failure)
            self.ack_release_time = arrival
            self.master_rx.append(('ACK', arrival, 'ESCAPE'))
            return ('ESCAPE', arrival)
        if 'ack_relative_deadlines' in self.mut:
            self.ack_deadline = arrival + self.qid2_meta('a')   # BUG: re-anchor to arrival
        # held behind the qid7 reservoir until the (T0-anchored) deadline
        self.ack_release_time = self.ack_deadline
        self.master_rx.append(('ACK', self.ack_deadline, 'HELD'))
        return ('HELD', self.ack_deadline)

    # ---- relay echo (49B OPERATE echo) arrives: held to T0+R, released to master ----
    def relay_echo(self, arrival):
        if not self.resp_resv:
            self.echo_release_time = arrival
            self.master_rx.append(('ECHO', arrival, 'ESCAPE'))
            return ('ESCAPE', arrival)
        if 'ack_relative_deadlines' in self.mut:
            self.echo_deadline = arrival + self.qid2_meta('r')  # BUG: re-anchor to arrival
        self.echo_release_time = self.echo_deadline
        self.master_rx.append(('ECHO', self.echo_deadline, 'HELD'))
        return ('HELD', self.echo_deadline)

    # A/R totals for the last held OPERATE (retained for the re-anchor mutant math)
    def qid2_meta(self, k):
        return self._last_ar.get(k, 0)


# qid3 token touching RRC state? In the corrected P4 the (bor_pc <= BPC_OPERATE) guard keeps the
# qid2/qid3 classes OFF reg_tag/reg_failopen entirely. Model the separation as a shadow.
class Domain:
    def __init__(self, mut):
        self.mut = mut
        self.rrc_failopen = 0

    def qid3_token(self, sw, tok_epoch):
        if 'qid3_touches_rrc_failopen' in self.mut:
            self.rrc_failopen += 1   # BUG: OP token perturbs the RRC failopen domain


def run(mut=None):
    mut = set(mut or [])
    sw = Switch(mut)
    dom = Domain(mut)
    res = {}
    A, R, J = 20, 24, 6
    T0 = 1000
    sw._last_ar = {'a': A, 'r': R}

    # ---- clean SBO: SELECT -> OPERATE(first) -> release@T0+J -> ACK@T0+A -> echo@T0+R ----
    sw.now = 0
    sw.select(b'SEL')
    res['residency_before_operate'] = (sw.ready == sw.epoch and sw.epoch != 0)
    dom.qid3_token(sw, sw.epoch)                      # a qid3 token loops (does NOT touch RRC)

    r1 = sw.operate(b'OP1', gen=5, t0=T0, j=J, a=A, r=R)
    res['first_operate_held'] = (r1[0] == 'HOLD')
    res['operate_commit_exactly_once'] = (r1[1] == 1)
    # blocker 2: the ACK + RESP reservoirs are seeded by the OPERATE hold
    res['operate_ack_reservoir_seeded'] = (len(sw.ack_resv) > 0 and len(sw.resp_resv) > 0)

    # retransmit WHILE held -> drop (exactly-once)
    r2 = sw.operate(b'OP1', gen=5, t0=T0, j=J, a=A, r=R)
    res['retransmit_dropped'] = (r2[0] == 'DROP_DUP')

    # release the held OPERATE at T0+J
    sw.now = T0 + J
    rr = sw.tick_release()
    res['released_at_T0_plus_J'] = (rr[0] == 'RELEASE')
    res['relay_gets_operate_once'] = (sum(1 for f in sw.relay_rx if f[0] == 'OPERATE') == 1)
    res['no_source_copy'] = (not any(f[0] == 'OPERATE_SRC' for f in sw.relay_rx))
    res['byte_identical_release'] = (('OPERATE', b'OP1') in sw.relay_rx)
    res['rrc_domain_untouched_by_qid3'] = (dom.rrc_failopen == 0)
    res['ready_cleared_at_release'] = (sw.ready == 0)

    # relay ACK arrives after the OPERATE was released (~T0+J+native), held to T0+A
    ack_arrival = T0 + J + 2
    sw.relay_ack(ack_arrival)
    # blocker 2: the ACK was HELD (subject to the blocker path), not escaping at arrival
    res['ack_echo_subject_to_blocker'] = (sw.ack_release_time is not None
                                          and sw.ack_release_time != ack_arrival)
    # blocker 3: T0-anchored ACK deadline
    res['ack_released_at_T0_plus_A'] = (sw.ack_release_time == T0 + A)

    # relay echo arrives a little later, held to T0+R
    echo_arrival = T0 + J + 4
    sw.relay_echo(echo_arrival)
    res['echo_released_at_T0_plus_R'] = (sw.echo_release_time == T0 + R)
    # blocker 3: anti-subtraction — echo_release - ack_release == R - A, independent of J
    if sw.ack_release_time is not None and sw.echo_release_time is not None:
        res['anti_subtraction_constant'] = ((sw.echo_release_time - sw.ack_release_time) == (R - A))
    else:
        res['anti_subtraction_constant'] = False

    # ---- blocker 5: retransmit of the SAME OPERATE AFTER release must be suppressed ----
    r3 = sw.operate(b'OP1', gen=5, t0=T0 + 30, j=J, a=A, r=R)
    res['retransmit_after_release_suppressed'] = (r3[0] == 'DROP_DUP')

    # ---- a genuinely NEW OPERATE (different generation) with no fresh SELECT fails open ----
    r4 = sw.operate(b'OP3', gen=7, t0=T0 + 40, j=J, a=A, r=R)
    res['stray_operate_fails_open'] = (r4[0] == 'FAILOPEN')
    return res


CLEAN_EXPECT = {k: True for k in
                ['residency_before_operate', 'first_operate_held', 'operate_commit_exactly_once',
                 'operate_ack_reservoir_seeded', 'retransmit_dropped', 'released_at_T0_plus_J',
                 'relay_gets_operate_once', 'no_source_copy', 'byte_identical_release',
                 'rrc_domain_untouched_by_qid3', 'ready_cleared_at_release',
                 'ack_echo_subject_to_blocker', 'ack_released_at_T0_plus_A',
                 'echo_released_at_T0_plus_R', 'anti_subtraction_constant',
                 'retransmit_after_release_suppressed', 'stray_operate_fails_open']}

MUTANTS = {
    'retransmit_releases_second_copy': 'retransmit_dropped',
    'duplicate_release': 'relay_gets_operate_once',
    'source_copy_leaks_to_relay': 'no_source_copy',
    'qid3_touches_rrc_failopen': 'rrc_domain_untouched_by_qid3',
    'early_qid2_release': 'relay_gets_operate_once',
    'stale_ready_after_seq_wrap': 'ready_cleared_at_release',
    'ready_without_reservoir': 'first_operate_held',
    # ---- the four correction mutants (2026-08-13) ----
    'operate_no_seed': 'ack_echo_subject_to_blocker',        # blocker 2
    'ack_relative_deadlines': 'ack_released_at_T0_plus_A',    # blocker 3
    'clear_gen_at_release': 'retransmit_after_release_suppressed',  # blocker 5
}


def main():
    clean = run()
    ok = (clean == CLEAN_EXPECT)
    print(f"CLEAN model: {sum(clean.values())}/{len(clean)} invariants hold ->", "PASS" if ok else "FAIL")
    if not ok:
        for k in clean:
            if clean[k] != CLEAN_EXPECT.get(k):
                print(f"   FAIL {k}: got {clean[k]}")
        # any invariant not in CLEAN_EXPECT is a bookkeeping bug
        for k in clean:
            if k not in CLEAN_EXPECT:
                print(f"   UNTRACKED invariant {k}")
    killed = 0
    total = 0
    for m, target in MUTANTS.items():
        total += 1
        r = run([m])
        broke = (r.get(target) != CLEAN_EXPECT[target])
        print(f"  mutant {m:34s} -> target invariant '{target}': "
              f"{'KILLED' if broke else 'SURVIVED (non-vacuity FAIL)'}")
        if broke:
            killed += 1
    print(f"mutants killed: {killed}/{total}")
    sys.exit(0 if (ok and killed == total) else 1)


main()

#!/usr/bin/env python3
"""
test_tag_domain.py — CHECK 1 (meeting_direction.md 2026-07-29) as executable tests.

F02 was a state write that silently never committed because a stateful-ALU predicate
compared against 0xFF. The repair moved the "no transaction" marker to 0x00. The
direction requires proving the marker is consistently zero everywhere, that NO ACTIVE
GENERATION CAN EVER BE ZERO, and that initialization, normal increment and wrap are
all tested.

This file models the tag state machine EXACTLY as the P4 implements it — the three
reg_tag RegisterActions and the const entries of tbl_state_decode / tbl_txn_active —
and asserts the invariants over the WHOLE domain rather than at the one generation a
trial happens to use. It is pure Python, stdlib only, and touches no hardware: these
are properties of the program, so they are checked where they can be checked
exhaustively.

    python3 analysis/test_tag_domain.py

Exit 0 if every property holds, 1 otherwise.
"""

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
# Overridable so the test can be pointed at a deliberately BROKEN copy of the P4 to
# prove it fails when it should — see the mutation checks in the CHECK 1 report.
P4 = os.environ.get("D3_P4",
                    os.path.join(ROOT, "p4",
                                 "case_a_defense3_fixed_ack_delay.p4"))

# ---------------------------------------------------------------------------
# The constants are READ OUT OF THE P4, not restated here. A test that restates
# them cannot catch the failure this test exists for: the constants drifting apart
# between the P4 and the things that mirror it.
# ---------------------------------------------------------------------------


def p4_const(name, src):
    m = re.search(r"^const\s+bit<\d+>\s+%s\s*=\s*\d+w(0x[0-9A-Fa-f]+|\d+)\s*;"
                  % re.escape(name), src, re.M)
    if not m:
        raise AssertionError("constant %s not found in %s" % (name, P4))
    return int(m.group(1), 0)


SRC = open(P4).read()
TAG_INACTIVE = p4_const("TAG_INACTIVE", SRC)
TAG_NO_WRITE = p4_const("TAG_NO_WRITE", SRC)
# E1 (Gate 4C repair): the early-RESPONSE pending marker.
TAG_PENDING_DELTA = p4_const("TAG_PENDING_DELTA", SRC)

# The generation domain, as the PARSER pins it (GATE 4:
# (app_control & 0xF0) == 0xC0 admits ROLE_ARM). The DNP3 application sequence is
# the low nibble and advances 0..15 per poll, so this list IS the increment cycle.
GENERATIONS = list(range(0xC0, 0xD0))

MASK8 = 0xFF

# E1: the THIRD reg_tag domain — live, with one early RESPONSE queued.
PENDING = [(g + TAG_PENDING_DELTA) & MASK8 for g in GENERATIONS]


# ---------------------------------------------------------------------------
# the model: reg_tag's three RegisterActions, byte for byte as written in the P4
# ---------------------------------------------------------------------------
def tag_arm(v, gen_in):
    """rv = gen_in - v ; if (v == TAG_INACTIVE) v = gen_in"""
    rv = (gen_in - v) & MASK8
    if v == TAG_INACTIVE:
        v = gen_in
    return v, rv


def tag_rmw(v, gen_in, tag_val):
    """rv = gen_in - v ; if (tag_val != TAG_NO_WRITE) v = tag_val"""
    rv = (gen_in - v) & MASK8
    if tag_val != TAG_NO_WRITE:
        v = tag_val
    return v, rv


def tag_read_or_mark(v, delta):
    """E1: rv = pre-state; if MSB set (SIGNED < 0) then v += delta.
    delta 0x50 marks an early RESPONSE (0xCn -> 0x1n); delta 0 makes it a pure read,
    which is how a generated blocker token uses the same arm."""
    rv = v
    if v & 0x80:                      # (int<8>)v < 0
        v = (v + delta) & MASK8
    return v, rv


def tag_retire_if_unmarked(v):
    """E1's repair: on ACK commitment retire IFF nothing is pending (MSB set)."""
    rv = v
    if v & 0x80:
        v = TAG_INACTIVE
    return v, rv


def tag_read(v):
    return v, v


def txn_active(cur_gen):
    """tbl_txn_active: 1 = live/nothing pending, 2 = live/one RESPONSE pending, 0 = idle.
    TWO distinct live values, not a flag, so every existing `== 1` test keeps its exact
    meaning and a duplicate RESPONSE falls out of the hold branch by itself."""
    if (cur_gen & 0xF0) == 0xC0:
        return 1
    if (cur_gen & 0xF0) == 0x10:
        return 2
    return 0


def blocker_live(tag_diff):
    """tbl_state_decode's CLASS_BLOCK_DEQ entries: 0x00 (unmarked) and 0xB0 (marked)."""
    return (tag_diff & MASK8) in (0x00, 0xB0)


# tbl_state_decode's CLASS_ARM entries, IN PRIORITY ORDER (entry order is priority).
def decode_arm(tag_diff):
    if (tag_diff & 0xFF) == 0x00:
        return "ARM_DUP"
    if (tag_diff & 0xF0) == 0xC0:
        return "ARM_FRESH"
    return "ARM_BUSY"


# tbl_state_decode's CLASS_ACK generation conjunct: the first entry
# (0x00 &&& 0xFE) rejects, i.e. tag_diff in {0x00, 0x01} means "no live transaction".
def ack_has_live_txn(tag_diff):
    return (tag_diff & 0xFE) != 0x00


# ---------------------------------------------------------------------------
FAILURES = []
CHECKS = [0]


def check(cond, label, detail=""):
    CHECKS[0] += 1
    if not cond:
        FAILURES.append("%s%s" % (label, (" — " + detail) if detail else ""))
    return cond


# =========================== the properties ================================
def t_marker_is_zero():
    check(TAG_INACTIVE == 0x00,
          "TAG_INACTIVE is 0x00",
          "read 0x%02X from the P4; the direction requires the inactive tag to be "
          "zero and tag_arm's predicate lowers to `equ lo, lo` only at zero"
          % TAG_INACTIVE)


def t_sentinels_distinct():
    """THE BUG CHECK 1 ACTUALLY CAUGHT.

    tag_rmw and ack_rel_rmw write on `tag_val != TAG_NO_WRITE`, and BOTH
    transaction-retire paths (fail-open blocker, released RESPONSE) retire by writing
    TAG_INACTIVE through tag_rmw. If the two constants are equal the retire is a
    no-op: reg_tag keeps a live generation for ever, a later keepalive finds a live
    transaction, and "returns clean" can never be true.
    """
    check(TAG_NO_WRITE != TAG_INACTIVE,
          "TAG_NO_WRITE != TAG_INACTIVE",
          "both are 0x%02X, so the retire write cannot commit" % TAG_INACTIVE)
    # and the retire must actually change the register in the model
    for g in GENERATIONS:
        v, _ = tag_rmw(g, 0, TAG_INACTIVE)
        check(v == TAG_INACTIVE,
              "retire from generation 0x%02X commits" % g,
              "reg_tag stayed 0x%02X" % v)


def t_no_generation_is_zero():
    """The direction's explicit obligation."""
    for g in GENERATIONS:
        check(g != 0, "generation 0x%02X is non-zero" % g)
        check(g != TAG_INACTIVE,
              "generation 0x%02X != TAG_INACTIVE" % g)
        check(g != TAG_NO_WRITE,
              "generation 0x%02X != TAG_NO_WRITE" % g)
    check(txn_active(TAG_INACTIVE) == 0,
          "TAG_INACTIVE does not read as an active transaction")
    check(txn_active(TAG_NO_WRITE) == 0,
          "TAG_NO_WRITE does not read as an active transaction")
    for g in GENERATIONS:
        check(txn_active(g) == 1, "generation 0x%02X reads as active" % g)


def t_initialization():
    """INITIALIZATION: from the register's declared init, every generation arms."""
    m = re.search(r"Register<bit<8>,\s*bit<1>>\(1,\s*(0x[0-9A-Fa-f]+|\d+)\)\s+reg_tag",
                  SRC)
    check(m is not None, "reg_tag's declared initial value is parseable")
    if m:
        init = int(m.group(1), 0)
        check(init == TAG_INACTIVE,
              "reg_tag initialises to TAG_INACTIVE",
              "declared 0x%02X, TAG_INACTIVE 0x%02X" % (init, TAG_INACTIVE))
    for g in GENERATIONS:
        v, rv = tag_arm(TAG_INACTIVE, g)
        check(v == g, "arm from init writes generation 0x%02X" % g,
              "reg_tag became 0x%02X" % v)
        check(decode_arm(rv) == "ARM_FRESH",
              "arm from init decodes ARM_FRESH at 0x%02X" % g,
              "tag_diff=0x%02X decoded %s" % (rv, decode_arm(rv)))


def t_normal_increment():
    """NORMAL INCREMENT: gen n -> n+1 across the whole cycle, with a retire between
    polls (the released RESPONSE), which is the real steady-state sequence."""
    for i in range(len(GENERATIONS) - 1):
        g0, g1 = GENERATIONS[i], GENERATIONS[i + 1]
        v, rv = tag_arm(TAG_INACTIVE, g0)
        check(v == g0 and decode_arm(rv) == "ARM_FRESH",
              "poll 0x%02X arms" % g0)
        # a duplicate/retransmitted READ of the SAME generation must not re-arm
        v2, rv2 = tag_arm(v, g0)
        check(v2 == g0 and decode_arm(rv2) == "ARM_DUP",
              "retransmitted READ of 0x%02X decodes ARM_DUP" % g0,
              "tag_diff=0x%02X -> %s" % (rv2, decode_arm(rv2)))
        # the released RESPONSE retires the generation
        v3, _ = tag_rmw(v2, 0, TAG_INACTIVE)
        check(v3 == TAG_INACTIVE, "poll 0x%02X retires" % g0)
        # next poll arms cleanly
        v4, rv4 = tag_arm(v3, g1)
        check(v4 == g1 and decode_arm(rv4) == "ARM_FRESH",
              "next poll 0x%02X arms after retire" % g1,
              "reg_tag=0x%02X tag_diff=0x%02X -> %s"
              % (v4, rv4, decode_arm(rv4)))


def t_wrap():
    """WRAP: 0xCF -> 0xC0 (DNP3 application sequence 15 -> 0). Nothing may become
    zero, and the wrap must be indistinguishable from any other increment."""
    g_last, g_first = GENERATIONS[-1], GENERATIONS[0]
    check(g_last == 0xCF and g_first == 0xC0, "the wrap boundary is 0xCF -> 0xC0")
    v, _ = tag_arm(TAG_INACTIVE, g_last)
    check(v == 0xCF, "0xCF arms")
    v, _ = tag_rmw(v, 0, TAG_INACTIVE)
    check(v == TAG_INACTIVE, "0xCF retires")
    v, rv = tag_arm(v, g_first)
    check(v == 0xC0 and decode_arm(rv) == "ARM_FRESH",
          "0xC0 arms across the wrap",
          "reg_tag=0x%02X tag_diff=0x%02X -> %s" % (v, rv, decode_arm(rv)))
    # the arithmetic itself can never produce the marker: gen_in - stored == 0 only
    # when they are EQUAL, which is ARM_DUP, never "idle"
    for g in GENERATIONS:
        _, rv = tag_arm(TAG_INACTIVE, g)
        check(rv != 0x00,
              "idle + generation 0x%02X never yields tag_diff 0 (would read as DUP)"
              % g)


def t_concurrent_is_busy():
    """A DIFFERENT live generation must decode ARM_BUSY — never FRESH (which would
    claim an arm that tag_arm's predicate refuses to commit) and never DUP."""
    for stored in GENERATIONS:
        for gen_in in GENERATIONS:
            if gen_in == stored:
                continue
            v, rv = tag_arm(stored, gen_in)
            check(v == stored,
                  "concurrent READ 0x%02X does not overwrite live 0x%02X"
                  % (gen_in, stored))
            check(decode_arm(rv) == "ARM_BUSY",
                  "concurrent 0x%02X over 0x%02X decodes ARM_BUSY"
                  % (gen_in, stored),
                  "tag_diff=0x%02X -> %s" % (rv, decode_arm(rv)))


def t_decode_sets_disjoint():
    """The three CLASS_ARM decode sets must partition every reachable tag_diff, and
    the removed 0xFF-era `tag_diff == 0xD0 -> ARM_FRESH` entry must be unreachable —
    if it were reachable it would declare FRESH on a state whose write cannot commit,
    which is the F02 signature exactly."""
    reachable = set()
    for stored in [TAG_INACTIVE] + GENERATIONS:
        for gen_in in GENERATIONS:
            reachable.add(tag_arm(stored, gen_in)[1])
    check(0xD0 not in reachable,
          "tag_diff 0xD0 is UNREACHABLE (the removed 0xFF-era entry)",
          "reachable diffs include 0xD0")
    fresh = {d for d in reachable if decode_arm(d) == "ARM_FRESH"}
    dup = {d for d in reachable if decode_arm(d) == "ARM_DUP"}
    busy = {d for d in reachable if decode_arm(d) == "ARM_BUSY"}
    check(not (fresh & dup) and not (fresh & busy) and not (dup & busy),
          "the ARM decode sets are disjoint")
    check(fresh == set(GENERATIONS),
          "ARM_FRESH is reached by exactly the idle+generation diffs",
          "fresh=%s" % sorted("0x%02X" % d for d in fresh))
    check(dup == {0x00}, "ARM_DUP is reached only by tag_diff 0")
    # and FRESH may only ever be decoded when the write DID commit
    for stored in [TAG_INACTIVE] + GENERATIONS:
        for gen_in in GENERATIONS:
            v, rv = tag_arm(stored, gen_in)
            if decode_arm(rv) == "ARM_FRESH":
                check(v == gen_in,
                      "ARM_FRESH implies the generation was written "
                      "(stored 0x%02X, gen 0x%02X)" % (stored, gen_in),
                      "reg_tag=0x%02X — this is the F02 failure mode" % v)


def t_ack_liveness():
    """A pure ACK carries no DNP3 application layer, so gen_in == 0 and
    tag_diff == 0 - stored. Idle must read "no live transaction"; every generation
    must read live. Under the OLD 0xFF marker idle gave 0x01; under 0x00 it gives
    0x00 — the (0x00 &&& 0xFE) entry covers BOTH, which is why it still holds."""
    _, rv_idle = tag_rmw(TAG_INACTIVE, 0, TAG_NO_WRITE)
    check(not ack_has_live_txn(rv_idle),
          "ACK while idle reads NO live transaction",
          "tag_diff=0x%02X" % rv_idle)
    _, rv_stale = tag_rmw(0xFF, 0, TAG_NO_WRITE)
    check(not ack_has_live_txn(rv_stale),
          "ACK against a STALE 0xFF also reads NO live transaction "
          "(the old marker stays rejected)",
          "tag_diff=0x%02X" % rv_stale)
    for g in GENERATIONS:
        _, rv = tag_rmw(g, 0, TAG_NO_WRITE)
        check(ack_has_live_txn(rv),
              "ACK during generation 0x%02X reads LIVE" % g,
              "tag_diff=0x%02X" % rv)
    # read-only: an ACK must never move the tag
    for g in [TAG_INACTIVE] + GENERATIONS:
        v, _ = tag_rmw(g, 0, TAG_NO_WRITE)
        check(v == g, "ACK leaves reg_tag unchanged at 0x%02X" % g)


def t_blocker_generation():
    """A blocker token's stamped generation comes from cur_gen at admission, and
    admission requires txn_active, so it is always 0xCn. That is what stops a token
    from ever carrying 0x00 — which would match the idle register for ever and
    produce a token that never terminates."""
    for g in GENERATIONS:
        stamped = g                      # hdr.ib.gen = meta.cur_gen
        check(stamped != TAG_INACTIVE,
              "a stamped blocker generation is never TAG_INACTIVE (0x%02X)" % g)
        _, rv = tag_read(g)
        check(txn_active(rv) == 1, "blocker of generation 0x%02X sees active" % g)
    check(txn_active(TAG_INACTIVE) == 0,
          "a token generated while idle cannot be admitted "
          "(txn_active reads 0 at TAG_INACTIVE)")


def t_e1_domains_disjoint():
    """The three reg_tag domains must be pairwise disjoint, and the marker must map
    the live domain ONTO the pending domain exactly."""
    check(TAG_PENDING_DELTA == 0x50,
          "TAG_PENDING_DELTA is 0x50", "read 0x%02X" % TAG_PENDING_DELTA)
    check(PENDING == list(range(0x10, 0x20)),
          "0xC0..0xCF + delta == 0x10..0x1F",
          "got %s" % ["0x%02X" % p for p in PENDING])
    dom_i, dom_l, dom_p = {TAG_INACTIVE}, set(GENERATIONS), set(PENDING)
    check(not (dom_i & dom_l) and not (dom_i & dom_p) and not (dom_l & dom_p),
          "INACTIVE / LIVE / PENDING are pairwise disjoint")
    check(TAG_INACTIVE not in dom_p,
          "no pending value collides with TAG_INACTIVE")
    check(TAG_NO_WRITE not in dom_p and TAG_NO_WRITE not in dom_l,
          "TAG_NO_WRITE collides with neither live domain")
    # the sign test is what separates them, so it must separate them
    for g in GENERATIONS:
        check(g & 0x80, "live 0x%02X has the MSB SET (signed negative)" % g)
    for p in PENDING:
        check(not (p & 0x80), "pending 0x%02X has the MSB CLEAR" % p)
    check(not (TAG_INACTIVE & 0x80), "TAG_INACTIVE has the MSB clear")


def t_e1_marker_is_one_shot():
    """A duplicate, retransmitted or stale RESPONSE must NOT transform a tag that is
    already pending. One-shot is enforced by the predicate, not by a flag."""
    for g in GENERATIONS:
        v1, rv1 = tag_read_or_mark(g, TAG_PENDING_DELTA)
        check(v1 == (g + TAG_PENDING_DELTA) & MASK8,
              "first RESPONSE marks 0x%02X -> 0x%02X" % (g, v1))
        check(rv1 == g, "the marker returns the PRE-state as cur_gen")
        # a SECOND, THIRD, ... RESPONSE must be idempotent
        v2 = v1
        for _ in range(5):
            v2, rv2 = tag_read_or_mark(v2, TAG_PENDING_DELTA)
            check(v2 == v1,
                  "duplicate RESPONSE leaves 0x%02X unchanged" % v1,
                  "became 0x%02X" % v2)
            check(txn_active(rv2) == 2,
                  "a duplicate RESPONSE reads txn_active == 2, so it MISSES the hold "
                  "branch and is forwarded as a bypass")
        check(v2 in PENDING,
              "no value outside the defined domains is ever produced",
              "0x%02X" % v2)
    # a generated blocker token uses the SAME arm with delta 0: pure read
    for g in list(GENERATIONS) + PENDING + [TAG_INACTIVE]:
        v, rv = tag_read_or_mark(g, 0)
        check(v == g and rv == g,
              "delta 0 leaves 0x%02X untouched (a token's pure read)" % g)


def t_e1_ack_release_retirement():
    """The Gate 4C repair: retire on ACK commitment iff nothing is pending."""
    for g in GENERATIONS:
        v, rv = tag_retire_if_unmarked(g)
        check(v == TAG_INACTIVE,
              "no RESPONSE pending: ACK commitment RETIRES 0x%02X" % g,
              "reg_tag stayed 0x%02X" % v)
        check(rv == g, "the retirement returns the PRE-state")
        check(txn_active(rv) == 1,
              "the pre-state reports txn_active == 1, which is how the counter split "
              "records that the retirement path ran")
    for p in PENDING:
        v, rv = tag_retire_if_unmarked(p)
        check(v == p,
              "RESPONSE pending: ACK commitment does NOT retire 0x%02X" % p,
              "became 0x%02X" % v)
        check(txn_active(rv) == 2,
              "the pre-state reports txn_active == 2 (a RESPONSE is queued)")
    # and the queued RESPONSE's release still retires, via tag_rmw
    for p in PENDING:
        v, _ = tag_rmw(p, 0, TAG_INACTIVE)
        check(v == TAG_INACTIVE,
              "the queued RESPONSE's release retires 0x%02X" % p)
    # an already-idle tag must not be disturbed by an ACK release
    v, _ = tag_retire_if_unmarked(TAG_INACTIVE)
    check(v == TAG_INACTIVE, "an idle tag survives an ACK release unchanged")


def t_e1_pending_not_inactive_and_busy():
    """Pending tags must read ACTIVE, and a new READ against one must read BUSY."""
    for p in PENDING:
        check(txn_active(p) != 0,
              "pending 0x%02X is NOT treated as inactive" % p)
        check(txn_active(p) == 2, "pending 0x%02X reads txn_active == 2" % p)
        for g in GENERATIONS:
            v, rv = tag_arm(p, g)
            check(v == p,
                  "a new READ does NOT overwrite pending 0x%02X" % p,
                  "became 0x%02X" % v)
            check(decode_arm(rv) == "ARM_BUSY",
                  "a new READ against pending 0x%02X decodes ARM_BUSY" % p,
                  "tag_diff=0x%02X -> %s" % (rv, decode_arm(rv)))


def t_e1_blocker_decode():
    """A token of the CURRENT generation must stay live under BOTH tag encodings, and a
    foreign token must stay stale under both."""
    for g in GENERATIONS:
        marked = (g + TAG_PENDING_DELTA) & MASK8
        check(blocker_live((g - g) & MASK8),
              "token 0x%02X live against an UNMARKED tag (tag_diff 0x00)" % g)
        diff = (g - marked) & MASK8
        check(diff == 0xB0,
              "token 0x%02X against a MARKED tag gives tag_diff 0xB0" % g,
              "got 0x%02X — the single entry only works if this is "
              "generation-independent" % diff)
        check(blocker_live(diff),
              "token 0x%02X live against a MARKED tag" % g)
    # a FOREIGN token must remain stale against both encodings
    for carried in GENERATIONS:
        for stored_gen in GENERATIONS:
            if carried == stored_gen:
                continue
            check(not blocker_live((carried - stored_gen) & MASK8),
                  "foreign token 0x%02X vs live 0x%02X stays STALE"
                  % (carried, stored_gen))
            marked = (stored_gen + TAG_PENDING_DELTA) & MASK8
            check(not blocker_live((carried - marked) & MASK8),
                  "foreign token 0x%02X vs marked 0x%02X stays STALE"
                  % (carried, marked))
    # and a token can never be stamped with a pending or inactive value, because
    # admission requires txn_active == 1
    check(txn_active(TAG_INACTIVE) != 1,
          "a token cannot be admitted while idle")
    for p in PENDING:
        check(txn_active(p) != 1,
              "a token cannot be admitted while a RESPONSE is pending (0x%02X)" % p)


def t_no_large_constant_compares():
    """The audit rule the F02 evidence produced, enforced on the SOURCE.

    bf-p4c emits `equ lo, lo, -K` for EVERY K, silently, with no error or warning —
    a probe over K in {1,2,7,8,15,16,63,64,127,128,192,254,255} showed identical
    lowering at all of them (p4/probe_salu_immediate.p4). So the .bfa CANNOT be used
    to tell a safe constant from an unsafe one, and the only durable rule is: do not
    compare SALU state against a large constant at all. Compare against zero or
    against a PHV field.

    This test greps every RegisterAction body for a comparison against a literal and
    fails on any constant above the one value proven to work on silicon
    (UNARMED_WORD = 2, in deadline_arm_once).
    """
    # 0x50 is a WRITE operand (an add), never a comparison, so it is not in scope
    # here; the comparisons E1 adds are all against ZERO (`(int<8>)v < 8s0`).
    PROVEN_MAX = 2
    # NOTE the character class excludes '(' rather than '>': the type arguments
    # themselves contain '>' (RegisterAction<bit<8>, bit<1>, bit<8>>), so a
    # '[^>]*' stops inside bit<8> and matches nothing.
    bodies = re.findall(
        r"RegisterAction<[^(]*\(\s*(\w+)\s*\)\s+(\w+)\s*=\s*\{(.*?)\n    \};",
        SRC, re.S)
    check(len(bodies) >= 10,
          "RegisterAction bodies were found to audit",
          "found %d" % len(bodies))
    for reg, act, body in bodies:
        for m in re.finditer(r"(==|!=)\s*(?:\d+w)?(0x[0-9A-Fa-f]+|\d+)\b", body):
            k = int(m.group(2), 0)
            check(k <= PROVEN_MAX,
                  "%s.%s compares against %d (0x%X) <= the proven-safe %d"
                  % (reg, act, k, k, PROVEN_MAX),
                  "a SALU predicate against a large constant is the F02 class: the "
                  "compiled immediate is emitted without complaint and the "
                  "conditional write can silently never commit")
        # A named constant is fine only if it RESOLVES and resolves small. An
        # unresolvable name is a FAILURE, never a skip: silently passing over a
        # comparison the audit could not evaluate is precisely how F02 survived
        # two review passes.
        for m in re.finditer(r"(==|!=)\s*([A-Z][A-Z0-9_]+)\b", body):
            nm = m.group(2)
            try:
                k = p4_const(nm, SRC)
            except AssertionError:
                check(False,
                      "%s.%s compares against %s, which this audit could resolve"
                      % (reg, act, nm),
                      "the constant's declaration does not match the expected "
                      "`const bit<N> NAME = Nw<value>;` form, so its magnitude is "
                      "UNKNOWN — resolve it by hand and widen p4_const()")
                continue
            check(k <= PROVEN_MAX,
                  "%s.%s compares against %s = %d (0x%X) <= %d"
                  % (reg, act, nm, k, k, PROVEN_MAX),
                  "F02 class: see the note at TAG_INACTIVE")


def t_mirrors_agree():
    """The constants are mirrored into three Python files because neither the control
    plane nor the analyzer can read a P4 constant. Every mirror must match the P4 —
    the analyzer's stale 0xFF is exactly the drift this catches."""
    mirrors = [
        (os.path.join(ROOT, "setup",
                      "case_a_defense3_fixed_ack_delay_setup.py"),
         "TAG_INACTIVE", TAG_INACTIVE),
        (os.path.join(ROOT, "setup",
                      "case_a_defense3_fixed_ack_delay_setup.py"),
         "TAG_NO_WRITE", TAG_NO_WRITE),
        (os.path.join(ROOT, "analysis", "analyze_defense3.py"),
         "TAG_INACTIVE", TAG_INACTIVE),
    ]
    for path, name, want in mirrors:
        src = open(path).read()
        m = re.search(r"^%s\s*=\s*(0x[0-9A-Fa-f]+|\d+)" % name, src, re.M)
        if not check(m is not None,
                     "%s defines %s" % (os.path.basename(path), name)):
            continue
        got = int(m.group(1), 0)
        check(got == want,
              "%s: %s == 0x%02X" % (os.path.basename(path), name, want),
              "mirror says 0x%02X, P4 says 0x%02X" % (got, want))
    # and no file may still carry the retired 0xFF as "the inactive tag"
    for path in [os.path.join(ROOT, "analysis", "analyze_defense3.py"),
                 os.path.join(ROOT, "setup",
                              "case_a_defense3_fixed_ack_delay_setup.py")]:
        src = open(path).read()
        bad = re.findall(r"^[^#\n]*(?:==|!=)\s*0xFF\b.*$", src, re.M)
        bad = [b for b in bad if "reg_tag" in b or "TAG" in b]
        check(not bad,
              "%s has no live comparison against 0xFF as the inactive tag"
              % os.path.basename(path),
              "; ".join(b.strip()[:90] for b in bad))


# ---------------------------------------------------------------------------
def main():
    tests = [
        ("inactive marker is zero", t_marker_is_zero),
        ("no-write sentinel is distinct from the inactive marker",
         t_sentinels_distinct),
        ("no active generation can be zero", t_no_generation_is_zero),
        ("INITIALIZATION", t_initialization),
        ("NORMAL INCREMENT", t_normal_increment),
        ("WRAP 0xCF -> 0xC0", t_wrap),
        ("concurrent generation decodes BUSY", t_concurrent_is_busy),
        ("ARM decode sets are disjoint and FRESH implies committed",
         t_decode_sets_disjoint),
        ("pure-ACK liveness test over the whole domain", t_ack_liveness),
        ("blocker generations are never the marker", t_blocker_generation),
        ("E1 domains are disjoint", t_e1_domains_disjoint),
        ("E1 marker is ONE-SHOT (duplicate RESPONSE)", t_e1_marker_is_one_shot),
        ("E1 ACK-release retirement", t_e1_ack_release_retirement),
        ("E1 pending is active, and a new READ reads BUSY",
         t_e1_pending_not_inactive_and_busy),
        ("E1 blocker decode accepts 0x00 and 0xB0, foreign stays stale",
         t_e1_blocker_decode),
        ("no SALU predicate compares against a large constant",
         t_no_large_constant_compares),
        ("python mirrors agree with the P4", t_mirrors_agree),
    ]
    print("=" * 74)
    print("CHECK 1 — INACTIVE MARKER SAFETY   (%s)" % os.path.basename(P4))
    print("TAG_INACTIVE = 0x%02X   TAG_NO_WRITE = 0x%02X   generations 0x%02X..0x%02X"
          % (TAG_INACTIVE, TAG_NO_WRITE, GENERATIONS[0], GENERATIONS[-1]))
    print("=" * 74)
    for label, fn in tests:
        before = len(FAILURES)
        n0 = CHECKS[0]
        fn()
        n = CHECKS[0] - n0
        bad = FAILURES[before:]
        print("%-6s %-56s %3d assertion(s)"
              % ("FAIL" if bad else "PASS", label, n))
        for b in bad:
            print("         %s" % b)
    print("-" * 74)
    print("%d assertion(s), %d failure(s)" % (CHECKS[0], len(FAILURES)))
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())

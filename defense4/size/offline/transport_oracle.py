#!/usr/bin/env python3
"""Bounded offline oracle for the per-flow TCP sequence/ACK translation that DNP3
size obfuscation forces when the switch INSERTS bytes into a stream (response
padding on outstation->master, or SBO CROB expansion on master->outstation).

This is a transport-layer state machine only. It does NOT build DNP3 frames,
recompute CRCs, or fold TCP/IP checksums -- those live in sbo_oracle.py /
joint_transform_oracle.py / p4_egress_emulator.py. Here the single question is:
after we add N bytes to one direction of a flow, can a BOUNDED amount of on-chip
state keep BOTH endpoints' TCP views (seq and cumulative ack) byte-consistent
across retransmits, dup-acks, out-of-order delivery, unsupported packets,
collisions, connection teardown, and sequence wraparound -- and where it
provably cannot, what is the safe degraded behavior?

Model summary (see README.md for the full write-up):
  * Two INDEPENDENT streams per flow: FWD = outstation->master, REV = master->outstation.
  * Each stream carries its own insertion ledger (Delta_fwd, Delta_rev).
  * A packet flowing in direction D:
        seq' = seq + Delta_D(seq)          # its own stream was padded: add
        ack' = ack - Delta_opp(ack)        # it acks the OTHER stream: subtract
  * Translation is a step function of the ORIGINAL sequence number, stored as a
    small ledger of insertion boundaries. Keying on the original seq makes
    retransmission idempotent by construction (same seq -> same delta, no double
    count) and makes out-of-order / duplicate packets translate correctly with no
    extra state.

Safety contract encoded and tested here:
  * Before a flow's first insertion, an unsupported packet MAY pass native (it was
    never modified -> safe).
  * AFTER any insertion, every packet on that flow is translated -- including
    packets the classifier does not "support". Raw untranslated pass-through of a
    post-insertion packet is UNSAFE and this model never emits it.
  * The bounded limits are encoded as explicit, tested behaviors, never as raw
    pass-through: (a) ledger-depth cap -> FREEZE new insertions, keep translating
    to clean retirement; (b) flow-table pressure -> DENY a colliding NEW flow (it
    stays native, safe) and NEVER evict an active-epoch flow.

Run:  python3 transport_oracle.py            # scenario demo + JSON summary to stdout
Test: python3 test_transport_oracle.py       # adversarial suite (stdlib unittest)
"""
from __future__ import annotations

import json
import zlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, List, Optional, Tuple

SEQ_MOD = 1 << 32
# Keep each flow's in-use offset window inside the low half of the sequence space so
# that to_off()'s modular subtraction stays unambiguous (an old retransmit reads as a
# small offset, never as a near-2^32 one). New insertions are refused once a flow's
# offset span would reach this bound; ordinary seq wrap at a high ISN is unaffected.
WRAP_GUARD = SEQ_MOD >> 1     # 2^31 (~2 GB transferred on one stream)


def mod32(x: int) -> int:
    return x % SEQ_MOD


# --------------------------------------------------------------------------- #
# Directions
# --------------------------------------------------------------------------- #
class Dir(Enum):
    FWD = 0   # outstation -> master   (response stream)
    REV = 1   # master -> outstation   (request stream)


def opp(d: Dir) -> Dir:
    return Dir.REV if d is Dir.FWD else Dir.FWD


# --------------------------------------------------------------------------- #
# Per-packet inputs / outputs
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Flags:
    syn: bool = False
    fin: bool = False
    rst: bool = False
    ack: bool = True


@dataclass(frozen=True)
class Segment:
    """One TCP segment as it arrives at the switch, in the EMITTER's own space."""
    flow: object            # opaque flow identity (same value for both directions)
    direction: Dir
    seq: int                # 32-bit, emitter's local sequence space
    ack: int                # 32-bit cumulative ack for the opposite stream
    payload_len: int = 0
    flags: Flags = Flags()
    supported: bool = True   # did the classifier recognise/parse this packet?
    insert: int = 0          # bytes the size policy wants to add to THIS stream here


class Outcome(Enum):
    NATIVE = "NATIVE"                       # no epoch, passed unchanged (safe)
    TRANSLATED = "TRANSLATED"               # seq/ack translated, no new insertion
    TRANSLATED_INSERTED = "TRANSLATED_INSERTED"   # translated AND recorded a boundary
    TRANSLATED_FROZEN = "TRANSLATED_FROZEN"       # epoch live, insertion suppressed, still translated
    DENIED_COLLISION = "DENIED_COLLISION"   # slot owned by another flow -> intruder stays native
    RETIRED = "RETIRED"                     # RST / both-FIN: translated, then state freed


@dataclass
class Result:
    seq: int
    ack: int
    outcome: Outcome
    inserted: int = 0
    partial_ack: bool = False
    note: str = ""


# --------------------------------------------------------------------------- #
# Insertion ledger -- the step function, in OFFSET space (anchored at the ISN)
# --------------------------------------------------------------------------- #
@dataclass
class Insertion:
    boundary: int   # offset; original bytes with offset >= boundary shift by +size
    size: int


@dataclass
class Ledger:
    """One stream's insertion boundaries. Offsets are ints anchored at the ISN, so
    all step-function math is plain integer arithmetic; wire<->offset conversion
    (the only place mod-2^32 matters) is done by the Flow."""
    max_depth: int
    entries: List[Insertion] = field(default_factory=list)
    frozen: bool = False

    def total(self) -> int:
        return sum(e.size for e in self.entries)

    def empty(self) -> bool:
        return not self.entries

    def delta_at(self, off: int) -> int:
        """Cumulative bytes inserted at boundaries <= off (forward seq translation)."""
        return sum(e.size for e in self.entries if e.boundary <= off)

    def translate_seq(self, off: int) -> int:
        return off + self.delta_at(off)

    def translate_ack(self, a_off: int) -> Tuple[int, bool]:
        """Inverse map for a cumulative ack expressed in PADDED (translated) offset
        space -> original offset. Returns (orig_off, partial) where partial=True
        means the ack landed strictly inside a pad region and was snapped to that
        insertion's boundary (a fractional ack of inserted bytes)."""
        cum = 0
        for e in sorted(self.entries, key=lambda x: x.boundary):
            tstart = e.boundary + cum          # translated start of this pad region
            if a_off <= tstart:                # ack is at/below this pad -> done
                return a_off - cum, False
            if a_off < tstart + e.size:        # ack lands inside the pad -> snap
                return e.boundary, True
            cum += e.size                      # ack is fully past this pad
        return a_off - cum, False

    def has_boundary(self, boundary: int) -> Optional[Insertion]:
        for e in self.entries:
            if e.boundary == boundary:
                return e
        return None

    def add(self, boundary: int, size: int) -> str:
        """Try to record an insertion. Returns one of:
        'inserted' | 'idempotent' | 'frozen' (depth cap) | 'conflict' (re-segmented)."""
        existing = self.has_boundary(boundary)
        if existing is not None:
            return "idempotent" if existing.size == size else "conflict"
        if self.frozen or len(self.entries) >= self.max_depth:
            self.frozen = True
            return "frozen"
        self.entries.append(Insertion(boundary, size))
        return "inserted"


# --------------------------------------------------------------------------- #
# Per-flow state
# --------------------------------------------------------------------------- #
class Flow:
    def __init__(self, owner_tag: object, generation: int, ledger_depth: int):
        self.owner_tag = owner_tag
        self.generation = generation
        self.isn: Dict[Dir, Optional[int]] = {Dir.FWD: None, Dir.REV: None}
        self.ledger: Dict[Dir, Ledger] = {
            Dir.FWD: Ledger(ledger_depth),
            Dir.REV: Ledger(ledger_depth),
        }
        self.fin_seen: Dict[Dir, bool] = {Dir.FWD: False, Dir.REV: False}
        self.retired = False

    def epoch_begun(self) -> bool:
        return not (self.ledger[Dir.FWD].empty() and self.ledger[Dir.REV].empty())

    def learn_isn(self, d: Dir, seq: int) -> None:
        if self.isn[d] is None:
            self.isn[d] = seq

    def to_off(self, d: Dir, seq: int) -> int:
        return mod32(seq - self.isn[d])

    def to_wire(self, d: Dir, off: int) -> int:
        return mod32(self.isn[d] + off)


# --------------------------------------------------------------------------- #
# Bounded flow table with owner-tag collision detection + generation counter
# --------------------------------------------------------------------------- #
class FlowTable:
    def __init__(self, size: int, ledger_depth: int,
                 hash_fn: Optional[Callable[[object], int]] = None,
                 tag_fn: Optional[Callable[[object], object]] = None):
        self.size = size
        self.ledger_depth = ledger_depth
        self.slots: List[Optional[Flow]] = [None] * size
        self.gen = 0
        self._hash = hash_fn or (lambda f: zlib.crc32(repr(f).encode()) % size)
        # owner tag: a wide identity of the flow. On silicon this is a compressed
        # 16/32-bit value; here we default to the full identity so tag aliasing
        # (same slot AND same tag, different flow) is not modelled as a false hit.
        self._tag = tag_fn or (lambda f: f)

    def slot_of(self, flow: object) -> int:
        return self._hash(flow)

    def lookup(self, flow: object) -> Tuple[int, Optional[Flow], str]:
        """Return (idx, flow_state_or_None, status) where status is
        'own' | 'empty' | 'collision'."""
        idx = self.slot_of(flow)
        occ = self.slots[idx]
        if occ is None:
            return idx, None, "empty"
        if occ.owner_tag == self._tag(flow):
            return idx, occ, "own"
        return idx, occ, "collision"

    def claim(self, flow: object) -> Flow:
        idx = self.slot_of(flow)
        self.gen += 1
        st = Flow(self._tag(flow), self.gen, self.ledger_depth)
        self.slots[idx] = st
        return st

    def retire(self, flow: object) -> None:
        idx = self.slot_of(flow)
        occ = self.slots[idx]
        if occ is not None and occ.owner_tag == self._tag(flow):
            self.slots[idx] = None

    def force_evict(self, flow: object) -> bool:
        """Attempt to reclaim a slot for reuse. An ACTIVE-EPOCH flow is NON-evictable
        (evicting it would strand padded bytes with no delta -> the only alternative
        would be unsafe raw pass-through). Returns True only if it was safe to evict
        (empty, native, or already retired)."""
        idx = self.slot_of(flow)
        occ = self.slots[idx]
        if occ is None:
            return True
        if occ.owner_tag != self._tag(flow):
            return False   # not ours to evict
        if occ.epoch_begun() and not occ.retired:
            return False   # protected
        self.slots[idx] = None
        return True


# --------------------------------------------------------------------------- #
# The oracle
# --------------------------------------------------------------------------- #
class TransportOracle:
    def __init__(self, table_size: int = 1024, ledger_depth: int = 4,
                 hash_fn: Optional[Callable[[object], int]] = None,
                 tag_fn: Optional[Callable[[object], object]] = None):
        self.table = FlowTable(table_size, ledger_depth, hash_fn, tag_fn)

    # -- helpers ----------------------------------------------------------- #
    def _translate(self, fl: Flow, seg: Segment) -> Tuple[int, int, bool]:
        """Apply the current ledgers to (seq, ack). Empty ledgers are the identity,
        so this is always safe to call and never needs an ISN we have not learned."""
        d = seg.direction
        seq_out, ack_out, partial = seg.seq, seg.ack, False

        led = fl.ledger[d]
        if not led.empty():
            fl.learn_isn(d, seg.seq)                      # ensure anchor exists
            off = fl.to_off(d, seg.seq)
            seq_out = fl.to_wire(d, led.translate_seq(off))

        oled = fl.ledger[opp(d)]
        if not oled.empty() and fl.isn[opp(d)] is not None:
            a_off = fl.to_off(opp(d), seg.ack)
            o_off, partial = oled.translate_ack(a_off)
            ack_out = fl.to_wire(opp(d), o_off)

        return seq_out, ack_out, partial

    def _wrap_guard(self, fl: Flow, seg: Segment) -> bool:
        """True if a NEW insertion here would push this stream's in-use OFFSET span to
        or past WRAP_GUARD (half the sequence space). Insertions are then refused
        (freeze) so to_off()'s modular subtraction stays unambiguous. This is an
        explicit eligibility rejection BEFORE the offset window becomes ambiguous, not
        a bet on modular inversion through a wrap. A high ISN with a small offset (an
        ordinary wire-seq wrap) is NOT affected -- translation handles that with mod32."""
        d = seg.direction
        off = 0 if fl.isn[d] is None else fl.to_off(d, seg.seq)
        end_off = off + seg.payload_len + fl.ledger[d].total() + seg.insert
        return end_off >= WRAP_GUARD

    # -- main entry -------------------------------------------------------- #
    def process(self, seg: Segment) -> Result:
        idx, fl, status = self.table.lookup(seg.flow)

        # Collision: the slot is held by a different flow. The intruder is DENIED a
        # transform epoch; it has never been modified, so passing it native is safe.
        if status == "collision":
            return Result(seg.seq, seg.ack, Outcome.DENIED_COLLISION,
                          note="slot owned by another flow; intruder stays native")

        wants_insert = seg.insert > 0 and not (seg.flags.syn or seg.flags.rst)

        # No state yet.
        if fl is None:
            if not wants_insert:
                # Nothing to translate, nothing to insert -> native pass (safe).
                return Result(seg.seq, seg.ack, Outcome.NATIVE,
                              note="pre-epoch native pass")
            fl = self.table.claim(seg.flow)

        # RST -> translate this control segment with the CURRENT ledgers, then retire.
        if seg.flags.rst:
            seq_out, ack_out, partial = self._translate(fl, seg)
            fl.retired = True
            self.table.retire(seg.flow)
            return Result(seq_out, ack_out, Outcome.RETIRED, partial_ack=partial,
                          note="RST: translated then state freed")

        # Decide on insertion (may be suppressed -> freeze, still translate).
        did_insert = 0
        note = ""
        if wants_insert:
            fl.learn_isn(seg.direction, seg.seq)
            if self._wrap_guard(fl, seg):
                fl.ledger[seg.direction].frozen = True
                note = "insertion refused (would wrap 2^32); frozen, still translating"
            else:
                off = fl.to_off(seg.direction, seg.seq)
                boundary = off + seg.payload_len          # pad appended after this payload
                st = fl.ledger[seg.direction].add(boundary, seg.insert)
                if st == "inserted":
                    did_insert = seg.insert
                elif st == "idempotent":
                    note = "retransmit of an already-transformed segment (no double count)"
                elif st == "frozen":
                    note = "ledger depth cap reached; frozen, still translating"
                elif st == "conflict":
                    note = "re-segmented retransmit at a known start (LIMITATION); not re-inserted"

        # Translate seq/ack with the (possibly just-updated) ledgers.
        seq_out, ack_out, partial = self._translate(fl, seg)

        # FIN bookkeeping / clean retirement.
        outcome: Outcome
        if seg.flags.fin:
            fl.fin_seen[seg.direction] = True
            if fl.fin_seen[Dir.FWD] and fl.fin_seen[Dir.REV]:
                fl.retired = True
                self.table.retire(seg.flow)
                return Result(seq_out, ack_out, Outcome.RETIRED, inserted=did_insert,
                              partial_ack=partial,
                              note="both FINs seen: translated then state freed")

        if did_insert:
            outcome = Outcome.TRANSLATED_INSERTED
        elif fl.ledger[seg.direction].frozen and wants_insert:
            outcome = Outcome.TRANSLATED_FROZEN
        elif fl.epoch_begun():
            outcome = Outcome.TRANSLATED
        else:
            # Not epoch-begun and no insert happened. Only reachable if wants_insert
            # was true but refused before any boundary existed (e.g. wrap on the very
            # first insertion) -> nothing padded yet, safe to treat as native-ish, but
            # keep it TRANSLATED_FROZEN to signal the epoch was ATTEMPTED and denied.
            outcome = Outcome.TRANSLATED_FROZEN if wants_insert else Outcome.NATIVE
        return Result(seq_out, ack_out, outcome, inserted=did_insert,
                      partial_ack=partial, note=note)


# --------------------------------------------------------------------------- #
# Scenario demo -- exercises the mainline path and prints a machine-readable
# summary. The authoritative adversarial checks live in test_transport_oracle.py.
# --------------------------------------------------------------------------- #
def _demo() -> dict:
    PAD = 7
    o = TransportOracle(table_size=64, ledger_depth=4)
    F = "flowA"
    isn_fwd, isn_rev = 1000, 5000
    steps = []

    def run(label, seg, exp_seq=None, exp_ack=None):
        r = o.process(seg)
        rec = {
            "step": label, "dir": seg.direction.name,
            "in_seq": seg.seq, "in_ack": seg.ack,
            "out_seq": r.seq, "out_ack": r.ack,
            "outcome": r.outcome.value, "inserted": r.inserted,
        }
        ok = True
        if exp_seq is not None:
            rec["exp_seq"] = exp_seq; ok = ok and r.seq == exp_seq
        if exp_ack is not None:
            rec["exp_ack"] = exp_ack; ok = ok and r.ack == exp_ack
        rec["ok"] = ok
        steps.append(rec)
        return r

    # resp#1 (54 B) padded by 7: master must still see seq 1000; delta_fwd -> 7
    run("resp#1 (pad 7)",
        Segment(F, Dir.FWD, seq=isn_fwd, ack=isn_rev, payload_len=54, insert=PAD),
        exp_seq=1000)
    # master acks padded stream (1000+54+7) -> outstation must see 1000+54
    run("master ack #1",
        Segment(F, Dir.REV, seq=isn_rev, ack=isn_fwd + 54 + PAD, payload_len=0),
        exp_ack=1054)
    # resp#2 at native 1054 -> master sees 1054+7 (prior delta); delta_fwd -> 14
    run("resp#2 (pad 7)",
        Segment(F, Dir.FWD, seq=isn_fwd + 54, ack=isn_rev, payload_len=54, insert=PAD),
        exp_seq=1061)
    # retransmit of resp#2 -> SAME wire seq, no double count
    run("resp#2 retransmit",
        Segment(F, Dir.FWD, seq=isn_fwd + 54, ack=isn_rev, payload_len=54, insert=PAD),
        exp_seq=1061)
    # out-of-order retransmit of resp#1 -> still maps to 1000
    run("resp#1 retransmit (OOO)",
        Segment(F, Dir.FWD, seq=isn_fwd, ack=isn_rev, payload_len=54, insert=PAD),
        exp_seq=1000)

    npass = sum(1 for s in steps if s["ok"])
    return {"suite": "transport_oracle demo", "pass": npass, "total": len(steps),
            "steps": steps}


if __name__ == "__main__":
    import sys
    summary = _demo()
    print(json.dumps(summary, indent=2))
    print(f"\nDEMO: {summary['pass']}/{summary['total']} mainline steps consistent")
    sys.exit(0 if summary["pass"] == summary["total"] else 1)

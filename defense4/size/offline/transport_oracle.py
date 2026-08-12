#!/usr/bin/env python3
"""Bounded offline oracle for the per-flow TCP sequence/ACK translation that DNP3
size obfuscation forces when the switch INSERTS bytes into a stream (response
padding on outstation->master, or SBO CROB expansion on master->outstation).

This is a transport-layer state machine only. It does NOT build DNP3 frames,
recompute CRCs, or fold TCP/IP checksums -- those live in sbo_oracle.py /
joint_transform_oracle.py / p4_egress_emulator.py. The single question here is:
after we add N bytes to one direction of a flow, can a BOUNDED amount of on-chip
state keep BOTH endpoints' TCP views (seq, cumulative ack, and the actual bytes
delivered) consistent across retransmits, resegmentation, dup-acks, out-of-order
delivery, teardown, tuple reuse, ownership aliasing, SACK, and sequence wrap --
and where it provably cannot, what is the safe, tested degraded behavior?

CENTRAL INVARIANT (redesigned 2026-08-11): the EMITTED BYTE STREAM.
An earlier version treated "do not double-count the cumulative offset on a
retransmit" as if it were retransmission safety, and reported `inserted=0` for a
retransmitted segment. That is a decisive bug: a retransmitted segment that does
NOT re-emit the inserted bytes leaves the receiver's transformed stream with a
hole. This model separates the two concepts explicitly:

  * committed_len -- new bytes added to the cumulative offset ledger. 0 on any
    retransmit (the boundary already exists; the offset must not grow again).
  * inserted_len  -- inserted bytes EMITTED on THIS packet. A retransmit that
    covers a committed boundary RE-EMITS the identical bytes, so this is > 0.

Correctness is judged by reconstructing the receiver-visible transformed stream
byte-for-byte from the per-packet `emitted` images (see stream_reconstruction.py),
not by trusting any single per-packet field.

Model summary (see README.md for the full write-up):
  * Two INDEPENDENT streams per flow: FWD = outstation->master, REV = master->outstation.
  * Each stream carries its own insertion ledger. A ledger entry records the
    original-sequence-space boundary, the insertion length, a template identity,
    and the owning generation -- enough to REPRODUCE the exact inserted bytes.
  * A packet flowing in direction D:
        seq' = seq + Delta_D(seq)          # its own stream was padded: add
        ack' = ack - Delta_opp(ack)        # it acks the OTHER stream: subtract
    and its data image is re-emitted with EVERY committed insertion whose original
    boundary lies in (segment_start, segment_end] -- one documented convention that
    makes exact, overlapping, and resegmented retransmits reproduce every insertion.

Run:  python3 transport_oracle.py            # scenario demo + gate verdict to stdout
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
# Reproducible byte generators -- the "template identity -> bytes" contract.
# Both the oracle's emitted image and the independent canonical reference call
# these, so the two agree on the CONTENT of an insertion while the oracle remains
# solely responsible for its PLACEMENT and re-emission.
# --------------------------------------------------------------------------- #
def render_insertion(template_id: int, size: int, boundary: int, generation: int) -> bytes:
    """Deterministic filler bytes for one committed insertion. Reproducible from the
    fields the ledger stores (template_id, size, boundary, generation)."""
    x = (template_id * 2654435761 + boundary * 40503 + generation * 97 + 0x9E3779B9) & 0xFFFFFFFF
    out = bytearray(size)
    for i in range(size):
        x = (x * 1103515245 + 12345) & 0x7FFFFFFF
        out[i] = (x >> 16) & 0xFF
    return bytes(out)


def default_orig_byte(direction: "Dir", off: int) -> int:
    """Deterministic 'original' payload byte at (direction, offset). A retransmit or
    resegmentation of the same original range yields identical bytes by construction,
    so any inconsistency in a test must be injected deliberately via Segment.payload."""
    # NB: compare by .value, not enum identity -- when this module is run as __main__
    # a helper module can re-import it as a second instance with a distinct Dir class.
    x = (off * 2246822519 + (7 if direction.value == Dir.FWD.value else 13)) & 0xFFFFFFFF
    x ^= (x >> 15)
    x = (x * 2654435761) & 0xFFFFFFFF
    x ^= (x >> 13)
    return x & 0xFF


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
    template_id: int = 0     # identity of the template to insert (reproduces the bytes)
    payload: Optional[bytes] = None   # explicit original bytes; None -> deterministic
    sack_permitted: bool = False      # did this flow negotiate SACK-permitted in SYN?
    sack: Optional[Tuple[int, int]] = None   # a single SACK block (left, right), wire space

    def plen(self) -> int:
        return len(self.payload) if self.payload is not None else self.payload_len


@dataclass(frozen=True)
class EmittedInsertion:
    """One inserted region actually placed on a packet's wire image."""
    boundary: int         # original-space boundary this insertion belongs to
    wire_off: int         # translated (padded-space) wire offset where the bytes start
    data: bytes           # the exact inserted bytes emitted
    template_id: int


class Outcome(Enum):
    NATIVE = "NATIVE"                              # no epoch, passed unchanged (safe)
    TRANSLATED = "TRANSLATED"                      # seq/ack translated, no new insertion
    TRANSLATED_INSERTED = "TRANSLATED_INSERTED"    # translated AND recorded a new boundary
    TRANSLATED_FROZEN = "TRANSLATED_FROZEN"        # epoch live, new insertion suppressed
    DENIED_COLLISION = "DENIED_COLLISION"          # slot owned by another flow -> stays native
    RETIRED = "RETIRED"                            # RST / both-FIN-acked: translated then freed


@dataclass
class Result:
    seq: int                       # translated wire seq
    ack: int                       # translated wire ack
    outcome: Outcome
    # -- the two separated accounting fields (the core of the redesign) --------
    committed_len: int = 0         # NEW bytes added to the cumulative offset (0 on retransmit)
    inserted_len: int = 0          # inserted bytes EMITTED on THIS packet (re-emit re-counts)
    newly_recorded: bool = False   # a boundary was newly committed this packet
    # -- the emitted byte-stream image ----------------------------------------
    emitted: bytes = b""           # full transformed data image emitted on this packet
    emitted_insertions: List[EmittedInsertion] = field(default_factory=list)
    # -- status flags ----------------------------------------------------------
    partial_ack: bool = False      # ack landed inside a pad region and was snapped
    frozen: bool = False           # translation/insertion was frozen or denied by policy
    denied: bool = False           # slot-collision denial (stayed native)
    retired: bool = False          # state was freed on this packet
    sack: Optional[Tuple[int, int]] = None   # translated SACK block, if the packet carried one
    note: str = ""


# --------------------------------------------------------------------------- #
# Insertion ledger -- the step function, in OFFSET space (anchored at the ISN)
# --------------------------------------------------------------------------- #
@dataclass
class Insertion:
    boundary: int       # offset; original bytes with offset >= boundary shift by +size
    size: int
    template_id: int    # reproduces the inserted bytes with render_insertion(...)


@dataclass
class Ledger:
    """One stream's insertion boundaries. Offsets are ints anchored at the ISN, so all
    step-function math is plain integer arithmetic; wire<->offset conversion (the only
    place mod-2^32 matters) is done by the Flow."""
    max_depth: int
    entries: List[Insertion] = field(default_factory=list)
    frozen: bool = False

    def total(self) -> int:
        return sum(e.size for e in self.entries)

    def empty(self) -> bool:
        return not self.entries

    def max_boundary(self) -> int:
        return max((e.boundary for e in self.entries), default=-1)

    def boundary_obj(self, boundary: int) -> Optional[Insertion]:
        for e in self.entries:
            if e.boundary == boundary:
                return e
        return None

    def delta_at(self, off: int) -> int:
        """Cumulative bytes inserted at boundaries <= off (forward seq translation)."""
        return sum(e.size for e in self.entries if e.boundary <= off)

    def translate_seq(self, off: int) -> int:
        return off + self.delta_at(off)

    def translate_ack(self, a_off: int) -> Tuple[int, bool]:
        """Inverse map for a cumulative ack expressed in PADDED (translated) offset
        space -> original offset. Returns (orig_off, partial) where partial=True means
        the ack landed strictly inside a pad region and was snapped to that insertion's
        boundary (a fractional ack of inserted bytes)."""
        cum = 0
        for e in sorted(self.entries, key=lambda x: x.boundary):
            tstart = e.boundary + cum          # translated start of this pad region
            if a_off <= tstart:                # ack is at/below this pad -> done
                return a_off - cum, False
            if a_off < tstart + e.size:        # ack lands inside the pad -> snap
                return e.boundary, True
            cum += e.size                      # ack is fully past this pad
        return a_off - cum, False

    def add(self, boundary: int, size: int, template_id: int) -> str:
        """Try to record a NEW insertion. Returns one of:
        'inserted'   -- a new boundary was committed.
        'idempotent' -- exact boundary already committed at the same size (retransmit).
        'frozen'     -- depth cap reached (or already frozen); nothing committed.
        'conflict'   -- boundary clashes with committed history (different size at a
                        known boundary, or a new boundary INSIDE already-committed range).
        A 'conflict'/'idempotent'/'frozen' never corrupts committed entries; those are
        still re-emitted on every overlapping segment by the emitter."""
        existing = self.boundary_obj(boundary)
        if existing is not None:
            return "idempotent" if existing.size == size else "conflict"
        if self.frozen or len(self.entries) >= self.max_depth:
            self.frozen = True
            return "frozen"
        if self.entries and boundary < self.max_boundary():
            # a brand-new insertion inside already-transformed history would require
            # re-numbering committed boundaries -> refuse it (coverage loss, never a
            # corruption). Committed boundaries in this range are still re-emitted.
            return "conflict"
        self.entries.append(Insertion(boundary, size, template_id))
        return "inserted"


# --------------------------------------------------------------------------- #
# Per-flow state
# --------------------------------------------------------------------------- #
class Flow:
    def __init__(self, full_key: object, generation: int, ledger_depth: int):
        self.full_key = full_key          # exact flow identity (P4 exact-match key)
        self.generation = generation
        self.isn: Dict[Dir, Optional[int]] = {Dir.FWD: None, Dir.REV: None}
        self.ledger: Dict[Dir, Ledger] = {
            Dir.FWD: Ledger(ledger_depth),
            Dir.REV: Ledger(ledger_depth),
        }
        # teardown bookkeeping: retain state until BOTH FINs are translated AND each
        # FIN is cumulatively acked in the opposite space (or a safe timeout).
        self.fin_seen: Dict[Dir, bool] = {Dir.FWD: False, Dir.REV: False}
        self.fin_off: Dict[Dir, Optional[int]] = {Dir.FWD: None, Dir.REV: None}
        self.fin_acked: Dict[Dir, bool] = {Dir.FWD: False, Dir.REV: False}
        self.teardown_deadline: Optional[int] = None
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
# Bounded flow table with owner verification + generation counter
# --------------------------------------------------------------------------- #
class FlowTable:
    """A hash-indexed flow table. Two ownership disciplines are modelled:

      verify_full_key=True (default, faithful to a P4 exact-match table): the FULL
      flow key is stored and compared on lookup, so a hash collision is DETECTED and
      the intruder is denied -- no false hit is possible.

      verify_full_key=False (adversarial 'hash-only' silicon): only a narrow compressed
      tag is compared. When two distinct keys share a slot AND a compressed tag, the
      match cannot tell them apart. The model, holding the true key, COUNTS such
      undetected false hits so the suite can flag hash-only ownership as a BLOCKING
      hardware limitation (rather than pretending Python object identity hides it)."""

    def __init__(self, size: int, ledger_depth: int,
                 hash_fn: Optional[Callable[[object], int]] = None,
                 compress_fn: Optional[Callable[[object], int]] = None,
                 verify_full_key: bool = True):
        self.size = size
        self.ledger_depth = ledger_depth
        self.slots: List[Optional[Flow]] = [None] * size
        self.gen = 0
        self.verify_full_key = verify_full_key
        self.false_hits_undetected = 0
        self._hash = hash_fn or (lambda f: zlib.crc32(repr(f).encode()) % size)
        # compressed owner tag: on silicon a narrow (e.g. 16-bit) value. Default here
        # is a real 16-bit CRC so 'hash-only' mode exhibits genuine tag aliasing.
        self._compress = compress_fn or (lambda f: zlib.crc32(repr(f).encode()) & 0xFFFF)

    def slot_of(self, flow: object) -> int:
        return self._hash(flow)

    def lookup(self, flow: object) -> Tuple[int, Optional[Flow], str]:
        """Return (idx, flow_state_or_None, status): 'own' | 'empty' | 'collision'."""
        idx = self.slot_of(flow)
        occ = self.slots[idx]
        if occ is None:
            return idx, None, "empty"
        if self.verify_full_key:
            matched = (occ.full_key == flow)
        else:
            matched = (self._compress(occ.full_key) == self._compress(flow))
        if matched:
            if occ.full_key != flow:
                # silicon proceeds as 'own' but it is a DIFFERENT real flow: an
                # undetected false hit. Recorded; this configuration is a blocking limit.
                self.false_hits_undetected += 1
            return idx, occ, "own"
        return idx, occ, "collision"

    def claim(self, flow: object) -> Flow:
        idx = self.slot_of(flow)
        self.gen += 1
        st = Flow(flow, self.gen, self.ledger_depth)
        self.slots[idx] = st
        return st

    def retire(self, flow: object) -> None:
        idx = self.slot_of(flow)
        occ = self.slots[idx]
        if occ is not None and occ.full_key == flow:
            self.slots[idx] = None

    def force_evict(self, flow: object) -> bool:
        """Reclaim a slot for reuse. An ACTIVE-EPOCH, non-retired flow is NON-evictable
        (evicting it would strand padded bytes with no delta -> the only alternative
        would be unsafe raw pass-through). Returns True only if it was safe to evict
        (empty, native, or already retired)."""
        idx = self.slot_of(flow)
        occ = self.slots[idx]
        if occ is None:
            return True
        if occ.full_key != flow:
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
                 compress_fn: Optional[Callable[[object], int]] = None,
                 verify_full_key: bool = True,
                 sack_policy: str = "reject",
                 retire_timeout: int = 64):
        assert sack_policy in ("reject", "translate")
        self.table = FlowTable(table_size, ledger_depth, hash_fn, compress_fn,
                               verify_full_key)
        self.sack_policy = sack_policy
        self.retire_timeout = retire_timeout
        self.clock = 0          # logical clock: one tick per processed segment
        # SYN-anchor cache: the switch always sees the handshake before any data, so a
        # direction's ISN is learned from its SYN/SYN-ACK. Consumed when the flow is
        # claimed. Bounded by concurrent handshakes, like the flow table itself.
        self._isn_hint: Dict[object, Dict[Dir, int]] = {}

    # -- test/introspection accessor -------------------------------------- #
    def flow(self, flow: object) -> Optional[Flow]:
        _, fl, status = self.table.lookup(flow)
        return fl if status == "own" else None

    # -- helpers ----------------------------------------------------------- #
    def _orig_bytes(self, seg: Segment, off: int) -> bytes:
        if seg.payload is not None:
            return seg.payload
        return bytes(default_orig_byte(seg.direction, off + i) for i in range(seg.plen()))

    def _translate(self, fl: Flow, seg: Segment) -> Tuple[int, int, bool]:
        """Apply the current ledgers to (seq, ack). Empty ledgers are the identity, so
        this is always safe to call and never needs an ISN we have not learned."""
        d = seg.direction
        seq_out, ack_out, partial = seg.seq, seg.ack, False

        led = fl.ledger[d]
        if not led.empty():
            fl.learn_isn(d, seg.seq)
            off = fl.to_off(d, seg.seq)
            seq_out = fl.to_wire(d, led.translate_seq(off))

        oled = fl.ledger[opp(d)]
        if not oled.empty() and fl.isn[opp(d)] is not None:
            a_off = fl.to_off(opp(d), seg.ack)
            o_off, partial = oled.translate_ack(a_off)
            ack_out = fl.to_wire(opp(d), o_off)

        return seq_out, ack_out, partial

    def _ack_orig_off(self, fl: Flow, seg: Segment) -> Optional[int]:
        """The opposite stream's ORIGINAL offset this segment cumulatively acks, or
        None if the opposite ISN is not yet known. Used for FIN-ack bookkeeping."""
        o = opp(seg.direction)
        if fl.isn[o] is None:
            return None
        a_off = fl.to_off(o, seg.ack)
        oled = fl.ledger[o]
        if oled.empty():
            return a_off
        orig, _ = oled.translate_ack(a_off)
        return orig

    def _translate_sack(self, fl: Flow, seg: Segment) -> Optional[Tuple[int, int]]:
        """Translate a SACK block's edges. A SACK acks the OPPOSITE stream, so its edges
        live in the same padded space as the cumulative ack and invert with the opposite
        ledger. Only used under sack_policy='translate'."""
        if seg.sack is None:
            return None
        o = opp(seg.direction)
        if fl.isn[o] is None:
            return seg.sack
        oled = fl.ledger[o]
        left, right = seg.sack
        if oled.empty():
            return (left, right)
        lo, _ = oled.translate_ack(fl.to_off(o, left))
        ro, _ = oled.translate_ack(fl.to_off(o, right))
        return (fl.to_wire(o, lo), fl.to_wire(o, ro))

    def _emit_segment(self, fl: Flow, seg: Segment, off: int
                      ) -> Tuple[bytes, List[EmittedInsertion]]:
        """Build the transformed data image for a segment covering original offsets
        [off, off+plen). Convention (SINGLE, documented): re-emit every committed
        insertion whose boundary b satisfies off < b <= off+plen -- an interior boundary
        is emitted immediately before its original byte; a tail boundary (b == off+plen)
        is emitted after the last original byte. A boundary at b == off belongs to the
        preceding segment, so it is NOT emitted here (no double emission across adjacent
        segments). This reproduces every committed insertion for exact, overlapping, and
        resegmented retransmits alike, and never silently suppresses one."""
        d = seg.direction
        plen = seg.plen()
        led = fl.ledger[d]
        orig = self._orig_bytes(seg, off)
        base_t = led.translate_seq(off)      # transformed offset of the first original byte
        out = bytearray()
        ins: List[EmittedInsertion] = []

        def emit_boundary(b: int) -> None:
            e = led.boundary_obj(b)
            if e is None:
                return
            data = render_insertion(e.template_id, e.size, e.boundary, fl.generation)
            wire_off = fl.to_wire(d, base_t + len(out)) if fl.isn[d] is not None else base_t + len(out)
            ins.append(EmittedInsertion(e.boundary, wire_off, data, e.template_id))
            out.extend(data)

        for i in range(plen):
            pos = off + i
            if i > 0:                        # interior boundary (b == pos, off < pos < end)
                emit_boundary(pos)
            out.append(orig[i])
        if plen > 0:                         # tail boundary (b == off+plen)
            emit_boundary(off + plen)
        return bytes(out), ins

    def _wrap_guard(self, fl: Flow, seg: Segment) -> bool:
        """True if a NEW insertion here would push this stream's in-use OFFSET span to or
        past WRAP_GUARD. Insertions are then refused (freeze) so to_off()'s modular
        subtraction stays unambiguous. An ordinary wire-seq wrap at a high ISN with a
        small offset is NOT affected -- translation handles that with mod32."""
        d = seg.direction
        off = 0 if fl.isn[d] is None else fl.to_off(d, seg.seq)
        end_off = off + seg.plen() + fl.ledger[d].total() + seg.insert
        return end_off >= WRAP_GUARD

    def _native(self, seg: Segment, note: str = "pre-epoch native pass",
                frozen: bool = False) -> Result:
        emitted = seg.payload if (seg.payload is not None and not frozen) else b""
        return Result(seg.seq, seg.ack, Outcome.NATIVE, emitted=emitted or b"",
                      frozen=frozen, note=note)

    def _denied(self, seg: Segment) -> Result:
        return Result(seg.seq, seg.ack, Outcome.DENIED_COLLISION, denied=True,
                      note="slot owned by another flow; intruder stays native")

    # -- main entry -------------------------------------------------------- #
    def process(self, seg: Segment) -> Result:
        self.clock += 1
        d = seg.direction
        o = opp(d)
        plen = seg.plen()

        # SYN: opens a connection. It is never inserted into and needs no translation
        # (pre-epoch), and it must NOT claim, retire, or mutate any existing state. A
        # slot still holding a quarantined/lingering flow (tuple reuse) is preserved,
        # so that old flow keeps translating its outstanding packets and its final ACK.
        if seg.flags.syn:
            # Anchor this direction's ISN for the NEXT epoch on this key, without
            # disturbing any live/quarantined state already in the slot.
            self._isn_hint.setdefault(seg.flow, {})[d] = seg.seq
            return self._native(seg, note="SYN: native; ISN anchored for this direction")

        idx, fl, status = self.table.lookup(seg.flow)
        if status == "collision":
            return self._denied(seg)

        wants_insert = seg.insert > 0 and not seg.flags.rst

        # No state yet.
        if fl is None:
            if not wants_insert:
                return self._native(seg)
            if self.sack_policy == "reject" and seg.sack_permitted:
                # STRICT eligibility: a SACK-capable connection is rejected BEFORE its
                # first insertion, so no post-insertion SACK can ever pass untranslated.
                return self._native(
                    seg, frozen=True,
                    note="SACK-permitted: insertion refused (ineligible), stays native")
            fl = self.table.claim(seg.flow)
            for hd, hseq in self._isn_hint.pop(seg.flow, {}).items():
                fl.isn[hd] = hseq          # seed ISN(s) learned from the handshake

        # RST -> translate this control segment with the CURRENT ledgers, then retire.
        if seg.flags.rst:
            seq_out, ack_out, partial = self._translate(fl, seg)
            sack_out = self._translate_sack(fl, seg)
            fl.retired = True
            self.table.retire(seg.flow)
            return Result(seq_out, ack_out, Outcome.RETIRED, retired=True,
                          partial_ack=partial, sack=sack_out,
                          note="RST: translated then state freed")

        fl.learn_isn(d, seg.seq)
        off = fl.to_off(d, seg.seq)

        # Decide on a NEW insertion (may be refused; committed insertions still re-emit).
        committed = 0
        newly = False
        note = ""
        if wants_insert:
            if self.sack_policy == "reject" and seg.sack_permitted:
                fl.ledger[d].frozen = True
                note = "SACK-permitted: new insertion refused (ineligible)"
            elif self._wrap_guard(fl, seg):
                fl.ledger[d].frozen = True
                note = "insertion refused (would wrap 2^32); frozen, still translating"
            else:
                boundary = off + plen
                st = fl.ledger[d].add(boundary, seg.insert, seg.template_id)
                if st == "inserted":
                    committed = seg.insert
                    newly = True
                elif st == "idempotent":
                    note = "retransmit at a committed boundary: re-emit, no new offset"
                elif st == "frozen":
                    note = "ledger depth cap reached; frozen, still translating & re-emitting"
                elif st == "conflict":
                    note = ("resegmentation/size-conflict at/into committed history; "
                            "not newly committed, committed insertions still re-emitted")

        # Translate seq/ack, then build the emitted data image (re-emits committed
        # insertions in (off, off+plen] -- this is what makes a retransmit safe).
        seq_out, ack_out, partial = self._translate(fl, seg)
        sack_out = self._translate_sack(fl, seg)
        emitted, ins = self._emit_segment(fl, seg, off)
        inserted_len = sum(len(e.data) for e in ins)

        # FIN bookkeeping. A FIN consumes the sequence number AFTER its payload.
        if seg.flags.fin:
            fl.fin_seen[d] = True
            fl.fin_off[d] = off + plen
        # Does this segment cumulatively ack the OPPOSITE side's FIN?
        o_off = self._ack_orig_off(fl, seg)
        if fl.fin_seen[o] and o_off is not None and fl.fin_off[o] is not None \
                and o_off >= fl.fin_off[o] + 1:
            fl.fin_acked[o] = True
        # Arm the safe-retirement timeout once both FINs are seen.
        if fl.fin_seen[Dir.FWD] and fl.fin_seen[Dir.REV] and fl.teardown_deadline is None:
            fl.teardown_deadline = self.clock + self.retire_timeout

        both_acked = fl.fin_acked[Dir.FWD] and fl.fin_acked[Dir.REV]
        timed_out = (fl.teardown_deadline is not None and self.clock >= fl.teardown_deadline)
        if fl.fin_seen[Dir.FWD] and fl.fin_seen[Dir.REV] and (both_acked or timed_out):
            fl.retired = True
            self.table.retire(seg.flow)
            why = "both FINs acked" if both_acked else "safe retirement timeout"
            return Result(seq_out, ack_out, Outcome.RETIRED, retired=True,
                          committed_len=committed, inserted_len=inserted_len,
                          newly_recorded=newly, emitted=emitted, emitted_insertions=ins,
                          partial_ack=partial, sack=sack_out, note=f"retired: {why}")

        # Outcome classification for a still-live flow.
        if newly:
            outcome = Outcome.TRANSLATED_INSERTED
        elif fl.ledger[d].frozen and wants_insert:
            outcome = Outcome.TRANSLATED_FROZEN
        elif fl.epoch_begun():
            outcome = Outcome.TRANSLATED
        else:
            outcome = Outcome.TRANSLATED_FROZEN if wants_insert else Outcome.NATIVE
        return Result(seq_out, ack_out, outcome, committed_len=committed,
                      inserted_len=inserted_len, newly_recorded=newly, emitted=emitted,
                      emitted_insertions=ins, partial_ack=partial,
                      frozen=fl.ledger[d].frozen and wants_insert, sack=sack_out, note=note)


# --------------------------------------------------------------------------- #
# Scenario demo -- exercises the mainline path AND the byte-stream invariant, then
# prints a machine-readable summary. The authoritative adversarial checks (and the
# per-area transport-gate verdict) live in test_transport_oracle.py.
# --------------------------------------------------------------------------- #
def _demo() -> dict:
    from stream_reconstruction import StreamReassembler, build_canonical

    PAD = 7
    o = TransportOracle(table_size=64, ledger_depth=4)
    F = "flowA"
    isn_fwd, isn_rev = 1000, 5000
    steps: List[dict] = []
    reasm = StreamReassembler(isn_fwd)

    def run(label, seg, exp_seq=None, exp_ack=None):
        r = o.process(seg)
        reasm.deliver(r.seq, r.emitted)
        rec = {
            "step": label, "dir": seg.direction.name,
            "in_seq": seg.seq, "in_ack": seg.ack,
            "out_seq": r.seq, "out_ack": r.ack, "outcome": r.outcome.value,
            "committed": r.committed_len, "emitted_inserted": r.inserted_len,
        }
        ok = True
        if exp_seq is not None:
            rec["exp_seq"] = exp_seq; ok = ok and r.seq == exp_seq
        if exp_ack is not None:
            rec["exp_ack"] = exp_ack; ok = ok and r.ack == exp_ack
        rec["ok"] = ok
        steps.append(rec)
        return r

    run("resp#1 (pad 7)",
        Segment(F, Dir.FWD, seq=isn_fwd, ack=isn_rev, payload_len=54, insert=PAD),
        exp_seq=1000)
    run("master ack #1",
        Segment(F, Dir.REV, seq=isn_rev, ack=isn_fwd + 54 + PAD, payload_len=0),
        exp_ack=1054)
    run("resp#2 (pad 7)",
        Segment(F, Dir.FWD, seq=isn_fwd + 54, ack=isn_rev, payload_len=54, insert=PAD),
        exp_seq=1061)
    # retransmit of resp#2 -> SAME wire seq, RE-EMITS the pad, offset NOT double-counted
    rr = run("resp#2 retransmit",
             Segment(F, Dir.FWD, seq=isn_fwd + 54, ack=isn_rev, payload_len=54, insert=PAD),
             exp_seq=1061)
    run("resp#1 retransmit (OOO)",
        Segment(F, Dir.FWD, seq=isn_fwd, ack=isn_rev, payload_len=54, insert=PAD),
        exp_seq=1000)

    # byte-stream invariant: the reconstructed FWD stream equals ONE canonical stream.
    canon = build_canonical(Dir.FWD, 108, [(54, PAD, 0), (108, PAD, 0)], generation=1)
    data, gaps = reasm.reconstruct()
    recon_ok = (data == canon and not gaps and not reasm.conflicts)

    npass = sum(1 for s in steps if s["ok"])
    return {
        "suite": "transport_oracle demo",
        "pass": npass, "total": len(steps), "steps": steps,
        "retransmit_reemits_pad": rr.inserted_len == PAD and rr.committed_len == 0,
        "reconstruction_byte_exact": recon_ok,
    }


if __name__ == "__main__":
    import sys
    summary = _demo()
    print(json.dumps(summary, indent=2))
    ok = (summary["pass"] == summary["total"]
          and summary["retransmit_reemits_pad"]
          and summary["reconstruction_byte_exact"])
    print(f"\nDEMO: {summary['pass']}/{summary['total']} mainline steps consistent; "
          f"retransmit re-emits pad={summary['retransmit_reemits_pad']}; "
          f"reconstruction byte-exact={summary['reconstruction_byte_exact']}")
    sys.exit(0 if ok else 1)

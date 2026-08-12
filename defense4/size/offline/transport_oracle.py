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

TRANSPORT-SAFETY REPAIRS (2026-08-11): a follow-up audit found the "46/46 PASS" was
false-green -- several safety-critical hazards were unhandled or mis-tested. Repaired here,
each with a regression that fails on the pre-repair source and a source mutation that kills
a named test (see test_transport_repairs.py + mutation_harness.py):
  1. Concurrent 5-tuple reuse. A reused-tuple SYN opens a NEW connection while the old
     epoch is still quarantined. The exact-key lookup returns the OLD Flow, so new-epoch
     data was translated with the OLD ledger (seq 9001 -> 9008). Now a reuse-aware SYN
     anchors the new incarnation and a per-packet epoch discriminator FAILS CLOSED: a
     new-incarnation packet is passed native (no coverage) until the old epoch retires;
     old lingering packets keep translating.
  2. Template conflict. A committed boundary with the SAME size but a DIFFERENT template_id
     is a CONFLICT (two insertions claiming one boundary), never a silent re-emit of the
     stale template.
  3. SACK eligibility is LEARNED from the SYN/SYN-ACK options and RETAINED per epoch. A
     later data segment does not carry the option, so the data segment's field is never
     trusted for eligibility.
  4. Retirement has a wall-clock / sweepable horizon (`sweep()`), so a flow that receives
     no further packet is still reclaimable -- the per-segment logical clock alone could
     leak state on a silent flow.
  5. Delayed duplicates after retirement are quarantined (TIME_WAIT tombstone): a delayed
     duplicate of a retired epoch passes native and can NOT spawn a phantom epoch.

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
            # A genuine retransmit re-derives the SAME template (deterministic from the
            # flow/boundary), so an already-committed boundary is idempotent ONLY when both
            # size AND template match. A different template_id (or size) at a committed
            # boundary is two distinct insertions claiming one boundary -> a conflict, never
            # a silent re-emit of the stale template.
            if existing.size == size and existing.template_id == template_id:
                return "idempotent"
            return "conflict"
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
        # SACK-permitted is negotiated in the SYN/SYN-ACK options and RETAINED per epoch;
        # a later data segment never carries it, so it is never trusted from data.
        self.sack_permitted = False
        # Tuple-reuse quarantine: a reused-tuple SYN seen while THIS epoch is still live
        # anchors the NEXT incarnation's ISN(s) without disturbing this state.
        self.reuse_isn: Dict[Dir, Optional[int]] = {Dir.FWD: None, Dir.REV: None}
        self.reuse_pending = False
        # Highest original offset legitimately reached per direction (the old-epoch window
        # edge, used to tell a lingering old packet from a new incarnation's packet).
        self.max_off_seen: Dict[Dir, int] = {Dir.FWD: 0, Dir.REV: 0}
        # Wall-clock of the last packet that belonged to THIS epoch (drives the idle sweep).
        self.last_seen = 0

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
                 retire_timeout: int = 64,
                 idle_horizon: int = 1 << 30,
                 time_wait: int = 1 << 20,
                 reuse_inflight_window: int = 1 << 16):
        assert sack_policy in ("reject", "translate")
        self.table = FlowTable(table_size, ledger_depth, hash_fn, compress_fn,
                               verify_full_key)
        self.sack_policy = sack_policy
        self.retire_timeout = retire_timeout
        # idle_horizon: wall-clock idleness after which sweep() reclaims a flow regardless
        #   of FIN state (the sweepable horizon; without it a silent flow leaks forever).
        # time_wait: how long a retired tuple keeps a tombstone to quarantine delayed dups.
        # reuse_inflight_window: how far past the old epoch's high-water an old lingering
        #   packet may still legitimately sit (a classic receive window); anything beyond it
        #   in a reuse/time-wait situation is treated as a new incarnation and failed closed.
        self.idle_horizon = idle_horizon
        self.time_wait = time_wait
        self.reuse_inflight_window = reuse_inflight_window
        self.clock = 0          # logical clock: one tick per processed segment
        self.wall = 0           # monotonic wall clock (set from process(now=)/sweep(now=))
        # SYN-anchor cache: the switch always sees the handshake before any data, so a
        # direction's ISN is learned from its SYN/SYN-ACK. Consumed when the flow is
        # claimed. Bounded by concurrent handshakes, like the flow table itself.
        self._isn_hint: Dict[object, Dict[Dir, int]] = {}
        # SACK-permitted learned at the handshake, keyed by flow, consumed at claim.
        self._sack_hint: Dict[object, bool] = {}
        # TIME_WAIT tombstones for just-retired tuples: full_key -> snapshot for delayed-dup
        # quarantine. Bounded by time_wait * arrival rate; purged by sweep().
        self._tombstones: Dict[object, dict] = {}

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

    # -- wall clock / retirement horizon ---------------------------------- #
    def _touch_wall(self, now: Optional[int]) -> None:
        if now is not None:
            self.wall = max(self.wall, now)     # monotonic: never step backward

    def _snapshot_tombstone(self, fl: Flow) -> None:
        """Record a lightweight TIME_WAIT tombstone for a just-retired tuple so delayed
        duplicates of the old epoch can be quarantined (native) rather than spawning a
        phantom epoch. Carries the reuse ISN(s) so a genuine new incarnation still claims."""
        self._tombstones[fl.full_key] = {
            "gen": fl.generation,
            "isn": dict(fl.isn),
            "reuse_isn": dict(fl.reuse_isn),
            "hw": dict(fl.max_off_seen),
            "wall": self.wall,
        }

    def sweep(self, now: Optional[int] = None) -> List[object]:
        """Reclaim flows idle past the wall-clock horizon, regardless of FIN state -- the
        sweepable horizon a P4 control plane provides. A flow that receives no further
        packet is still reclaimable, so state cannot leak on a silent flow. Also purges
        expired tombstones. Returns the reclaimed flow keys."""
        self._touch_wall(now)
        reclaimed: List[object] = []
        for idx, occ in enumerate(self.table.slots):
            if occ is not None and self.wall - occ.last_seen >= self.idle_horizon:
                occ.retired = True
                self._snapshot_tombstone(occ)
                self.table.slots[idx] = None
                reclaimed.append(occ.full_key)
        for k in [k for k, t in self._tombstones.items()
                  if self.wall - t["wall"] >= self.time_wait]:
            self._tombstones.pop(k, None)
        return reclaimed

    def _reuse_is_new_incarnation(self, fl: Flow, seg: Segment) -> bool:
        """During reuse-pending quarantine, decide whether this packet belongs to the NEW
        incarnation (must be failed closed to native) rather than the OLD quarantined epoch.
        A packet is NEW iff it is nearer the anchored new-incarnation ISN than the old ISN
        (when that direction has a new anchor), or it sits beyond the old epoch's plausible
        in-flight window. Otherwise it is an old lingering packet and is translated."""
        d = seg.direction
        isn_old = fl.isn[d]
        if isn_old is None:
            return True                          # cannot old-translate this dir -> fail closed
        off_old = mod32(seg.seq - isn_old)
        isn_new = fl.reuse_isn.get(d)
        if isn_new is not None and mod32(seg.seq - isn_new) < off_old:
            return True                          # nearer the new incarnation's ISN
        if off_old > fl.max_off_seen[d] + self.reuse_inflight_window:
            return True                          # beyond any plausible old lingering packet
        return False

    def _tombstone_is_delayed_dup(self, seg: Segment) -> bool:
        """A non-SYN packet on a just-retired tuple is a delayed duplicate (native, no new
        epoch) iff its seq lies inside the retired epoch's window and it is not nearer a
        recorded new-incarnation ISN. An expired tombstone is dropped and does not block."""
        d = seg.direction
        tomb = self._tombstones.get(seg.flow)
        if tomb is None:
            return False
        if self.wall - tomb["wall"] >= self.time_wait:
            self._tombstones.pop(seg.flow, None)
            return False
        isn_old = tomb["isn"].get(d)
        if isn_old is None:
            return False
        off_old = mod32(seg.seq - isn_old)
        isn_new = tomb["reuse_isn"].get(d)
        if isn_new is not None and mod32(seg.seq - isn_new) < off_old:
            return False                         # a genuine new incarnation -> allow claim
        return off_old <= tomb["hw"].get(d, 0) + self.reuse_inflight_window

    # -- main entry -------------------------------------------------------- #
    def process(self, seg: Segment, now: Optional[int] = None) -> Result:
        self.clock += 1
        self._touch_wall(now)
        d = seg.direction
        o = opp(d)
        plen = seg.plen()

        # SYN: opens a connection. It is never inserted into and needs no translation
        # (pre-epoch), and it must NOT claim, retire, or mutate any existing DATA state.
        if seg.flags.syn:
            _, syn_fl, syn_status = self.table.lookup(seg.flow)
            if syn_status == "own" and syn_fl is not None \
                    and syn_fl.epoch_begun() and not syn_fl.retired:
                # Tuple reuse while the old epoch is still quarantined: anchor the NEXT
                # incarnation's ISN for this direction WITHOUT disturbing live state, and
                # arm the per-packet epoch discriminator.
                syn_fl.reuse_isn[d] = seg.seq
                syn_fl.reuse_pending = True
                self._isn_hint.setdefault(seg.flow, {})[d] = seg.seq
                if seg.sack_permitted:
                    self._sack_hint[seg.flow] = True
                return self._native(seg, note="SYN: tuple reuse; old epoch quarantined, "
                                              "new incarnation ISN anchored")
            # Normal pre-epoch SYN/SYN-ACK: anchor ISN + LEARN SACK-permitted for the next
            # epoch, and clear any tombstone (a real new connection supersedes TIME_WAIT).
            self._isn_hint.setdefault(seg.flow, {})[d] = seg.seq
            if seg.sack_permitted:
                self._sack_hint[seg.flow] = True
            self._tombstones.pop(seg.flow, None)
            return self._native(seg, note="SYN: native; ISN anchored for this direction")

        idx, fl, status = self.table.lookup(seg.flow)
        if status == "collision":
            return self._denied(seg)

        # Tuple-reuse quarantine: while an old epoch is live and a reused-tuple SYN has
        # been seen, a NEW-incarnation packet must NEVER be translated with the old ledger.
        if fl is not None and fl.reuse_pending and self._reuse_is_new_incarnation(fl, seg):
            return self._native(seg, note="tuple-reuse quarantine: new incarnation passed "
                                          "native (no coverage until old epoch retires)")

        # TIME_WAIT quarantine: a delayed duplicate of a just-retired epoch passes native
        # and must NOT spawn a phantom epoch. A seq outside the old window (a genuine new
        # incarnation) falls through to normal claiming.
        if fl is None and self._tombstone_is_delayed_dup(seg):
            return self._native(seg, note="TIME_WAIT: delayed duplicate of a retired epoch "
                                          "passed native (no new epoch)")

        wants_insert = seg.insert > 0 and not seg.flags.rst

        # No state yet.
        if fl is None:
            if not wants_insert:
                return self._native(seg)
            learned_sack = self._sack_hint.get(seg.flow, False)
            if self.sack_policy == "reject" and learned_sack:
                # STRICT eligibility, keyed on the HANDSHAKE-learned option (never the data
                # segment): a SACK-capable connection is rejected BEFORE its first insertion,
                # so no post-insertion SACK can ever pass untranslated.
                return self._native(
                    seg, frozen=True,
                    note="SACK-permitted (learned at handshake): insertion refused "
                         "(ineligible), stays native")
            fl = self.table.claim(seg.flow)
            for hd, hseq in self._isn_hint.pop(seg.flow, {}).items():
                fl.isn[hd] = hseq          # seed ISN(s) learned from the handshake
            fl.sack_permitted = self._sack_hint.pop(seg.flow, False)   # retained per epoch
            self._tombstones.pop(seg.flow, None)

        fl.last_seen = self.wall           # this packet belongs to (or opens) THIS epoch

        # RST -> translate this control segment with the CURRENT ledgers, then retire.
        if seg.flags.rst:
            seq_out, ack_out, partial = self._translate(fl, seg)
            sack_out = self._translate_sack(fl, seg)
            fl.retired = True
            self._snapshot_tombstone(fl)
            self.table.retire(seg.flow)
            return Result(seq_out, ack_out, Outcome.RETIRED, retired=True,
                          partial_ack=partial, sack=sack_out,
                          note="RST: translated then state freed")

        fl.learn_isn(d, seg.seq)
        off = fl.to_off(d, seg.seq)
        fl.max_off_seen[d] = max(fl.max_off_seen[d], off + plen)

        # Decide on a NEW insertion (may be refused; committed insertions still re-emit).
        committed = 0
        newly = False
        note = ""
        if wants_insert:
            if self.sack_policy == "reject" and fl.sack_permitted:
                fl.ledger[d].frozen = True
                note = "SACK-permitted (learned): new insertion refused (ineligible)"
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
                    note = ("boundary conflict (different size/template, or new insert into "
                            "committed history); not newly committed, committed insertions "
                            "still re-emitted")

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
            self._snapshot_tombstone(fl)
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

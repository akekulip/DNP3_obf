# Option B hardware feasibility — does the padding need the same mapper that failed for M?

Scope: this analysis is derived from reading the existing software oracle
(`framework/size/case4_transport.py`, `case4_padding.py`) directly, not from a P4 implementation attempt or
a compile. It answers the architectural question a P4 implementation attempt would otherwise have to
discover the hard way. The actual register count and stage cost still need a real compile to confirm — that
is the explicit next step this document recommends, not something it claims to have measured.

## Headline finding

**Yes, Option B's padding needs state of the same KIND as M's problem — per-connection state, read on
(almost) every packet, written at an insertion event — because that is a property of inserting bytes into a
TCP byte stream, not a property of any particular DNP3 role. But the SCALE is different for the two roles
Option B must cover, and for one of them (SELECT/OPERATE) the shape is structurally more favorable than
M's wall. For the other (READ), the existing software design does not directly apply and a different,
likely simpler design is needed.**

## Why the state is unavoidable (not a design choice)

Once a padded response is sent, every later packet in **both directions** of that TCP connection must be
translated against the inserted delta for as long as the connection lives:
- Forward direction: any later segment's sequence number must be computed as native-offset plus the sum of
  all deltas committed so far (`RequestLedger._wire_offset`).
- Reverse direction: any ACK number or window edge arriving from the far end references the *wire* sequence
  space, and must be translated back to the *native* space the sender's own retransmission logic expects
  (`RequestLedger._native_offset`, `.reverse()`). This happens on every ACK the far end sends, not just once.

This is a basic consequence of modifying a byte stream's length mid-connection — TCP has no notion of "this
one packet was bigger, but ignore that from now on." Any mechanism that pads a response, in the switch or
anywhere else, inherits this. It is not specific to G12V1 objects, DNP3, or the particular codec used here.

## Why SELECT/OPERATE's version of this is smaller than M's problem

`case4_transport.py`'s `RequestLedger` already solves exactly this for the SELECT/OPERATE case, in software,
proven (37/37 tests including `test_case4_transport.py`'s 12 bounded-transport cases). Reading its actual
design (`ControlConnection`, `RequestLedger.__init__`/`.forward`/`.reverse`):

- **At most 2 images per connection** (`len(self.entries) < 2` gates every new insertion). `ControlConnection`
  is explicitly built for "one native-CROB/one-decoy SELECT then matching OPERATE" — a single SBO pair, not
  unbounded repeated insertions.
- Both the forward-direction translation (`_wire_offset`, a sum over ≤2 entries) and the reverse-direction
  translation (`_native_offset`, a scan over the same ≤2 entries) consult the **same small table** — there is
  one place state lives, read by both directions' logic.
- This is structurally different from M's four-register wall: M failed because it had **four separate
  registers**, each with its **own independent** early-reader/late-writer stage conflict (an early cheap
  check wanting an early stage, a late update wanting a late stage, repeated four times over). Here, there
  is **one** small per-connection table (bounded at 2 entries), consulted the same way by both the forward
  and reverse paths — a single state structure, not four competing ones. That does not guarantee it compiles
  in the pipe's remaining stage budget, but it is not the same multi-way conflict that refuted M's mapper.
- A Tofino realization would not need to store `Image` objects as the software does; a fixed-width register
  pair per connection (e.g. `delta_total`, `boundary_offset` for up to 2 commit events) is a plausible,
  much smaller encoding than the software's general list structure. This is an inference from the software's
  own bound (≤2 entries), not a P4 design that has been written or compiled.

**Conclusion for SELECT/OPERATE: likely cheaper than M's four-register problem, because the state is
singular and bounded rather than four-way and conflicting — but unverified without an actual compile
attempt, and "likely cheaper" is not "free."**

## Why READ's version of this is a different, currently-undesigned problem

Option A let READ stay completely untouched (already native at the 49B target, no transform). Option B
needs READ padded too (49B → 58B), and this is **new** — no existing software codec handles it, and the
existing `RequestLedger`/`ControlConnection` design is explicitly scoped to a **one-shot SBO pair per
connection**, not to a role that may poll **repeatedly** on a single long-lived connection.

If READ padding must happen on every READ response for the life of a connection (not just once), the
existing capped-at-2-entries design does not apply as-is — a connection with many READ polls would need
many more than 2 tracked images under the current `RequestLedger` shape. Two paths forward, neither
implemented yet:

1. **A fixed, repeatable per-poll delta** (every READ response gets padded by the same, predetermined byte
   count, since the common pattern already fixes READ's response at 49B native → 58B target, a constant
   +9B every time): this can likely be realized as a single **monotonically incrementing cumulative-offset
   register per connection** (incremented by the same fixed amount on every READ response, consulted by both
   directions' translation the same way `RequestLedger` does) rather than a bounded list of distinct images.
   This is simpler than the SELECT/OPERATE case, not harder, because every insertion is identical and the
   state collapses to one running counter instead of a list.
2. **Reuse/extend the existing `RequestLedger` design to drop its 2-entry cap** and generalize it to an
   unbounded sequence of identical-delta insertions — more code, but conceptually the same mechanism.

Path 1 is the one worth attempting first: it is a smaller hardware problem than the general SELECT/OPERATE
ledger, not a larger one, precisely because every READ insertion is the same fixed size.

**2026-10-08 correction, confirmed by external review and verified against this project's own transport
model:** the single-counter sketch above is necessary but not sufficient. It tracks only the cumulative
byte offset, not which exact bytes were already rewritten at each point in the stream. It does not by
itself account for (a) retransmissions of an already-padded response needing byte-for-byte identical
replay (not re-padding) of what the real master already received once, (b) a partial ACK that leaves a
padded response only partly acknowledged, forcing the mapper to resume mid-insertion, or (c) either
receive-window edge capping how much of a padded response is reachable at a given moment. A sound design
needs a full per-connection transport-sequence state machine tracking inserted-byte regions by absolute
sequence number — the same class of model `case4_transport.py`'s existing `RequestLedger`/`Image`/`Forward`
already implements in bounded form for the one-shot SBO case — not a single scalar counter. Treat this as
a first-pass sketch, not a sufficient design, before any P4 realization is attempted.

## What this means for the combined Option B mechanism

- **Carve/PRE machinery is not needed at all under Option B** (no splitting) — this removes the RID-driven
  egress complexity that Option A's design carried, a genuine simplification relative to Option A.
- **Ingress-side DNP3 CRC validation**, which `HARDWARE_FEASIBILITY_ANALYSIS.md` found accounts for 7 of
  `protocol/padding.p4`'s 11 standalone ingress stages, may not be strictly required for a from-scratch
  Option B design if the padding target object's CRC can be precomputed at compile time (a known, fixed
  filler object, not a value that depends on run-time content) — this needs to be checked against the actual
  DNP3 CRC algorithm's linearity properties before assuming it, not assumed here.
- **The state that matters is the sequence/ACK/window translation register(s)**, not the padding action
  itself (appending bytes and fixing lengths is a deparser-level operation with no persistent state). The
  translation register(s) must be consulted on every packet in the connection after the first insertion,
  which is an ingress (or ingress-adjacent) concern regardless of where the padding itself happens.

## Honest status

This is a reasoned estimate from reading the software oracle's actual design, not a measurement. It has
**not** been checked against an actual P4 attempt or compile. The next concrete step (not performed here):
attempt a minimal P4 realization of the single-running-counter design for READ and the bounded-2-entry
design for SELECT/OPERATE, compile both, and report real stage/PHV numbers — the same discipline used for
every other feasibility claim in this effort. Two prior attempts to produce this exact report via a dispatched
agent were interrupted before producing one (a context budget cutoff mid-write, then a content-safety
classifier stop on an unrelated phrasing issue, neither a finding about the technical question); this
document was written directly from the source code to avoid a third stall, and should be treated as a
reasoned architectural read, not a substitute for the compile attempt it recommends.

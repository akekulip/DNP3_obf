# Transport-translation oracle (offline, bounded)

`transport_oracle.py` + `stream_reconstruction.py` + `test_transport_oracle.py` +
`test_transport_repairs.py` + `mutation_harness.py` + `gate_a.py`.

When the size defense **inserts bytes** into a TCP stream (padding a response on the
outstation->master direction, or expanding a SELECT/OPERATE with inert decoy CROBs on
master->outstation), the two endpoints' TCP sequence spaces stop agreeing. The switch must
translate every seq/ack afterward, and re-emit the inserted bytes on every copy of a segment,
so an **unmodified** master and outstation each still see one consistent byte stream. This is an
offline, hardware-free model of that translation as a bounded per-flow state machine, plus an
adversarial suite and a byte-level reconstruction oracle that check the receiver's view stays
consistent under the hazards a real link produces.

It is transport-only. DNP3 frame building, CRC-16/DNP, and TCP/IP checksum folding live in
`sbo_oracle.py`, `joint_transform_oracle.py`, and `p4_egress_emulator.py`. No P4 is touched.

## Why this was redesigned (2026-08-11)

An audit found a decisive bug in the previous version. On an already-existing insertion
boundary, the code returned an idempotent ledger result but set `inserted=0`, so a
**retransmitted** segment did not re-emit the inserted bytes. "No re-insertion" is not
retransmission safety: if a retransmit does not re-carry the pad, the receiver's transformed
stream ends up with a hole. The previous 19-test suite passed only because it never checked the
re-emitted bytes on a retransmit — one test even asserted `inserted == 0` on the retransmit,
enshrining the bug as correct.

The redesign is built around an **emitted byte-stream invariant** and separates the two ideas the
old code conflated:

- `committed_len` — new bytes added to the cumulative offset. **0 on any retransmit** (the
  boundary already exists; the offset must not grow again).
- `inserted_len` — inserted bytes **emitted on this packet**. A retransmit that covers a
  committed boundary **re-emits the identical bytes**, so this is `> 0`.

Correctness is judged by reconstructing the receiver-visible stream **byte-for-byte** from the
per-packet `emitted` images, not by trusting any single field.

## Transport-safety repairs (2026-08-12)

A second audit found the earlier **"46/46 gate PASS" was false-green**: the suite never exercised
several safety-critical transport hazards, so a passing run said nothing about them. Reproduced
against the unmodified source, five defects were live. Each is now repaired, each carries a
regression that **fails on the pre-repair behavior** (proven mechanically by the mutation harness,
which reverts the fix and shows a named test die), and each is driven through the mechanism that
actually exists on the wire, not a data-segment field.

1. **Concurrent 5-tuple reuse.** A reused-tuple SYN opens a *new* connection while the old epoch
   is still quarantined. The exact-key lookup returns the OLD `Flow`, so new-epoch data was
   translated with the OLD ledger (seq `9001` → `9008`, corrupting the fresh connection). A reuse-
   aware SYN now anchors the new incarnation's ISN, and a per-packet **epoch discriminator fails
   closed**: a new-incarnation packet is passed native (no coverage) until the old epoch retires,
   while old lingering packets keep translating. Both coexisting cases are tested.
2. **Template conflict.** A committed boundary re-hit with the same size but a **different
   `template_id`** is a CONFLICT (two insertions claiming one boundary), never a silent re-emit of
   the stale template.
3. **SACK eligibility is LEARNED at the SYN/SYN-ACK and RETAINED per epoch.** A later data segment
   carries no SACK option, so its `sack_permitted` field is **never trusted** for eligibility.
4. **Retirement has a wall-clock / sweepable horizon** (`oracle.sweep(now)`): a flow that receives
   no further packet is still reclaimable. The per-segment logical clock alone leaked such state.
5. **Delayed duplicates after retirement are quarantined** (a TIME_WAIT tombstone): a delayed
   duplicate of a retired epoch passes native and can **not** spawn a phantom translated epoch.

## The model

Two **independent** streams per flow: `FWD` = outstation->master (responses), `REV` =
master->outstation (requests). Each stream owns an insertion **ledger**. A ledger entry records
the **original-sequence-space boundary**, the **insertion length**, a **template identity**, and
the owning **generation** — enough to *reproduce the exact inserted bytes*. For a segment flowing
in direction `D`:

```
seq' = seq + Delta_D(seq)      # its own stream was padded  -> add
ack' = ack - Delta_opp(ack)    # it acknowledges the OTHER stream -> subtract
```

and its data image is re-emitted with **every committed insertion whose original boundary `b`
lies in `(segment_start, segment_end]`** — one documented convention (a boundary at the segment
start belongs to the preceding segment; a tail boundary belongs to this one). That single rule is
what makes exact, overlapping, and resegmented retransmits each reproduce every insertion exactly
once, with no double emission across adjacent segments.

Each processed segment reports, separately: translated `seq`, translated `ack`, whether a boundary
was **newly recorded**, the **insertion bytes emitted on this packet** (`emitted_insertions` /
`inserted_len`), and whether translation was **frozen / denied / retired**.

## Demonstrated-model behavior (what the suites prove)

Two suites, **84 tests total**, run by `gate_a.py`. The legacy suite
(`test_transport_oracle.py --json`, 46 tests) covers `retx`, `overlap`, `recon`, `teardown`,
`owner`, `sack`, `seqack`, `degrade`. The repair suite (`test_transport_repairs.py --json`,
38 tests) adds the areas the false-green missed:

| Area | What it proves | Result |
|------|----------------|--------|
| `reuse` | the mandatory counterexample: new-epoch data on a reused tuple is **never** translated with the old ledger (stays `9001`, not `9008`); a new-incarnation insert is failed **closed**; old lingering packets still translate and reconstruct byte-exact; after the old epoch retires the new incarnation claims a fresh generation | PASS (5) |
| `template` | same boundary+size, **different `template_id`** is a CONFLICT, not idempotent; the committed template is what re-emits; reconstruction stays consistent with the committed plan | PASS (3) |
| `sacklearn` | eligibility **learned** at the SYN and at the SYN-ACK direction, **retained** per epoch; a lying data-segment field is ignored either way | PASS (4) |
| `sweep` | a wall-clock horizon reclaims a **silent** flow and a **mid-epoch flow with no FIN**; a recently-seen flow survives; expired tombstones are purged | PASS (4) |
| `timewait` | a delayed duplicate after RST or full teardown is quarantined to native (no phantom epoch); a genuine new incarnation still claims; the tombstone expires | PASS (4) |
| `fin` | FIN each side, ack of each FIN, **final ACK translated (de-shifted, not native)**; half-close data still translated | PASS (2) |
| `rst` | RST translate-before-retire, both directions (FWD seq, REV ack) | PASS (2) |
| `wrap` | wrap eligibility refused; modular translation across `2^32` | PASS (2) |
| `reorder` | an **older** response retransmit after newer ones re-emits at the correct lower seq; a resegmented retransmit reconstructs | PASS (2) |
| `ackpos` | an ACK **before / at / inside / after** a pad; duplicate and out-of-order ACK in **both** directions | PASS (6) |
| `owner2` | a genuine hash collision denies the intruder and preserves the incumbent; table pressure denies the newcomer | PASS (2) |
| `notnative` | **no silent native pass once translation has begun** on an epoch (data, retransmit, pure ack, dup, OOO, unsupported) | PASS (2) |

### The fixes are mutation-checked — mechanically, not narratively

`mutation_harness.py` is a real, committed harness (the earlier README's "mutation-checked" was
prose with no artifact). For each critical invariant it copies the tree to a temp dir, applies one
behavior-reverting source mutation, runs **both** suites, and proves the mutation is **KILLED** —
at least one named test fails, and the specific test meant to defend that invariant is among the
failures. A surviving mutant is an *undefended invariant* and fails the harness; a mutation whose
target text is missing or non-unique is flagged as source drift. **12/12 mutants killed, baseline
clean at 84 tests.** The mutations cover: retransmit re-emission, template conflict, SACK learning,
the reuse discriminator, the sweep, the TIME_WAIT quarantine, teardown's both-FINs-acked rule, the
boundary-emit convention, the partial-ACK snap, full-key ownership, seq delta, and ack de-shift.
Machine-readable results land in `gate_results/mutation_results.json`.

### Boundary convention (the one documented rule)

An insertion at original boundary `b` is re-emitted on a segment covering `[s, e)` iff
`s < b <= e`. Its bytes sit immediately before original byte `b` in transformed space (a tail
boundary `b == e` lands at the end of the segment). Each boundary therefore appears exactly once
across a partition of the stream, and overlapping retransmits overwrite it with identical bytes.

## Stated limitations (honest, not defended away)

- **Insertions commit in forwarding order.** The switch sees each direction in the order it
  forwards it, so boundaries commit in increasing original offset. A *first-time* insertion whose
  boundary is **earlier** than one already committed cannot be added, because it would retroactively
  shift bytes the switch has already forwarded. Such a segment is **refused (coverage loss), never
  corrupted**: it is still translated and its bytes emitted, and the reconstruction stays consistent
  with the actually-committed plan (`test_overlap_out_of_order_first_insert_refused_but_safe`).
  Out-of-order **delivery/retransmission of already-committed data** is fully handled.
- **Concurrent tuple reuse on one slot.** While an old flow is quarantined awaiting its final ACK,
  a reused-tuple SYN anchors the *next* incarnation's ISN and the old state is preserved. A
  per-packet **epoch discriminator** (nearest-forward-ISN, with an in-flight-window backstop when a
  direction has no new anchor yet) routes each packet: old lingering packets translate with the old
  ledger; a **new incarnation is failed closed to native** (no size coverage) until the old epoch
  retires or is swept, at which point it claims a fresh generation. The cost is a documented
  **coverage** gap for the new connection during the overlap, never a correctness bug — new-epoch
  data is never translated with old state. Full simultaneous coverage of old + new on one slot would
  need a second slot.
- **Compressed owner tags.** A hash-only table with a narrow tag has genuinely undetectable false
  hits; the model records them and the suite flags hash-only ownership as a **blocking hardware
  limitation**. The safe design stores and compares the **full flow key** (standard P4 exact-match
  semantics), which the default uses.
- **Partial ACK inside a pad** is snapped to the insertion boundary (`partial_ack=True`) — exact
  for whole-segment cumulative acks, approximate if an endpoint ever acked a fraction of the pad.
- **Ledger depth / flow-table size** are finite: past them the model *freezes new insertions* or
  *denies new flows* (native), never raw post-insertion pass-through. A production build must size
  these to the expected concurrency.
- **State retirement** is bounded three ways: both-FINs-acked (fast), an in-band FIN timeout, and a
  wall-clock **idle sweep** (`sweep(now)`) that reclaims a flow which receives no further packet.
  A production build drives `sweep` from the control-plane ager; the horizons (`idle_horizon`,
  `time_wait`, `reuse_inflight_window`) are constructor parameters.
- **SACK** is handled by **strict eligibility**, learned from the SYN/SYN-ACK options and retained
  per epoch (never trusted from a data segment), rejecting SACK-permitted flows before their first
  insertion — the basis for the P4 claim. Eligibility is conservative: any SACK-permitted seen in
  the handshake refuses insertion (a coverage cost on one-sided offers, never a safety risk). The
  alternative edge-translation policy is implemented and tested but not the default, because a SACK
  edge inside a pad must snap.

## Gate A verdict

`gate_a.py` is the single authority. Gate A opens **only** if all of these hold: the legacy suite
passes every required area with zero failures; the repair suite passes every required area with zero
failures; the scenario demo exits 0 (mainline + byte-exact reconstruction); the mandatory
tuple-reuse counterexample's named test passes; and the mutation harness kills **every**
critical-invariant mutant with a clean baseline. It writes a machine-readable **run manifest**
(`gate_results/gate_a_manifest.json`, with a per-input `sha256` and a manifest self-hash sidecar)
plus `gate_results/mutation_results.json`, and prints `MACHINE_GATE_A {...}` under `--json`.

Current verdict: **PASS** — 84/84 tests, 12/12 mutants killed, counterexample fixed. A P4 build may
proceed **within the stated limitations** (in-order insertion commit; full-key flow table sized to
concurrency and aged by a wall-clock sweep; SACK-permitted flows, learned at the handshake, excluded
from insertion; a reused tuple's new incarnation uncovered until the old epoch retires). If any
required area regresses, or any mutant survives, Gate A reports `FAIL` and P4 must not begin.

## Run

```bash
python3 gate_a.py                          # the whole gate: both suites + demo + mutation + manifest
python3 gate_a.py --json                   # + MACHINE_GATE_A {...}

python3 transport_oracle.py                # scenario demo + reconstruction check + exit code
python3 test_transport_oracle.py --json    # legacy suite + MACHINE_SUMMARY (per-area gate)
python3 test_transport_repairs.py --json   # repair suite + MACHINE_SUMMARY (per-area gate)
python3 mutation_harness.py --json         # mutation harness + MACHINE_MUTATION_SUMMARY
```

Stdlib only (system `python3` 3.8 is fine). No network, no hardware, no P4. The only files written
are the machine-readable artifacts under `gate_results/`.

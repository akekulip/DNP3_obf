# Transport-translation oracle (offline, bounded)

`transport_oracle.py` + `stream_reconstruction.py` + `test_transport_oracle.py`.

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

## Demonstrated-model behavior (what the suite proves)

Per-area results from `python3 test_transport_oracle.py --json` (46 tests):

| Area | What it proves | Result |
|------|----------------|--------|
| `retx` | exact retransmit re-emits identical bytes, same translated seq, **offset not double-counted**; the switch re-inserts even when the segment carries `insert=0` | PASS (4) |
| `overlap` | an overlapping/resegmented retransmit reproduces **every** committed insertion in `(start, end]`, tested at segment start, interior, end, adjacent segment, and multiple boundaries; a new insert into committed history is refused, never a committed one suppressed | PASS (7) |
| `recon` | the receiver-visible transformed stream reassembles **byte-for-byte** to one canonical stream under in-order, exact-retransmit, overlapping, different-segmentation, duplicate, and out-of-order delivery, both directions; inconsistent retransmit data is **detected** | PASS (7) |
| `teardown` | state is retained until **both FINs are cumulatively acked** (or a safe timeout); the **final ACK is translated, never passed native**; RST-before-retire, delayed duplicate after FIN, and tuple-reuse quarantine are handled | PASS (6) |
| `owner` | full-key ownership **detects** slot collisions and denies the intruder (native, safe); a compressed-tag **false hit is detected and recorded** as a blocking limit; generation reuse does not alias; an active epoch is never evicted | PASS (6) |
| `sack` | a SACK-permitted connection is **rejected before its first insertion** (strict eligibility), so no post-insertion SACK can pass untranslated; an optional translate policy inverts both edges | PASS (4) |
| `seqack` | the core step function: cumulative deltas, exact ack inverse, partial-ack snap, out-of-order per-seq delta, bidirectional independent deltas, wrap eligibility, modular translation across a wire wrap | PASS (8) |
| `degrade` | bounded-limit behaviors stay safe: depth-cap freeze keeps translating, unsupported post-epoch is still translated, non-eviction | PASS (4) |

The two fixes are **mutation-checked**: reintroducing the audit bug (`inserted_len = committed`)
turns 8 tests red including both `retx` tests; reverting the teardown to "retire on both-FINs-seen"
turns 4 `teardown` tests red including the final-ACK-translated regression.

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
  a reused-tuple SYN is anchored for the *next* epoch but the old state is preserved; a *new*
  connection's data arriving before the old flow retires shares the slot and is denied coverage
  until retirement. Modeling old + new simultaneously on one slot would need a second slot.
- **Compressed owner tags.** A hash-only table with a narrow tag has genuinely undetectable false
  hits; the model records them and the suite flags hash-only ownership as a **blocking hardware
  limitation**. The safe design stores and compares the **full flow key** (standard P4 exact-match
  semantics), which the default uses.
- **Partial ACK inside a pad** is snapped to the insertion boundary (`partial_ack=True`) — exact
  for whole-segment cumulative acks, approximate if an endpoint ever acked a fraction of the pad.
- **Ledger depth / flow-table size** are finite: past them the model *freezes new insertions* or
  *denies new flows* (native), never raw post-insertion pass-through. A production build must size
  these to the expected concurrency.
- **SACK** is handled by **strict eligibility** (reject SACK-permitted flows before their first
  insertion), which is the basis for the P4 claim. The alternative edge-translation policy is
  implemented and tested but not the default, because a SACK edge inside a pad must snap.

## Transport-gate verdict

**PASS.** Under the shipped defaults — full-key ownership and strict SACK eligibility — retransmit
re-emission, overlap reproduction, final-ACK retirement, ownership, and SACK are all correct or
explicitly gated, and the byte-level reconstruction is exact. The gate opens only if every required
area (`retx`, `overlap`, `recon`, `teardown`, `owner`, `sack`) passes; the `--json` summary computes
this and prints `"transport_gate": "PASS"` / `"FAIL"`. A P4 build may proceed **within the stated
limitations** (in-order insertion commit, full-key flow table sized to concurrency, SACK-permitted
flows excluded from insertion). If any required area regresses, the summary reports `FAIL` and P4
must not begin.

## Run

```bash
python3 transport_oracle.py               # scenario demo + reconstruction check + exit code
python3 test_transport_oracle.py          # adversarial suite (verbose)
python3 test_transport_oracle.py --json    # + one-line MACHINE_SUMMARY {...} with per-area gate
```

Stdlib only (system `python3` 3.8 is fine). No network, no hardware, no P4, no build artifacts
written to the tree.

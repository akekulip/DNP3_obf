# Transport-translation oracle (offline, bounded)

`transport_oracle.py` + `test_transport_oracle.py`.

When the size defense **inserts bytes** into a TCP stream (padding a response on the
outstation->master direction, or expanding a SELECT/OPERATE with inert decoy CROBs on
master->outstation), the two endpoints' TCP sequence spaces stop agreeing. The switch must
translate every seq/ack afterward so an **unmodified** master and outstation each still see a
consistent byte stream. This oracle is an offline, hardware-free model of that translation as a
bounded per-flow state machine, plus an adversarial suite that checks the receiver's TCP view
stays byte/seq-consistent under the hazards a real link produces.

It is transport-only. DNP3 frame building, CRC-16/DNP, and TCP/IP checksum folding live in
`sbo_oracle.py`, `joint_transform_oracle.py`, and `p4_egress_emulator.py`. No P4 is touched.

## The model

Two **independent** streams per flow: `FWD` = outstation->master (responses), `REV` =
master->outstation (requests). Each stream owns an insertion **ledger** (its cumulative delta).
For a segment flowing in direction `D`:

```
seq' = seq + Delta_D(seq)      # its own stream was padded  -> add
ack' = ack - Delta_opp(ack)    # it acknowledges the OTHER stream -> subtract
```

Translation is a **step function of the original sequence number**, stored as a small ledger of
insertion boundaries anchored at the stream's ISN (so the math is plain integer offsets; the only
mod-2^32 step is wire<->offset conversion). Keying on the original seq is what makes the hard
cases fall out for free:

- **Retransmission** of a transformed segment hits the same boundary -> same delta, **no double
  count** (idempotent by construction; the ledger refuses a second boundary at a known position).
- **Out-of-order / duplicate** packets each translate from their own seq via the same step
  function -> correct regardless of arrival order, no extra state.
- **Duplicate ACKs** invert to the same original ack with no state change.
- **Consecutive transforms** accumulate in the ledger (cumulative delta).
- **Bidirectional** insertions keep separate `Delta_fwd` / `Delta_rev`; a FWD packet's *seq* uses
  `Delta_fwd` while its *ack* uses `Delta_rev`, and vice versa.

State ownership is an **owner tag + generation**, not a bare hash index: two flows that hash to
one slot are **detected** (the intruder is denied a transform epoch and stays native, safe because
it was never modified) rather than silently corrupting each other's delta.

## Safety contract (encoded and tested)

- **Before** a flow's first insertion, an unsupported packet MAY pass **native** — it was never
  modified, so its seq/ack are already correct.
- **After** any insertion, **every** packet on that flow is translated — including packets the
  classifier does not "support". Raw untranslated pass-through of a post-insertion packet is
  **unsafe**, and the model never emits it. (`test_unsupported_post_epoch_still_translated`;
  mutation-proven: forcing raw pass-through fails 15 of 19 tests.)
- **FIN/RST** are translated with the live ledgers **before** the state is freed, so the teardown
  segments carry consistent seq/ack; the slot (and its generation) is then reclaimed.

## Bounded limits — stated as tested behaviors, never as raw pass-through

The task's degraded-mode requirement ("stop creating NEW insertions but CONTINUE translating until
the flow is cleanly retired") is met, and the two places the bounded model reaches its edge are
encoded as explicit, tested behaviors:

1. **Ledger depth cap.** A flow can hold at most `ledger_depth` distinct insertion boundaries.
   The `(depth)+1`-th insertion is **refused (freeze)** — but the segment is **still translated**
   with the committed delta, and all retransmit/ack inversion stays correct to clean retirement.
   Only obfuscation *coverage* degrades, not correctness. (`test_depth_cap_freezes_but_keeps_translating`)

2. **Flow-table pressure / non-eviction.** An **active-epoch** flow is **non-evictable**: it holds
   its slot until FIN/RST retirement. Under table pressure a colliding **new** flow is **denied**
   an epoch and passes native (safe — unmodified), rather than evicting an active flow and
   stranding its padded bytes with no delta. Evicting an active-epoch flow would leave only unsafe
   raw pass-through as the alternative, so the model forbids it (`force_evict` refuses).
   (`test_active_epoch_flow_is_non_evictable`, `test_table_pressure_denies_newcomer_not_incumbent`)

   **Architectural limitation (honest statement):** the model cannot obfuscate more *concurrent*
   flows than the table has slots, and cannot translate a flow whose state was lost. It never
   resorts to raw post-insertion pass-through; the cost is denied coverage for excess flows, not a
   correctness/safety hole. A production build must therefore size the flow table to the expected
   concurrent-flow count, or fail a new flow closed (native) when full.

3. **Sequence wrap.** New insertions are **refused** once a stream's in-use offset window would
   reach `WRAP_GUARD` (2^31, ~2 GB), keeping the ISN-anchored offset unambiguous
   (`test_wrap_eligibility_rejection`). An ordinary wire-seq wrap at a high ISN with a small offset
   is unaffected — translation handles it with mod-2^32 (`test_modular_translation_across_wrap`).

### Residual limitations (not currently defended)

- **Re-segmented retransmission** (a retransmit that starts at a known seq but with a *different*
  payload length) produces a new boundary position; the ledger flags it `conflict` and does not
  re-insert, but the model does not reconcile the differing segmentation. DNP3 responses are padded
  deterministically per logical response, so this is unlikely, but it is not handled.
- **Partial ACK inside a pad region** is snapped to the insertion boundary (`partial_ack=True`);
  exact for whole-segment cumulative acks, approximate if an endpoint ever acked a fraction of the
  inserted bytes.
- **Owner-tag aliasing:** collision detection is only as strong as the tag width. The oracle uses a
  full identity; a silicon build with a narrow tag has a small residual undetected-collision rate.

## Run

```bash
python3 transport_oracle.py            # scenario demo, JSON summary to stdout
python3 test_transport_oracle.py       # adversarial suite (verbose)
python3 test_transport_oracle.py --json   # + one-line MACHINE_SUMMARY {...} for tooling
```

Stdlib only (system `python3` 3.8 is fine; `$RESEARCH_PYTHON` also works). No network, no
hardware, no P4, no build artifacts written to the tree.

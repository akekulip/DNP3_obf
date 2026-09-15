# Measuring epsilon: what to build, what it can answer, and what it cannot

Epsilon is the interval **after a release deadline expires** during which the blocker queue is
still blocking a packet that is already due. It is unmeasured on the loaded build and this plan
does not measure it. What follows is the candidate instrumentation, the procedure that would
measure it, and the limits that survive either way.

**Base for any candidate.** `implementation/exact_experiment_source/defense4_rrc_bor_unified12.p4`,
sha256 `7ce30494668df4271c5dcef5cb879a03ddb6a7901e7aad811a7ea9d92c55e861`. A candidate is a patch
over exactly that file and carries this hash, so the base can never be guessed later.

## 1. Why the existing artefacts do not answer it

**The declared timestamp registers do nothing.** `reg_ts_first_block`, `reg_ts_block_term`,
`reg_ts_ack_arm` and `reg_ts_ack_release` are declared with RegisterActions and there is no
`.execute()` call for any of them. They are inert, and a control plane reading them reads zeros.

**The 2026-09-15 blocker figures are not epsilon.** They start when a transaction *arms* the
reservoirs, so they measure circulation and budget lifetime including the intended hold. See
`relay_rto_20260915/CORRECTION_20260915.md`.

**Port counters cannot separate the two read lanes.** The ACK and RESPONSE reservoirs are qid7
and qid5 on the same loopback, dp8, behind one priority scheduler, so a dp8 counter sums them.
The dp10 reservoir is the OPERATE domain, a different lane, not the second read gate.

**A last `_DL` ingress timestamp is a proxy and must be labelled one.** It records when the
program last took a blocking decision for that slot. It is not the traffic manager going empty
and it is not the packet reaching the wire. Deadline-detection latency, remaining blocking and
subsequent service are three different intervals, and an external capture alone separates none
of them.

## 2. The four events, defined before any register is named

Per lane, independently, because the answer differs between them:

| event | definition | observable in ingress? |
|---|---|---|
| `T_deadline` | the scheduled release instant, already held in `reg_deadline` (ACK) and `reg_tresp` (RESPONSE) | yes, it is already stored |
| `T_expiry_first` | the first blocker token to observe `now >= T_deadline` for that slot | yes |
| `T_block_last` | the last blocking action for that slot before it stops blocking | yes |
| `T_departure` | the held packet actually leaving toward the master | **no** |

Epsilon as asked for is `T_block_last - T_deadline`. Detection latency is
`T_expiry_first - T_deadline`, and it is worth separating rather than folding in, because the
older release audit defines drain from each of those two starts in different places and the
intervals differ by exactly this term.

`T_departure` is the honest gap. Ingress sees a packet arrive, not leave; there is no egress-side
timestamp register in this program. Any candidate must therefore report epsilon as ending at the
last blocking action and say so, or add egress instrumentation, which is a larger change than
this plan proposes.

## 3. The candidate, kept minimal

Per lane, using the existing `SLOT_ACK` and `SLOT_RESP` discrimination that already selects
`reg_deadline` against `reg_tresp`:

* `reg_ts_expiry_first[slot]` — write-if-zero, so the first observation wins and later tokens
  cannot overwrite it;
* `reg_ts_block_last[slot]` — write-always, so the last write wins;
* `reg_ep_valid[slot]` — a flag set only when both of the above were written within one
  generation, so a missing measurement reads as invalid rather than as an elapsed time of zero.

Nothing else. Do not enable the other dormant registers, add a tracing framework or touch
scheduling.

**Requirements the candidate must satisfy, each because it can silently corrupt the answer:**

- **One clock.** `ig_intr_md.ingress_mac_tstamp` throughout, nanoseconds, the same source the
  deadlines are computed from. Mixing it with any other clock makes the subtraction meaningless.
- **Wrap.** The deadline words are 32-bit nanosecond values with a 256 ns tick. Subtraction must
  be modular and the result rejected if it exceeds the half-range, which is how a wrap shows up.
- **Association.** Each token already carries its transaction and lane tag; the write must be
  keyed on it, or a token from a previous transaction lands in this one's measurement.
- **Stale tokens and retirement.** The registers must be cleared as part of the same retirement
  that clears the rest of the slot's state, and in the same order, or a late token from a retired
  transaction writes `T_block_last` after the fact.
- **Outcomes kept apart.** Deadline release, budget release, late arrival and bypass must be
  distinguishable in the readback; averaging them produces a number that describes none of them.
- **No controller in the loop.** The control plane may read these registers and must not
  participate in any per-packet release decision.

## 4. The resource risk, stated before anyone compiles

The program already occupies **all twelve ingress match-action stages** of the pipeline with 112
tables, and Tofino allows one stateful access per register per packet. Three new registers with
their own SALUs, two of them accessed on the blocker path, may not fit without displacing
something. **This is the most likely way the candidate fails, and it fails at compile time rather
than silently.** A candidate that does not fit is a result too: it means epsilon cannot be
measured this way on this program without restructuring.

## 5. Compilation dependency, unmet here

`bf-p4c` exists only on the switch, which this work does not access. The `/usr/bin/p4c` present
locally is the open-source compiler and cannot target Tofino, so it cannot even type-check a TNA
program meaningfully. **The candidate is therefore uncompiled and unverified.** A successful
compile later would establish that it fits, and nothing more: it would not be a measurement, and
it would not show that the instrumentation leaves the timing it measures undisturbed.

## 6. The procedure, for when it is separately authorised

1. Apply the patch to the recorded base hash. Build with the switch's own SDE. Record the new
   binary hash and the resource report, and diff that report against the frozen build's.
2. Load the candidate under its own build identity. It is a new program; its results must never
   be filed into `campaign_v1`.
3. Configure through the timing-only path in `active_control/`, so shaping is never enabled, and
   archive the verification record.
4. Drive READ only, with the guarded driver. Capture on the master-facing link at nanosecond
   precision.
5. Read the three registers per lane per transaction, with the outcome code, and archive the raw
   readback rather than a summary.

**Expected output:** per lane, a distribution of `T_block_last - T_deadline` and of
`T_expiry_first - T_deadline`, each with a validity flag and an outcome code, over transactions
whose response arrived before its deadline.

**Failure criteria, any of which means epsilon is still unmeasured:** the candidate does not fit
and the build fails; the validity flag is unset for a material fraction of transactions; the
modular subtraction rejects a material fraction as wrapped; the two lanes cannot be told apart in
the readback; or the measured interval varies with offered load in a way that indicates the
instrumentation is itself perturbing the schedule.

**Not authorised by this plan:** loading the candidate, running hardware, or describing epsilon
as measured. Epsilon stays unmeasured until a separately authorised experiment records its
endpoints.

# First loaded run of the epsilon candidate, 2026-09-15

The candidate was loaded, configured and driven with READ traffic. The instrumentation **works**:
the registers were zero before traffic and written after. One of the two lanes produced a valid
measurement; the other exposed a defect in the candidate. **Epsilon is still not measured**, and
this file explains why rather than reporting a number that would not mean what it says.

## Configuration, read back not assumed

Loaded program `epsilon_candidate`, binary sha256
`1d5470a678c6df4eb881d208ec58ae484079bff5e8b7fe247335c39123c8fb1f`, from source
`ac3eb62a1be7e0b38d9c36185034b2e0e48a78a7d0e825b2a5df1283cbe33c60` over base
`7ce30494668df4271c5dcef5cb879a03ddb6a7901e7aad811a7ea9d92c55e861`.

Mode D4, `d_ticks` 20,000,000 ns, `da_dr` 24,000,000 ns, so D_A = 20 ms and the configured
CLRT_new = 4 ms. Ten cycles of: clear both registers, one READ transaction, read both registers
together with `reg_deadline` and `reg_tresp`. Raw samples in `epsilon_samples.jsonl`.

**`configure-all` again ended with `shape_enable = 1`.** It was read back as 1, forced to 0, and
read back as 0 with the timing fields preserved, before any traffic ran. This is the second time
the defect has been observed on hardware, and it is why `active_control/timing_only_profile.py`
exists.

## What was measured: the ACK lane's detection latency

Modular subtraction on 32-bit nanoseconds, samples above the half-range rejected as wrapped.

| quantity | valid | median | min | max |
|---|---|---|---|---|
| ACK detection, first expiry minus deadline | 10/10 | **15 ns** | 3 ns | 21 ns |

**The first blocker token observes its deadline has passed within about 15 nanoseconds of that
deadline.** Deadline detection is therefore not a material term in any release budget, which was
an open question: the older audit's two definitions of drain differ by exactly this term, and the
difference is now known to be negligible.

## What was not measured, and why

**The ACK lane's `block_last` is not epsilon.** It lands at deadline + 3,999,985 ns, and the
reason is visible in the raw data: `reg_tresp − reg_deadline` is exactly 4,000,000 ns, and
`block_last_ack` sits 2 to 26 ns *before* `reg_tresp`. So `block_last` is recording the last
moment any token observed the expired flag for that slot, which continues for as long as the
transaction is live, ending at the response release rather than when the acknowledgment's own
gate stopped blocking it. The quantity is real but it is transaction lifetime, not the drain of
one packet's gate.

**The RESPONSE lane is contaminated by stale tokens.** Every sample has `expiry_first_resp`
about 24 ms *before* `reg_tresp`, which is D_A + CLRT_new: tokens circulating before the deadline
is armed evaluate `age_resp` against the previous or cleared value, mark themselves expired and
take the write-if-zero slot. All ten RESP detection samples are rejected as negative, and the
RESP epsilon figures, median 55.5 ms and max 766 ms, are meaningless.

This is exactly the failure the measurement plan listed as a requirement: *"Reset/retirement
ordering and stale-token isolation ... or a late token from a retired transaction writes
`T_block_last` after the fact."* The candidate does not implement it. The plan predicted the
failure mode; the run confirmed it.

## What the candidate needs before it can measure epsilon

1. **Generation gating.** Both writes must be keyed on the token's generation tag matching the
   live transaction, so a token from before the arm or after retirement cannot write.
2. **A narrower `block_last` predicate.** It must record the last blocking action *for the packet
   being gated*, not the last observation of a flag that stays set while the transaction lives.
   The release outcome, `OUT_ACK_RELEASE` or the deadline-release path, is the better trigger.
3. **Re-run with both, then compare against the frozen build** to check the instrumentation does
   not perturb what it measures.

Until then: detection latency is measured at about 15 ns on the ACK lane, and **epsilon is not
measured**. The blocker-drain figures of earlier today remain what the correction note says they
are, circulation and budget lifetime, and neither they nor this run is epsilon.

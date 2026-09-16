# Epsilon measured, 2026-09-15

> **Superseded in part, 2026-09-16.** The arithmetic below decodes the deadline register as a bare
> timestamp. It is `(timestamp & 0xFFFFFF00) | 1`, so every interval here is one nanosecond short,
> and the "wrapped clock" rejected from the ACK detection row is a 0 ns interval rather than a
> wrap. The corrected values are 1,706 ns and 1,705 ns with 12 of 12 valid on every lane. The
> source and binary hashes quoted for this run belong to candidate v1 and cannot be attributed to
> the v2 patch that is in this directory. See `../ATTRIBUTION_AND_DECODE_20260916.md`. The raw rows
> in `epsilon_v2.jsonl` are unchanged and remain the record.

Candidate v2, loaded and driven with READ traffic. **Epsilon is measured**: the post-deadline
blocking interval is about **1.7 microseconds** on both read lanes. v1's samples in
`epsilon_samples.jsonl` are superseded and retained only to show what was wrong with them
(`RESULT.md`).

## What changed between v1 and v2

v1 drove the writes from `meta.expired` / `meta.expired_resp` and both lanes were wrong, in two
different ways that the run exposed:

* the RESPONSE lane's first expiry fired about 24 ms **before** its own deadline, exactly
  D_A + CLRT_new early, because blockers circulating before `reg_tresp` is armed evaluate
  `age_resp` against a stale value and take the write-if-zero slot;
* the ACK lane's last write landed within 26 ns of `reg_tresp`, because the expired flag stays
  set for the whole life of the transaction, so "last flag seen" is transaction lifetime.

v2 keys on the **outcome** instead. `OUT_AB_DL` and `OUT_RB_DL` are `CD_BLOCK_TERM_DL`: a blocker
token terminating *because* its deadline passed, which is the event of interest. Stale tokens take
`OUT_AB_STALE` / `OUT_RB_STALE` and timed-out ones `OUT_AB_TMO` / `OUT_RB_TMO`, so both are
excluded by construction rather than by a generation test written by hand.

## Result

Twelve transactions, one per clear-run-read cycle. Modular subtraction on 32-bit nanoseconds,
samples above the half-range rejected as wrapped. Raw data in `epsilon_v2.jsonl`.

| quantity | valid | median | min | max | sd |
|---|---|---|---|---|---|
| ACK detection, first `AB_DL` − deadline | 11/12 | 12 ns | 0 | 24 | 8 |
| **ACK epsilon, last `AB_DL` − deadline** | 12/12 | **1,705 ns** | 1,691 | 1,719 | 9 |
| RESP detection, first `RB_DL` − deadline | 12/12 | 12 ns | 2 | 25 | 8 |
| **RESP epsilon, last `RB_DL` − deadline** | 12/12 | **1,704 ns** | 1,694 | 1,719 | 8 |

Three things this establishes.

**Epsilon is about 1.70 microseconds and tight.** A standard deviation of 9 ns over a 1.7 µs
interval is a spread of half a percent, so it is a near-constant of the mechanism at this
configuration rather than a quantity that varies per transaction.

**The two lanes agree.** 1,705 ns against 1,704 ns, which is what should happen if the same
reservoir mechanism gates both, and is the first direct evidence for that. It also confirms the
lanes are now separated: v1 could not tell them apart at all.

**Deadline detection is negligible.** A median of 12 ns means the first blocker sees the expiry
essentially immediately, so the older release audit's two definitions of drain, one starting at
the deadline and one at first expiry, differ by an amount that does not matter.

## Cross-check against an inherited constant

`implementation/control/parameter_policy.py` carries `T_TAIL_NS = 1736.0`, "release tail after the
deadline (measured ~1.72 us)", from Defense 3 on 2026-07-29 and therefore from an **earlier
build**. The measurement here is 1,705 ns, within 2 % of it.

That is corroboration, not a restatement: the constant was inherited and this is a direct
measurement of the current build by a different method. The policy's other inherited term,
`T_DETECT_NS = 1217.0`, describes something else, the time to admit a full 64-token reservoir, and
is not comparable with the 12 ns detection measured here.

## Scope

One relay, one switch, one configuration (D4, D_A = 20 ms, configured CLRT_new = 4 ms, shaping
off), twelve transactions, READ only. Measured from the release deadline to the last
deadline-driven blocker termination, both timestamped in ingress from
`ig_intr_md.ingress_mac_tstamp`.

**Still not observed: the held packet's departure.** Ingress sees a packet arrive, not leave, and
this program has no egress timestamp register, so epsilon here ends at the last blocking action
rather than at the wire. Whatever service time follows that is not in these numbers.

**Not established: that the instrumentation is free.** These registers run in the same pipeline
they measure. Comparing a campaign under the candidate against the frozen build would settle it;
that was not done.

`configure-all` again ended with `shape_enable = 1`, read back as 1, forced to 0 and verified
before any traffic. Third hardware observation of that defect.

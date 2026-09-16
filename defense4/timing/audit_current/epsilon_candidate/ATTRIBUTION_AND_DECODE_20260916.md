# Epsilon: build attribution and a decode correction, 2026-09-16

This supersedes the arithmetic in `run_20260915/RESULT_V2.md` and the resource comparison in
`COMPILE_RESULT_20260915.md`. It does not touch the raw rows: `run_20260915/epsilon_v2.jsonl` and
`run_20260915/epsilon_samples.jsonl` are unchanged, and every number below is re-derived from them
by `run_20260915/decode_epsilon.py`, which carries an explicit `DECODE_VERSION`.

Nothing here required hardware. No switch was contacted and no program was loaded or compiled.

---

## 1. The loaded build cannot be attributed to the patch in this directory

The records name one candidate source. Applying the patch that is actually here to the verified
base produces a different one.

| | sha256 |
|---|---|
| base `defense4_rrc_bor_unified12.p4`, verified on disk and on the switch | `7ce30494668df4271c5dcef5cb879a03ddb6a7901e7aad811a7ea9d92c55e861` |
| **`epsilon_candidate.patch` in this directory, applied to that base** | **`7d1752225e85b5476e14eed3e93127c272167caeec1ee4d00661e1e4c6fc54e5`** |
| candidate source cited by `README.md`, `COMPILE_RESULT_20260915.md` and `run_20260915/RESULT.md` | `ac3eb62a1be7e0b38d9c36185034b2e0e48a78a7d0e825b2a5df1283cbe33c60` |
| candidate `tofino.bin` cited by the same three records | `1d5470a678c6df4eb881d208ec58ae484079bff5e8b7fe247335c39123c8fb1f` |

Reproduce it with `patch` against a copy of the base; the base's own hash matches its record, so
the disagreement is in the patch, not in the base.

**What follows from that.** The three records were written for **v1**, whose register writes rode
`meta.expired` and `meta.expired_resp`. The patch now in this directory is **v2**, which keys on
`OUT_AB_DL` and `OUT_RB_DL` instead, and it was never hashed, never recorded against a compile,
and never recorded against a loaded binary. The source and binary hashes therefore belong to v1
and **are not evidence of what produced `epsilon_v2.jsonl`**.

They have not been overwritten to agree with the current patch. v1's hashes are v1's history and
stay where they are.

**RESOLVED on the switch, 2026-09-16.** The v2 rows were produced by a binary built from
`7d175222…`, the patch in this directory. The 2026-09-15 build tree survives on the switch: its
`epsilon_candidate.p4` hashes to `7d175222…`, its `out_v2` build normalises to the same
`b5780196…` that an independent recompile of this repository's patch produces, and
`switchd_v2.log` records that conf being loaded three minutes before the rows were captured. What
was wrong was narrower than it looked: `1d5470a6…` is genuinely v1's binary in `out/`, and the v2
result inherited that citation from v1. The raw hash could never have settled it either way,
because `bf-p4c` stamps a random `run_id` into every binary. See
`BUILD_ATTRIBUTION_20260916.md`.

## 2. The decode was wrong by the armed marker, and one value was not a clock wrap

The program does not store a bare timestamp in the deadline registers. It stores
`(timestamp & TICK_MASK) | ARMED_MARK`, with `TICK_MASK = 0xFFFFFF00` and `ARMED_MARK = 1`, so the
low byte is a flag and not nanoseconds. `RESULT_V2.md` subtracted the raw word.

Two consequences, both now fixed in `decode_epsilon.py`:

* Every interval was reported one nanosecond short.
* Row 8's first ACK expiry, `562737152`, against the deadline word `562737153`, gives **−1 ns**
  undecoded. `RESULT_V2.md` treated the negative sample as a wrapped clock and rejected it, which
  is why its ACK detection row reads 11 of 12. Decoded, the deadline is `562737152` and the
  interval is **0 ns**: the first blocker saw the expiry in the same nanosecond. It was never a
  wrap. A single non-negative error term cannot explain a negative observation, and reaching for
  the clock is how a decode error acquires a plausible-sounding cover.

Wrap is still handled, but narrowly and on its own terms: the register is 32 bits of nanoseconds
and wraps about every 4.295 s, so a modular difference is accepted only inside a stated plausible
bound and is otherwise reported as rejected rather than folded into range. With the corrected
decode **no row is rejected on any lane**.

## 3. The re-derived numbers

From the same twelve rows, decode version 2:

| quantity | valid | median | min | max | sd |
|---|---|---|---|---|---|
| ACK detection, first `AB_DL` − deadline | 12/12 | 12.5 ns | 0 | 25 | 8.18 |
| **ACK blocker-termination interval** | 12/12 | **1,706 ns** | 1,692 | 1,720 | 8.72 |
| RESP detection, first `RB_DL` − deadline | 12/12 | 13.5 ns | 3 | 26 | 7.90 |
| **RESP blocker-termination interval** | 12/12 | **1,705 ns** | 1,695 | 1,720 | 8.03 |

The published 1,705 and 1,704 ns become 1,706 and 1,705 ns. The shift is the marker bit, and the
standard deviations are unchanged because a constant offset does not move them.

## 4. What the interval is, at its endpoints

Both timestamps are `ig_intr_md.ingress_mac_tstamp`, taken in **ingress**, on a recirculating
blocker token. The interval runs from the stored release deadline to the ingress timestamp of the
last blocker token that terminated *because* that deadline had passed.

That is an **internal blocker-termination interval**. Calling it epsilon outright overstates it,
for a reason that is structural rather than cautious:

* A terminating recirculated blocker's ingress timestamp is not a traffic-manager queue-empty
  time, and it is not the held packet's departure. Ingress records an arrival.
* This program has no egress timestamp register, so whatever service and egress time follows the
  last blocking action is outside the number entirely.

Epsilon's intended physical meaning, the post-deadline blocking interval up to release, is
preserved as the definition. What was measured is that interval **up to the last blocking
action**, which is a lower bound on it. Closing the gap needs egress instrumentation, which is a
different candidate and a separately authorised run.

**Twelve samples at one configuration are not an all-load drain bound.** They are READ only, one
relay, one switch, `D_A = 20 ms`, configured `CLRT_new = 4 ms`, shaping off. Nothing here licenses
using 1.7 µs as a universal admission constant, and `delay_admission.py` accordingly takes the
release tail as a named input with its own provenance rather than assuming it.

**Not verified:** that the two samples in a row belong to the same correctly armed transaction.
`ep_cycle.py` reads each register by wildcard pipe and takes the first returned word, and the
cycle clears the registers between transactions rather than tagging them. The agreement between
lanes and the tightness of the spread are consistent with correct association, but consistency is
not verification, and a transaction identifier written alongside each timestamp is what would
establish it.

## 5. The resource counts do not conflict; they are counted differently

`COMPILE_RESULT_20260915.md` reports 13 ingress stages for both builds and an ingress table count
rising from 176 to 182. The manuscript reports twelve ingress stages, six egress stages and 112
tables. Both were treated as describing the same thing, and they do not.

The manuscript's figures come from the compiler's own allocation summary for the frozen build,
`evidence/final_read_sbo/readbacks/tofino_resource_table_summary.log`, which states them
explicitly: `Number of stages for ingress table allocation: 12`, `for egress table allocation: 6`,
`Number of tables allocated: 112`. That is a preserved artefact and the manuscript matches it.

The candidate's 13 and 176/182 have **no preserved source**. `compile_20260915/compile.log`
contains the nine warnings and the exit status and no allocation summary at all, so the counting
basis behind those numbers is not recorded. Thirteen is consistent with counting stage indices 0
through 12 inclusive, and 176 with counting table objects rather than allocated tables, but that
is a reading of the numbers, not a record of how they were produced.

**Settled on hardware, 2026-09-16.** Both builds were recompiled and the allocator reports twelve
ingress stages, six egress stages and 112 tables for the frozen base and 114 for the v2
candidate, so the manuscript is right and the candidate adds two tables rather than six. See
`BUILD_ATTRIBUTION_20260916.md` §4. The paragraphs below record the reasoning from before that
run.

**Therefore:** the manuscript's counts stand, because they are sourced. The candidate's counts are
marked unresolved in `COMPILE_RESULT_20260915.md` rather than being used to contradict them. No
hardware impossibility follows from two counts that were never defined the same way.

What the candidate compile does still establish is narrower and survives: it exited zero, and its
unused-instance warnings name `ts_first_block_w`, `ts_ack_arm_w`, `ts_block_term_w`,
`ts_ack_release_w`, `ctr_fresh` and `ctr_deq` while naming neither `ep_expiry_first_w` nor
`ep_block_last_w`, so the two instrumentation registers are reachable where the four inherited
timestamp registers are not.

## 6. Perturbation: a comparison exists, and it is not a certificate

`run_20260915/PERTURBATION.md` records a frozen-versus-candidate comparison of 200 READ
measurements per capture. Any text saying no perturbation comparison was conducted is out of date.
Independent re-extraction reproduces it:

| build | n | mean CLRT | median CLRT | sd |
|---|---|---|---|---|
| frozen | 200 | 3.999470 ms | 3.999214 ms | 0.015412 ms |
| candidate | 200 | 4.000282 ms | 3.999887 ms | 0.015335 ms |

Re-extracted here with integer nanosecond arithmetic. An extraction that converts each timestamp
to a float second first gives 3.999466 / 3.999233 for the frozen build and 4.000285 / 3.999829 for
the candidate: the same conclusion, differing in the last few nanoseconds, which is the size of
the float representation error and not a difference in the captures.

These two captures are **nanosecond-resolution** pcaps, unlike the campaign corpus; see the note
below.

### The two corpora do not have the same timestamp resolution

| corpus | pcap magic | resolution |
|---|---|---|
| `evidence/campaign_v1`, all 172 captures | `d4c3b2a1` | **microsecond** |
| the 2026-09-15 diagnostics: perturbation, duplicate, relay RTO | `4d3cb2a1` | **nanosecond** |

No campaign interval can carry sub-microsecond information, whatever precision it is printed to.
The diagnostics can. Mixing the two, or quoting a campaign median to more than three decimal
places of a millisecond, asserts precision the capture never had.

One pair of captures and a non-significant rank test do not establish equivalence, and a net CLRT
can hide cancellation between a change in the ACK release delay and an opposite change in the
RESPONSE release delay, because CLRT is the difference of the two. The correct statement is that
the comparison was made, at this scope, and found no detectable difference. The apparatus has not
been certified non-perturbing, and this file does not claim it has been.

# Response to the external audit (`CORRECTIONS.md`)

Every item checked against the actual source, the compiled artifacts and the raw campaign
data in this directory. Verdicts are one of **CONFIRMED** (the audit is right),
**CONFIRMED WITH CORRECTION** (right conclusion, wrong reasoning or wrong detail),
**REFUTED** (the audit is wrong), or **NOT APPLICABLE TO THIS REPO** (true of the package
the auditor received, not of the repository).

Headline: **the audit is substantially correct.** Two genuine state-ordering defects exist
in the P4, one advertised parameter range is arithmetically impossible, and six factual or
terminological errors in `REPORT.md`/`REPORT.pdf` are real and must be corrected. Three
items are wrong, and one of the two "critical" items is right about the code but wrong
about what the evidence shows.

---

## Part 1 — the two claimed critical P4 defects

### Item 1 — a RESPONSE marks the transaction before it is validated

**CONFIRMED as a code fact. The predicted failure signature is REFUTED by the counters.
My §9.8 PASS is separately unsupported, for a different reason than the audit gives.**

The ordering claim is exactly right. In `Ingress.apply`:

| level | what runs | file |
|---|---|---|
| 1 | class driver sets `meta.tag_val = TAG_PENDING_DELTA` for a RESPONSE | `p4/…p4:1924–1932` |
| 2 | `meta.cur_gen = tag_read_or_mark.execute(0)` — **the write happens here** | `p4/…p4:1973–1978` |
| 3 | `tbl_state_decode.apply()` — seq / ack / learned-port conjuncts resolve here | `p4/…p4:1990` |

`CLASS_RESP` is assigned on `role == ROLE_RESP && sess == SESS_RELAY && dir == DIR_RELAY`
only. The SALU's own predicate is `(int<8>)v < 8s0` — a test on the **stored** state, not
on **this packet's** validity. So a response-shaped frame on the configured session with a
wrong TCP sequence does execute the marker. The audit is correct.

**But its predicted consequence did not occur.** The audit predicts: stale marks → the
legitimate response reads `txn_active == 2` → suppressed as a duplicate. The Gate 4 F-case
evidence (`evidence/gate2/gate4_20260730T004806Z/gate4.json`, all three repetitions) shows:

```
RESP_HOLD_EARLY = 1     RESP_BYPASS = 1     RESP_DUP_SUPP = 0
```

Duplicate suppression never fired. The predicted signature is absent in 3/3 reps.

**However, the F-case PASS still cannot stand**, for a reason neither the report nor the
audit identified. The intended schedule is READ +0.000 ms, ACK +0.500, **stale response
+0.800**, legitimate response +1.000 (`--stale-offset-ns 800000`, `--ack-offset-ns
500000`, `--timer-ns 1000000`). The measured internal timestamps in all three reps are:

```
reg_ts_read        +0.000 ms
reg_ts_ack_arm     +0.500 ms      <- matches app 3's scheduled ACK exactly
reg_ts_resp_bypass +1.000 ms      <- matches the LEGITIMATE response's slot, not +0.800
```

`ts_resp_bypass_w` fires only on the arm that forwards (`p4/…p4:2289–2292`), and only one
bypass occurred, so this is a single unambiguous write — and it lands 200 µs away from the
stale injector's slot. Worse, `pktgen_after` in the record reads back `app_block`,
`app_event` and `app_event2` **but not app 4**, so the stale injector's own trigger and
packet counters were never captured.

Consequently the evidence cannot say which of the two responses was held and which was
bypassed. Either the stale injector fired 200 µs late, or the legitimate response was the
one bypassed and the stale one was held — an inverted test. **§9.8's "PASS 3/3" is
withdrawn** pending a rerun in which the two responses are separately identifiable (a
distinct counter or role for app 4, and app-4 counter readback).

The audit's stated reason — "the ACK finding a pending marker proves only that *some*
response set it" — is also correct as far as it goes.

**Severity of the underlying defect.** The hazard is real but was never observed: across
400 defended physical transactions `RESP_DUP_SUPP = 0` and `BLOCK_TERM_STALE = 0`. It
requires a same-session, correctly-framed response with a mismatched sequence — i.e.
exactly the case §9.8 was built to test. If it fires, the legitimate response is
**dropped** (not merely delayed) and the transaction hangs until fail-open.

### Item 2 — a stale zero-budget token can retire the current transaction

**CONFIRMED.** Same defect class, same mechanism.

```
p4/…p4:1938   } else if (meta.role == ROLE_BLOCK) {
                  meta.pkt_class = CLASS_BLOCK_DEQ;
                  if (meta.budget_zero == 8w1) { meta.tag_val = TAG_INACTIVE; }
p4/…p4:1985   meta.tag_diff = tag_rmw.execute(0);      // writes tag_val unconditionally
p4/…p4:1990   tbl_state_decode.apply();                 // generation check happens HERE
```

`tag_rmw`'s only guard is `meta.tag_val != TAG_NO_WRITE`. The generation test is
`tag_diff`, consumed one level later. So a dequeued token whose `hdr.ib.seq == 0` retires
whatever transaction is live, regardless of whose generation it carries. The action block's
documented `stale > deadline > budget` priority (`p4/…p4:2201–2212`) cannot undo a
committed SALU write — the audit's closing line on this item is exactly right.

Not reachable in normal operation: the deadline retires tokens ~15× before the budget
(30.802 ms horizon vs a 2 ms hold), and `BLOCK_TERM_TMO` was 0 in every test. It becomes
reachable when combined with item 3.

### Item 3 — the legacy host-injected blocker path

**CONFIRMED.**

- `p4/…p4:941–945` — EtherType `0x88C1` is forced to `ROLE_BLOCK` **in the parser**, with
  no ingress-port qualification.
- `p4/…p4:835–851` — `port_ok = 1` is set for *every* topology port, including
  `from_master` and `from_relay`.
- `p4/…p4:2052–2057` — a fresh `ROLE_BLOCK` frame that is not from the packet generator
  falls to the legacy branch and calls `to_block()`, i.e. enqueues into the
  strict-priority `Q_BLOCK`.

So an externally injected `0x88C1` frame from the master or relay port enters the blocker
queue carrying an attacker-chosen `ib.gen` and `ib.seq`. With `ib.seq = 0` it returns from
the loopback as `dequeued`, hits item 2's path, and retires the live transaction — which
collapses the reservoir and releases the held ACK early. The threat model is passive, so
this is outside the modelled adversary, but the audit's recommendation stands: gate
`ROLE_BLOCK` admission on `ingress_port ∈ {PORT_PGEN, PORT_L}` or compile the legacy branch
only under a microbenchmark flag.

---

## Part 2 — the fail-open horizon

### Item 4 — the horizon is sized against the wrong quantity

**CONFIRMED, and it is worse than the report admits.** The correct constraint is
`H > a + D + detection + drain + tail`, not `H > D`. Recomputed from the campaign's own
per-transaction data:

| arm | worst observed `a` | `a + D` | margin `H/(a+D)` |
|---|---|---|---|
| D = 1 | 4.608 ms | 5.608 ms | 5.49× |
| D = 2 | 3.399 ms | 5.399 ms | 5.71× |
| D = 4 | 5.651 ms | 9.651 ms | 3.19× |
| D = 8 | 1.509 ms | 9.509 ms | 3.24× |
| **D = 16** | **4.673 ms** | **20.673 ms** | **1.49×** |

`REPORT.md` §6.3 claims an 8.8× margin. That figure uses `D = 3 ms` as "the longest
legitimate hold" — a stale design point — and omits `a` entirely. The true worst-case
margin in the campaign was **1.49×**.

The clamp is worse still: `D_MAX_MS = 40.0` (`setup/…_setup.py:119`) with
`BUDGET_DEFAULT = 18000` gives `H = 30.802 ms < 40 ms`. **At the advertised maximum D the
budget expires before the deadline can arrive, even with an instantaneous ACK.** The
report's §12.3 line that the 40 ms boundary "blocks nothing already claimed" is wrong; it
blocks the correctness of the supported parameter range. Either B must be computed from
`a_max + D`, or `D_MAX` must be reduced to roughly `H − a_max − ε ≈ 24 ms`.

---

## Part 3 — factual errors in the report

### Item 7 — 480 vs 400 defended transactions

**CONFIRMED.** From `evidence/physical/dsweep_blocks.jsonl`: 20 blocks with
`reservoir_armed = true` → **400 defended transactions**; 4 blocks native → 80 undefended.
`REPORT` §12.1's "480 of 480 transactions, exactly 64 tokens each" is wrong; only the
ordering-invariant part of that sentence is true of all 480. Correct totals: 480 completed,
400 defended, 64 tokens per defended transaction, 25 600 tokens across the five defended
arms. The report's own §11.3 exit-partition table already totals 400, which is what makes
this an internal inconsistency rather than a data problem.

### Item 8 — "all 80 land on the same 32 µs constant"

**CONFIRMED FALSE.** Recomputed for D = 16 ms, n = 80:

```
distinct CLRT values      18
min 0.0000 ms   max 0.0470 ms   sd 0.0120 ms
within ±0.5 µs of 0.032 ms:  29 / 80
exactly 0.000 ms (below the 1 µs capture resolution):  7
```

The distribution compressed sharply; it did not become a constant. "Flattened to a
constant", "all 80 land on the same 32 µs release tail" and "the entire cloud collapsed
onto 32 µs" are overclaims contradicted by the report's own table. The ~238× standard-
deviation reduction is real and is the claim that should be made.

### Item 9 — two different quantities called "release tail"

**CONFIRMED.** In `REPORT.md`, "release tail" means 26–27 ns at lines 317, 670 and 860
(internal: last token termination → ACK loopback return) and ~32 µs at lines 946, 958 and
968 (external: master-capture ACK→RESPONSE gap). Three orders of magnitude apart, same
name, and the second is used as the headline floor. They need distinct names.

### Item 20 — "the compiler accepted all four without complaint"

**CONFIRMED FALSE**, twice over.

- Trap 3 is a **hard compiler error** (`too many RegisterActions attached to the
  Register`), quoted as such in the same section. The sentence contradicts its own §7.3.
- The unsigned-comparison trap is **not** a miscompile. `v < 8w0` on a `bit<8>` is
  semantically an unsigned comparison against zero and is correctly false; the fault is a
  programmer type error that the compiler failed to diagnose. Calling it a "silent
  miscompile" alongside the large-constant case is wrong. Only the large-constant case is a
  confirmed silent target anomaly — and even there, the report already correctly narrows
  the *cause* to an inference (§7.1).

The four should be relabelled: one confirmed silent target anomaly, one programmer type
error with a missing diagnostic, one hard resource error, one documented multi-pipe
generator behaviour.

### Item 19 — the drain model is off by one

**CONFIRMED.** The interval from the first to the last of K evenly spaced terminations
contains K − 1 gaps. With r = 37.4 Mpps:

```
K/r      = 1711.2 ns      |measured 1694 − K/r|     = 17.2 ns
(K−1)/r  = 1684.5 ns      |measured 1694 − (K−1)/r| =  9.5 ns
```

The measurement fits `(K−1)/r` better. It does not invalidate the drain measurement, but
the claim that it "independently verifies K/r to 1.1 %" is imprecise; `K/r` is the
reservoir circulation period, `(K−1)/r` is the first-to-last drain span.

### Item 11 — which build produced the physical timing results

**CONFIRMED.** `artifacts/resources/bx_fulltel.table_summary.log` reports 10 ingress
stages; `bx_core` reports 9. The hold decomposition requires `reg_ts_last_block` and
`reg_ts_last_term`, which exist only under `D3_LIVE_FULL_TELEMETRY`. The report lists all
three builds in §9.9 but never states that the physical numbers came from the 10-stage
variant. It must. (Critical path stayed at 8 in both, which supports functional similarity
but is not proof of timing identity — the audit's phrasing here is fair.)

### Item 6 — the uninitialized-metadata warning

**CONFIRMED as an undisclosed warning**, with one mitigating fact the audit omits. Every
compile log carries it:

```
p4/build_live_9.13.1_compile.log:1:  [--Wwarn=uninitialized_out_param] warning:
  out parameter 'meta' may be uninitialized when 'IgParser' terminates
```

and `p4/…p4:784` states the omission is deliberate. The mitigation: if the metadata really
is zeroed, an unparsed packet gets `port_ok = 0`, which the MAU **drops** — the default is
fail-closed, not fail-open. But that is precisely what the compiler declines to prove, so
the audit's requirement (assign every load-bearing field on every terminal parser path) is
the right disposition. The report should also stop being silent about a warning present in
every build.

---

## Part 4 — scope and disclosure

| # | claim | verdict | evidence |
|---|---|---|---|
| 21 | the response is not bound to the DNP3 application sequence | **CONFIRMED** | the RESPONSE takes `tag_read_or_mark`, a raw read; no comparison against `meta.gen_in`. The in-source justification (a response may set CON and become `0xEn`) is inconsistent with the parser, which admits only `(app_control & 0xF0) == 0xC0` — so the low nibble *is* available for the supported subset. "Same transaction identity" in §9.7 should read "same generation domain". |
| 22 | not specifically a Class-0 READ defense | **CONFIRMED** | `p4/…p4:1058–1062` matches only `(app_control & 0xF0) == 0xC0` and `func_code == READ`. No object group, variation or qualifier is parsed. Any supported READ of the configured payload length arms the defense. The report never claims the P4 parses group 60, but "Evaluated using Class-0 READ transactions" is the accurate framing. |
| 23 | undisclosed protocol constraints | **CONFIRMED, and precisely so** | VLAN-tagged frames bypass (`ETHERTYPE_IPV4` only, no `0x8100` case, `p4/…p4:921`); `ihl == 5`, `MF == 0`, `frag_offset == 0` (`p4/…p4:950–953`); **pure ACKs accept `data_offset` 5–15 but DNP3-bearing packets only 5–8** (`p4/…p4:979–995`), so a response with more than 12 bytes of TCP options is forwarded unprotected. Only segmentation and concurrency are disclosed in §12.2. |
| 24 | requires plaintext DNP3 | **CONFIRMED** | the parser needs the function code, application control byte, transport FIR/FIN and TCP fields. §1 motivates the work partly with "encryption does not hide timing" without stating that this implementation cannot see inside encrypted traffic. Both statements are true; the report must carry the second one too. |
| 25 | global session state, and `0` is a valid TCP sequence | **CONFIRMED** | `p4/…p4:1289` `if (meta.seq_w != 32w0) { v = meta.seq_w; }` and `:1297` for the port. Every state register has size 1, so the limit is one protected TCP connection, not merely one transaction. |
| 26 | duplicate suppression changes TCP reliability | **CONFIRMED** | dropping a retransmission while the original is queued discards a recovery opportunity. Worth stating; the risk is small and bounded by the transaction lifetime. |
| 27 | "zero dropped packets" is imprecise | **CONFIRMED** | the mechanism deliberately drops tokens at the deadline, trigger clones, stale tokens and matching duplicates. The defensible claims are zero *queue* drops and zero unintended host-packet drops. |
| 28 | source comments are materially out of date | **PARTIALLY CONFIRMED** | spot-checked and true in substance — the header still describes a never-loaded compile-fit artifact while the body documents silicon results. Not exhaustively verified line by line. |
| 29 | the baseline file carries superseded data | **CONFIRMED** | `design/DEFENSE3_BASELINE.md:67` still reads "Native CLRT (n=100 **steady**) … max 21.695 ms" with no supersession notice, although `evidence/defense3/CORRECTION_cold_poll_in_C3.md` establishes that 21.695 ms was a connection-cold first poll. |

---

## Part 5 — statistics and claim strength

| # | claim | verdict |
|---|---|---|
| 13 | transactions treated as independent | **CONFIRMED.** 80 observations per arm come from 4 connections of 20 polls. The effective replication is 4 blocks, not 80 transactions. No block-clustered intervals, no connection-level bootstrap, no per-round results. The single rounds-1-2/3-4 split is better than fitting on the test set but quantifies no uncertainty. |
| 14 | Figure 1(b) mixes incommensurate quantities | **CONFIRMED.** "% collapsed below 0.1 ms" (a thresholded proportion) and separability × 100 (a ranking statistic) share one percentage axis. The qualitative conclusion survives on the AUROC and the held-out classifier alone; the numeric comparison should not be drawn on one scale. |
| 15 | "concealment" rests on an arbitrary 0.1 ms threshold | **CONFIRMED.** At D = 4 the report calls 63/80 concealed while CLRT separability is 0.966 — a feature that rank-separates at 0.966 has been transformed into a different recognizable distribution, not concealed. Use "collapsed below threshold" for the count and reserve "concealment" for a failed cross-device classifier. |
| 16 | cannot claim the threat-model objective is met | **CONFIRMED.** With one device, no confusion set and no device-model classifier, "the objective the threat model sets is met" and "the timing fingerprint is genuinely destroyed" are unsupported. This also contradicts the report's own §12.2. Both the title-page framing and the §11.2 box need rewriting. |
| 17 | defense detectability ≠ device identifiability | **CONFIRMED.** The campaign measures native-SEL vs defended-SEL (task A); the threat model concerns defended-SEL vs defended-other (task B). The report's detectability result is a genuine secondary leakage finding, not a refutation of device concealment — and grading against the broader criterion is the error the report itself records as mistake #1. |
| 18 | D = 1 ms is not a null control | **CONFIRMED.** It produces the predicted ≈1 ms shift (median 2.828 → 1.799). It is a sub-threshold / low-dose arm; the native arm is the null. |

---

## Part 6 — where the audit is wrong

### Item 12 — "the compile logs do not prove the reported resource numbers"

**NOT APPLICABLE TO THIS REPO.** `artifacts/resources/*.table_summary.log` contains exactly
the cited numbers:

```
bx_core.table_summary.log      ingress 9,  egress 0, critical path 8, 75 tables
bx_fulltel.table_summary.log   ingress 10, egress 0, critical path 8
bx_synth.table_summary.log     ingress 9,  egress 0, critical path 8
```

PHV occupancy, SALU instruction listings and artifact hashes are indeed absent and should
be added, but the specific resource claims are substantiated in-repo.

### Item 31 — "the supplied package omits the evidence"

**NOT APPLICABLE TO THIS REPO.** `evidence/physical/dsweep_blocks.jsonl` (24 blocks, 480
rows), all five analyzers, `test_tag_domain.py`, `assert_salu_asm.py`, `setarm.py`,
`block.py`, the control plane, the gate evidence tree and the physical captures are all
present and all four self-tests pass on a clean checkout. This is a packaging failure, not
a missing-artifact failure. The audit is careful to say so ("that absence is not evidence
of fabrication"), and it is right to withhold confirmation on what it could not see.

Its one substantive suspicion — the stale-response PASS — turns out to be justified, though
for a different reason (see item 1).

### Final disposition item — "reconcile 'outstation 0' with outstation address 10"

**REFUTED.** Outstation link address **0** is correct for the physical SEL-751 and was
verified on the wire on 2026-07-25 (READ dst=0 src=1 func=1; RESPONSE dst=1 src=0 func=129,
CRC-validated). Address 10 comes from the older 10.0.0.x capture corpus and is explicitly
superseded for the physical relay in the project's own `CLAUDE.md`. The audit is applying a
stale fact; no reconciliation is needed.

### Item 1's predicted signature

**REFUTED** as described above: `RESP_DUP_SUPP = 0` and `RESP_HOLD_EARLY = 1` in 3/3 reps,
so the specific failure chain the audit predicts did not occur in the recorded run. The
underlying defect is real; the evidence does not show it firing.

---

## Disposition, in priority order

**Blocking any further claim (report edits, no hardware):**

1. Correct 480 → 400 defended transactions in §12.1, the summary and the title-page framing.
2. Replace "all 80 land on the same 32 µs constant" with the measured distribution
   (median 32 µs, sd 12 µs, max 47 µs, 18 distinct values).
3. Split "release tail" into the internal 26 ns tail and the external ~32 µs ACK→RESPONSE gap.
4. Fix "the compiler accepted all four without complaint" and reclassify the four traps.
5. Withdraw §9.8's stale-response PASS and state why.
6. Rewrite §6.3's horizon inequality as `H > a + D + …` with the measured 1.49× worst case,
   and withdraw the claim that the 40 ms clamp blocks nothing.
7. Rewrite the strongest claims per item 30: CLRT compression on one device, not fingerprint
   destruction; state that physical results came from the 10-stage instrumented build.
8. Disclose the parser constraints (VLAN, IHL, fragmentation, TCP option width, one session)
   and the plaintext requirement.

**Code, before any further physical run.** Items 9–11 have since been designed and
compiled; see [`design/REPAIR_R1_R2_R3.md`](design/REPAIR_R1_R2_R3.md) and
`p4/case_a_defense3_repair_candidate.p4`. Status as of 2026-07-30:

9. **R1 — move the response marker write behind full validation. DONE, compiles at
   10/12** (from 9/12; critical path 8 → 10). The RESPONSE verdict never depended on
   `reg_tag`, so the same conjuncts resolve one level earlier and choose the delta;
   `reg_tag` keeps its placement and its four actions. Verified offline by 98 new
   assertions with a negative control (2 354 total, 0 failures).
10. **R2 — generation-qualified fail-open. REFUTED as specified.** Both obvious forms are
    hard target errors, reproduced in `p4/probe_failopen_qualification.p4`: a merged arm
    needs three PHV operands and fails the SALU input crossbar, and keeping the arms
    separate needs a fifth RegisterAction. Two structural options remain (a second
    register, or removing the data-plane write); both need a design decision.
11. **R3 — drop host-injected `0x88C1` frames instead of enqueuing them. DONE, free**:
    9 stages, critical path 8, resources bit-identical to baseline. This closes the only
    practical route to defect 2 while R2 is open.
12. Eliminate the uninitialized-metadata warning. **Not started.**
13. Recompute B from `a_max + D`, or reduce `D_MAX` to ≈ 24 ms. **Not started** (control
    plane only, no P4 risk).

All three repairs need a hardware gate before loading; nothing has been loaded.

**Re-test:**

14. Rerun the stale-response case with app 4 separately identifiable and its counters read
    back; add wrong-port and wrong-ACK response variants.
15. Sweep the ACK-retirement boundary at 0 / 32 / 64 / 128 / 256 / 512 ns / 1 µs, measuring
    master-facing egress order rather than ingress timestamps.
16. A short physical parity run on the 9-stage core build.

**Analysis:**

17. Block bootstrap with the connection as the resampling unit; leave-one-round-out
    evaluation; confidence intervals on AUROC and balanced accuracy.
18. Split Figure 1(b) so the proportion and the ranking statistic no longer share an axis.
19. Correct or rename `design/DEFENSE3_BASELINE.md`.

**Not accepted:** items 12 and 31 as stated (the artifacts and resource numbers are in this
repo), and the outstation-address reconciliation (address 0 is the verified value).

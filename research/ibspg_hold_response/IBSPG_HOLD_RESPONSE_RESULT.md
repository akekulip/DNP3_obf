# Part 12 — HOLD_RESPONSE deadline branch: RESULT

**Target:** Tofino-1, BF-SDE 9.13.2 (switch `10.10.54.81`), program `ibspg_hold_response`,
P4 source SHA-256 `fa073cf691a6beb45fa8ffa61146cf481fc81e42f6cf4640bcb44ae6fe08f947`.
**Dates:** designed/compiled/run 2026-07-25. Synthetic protocol roles only — no DNP3 parsing, no
physical SEL-751.

Evidence tags: `[DESIGN]` intent · `[DOC]` documented elsewhere · `[COMPILED]` compiler output ·
`[OBS]` single silicon observation · `[REP]` repeated/statistical · `[FIX]` corrected defect ·
`[OPEN]` unresolved.

> **SUPERSEDING NOTE 2026-07-25 (timing wording).** Earlier commits and an earlier revision of this
> file described the ~1.73 µs offset as "one loopback RTT". **That wording is withdrawn.** It was an
> unproven model, not a measurement: the independently measured single-token dp8 MAC-near loop RTT is
> **408 ns** (`research/ibspg_root_cause_repair/IBSPG_BLOCKER_LOOP_TIMING_REPORT.md`) `[DOC]`, so the
> offset is ≈4.2× a single traversal and cannot be one. The supported
> statement is *"released at the programmed deadline plus a stable ≈1.72 µs release tail"*, decomposed
> in §17. The earlier text is left in git history deliberately rather than rewritten.

---

## 1. Research question

Can a Tofino-1 release a **queue-resident** original packet at a **programmed wall-clock deadline**
derived from an earlier packet in the same transaction — with no controller action in the transaction
fast path, no explicit drain packet, no externally visible chaff, and no continuous recirculation of
the original packet — and is the resulting interval stable enough to serve as a timing normalizer?

Concretely: an observer measures the interval between an outstation's ACK and its response (the
Formby CLRT fingerprint). Can the switch make that interval a constant chosen by policy rather than a
property of the device?

## 2. Starting Part 9 / Part 11 primitives `[DOC]`

Part 12 changes only the *release trigger*; everything under it is inherited and unmodified.

- **Part 9** — controlled slot+generation-matched data-plane drain; queue-resident hold;
  byte-identical external release; FIFO preservation; unrelated/stale-generation drain rejection;
  separate pass-budget fail-open; 100/100 reps; blocker isolation; reservoir K=64 validated for the
  tested 11-stage program.
- **Part 11** — three strict-priority levels (Q_BLOCK 7 > Q_ACK 3 > Q_RESP 0); ACK-before-response
  structurally enforced; ACK still first when the RESPONSE is injected first; causal
  priority-collapse/restoration control; 100/100 randomized reps; ACK→response handoff 25–58 ns.

## 3. HOLD_RESPONSE architecture `[DESIGN]`

The other branch of the same unified transaction state machine:

- the **ACK is forwarded immediately** — never queued, never held — and its arrival stamps `t_ack`;
- only the **RESPONSE** is held, queue-resident in Q_RESP (qid1, `max_priority` LOW);
- the **blocker reservoir** in Q_BLOCK (qid7, `max_priority` HIGH) starves Q_RESP while it is occupied;
- each blocker token, on each loopback pass, **tests the deadline itself** and self-terminates once it
  has passed. When the reservoir empties, Q_RESP becomes the highest eligible queue and the response
  dequeues.

Two levels of strict priority suffice here (the ACK is never queued); the Part 11 three-level
configuration is harmless because qid5 is simply never used.

**There is no drain role and no drain register in this program.** The only release causes are the
deadline and the pass-budget fail-open, so no injected packet can cause a release — a strictly
stronger isolation property than Part 9 demonstrated.

## 4. ACK qualification logic `[DESIGN]` `[OBS]`

A fresh ACK arms the deadline only if **slot matches**, **generation matches**, and the transaction is
**armed** (`active==1`). A non-qualifying ACK is still **forwarded** — transparency is preserved — but
arms nothing, and is counted separately (`ctr_ack_bypass`). Measured in §12–13.

## 5. Deadline representation `[DESIGN]`

`deadline_tick = t_ack + G`, one 32-bit register (`reg_deadline`), nanoseconds, from
`ig_intr_md.ingress_mac_tstamp[31:0]`. `deadline == 0` means *unarmed*.

G is carried in the ACK's `hdr.ib.seq` field (**TEST_ONLY**) so a G sweep needs no control-plane write
per trial. In a deployment G is policy and belongs in a register or table; the mechanism under test
does not depend on which. `[OPEN]`

Bounds: the sign-bit test is valid for `0 ≤ G < 2^31` ns (~2.147 s) and the 32-bit ns clock wraps
every ~4.29 s; all differences are computed mod 2^32.

## 6. Deadline comparison and state machine `[COMPILED]` `[FIX]`

`age = now − deadline`; expired ⇔ a deadline is armed **and** `age`'s sign bit is 0.

Two compiler defects were hit and fixed, both the same underlying constraint `[FIX]`:

1. A bit-slice **inside a gateway condition** is rejected: `error: condition expression too complex`.
2. A bit-slice of a 32-bit arithmetic field **breaks PHV allocation entirely**, even when moved out of
   the gateway into a plain assignment: `PHV allocation was not successful — 12 field slices remain
   unallocated`, naming `meta.ts32`, `meta.dl_val`, `meta.dl_now`, `hdr.ib.seq` and
   `ig_intr_md.ingress_mac_tstamp`. This is the invalid-SuperCluster trap the Part 9/11 header warns
   about, reproduced exactly.

**Resolution:** decide expiry with a **ternary match on the sign bit** (`tbl_deadline_expiry`, key =
`dl_armed` exact + `age` ternary, one const entry `0 &&& 0x80000000`). The match unit tests the same
bit under a TCAM mask and creates no PHV slicing constraint; bf-p4c folds the single-entry const table
into gateway logic, so final TCAM usage is 0.

State registers keep the Part 9/11 discipline: `reg_gen → reg_active → reg_deadline`, each ONE
RegisterAction with ONE unconditional call site driven by upstream metadata write-enable/value fields.

**On-chip deadline arithmetic was verified every trial**, not assumed: `reg_deadline == (t_ack + G)
mod 2^32` in **100/100** campaign-A reps `[REP]`.

## 7. Blocker lifecycle `[DESIGN]` `[OBS]`

Termination priority: **stale** (`active==0` or generation mismatch) > **deadline** > **budget**
(fail-open watchdog, `hdr.ib.seq` decremented per pass). Deadline expiry deliberately does **not**
clear `active`, because the response is still queue-resident and its release path must stay reachable.

**Fail-open fingerprint (expected, not an anomaly) `[OBS]`:** the first token to exhaust its budget
clears `reg_active`, so the remaining K−1 terminate as *stale* on their next pass. At K=64 that is
`ctr_block_term_timeout=1, ctr_block_term_stale=63`. Same shape as Part 9's "1 controlled + K−1 stale"
cascade.

## 8. Resource use `[COMPILED]`

| | local 9.13.1 | on-switch 9.13.2 |
|---|---|---|
| errors / warnings | 0 / 2 (benign parser-unroll) | 0 / 2 (same) |
| ingress stages | **12 / 12** | **12 / 12** |
| egress stages | 0 | 0 |
| logical tables / SRAM / TCAM / map RAM | 44 / 36 / 0 / 36 | 44 / 36 / 0 / 36 |
| source SHA-256 | `fa073cf6…` | `fa073cf6…` (byte-identical, `sha256sum` on both hosts) |

No 9.13.1 → 9.13.2 drift. Fits at 12/12 with zero spare stages; the final stage is the timestamp
bank. Reclaim lever held in reserve: drop `reg_ts_first_block` (+ its event flag) — a timeline
convenience no gate depends on. Relevant to Part 13, which must add DNP3 parsing to this budget.

The on-switch compile was **non-destructive**: `bf_switchd` was not restarted and stayed on the Part 11
conf (PID 112251 before and after).

## 9. TM configuration `[OBS]`

Read back from hardware, and re-read inside **every** trial's reader json:

```
Q_BLOCK (dp8 qid7): max_priority "7"   min_priority "7"   scheduling_enable true
                    max_rate_enable false   dwrr_weight 1023
Q_RESP  (dp8 qid1): max_priority "LOW" min_priority "LOW" scheduling_enable true
                    max_rate_enable false   dwrr_weight 1023
```

`max_priority` is the active remaining-bandwidth strict field — the field whose absence was the root
cause of the original IBSPG failure. Ports: dp8 `BF_LPBK_MAC_NEAR` (internal loopback L), dp9 → Vision
(master side, released frames egress here), dp11 → Hulk (outstation side, injection lands here); all
`PORT_UP=True` at 25G, dp9/dp11 RS-FEC. All 18 bfrt objects (7 registers, 11 counters) resolve and
reset — verified before any traffic gate depended on them.

## 10. No-blocker control (Gate 12.3) `[OBS]`

K=0, everything else identical. The response egressed in **2.10 ms** — i.e. tracking the injector's own
0.5–2 ms spacing, not the 20 ms deadline — byte-identical, ACK first. **Without a blocker reservoir
nothing holds the response.** This is the control that makes every hold result below meaningful, and
it is also the honest statement of the mechanism's precondition: *established-before-admit* is a
harness obligation, not something the P4 enforces.

## 11. No-ACK fail-open control (Gate 12.4) `[OBS]`

K=64, no ACK at all. **127,989,373 blocker passes with no release**, then fail-open
(`ctr_block_term_timeout=1`, `ctr_block_term_stale=63`), response released byte-identically 1,720 ns
after the first termination. The response is not released early merely because it is queued.

## 12. Stale-generation ACK control (Gate 12.7) `[OBS]`

ACK carrying a generation that does not match the armed generation: **forwarded** (`ctr_ack_bypass=1`)
but **arms nothing** (`ctr_ack_arm=0`, `ctr_block_term_deadline=0`). 127,989,314 passes, then fail-open.

## 13. Unrelated-slot ACK control (Gate 12.7) `[OBS]`

ACK carrying `slot != 0`: identical signature — forwarded, arms nothing, 127,991,713 passes, fail-open.

**§10–13 together are the causal claim:** a qualifying ACK, and only a qualifying ACK, sets the release
time.

## 14. Valid qualifying ACK result (Gate 12.5) `[OBS]`

G = 20 ms: observed interval **20.0017 ms**, all 64 blockers deadline-terminated
(`ctr_block_term_deadline=64`, `timeout=0`, `stale=0`), response byte-identical, ACK first.

## 15. G sweep (Gate 12.6) `[OBS]`

K=64, response injected 0.5 ms after the ACK, one trial per point.

| G (ms) | observed (ns) | deadline error (ns) | release tail c2 (ns) | blocker passes | terminated by |
|---:|---:|---:|---:|---:|---|
| 1 | 1,001,744 | +1,744 | 1,719 | 1,901,830 | deadline ×64 |
| 2 | 2,001,736 | +1,736 | 1,719 | 1,948,627 | deadline ×64 |
| 5 | 5,001,742 | +1,742 | 1,721 | 2,059,773 | deadline ×64 |
| 10 | 10,001,724 | +1,724 | 1,720 | 2,246,934 | deadline ×64 |
| **17** | 17,001,743 | +1,743 | 1,720 | 2,506,597 | deadline ×64 |
| **25** | 25,001,721 | +1,721 | 1,721 | 2,803,872 | deadline ×64 |
| 40 | 40,001,731 | +1,731 | 1,721 | 3,361,896 | deadline ×64 |

Error 1,721–1,744 ns across a 40× range of G, spread 23 ns, with nothing tuned per point.
`ctr_block_term_timeout = 0` and `ctr_block_term_stale = 0` in all seven, so no point is contaminated
by the fail-open path.

## 16. SEL-related 17 ms and 25 ms targets `[OBS]`

17 ms and 25 ms are the measured SEL-751 native CLRT p95 and p99. Both are hit as precisely as every
other point (errors +1,743 and +1,721 ns), and both appear again in campaign B (§22). No target-specific
behaviour was observed anywhere in 1–40 ms.

## 17. Release-tail decomposition `[REP]` `[OPEN]`

The observable chain, and what is instrumented:

```
t_ack                          reg_ts_ack_arm            [instrumented]
  ↓ + G (programmed)
deadline reached               reg_deadline              [instrumented, arithmetic verified 100/100]
  ↓ c1
first blocker observes expiry  reg_ts_block_term         [instrumented]
  ↓ c2   (reservoir drains / becomes stale; Q_RESP becomes highest eligible; dequeue; egress dp9)
first RESPONSE released        reg_ts_first_resp_release [instrumented]
```

Campaign A, n=100, recomputed from raw registers (not from the reader's own derived block):

| component | min | median | p95 | p99 | max | mean | sd | range |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| **c1** deadline → first blocker termination (ns) | 0 | 15 | 25 | 26 | 26 | 14.4 | 7.16 | 26 |
| **c2** blocker termination → response released (ns) | 1,717 | 1,720 | 1,722 | 1,722 | 1,723 | 1,720.13 | 1.14 | 6 |
| **total** deadline error (ns) | 1,720 | 1,735 | 1,745 | 1,747 | 1,747 | 1,734.53 | 7.34 | 27 |

Readings:

- **c1 is essentially immediate** — a blocker notices the deadline within 0–26 ns, i.e. within roughly
  one pass. All of the total's variance comes from c1 (sd 7.16 of the total's 7.34).
- **c2 is the tail, and it is remarkably constant**: 1,720 ns ± 1.14, range 6 ns over 100 trials.
- Because c2 is constant across G (§15) and across repetition, it is an **implementation offset**, not
  random deadline error. A deployment can simply program `G' = G − 1.72 µs`.
- **What c2 is NOT:** it is ≈4.2× the independently measured single-token dp8 MAC-near loop RTT of
  **408 ns** (jitter 403–415, spread 12 ns) — `research/ibspg_root_cause_repair/IBSPG_BLOCKER_LOOP_TIMING_REPORT.md`
  and `IBSPG_EMPTY_GAP_MODEL.md` `[DOC]` — so it is not a single loop traversal. It plausibly covers draining/staling the
  remaining reservoir plus dequeue and egress, but **the internal composition of c2 is not directly
  instrumented** — there is no per-token termination timestamp and no queue-depth trace at this
  resolution. Stated as an open item rather than modelled. `[OPEN]`

## 18. On-chip timing `[REP]`

All intervals above are computed on-chip from `ingress_mac_tstamp` (ns) register pairs, with wrapping
32-bit arithmetic. This is the authoritative measurement.

## 19. Host-PCAP corroboration `[REP]`

Vision-side capture, campaign A, n=100: ACK→RESPONSE gap mean **19,994,187 ns**, median 19,994,974,
min 19,963,980, max 20,037,889, **sd 10,419 ns**.

This is **millisecond-scale corroboration only**. Kernel capture timestamps carry ~10 µs of jitter —
four orders of magnitude coarser than the on-chip figure — so the PCAP confirms *that the interval is
≈20 ms and that the response really left the switch*, and is explicitly **not** used to validate the
nanosecond-scale accuracy in §17. A single decoded example:

```
frames captured on Vision: 2
  t+0.000000s  etype=0x88c0 ACK       slot=0 gen=7 seq=20000000  len=60
  t+0.019990s  etype=0x88c0 RESPONSE  slot=0 gen=7 seq=1         len=60
```

The ACK's `seq` reads 20,000,000 — G in ns — confirming the value the switch armed from is the value
the generator sent.

## 20. Byte identity and FIFO `[REP]`

Every trial's verifier run passed all checks: response byte-identical to its reconstructed injected
twin (keyed by unique packet id: count, FIFO order, no duplicate / missing / corrupt / unexpected),
ACK byte-identical, ACK-before-response on the wire and on-chip. Campaign A: `ctr_resp_enq=1` and
`ctr_resp_release=1` in 100/100 — no missing, duplicate, or premature response, and no negative
deadline error in any rep.

Injected frames are **reconstructed** in the verifier rather than captured, because capturing on the
inject interface fights the AF_PACKET inject.

## 21. Token isolation `[REP]` `[FIX]`

Two independent methods, because the two host ports admit different ones:

- **dp9 / Vision — captured.** `[FIX]` The capture filter originally admitted only `0x88c0`, which
  would have made "no blocker tokens seen" a statement about the filter rather than about the switch.
  It was widened to `ether proto 0x88c0 or ether proto 0x88c1` and a `b3_no_blocker_escape` check added
  to the verifier **before any trial was run**. Result: **0 blocker frames across 100/100 campaign-A
  reps**, counted per rep from the capture itself.
- **dp11 / Hulk — cannot be captured** (it is the AF_PACKET inject interface). Switch-side counter
  instead: **`FramesTransmittedOK = 0`**. Nothing has *ever* been transmitted toward Hulk, so no token
  can have reached it.
- **dp8 / internal loopback:** `TX = RX = 411,276,249` — the blocker circulation is entirely internal.

## 22. 100-repetition campaign (Gate 12.9) `[REP]`

Two campaigns were run. Both are retained.

### Campaign A — fixed G = 20 ms, n=100

`evidence/part12/rep_campaign_100/` (per-rep RESULT log, reader json, verify json, Vision pcap;
`campaignA_summary.json`). Registers and counters reset before every rep.

| check | result |
|---|---|
| reps completed / unique / skipped / duplicated | 100 / 100 / 0 / 0 |
| `verify=PASS` | **100 / 100** |
| released by **deadline** | **100 / 100** (`ctr_block_term_deadline=64` each) |
| watchdog expiry in a deadline trial | **0 / 100** (`timeout=0`, `stale=0` each) |
| on-chip deadline arithmetic `deadline == t_ack+G` | **100 / 100** |
| reservoir `ctr_block_enq=64` | 100 / 100 |
| response enqueue / release = 1 / 1 | 100 / 100 (no missing, duplicate, corrupted) |
| ACK qualified exactly once | 100 / 100 |
| premature release (negative error) | **0 / 100** |
| blocker escapes at Vision | **0 / 100** |
| ACK before response (wire and on-chip) | 100 / 100 |
| reconciliation failures | **0** |

Distributions in §17 and §19. Blocker loops: mean 2,618,341, range 13,756.

`[FIX]` **Campaign A's runner did not capture the campaign process exit code** — the wrapper
discarded it. Integrity for A is established by the `CAMPAIGN_DONE reps=100` sentinel (written only if
the loop completed), 100 unique non-duplicated rep ids, per-rep artifacts, and the independent
reconciliation above. **Campaign B was run specifically to close this gap and exits 0** (§22B).

### Campaign B — randomized G, n=100, full capture `[REP]`

`evidence/part12/campaignB_randomG/` (per-rep RESULT log with per-trial rc, reader json, verify json,
Vision pcap; `campaign_meta.txt`; `campaignB_summary.json`). G is randomized over all eight swept
targets by a deterministic permutation (reproducible, no RNG state). Run 2026-07-25
**03:29:45.94Z → 03:41:01.59Z**, `campaign_exit_code: 0`, wrapper exit 0.

| check | result |
|---|---|
| campaign process exit code | **0** (the gap left open by campaign A, now closed) |
| reps logged / unique ids / duplicates / missing from 1..100 | 100 / 100 / **0** / **0** |
| per-trial exit code ≠ 0 | **0 / 100** |
| `verify=PASS` | **100 / 100** |
| released by **deadline** | **100 / 100** |
| watchdog expiry in a deadline trial | **0 / 100** |
| on-chip deadline arithmetic `deadline == t_ack+G` | **100 / 100** |
| premature release / missing / duplicate / corrupted response | **0 / 100** each |
| blocker escapes at Vision | **0 / 100** |
| reconciliation failures | **0** |

| quantity (ns) | min | median | p95 | p99 | max | mean | sd | range |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| deadline error | 1,720 | 1,733 | 1,746 | 1,747 | 1,747 | 1,733.99 | 8.38 | 27 |
| c1 deadline → blocker term | 0 | 13 | 26 | 27 | 27 | 13.72 | 8.46 | 27 |
| c2 blocker term → release | 1,719 | 1,720 | 1,722 | 1,723 | 1,723 | 1,720.27 | 1.02 | 4 |

**Deadline error broken down by G** — the point of randomizing:

| G (ms) | n | min | median | max | sd |
|---:|---:|---:|---:|---:|---:|
| 1 | 13 | 1,724 | 1,734 | 1,745 | 6.67 |
| 2 | 13 | 1,720 | 1,731 | 1,747 | 9.44 |
| 5 | 13 | 1,721 | 1,728 | 1,747 | 9.03 |
| 10 | 12 | 1,720 | 1,734 | 1,747 | 9.39 |
| **17** | 12 | 1,723 | 1,739 | 1,745 | 7.06 |
| 20 | 12 | 1,726 | 1,736 | 1,746 | 6.56 |
| **25** | 12 | 1,722 | 1,733 | 1,747 | 8.92 |
| 40 | 13 | 1,724 | 1,731 | 1,746 | 7.48 |

**No target-specific behaviour anywhere in 1–40 ms.** Every G shares the same tail to within a few ns
of median, and the sd is ~7–9 ns at every target. Campaign B interleaved the targets in a randomized
order, so this is not an artifact of running each G as a contiguous block.

### Both campaigns together

n=**200** repetitions, **200/200** released by deadline, **200/200** deadline arithmetic verified on
chip, **0** escapes, **0** premature releases, **0** failures, **0** watchdog expiries in a deadline
trial. Campaign A (fixed G) mean error 1,734.53 sd 7.34; campaign B (randomized G) mean 1,733.99
sd 8.38 — statistically indistinguishable, which is the reproducibility claim.

**Final port counters after both campaigns** (`evidence/part12/final_state/switch_port_counters.json`):
dp8 loopback `TX = RX = 908,070,328` (all blocker circulation internal); **dp9 `TX = 423`**, which is
≈2 frames (ACK + response) per trial across all 209 trials — i.e. the released-frame count is fully
accounted for with nothing extra egressing; **dp11 `TX = 0`** (nothing ever sent toward Hulk).

## 23. Failures and measurement corrections

Nothing in this line was worked around; each of these was diagnosed and fixed, and the earlier state
is left in git history.

1. `[FIX]` **Gateway bit-slice rejected** — §6.1. Cost one compile cycle.
2. `[FIX]` **PHV allocation broken by a 32-bit field slice** — §6.2. Cost one compile cycle. Resolved
   by the ternary sign-bit match.
3. `[FIX]` **Vacuous isolation proof** — the capture filter excluded the very ethertype the check was
   supposed to find, and the verifier parsed blocker frames without ever asserting their absence.
   Filter widened and `b3_no_blocker_escape` added before any trial ran (§21).
4. `[FIX]` **Duplicate check label** — two verifier checks shared the `b2` prefix; the isolation check
   was renamed `b3_no_blocker_escape` before the campaigns. The nine exploratory gate runs carry the
   older label.
5. `[FIX]` **Timing wording withdrawn** — "one loopback RTT" replaced by the measured decomposition
   (§17, and the superseding note at the top). The offset is ≈4.2× the ≈408 ns single-token loop RTT
   and cannot be a single traversal.
6. `[FIX]` **Campaign A exit code not captured** — the runner discarded it. Closed by campaign B,
   which records the campaign exit code (0), per-trial exit codes, and start/end timestamps.
7. `[OPEN]` **Response hold duration is not directly instrumented.** There is no response-admit
   timestamp register (it was removed to buy stage budget), so "how long the response sat in Q_RESP"
   can only be derived as `G − (response injection offset)`, not measured. Add a `reg_ts_resp_admit`
   in a later part if that quantity is needed.

## 24. Exact claims supported

> On Tofino-1, a qualifying ACK arms a slot- and generation-specific data-plane deadline that releases
> a queue-resident RESPONSE at `t_ack + G` plus a stable ≈1.72 µs release tail. Unrelated-slot and
> stale-generation ACKs do not arm release. Pass-budget expiry provides an independent fail-open path.
> The mechanism requires no controller action in the transaction fast path, no explicit drain packet,
> and no externally visible chaff.

Qualified by: Tofino-1 / BF-SDE 9.13.2; the tested dp8 MAC-near internal loopback; the tested
reservoir depth K=64; synthetic protocol roles; tested G range 1–40 ms; physical SEL not involved.

## 25. Remaining limitations — NOT yet claimed

- full DNP3 integration (Part 13); physical SEL validation; multi-master / multi-outstation scale;
  production readiness; universal target-independent behaviour.
- one fixed synthetic slot, one flow, one held response per transaction.
- G carried in the ACK (TEST_ONLY) rather than a policy register (§5).
- fail-open is a **pass budget**, not a wall clock: at K=64 a 2,000,000-pass budget worked out to
  roughly 3.4 s. A deployment wanting a wall-clock fail-open should arm a second deadline.
- c2's internal composition is uninstrumented (§17).
- `deadline == 0` doubles as the unarmed sentinel; a genuine deadline landing exactly on 0 (p = 2⁻³²)
  would fall through to fail-open. Recorded, not defended against.

## 26. Part 13 integration gate

Part 13 replaces synthetic role markers with correctly classified **real DNP3 frames** under replay —
parser-hardened classifier, transaction slot allocation, slot+generation matching, direction mapping,
HOLD_ACK controlled drain, ACK-before-response, HOLD_RESPONSE deadline release, timeout/fail-open,
full-frame byte preservation, token isolation — **without redesigning the validated scheduler
mechanism**. Replay first; no physical SEL; no DNP3 writes or control commands.

The binding constraint is **stage budget**: this program already fits at 12/12 with zero spare, so
DNP3 parsing must be paid for out of telemetry that is no longer load-bearing (the reclaim lever in
§8), never out of fail-open, generation safety, token isolation, or parser validation.

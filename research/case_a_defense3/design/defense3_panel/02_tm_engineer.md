# Panel memo B — Traffic Manager and queue-scheduling engineer

**Scope:** DEFENSE 3, two-queue construction (`Q_BLOCK` HIGH > `Q_HOLD` LOW), K=64 request-triggered
blocker reservoir, one deadline `d_ACK = t_ACK + D`.
**Status:** analysis only. No code, no compile, no switch load. One read-only `ssh` executed
(process/conf-file identity of the currently loaded program).

---

## Verdict

Two queues are sufficient, and the two-queue construction is a strict, safe subset of the
four-level ordering already proven on this silicon. Ordering is **not** guaranteed by FIFO alone —
it is guaranteed by FIFO **plus** the requirement that the ACK and the RESPONSE traverse the same
number of loopback passes, or that the RESPONSE's shortcut is gated on a fact that the ingress
pipeline has already ordered. Three things must be fixed or added relative to the current
Defense 2 setup:

1. the early/late discriminator must be `ack_release_gen == current_generation` and must contain
   **no deadline term whatsoever** (§3);
2. the per-queue and per-port shapers on dp8 must be explicitly forced off and read back — the
   Defense 2 setup does neither, and the four-queue oracle work leaves the dp8 **port** shaper as
   an armed release gate (§5);
3. dp8 `$SPEED` must be read back and asserted at `BF_SPEED_25G` — the K=64 safety margin is
   speed-conditional, and one prior run was invalidated by dp8 silently sitting at 10G (§2, §5).

The fail-open budget value `B = 100000` is adequate for all of D ∈ {1, 2, 3} ms and should be kept.
Its justifying comment is wrong by ~5.8× and must be rewritten, because the wrong model gives the
wrong answer the moment anyone changes D, K, or dp8's speed (§4).

---

## 0. The configuration being analysed

Read from `research/defense2_pktgen/setup/dnp3_timing_normalizer_pktgen_setup.py` and
`research/defense2_pktgen/p4/dnp3_timing_normalizer_pktgen.p4`.

| element | value | note |
|---|---|---|
| master-facing port | dp9, `BF_SPEED_25G` | Vision |
| relay-facing port | dp64, `BF_SPEED_1G` | physical SEL-751 leg |
| hold ring | dp8, `BF_SPEED_25G`, `BF_LPBK_MAC_NEAR` | port group `pg_id=2`, `pg_l_nr=0` |
| pktgen source/recirc | dp68 | pipe 0 |
| `Q_BLOCK` | dp8 qid **7**, `max_priority=HIGH` | reservoir |
| `Q_HOLD` | dp8 qid **1**, `max_priority=LOW` | Defense 2's `Q_RESP`, renamed, new occupant |
| final master FIFO | dp9 qid **0** | `to_fwd()` sets `ig_tm_md.qid = 5w0` |

All of dp8 / dp9 / dp64 / dp68 are in **pipe 0**. This is load-bearing and must be asserted, not
assumed: registers on TF1 are per-pipe, so a leg on another pipe splits the state machine silently
and the transaction fails open with no error.

**Keep Defense 2's qid numbering.** Q_BLOCK=7 / Q_HOLD=1 carries over the `pg_queue = pg_l_nr*8 +
qid` arithmetic, the restore path, and the four-queue evidence unchanged. Renumbering buys nothing
and invalidates the inherited configuration.

### Derived ring arithmetic (used throughout)

MEASURED inputs: dp8 loop rate **37.4 Mpps** (`ibspg_hold_response`: 1,460,066 passes over 39 ms);
unloaded single-token dp8 loop RTT **T_f = 408 ns**; Part 12 release tail **~1.72 µs**; Part 12
deadline-release spread **~23 ns**.

Sanity: a 64 B frame on a 25G link occupies 64+8+12 = 84 B = 672 bit-times → 25e9/672 = **37.2 Mpps**.
The measured 37.4 Mpps is line rate. **The dp8 egress port is the ring's bottleneck**, which is the
entire reason the reservoir works — see §2.

DERIVED:

```
τ   (per-token loop period)   = K / rate      = 64 / 37.4e6   = 1.711 µs   [repo states 1.715 µs]
N_f (tokens in flight)        = rate × T_f    = 37.4e6 × 408e-9 = 15.3
B_q (standing Q_BLOCK backlog)= K − N_f       = 64 − 15.3      = 48.7 frames ≈ 49 cells
```

---

## 1. Is two queues sufficient, and what actually guarantees ACK-before-RESPONSE?

**Sufficient: yes.** The four-queue oracle established four-level strict priority behaviourally on
this silicon, with control C (reversing *only* `max_priority`) reversing the dequeue order
(`FOUR_QUEUE_ORACLE_CLOSED.md`). Two levels is a strict subset of that result — same table, same
field, fewer distinct values. Nothing in Defense 3 needs a priority relation that the oracle did
not exercise.

But the priority relation only buys one thing: **Q_HOLD is not served while Q_BLOCK is backlogged.**
That is the *hold*. It says nothing about ACK-before-RESPONSE. That ordering comes from a different
property, and it is worth stating the guarantee precisely:

> **Ordering lemma.** Every protected packet reaches the master by exactly one path —
> dp64 ingress → pipe 0 → `Q_HOLD` (dp8 qid 1) → dp8 egress → MAC-near loopback → dp8 ingress →
> pipe 0 → dp9 qid 0 → master. dp8 egress and dp9 egress are each a single serialization point, and
> the ingress pipeline is in-order. So ACK-before-RESPONSE holds **iff** the ACK is enqueued ahead
> of the RESPONSE at every one of those points, which reduces to: same ingress port, same dp8 qid,
> **equal loopback pass count**, and same dp9 qid.

"Equal pass count" is the condition that the prior design broke. Full enumeration:

| # | Violation mechanism | How it is excluded |
|---|---|---|
| V1 | ACK and RESPONSE enter on **different ingress ports**, so their relative enqueue order into Q_HOLD is an inter-port race | Both are relay-sourced on **dp64** (single 1G link). Assert in setup; refuse a split relay leg. The 1G leg also guarantees ≥ ~0.67 µs of natural wire separation, so a same-cycle race is not physically reachable. |
| V2 | RESPONSE assigned a **different dp8 qid** than the ACK (e.g. lands on Q_BLOCK=7, HIGH → jumps it) | Structural: exactly one action `to_hold()` may write `ig_tm_md.qid = QID_HOLD`, and it is the only qid a non-blocker can receive. Prove from `pipe/context.json` action immediates, not from source reading. |
| V3 | **Unequal loopback pass count** — RESPONSE takes 0 passes (direct forward) while the ACK still has ≥1 pass to run | **This is the real defect.** Excluded only by making the direct-forward branch conditional on `ack_release_gen == cur_gen`, never on the deadline. Full analysis in §3. |
| V4 | ACK and RESPONSE assigned **different qids on dp9**, letting the dp9 scheduler reorder | Structural: one master-facing action `to_fwd()`, `qid = 5w0`, used by every path. Defense 2 already does this — do not add a second master-facing action. |
| V5 | **Ingress reordering** via resubmit / recirculate / mirror on the protected path | None used. The only mirror is the READ→dp68 pktgen trigger clone, which never reaches dp9. Assert: no resubmit on any protected path. |
| V6 | **Pipe split** — a leg on a pipe other than the loopback's | All of dp8/9/64/68 in pipe 0. Assert from `tf1.tm.port.cfg` readback. Failure mode is silent fail-open, not an error. |
| V7 | Reorder **inside the dp8 loopback** between Q_HOLD dequeue and re-ingress | dp8 is one physical port with one MAC; MAC-near loopback preserves frame order. This single serialization point is what makes the §3 corner case safe. |
| V8 | RESPONSE enqueued to Q_HOLD with **no ACK ahead of it** (ACK never admitted, or arrival inverted by retransmission) | Hold only when `deadline_valid == 1`. With no admitted ACK the RESPONSE must be **bypassed**, not held — a held response with nothing ahead of it is the one configuration where the defense itself creates the reorder. Add `ctr_resp_no_ack_bypass`. Predicate detail is panelist C's. |
| V9 | Blocker token **leaks to dp9**, appearing between ACK and RESPONSE | Parser forces `0x88C1 → ROLE_BLOCK`; `to_block()` is a token's only egress; termination is `drop_pkt()` at ingress. External gate: `eth.type == 0x88C1` count **0** on dp9 and dp64 captures. |
| V10 | **Cut-through** on dp9 changing effective order | Within a single qid, cut-through changes when transmission starts, not the order. Only one qid is in use on dp9. Not a hazard; noted for completeness. |
| V11 | Apparent reorder **off-switch** (master NIC RSS spreading ACK and RESPONSE across RX queues, capture artifacts) | Measure order as frame index within **one** capture on **one** interface (`tcpdump -Q in` on the master leg is known to work here). Do not score ordering from a multi-queue merge. |

Cost of the guarantee: `Q_HOLD` holds at most **2** packets, so this is a depth-2 FIFO. No sizing
concern. The dp8 pool carries ~49 blocker cells + 2 held cells ≈ 51 cells — negligible against any
TM pool. Still gate on `tf1.tm.counter.queue drop_count_packets == 0` for both queues: the shared TM
buffer *can* drop a held packet, and a dropped ACK is indistinguishable from a defense failure in
the master-side pcap.

---

## 2. The empty-gap risk

### The occupancy dynamic is structural, not statistical

A token is absent from `Q_BLOCK` only while it is in flight (dequeue → dp8 wire → ingress → TM
re-enqueue). The ring is at **line rate**: the dp8 egress port is the bottleneck, so tokens queue up
behind it. By Little's law on the in-flight subsystem:

```
in flight   = rate × T_f = 37.4e6 × 408e-9 = 15.3 tokens
Q_BLOCK     = K − 15.3   = 48.7 frames  (K = 64)
gap iff       K ≤ rate × T_f   →   K_min ≈ 16   at 25G
```

So at K=64 the reservoir carries a **standing backlog of ~49 frames** and the margin to the gap
condition is **4.2×**. This is a hard-bottleneck argument, not a probabilistic one, and it explains
the repo's own history: at K=1 the single token spends its entire 408 ns loop out of the queue, so
Q_BLOCK is empty essentially always — exactly the Part 9 K=1 failure.

**The margin is speed-conditional**, and this is the part the directive's "K=64 is the validated
safe reservoir depth" language hides:

| dp8 speed | rate (64 B) | in flight | Q_BLOCK backlog | K_min | margin at K=64 |
|---|---|---|---|---|---|
| 10G | 14.9 Mpps | 6.1 | 57.9 | ~7 | 10.5× |
| **25G** | **37.4 Mpps** | **15.3** | **48.7** | **~16** | **4.2×** |
| 40G | 59.5 Mpps | 24.3 | 39.7 | ~25 | 2.6× |
| 100G | 148.8 Mpps | 60.7 | **3.3** | ~61 | **1.05×** |

At 100G, K=64 has three frames of margin and is not safe. dp8 `$SPEED` is therefore a **correctness
parameter of the reservoir**, not a link setting, and must be a hard readback gate.

### The risk window is smaller than the directive implies

The gap only matters when `Q_HOLD` is non-empty — i.e. between **t_ACK and d_ACK**, a span of exactly
**D**. Before the ACK is admitted, `Q_HOLD` is empty, a gap releases nothing, and the ring self-heals
(a gap does not terminate tokens; they return and re-fill). Directive §7's "blockers must continue
circulating while `deadline_valid == 0`" is correct as a mechanism, but it should not be read as a
correctness requirement: **no gap guarantee is needed in the pre-ACK phase.** Concentrate design and
test effort on the D-length window.

### Instrumentation, given `usage_cells` is unusable

`usage_cells` read 0 on dp8 queues in all five shaper settings including one that demonstrably
leaked. Do not gate on it and do not report it. Replacements, in descending order of strength:

1. **Outcome gate (definitive).** Measured ACK hold duration at the master ≥ D, 100/100. Any gap
   that mattered releases the ACK early, and that is directly visible in the master-side capture.
   Everything below exists to attribute a failure, not to detect one.
2. **Token conservation (the real drain test).** Per fresh READ: `ctr_pktgen_admit == 64`;
   `ctr_block_term_stale + _deadline + _timeout == ctr_pktgen_admit` per generation;
   `ctr_pktgen_drop` accounts for every token generated with no active transaction. A conservation
   violation means tokens left the ring by an unaccounted path.
3. **Loop count vs. wall clock (cheapest gap proxy, no new resources).** `ctr_block_loop` over one
   transaction should be ≈ `(a + D) × 37.4e6`. For D=2 ms and a≈0.5 ms that is **~93,500**. A
   shortfall means the ring stalled. This counter already exists.
4. **`watermark_cells` as a quantitative model check, not a presence check.** Clear it (write 0)
   before each transaction; after the hold it should read **≈ 49**. Gate at ≥ 32. A reading of ~5
   falsifies the saturation model and invalidates the whole margin argument — that is precisely the
   signal worth having. (`watermark_cells` is a max gauge, so it can never prove non-emptiness; it
   can prove the backlog was the predicted depth, which is the useful half.)
5. **dp8 MAC TX as dequeue ground truth.** ΔTX(dp8) across the hold ≈ `(a+D) × 37.4e6 + 2`. Idle time
   on dp8 shows up here as a TX shortfall independent of any P4 counter.
6. **Max inter-dequeue gap (instrumented build only — the only true on-chip gap detector).** Two
   SALUs: `reg_last_ts` returns `now − last` and writes `now`; `reg_max_gap` keeps the running max.
   Nominal Δ is 26.7 ns (one 64 B slot at 25G); any Δ above ~200 ns on a current-generation blocker
   is a stall signature. Costs 1 extra register + 1 SALU over the plain build; keep it out of the
   production program.

### Recommended negative control

Rerun Gate 2 once with the pktgen batch at **K=8** (below the predicted K_min ≈ 16) and require the
ACK to escape early. This validates the entire instrument chain — an instrument set that cannot
detect a deliberately-broken reservoir cannot certify a working one — and it demonstrates that the
failure boundary is real. It does **not** claim K=64 is minimal, so it is directive-compliant.
An optional K ∈ {16, 32} probe would locate the boundary and test the Little's-law model; that is
model validation only, and the production reservoir stays at 64.

---

## 3. Release ordering at the deadline

### The window, quantified

At the deadline instant, ~49 tokens are resident in Q_BLOCK and ~15 are in flight. The in-flight
ones arrive after the deadline, fail the expiry check, and are dropped at ingress — they never
re-enter Q_BLOCK. So the drain is just the resident backlog, at the port rate:

```
drain      = (K − N_f)/rate = 48.7 / 37.4e6      = 1.303 µs
+ ACK loop = T_f                                 = 0.408 µs
─────────────────────────────────────────────────────────────
release tail (deadline → ACK enqueued at dp9)    = K / rate = 1.711 µs
```

The `T_f` terms cancel: **the release tail is exactly one reservoir loop period, K/rate.**
Predicted 1.711 µs against Part 12's measured **1.72 µs** — 0.5% agreement. Two further
consistency checks fall out: the release instant is quantized to the dp8 dequeue slot (26.7 ns at
25G), matching Part 12's measured **~23 ns** spread; and the tail should scale linearly with K,
so K=32 predicts ~0.86 µs — a cheap falsifiable test if anyone wants to confirm the model.

This is a **deterministic, K-proportional bias on every hold**, not jitter (see disagreement D4).

### Can a late RESPONSE overtake the ACK in that window?

**Yes — if the discriminator is the deadline.** During the full 1.711 µs the ACK is still in the
drain or on the loopback. A RESPONSE arriving in that window, tested against `now >= ack_deadline`,
is classified LATE, takes **zero** loopback passes (dp64 → pipe 0 → dp9), and is enqueued at dp9
ahead of an ACK that still has up to 1.711 µs to run. That is violation V3 and it is exactly the
defect the prior design hit.

The directive already prescribes the right fix in §7 — "if the matching RESPONSE arrives **after the
ACK release pass**" and "use `ack_release_gen == current_generation`". I want to reinforce that this
is the single most important sentence in §7, and that the natural implementation shortcut
(`now >= ack_deadline`) is the wrong one.

### Recommended construction

**Make the discriminator a pipeline-ordered fact, not a clock fact.** Then the window is not
narrowed — it is eliminated, because the ACK's write and the RESPONSE's read are ordered by the
ingress pipeline itself.

- One register `reg_ack_release`, written **only** on the ACK's dp8 return pass, in the **same
  ingress pass and same action block** that calls `to_fwd()`. Do not let a predicate separate the
  write from the forward.
- Two mutually-exclusive RegisterActions on it (Defense 2's proven `tag_read` / `tag_rmw` idiom —
  mutually exclusive per packet, so one SALU access):
  - `ack_rel_set` — writes `cur_gen`, used on the ACK release pass;
  - `ack_rel_read` — no write, returns `cur_gen − v`, used on the RESPONSE path.
  Returning the **difference** folds the compare into the SALU output and costs no MAU level.
- RESPONSE decision, with **no deadline term anywhere in it**:
  ```
  if (ack_rel_diff == 0)  to_fwd();     // ACK already enqueued at dp9, strictly earlier
  else                    to_hold();    // ACK not yet out: queue behind it
  ```

**Why this is complete.** Both branches preserve order, including the corner case:

- *Branch `to_hold()`, ACK still in Q_HOLD* — normal early response, FIFO does the work.
- *Branch `to_hold()`, ACK already dequeued from Q_HOLD but its return pass has not yet written
  the register* — the RESPONSE lands in a now-eligible Q_HOLD and is dequeued almost immediately.
  It still lands behind the ACK, because the ACK was serialized out of dp8 **before** the RESPONSE
  was even enqueued, and dp8 is a single serialization point that preserves order (V7). Equal pass
  count, ACK ahead.
- *Branch `to_fwd()`* — the register write happened on a packet strictly ahead of this one in the
  same in-order ingress pipeline, so the ACK is already enqueued at dp9 qid 0. Same qid, FIFO holds.

**Failure polarity.** Default to holding. `to_fwd()` on the RESPONSE path is the only branch that
can reorder, so it must be the narrow, explicitly-gated exception. If the register read is ever
ambiguous, hold — a late ACK costs latency; a reordered RESPONSE breaks the mechanism *and* is a
protocol-visible defect.

**Verification.** Structural exclusion beats a runtime check: there should be no code path that
forwards a protected RESPONSE directly while `ack_rel_diff != 0`, so no counter is needed to catch
one. Instead gate on:
- `ctr_resp_hold + ctr_resp_fwd_after_release == transactions` (every RESPONSE took one of the two
  legal branches);
- per-transaction pcap: ACK frame index < RESPONSE frame index, 100/100, from a single capture on a
  single interface.

---

## 4. Fail-open budget sizing for D ∈ {1, 2, 3} ms

### Correct model

The budget is **per token**, decremented once per that token's own loop:

```
H (fail-open horizon) = B × τ = B × K / rate_dp8
```

At B = 100000, K = 64, 25G: **H = 171.1 ms** (repo states 171.5 ms; same number).

The existing comment in `dnp3_timing_normalizer_pktgen.p4` (~line 212) says "the ~10 us/pass
Q_BLOCK shaper rate", which gives H = 1 s. The measured pass time is 1.715 µs, so the comment is
**~5.8× wrong**. The *value* survives the error; the *model* does not, and the model is what someone
will use the next time D, K, or dp8's speed changes.

### Required horizon

The reservoir must survive from the burst (at `t_READ`) to `d_ACK`, i.e. `T_hold = a + D`, where
`a` = READ→ACK. MEASURED on the physical SEL-751 (n=100 steady state,
`case_a_fixed_ack_delay/evidence/envelope_analysis_result.txt`): **median a = 0.505 ms, sd = 0.391 ms**.
The worst observed `a` is bounded above by **22 ms** (the A=22 ms row reaches 100/100 coverage), driven
by the connection-cold first poll.

| D | nominal hold (a=0.505) | margin H/T | worst-case hold (a=22) | margin H/T |
|---|---|---|---|---|
| 1 ms | 1.505 ms | **114×** | 23.0 ms | **7.4×** |
| 2 ms | 2.505 ms | **68×** | 24.0 ms | **7.1×** |
| 3 ms | 3.505 ms | **49×** | 25.0 ms | **6.8×** |

**Recommendation: keep B = 100000 for all three D.** It clears the worst observed transaction by
~7× and the typical one by 50–110×, and "do not change what is proven" outweighs the marginal
benefit of a tighter value. Two changes are required alongside it:

1. **Rewrite the comment** to `H = B × K / rate_dp8`, stating the measured 37.4 Mpps and 1.715 µs.
2. **Derive and assert H at setup time** from the *readback* dp8 speed and the configured K and B,
   and refuse to run if `H < 4 × (a_max + D)`. This matters because H scales with speed in the
   dangerous direction: at 10G, H = 428 ms (safe, just slow to clear a stuck transaction); at 100G,
   **H = 43 ms**, only 1.7× the 25 ms worst case. A silent dp8 speed change is a documented failure
   mode in this repo — the four-queue Control A rerun was invalidated by dp8 sitting at 10G.

### Two consequences worth stating

- **Fail-open in Defense 3 fails toward forwarding.** Budget exhaustion drains Q_BLOCK, Q_HOLD
  becomes eligible, and the ACK leaves. No packet is lost, but the defense is absent for that
  transaction. It must be counted (`ctr_release_fail_open` / `ACK_MISSING_FAIL_OPEN`) and excluded
  from the protected arm's statistics, not silently averaged in.
- **Internal load is not a problem at DNP3 rates.** The ring runs dp8 at line rate for `(a + D)`:
  ~131,000 frame passes / 25 Gbps for 3.5 ms at D=3 ms. At 1 Hz polling that is a **0.35% duty
  cycle**; at 10 Hz, 3.5%. The pathological ACK-missing case runs 171 ms, a 17% duty cycle at 1 Hz —
  bounded and acceptable. The mechanism study's objection that the reservoir is "heavy" is correct
  per transaction and irrelevant per second (see D5).

---

## 5. Queue / shaper configuration and restoration

### Configuration (dp8, `pg_id=2`, `pg_l_nr=0`; `pg_queue = pg_l_nr*8 + qid`)

| table | key | write |
|---|---|---|
| `tf1.tm.queue.sched_cfg` | (pg_id=2, pg_queue=7) | `scheduling_enable=True`, `max_priority='HIGH'`, `min_priority='HIGH'`, **`max_rate_enable=False`**, **`min_rate_enable=False`** |
| `tf1.tm.queue.sched_cfg` | (pg_id=2, pg_queue=1) | `scheduling_enable=True`, `max_priority='LOW'`, `min_priority='LOW'`, **`max_rate_enable=False`**, **`min_rate_enable=False`** |
| `tf1.tm.port.sched_cfg` | dev_port=8 | **`max_rate_enable=False`**, `scheduling_speed=BF_SPEED_25G` |
| `$PORT` | dev_port=8 | `$SPEED=BF_SPEED_25G`, `$FEC=BF_FEC_TYP_NONE`, `$AUTO_NEGOTIATION=PM_AN_FORCE_DISABLE`, `$LOOPBACK_MODE=BF_LPBK_MAC_NEAR`, `$PORT_ENABLE=True` |
| `tf1.tm.counter.queue` | both queues | write `watermark_cells=0`, `drop_count_packets=0` before each transaction |
| dp9 / dp64 | — | **do not touch** scheduling; single qid 0 in use on dp9 |

`min_priority` is inert unless `min_rate_enable=True`, which we force off. Write it for parity with
the proven Defense 2 config, but **gate only on `max_priority`** — the original IBSPG root cause was
setting the inert field and getting a silent fair split.

**Three gaps in the current Defense 2 setup that must be closed for Defense 3:**

1. It never writes `max_rate_enable` / `min_rate_enable` on the dp8 queues. A shaped Q_BLOCK goes
   shaping-**ineligible** and the TM serves Q_HOLD instead — a false early release that is
   indistinguishable from an empty gap in every instrument in §2. Force both off explicitly.
2. It never touches `tf1.tm.port.sched_cfg` on dp8. The four-queue oracle work uses the dp8 **port**
   shaper as a single-write global release gate; a Defense 3 run that inherits an armed port shaper
   from a prior oracle session gates the entire ring. Force `max_rate_enable=False` and read it back.
3. It never reads back dp8 `$SPEED`. See §2 — the K=64 margin is speed-conditional.

### Mandatory readback gates before any trial

1. `max_priority[Q_BLOCK] == HIGH (7)` **>** `max_priority[Q_HOLD] == LOW (0)`; both
   `scheduling_enable == True`.
2. Both queues: `max_rate_enable == False`, `min_rate_enable == False`.
3. dp8 port: `max_rate_enable == False`, `scheduling_speed == BF_SPEED_25G`.
4. dp8 `$PORT`: `$PORT_UP == True`, `$SPEED == BF_SPEED_25G`, `$LOOPBACK_MODE == BF_LPBK_MAC_NEAR`.
5. `pg_id` / `pg_l_nr` **derived** from `tf1.tm.port.cfg` for dp8, not the hardcoded `--pg-l 2
   --pg-l-nr 0` defaults; assert the derived values match.
6. All of dp8 / dp9 / dp64 / dp68 report **pipe 0**.
7. Both queues: `drop_count_packets == 0` at read-out.

Compare every readback against what was written and treat a silent clamp as a STOP, not a warning.

### Restoration

The switch currently runs Defense 2 — verified read-only this session:
`pgrep -cx bf_switchd` → 1, `--conf-file /home/decps/defense2_pktgen_compile/pktgen_abs.conf`.
That conf file is the restore target.

- **Snapshot first.** Write a pre-run JSON snapshot of every field in the table above (plus the
  pktgen app state) before touching anything. Restore reads from the snapshot, not from constants.
- **One guarded restore on an EXIT trap.** INT/TERM/HUP should `exit` so they converge on the single
  EXIT path. Restore must be **idempotent and convergent**: if `bf_switchd` is already running the
  right conf, re-assert the control plane and verify — do **not** cycle the daemon.
- **Restore, in order:** reload Defense 2 (only if displaced) → re-assert Q_BLOCK/Q_RESP priorities →
  restore dp8 `$SPEED` / `$LOOPBACK_MODE` / `$PORT_ENABLE` from snapshot → disarm the dp8 port shaper
  → restore per-queue shaper enables from snapshot → disable the Defense 3 pktgen app
  (`pktgen_enable=False`) and restore `tf1.pktgen.port_cfg` on dp68 from snapshot.
- **Verify restore** with the same seven readback gates, plus `pgrep -cx bf_switchd == 1` (never
  `pgrep -cf` — it returns 3 for one daemon here), plus the loaded program name read authoritatively
  from `/proc/$(pgrep -ox bf_switchd)/cmdline` → `--conf-file` → JSON
  `p4_devices[0].p4_programs[0]["program-name"]`, not from a setup script's belief.
- **External isolation gate:** `eth.type == 0x88C1` count **0** on both dp9 and dp64 host captures,
  every run.

---

## 6. Disagreements with, and corrections to, the directive

**D1 — §6's "K=64 is the validated safe reservoir depth" is incomplete: it is speed-conditional.**
The margin is 4.2× at 25G, 2.6× at 40G and ~1.05× at 100G. K=64 is only a validated depth when paired
with a hard dp8 `$SPEED == BF_SPEED_25G` readback gate. This is a missing precondition, not a
redesign request. I fully support keeping K=64 and making no claim of minimality.

**D2 — §7's pre-ACK gap requirement is stronger than correctness needs.** While `deadline_valid == 0`,
Q_HOLD is empty, so a momentary Q_BLOCK gap releases nothing and the ring self-heals. The genuine
risk window is `(t_ACK, d_ACK)`, of length exactly D. Keep the mechanism as written; correct the risk
model, and spend the test budget on the D-length window.

**D3 — §7's release-pass discriminator is right, and I want it strengthened to a structural rule.**
The RESPONSE path should contain **no deadline term at all**, so that `now >= ack_deadline` cannot be
reintroduced by a later edit. This is the single sentence in §7 that the whole ordering guarantee
rests on.

**D4 — the directive conflates the deadline instant with the release instant; they differ by
K/rate = 1.711 µs.** "When all blockers terminate → Q_BLOCK empty → ACK leaves" is true, but the
residual backlog must drain first. The consequence is a deterministic, K-proportional **bias** on
every measured hold — not jitter. Gate 2 and the physical campaign must score configured-deadline
error against `D + K/rate_dp8`, or every transaction reads ~1.7 µs late and a systematic offset gets
misreported as spread. (Independently confirmed: predicted 1.711 µs vs Part 12's measured 1.72 µs;
the ~23 ns spread is one dp8 dequeue slot.)

**D5 — I do not support the mechanism study's recommendation to drop the reservoir on internal-load
grounds.** 37.4 Mpps for the duration of the hold is a real per-transaction cost and a 0.35% duty
cycle at DNP3 poll rates. The reservoir is the proven construction; the load objection does not
justify overriding the directive.

**D6 — for panelist E: the study's `δ_release = 0.050 ms` is not a hardware number.** The hardware
ACK→RESPONSE floor for an early response is the Q_HOLD dequeue spacing plus the dp9 serialization
slot — tens of nanoseconds at 25G, three orders of magnitude below 50 µs. Whatever the master
actually observes is set by NIC coalescing and capture resolution, not by the switch. The D=1/2/3
entropy tables depend on this constant at the low end, so it must be replaced with a value measured
in Gate 2 rather than carried forward.

---

## 7. What I need from the other panelists

- **A (pipeline/PHV):** confirm `reg_ack_release` fits as one register with two mutually-exclusive
  RegisterActions, and that the register write and `to_fwd()` land in the same action block on the
  ACK release pass. Deleting Defense 2's G-guard block should more than pay for it.
- **C (protocol):** the ACK and RESPONSE predicates must both pin the relay-facing ingress port
  (V1), and must define what happens to a RESPONSE arriving with `deadline_valid == 0` — my
  requirement is **bypass, never hold** (V8).
- **E (methods):** the K/rate release-tail bias (D4) and the δ_release correction (D6) both change
  how the timing results should be scored.
- **F (safety):** the three missing setup gates in §5 (queue shapers, port shaper, dp8 speed) belong
  in the pre-flight snapshot/restore contract.

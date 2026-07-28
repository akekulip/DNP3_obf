# Case A — READ-anchored dual-release gate

**Branch:** `research/case-a-read-anchored-dual-release`
**Status:** DESIGN. No P4 written, no compile run, no switch touched.
**Supersedes:** the fixed-D ACK hold (kept as a negative analytical baseline, see
`../evidence/fixed_d_negative_result/README.md`). **Preserves:** the frozen Defense 2
implementation, recorded in `../BASELINE.md`.

---

## 1. Objective

For every fresh eligible Class-0 READ observed at ingress time `t_READ`, release the original
pure TCP ACK and the original DNP3 RESPONSE at **switch-selected, READ-relative** deadlines:

```
d_ACK  = t_READ + A
d_RESP = t_READ + R          R = A + S,   A > 0,  S >= 0
```

For packets arriving before their deadlines, the observer sees:

```
READ -> ACK        ~= A
ACK  -> RESPONSE   ~= S
READ -> RESPONSE   ~= R
```

**The relay's native ACK arrival time and native response arrival time are not inputs to either
deadline.** The switch may delay, never synthesize, replace, or advance a real packet.

Scope is Case A only: `READ -> pure TCP ACK -> DNP3 RESPONSE`. No Case B, no size normalization.

### Why this supersedes the previous mechanisms

Each earlier design computes its release time from something the **device** produced, so device
timing survives into some observable:

| Mechanism | Release rule | READ→ACK | CLRT | READ→RESPONSE |
|---|---|---|---|---|
| Native | — | `a` | `c` | `a + c` |
| Defense 1 | ACK released on RESPONSE arrival | **`a + c`** | `δ` | **`a + c`** (unchanged) |
| Defense 2 | RESPONSE released at `t_ACK + G` | **`a`** | `max(c, G)` | `a + max(c, G)` |
| Fixed-D | ACK released at `t_ACK + D` | **`a + D`** | `max(c − D, δ)` | `a + max(c, D+δ)` |
| **This design** | both released at `t_READ + {A, R}` | **`A`** | **`S`** | **`R`** |

Defense 1 does not destroy the CLRT — it relocates it, leaving the end-to-end envelope
bit-identical to native. Fixed-D conceals the CLRT once `D ≥ max(c)`, but leaves `a` intact under
a constant shift. Anchoring on `t_READ` — a switch-generated timestamp — makes all three intervals
functions of policy.

**Degenerate cases worth stating explicitly**, because they make this a generalization rather than
a fourth mechanism: `S = 0` (i.e. `A = R`) releases both packets on the same deadline and collapses
the observed CLRT to the hardware separation — Defense 1's outcome, but response-independent.
`S > 0` places the observed CLRT on any constant we choose. Defense 2 is the special case where the
ACK is not held at all.

---

## 2. Traffic-manager construction

Four queues on the dp8 MAC-near loopback, one scheduling domain:

| Queue | Priority | Content |
|---|---|---|
| `Q_ABLOCK` | 7 | ACK-deadline blocker tokens |
| `Q_ACK` | 6 | the original pure TCP ACK |
| `Q_RBLOCK` | 5 | response-deadline blocker tokens |
| `Q_RESP` | 4 | the original DNP3 RESPONSE |

Required strict ordering `Q_ABLOCK > Q_ACK > Q_RBLOCK > Q_RESP`, configured via **`max_priority`**
and **read back after configuration**. Queue ID alone does not determine scheduling priority — the
IBSPG root-cause repair established that `min_priority` is inert and that leaving `max_priority`
unset silently degrades to a fair split. Part 11 has already proven three strict-priority levels on
this silicon; four is an increment on a validated configuration.

### Timeline

```
t_READ ............ Q_ABLOCK non-empty -> starves Q_ACK, Q_RBLOCK, Q_RESP
                    ACK and RESPONSE accumulate in their own queues, in any order
t_READ + A ........ ACK blockers terminate; Q_ABLOCK empties
                    next eligible queue is Q_ACK (priority 6 > 5) -> the ACK leaves, alone
                    Q_RBLOCK immediately becomes the highest non-empty queue
A .. R ............ Q_RBLOCK non-empty -> Q_RESP stays starved
t_READ + R ........ response blockers terminate; Q_RBLOCK empties -> the RESPONSE leaves
```

### Why the four-level ladder is the right construction

It removes the re-blocking race. At the ACK deadline the response gate is **already standing** at
priority 5 — no token has to be inserted in the nanoseconds between the last ACK blocker draining
and the ACK being scheduled, and no controller is involved. A three-queue design would have to
refill the single blocker reservoir inside that window, which is not achievable from the data
plane.

It also has a resource property worth stating as a virtue rather than discovering later: **the two
reservoirs never circulate simultaneously.** While `Q_ABLOCK` is occupied it starves `Q_RBLOCK`,
so the response blockers sit parked at zero bandwidth cost until the ACK deadline passes. Peak
internal loopback load is therefore the same as the single-reservoir Defense 2 design, not double
it; total circulation is proportional to `R`, not `A + R`.

---

## 3. Blocker generation — corrected construction

> **The direction's primary construction is already refuted by evidence in this repo and must not
> be micro-benchmarked.** One application emitting batch 0 = ACK blockers and batch 1 = response
> blockers, distinguished by `batch_id`, **cannot work on Tofino-1**: the recirculation-triggered
> generator header has no `batch_id` field — the 24-bit `key` occupies that position — and
> recirculation triggers are single-batch only. Source:
> `research/defense2_pktgen/evidence/REQUEST_TRIGGERED_PKTGEN_IMPLEMENTATION_REPORT.md` §A.3–A.4.

```p4
header pktgen_recirc_header_t {
    @padding bit<3> _pad1;
    bit<2>  pipe_id;
    bit<3>  app_id;      // usable discriminator (fallback)
    bit<24> key;         // occupies the batch_id position; carries READ context
    bit<16> packet_id;   // 0 .. packets_per_batch_cfg  <-- PREFERRED discriminator
}
```

**Preferred: one application, one batch of 128, split on `packet_id`.**

```
packets_per_batch_cfg = 127      (zero-based -> 128 tokens)
batch_count_cfg       = 0        (single batch, as the hardware requires)

ingress:  packet_id[6] == 0  ->  Q_ABLOCK   (tokens   0..63,  K_A = 64)
          packet_id[6] == 1  ->  Q_RBLOCK   (tokens  64..127, K_R = 64)
```

One bit test, one trigger, one application — the minimal delta from the proven path, and it uses
a field the SDE documents as present.

**Must verify before committing (do not guess):** the maximum `packets_per_batch_cfg` on Tofino-1.
The repo confirms 64 works and never establishes the ceiling. If 128 is not permitted, fall back to
**two applications sharing the same recirculation-pattern trigger**, discriminated by the 3-bit
`app_id`; Tofino-1 exposes eight applications. Do not fall back to periodic generation, controller
triggering, or host-generated tokens.

Required per fresh READ: exactly 64 ACK blockers and exactly 64 response blockers. A duplicate or
retransmitted READ must produce no second reservoir (the baseline `reg_tag` idempotency already
delivers this — silicon gate (c)).

`K = 64` is empirically required and must not be tuned down; Part 9 corrected an earlier `K = 1`
claim. The reservoir must never be momentarily empty before its deadline — that is the empty-gap
failure mode, and it is a stop condition.

---

## 4. Transaction state and packet handling

### On a fresh eligible Class-0 READ

1. Store `t_READ = ingress_mac_tstamp`.
2. Advance `transaction_generation` exactly once.
3. Set `transaction_active = 1`; clear `ack_seen`, `ack_released`, `response_seen`,
   `response_released`.
4. Select `A` and `R` (runtime action parameters, not compile-time constants — see §6).
5. Trigger exactly one pktgen event.
6. Forward the original READ byte-identically to the relay.
7. Suppress a second trigger for a duplicate of the same active transaction.

### ACK admission predicate — tightened

The keepalive defect found during the fixed-D study applies here and is **worse**, because a
qualifying ACK is now *enqueued into `Q_ACK`* rather than merely arming a register. The relay emits
keepalives every ~10.02 s carrying `seq = SND.NXT − 1`, and they satisfy every condition of the
current classifier. Admit as *the* transaction ACK only if **all** hold:

| # | Condition | Rejects |
|---|---|---|
| 1 | `ingress_port == PORT_RELAY`, 5-tuple matches the tracked session, `ip.ihl == 5`, `ip.protocol == 6` | wrong direction, other flows |
| 2 | `(tcp.flags & 0x3F) == 0x10` — **mask tightened from `0x17`** | SYN-ACK, FIN-ACK, RST, PSH-with-no-payload |
| 3 | `ip.total_len == 4·ip.ihl + 4·tcp.data_offset` (zero payload) | data-bearing segments |
| 4 | `tcp.ack_no == EXP_ACK`, latched as `READ.tcp.seq + READ.tcp.payload_len` when the READ armed | ACKs of any other READ |
| 5 | **`tcp.seq == EXP_RELAY_SEQ`**, tracked as `prev_response.seq + prev_response.len`, seeded from `SYN-ACK.ISN + 1` | **the keepalive, structurally** — it is retrograde by exactly one |
| 6 | `txn_state == AWAITING_ACK`, one-shot, cleared on response release **and** on watchdog | window updates, duplicate ACKs, correct-ACK-after-completion |

Condition 4 alone does **not** reject the keepalive — it carries exactly the last READ's expected
ack, which is why the offline analyzer flagged ambiguity in 20 of 23 transactions in the idle
cells. Condition 5 is the decisive discriminator. There is no purely header-field predicate that
separates the transaction ACK from a window update; condition 6 is load-bearing.

Also retire `reg_tag` on the ACK/response release pass. The baseline retires it only via fail-open,
which is why a keepalive between polls still qualifies.

### ACK handling

Enqueue into `Q_ACK`, bytes untouched, no deadline computed from its arrival, no second pktgen
trigger, duplicates suppressed. If it arrives **after** `d_ACK` it preempts `Q_RBLOCK` (priority
6 > 5), leaves immediately, and increments `ACK_LATE_ESCAPE`. On its release pass set
`ack_released = 1` and prevent re-holding.

### RESPONSE handling

Enqueue into `Q_RESP`, bytes untouched, no deadline from its own arrival. If it arrives after
`d_RESP` **and** `ack_released == 1`, forward immediately and increment `RESPONSE_LATE_ESCAPE`. If
it arrives after `d_RESP` but `ack_released == 0`, it stays gated until the ACK releases or
fail-open resolves.

### Blocker termination

```
ACK blocker:       terminate iff  (now - t_READ) >= A
RESPONSE blocker:  terminate iff  (now - t_READ) >= R  AND  ack_released == 1
```

The `ack_released` conjunct is what prevents the response overtaking a late or missing ACK. It is
the structural fix for the race that the fixed-D design would have hit in its ~1.72 µs release
tail. Both comparisons occur **in ingress**; never in egress, never in the traffic manager.

---

## 5. Implementation facts carried forward (each already cost a compile cycle once)

1. **Deadline word format.** The armed marker rides in the low byte of `reg_deadline`, so any
   deadline offset must be a **multiple of 256 ns**. Ticks are 256 ns; 24 tick bits span exactly
   4.295 s.
2. **Sign handling: no new bit-slices.** A bit-slice inside a gateway condition gives
   `condition expression too complex`; a bit-slice of a 32-bit arithmetic field breaks PHV
   allocation outright. Test the sign with a **ternary TCAM mask on the whole 32-bit container**,
   as `tbl_deadline_expiry` already does (`0x00000000 &&& 0x800000FF` — bit 31 clear *and* armed,
   in one match). This design needs **two** such tables, one per deadline.
3. **Wrap.** The on-chip modular compare is wrap-correct for `|now − deadline| < 2^31 ns ≈ 2.147 s`.
   The hazard is **host-side**: the 32-bit ns counter wraps every ~4.3 s, ~14 times in a 60 s run.
   All register-readback arithmetic must compute `(b − a) & 0xFFFFFFFF` and treat results above
   `2^31` as wrap corrections. Since the ACK hold is measurable only on-chip (the relay leg is
   untappable, no SPAN), a plain signed subtraction here would fabricate the headline rather than
   measure it. Unit-test with `(arm = 0xFFFFF000, release = 0x00001000) -> 8192`.
4. **Fail-open budget.** Separate bounded budgets for the two blocker classes, carried per-token in
   the header so they cost no register. Size them by horizon, not by inheritance: the baseline's
   100,000 passes gives ~171 ms, which sat next to a ~211 ms TCP RTO. Target roughly `10 × R`
   (~120 ms at R = 12 ms) and expose both as runtime parameters.
5. **Q_HOLD direction invariant.** The release path hard-codes `fwd_port = PORT_VISION`, so
   `Q_ACK` and `Q_RESP` may only ever carry relay→master frames. Make this explicit with a guard
   and a counter rather than relying on the implicit `dir == DIR_OUT` chain.

---

## 6. Operating point — start at A = 3 ms, R = 12 ms

`A` and `R` govern near-independent escapes, and they cost very different amounts. Measured on the
n=100 steady-state corpus (`evidence/corrected_v2/cwi/out_C3/`):

| interval | min | median | p95 | **p99** | max |
|---|---|---|---|---|---|
| READ→ACK (sets `A`) | 0.400 | 0.505 | 1.495 | **1.607** | 2.138 |
| READ→RESPONSE (sets `R`) | 1.477 | 2.507 | 7.602 | **12.607** | 22.257 |

| A / R | ACK late | RESPONSE late | both met |
|---|---|---|---|
| 3 / 4 ms | 0/100 | 14/100 | 86 |
| 5 / 8 ms *(direction's start)* | 0/100 | 4/100 | 96 |
| 3 / 8 ms | 0/100 | 4/100 | 96 |
| **3 / 12 ms** *(recommended)* | **0/100** | **2/100** | **98** |
| 8 / 25 ms | 0/100 | 0/100 | 100 |

The ACK latency is tight and cheap to cover — `A = 3 ms` already yields zero ACK escapes against a
p99 of 1.607 ms, and `A = 5 ms` buys nothing further. The envelope carries the long tail, so
**escapes are dominated almost entirely by `R`**: spend the latency budget there. `R = 12 ms` lands
on the measured p99 exactly as the percentile rule prescribes.

Targets derive from `A ≥ Q_p(T_ACK − T_READ)` and `R ≥ Q_p(T_RESP − T_READ)` for a declared `p`.
None of these values is claimed optimal, and all must be recomputed from the campaign's own native
arm rather than reused from this table.

---

## 7. Build order — reclaim stages first

**The binding risk is the ingress stage budget, not correctness.** The frozen program fits at
**10 of 12** stages, and its load-bearing forwarding chain already occupies stages 0–6. This design
adds a second deadline comparison, a second blocker class with its own classification, the
`ack_released` gate, and a second budget. Tofino-1 gives 12.

Building correct-first and stripping telemetry later risks hitting the ceiling with no headroom and
no diagnosis. Invert it:

1. **Reclaim stages 7, 8 and 9 before adding anything.** The compiler's own allocation shows stage
   9 is 100% G-selection guard (delete the feature outright — this design never branches on native
   CLRT), stage 8 is 100% telemetry, and stage 7 is four counters with no logic. Collapse counter
   *objects* into indexed `Counter` arrays with compile-time-constant indices; Stats-ALU occupancy
   is charged per *(counter, stage)* pair, not per object.
2. **Compile a skeleton early** — both deadline comparisons and both token classes wired, no
   telemetry — purely to see where it lands. One hour, and it answers the question most likely to
   derail the build.
3. Then build the full construction into the banked headroom.

Do not cut the on-chip timestamps to chase a stage count: the ACK is held, so Vision cannot observe
`t_ACK`, and the relay leg is untappable. **On-chip registers are the only possible measurement of
the hold.** Keep `reg_ts_first_block`, `reg_ts_ack_arm`, `reg_ts_ack_release`, `reg_ts_resp_release`.

Report the measured stage count. Do not claim seven before bf-p4c says seven.

---

## 8. Pre-identified equivalent construction (for the stop-condition path)

If Phase 1 or Phase 2 fails, the stop conditions require testing an equivalent construction. Name
it now rather than inventing it under pressure:

**Self-timed dual deadline.** The ACK and the RESPONSE each recirculate on dp8 and check their own
deadline every ~408 ns pass — `now − t_READ >= A` for the ACK, `>= R AND ack_released` for the
response. Ordering is enforced by the deadline **arithmetic** rather than by queue priority, since
`R > A` strictly. No pktgen, no mirror session, no value-set, no four-queue configuration, no
strict-priority setup: two packets in flight instead of 128 tokens (~2.9 Mpps against ~37.4 Mpps).
It is a graft of `dcrn_defense1.p4`'s existing ACK-hold loop and Part 12's deadline comparison, and
the "does the timestamp refresh on recirculation" question is already settled for dp8 (0–26 ns
detection latency, 200/200 reps).

Its costs, for an honest comparison: pass budgets must cover `R` (~19,600 passes at R = 12 ms,
inside the existing 65,536 cap), byte identity is exercised thousands of times per packet (already
proven, 26/26 byte-identical), and it scales as O(N) in concurrently held packets where the
reservoir is O(1).

---

## 9. Phases

**Phase 0 — stage reclamation + skeleton compile.** Per §7. Gate: measured stage count with the
guard deleted and counters collapsed, before new logic.

**Phase 1 — four-queue dequeue oracle.** Synthetic roles `ABLOCK / HELD_ACK / RBLOCK / HELD_RESP`;
≥100 trials, randomized enqueue order. Required: 0 response-before-ACK, 0 premature releases, 0
unexpected priority outcomes. Verify `max_priority` by readback, not by assumption.

**Phase 2 — two-deadline token behavior.** One stored `t_READ`, constant `A`/`R`. Measure
configured-deadline → first termination, first → final termination, final termination → real-packet
release, for both deadlines. Confirm `Q_RBLOCK` occupancy never reaches zero before `d_RESP`.

**Phase 3 — dual-reservoir pktgen.** One synthetic READ → exactly 64 `Q_ABLOCK` + 64 `Q_RBLOCK`
tokens via the `packet_id` split. No READ → zero tokens. Duplicate READ → no second reservoir.
Verify the `packets_per_batch_cfg` ceiling against the installed SDE first.

**Phase 4 — full Case A parser, transaction matching, cleanup, fail-open.**

**Phase 5 — physical SEL-751 validation.** Completion requires this.

---

## 10. Test matrix

The direction's twenty cases, plus three that the relay generates for free and that the current
predicate would fail:

1–20 as specified (both early; ACK early / RESPONSE between A and R; ACK after A before R;
RESPONSE after R; ACK after R; synthetic reorder; duplicate READ / ACK / RESPONSE; stale ACK and
response blockers; missing ACK; missing RESPONSE; FIN/RST mid-transaction; budget exhaustion;
timestamp wrap boundary; back-to-back transactions; unrelated TCP; non-Class-0 DNP3; external token
capture).

**21. Qualifying pure ACK with no active transaction** — must not be held, must not arm.
**22. Keepalive arriving mid-hold** — must not enter `Q_ACK`, must not consume the one-shot.
**23. Keepalive between ACK release and RESPONSE arrival** — must not re-arm or disturb `Q_RBLOCK`.

Cases 21–23 are cheap: hold the connection idle >30 s during an armed window and the relay
generates them itself. Required: `ctr_ack_hold == 0` across a 60 s poll-free protected run.

---

## 11. Evaluation and claim

≥100 successful read-only Class-0 transactions per arm: native (same program, defense disabled),
Defense 1, fixed-D analytical transform, Defense 2, and READ-anchored dual release. Randomized
complete blocks, fixed poll period, absolute monotonic schedule (a response-relative schedule leaks
the added delay into the inter-poll interval), separate run directories, no appended CSVs.

Measure all three intervals — `READ→ACK`, `ACK→RESPONSE`, `READ→RESPONSE` — never CLRT alone, plus
both deadline errors, both escape fractions, added application latency, retransmissions, duplicate
ACKs, loss, reorder, completion, blocker counts, cleanup. Verify `eth.type == 0x88c1` is zero on
both external links every run.

Report distributions, mean/median/sd/quantiles, escape fractions, deadline error, correlation with
native timing, and classifier performance where labels support it. Binned entropy goes in an
appendix with bin width, origin, edge convention and `n` stated — it is artifact-laden (a pure
shift measured **+0.260 bits** in the fixed-D study, under a transform that cannot add
information).

**The claim, and its limits.** Supportable: *for transactions arriving before the selected
READ-relative deadlines, the switch makes all three externally visible timing intervals functions
of switch policy rather than the relay's native ACK and response timing.* With one physical device
there is no anonymity-set claim and no general cross-device fingerprint-prevention claim. Residuals
that survive and must be disclosed: ACK mode (the relay still emits a separate ACK), response size,
TCP stack fingerprint, the connection-cold first poll, the TCP-timestamp channel (0.144 bits), and
the fact that constant `A`/`R` produce a near-zero-variance cluster that is itself recognizable as
normalization.

---

## 12. Second stage — per-transaction target selection

Only after deterministic dual release works. A small table of pairs `(A_i, R_i)` with `R_i > A_i`,
selected per transaction by a data-plane index **independent of the relay's measured timing** —
e.g. `hash(transaction_generation, salt) -> profile_id`, storing only `profile_id`. Draw the pairs
from a declared reference distribution. Do not claim cryptographic randomness. Do not claim
target-device mimicry until it is evaluated against a real reference distribution and an adaptive
attacker.

---

## 13. Stop conditions

A failed construction is not permission to conclude the mechanism is impossible. On failure:
isolate the smallest failing component, build a minimal microbenchmark, identify the cause
(compiler dependency, PHV allocation, queue priority configuration, pktgen batch semantics,
reservoir depth, timestamp comparison, transaction state, loopback ordering), test the equivalent
construction in §8, and preserve the negative evidence.

Do not pivot to a host, SmartNIC, controller timer, periodic pktgen, Case B, or size work. Escalate
only after the exact Tofino-1 limitation is demonstrated by source, compiler output, BFRT readback,
switch counter, dequeue trace, or physical PCAP.

**All hardware steps remain gated on explicit authorization.**

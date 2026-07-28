# Case A — READ-anchored dual-release gate

**Branch:** `research/case-a-read-anchored-dual-release`
**Status:** DESIGN (corrected). No P4 written, no compile run, no switch touched.
**Preserves:** the frozen Defense 2 implementation — identity in `../BASELINE.md`.
**Preserves:** fixed-D as a negative *analytical* baseline —
`../evidence/fixed_d_negative_result/README.md`.

---

## 1. Objective

For every fresh eligible Class-0 READ received at ingress time `t_READ`, compute and store two
switch-selected **absolute** deadlines:

```
d_ACK  = t_READ + A
d_RESP = t_READ + R          R > A > 0,   S = R − A
```

For packets reaching the switch before their deadline, the observer sees:

```
READ → ACK_out        ≈ A
ACK_out → RESP_out    ≈ S
READ → RESP_out       ≈ R
```

**The relay's native ACK-arrival timestamp and RESPONSE-arrival timestamp are not used to compute
either deadline.** The switch delays only the original ACK and original RESPONSE. It must not
synthesize a replacement for either, modify externally visible bytes, advance a packet before the
relay produces it, or depend on the controller or host for per-transaction release.

Scope is Case A only: `READ → pure TCP ACK → DNP3 RESPONSE`. Out of scope: Case B, packet-size
normalization, SmartNIC, DPU, eBPF, host pacing, controller fast-path timing.

### 1.1 Relationship to the earlier mechanisms — stated precisely

Each earlier design computes its release time from a **device-generated** quantity, so the relay's
timing survives into some observable:

| Mechanism | Release rule | Anchor | READ→ACK | CLRT | READ→RESPONSE |
|---|---|---|---|---|---|
| Native | — | — | `a` | `c` | `a + c` |
| Defense 1 | ACK released on RESPONSE arrival | RESPONSE **event** | **`a + c`** | `δ` | **`a + c`** (unchanged) |
| Defense 2 | RESPONSE released at `t_ACK + G` | **`t_ACK`** (device) | **`a`** | `max(c, G)` | `a + max(c, G)` |
| Fixed-D | ACK released at `t_ACK + D` | **`t_ACK`** (device) | **`a + D`** | `max(c − D, δ)` | `a + max(c, D+δ)` |
| **This design** | both released at `t_READ + {A, R}` | **`t_READ`** (switch) | **`A`** | **`S`** | **`R`** |

**Defense 2 is not a special case of this design.** Its deadline is ACK-relative
(`d_RESP = t_ACK + G`); this mechanism is READ-relative (`d_RESP = t_READ + R`). The two may
produce related observable behaviour, but they use fundamentally different anchors, and a
READ-relative rule cannot be obtained by reparameterizing an ACK-relative one.

**Do not claim this is a strict generalization of Defense 1 and Defense 2.** The supportable
statement is:

> Setting `S = 0` reproduces the near-zero-CLRT output objective of Defense 1 for packets arriving
> before the common deadline, but uses a response-independent, READ-relative release rule.

Defense 1 does not destroy the CLRT — it relocates it, leaving the end-to-end envelope
bit-identical to native. Fixed-D conceals the CLRT once `D ≥ max(c)` but leaves `a` intact under a
constant shift. Anchoring on a switch-generated timestamp is what makes all three intervals
functions of policy.

---

## 2. Initial concurrency scope

**The first implementation supports exactly one outstanding protected Case A transaction per
scheduling domain.** All persistent state in the inherited construction is single-entry
(`reg_tag`, `reg_deadline`, `reg_t_ack` are each `Register<..., bit<1>>(1, 0)`), and `Q_ACK` /
`Q_RESP` are single FIFOs, so a second concurrent transaction would head-of-line block behind the
first.

A second eligible READ arriving while a transaction is active must be handled explicitly:

```
forward the new READ WITHOUT protection
increment CONCURRENT_TRANSACTION_ESCAPE
do not overwrite active state
do not advance the active generation
do not trigger another blocker reservoir
```

**Do not claim support for concurrent protected transactions.** Sequential SEL-751 polling is the
target evaluation workload; flow-indexed state is future work.

---

## 3. Traffic-manager construction

Four queues on the established dp8 internal MAC-near loopback scheduling domain:

| Queue | Priority | Content |
|---|---|---|
| `Q_ABLOCK` | 7 | ACK-deadline blocker tokens |
| `Q_ACK` | 6 | the original pure TCP ACK |
| `Q_RBLOCK` | 5 | response-deadline blocker tokens |
| `Q_RESP` | 4 | the original DNP3 RESPONSE |

Required strict ordering `Q_ABLOCK > Q_ACK > Q_RBLOCK > Q_RESP`, configured via **`max_priority`**.
**Queue ID does not imply priority** — the IBSPG root-cause repair established that `min_priority`
is inert and that leaving `max_priority` unset degrades silently to a fair split. Part 11 has
already proven three strict-priority levels on this silicon; four is an increment on a validated
configuration.

After configuration, read back and record for each queue: queue ID, `max_priority`,
`min_priority`, scheduling enable state, port, pipe, queue mapping.

### 3.1 Required internal timeline

```
before d_ACK      Q_ABLOCK continuously non-empty
                  Q_ACK, Q_RBLOCK, Q_RESP ineligible
                  ACK and RESPONSE accumulate in their own queues, in any order

at d_ACK          ACK blockers terminate; Q_ABLOCK drains
                  Q_ACK becomes the highest-priority non-empty queue (6 > 5)
                  the original ACK is dequeued, alone

after ACK release Q_RBLOCK becomes the highest-priority non-empty queue
                  Q_RESP remains blocked

at d_RESP         response blockers terminate ONLY after the ACK has been committed
                  to the master-facing output path; Q_RBLOCK drains; Q_RESP eligible
```

### 3.2 Why four levels

The response gate is **already standing** at priority 5 when the ACK gate drains, so no token has
to be inserted in the nanoseconds between the last ACK blocker leaving and the ACK being scheduled,
and no controller is involved. A three-queue design would have to refill a single reservoir inside
that window, which the data plane cannot do.

A resource property follows and should be reported rather than discovered: **the two reservoirs
never circulate simultaneously.** While `Q_ABLOCK` is occupied it starves `Q_RBLOCK`, so the
response blockers sit parked at zero bandwidth cost until the ACK deadline passes. Peak internal
loopback load equals the single-reservoir Defense 2 design, not double it; total circulation is
proportional to `R`, not `A + R`.

---

## 4. External output ordering — the four queues alone do not prove wire order

Internal dequeue order from dp8 is necessary but not sufficient. After release, **both the ACK and
the RESPONSE must use `PORT_VISION` and the same normal master-facing FIFO queue**, or ordering
established internally can still be lost on the way out.

Define **`ack_committed_to_master`** — not the ambiguous `ack_released`. Set it only when the
released ACK:

1. returns from dp8;
2. is classified as a released held ACK;
3. is assigned to `PORT_VISION`;
4. is assigned to the normal master-facing FIFO queue;
5. is prevented from being held again.

The switch cannot know the physical wire-transmission instant. The state means the ACK has been
**committed to the master-facing FIFO ahead of any later RESPONSE**. Response blockers may
terminate only when `now >= d_RESP AND ack_committed_to_master == 1`, and the released RESPONSE
must subsequently enter that same FIFO.

**Prove:** ACK committed to `PORT_VISION`/`qid_normal` *before* RESPONSE committed to
`PORT_VISION`/`qid_normal`.

---

## 5. Absolute deadlines

One consistent time representation. On a fresh READ:

```
t_READ = ingress_mac_tstamp
d_ACK  = t_READ + A            stored in its own persistent register
d_RESP = t_READ + R            stored in its own persistent register
```

Returning ACK blocker: `expired_ACK = now >= d_ACK`.
Returning response blocker: `expired_RESP = (now >= d_RESP) AND (ack_committed_to_master == 1)`.

`t_READ` is retained **separately, for telemetry and validation only** — it is not an operand of
the release comparison. Reuse the proven wrap-safe absolute-deadline comparison rather than
computing an elapsed interval per pass.

All deadline comparisons occur **in ingress**. Never in egress, the traffic manager, the control
plane, or host software.

### 5.1 Quantization

The armed marker occupies the low byte of the deadline word, so offsets must be **multiples of
256 ns**. Quantize `A` and `R` explicitly and report **requested offset, programmed offset,
quantization error** for every configuration (computed in `../evidence/AR_selection_basis.txt`;
the setup script must recompute and echo these into each run manifest rather than trusting the
table):

| offset | requested | ticks | programmed | error |
|---|---|---|---|---|
| A = 3 ms | 3 000 000 ns | `0x002DC6` | 2 999 808 ns | **−192 ns** |
| R = 8 ms | 8 000 000 ns | `0x007A12` | 8 000 000 ns | 0 |
| R = 12 ms | 12 000 000 ns | `0x00B71B` | 12 000 000 ns | 0 |
| R = 13 ms | 13 000 000 ns | `0x00C65D` | 12 999 936 ns | **−64 ns** |
| A = 8 ms | 8 000 000 ns | `0x007A12` | 8 000 000 ns | 0 |
| R = 25 ms | 25 000 000 ns | `0x017D78` | 24 999 936 ns | **−64 ns** |

Worst case −192 ns: two orders of magnitude below the ~1.72 µs release tail and four to five below
the deadlines themselves. Report it rather than rounding it away.

### 5.2 Comparison construction — carry both traps forward

A bit-slice **inside a gateway condition** produces `condition expression too complex`. A bit-slice
of a 32-bit **arithmetic** field breaks PHV allocation outright (`12 field slices remain
unallocated`). Test the sign with a **ternary TCAM mask on the whole 32-bit container**, as
`tbl_deadline_expiry` already does (`0x00000000 &&& 0x800000FF` — bit 31 clear *and* armed, in one
match). This design needs **two** such tables, one per deadline. **Introduce no new slice.**

### 5.3 Wrap

The on-chip modular compare is wrap-correct while `|now − deadline| < 2^31 ns ≈ 2.147 s`; both
deadlines and every fail-open horizon sit three orders inside that. The hazard is **host-side**:
the 32-bit nanosecond counter wraps every ~4.3 s, ~14 times in a 60 s run. All register-readback
arithmetic must compute `(b − a) & 0xFFFFFFFF` and treat results above `2^31` as wrap corrections.
Because the ACK hold is measurable only on-chip — the relay leg is untappable, no SPAN — a plain
signed subtraction would fabricate the headline rather than measure it. Unit-test with
`(arm = 0xFFFFF000, release = 0x00001000) -> 8192`.

---

## 6. Operating point

Selection basis, n=100 native steady-state, physical SEL-751
(`../evidence/AR_selection_basis.txt`):

| interval | min | median | p95 | **p99** | max |
|---|---|---|---|---|---|
| READ→ACK (sets `A`) | 0.400 | 0.505 | 1.495 | **1.607** | 2.138 |
| READ→RESPONSE (sets `R`) | 1.477 | 2.507 | 7.602 | **12.607** | 22.257 |

**First proof-of-mechanism operating point: `A = 3 ms, R = 13 ms, S = 10 ms`.**

`R = 13 ms` is the smallest whole-millisecond value that **exceeds** the measured p99 of 12.607 ms.
An earlier revision proposed `R = 12 ms` and described it as landing on p99; that was wrong —
12 ms is below 12.607 and corresponds to p98 (2/100 escapes). `A = 3 ms` clears the READ→ACK p99 of
1.607 ms with margin; `A = 5 ms` buys nothing further.

Also prepare: `A=3/R=8`, `A=3/R=12`, `A=3/R=13`, `A=8/R=25`.

| A / R | ACK late | RESPONSE late | both met | mean added latency |
|---|---|---|---|---|
| 3 / 8 ms | 0/100 | 4/100 | 96 | 5.08 ms |
| 3 / 12 ms | 0/100 | 2/100 | 98 | 8.96 ms |
| **3 / 13 ms** | **0/100** | **1/100** | **99** | **9.95 ms** |
| 8 / 25 ms | 0/100 | 0/100 | 100 | 21.85 ms |

Escapes are dominated almost entirely by `R` — the ACK latency is tight and cheap to cover, the
envelope carries the long tail. **No pair is claimed optimal**, and all must be re-derived from the
campaign's own calibration arm (§12), never reused from this table.

---

## 7. Blocker generation

> The direction's original construction — one application, batch 0 = ACK blockers, batch 1 =
> response blockers, split by `batch_id` — **cannot work on Tofino-1**. The recirculation-triggered
> generator header has no `batch_id` field (the 24-bit `key` occupies that position) and
> recirculation triggers are single-batch only. Source:
> `research/defense2_pktgen/evidence/REQUEST_TRIGGERED_PKTGEN_IMPLEMENTATION_REPORT.md` §A.3–A.4.

```p4
header pktgen_recirc_header_t {
    @padding bit<3> _pad1;
    bit<2>  pipe_id;
    bit<3>  app_id;      // fallback discriminator
    bit<24> key;         // occupies the batch_id position; carries READ context
    bit<16> packet_id;   // 0 .. packets_per_batch_cfg   <-- preferred discriminator
}
```

**Preferred: one recirculation-triggered application, one batch, 128 generated packets.**

```
batch_count_cfg       = 0        (single batch — the hardware requires it)
packets_per_batch_cfg = 127      (candidate: fields MAY be zero-based — VERIFY)
```

Do not assume the zero-basing without checking the installed SDE schema **and** a live readback.

**Classification must use a full-width ternary table, not a bit-slice** (§5.2 — branching on
`packet_id[6]` in P4 would hit the gateway-complexity and PHV traps):

| match | value | mask | action |
|---|---|---|---|
| `packet_id` 0–63 | `0x0000` | `0xFFC0` | `set_ack_blocker` |
| `packet_id` 64–127 | `0x0040` | `0xFFC0` | `set_response_blocker` |
| — | — | — | **default: drop** |

Admission additionally requires: internal pktgen ingress source; expected `app_id`; active
transaction; expected trigger key / transaction generation; valid generated-packet role.

**Fallback**, only if the hardware refuses 128 packets per batch: two recirculation-triggered
applications on the same READ-generated trigger pattern, discriminated by the 3-bit `app_id`, 64
packets each. Tofino-1 exposes eight applications. Do not use periodic pktgen, Vision-generated
blockers, controller-triggered bursts, or per-transaction software writes.

### 7.1 K = 64 — accurate wording

> `K = 64` is the **validated safe reservoir depth** for the current loopback and scheduler
> configuration. `K = 1` was refuted (Part 9, correcting an earlier Part 8 claim). The current
> evidence does **not** establish that 64 is the mathematical minimum.

Use `K_ACK = 64`, `K_RESP = 64` initially. Do not reduce `K` without a separate occupancy and
empty-gap experiment.

---

## 8. Blocker reservoir readiness — mandatory new gate

The original READ is forwarded immediately, and the relay's **minimum measured READ→ACK interval is
0.400 ms**. The ACK blocker reservoir must be established before the earliest possible ACK can
reach `Q_ACK`, or the ACK enters an unblocked queue and leaves at once — a **silent zero-hold that
reads as a working run with a small measured delay**.

Instrument and measure: `t_READ`, `t_first_ABLOCK_admitted`, `t_64th_ABLOCK_admitted`,
`t_first_RBLOCK_admitted`, `t_64th_RBLOCK_admitted`.

**Initial target: all 64 ACK blockers admitted within 100 µs of READ detection** (a 4× margin
against the 0.400 ms floor).

Also prove: `Q_ABLOCK` never reaches zero after establishment and before `d_ACK`; no ACK escapes
during pktgen startup; no generated token reaches an external port; exactly 64 ACK blockers and 64
response blockers admitted.

If the 128-packet stream orders ACK blockers first, verify that **all** ACK blockers are generated
before any response blocker. If generation interleaves or reorders packet IDs, **characterize the
actual behaviour rather than assuming sequence** — the classification is by `packet_id`, so
interleaving is tolerable, but the readiness measurement must then be taken per class.

**Do not proceed to the physical SEL-751 until reservoir readiness passes.**

---

## 9. Packet classification

### 9.1 READ

1. Verify: master-facing ingress port; expected 5-tuple; valid IPv4/TCP structure; DNP3 Class-0
   READ; **no active protected transaction** (else §2 escape path).
2. Record `t_READ`.
3. Compute and store `d_ACK`, `d_RESP`.
4. Advance transaction generation exactly once.
5. Set `transaction_active = 1`, `txn_state = AWAITING_ACK`, `ack_seen = 0`,
   `ack_committed_to_master = 0`, `response_seen = 0`, `response_committed = 0`.
6. Latch expected master TCP acknowledgment state, expected relay sequence state, transaction
   matching key.
7. Trigger exactly one internal pktgen event.
8. Forward the original READ byte-identically to the relay.
9. Suppress a second trigger for a duplicate or retransmitted copy.

### 9.2 ACK — all eleven predicates required

A packet may enter `Q_ACK` only if **all** hold:

1. `ingress_port == PORT_RELAY`;
2. reverse 5-tuple matches the active tracked session;
3. IPv4 IHL and TCP structure valid;
4. pure TCP ACK: `(tcp.flags & 0x3F) == 0x10` *(mask tightened from the baseline's `0x17`)*;
5. zero payload: `ip.total_len == 4·ip.ihl + 4·tcp.data_offset`;
6. `tcp.ack_no == EXP_ACK`;
7. **`tcp.seq == EXP_RELAY_SEQ`**;
8. `transaction_active == 1`;
9. `txn_state == AWAITING_ACK`;
10. current transaction generation matches;
11. one-shot ACK admission has not already occurred.

Predicate 7 is the keepalive discriminator: the relay's keepalive carries a **retrograde** relay
sequence number (`SND.NXT − 1`) and fails it structurally. Predicate 6 alone does **not** reject a
keepalive — it carries exactly the last READ's expected ack, which is why the offline analyzer
recorded ambiguity in 20 of 23 transactions in the idle cells.

On acceptance: `ack_seen = 1`, `txn_state = AWAITING_RESPONSE`, enqueue the original ACK into
`Q_ACK`. Do not compute a deadline from its arrival, trigger pktgen again, hold duplicates, or
modify externally visible bytes.

If it arrives **after** `d_ACK`: enqueue into `Q_ACK`, allow it to preempt `Q_RBLOCK` (6 > 5),
count `ACK_LATE_ESCAPE`.

On its dp8 release pass: assign `PORT_VISION`, assign the normal external FIFO queue, set
`ack_committed_to_master = 1`, prevent recursive holding.

### 9.3 RESPONSE — explicit predicate

1. `ingress_port == PORT_RELAY`;
2. reverse 5-tuple matches;
3. active transaction;
4. current transaction generation;
5. expected TCP acknowledgment number;
6. expected relay TCP sequence state;
7. valid DNP3 RESPONSE function;
8. `txn_state == AWAITING_RESPONSE`;
9. RESPONSE not already admitted.

On acceptance: `response_seen = 1`, enqueue the original RESPONSE into `Q_RESP`. Do not compute a
deadline from its arrival, trigger pktgen, or modify externally visible bytes.

If it arrives after `d_RESP` **and** `ack_committed_to_master == 1`: forward through the release
path immediately, count `RESPONSE_LATE_ESCAPE`, terminate remaining current-generation response
blockers as stale/completed, record the cleanup reason.

If it arrives after `d_RESP` but `ack_committed_to_master == 0`: retain behind `Q_RBLOCK` until ACK
commitment or fail-open.

### 9.4 Segmentation scope

Determine from the current SEL-751 campaign whether the protected Class-0 response is a single TCP
segment. (The 300-poll campaign records 54 B TCP payload, single DNP3 fragment, `FIR=FIN=1`,
identical in all 300 — but this must be re-confirmed for the evaluation corpus, not inherited.)

If the first implementation supports only one response segment: bypass multi-segment transactions,
increment `MULTISEGMENT_ESCAPE`, and **do not claim transaction-wide multi-segment
normalization**. Later segments must never bypass silently.

---

## 10. Blocker processing

```
ACK blocker:
    stale generation      -> drop, count STALE_ACK_BLOCKER
    now <  d_ACK          -> decrement ACK budget, return to Q_ABLOCK
    otherwise             -> terminate, do not re-enqueue

RESPONSE blocker:
    stale generation      -> drop, count STALE_RESP_BLOCKER
    now <  d_RESP         -> decrement RESP budget, return to Q_RBLOCK
    ack_committed == 0    -> decrement RESP budget, return to Q_RBLOCK
    otherwise             -> terminate, do not re-enqueue
```

Separate bounded pass budgets per class, **sized from measured loop time and the selected horizon,
not inherited**. The baseline's 100,000 passes gave a ~171 ms horizon sized for `G = 25 ms`, which
sat next to a ~211 ms TCP RTO. Compute each budget as `horizon / measured_loop_time` with the
horizon at roughly `10 × ` the corresponding deadline, and expose both as runtime parameters.

Record `ACK_BLOCK_BUDGET_EXPIRED` and `RESP_BLOCK_BUDGET_EXPIRED`. A budget expiry must produce
bounded fail-open behaviour and cleanup — never an indefinite hold.

---

## 11. Terminal states

| # | Condition | Behaviour |
|---|---|---|
| A | Normal: ACK and RESPONSE both early | commit ACK at ≈`d_ACK`, RESPONSE at ≈`d_RESP`; mark complete; retire generation and READ tag |
| B | ACK late | ACK enters `Q_ACK`, preempts `Q_RBLOCK`; count `ACK_LATE_ESCAPE`; response gate continues safely |
| C | RESPONSE late, ACK committed | release immediately; count `RESPONSE_LATE_ESCAPE`; invalidate remaining response blockers; complete |
| D | RESPONSE late, ACK not committed | retain behind `Q_RBLOCK`; release ACK first or invoke bounded fail-open |
| E | Missing ACK | bounded timeout or ACK budget expiry; release/bypass per documented fail-open; **never hold the response indefinitely**; count `ACK_MISSING_TIMEOUT` |
| F | Missing RESPONSE | bounded response timeout; terminate response blockers; clear active state; count `RESP_MISSING_TIMEOUT` |
| G | FIN or RST | abort; invalidate generation; terminate both blocker classes as stale; count `TRANSACTION_ABORT` |
| H | Concurrent READ | forward unprotected; preserve active transaction; count `CONCURRENT_TRANSACTION_ESCAPE` |

Do not clear state before all queued packets required by the selected terminal path have been
committed or safely bypassed.

---

## 12. Calibration and evaluation must be independent

**Do not derive `A` and `R` from the same protected campaign used to report success.** Two stages:

**Calibration.** Native, n ≥ 100. Compute READ→ACK and READ→RESPONSE quantiles. Select `A` and `R`.
**Lock them.** Document the selection rule.

**Evaluation.** A *new independent* native arm, n ≥ 100, plus protected n ≥ 100. **No retuning.**

Randomized complete blocks where practical. A **fixed absolute monotonic poll schedule** — never
schedule each poll relative to the previous response, which would move the defense delay into the
inter-poll pattern and leak both the presence and the magnitude of the offsets. Store each run
separately; never append unrelated campaigns into one CSV.

---

## 13. Build order

**PHASE 0 — baseline preservation and stage reclamation.**
Confirm the unmodified baseline still compiles. Copy it to a new source file. Remove **only**
functionality proven dispensable: the obsolete G-selection guard, detailed research telemetry not
needed for correctness, redundant counters, unused experiment scaffolding. **Preserve:**
request-triggered pktgen, transaction generation, exact matching, queue selection, fail-open,
deadline comparison, cleanup, token isolation, lightweight validation counters. Compile; record
actual ingress and egress stages. **Do not claim seven stages unless bf-p4c confirms seven.**

Then compile an early **skeleton**: both blocker roles, both absolute deadlines, four queue
assignments, `ack_committed_to_master`, no detailed telemetry. **This skeleton compile is a
mandatory gate before full integration.**

Compiler evidence for what to strip: ingress stage 9 is 100% G-selection guard, stage 8 is 100%
telemetry (four counters at 4/4 Stats ALU plus the four write-if-zero timestamp registers at 4/4
Meter ALU), stage 7 is four counters with no logic. Stats-ALU occupancy is charged per
*(counter, stage)* pair, so the lever is collapsing counter **objects** into indexed `Counter`
arrays with compile-time-constant indices.

Do **not** cut the on-chip timestamps to chase a stage count — the ACK is held and the relay leg is
untappable, so on-chip registers are the only possible measurement of the hold.

**PHASE 1 — pktgen metadata and reservoir readiness.** Verify max packets per batch; verify
zero-based configuration; verify `packet_id` values; verify 64/64 classification; measure first and
final blocker admission per class; prove no startup ACK escape; prove no `Q_ABLOCK` empty gap.

**PHASE 2 — four-queue dequeue oracle.** Synthetic roles `ABLOCK / HELD_ACK / RBLOCK / HELD_RESP`,
≥100 trials, randomized enqueue order. Required: 0 response-before-ACK, 0 premature ACK, 0
premature response, 0 priority violations, `max_priority` readback PASS.

**PHASE 3 — two absolute deadlines.** Synthetic packets, one stored `t_READ`. Measure, for each
deadline: deadline → first blocker termination; first → final termination; final termination →
packet commitment.

**PHASE 4 — full Case A classification.** READ, exact ACK predicate, exact RESPONSE predicate,
keepalive rejection, duplicates, stale generations, cleanup, fail-open, single-active-transaction
behaviour.

**PHASE 5 — synthetic boundary tests.** Inject just before, at, and just after each of `d_ACK` and
`d_RESP`.

**PHASE 6 — physical SEL-751 validation.** Completion requires this phase.

Do not begin full DNP3 integration until the stage-reclaimed skeleton, pktgen reservoir-readiness
test, and four-queue oracle have passed.

---

## 14. Keepalive testing — corrected method

**Do not claim a natural ~10 s keepalive can be reliably observed inside a 13 ms hold window.** The
coincidence rate is of order 0.1%; the test requires injection.

| Test | Method | Requirement |
|---|---|---|
| 1 | physical 60 s poll-free idle connection, no active transaction | held-ACK count = 0 |
| 2 | replay or synthetically inject a captured SEL keepalive during the **ACK blocker phase** | see below |
| 3 | replay or inject a captured keepalive **after ACK commitment, before RESPONSE commitment** | see below |

Required in all cases: the keepalive never enters `Q_ACK`; never consumes the one-shot ACK state;
never alters a deadline; never triggers pktgen; never disturbs `Q_RBLOCK`; and is forwarded
normally where appropriate.

---

## 15. Required experiments

Arms: (1) native; (2) existing response-triggered ACK hold; (3) fixed-D analytical baseline;
(4) existing ACK-relative response hold (Defense 2); (5) new READ-anchored dual release at
`A=3/R=8`, `A=3/R=12`, `A=3/R=13`, `A=8/R=25`.

Measure: READ→ACK; ACK→RESPONSE; READ→RESPONSE; ACK deadline error; RESPONSE deadline error; ACK
late-escape fraction; RESPONSE late-escape fraction; concurrent-transaction escape fraction;
multi-segment escape fraction; added application latency; retransmissions; duplicate ACKs; loss;
reordering; transaction completion; blocker counts; stale blocker counts; budget expirations;
cleanup reasons.

Verify `eth.type == 0x88c1` on **both** external links — expected zero.

---

## 16. Claim boundary

**The first supportable claim:**

> For Case A transactions whose ACK and RESPONSE arrive before the selected READ-relative
> deadlines, the Tofino makes READ→ACK, ACK→RESPONSE and READ→RESPONSE functions of switch policy
> rather than functions of the SEL-751's native ACK and response timing.

**Do not claim:** full anonymity; cross-device fingerprint prevention; universal DNP3 coverage;
concurrent transaction support; multi-segment support unless implemented; exact wire-time
transmission; mathematically minimal `K`; zero variance; cryptographic randomness; target-device
mimicry.

**Disclose:** late-arrival escapes; the constant-target normalization signature; TCP timestamp
leakage (measured 0.144 bits, ~6% of CLRT entropy, surviving any byte-preserving hold); response-
size leakage; TCP-stack characteristics; ACK-mode visibility; the connection-first outlier;
single-device evaluation; the single-active-transaction limitation.

---

## 17. Compiler and resource gates

Compile on **BF-SDE 9.13.1** and **9.13.2**. Required: zero compile errors; successful switch load;
ingress ≤ 12 stages; egress ≤ 1 stage; no load-bearing egress registers; deadline comparison in
ingress; no controller fast path.

Report: ingress stages; egress stages; PHV; SRAM; Map RAM; TCAM; stateful ALUs; logical tables;
parser states; deparser changes; pktgen application usage; queue configuration.

**Do not remove ordering, fail-open, transaction isolation or exact matching to satisfy a stage
count.**

---

## 18. Equivalent construction

If the four-queue dual-reservoir construction fails, **do not conclude that READ-anchored dual
release is impossible.** Test the pre-identified equivalent:

**Self-timed ACK and RESPONSE recirculation.** The original ACK and original RESPONSE each
recirculate through dp8 and check their READ-relative absolute deadline — `now >= d_ACK` for the
ACK, `now >= d_RESP AND ack_committed_to_master == 1` for the RESPONSE. It uses the original
packets instead of blocker reservoirs, preserves READ-relative deadlines, avoids four internal
priority queues and dual-reservoir pktgen, and must retain bounded pass budgets, byte identity, and
ACK-before-RESPONSE ordering. Ordering comes from the deadline arithmetic (`R > A`) rather than
queue priority. The timestamp-refresh question is already settled for dp8 (0–26 ns detection
latency, 200/200 reps).

Do not pivot to host, controller, SmartNIC, DPU, eBPF, Case B, or size work.

---

## 19. Stop-condition procedure

For any failure: isolate the smallest failing component; produce a minimal microbenchmark; collect
compiler output, BFRT schema evidence, BFRT readback, queue counters, pktgen counters, dequeue
trace, timestamps, and PCAP where relevant; determine whether the cause is compiler dependency, PHV
allocation, stage placement, pktgen batch limit, `packet_id` semantics, reservoir startup,
reservoir empty gap, strict-priority configuration, timestamp comparison, transaction matching,
loopback ordering, or external FIFO ordering; test one equivalent Tofino-1 construction; preserve
all negative evidence.

**A failed subconstruction is not permission to abandon the research goal.**

---

## 20. Completion criteria

Corrected design PASS · stripped baseline compile PASS · pktgen 64/64 classification PASS ·
reservoir-readiness PASS · zero pre-deadline `Q_ABLOCK` gaps · four-queue oracle PASS · two-deadline
behaviour PASS · ACK-before-RESPONSE external FIFO ordering PASS · keepalive rejection PASS ·
stale-generation isolation PASS · bounded fail-open PASS · **physical SEL-751 PASS** · zero external
blocker leakage · independent calibration and evaluation · final compiler and resource report ·
preserved negative evidence.

Completion is never declared from design or compilation alone.
**All hardware steps remain gated on explicit authorization.**

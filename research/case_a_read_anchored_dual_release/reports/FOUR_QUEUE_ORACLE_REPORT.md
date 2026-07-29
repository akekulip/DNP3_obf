# Behavioural Four-Queue Dequeue Oracle — Tofino-1

**Status: AUTHORED + LOCALLY COMPILED. NOT RUN. No results yet.**
Nothing in this work has been loaded on the switch or executed against hardware.
`bf_switchd` is running the proven `dnp3_timing_normalizer_pktgen`
(`/home/decps/defense2_pktgen_compile/pktgen_abs.conf`, PIDs 451936/451939) and was
not touched. The hardware run is Philip's to execute.

---

## 1. What this proves, and why a readback is not enough

The Case A dual-release design requires the Traffic Manager to serve four queues on
the dp8 loopback in **strict priority**:

```
Q_ABLOCK (qid 7)  >  Q_ACK (qid 6)  >  Q_RBLOCK (qid 5)  >  Q_RESP (qid 4)
```

A `max_priority` readback is **not** proof of this and is explicitly rejected as
evidence. The reason is on the record in this project: the IBSPG campaign
(`research/ibspg_root_cause_repair/TOFINO1_STRICT_PRIORITY_SEMANTICS_AUDIT.md`) set
`min_priority` — which is **inert** unless `min_rate_enable` is true — for an entire
measurement campaign. Every readback looked healthy. The scheduler was actually doing
a 50/50 DWRR split, because both queues sat at the default `max_priority`. A readback
tells you what was *written*, not what the scheduler *did*.

This oracle therefore measures the **observed dequeue order** and nothing else. It
tests the scheduler in isolation, independently of deadlines, recirculation, the DNP3
parser and the ACK predicate.

---

## 2. Design

### 2.1 Why a dedicated P4 rather than reusing the skeleton

`p4/four_queue_oracle.p4` is written from scratch. `case_a_dual_release_skeleton.p4`
was deliberately **not** reused, for two reasons:

1. Its release path hardcodes `PORT_VISION` (dp9). Oracle traffic must never touch the
   Vision ↔ relay path.
2. It classifies packets by DNP3/TCP structure. The oracle would then depend on the
   very parser and ACK predicate it is supposed to be independent of — a scheduler
   result contaminated by a classification bug would be worthless.

The oracle has no register, no deadline, no recirculation loop, no pktgen and no
mirror. The only thing under test is the scheduler.

### 2.2 Isolated path — Hulk only

```
Hulk (dp11) --inject--> [ingress: role -> qid] --> dp8 queues {7,6,5,4}
                                                        |
                            (held while scheduling_enable = False)
                                                        |
                                                  release (control plane)
                                                        |
                                dp8 egress -> MAC-near loopback --------+
                                                        |
                          [ingress: dequeued == 1 -> pass = 1] ---------+
                                                        |
                                        dp11 --capture--> Hulk (tcpdump)
```

Each packet makes **exactly one** loopback pass: a frame arriving on dp8 is forwarded
to dp11 and never re-enqueued to dp8. Nothing loops repeatedly, so there is no pass
budget and no fail-open watchdog.

### 2.3 Oracle frame — 64 bytes, EtherType `0x88C2`

`0x88C2` is deliberately distinct from `0x88C1` (the IBSPG blocker-token marker) so the
two can never be confused in a parser, a capture filter, or a hex dump. This program
does not know about `0x88C1` at all; such a frame is simply not oracle traffic and is
dropped.

| Offset | Field | Width | Purpose |
|---|---|---|---|
| 0–5 | dst MAC | 48 | `02:00:00:00:C2:01` |
| 6–11 | src MAC | 48 | `02:00:00:00:C2:02` |
| 12–13 | ethertype | 16 | `0x88C2` |
| 14–15 | `trial_id` | 16 | groups a capture into trials (TM counters are cumulative) |
| 16 | `role` | 8 | 1=ABLOCK 2=HELD_ACK 3=RBLOCK 4=HELD_RESP; selects the queue |
| 17–18 | `per_role_seq` | 16 | identity within a role → duplicate detection |
| 19–20 | `global_inj_seq` | 16 | the (randomized) injection order |
| 21 | `pass` | 8 | 0 injected; ingress sets 1 on the loopback pass |
| 22–63 | pad | 336 | never parsed; rides in the residual, re-emitted verbatim |

`global_inj_seq` is load-bearing. The injection order is **randomized** with a recorded
seed, so the analyzer can show the observed dequeue order is not merely the arrival
order. `pass` is the short-circuit detector: a captured frame with `pass == 0` reached
the host without traversing a queue, which the analyzer would otherwise score as a
valid dequeue.

### 2.4 Why the capture order *is* the dequeue order

Every stage downstream of the dp8 dequeue is order-preserving and single-file:

```
dp8 queue dequeue   <-- THE ORDER BEING MEASURED
  -> dp8 egress MAC -> MAC-near loopback -> dp8 ingress MAC
  -> ingress pipeline (in-order for packets bound to one egress queue)
  -> dp11 queue qid 0   <-- ONE queue, FIFO, no arbitration
  -> dp11 egress MAC -> Hulk NIC -> tcpdump
```

The four queues under test are the **only** point in the path where more than one queue
competes. All released traffic converges on a single dp11 queue precisely so the return
path cannot reorder what the scheduler produced.

---

## 3. Preload / release and the "demonstrably nonempty" requirement

Per trial:

1. `--reset-counters` — zero `usage_cells`, `watermark_cells`, `drop_count_packets`.
2. `--preload` — `scheduling_enable = False` on all four dp8 queues.
3. Inject 64 ABLOCK + 1 HELD_ACK + 64 RBLOCK + 1 HELD_RESP in **randomized** order
   (seed and full sequence recorded in the trial JSON).
4. `--occupancy --require-nonempty` — read `usage_cells` and `watermark_cells` and
   require **all four > 0**.
5. `--gate-open` — **ONE** write reopens the dp8 port. This is the release.
6. Capture; then read `drop_count_packets` and require 0.

**A trial where any queue reads 0 is INVALID, not a failure.** The packets were never
parked, so the trial says nothing about ordering in either direction. The runner exits
with a distinct code (3), records `invalid_reason = NOT_ALL_QUEUES_NONEMPTY`, and the
analyzer counts it separately. This distinction is enforced in code, not left to
whoever reads the output.

---

## 4. The release mechanism: ONE global release event

**Revised 2026-07-28.** The four independent `scheduling_enable` writes that this
oracle originally used are **no longer the release mechanism**. They are retained only
as supplemental stress evidence and are explicitly **not** the acceptance gate.

### 4.1 Why the four-write release had to go

There is **no port-level scheduling enable** on Tofino-1 in this SDE.
`tf1.tm.port.sched_cfg` carries only `{max_rate_enable, scheduling_speed}` (verified
against the schema, §4.4). So with `scheduling_enable` as the actuator, releasing four
queues is inescapably four separate writes. The arithmetic that makes that fatal:

> Draining 64 x 64-byte frames at 25G takes roughly **1.7 us**
> (64 x 84 B x 8 / 25e9, including preamble and IFG).

That is the same order as the driver's per-entry write latency, so enable order — not
priority — could decide the drain order, and a clean sequence would be reporting
control-plane ordering rather than strict-priority scheduling.

`lo-first` is separately unusable as a primary mechanism. Because each blocker backlog
is finite, enabling the lowest-priority queue first can let it drain *to completion*
before the other queues are enabled at all. The result is neither a pass nor a
conservative failure — it is uninterpretable.

### 4.2 The gate

All four queues stay `scheduling_enable = True` for the entire trial. The hold is a
**port-level max-rate shaper** on the port that owns the four queues; the release is a
single write that reopens that port. Because the gate sits *above* the queue scheduler,
all four queues become servable at the same instant, and the observed order is
arbitration rather than write order.

| Step | Table | Write | Count |
|---|---|---|---|
| Close (shape) | `tf1.tm.port.sched_shaping` | `unit`, `provisioning=UPPER`, `max_rate`, `max_burst_size` | 1 |
| Close (arm) | `tf1.tm.port.sched_cfg` | `max_rate_enable = True` | 1 |
| **Release** | `tf1.tm.port.sched_cfg` | **`max_rate_enable = False`** | **1** |

Only the *release* has to be atomic, so a two-write close is fine.

### 4.3 ⚠ Which port carries the gate — a correction to the task brief

The brief specified a **dp11** port-level shaper. The four queues under test are not on
dp11. Per `p4/four_queue_oracle.p4`, a freshly injected frame is enqueued to
`PORT_L = dp8` on qids 7/6/5/4; dp11 carries only `QID_FWD = qid 0`, the single return
FIFO that released frames come back on — deliberately one queue so the return path
cannot reorder.

A gate on dp11 would therefore hold traffic that the **dp8 scheduler has already
ordered**. It would produce a clean-looking result that measures nothing. The gate must
sit on the port whose scheduler is under test:

> **GATE PORT = dp8 = `PORT_L`.**

This is implemented as `--gate-port`, defaulting to `PORT_L`. Because a wrong gate port
fails *silently and successfully*, the script **refuses** a gate port that does not own
the four queues unless `--i-know-the-gate-port-is-wrong` is passed, and then records
the result as not a strict-priority verdict.

### 4.4 Two ways to open, and why `disarm` is the default

| Mode | Single write | Boundary property |
|---|---|---|
| `disarm` (default) | `tf1.tm.port.sched_cfg max_rate_enable = False` | takes the token bucket **out of the path**, so the boundary cannot depend on banked burst credit or on the bucket's deficit state |
| `rate` | `tf1.tm.port.sched_shaping max_rate = <line rate>` | bucket stays armed and is merely re-parameterized, so the first packet still waits for credit |

`disarm` is the default on the a-priori argument above, but the choice is **measured**,
not asserted: `run/shaper_preload_microbench.sh` times both boundaries.

### 4.5 ⚠ Burst credit is the main threat to a clean boundary

A max-rate token bucket **refills while idle**. At injection time up to
`max_burst_size` of credit is already banked, and that many frames leave immediately —
before the release. So `max_burst_size` is driven to its minimum, and *zero frames
escaped while the gate was closed* is a **gate**, not a nice-to-have. Because the SDE
may silently clamp or quantize a minimum, the setup script compares the readback
against what was written and treats a clamp as a STOP.

### 4.6 The three enable orders — demoted, not deleted

`--release-order batch|lo-first|hi-first` still exists and still drives the four-write
`scheduling_enable` path, but only as supplemental stress evidence about how the
scheduler behaves under a skewed release. `--release` prints that demotion on every
invocation. **The acceptance gate is `--gate-open`.**

### 4.7 The preload gate

The trial is admitted as evidence only if all four hold:

1. all four queues simultaneously backlogged (`usage_cells > 0` **and**
   `watermark_cells > 0`),
2. zero `drop_count_packets` on every queue,
3. **no target-role frame reached the host before the release write** — decided from
   the capture, which is why the capture is started *before* injection,
4. exactly one port-rate update released the common output.

Conditions 1, 2 and 4 are checked by `--preload-gate-check`; condition 3 is the
analyzer's, and the setup script's JSON records explicitly that its own verdict is
incomplete without it.

### 4.8 If the port shaper cannot give a clean boundary

**Stop and report. Do not improvise.** The predefined fallback is
`Q_GATE > Q_ABLOCK > Q_ACK > Q_RBLOCK > Q_RESP`: populate the four target queues while
`Q_GATE` is backlogged, then release all four through one register-controlled
termination of `Q_GATE`. That needs a P4 change and is a **separate gated step**.

---

## 4.9 TM field provenance

Every Traffic-Manager field used, read this session out of the switch's own schema at
`/home/decps/Downloads/bf-sde-9.13.2/install/share/bf_rt_shared/bf_rt_tm_tf1.json`
(149080 bytes, dated 2024-02-07). Nothing below is from memory.

| Table | `table_type` | Key | Data fields used | Role here |
|---|---|---|---|---|
| `tf1.tm.port.sched_shaping` | `TmPortSchedShaping` | `dev_port` (uint32) | `unit` `['PPS','BPS']`, `provisioning` `['UPPER','LOWER','MIN_ERROR']`, `max_rate` (uint32), `max_burst_size` (uint32) | **the gate** — port-level hold |
| `tf1.tm.port.sched_cfg` | `TmPortSchedCfg` | `dev_port` (uint32) | `max_rate_enable` (bool), `scheduling_speed` (enum, 9 choices) | **arms/disarms the gate**; `max_rate_enable=False` is the single release write. Note there is **no** scheduling-enable field here — that is the whole reason the four-write release existed |
| `tf1.tm.counter.queue` | `TmCounterQueue` | `pg_id` (uint8), `pg_queue` (uint8) | `usage_cells`, `watermark_cells`, `drop_count_packets` (all uint64, all rw) | simultaneous-backlog proof and the zero-drop gate |
| `tf1.tm.queue.sched_cfg` | `TmQueueSchedCfg` | `pg_id`, `pg_queue` | `max_priority`, `min_priority` (enum `['LOW','0'..'7','HIGH']`), `scheduling_enable`, `max_rate_enable`, `min_rate_enable`, `dwrr_weight` | priority under test; `scheduling_enable` now supplemental; rate-enables forced False so no queue is shaping-ineligible |
| `tf1.tm.queue.sched_shaping` | `TmQueueSchedShaping` | `pg_id`, `pg_queue` | `unit`, `provisioning`, `min_rate`, `min_burst_size`, `max_rate`, `max_burst_size` | **not used as the gate** — cleared/disarmed only |
| `tf1.tm.port.cfg` | `TmPortCfg` | `dev_port` | `pg_id`, `pg_port_nr`, `port_queues_count` | `(pg_id, pg_queue)` is *read*, never guessed |
| `tf1.tm.queue.map` | — | `pg_id`, `pg_queue` | `dev_port`, `queue_nr`, `ingress_qid_count`, `ingress_qid_max` | confirms each queue really maps to dp8 |
| `tf1.tm.queue.buffer` | — | `pg_id`, `pg_queue` | `tail_drop_enable` (+ `guaranteed_cells`, `hysteresis_cells`) | context for a drop |
| `$PORT` | — | `$DEV_PORT` | `$SPEED`, `$FEC`, `$AUTO_NEGOTIATION`, `$LOOPBACK_MODE`, `$PORT_ENABLE` | dp11 up; dp8 `BF_LPBK_MAC_NEAR` |

Two schema facts worth stating because they are easy to assume wrongly:
`tf1.tm.port.sched_shaping` has **no** `min_rate`/`min_burst_size` (unlike the per-queue
shaper — it is max-only), and `tf1.tm.port.sched_cfg` has **no** scheduling-enable field.

---

## 5. ⚠ Scoping — this oracle says nothing about reservoir depth

**K=1 has been removed from the trial plan.** It was previously included "for
completeness"; that was a mistake, because a trivially-passing trial in an evidence
directory is an invitation to misread it as support.

A finite, **preloaded, non-recirculating** oracle cannot reproduce the K=1 empty-gap
failure. That failure is a *recirculation-timing* phenomenon — the reservoir momentarily
emptying between a token's dequeue and its re-enqueue — and this oracle excludes
recirculation entirely. With every packet preloaded before release, K=1 satisfies "all
ABLOCK before HELD_ACK" trivially: there is exactly one ABLOCK and it is already sitting
in a higher-priority queue when the scheduler starts. Nothing has to be sustained.

> **Running K=1 here would not exercise the failure mode that K=64 exists to prevent.
> Reservoir depth remains a separate recirculating-token experiment.** Nothing in this
> oracle confirms or challenges the K ≥ 64 requirement, which rests on the earlier
> Part 9 recirculating result.

Also out of scope: deadlines, the ACK predicate, byte preservation, and anything about
the DNP3 transaction. The oracle answers exactly one question — does the scheduler order
these four queues strictly?

---

## 6. ⚠ Shaped trials are a separate evidence class

Three of the five targeted modes (`late_ack_preempt`, `empty_ack_queue`,
`empty_resp_queue`) require a packet to arrive **mid-drain**. Unshaped, the whole drain
is ~1.7 µs, which a host cannot hit — these modes are physically impossible without
stretching the drain. `four_queue_oracle_setup.py --shaper --drain-shaper-pps 1000`
stretches it to ~64 ms via `tf1.tm.queue.sched_shaping`.

**A shaper changes what is being measured.** A queue over its max rate becomes
shaping-**ineligible**, and the TM then serves a lower-priority eligible queue. That is
not a strict-priority violation; it is the shaper working. The IBSPG repair records
this exact trap ("leave the blocker queue's max shaper disabled so it never becomes
shaping-ineligible").

So: **primary evidence must come from the unshaped preload/release trials.** Shaped
trials are supporting evidence about preemption dynamics only, and are reported as a
separate class. The runner records `shaped: true/false` on every trial record, and
warns when a late-injection mode runs with no shaper configured.

---

## 7. Targeted trial modes

| Mode | What it sets up | What must hold | Caveat |
|---|---|---|---|
| `reservoir` (K=64) | full preload, all four queues | strict order across all 130 | **primary evidence** |
| `resp_waiting` | HELD_RESP enqueued *before* HELD_ACK in arrival order | HELD_RESP stays blocked through both blocker phases | arrival order is explicitly swapped and recorded |
| `late_ack_preempt` | RBLOCK backlog draining, HELD_ACK injected mid-drain | HELD_ACK served next, subject only to a packet already in transmission | needs shaper; §6 |
| `empty_ack_queue` | ABLOCK drains with Q_ACK empty, RBLOCK active, HELD_ACK injected later | HELD_ACK preempts RBLOCK | needs shaper; §6 |
| `empty_resp_queue` | both blocker phases complete, HELD_RESP injected after | normal forwarding, no stale blocking | needs shaper; §6 |

---

## 8. Analyzer

`analysis/analyze_four_queue_oracle.py` is offline only (no network, no subprocess, no
socket imports — verified). It parses captures with a pure-stdlib classic-pcap reader
(both endiannesses; scapy optional) and evaluates per trial:

- `max(pos(ABLOCK)) < pos(HELD_ACK)` → `ORDER_ACK_AFTER_ABLOCK`
- `pos(HELD_ACK) < min(pos(RBLOCK))` → `ORDER_RBLOCK_AFTER_ACK`
- `max(pos(RBLOCK)) < pos(HELD_RESP)` → `ORDER_RESP_AFTER_RBLOCK`
- exact counts 64/1/64/1 → `COUNT_MISMATCH`
- duplicates → `DUPLICATE`; roles outside 1–4 → `UNEXPECTED_ROLE`
- every frame `pass == 1` → `PASS_FLAG`; nonzero TM drops → `TM_DROP`

Reason precedence: `UNEXPECTED_ROLE > PASS_FLAG > DUPLICATE > TM_DROP >
COUNT_MISMATCH >` the three order codes. An order check whose role is absent is
`INDETERMINATE`, never `PASS`. Exit codes: 0 all pass, 1 any fail, 2 indeterminate.

**Unit tests (`--self-test`), verified this session — 11/11 passed, exit 0:**

```
PASS  correct                    expected=OK                       got=OK                       [PASS]
PASS  response_before_ack        expected=ORDER_RESP_AFTER_RBLOCK  got=ORDER_RESP_AFTER_RBLOCK  [FAIL]
PASS  ack_before_final_ablock    expected=ORDER_ACK_AFTER_ABLOCK   got=ORDER_ACK_AFTER_ABLOCK   [FAIL]
PASS  dropped_packet             expected=COUNT_MISMATCH           got=COUNT_MISMATCH           [FAIL]
PASS  duplicate_packet           expected=DUPLICATE                got=DUPLICATE                [FAIL]
PASS  rblock_before_ack          expected=ORDER_RBLOCK_AFTER_ACK   got=ORDER_RBLOCK_AFTER_ACK   [FAIL]
PASS  resp_before_last_rblock    expected=ORDER_RESP_AFTER_RBLOCK  got=ORDER_RESP_AFTER_RBLOCK  [FAIL]
PASS  bad_pass_flag              expected=PASS_FLAG                got=PASS_FLAG                [FAIL]
PASS  unexpected_role            expected=UNEXPECTED_ROLE          got=UNEXPECTED_ROLE          [FAIL]
PASS  absent_role_indeterminate  expected=ORDER_RESP_AFTER_RBLOCK  got=ORDER_RESP_AFTER_RBLOCK  [INDETERMINATE]
PASS  frame_round_trip           expected=all fields preserved     got=all fields survive pack/parse

self-test: 11/11 passed, 0 failed
```

Each case asserts both the verdict **and** the exact reason code — a test that only
checks "it failed" would not catch a misdiagnosis.

### 8.1 Integration check (runner packer → analyzer parser, via a real pcap)

The runner and the analyzer were written independently, so their agreement on the wire
format was verified end to end rather than assumed. Frames were built with
`run/four_queue_oracle.py`'s own `build_frame()`, written to a classic pcap, and fed to
the analyzer:

- **Positive:** 130 frames in correct strict-priority order → `PASS / OK`, exit 0.
- **Negative control:** the same 130 frames with `HELD_RESP` moved to position 0 (the
  exact failure the oracle exists to catch) → `FAIL / ORDER_RESP_AFTER_RBLOCK`, exit 1.

The negative control matters: it shows the positive result is not a trivial pass.

---

## 8.2 Prerequisite — dp11 must be configured first

The pre-flight reconnaissance (commit `5f92c1d`) found that **dp11 is not configured at
all** in the currently running program — it has only dp8 (loopback, 25G), dp9 (Vision,
25G) and dp64 (relay, 1G), so Hulk's `enp59s0f0np0` reads DOWN/NO-CARRIER. This is a
missing port configuration, not a dead link.

`four_queue_oracle_setup.py --config` **already adds dp11 at 25G / RS-FEC /
PM_AN_DEFAULT**, so the normal path covers it. Confirm `port dp11 up (Hulk)` shows PASS
in the `--config` output before running any trial.

**Note on the recorded contingency.** That commit records a fallback to dp9 if dp11 will
not link. This oracle **cannot** take that fallback: dp9 is absent from the P4 by
construction (§10), which is the isolation requirement. Falling back to dp9 would mean
editing and recompiling the P4 and giving up the guarantee that oracle traffic can never
reach the Vision ↔ relay path. If dp11 will not link, that is a decision to make
explicitly, not a drop-in substitution.

---

## 9. Compile result (bf-p4c 9.13.1, local)

```
bf-p4c --target tofino --arch tna -g -o p4/build_oracle_9.13.1/ p4/four_queue_oracle.p4
0 errors, 3 warnings
```

| Metric | Value |
|---|---|
| **Ingress stages** | **1** |
| **Egress stages** | **0** |
| Critical path through the dependency graph | 1 |
| Tables allocated | 8 |
| Stage 0: SRAM / TCAM / Map RAM | 3 / 0 / 2 |
| Stage 0: Gateways / VLIW / Stats ALU / Logical TableIDs | 3 / 8 / 1 / 8 |
| PHV normal-container bits used | 4 / 256 (1.6 %) |
| Tagalong collections | 26.2 % |

The three warnings are benign: one `uninitialized_out_param` on `meta` (the deliberate
zero-default pattern — the compiler's own `init_zero: [B6, B7, B8, B1, B0, B2, H1, B5]`
line in the `.bfa` confirms the defaults are applied) and two internal
`min_parse_depth_accept_loop` unroll notices.

One ingress stage is the practical floor. This oracle will not perturb any resource
question in the dual-release work.

---

## 10. Structural isolation from dp9 and dp64

The claim is not a runtime check but a property of the compiled binary. `dp9` (Vision)
and `dp64` (the SEL-751 relay leg) appear nowhere in the program — not as a constant,
not as a parser transition, not as action data.

**Source (`p4/four_queue_oracle.p4`):**
- The complete port set is declared at lines 82–83: `PORT_L = 9w8`, `PORT_HULK = 9w11`.
  There is no other `PortId_t` constant in the file.
- The parser admits only these two ports (`transition select(ig_intr_md.ingress_port)`);
  anything else leaves `port_ok = 0` and is dropped in the MAU.
- `ucast_egress_port` is assigned in exactly five actions — `to_ablock`, `to_ack_q`,
  `to_rblock`, `to_resp` (all `PORT_L`) and `to_hulk` (`PORT_HULK`). It is **never**
  assigned from metadata, a header field, or table action data, so no runtime value can
  redirect a packet.

**Compiled evidence (`p4/build_oracle_9.13.1/pipe/context.json`)** — every action in the
binary that touches the egress port, with its immediate:

```
Ingress.tbl_enqueue  Ingress.to_ablock  ucast_egress_port = 9w8 ; qid = 5w7
Ingress.tbl_enqueue  Ingress.to_ack_q   ucast_egress_port = 9w8 ; qid = 5w6
Ingress.tbl_enqueue  Ingress.to_rblock  ucast_egress_port = 9w8 ; qid = 5w5
Ingress.tbl_enqueue  Ingress.to_resp    ucast_egress_port = 9w8 ; qid = 5w4
tbl_to_hulk          Ingress.to_hulk    ucast_egress_port = 9w11; qid = 5w0
```

`9w8` and `9w11` are the only egress ports the compiled program can produce. There is no
path to dp9 or dp64.

---

## 11. Name provenance

Every table and field name used by the control plane was read out of this SDE's schema,
`$SDE/install/share/bf_rt_shared/bf_rt_tm_tf1.json`. Nothing is invented.

| Name | Source | Kind |
|---|---|---|
| `tf1.tm.port.cfg` → `dev_port` / `pg_id`, `pg_port_nr`, `port_queues_count` | `bf_rt_tm_tf1.json` | key / data |
| `tf1.tm.queue.map` → `pg_id`, `pg_queue` / `dev_port`, `queue_nr`, `ingress_qid_count`, `ingress_qid_max` | `bf_rt_tm_tf1.json` | key / data |
| `tf1.tm.queue.sched_cfg` → `min_rate_enable`, `min_priority`, `max_rate_enable`, `max_priority`, `dwrr_weight`, `scheduling_enable` | `bf_rt_tm_tf1.json` | data |
| `tf1.tm.counter.queue` → `usage_cells`, `watermark_cells`, `drop_count_packets` | `bf_rt_tm_tf1.json` | data (all rw) |
| `tf1.tm.queue.buffer` → `tail_drop_enable`, `guaranteed_cells`, `hysteresis_cells` | `bf_rt_tm_tf1.json` | data |
| `tf1.tm.queue.sched_shaping` → `unit`, `provisioning`, `max_rate`, `max_burst_size` | `bf_rt_tm_tf1.json` | data |
| `tf1.tm.port.sched_cfg` → `max_rate_enable`, `scheduling_speed` only | `bf_rt_tm_tf1.json` | **no** `scheduling_enable` — §4 |
| `$PORT` → `$DEV_PORT`, `$SPEED`, `$FEC`, `$AUTO_NEGOTIATION`, `$LOOPBACK_MODE`, `$PORT_ENABLE` | proven in `case_a_read_anchored_dual_release_setup.py` | key / data |
| `Ingress.tbl_enqueue`, `Ingress.to_ablock/to_ack_q/to_rblock/to_resp/to_hulk` | `p4/four_queue_oracle.p4` + compiled `context.json` | P4 |

`min_priority` / `max_priority` are **string** enums with choices
`['LOW','0','1','2','3','4','5','6','7','HIGH']`; `pnorm()` normalizes them to ints.

---

## 12. `TODO(silicon)` — every unresolved item and the check that settles it

| # | Item | Exact check that resolves it |
|---|---|---|
| 1 | Does `scheduling_enable=False` **hold** packets rather than drop them? | `--preload`, inject, then `--occupancy`: all four `usage_cells > 0` **and** `drop_count_packets == 0`. Non-zero drops with zero usage means the TM discarded rather than parked. |
| 2 | Residual skew between the four enables in one gRPC Write RPC | Compare the ordering verdict across `--release-order batch`, `lo-first`, `hi-first`. Invariant ⇒ skew is not the explanation (§4). |
| 3 | Does `tf1.tm.queue.sched_cfg entry_mod` accept the full field set (rmw) or only the minimal write? | `--config`, then read `queue_write_path` in the `FQORACLE` JSON: `"rmw"` or `"minimal"`. |
| 4 | Is `usage_cells` writable (counter reset)? It is a live gauge, unlike the latched `watermark_cells` / `drop_count_packets`. | `--reset-counters`: each field is written independently and reported on its own line; a rejected field shows as `WARN reset <q> usage_cells`. |
| 5 | Does a 130-packet preload stay under the queue limit? | `--occupancy` after preload: `drop_count_packets == 0` on all four; note `tail_drop_enable`. |
| 6 | Does the dp8 pg map match the assumed `pg_id`/`pg_port_nr`? | `resolve_pg()` **reads** `tf1.tm.port.cfg` and prints `pg_id=… pg_port_nr=…`; `--pg-l`/`--pg-l-nr` are fallbacks only, and a fallback raises `WARN dp8 pg map fallback`. |
| 7 | Does `max_rate_enable` need to be true for the shaper to bite? | `--config` readback: `max_rate_enable` per queue alongside the shaper readback. |
| 8 | Can a host land a late injection inside the shaped drain window? | With `SHAPER_PPS=1000`, check the late-mode captures actually show the late frame mid-sequence rather than appended at the end. |
| 9 | Does `bypass_egress=1` on the dp8 path behave as assumed (frame still egresses, unmodified)? | Any successful trial: 130 frames captured at Hulk with `pass == 1` and a 64-byte length. |
| 10 | Queue depth vs. 64 cells per blocker queue | `watermark_cells` after preload should read ≈ the number of frames parked on that queue. |
| 11 | **Does a port-level `max_rate` shaper on dp8 actually hold all four queues?** | `--gate-close`, inject, wait, then `--preload-gate-check`: all four `usage_cells > 0` while the capture at Hulk shows **zero** frames. Any frame at Hulk before the release write fails the gate. |
| 12 | **What is the lowest `max_rate` / `max_burst_size` this SDE accepts without silently clamping?** | `run/shaper_preload_microbench.sh` sweeps `PPS:1:0`, `PPS:1:1`, `PPS:0:0`, `BPS:1:0`, `BPS:1:1`; the setup script compares the readback against what was written and FAILs on a mismatch. |
| 13 | **Does banked burst credit let frames escape while the gate is closed?** | Microbench step 2: inject 130 frames with the gate closed, dwell 3 s, count oracle frames at Hulk. The only acceptable answer is **0**. |
| 14 | **Is a single-field `entry_mod` of `max_rate_enable` accepted, or does this SDE demand the full row?** | `--gate-open` writes only `max_rate_enable`. If it is rejected, the release is no longer one write and the mechanism fails its own acceptance criterion — that is a STOP, not a fallback. |
| 15 | **Which bfrt `Target` do the `dev_port`-keyed TM tables accept — pipe-0 or device scope?** | `_port_entry()` / `_mod()` try `pipe0` then `device`; the winner is recorded as `shaping_target` / `cfg_target` in the `FQORACLE` JSON. |
| 16 | **Release latency and drain profile: `disarm` vs `rate`** | Microbench step 3 captures both with `--time-stamp-precision=nano` and records `t_write_ns` alongside the first captured frame. Decides the default on measurement rather than argument. |
| 17 | **Does the capture host see the release boundary at all, i.e. is `tcpdump` on Hulk running unprivileged?** | Preflight: the runner only checks `CAP_NET_RAW` on `oracle_inject`. Capture privilege on Hulk is a **separate** unresolved precondition — see §14. |

---

## 13. Results

### 13.1 Oracle trials — NOT RUN

**Nothing has been loaded and no trial has been run.** `four_queue_oracle.p4` is not on
the switch; `dnp3_timing_normalizer_pktgen` (Defense 2) has been running continuously
throughout this work.

| Item | Value |
|---|---|
| Date / SDE | not run |
| Trials attempted / valid / invalid | not run |
| Preload gate (4 backlogged, 0 drops, 0 escapes, 1 release write) | not run |
| Release latency `disarm` vs `rate` | not run |
| Lowest usable `max_rate` / `max_burst_size` | not run — `--microbench` establishes it |
| Supplemental `scheduling_enable` stress (`batch` / `hi-first`) | not run |
| **Behavioural strict-priority verdict** | **not run** |

### 13.2 `--restore-only` against the live switch — **PASS** (2026-07-29)

The one hardware action taken. Safe by construction: Defense 2 was already loaded, so
the restore path re-asserted a known-good state rather than displacing anything.

```
[00:34:57] re-executing inside tmux session 'fqo_restore_only_20260729T003457Z'
[00:34:57] acquired /tmp/fq_oracle.lock (pid 825010)
[00:34:58] snapshot -> evidence/four_queue_oracle/switch_state_snapshot_20260729T003457Z.json
{ "n_bf_switchd": 1, "pid": "451939",
  "conf": "/home/decps/defense2_pktgen_compile/pktgen_abs.conf",
  "p4_name": "dnp3_timing_normalizer_pktgen" }
[00:34:59] Defense 2 already loaded and exactly one bf_switchd - NOT restarting.
[00:34:59] re-asserting the control plane only.
[00:34:59] re-running the Defense 2 control plane: --config --mode native

RESTORE VERIFICATION
  RES    FACT                             OBSERVED
  PASS   p4_name                          dnp3_timing_normalizer_pktgen
  PASS   strict_priority_verified         true
  PASS   app_enable                       false
  PASS   exactly one bf_switchd           1

[00:35:02] RESTORE VERIFIED - switch is running dnp3_timing_normalizer_pktgen in native mode.
[00:35:02] exit 0
```

`bf_switchd` PID **451939 was never restarted** — the same PID and the same
`--conf-file` before and after, with the daemon's uptime advancing continuously
(40:01 -> 52:24). Only the control plane was rewritten, with values identical to those
already in place.

What the re-assert touched, from reading the Defense 2 setup: dp9 and dp64 via
`entry_add`-then-`entry_mod` (no delete, so no physical link flap on the SEL-751 leg),
a delete-and-re-add of the **internal** dp8 MAC-near loopback, `max_priority` rewritten
to the same HIGH/LOW pair, and pktgen re-armed with `app_enable = False`.

### 13.3 Local verification — all PASS

| Check | Evidence |
|---|---|
| `oracle_inject.c` compiles clean | `gcc -Wall -Wextra -Werror -O2 -std=c11 -D_GNU_SOURCE`, 0 warnings |
| Frame layout matches the P4 header | C `--emit-hex` output round-trips through the analyzer's `parse_oracle_frame`, and is byte-identical to `four_queue_oracle.py build_frame()` |
| `bash -n` on both shell scripts | clean |
| `py_compile` on the setup script | clean |
| Trap fires on INT / TERM / HUP | exit 130 / 143 / 129, each with restoration executed exactly once (§13.4) |
| `flock` refuses a concurrent run | second invocation dies with "another run holds ..." |
| Restore is idempotent | EXIT trap after an explicit restore logs "restore already performed this run; not repeating" |

### 13.4 Trap proof (stubbed restore, no hardware)

```
### SIGINT  -> exit code 130 | caught SIGINT  | on_exit: rc=130 | STUB RESTORE ran
### SIGTERM -> exit code 143 | caught SIGTERM | on_exit: rc=143 | STUB RESTORE ran
### SIGHUP  -> exit code 129 | caught SIGHUP  | on_exit: rc=129 | STUB RESTORE ran
```

Each run also left a `STUB_RESTORE_RAN <utc> mode=pilot` line on disk, so the proof is
a file artefact and not only console output. The signal traps `exit`, which fires the
EXIT trap, which restores; a `RESTORE_DONE` guard keeps restoration to exactly one
execution per run.

---

## 14. How to run (for the hardware session)

Everything below is **gated**. Nothing here has been run except `--restore-only`
(§13). The runner owns restoration unconditionally; see §14.2.

```bash
# 0. ANY TIME — re-assert and verify the known-good Defense 2 state.
#    Safe against a healthy switch: it converges, it does not cycle.
./run/run_four_queue_oracle.sh --restore-only

# 1. ON HULK (once, BY PHILIP) — grant the injector its capability.
make -C run                                   # builds run/oracle_inject
sudo setcap cap_net_raw+ep /home/decps/fqo/oracle_inject
getcap  /home/decps/fqo/oracle_inject         # must print cap_net_raw=ep
#    A REBUILD DROPS THE CAPABILITY. Re-run setcap after every 'make'.

# 2. GATED — load four_queue_oracle.p4 (this DISPLACES Defense 2).
#    The runner deliberately will not do this.

# 3. ON THE SWITCH — configure ports, queues and clear per-queue shapers:
SP=/home/decps/Downloads/bf-sde-9.13.2/install/lib/python3.8/site-packages
PYTHONPATH=$SP:$SP/tofino python3.8 four_queue_oracle_setup.py --config

# 4. Establish the gate empirically BEFORE any trial:
./run/run_four_queue_oracle.sh --microbench

# 5. FIVE pilot trials, then STOP for review. There is no flag that continues
#    to a full campaign — that decision is human.
GATE_UNIT=PPS GATE_RATE=1 GATE_BURST=0 \
  ./run/run_four_queue_oracle.sh --pilot

# 6. ANYWHERE — offline verdict:
python3 analysis/analyze_four_queue_oracle.py --evidence-dir evidence/four_queue_oracle
```

Validate the whole harness with **zero** hardware contact first:

```bash
DRYRUN=1 FQO_NO_TMUX=1 FQO_STUB_RESTORE=1 ./run/run_four_queue_oracle.sh --pilot
```

### 14.1 ⚠ Capture privilege on Hulk is an unresolved precondition

`CAP_NET_RAW` on `oracle_inject` covers **injection only**. The pilot also runs
`tcpdump` on Hulk, and the instruction "do not attempt sudo on Hulk" applies to that
too. Either grant the capture tool its own capability
(`sudo setcap cap_net_raw,cap_net_admin+ep $(readlink -f "$(command -v dumpcap)")`)
or put the account in the `wireshark` group. The runner **detects and reports**; it
never escalates. This is `TODO(silicon) 17`.

### 14.2 What the runner guarantees

`run/run_four_queue_oracle.sh` guarantees exactly one thing unconditionally: on
**EXIT, INT, TERM or HUP** the switch is returned to `dnp3_timing_normalizer_pktgen`
and that return is **verified** — `p4_name`, `strict_priority_verified == true`,
`app_enable == false`, and exactly one `bf_switchd`. It holds a `flock` so two runs can
never overlap, snapshots the pre-run state to disk before touching anything, and drives
the whole hardware transaction inside one tmux session so a dropped SSH connection
cannot orphan a half-finished swap.

**Process-check note.** `pgrep -f bf_switchd` **overcounts** — measured 3 for a single
daemon, because the launcher is `bash -c tail -f /dev/null | bf_switchd ...` and the
invoking shell's own command line also contains the string. The bracket trick fixes
only the second. The correct count is `pgrep -cx bf_switchd`, which matches the
executable name. The bracket trick is still used for every `pkill -f`.

---

## 15. Files

| Path | Role |
|---|---|
| `p4/four_queue_oracle.p4` | the oracle dataplane (1 ingress stage, 0 egress) |
| `p4/build_oracle_9.13.1/` | compile output; `pipe/logs/table_summary.log`, `pipe/context.json` |
| `p4/build_oracle_9.13.1_compile.log` | compile log (kept outside `-o`) |
| `setup/four_queue_oracle_setup.py` | control plane: ports, queues, preload/release, occupancy, shaper |
| `run/four_queue_oracle.py` | injector / orchestrator for one trial (runs on Hulk, needs sudo) |
| `run/run_four_queue_oracle.sh` | ≥100-trial driver with tcpdump (runs on Hulk) |
| `analysis/analyze_four_queue_oracle.py` | offline verdict + `--self-test` |
| `evidence/four_queue_oracle/` | per-trial pcap + JSON |

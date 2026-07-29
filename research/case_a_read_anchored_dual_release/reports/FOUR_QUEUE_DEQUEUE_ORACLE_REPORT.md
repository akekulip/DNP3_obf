# Four-queue on-chip TM dequeue-order oracle — methodology and results

**Status: BUILT AND COMPILED OFF-SWITCH. NOT LOADED, NOT RUN.**
Results are TODO pending the five pilot controls, which Philip runs.

The switch was not touched while this was authored. Verified read-only at
2026-07-29 01:22 UTC: `pgrep -cx bf_switchd` = 1, PID 458055, uptime 27:43
continuous, `--conf-file /home/decps/defense2_pktgen_compile/pktgen_abs.conf`,
`p4_name = dnp3_timing_normalizer_pktgen`. Defense 2 is still loaded and running.

| Artifact | Path |
|---|---|
| Dataplane | `research/case_a_read_anchored_dual_release/p4/four_queue_dequeue_oracle.p4` |
| Compile output | `research/case_a_read_anchored_dual_release/p4/build_dequeue_oracle_9.13.1/` |
| Compile log | `research/case_a_read_anchored_dual_release/p4/build_dequeue_oracle_9.13.1_compile.log` |
| Control plane | `research/case_a_read_anchored_dual_release/setup/four_queue_dequeue_oracle_setup.py` |
| Analyzer | `research/case_a_read_anchored_dual_release/analysis/analyze_four_queue_dequeue.py` |
| Runner | `research/case_a_read_anchored_dual_release/run/run_four_queue_oracle.sh --pilot5` |

---

## 1. What this measures, and what it does not

It measures **TM scheduler priority** among four queues that share one port, by
recording on chip the ORDER in which packets dequeue.

It does **not** measure:

- **Reservoir depth.** The K>=64 blocker-reservoir requirement rests on the
  recirculating Part 9 result and is untouched by anything here.
- **Recirculation empty gaps.** A finite, preloaded, non-recirculating oracle
  *cannot* reproduce the K=1 empty-gap failure, because that failure is a
  recirculation-timing phenomenon: the reservoir empties between a token's
  dequeue and its re-enqueue. With everything preloaded, K=1 passes trivially.
  **A pass here must never be read as vindicating K=1.**
- **Anything about the defense itself** — no deadlines, no CLRT, no DNP3.

Reservoir depth and empty gaps remain separate evidence, from separate
experiments.

### Why a `max_priority` readback is not the evidence

A readback reports what was **written**. The IBSPG root-cause repair established
that an entire campaign ran with the wrong field set — `min_priority`, which is
inert unless `min_rate_enable` is true — while its readback looked perfectly
healthy and the scheduler was actually performing a fair DWRR split. The
configuration and the behaviour disagreed and nothing in the readback could show
it. This oracle exists so the ordering claim rests on observed behaviour.

---

## 2. Relationship to prior work

Methodology is the validated two-queue P3 oracle
(`research/ibspg_root_cause_repair/ibspg_dequeue_oracle.p4`,
`P3_FINITE_BACKLOG_ORACLE_RESULT.md`), extended from two queues to four. Both
files are prior evidence and are **byte-for-byte untouched** — verified against
`HEAD` by `git hash-object`. `research/defense2_pktgen/` is likewise untouched.

Carried across verbatim in structure: the monotonic saturating `reg_event_ctr`,
the `reg_overflow` tally, trace register arrays written at a dynamic index, one
RegisterAction per register, the 8-bit in-range flag, `ingress_mac_tstamp[31:0]`
as the dequeue-time proxy, and record-then-DROP so each packet takes one pass.

Two differences from the host-injected sibling `p4/four_queue_oracle.p4` in this
same directory:

1. **No host.** Packets are generated inside the chip; the order is read out of
   registers. dp11 is never configured, Hulk is never contacted, no raw socket
   and no capture is needed. (The sibling's pilot 1 returned 5/5 INVALID because
   no traffic reached the switch — the dp11/Hulk link was dark. This design
   removes that entire failure surface.)
2. **Four queues, not two,** with a control-plane-rewritable role map.

---

## 3. Mechanism

```
pktgen (dp68) --128 generated pkts--> [ingress: packet_id -> role -> qid]
                                                    |
                                         dp8 queues 7 / 6 / 5 / 4
                                  (all four held by the dp8 PORT shaper)
                                                    |
                                       ONE release write opens the gate
                                                    |
                                 dp8 egress -> MAC-near loopback -+
                                                                  |
                 [ingress: ingress_port == dp8 => it JUST DEQUEUED]
                  record (trial_id, role, pkt_id, tstamp) at the next
                  monotonic trace index, then DROP. Single pass.
```

### 3.1 The release gate is on the PORT, not the queues

There is **no port-level scheduling enable on Tofino-1**: `tf1.tm.port.sched_cfg`
carries only `max_rate_enable` and `scheduling_speed`. So releasing four queues
via per-queue `scheduling_enable` is inescapably four separate writes — and
draining 32 x 64-byte frames at 25G takes about 1.7 us, the *same order* as the
driver's per-entry write latency. Enable order could therefore decide drain order
while the experiment looked perfectly healthy. That is the same class of
silent-configuration error as the original `min_priority` bug.

The fix: leave every queue scheduling-enabled and gate the **port**. A
port-level max-rate shaper sits above the queue scheduler, so it holds all four
queues at once and one write makes them all servable at the same instant.

| Step | Table | Write | Count |
|---|---|---|---|
| close (shape) | `tf1.tm.port.sched_shaping` | `unit=PPS, provisioning=UPPER, max_rate=1, max_burst_size=0` | 1 |
| close (arm) | `tf1.tm.port.sched_cfg` | `max_rate_enable=True` | 1 |
| **RELEASE** | `tf1.tm.port.sched_cfg` | **`max_rate_enable=False`** | **1** |

Only the release must be atomic, so a two-write close is fine. Disarming is
preferred over raising `max_rate`, because disarming takes the token bucket out
of the path entirely and the release boundary cannot then depend on the bucket's
banked credit or deficit state.

**The gate must be on the port that owns the queues.** Gating any other port
would hold traffic the dp8 scheduler had *already* ordered and would pass
meaninglessly — a silent-success failure. `guard_gate_port()` refuses a wrong
gate port rather than warning about it.

**Per-queue shapers are forced off** (`max_rate_enable=False`,
`min_rate_enable=False`). A queue over its own max rate goes shaping-INELIGIBLE
and the TM then serves a lower-priority eligible queue. That is not a priority
violation, but it is indistinguishable from one in the trace.

### 3.2 Generation is internal, and the randomization is in the table

One batch of 128 packets from the Tofino packet generator on dp68, with a
**one-shot timer** trigger — so no host packet is needed to start a batch:

- `batch_count_cfg = 0` (one batch), `packets_per_batch_cfg = 127` (128 packets)
  — counts are zero-based.
- `increment_source_port = False` — **load-bearing**: with it true the driver
  caps the batch at `127 - 68 = 59` and would silently reject 128.
- `pipe_local_source_port = 68` — **required on this silicon** despite the SDE's
  "implicit on Tofino-1" note. Without it the generated packets carry the wrong
  ingress port, miss the parser's `from_pgen` path, and are dropped. The
  localising symptom is `pkt_counter = N` with `traced = 0` and `drop_bad_port = N`.

All 128 packets are byte-identical copies of one buffer template. Their only
distinguishing mark is the hardware `packet_id` (0..127) in the 6-byte generator
header. So the role assignment lives entirely in `tbl_role`, a 128-entry exact
table on the **full 16-bit** `packet_id`, which the control plane rewrites from a
recorded seed before every trial, keeping exactly 32 entries per role.

Emission order is hardware-fixed at 0,1,2,...,127. Permuting `packet_id -> role`
is therefore what makes an observed order that tracks ROLE provably not an
artifact of emission order.

No bit-slice is taken on `packet_id`: a slice inside a gateway yields
`condition expression too complex`, and slicing a 32-bit arithmetic field breaks
PHV allocation. A full-field exact match has neither problem.

### 3.3 Why the role is stamped into the frame

The 6-byte generator header is **stripped at the ingress deparser** (it is
extracted and never emitted — the same behaviour the SDE's own `tna_pktgen`
example relies on), so `packet_id` does not survive the trip through the queue.
The enqueue pass therefore writes both the role and the packet_id into the oracle
header, where they do survive the loopback.

Recording both is deliberate: `role` is what `tbl_role` actually did, `pkt_id` is
what the hardware actually generated, and the analyzer cross-checks the two
against the control plane's mapping file. A disagreement means the mapping does
not describe the silicon, and every conclusion drawn from it would be unsound —
so it is an INVALID trial, not a failed one.

### 3.4 Why the trace order is the dequeue order

The four queues are the only point in the path where more than one queue
competes. Downstream of the dp8 dequeue every stage is single-file: dequeue ->
dp8 egress MAC -> MAC-near loopback -> dp8 ingress MAC -> ingress pipeline ->
`reg_event_ctr` allocates the next index -> DROP. `reg_event_ctr` is a single
SALU, so two packets cannot receive the same index and indices are handed out in
arrival order. `trace[0..n-1]` read in index order is the dequeue order.

`ingress_mac_tstamp[31:0]` is recorded alongside as corroboration, not as the
ordering key.

### 3.5 Structural port isolation, verified from the compiler output

dp9 (Vision), dp11 (Hulk) and dp64 (the SEL-751 leg) appear nowhere in the
program — not as constants, not as parser transitions, not as action data. This
is checkable rather than asserted. In
`pipe/four_queue_dequeue_oracle.bfa`, `ig_intr_md_for_tm.ucast_egress_port` lives
in PHV `H0(0..8)`, and the whole program contains exactly four instructions that
write it:

```
Ingress.enq_ablock: set ig_intr_md_for_tm.qid, 7   ; set H0(0..8), 8
Ingress.enq_ack   : set ig_intr_md_for_tm.qid, 6   ; set H0(0..8), 8
Ingress.enq_rblock: set ig_intr_md_for_tm.qid, 5   ; set H0(0..8), 8
Ingress.enq_resp  : set ig_intr_md_for_tm.qid, 4   ; set H0(0..8), 8
```

The egress port is the immediate `8` in all four and nowhere else, so no packet
can reach any other port. dp68 is ingress-only: it appears in one parser select
and in no action.

---

## 4. The five mandatory controls

These are the point of the exercise. Any one alone proves little: a
strict-looking order under the intended ladder is also what emission order, the
qid numbering, or a control plane that wrote its enables in priority order would
produce. What rules those out is the **set**.

| # | `--priority-mode` | Priorities (A/K/R/P) | Expected pattern |
|---|---|---|---|
| A | `equal` | 4 / 4 / 4 / 4 | `{ABLOCK/ACK/RBLOCK/RESP interleaved}` |
| B1 | `ladder` | 7 / 6 / 5 / 4, seed 1002 | `ABLOCK* ACK* RBLOCK* RESP*` |
| B2 | `ladder` | 7 / 6 / 5 / 4, seed 2002 | `ABLOCK* ACK* RBLOCK* RESP*` |
| C | `reversed` | 4 / 5 / 6 / 7 | `RESP* RBLOCK* ACK* ABLOCK*` |
| D | `tied` | 6 / 6 / 5 / 4 | `{ABLOCK/ACK interleaved} RBLOCK* RESP*` |

- **A** — no priority difference at all. If the trace still comes out in role
  order, something other than priority is ordering it.
- **B1 vs B2** — same configuration, two different `packet_id -> role`
  permutations. If the dequeue order tracks ROLE across both, it is not tracking
  emission order.
- **C is the strongest.** The qids, the P4, the generator and the map are
  identical to B; only `max_priority` changed. If the observed order reverses
  with it, the trace provably tracks the scheduler.
- **D** — a mixed case that must show interleaving *inside* the tied class and
  blocking *between* classes.

`max_priority` accepts `'LOW','0'..'7','HIGH'` (schema), so the numeric ladder is
directly expressible.

---

## 5. Predicates and integrity rules

### 5.1 Ordering (derived, not hardcoded)

Roles are partitioned into priority classes by their `max_priority` readback. For
any two roles with different priority:

```
max(pos(r_hi)) < min(pos(r_lo))
```

Under the intended ladder that is exactly the three predicates in the brief:

```
max(pos(ABLOCK)) < min(pos(ACK))
max(pos(ACK))    < min(pos(RBLOCK))
max(pos(RBLOCK)) < min(pos(RESP))
```

Under control C the priorities reverse, so the derived predicates reverse with
them and a trace that still came out ABLOCK-first now FAILS. The expectation
follows the configuration — that is what makes C meaningful.

### 5.2 Interleaving (derived)

Roles sharing a priority class have no priority difference to separate them, so
the scheduler falls back to DWRR and they **must** interleave. A class of size
> 1 that comes out as clean per-role blocks is a FAIL. This is what judges
control A (all four tied) and control D (ABLOCK and ACK tied). Singleton classes
have no interleaving expectation; the ordering rule already forces one block.

### 5.3 Integrity — failure means INVALID, never FAIL

| Rule | Source |
|---|---|
| `event_ctr == 128` | `reg_event_ctr` |
| trace length `== 128` | trace read |
| `reg_overflow == 0` | `reg_overflow` |
| exactly 32 events per role | trace |
| zero unknown roles | trace |
| zero duplicate `pkt_id` | trace |
| every event carries this trial's `trial_id` | trace vs `--trial-id` |
| on-chip role matches the control-plane map | trace vs `role_map.mapping` |
| zero TM queue drops | `tf1.tm.counter.queue drop_count_packets` |
| all four queues backlogged before release | `usage_cells > 0` and `watermark_cells > 0` |
| zero escapes before release (`event_ctr == 0`) | `reg_event_ctr` at the gate check |
| gate still armed at the preload check | `tf1.tm.port.sched_cfg` |
| release performed | runner |

An INVALID trial never established its preconditions. It is **not** an ordering
failure and must never be reported as one. The runner will not perform the
release at all if the preload gate is unsatisfied (unless `--release-anyway`).

Trace arrays are deliberately **not** cleared between trials — only the index
counter is. Indices restart at 0, only `[0, event_ctr)` is read, and the
`trial_id` carried in every entry turns a stale entry into a detected error.
Clearing 4 x 512 registers per trial would cost 2048 writes to buy nothing.

---

## 6. Compile result (bf-p4c 9.13.1, local, `-g`)

**0 errors, 3 warnings**, all benign and identical in kind to the sibling
program: one `uninitialized out param 'meta'` (intended — the TNA parser has no
clear-on-write, so metadata defaults are left to the compiler's zero-init and
every zero default is the safe one) and two `max_loop_depth` unroll notes from
the TNA library.

| Resource | Used |
|---|---|
| Ingress stages | **4** (0-3) |
| Egress stages | **0** |
| Critical path through the dependency graph | 3 |
| Logical tables | 15 |
| SRAM | 20 |
| Map RAM | 16 |
| TCAM | **0** |
| Meter ALU (= SALU) | 6 |
| Stats ALU | 2 |
| VLIW instructions | 11 |
| Gateways | 9 |
| Exact-match input xbar | 20 bytes |
| Hash bits | 67 |

The 6 SALUs are `reg_event_ctr`, `reg_overflow`, and the four trace arrays. Four
of them land in stage 2, which is the per-stage SALU limit on Tofino-1 — that is
the shape of the placement, not a problem, and it converged on the first
allocation pass (`Table allocation done 1 time(s), state = INITIAL`).

### Bit-slice audit

The program contains exactly two slices, and both are **byte-identical to the
silicon-validated two-queue oracle**:

```
p4/four_queue_dequeue_oracle.p4:430   meta.ts32    = ig_intr_md.ingress_mac_tstamp[31:0];
p4/four_queue_dequeue_oracle.p4:433   meta.evt_idx = ev[8:0];
research/ibspg_root_cause_repair/ibspg_dequeue_oracle.p4:189   (same)
research/ibspg_root_cause_repair/ibspg_dequeue_oracle.p4:193   (same)
```

`ev[8:0]` slices a SALU *output* into a metadata field used as a register index;
it is not a match key and not a 32-bit arithmetic field. **Zero slices are taken
on `packet_id` or on any table key.** Confirm with:

```bash
grep -n '\[[0-9]\+:[0-9]\+\]' p4/four_queue_dequeue_oracle.p4
```

---

## 7. Provenance

Every bfrt name below is cited to the 9.13.1 schema in
`$SDE/install/share/bf_rt_shared/`, or to the P4 source. Nothing is from memory.

### 7.1 Traffic Manager — `bf_rt_tm_tf1.json`

| Table | Key | Fields used | Purpose |
|---|---|---|---|
| `tf1.tm.port.cfg` | `dev_port` | `pg_id`, `pg_port_nr`, `port_queues_count` | resolve dp8's port group (read, not guessed) |
| `tf1.tm.queue.sched_cfg` | `pg_id`, `pg_queue` | `max_priority` (choices `LOW,0..7,HIGH`), `min_priority`, `scheduling_enable`, `max_rate_enable`, `min_rate_enable`, `dwrr_weight` | the priority under test; per-queue shapers forced off |
| `tf1.tm.queue.map` | `pg_id`, `pg_queue` | `dev_port` | confirm each queue really belongs to dp8 |
| `tf1.tm.counter.queue` | `pg_id`, `pg_queue` | `usage_cells`, `watermark_cells`, `drop_count_packets` (all uint64, all rw) | preload gate + drop check |
| `tf1.tm.port.sched_shaping` | `dev_port` | `unit` (`PPS`/`BPS`), `provisioning` (`UPPER`/`LOWER`/`MIN_ERROR`), `max_rate`, `max_burst_size` | the gate's shaping parameters. **max-only** — no `min_rate`/`min_burst_size`, unlike the per-queue shaper |
| `tf1.tm.port.sched_cfg` | `dev_port` | `max_rate_enable`, `scheduling_speed` (`BF_SPEED_*`) | arms/disarms the gate. **No `scheduling_enable` field exists** — this is why the gate is a shaper |

`pg_queue = pg_port_nr * 8 + qid` (8 queues per port in a Tofino-1 port group).

### 7.2 Packet generator — `bf_rt_pktgen_tf1.json`

| Table | Key | Fields used |
|---|---|---|
| `tf1.pktgen.port_cfg` | `dev_port` | `pktgen_enable` (also present: `recirculation_enable`, `pattern_matching_enable`, `clear_port_down_enable` — read back, not written) |
| `tf1.pktgen.pkt_buffer` | `pkt_buffer_offset`, `pkt_buffer_size` | `buffer` |
| `tf1.pktgen.app_cfg` (ACTION-based) | `app_id` | action `trigger_timer_one_shot(timer_nanosec)`; data `app_enable`, `pkt_len`, `pkt_buffer_offset`, `pipe_local_source_port`, `increment_source_port`, `batch_count_cfg`, `packets_per_batch_cfg`, `ipg`, `ibg`, `trigger_counter`, `batch_counter`, `pkt_counter` |

Available trigger actions on Tofino-1: `trigger_timer_one_shot(timer_nanosec)`,
`trigger_timer_periodic(timer_nanosec)`, `trigger_port_down()`,
`trigger_recirc_pattern(pattern_value, pattern_mask)`. This oracle uses the
one-shot timer, which needs no trigger packet and therefore no host.

The sequence (configure with `app_enable=False`, then a separate `entry_mod`
setting only `app_enable=True` to start the countdown) is from
`$SDE/pkgsrc/p4-examples/p4_16_programs/tna_pktgen/test.py`. That file also
records that **the app does not auto-disable** after a one-shot batch: it must be
driven False before it can be re-armed. `fire_pktgen()` does False -> True ->
wait -> False, so exactly one batch is generated per trial and nothing can
re-trigger afterwards.

### 7.3 Ports — `bf_rt_port_tf1.json`

`$PORT` keyed by `$DEV_PORT`; fields `$SPEED`, `$FEC`, `$AUTO_NEGOTIATION`,
`$LOOPBACK_MODE`, `$PORT_ENABLE` (all verified present in the schema). dp8 is
configured `BF_SPEED_25G` / `BF_FEC_TYP_NONE` / `PM_AN_FORCE_DISABLE` /
`BF_LPBK_MAC_NEAR`. **dp11 is not configured.**

### 7.4 Generated-packet header — `$SDE/install/share/p4c/p4include/tofino1_base.p4`

```
:343 pktgen_timer_header_t  { pad(3) pipe_id(2) app_id(3)  pad(8) batch_id(16)  packet_id(16) }
:367 pktgen_recirc_header_t { pad(3) pipe_id(2) app_id(3)  key(24)              packet_id(16) }
```

Both are 6 bytes with `packet_id` at bytes 4..5. The P4 declares its own
byte-exact overlay `pktgen_hdr_h` (`.p4:194`) and reads **only** `packet_id`, so
the program is trigger-agnostic — a future recirc-pattern trigger would work
without touching the dataplane. Bytes 1..3 are named `key_or_batch` and never
read, precisely because calling them `batch_id` would silently become a lie under
a recirc trigger.

### 7.5 P4 objects

| bfrt name | P4 source |
|---|---|
| `pipe.Ingress.tbl_role` | `.p4:400`, key `hdr.pgen.packet_id : exact` |
| `Ingress.enq_ablock` / `enq_ack` / `enq_rblock` / `enq_resp` / `drop_bad_id` | `.p4` action bodies |
| `Ingress.reg_event_ctr` (`$REGISTER_INDEX`) | `.p4:306` |
| `Ingress.reg_overflow` | `.p4:315` |
| `Ingress.trace_trial` / `trace_role` / `trace_pktid` / `trace_ts` | `.p4:324,329,334,339` (depth `TRACE_LEN` = 512, `.p4:154`) |
| `Ingress.ctr_oracle` (`$COUNTER_INDEX`, `$COUNTER_SPEC_PKTS`) | `.p4:300`, 16 slots |
| `PORT_PGEN=68`, `PORT_L=8` | `.p4:128,129` |
| `QID_ABLOCK/ACK/RBLOCK/RESP = 7/6/5/4` | `.p4:138-141` |
| `ROLE_ABLOCK/ACK/RBLOCK/RESP = 1/2/3/4` | `.p4:144-147` |
| `ETHERTYPE_ORACLE4 = 0x88C3` | `.p4:119` |

Ethertype 0x88C3 is a fresh value: 0x88C0 = IBSPG real, 0x88C1 = blocker token,
0x88C2 = the host-injected `four_queue_oracle`, 0x88C3 = this program.

A P4 `Counter` read requires an explicit `operations_execute(tgt, "SyncCounters")`
before the read; `from_hw` alone returns a stale 0. Registers read live.

---

## 8. Open silicon assumptions, each with its resolving check

Every `TODO(silicon)` in the code appears here.

| # | Assumption | Where | Resolving check |
|---|---|---|---|
| 1 | The SDE echoes `$REGISTER_INDEX` in the data dict, so a batched register read can be mapped back to indices without assuming response order | `setup:348` | `--trace-dump` reports `index_source`. `echoed` = batch path worked; `fallback-perindex` = it did not and the slower per-index path produced the trace. Either way the trace is correct |
| 2 | 128 keys are accepted in one `entry_add`/`entry_mod` | `setup:626` | the `tbl_role: 128 entries` check row. If rejected, its detail carries the gRPC error; switching to one RPC per entry cannot affect the measurement, because the map is fully written before the gate closes and before any packet exists |
| 3 | A one-shot **timer** app works with `pktgen_enable` alone — every previous pktgen run on this switch used a recirc-**pattern** trigger, which also needs `recirculation_enable` and `pattern_matching_enable` | `setup:874` | the `pktgen pkt_counter` row reads 128 if the app fires. If it reads 0, add `recirculation_enable=True` (then `pattern_matching_enable=True`) and re-run |
| 4 | `pkt_len` counts buffer bytes and **excludes** the 6-byte generator header | `setup:909` | if wrong, the ethertype does not land at byte 12 and every packet lands on `drop_non_oracle`. So `drop_non_oracle == 0` and `enq_* summing to 128` confirms the layout |
| 5 | `tf1.pktgen.app_cfg` accepts a **pipe-scoped** Target (the SDE example and the Defense 2 setup both use device scope) | `setup:1000` | `app_cfg.target` records which was accepted, and `drop_bad_port` distinguishes them: `0` = pipe-0 scope held; `384` (3 x 128) = all four pipe generators fired and the other three pipes' packets were correctly discarded. `traced == 128` either way |
| 6 | `usage_cells` (a live gauge, unlike the latched watermark and drop counters) accepts a write of 0 | `setup:1138` | a rejected field appears as a WARN row naming it. The preload gate tests `usage_cells > 0`, not equality, so it works regardless |

One further precondition is the experiment's own hypothesis rather than a code
assumption, and is stated here so it is not mistaken for a verified fact: **that
the dp8 port shaper holds packet-generator-sourced traffic the same way it held
host-injected traffic in P3.** Generated packets enter the same TM queues through
the same ingress path, so it should. The preload gate tests it directly — all
four queues backlogged AND `event_ctr == 0` — and a failure makes the trial
INVALID rather than silently producing a meaningless order.

---

## 9. How to run it

The runner owns restoration unconditionally, via traps, and stops after the five
controls. It will **not** load the oracle: that displaces Defense 2 and is a
separate, explicitly authorized step.

```bash
cd research/case_a_read_anchored_dual_release

# what the analyzer expects of each control mode (no hardware)
python3 analysis/analyze_four_queue_dequeue.py --show-expectations
python3 analysis/analyze_four_queue_dequeue.py --self-test

# rehearse the whole runner with no hardware at all
DRYRUN=1 FQO_NO_TMUX=1 bash run/run_four_queue_oracle.sh --pilot5

# re-assert and verify Defense 2 (safe against a live, healthy switch)
bash run/run_four_queue_oracle.sh --restore-only

# --- after the oracle has been loaded, by hand, with authorization ---
bash run/run_four_queue_oracle.sh --pilot5

python3 analysis/analyze_four_queue_dequeue.py \
    --evidence-dir evidence/four_queue_oracle/pilot5_<RUNTS>
```

Restoration converges to the known-good state rather than always restarting: if
`bf_switchd` is already running the Defense 2 conf it is not cycled, only
re-asserted. Five facts are verified and printed before the runner exits:
`p4_name`, `strict_priority_verified`, `app_enable`, `exactly one bf_switchd`,
and **`dp8 shaping restored`** — the last asserts dp8 back to its original
`max_rate_enable=False, max_rate=25010000, unit=BPS, max_burst_size=9216,
scheduling_speed=BF_SPEED_25G` and fails if any field disagrees. Leaving the
gate armed would throttle dp8 to 1 PPS for whatever runs next, which would
present as a mysterious stall rather than as a leftover.

Use `pgrep -cx bf_switchd` (matches the executable name) to count the daemon.
`pgrep -cf bf_switchd` **overcounts** — measured 3 for a single daemon, because
the launcher pipeline and the invoking shell both carry the string.

---

## 10. Verification performed while authoring

| Check | Result |
|---|---|
| `bf-p4c 9.13.1 -g` compile | **0 errors**, 3 benign warnings |
| Stage/resource report | 4 ingress / 0 egress, critical path 3, 0 TCAM, 6 SALU |
| `py_compile` on both Python deliverables | clean (system python is 3.8.10, the switch's version) |
| Analyzer self-test | **16/16**, including **5 negative controls that correctly FAILED** and 7 precondition cases that correctly came out INVALID |
| Setup-to-analyzer JSON contract | 5 simulated trials built from the setup module's own constants and `build_role_map()`, fed to the analyzer: 5 PASS with the correct per-mode patterns (C observed `P32 R32 K32 A32`) |
| Per-mode expectations differ | `--show-expectations` prints distinct classes, predicates and interleaving requirements for A / B / C / D |
| `--pilot5` dry-run end to end | 5 controls, stop, trap restore, all 5 restore facts PASS |
| Trap restore under SIGINT | script exits 130 via the signal path, EXIT trap runs the single guarded restore, all 5 facts PASS |
| `bash -n` on the runner | clean |
| Frozen dirs untouched | `ibspg_dequeue_oracle.p4`, `P3_FINITE_BACKLOG_ORACLE_RESULT.md`, `dnp3_timing_normalizer_pktgen.p4`, `dnp3_timing_normalizer_pktgen_setup.py` all byte-identical to `HEAD` (`git hash-object`) |
| Switch untouched | `pgrep -cx bf_switchd` = 1, conf `pktgen_abs.conf`, `p4_name dnp3_timing_normalizer_pktgen`, daemon uptime continuous |
| Structural port isolation | exactly 4 instructions write `ucast_egress_port`, all `set H0(0..8), 8` |

Nothing here was run on silicon.

---

## 11. Results

**TODO — pending the five pilot controls.**

| Control | Mode | Seed | Expected | Observed order | Verdict |
|---|---|---|---|---|---|
| A | `equal` | 1001 | `{ABLOCK/ACK/RBLOCK/RESP interleaved}` | TODO | TODO |
| B1 | `ladder` | 1002 | `ABLOCK* ACK* RBLOCK* RESP*` | TODO | TODO |
| B2 | `ladder` | 2002 | `ABLOCK* ACK* RBLOCK* RESP*` | TODO | TODO |
| C | `reversed` | 1004 | `RESP* RBLOCK* ACK* ABLOCK*` | TODO | TODO |
| D | `tied` | 1005 | `{ABLOCK/ACK interleaved} RBLOCK* RESP*` | TODO | TODO |

Integrity per trial (TODO): `event_ctr`, `reg_overflow`, per-role counts, queue
drops, `event_ctr_before_release`, `app_cfg.target`, `drop_bad_port`,
`index_source`.

### How to read the results when they arrive

Read the five **together**, never individually.

- B1 and B2 passing alone proves little: emission order and the qid numbering
  would produce the same trace.
- A conclusion of "the scheduler orders by `max_priority`" requires **A and D to
  show interleaving** (so a difference in priority, and only that, is what
  separates roles) **and C to reverse** (so the ordering follows the
  configuration rather than anything fixed in the program).
- If A comes out blocked in role order, stop: something other than priority is
  ordering the queues, and no B result means anything until that is explained.
- If C does not reverse, the trace is not tracking the scheduler, and the
  intended-ladder passes are uninterpretable.

Whatever the outcome, it is a statement about **scheduler priority only**.
Reservoir depth and recirculation empty gaps are not addressed here and remain
separate evidence.

# Tofino-1 TM / pktgen / multicast / mirror feasibility for a fixed-transcript defense

> **REVISED for the one-Tofino constraint (`CORRECTION_LOG.md`).** This document's mechanism analysis
> (empty-slot skip, one-size-cell scheduling, pktgen inventory, cadence risk R13) stands and is correct.
> Its framing assumed encrypted cover cells; under the binding testbed there is no encryption, so the
> authoritative native-scheduling analysis is `analysis/tofino_native_scheduling.md`, which establishes:
> the only byte-transparent TCP/DNP3-safe cover the switch can send an unchanged master is a fixed-size
> pure-ACK token (carries the release offset, not size); pktgen can hold a byte-exact DNP3 template but
> its frozen TCP seq/ack make it a stale-seq segment without a per-flow ingress seq rewrite that does not
> fit the saturated tail; and a functional (non-strippable) size mechanism does not fit the resources.
> The only realizable native mechanism is a timing-only, real-packet-only release grid at public offsets
> (the frozen Defense 4 mechanism). Read the cadence, empty-slot, and resource facts here; read the
> native verdict there.

**Phase:** architecture / feasibility only. No production P4, no load, no switch contact.
**Target:** one Intel Tofino-1 (TNA), BF-SDE 9.13.1 compiler, at the outstation edge
(master -> observed WAN -> switch -> relay).
**Goal being assessed:** emit an observable wire transcript
`O = [(direction, size, release_time, outer_header)_i], i=1..K` that is independent of the protected
device and its response — the leading hypothesis being a Ditto-style repeating pattern of
fixed-size cells.

**Authorities used.** The measured live-core footprint and every placement number come from the
pinned audit `research/size_timing_coresidency/reports/p4-resource-audit.md` (source repo, read
at commit `7c4a5a7`). The queue ladder, pktgen burst, loopback port and blocker ethertype come
from `defense4/timing/p4/defense4_caseA.p4` (same commit). TM/pktgen/mirror/PRE semantics come from
the locally installed SDE tree `/home/philip/bf-sde-9.13.1` and from prior silicon microbenches on
this testbed. Where a fact is silicon-measured vs read-from-source vs reasoned, it is labelled.

Throughout, each mechanism carries one of four verdicts —
**SUPPORTED** (the TF1 architecture provides it directly),
**NEEDS-LOOPBACK** (only via a second scheduling pass on an internal port),
**NOT-SUPPORTED** (no TF1 primitive; would have to be emulated or abandoned),
**MUST-BE-PRICED** (available but with a cost or caveat that changes the design) —
and, separately, whether each claim is **ARCHITECTURE-SUPPORTED** (guaranteed by the target's
scheduling model) or merely **COMPILER-ACCEPTED** (bf-p4c will place it, but placement is an
allocator outcome that can flip and does not by itself buy the runtime behavior).

---

## 0. Headline

1. **The single biggest feasibility risk is not stages or tables — it is TM cadence quality at
   ICS packet rates.** TF1's only rate-pacing primitive is a max-rate token-bucket shaper, and it
   is silicon-measured to **clump below ~600 pps** (whole seconds silent, then a burst) while
   still hitting the correct average. A fixed transcript is a *cadence* claim, not an average-rate
   claim. So a clean fixed grid needs either a cell rate at or above ~600 pps (heavy chaff) or a
   pktgen **periodic-timer** clock (steady ~100 pps ±1, input-independent) driving the chaff — the
   shaper alone cannot manufacture a fixed cadence for a sparse flow.

2. **An empty scheduled slot is SKIPPED, not idled — yes.** TF1 TM scheduling is work-conserving:
   both strict priority (`max_priority`) and DWRR serve the next *backlogged* queue and pass over
   empty ones; if all queues are empty the port emits nothing and the next arrival leaves
   immediately. This is why the whole design rests on **chaff being continuously backlogged**: the
   fixed grid is produced by an always-full chaff queue that the scheduler drains at a paced rate,
   and a real cell replaces a chaff cell for its slot by winning strict priority. It is *not*
   produced by the scheduler reserving time for an empty queue — TF1 has no such mode.

3. **One-size cells collapse the hard problem.** Multi-size cells would need two-level scheduling
   (size-pattern outer, real-preempts-chaff inner), which TF1 cannot express on one port (no L1
   scheduler layer — proven from SDE source), forcing the Ditto two-pass loopback. **One cell size
   reduces the whole scheduler to a single (real HIGH, chaff LOW) pair under one port shaper on one
   port — single-level, no loopback.** This is the decisive reason to commit to one size.

4. **The MAU cost of the transcript logic is small and mostly egress-side (free).** Per-cell outer
   headers stamp in egress exactly like the measured size axis (0 ingress stages). The only ingress
   additions are a cell-class -> {qid, egress_port} write and the chaff parse path (which already
   exists for the D4 blockers on dp68). The real resources spent are queues, one pktgen app, buffer
   cells, and — if the fixed transcript is combined with the D4 timing hold — a loopback hop.

5. **Without encryption, real and chaff cells are distinguishable on the wire by construction**
   (payload bytes, checksums, DNP3 structure differ). The switch can make them the same *size,
   direction, timing and outer header*; it cannot make the *contents* indistinguishable to a
   passive observer who reads inside the cell. **This is flagged and owned by the transport agent,
   not solvable in the TM/dataplane layer.**

---

## 1. The governing fact: the TM does not create packets

Stated explicitly because every candidate design depends on it. On Tofino-1 the Traffic Manager
**only schedules packets that already exist in the packet buffer**. It has no packet source. The
only data-plane -> TM handle is the ingress `ig_intr_md_for_tm` struct (`qid`, `ucast_egress_port`,
`packet_color`, `ingress_cos`, and the multicast fields), and all of it is chosen **once, at
enqueue, before the packet enters the queue** (source: `tofino1_base.p4`
`ingress_intrinsic_metadata_for_tm_t`; verdict recorded in prior TM-primitives audit against SDE
9.13.2). Egress sees the queue only as read-only post-dequeue telemetry (`enq_qdepth`,
`deq_timedelta`, `egress_qid`, ...). Egress cannot influence scheduling; it runs after dequeue.

Consequence for a fixed transcript: **the cells must be manufactured somewhere, and the only
in-chip packet sources are the packet generator (pktgen) and recirculation/mirror.** Chaff cells
come from pktgen (or a self-looping recirc ring); real cells are the protected device's frames
already in the pipe. There is no "emit an idle cell" scheduler action — an idle slot is silence,
not a cell.

**ARCHITECTURE-SUPPORTED** (this is a structural property of the target, not a compiler outcome).

---

## 2. The crux: strict priority and round-robin on an EMPTY queue

**Does the slot get skipped? YES — the empty queue is passed over.**

TF1 exposes two scheduling passes per port (`tf1.tm.queue.sched_cfg`, verbatim in
`share/bf_rt_shared/bf_rt_tm_tf1.json` and `include/traffic_mgr/traffic_mgr_sch_intf.h`):

- `min_priority` (C `bf_tm_sched_q_priority_set`) orders the **guaranteed-rate** pass, and is
  **inert unless `min_rate_enable=true`** (default false).
- `max_priority` (C `bf_tm_sched_q_remaining_bw_priority_set`) orders the **remaining-bandwidth**
  pass — this is where two merely-backlogged queues actually compete — with DWRR (`dwrr_weight`)
  breaking ties within a priority.

Both passes are **work-conserving**: they select among **backlogged** (non-empty) queues only. An
empty queue is not "held for its turn"; the scheduler advances to the next backlogged queue in the
same cycle. If every queue is empty, the port sits idle and the next packet to arrive is served
immediately.

This is confirmed on silicon on this testbed, not merely read from headers: in the strict-priority
microbench a momentarily empty HIGH queue let the LOW queue drain at MHz rate the instant the HIGH
queue emptied — direct evidence that the scheduler does **not** insert idle time for an empty
high-priority queue; it immediately services whatever else is backlogged. (Source: prior silicon
run, `ibspg_mb.p4`, dp68 pipe-0 recirc.)

**Why this is the crux.** A fixed transcript needs a cell in slot *i* whether or not real data is
present. A work-conserving scheduler will not produce that cell from an empty queue — so the fixed
cadence cannot come from "schedule this queue every slot." It must come from a queue that is
**always backlogged**. That queue is the chaff queue, kept full by pktgen. The scheduler then
drains it at a paced rate, producing one cell per slot; a real cell, enqueued at higher
`max_priority`, wins its slot and displaces a chaff cell. Empty-real-queue -> chaff fills;
non-empty-real-queue -> real preempts. The pattern never breaks **as long as chaff never runs
dry**, which turns the whole feasibility question into "can pktgen keep the chaff queue backlogged
indefinitely" (Section 5) and "is the paced drain a clean cadence" (Section 0.1 / Section 9).

**ARCHITECTURE-SUPPORTED** (work-conserving skip is the defined behavior of both TF1 scheduling
passes; the silicon run corroborates it).

---

## 3. Is one real + one chaff queue per pattern state required?

**Yes — one (real, chaff) pair per distinct cell pattern-state, and this is exactly why one-size
cells matter.**

A "pattern state" is a distinct (size, rate) the transcript can be in. For the scheduler to be able
to emit the correct cell for that state in every slot *regardless of whether real data is present*,
that state needs:

- a **chaff queue** that is always backlogged with cells of that state's size (so a cell of the
  right shape is available every slot), and
- a **real queue** at higher `max_priority` holding real cells of that state's size (so a real cell
  preempts a chaff cell when present).

With **N distinct cell sizes you need N such pairs = 2N queues, arbitrated by a two-level
scheduler**: an outer level that visits each size-state on its fixed sub-schedule, and an inner
level (strict priority) that picks real-over-chaff within the state. **TF1 has no outer level**
(Section 4). So multi-size forces the two-pass loopback.

**With one cell size there is exactly one pattern-state -> exactly one (real HIGH, chaff LOW)
pair = 2 queues, arbitrated by a single flat strict-priority level on one port.** No outer level is
needed because there is nothing to rotate among. This is the single most important simplification
in the whole design.

**ARCHITECTURE-SUPPORTED** for the one-size case (a single strict-priority pair is exactly what one
flat TF1 port scheduler provides). **NEEDS-LOOPBACK** for the multi-size case.

---

## 4. Does the pattern need a loopback / second scheduling pass?

**One-size, single-lane, standalone transcript: NO.** A single (real HIGH, chaff LOW) pair on the
WAN-facing egress port, drained by one queue/port max-rate shaper, is one flat scheduling level and
needs no second pass.

**Multi-size, or "outer rate grid + inner arbitration" (true Ditto): YES — NEEDS-LOOPBACK.** This
is not a preference, it is forced by hardware. **TF1 has no L1 scheduler node layer**, proven three
independent ways from the local SDE 9.13.1 tree:

- `bf_rt_tm_tf1.json` has 33 TM tables and **no `l1_node.*`**; `bf_rt_tm_tf2.json` has
  `tf2.tm.l1_node.sched_cfg`/`sched_shaping`.
- `pkgsrc/bf-drivers/src/traffic_mgr/hw_intf/tm_tofino_hw_intf.h` has **0** `l1_` matches; the TF2
  header has 16.
- The C API `bf_tm_sched_q_l1_*` exists in the shared, target-agnostic header but dispatches
  through a function table TF1 never populates for L1.

So on TF1 a port's queues share **one flat scheduler** (`max_priority` + DWRR). "Strict priority
inside a pair, round-robin/rate across pairs" is not expressible on one port. Ditto itself states
this and sends every packet through the switch twice via loopback for exactly this reason. That
result transfers verbatim. A loopback pass costs **zero MAU stages** (the same ingress control
re-executes) but adds ACT-block breadth and any new dependency level (which on a program already at
stage==critical-path converts 1:1 to a stage). Per-pass latency is ~0.4-1 us, negligible against a
millisecond-scale ICS schedule.

**Combined with the D4 timing hold: the loopback is already present.** D4 runs its blocker
reservoirs on `PORT_L` = dp8 (a MAC-near loopback, pipe 0). If the fixed transcript is layered on
top of D4's deadline release, the released real packet has to travel from D4's dp8 hold queues to
the transcript lane on the WAN port — a re-enqueue that is a loopback hop. So the honest statement
is: **standalone one-size transcript needs no loopback; transcript-composed-with-D4-timing inherits
D4's dp8 loopback and uses it.**

**ARCHITECTURE-SUPPORTED** verdict on the no-L1 fact (proven from source). The loopback-cost figure
is COMPILER-ACCEPTED (it depends on the specific graft's dependency structure and must be
re-measured per build — see the audit's non-monotonic-placement warning).

---

## 5. Can pktgen supply reliable slot/chaff inventory indefinitely?

**Yes, indefinitely — with a rate/quality caveat that decides which pktgen mode to use.**

TF1 pktgen has four triggers (`install/include/pipe_mgr/pktgen_intf.h`, and the only actions in
`bf_rt_pktgen_tf1.json`): `trigger_timer_one_shot`, `trigger_timer_periodic`, `trigger_port_down`,
`trigger_recirc_pattern`. Two are relevant:

- **Periodic timer** (`trigger_timer_periodic(timer_nanosec)`): fires forever at a fixed period,
  one batch per period. **Silicon-measured as a steady metronome: ~100 pps ±1, self-clocked,
  input-independent.** This is the clean low-rate cadence source. Batch size
  `packets_per_batch_cfg` and `batch_count_cfg` are 16-bit (max 65535, zero-based), so one batch
  can be 1..65536 cells. The app does **not** auto-disable after a batch (must be explicitly
  toggled). This is the recommended **transcript clock** for a low, ICS-plausible cell rate.

- **Recirc-pattern trigger** (`trigger_recirc_pattern`, matches the first 32 bits of a recirculated
  frame, ternary value/mask): fires on a data-plane event. This is what D4 uses to seed its two
  reservoirs from **one 128-cell batch (64 ACK + 64 RESP)**. For chaff that must be backlogged at
  *line rate* (a high-rate cell grid), a **self-looping recirc ring** — a fixed set of K frames
  that re-trigger themselves on dp68 — keeps a queue continuously backlogged at line rate, which is
  what the D4 blocker reservoir already does.

**Limits and hard constraints (all read from SDE source / silicon):**

- **8 pktgen apps per pipe** (`app_id` is 3 bits). D4 already spends apps on its recirc-pattern
  reservoir path; the transcript clock is +1 app. Budget it (Section 7 / RESOURCE_BUDGET.md).
- **pktgen ports are pipe-local 68-71 only** (enforced in `pipe_mgr_tof_pktgen.c`
  `port_is_pktgenable`); dp68 is the one in pipe 0 already in use. Generated packets ingress on
  `pipe_local_source_port` (which is **required** to be set — the "implicit on TF1" comment is
  false on real hardware) and consume **input buffer 17**, shared with recirc traffic. High-rate
  chaff therefore contends with the D4 recirc ring for input buffer 17 — a real coupling to price.
- **pktgen packet buffer is small** (~16 KB/pipe, shared across apps; holds only the payload after
  the 6-byte generator header). Fine for one cell template; not a place to stage large payloads.
- **Minimum inter-packet gap is undocumented for TF1** (`ipg=0` = "no extra delay"; the driver only
  saturates the ns->clock conversion at 0xFFFFFFFF). So the *maximum* pktgen rate and the exact
  cadence of a dense batch are **not derivable from the tree** and would need silicon measurement
  before being trusted. The *steady* ~100 pps periodic figure IS measured.
- **The 6-byte generator header is stripped at the ingress deparser**, so per-cell identity (e.g. a
  sequence byte) must be **stamped into the frame** on the first pass if it must survive a loopback
  — `packet_id` is gone on the return pass. This is the same constraint D4 already handles with its
  ethertype stamp.

**Verdict: SUPPORTED for indefinite supply.** MUST-BE-PRICED for the rate: use the **periodic
timer** as the clock for a clean low rate, or a **self-looping recirc ring** for a line-rate
backlogged chaff queue; the max dense-batch rate and its jitter are UNKNOWN on TF1 and must be
measured, not assumed. (The steady 100 pps figure is silicon-measured; the batch/ipg ceiling is
COMPILER/DRIVER-ACCEPTED only, not characterized.)

---

## 6. Can multicast replica-ID move copy selection into egress?

**Partly — RID differentiates egress FORMATTING and outer headers, but NOT scheduling/queue
choice.**

Two in-chip multiplication routes exist (both real on TF1, both read from SDE source):

- **Ingress mirror session whose destination is a multicast group** (recommended). A session
  (`$mirror.cfg`) carries its own `$ucast_egress_port`/`$mcast_grp_a`/`$egress_port_queue`(qid)/
  `$max_pkt_len`. `$pre.mgid` holds a list of L1 nodes, each with its own `$MULTICAST_RID` and its
  own `$DEV_PORT` list. **N nodes each pointing at one port = N copies to that port, each with a
  distinct RID.** K is a control-plane constant fixed at group-install time; the data plane cannot
  make N+1.
- **pktgen recirc-pattern trigger** (Section 5) — a genuine data-plane trigger, but it still needs
  a mirror/clone to build its 4-byte trigger header, i.e. it is the mirror route plus more.

**Where RID helps the transcript.** `eg_intr_md.egress_rid` is readable in egress, so a multicast
fan-out can produce K egress copies and an egress table keyed on RID gives each copy a **distinct
outer header** (the `outer_header_i` component of the transcript) or a distinct cell-formatting,
**with no ingress branching**. This is the clean way to synthesize a burst of K differently-stamped
cells from one trigger, and it lands in egress where stages are free (Section 7).

**Where RID does NOT help.** `ig_tm_md.qid` is **one scalar for the entire replication**
(`tofino1_base.p4`), chosen at ingress enqueue. So multicast can differentiate egress *headers and
bytes* per copy, but **all copies of one replication share one queue and one schedule**. It cannot
place different copies on different queues or give them different release times. Release-time and
queue diversity remain an enqueue-time, per-packet decision — not something RID can move to egress.

Also: to avoid the copies being pruned, set the session `$mcast_rid` outside the node RID range and
leave the L2/XID prune table empty (both traps are visible in the SDE `tna_multicast` test).

**Verdict: SUPPORTED for per-copy outer-header/format selection in egress (via RID);
NOT-SUPPORTED for per-copy queue/schedule selection (qid is one scalar per replication).**
ARCHITECTURE-SUPPORTED on both halves (these are structural properties of PRE and the TM handle).

---

## 7. How does queue-ID selection interact with the existing D4 blockers (qid7/6/5/4)?

D4 occupies four queues **on `PORT_L` = dp8**: qid7 ACK-blocker reservoir, qid6 held ACK, qid5
RESP-blocker reservoir, qid4 held RESP (source: `defense4_caseA.p4:328-339`). The blocker
reservoirs (qid7, qid5) are HIGH `max_priority` and **continuously backlogged** — that backlog *is*
the hold mechanism.

Two independent facts decide the interaction:

1. **The transcript lane must not share dp8's flat scheduler with the blocker reservoirs.** dp8 has
   one flat scheduler across its queues, and qid7/qid5 are permanently backlogged at HIGH priority.
   Any transcript queue placed on dp8 would either be starved by those reservoirs (strict priority)
   or share bandwidth with them (DWRR) — either way its cadence is destroyed. **Therefore the
   fixed-transcript (real, chaff) pair belongs on the WAN-facing egress port, not on dp8.** On the
   WAN port the transcript pair gets its own clean flat scheduler; on dp8 the D4 reservoirs keep
   running untouched. They only interact through the pipeline, not through a shared scheduler.

2. **qid is a 5-bit field**, so the two ports have independent qid spaces; the transcript pair can
   use any two qids on the WAN port (e.g. real=qid1 HIGH `max_priority`, chaff=qid0 LOW) without
   colliding with D4's dp8 qid4-7. There is no global qid contention — the collision worry is
   per-port scheduler sharing, which point (1) resolves by port separation.

**The real composition cost.** D4 decides *when* a real ACK/RESPONSE is released (by draining its
dp8 hold queue at the deadline). The transcript lane decides *which wire cell* that real packet
occupies. Because these are two scheduling domains on two ports, a released real packet must travel
dp8 -> ingress -> WAN-port transcript queue, i.e. **the composition rides D4's existing dp8
loopback** (Section 4). No new loopback port is needed, but the released packet takes one more pass
to reach the transcript lane, and that pass must re-classify it to the transcript real-queue qid.

**Verdict: SUPPORTED, by putting the transcript pair on the WAN port (separate flat scheduler from
dp8) and reusing D4's dp8 loopback to feed released real packets into it.** ARCHITECTURE-SUPPORTED
(port-separated schedulers and the 5-bit per-port qid space are structural); the extra
classification table is COMPILER-ACCEPTED and priced in RESOURCE_BUDGET.md.

---

## 8. Do one-size cells avoid the hierarchical multi-size scheduling problem?

**Yes — decisively, and this is the recommendation.** Covered in Section 3: multi-size needs an
outer scheduling level TF1 does not have (no L1 nodes), forcing the Ditto two-pass loopback and 2N
queues; one size collapses the whole scheduler to a single strict-priority (real, chaff) pair on
one flat port scheduler. One size also means:

- **No per-size chaff inventory**: one chaff template, one pktgen app, one backlogged queue.
- **No size-classification of the real packet at the scheduler**: every real cell is the same
  shape, so "which state's slot does this belong to" does not exist as a question.
- **The transcript's `size_i` component is a constant** by construction — the strongest possible
  guarantee that size leaks nothing, with zero runtime machinery.

The cost paid for one size is **fragmentation/padding**: a real response larger than one cell must
be split across cells (consuming TCP sequence space, which forces the per-flow cumulative-delta
seq/ack translator — the same "padding an observer can't strip must consume sequence space" rule
that the size-normalization line already established), and a real payload smaller than a cell must
be padded inside the cell. That padding/splitting is the transport agent's problem, not a TM
problem, but it is the price of one-size and must be named.

**Verdict: SUPPORTED and recommended.** ARCHITECTURE-SUPPORTED (single flat pair is native TF1).

---

## 9. Candidate scheduler families, mapped onto TM + pktgen + recirc

For each: the mapping, the empty-slot behavior, how a real cell replaces chaff, and how the
receiver tells real from chaff.

### A. Continuous constant-rate cells (IP-TFS-like) — RECOMMENDED for one size

**Mapping.** On the WAN egress port: real=qid1 (HIGH `max_priority`), chaff=qid0 (LOW). Chaff kept
backlogged by a pktgen source. Cadence set by one queue/port **max-rate shaper** (or, for a clean
low rate, by a pktgen **periodic timer** producing exactly one chaff cell per slot into a shallow
queue). Real cells enqueued at qid1 preempt chaff for their slot.

**Empty-slot behavior.** Chaff queue never empties -> the scheduler always has a cell -> one cell
per slot regardless of real traffic. This is the *only* candidate where the empty-slot problem is
fully neutralized by construction.

**Real replaces chaff.** Strict priority: a real cell at qid1 wins its slot; the displaced chaff
cell waits (and is dropped or aged out to keep depth bounded). Because both are one size, the wire
sees one same-size cell per slot either way.

**Receiver tells them apart.** By contents (payload/checksum/DNP3). Same size/timing/header,
different bytes. **Without encryption this is distinguishable — transport agent owns the fix**
(e.g. encrypt the cell body, or make chaff carry well-formed benign DNP3 that is indistinguishable
at the application layer — a strong and separate claim).

**Verdict: SUPPORTED (one lane, one size), MUST-BE-PRICED on cadence** — clean grid needs
rate >= ~600 pps (shaper) or a pktgen periodic clock; below ~600 pps the shaper clumps.

### B. Request-synchronized fixed epochs — this is D4's mechanism, generalized

**Mapping.** On each request (READ) arrival, arm a deadline and emit a fixed-shape burst of K cells
(pktgen recirc-pattern trigger — exactly D4's 128-cell burst path), released on the D4 deadline
schedule. The transcript per epoch is a constant K-cell shape.

**Empty-slot behavior.** Within the epoch the K cells are pktgen chaff; a slot with no real payload
stays chaff, a slot with real payload is rewritten/replaced. The epoch has a fixed number of slots
by construction, so there is no "skipped slot" — the burst length is fixed.

**Real replaces chaff.** As in D4: the real ACK/RESPONSE is held and released into the epoch; the
matching chaff cell is suppressed.

**Receiver tells them apart.** Same as A.

**Caveat that decides it.** A transcript "independent of the device" requires the epoch shape to be
constant *regardless of the real response's size* — which forces splitting the real response onto
the fixed K-cell grid, i.e. size normalization. The pinned audit shows size normalization's hard
part (TCP sequence translation) is **per-flow ingress state that lands on the saturated ingress
tail (stages 8-11 at 16/16 LTIDs) and the exhausted W0-15 group** — the one place the "free" egress
result does not transfer.

**Verdict: SUPPORTED as timing (it is D4), MUST-BE-PRICED for the size-normalization ingress state
it implies.**

### C. Ditto two-pass (outer rate grid + inner arbitration)

**Mapping.** Pass 1 on an internal loopback port imposes the outer fixed grid across pattern-states;
pass 2 emits to the WAN port. Required only if there is more than one cell size/state.

**Empty-slot behavior.** Each state's chaff pair backfills its own slots; the outer grid visits
states on a fixed sub-schedule.

**Two hard facts.** (1) It **NEEDS-LOOPBACK** because TF1 has no L1 layer (Section 4). (2) An outer
rate grid and D4's inner deadline hold are **SUBSTITUTES, not complements**: a coarse grid makes the
grid (not `t_ACK + D`) the observable and turns most of D4's 10-stage deadline apparatus into dead
weight; a fine grid that preserves D4's 1.72 us release precision needs ~580 kpps of chaff
(~297 Mbps at 64 B) — absurd as ICS cover traffic. So you get the grid or the hold, not both.

**Verdict: NEEDS-LOOPBACK; and for a single cell size it is unnecessary (collapses to A). Only
justified by genuine multi-size, and then it competes with rather than complements D4 timing.**

### D. Slot-token / calendar scheduler

**Mapping.** A calendar / timing-wheel that assigns each cell an explicit slot time.

**Fact.** **TF1 has no calendar or timing-wheel scheduler primitive.** The only pacing primitives
are the max-rate token-bucket shaper (clumps at low rate) and DWRR. A calendar would have to be
*emulated* — either by multiple pktgen periodic timers (one app per distinct period, 8 apps max) or
by a recirc ring plus a per-slot deadline register compared against the timestamp (the D4 deadline
idiom, one slot at a time). Emulation is coarse and spends the scarce pktgen-app / recirc budget.

**Verdict: NOT-SUPPORTED as a native primitive; MUST-BE-PRICED as a coarse emulation if pursued.**

---

## 10. ARCHITECTURE-SUPPORTED vs COMPILER-ACCEPTED — summary

| Claim | Verdict | Supported by |
|---|---|---|
| TM cannot create packets; chaff must come from pktgen/recirc | ARCHITECTURE-SUPPORTED | `ig_intr_md_for_tm` at enqueue only; TM has no source |
| Empty scheduled slot is skipped (work-conserving) | ARCHITECTURE-SUPPORTED | both TF1 sched passes serve backlogged queues only; silicon empty-gap |
| One (real,chaff) pair per size-state; 2N queues for N sizes | ARCHITECTURE-SUPPORTED | flat per-port scheduler; no L1 layer (SDE source) |
| One-size standalone lane needs no loopback | ARCHITECTURE-SUPPORTED | single flat strict-priority pair is native |
| Multi-size / Ditto grid needs loopback | ARCHITECTURE-SUPPORTED (the *need*); loopback cost COMPILER-ACCEPTED | no L1 nodes on TF1 |
| pktgen supplies chaff indefinitely (periodic timer) | ARCHITECTURE-SUPPORTED for supply; steady 100 pps silicon-measured | pktgen periodic trigger; measured |
| pktgen max dense-batch rate / ipg floor | UNKNOWN — neither; must measure | undocumented in SDE tree |
| Multicast RID -> per-copy egress header/format | ARCHITECTURE-SUPPORTED | `eg_intr_md.egress_rid` readable in egress |
| Multicast RID -> per-copy queue/schedule | NOT-SUPPORTED | `ig_tm_md.qid` is one scalar per replication |
| Transcript pair on WAN port, separate from dp8 blockers | ARCHITECTURE-SUPPORTED (port-separated schedulers) | per-port flat scheduler; 5-bit per-port qid |
| Cell-class -> {qid, egress_port} ingress table fits at 12/12 | COMPILER-ACCEPTED (expected absorbed; re-measure) | audit I1/I2: one early-keyed ingress table absorbed |
| Per-cell outer header stamped in egress at 0 ingress cost | COMPILER-ACCEPTED (measured for the size axis) | audit S1: egress tables land stages 0-1, free |
| Fixed low-rate cadence from the max-rate shaper alone | MUST-BE-PRICED / effectively unsupported <~600 pps | silicon: shaper clumps below ~600 pps |

**Rule of thumb for this program:** the *scheduling-model* claims (Sections 1-4, 6, 8) are
architecture-supported and will not move. The *placement* claims (which table lands where, whether a
graft costs a stage) are compiler-accepted and, per the audit, **non-monotonic in program size** —
every one must be re-measured after each edit, never assumed.

---

## 11. The single biggest Tofino feasibility risk

**TM cadence quality at ICS packet rates.** Everything else has a clean answer: chaff comes from
pktgen, the empty slot is handled by an always-backlogged chaff queue, one size removes the
hierarchical-scheduling wall, the MAU cost is small and mostly free egress work, and the queues/
ports/buffer all fit. The one thing TF1 does **not** give you cleanly is a *fixed low cadence*: the
only rate-pacing primitive is a max-rate token-bucket shaper that is silicon-measured to **clump
below ~600 pps** (whole seconds silent, then a burst) — it hits the right average but not a fixed
grid. A fixed transcript is a cadence property, so the design is forced to either (a) run the cell
grid at >= ~600 pps, paying heavy continuous chaff bandwidth to buy a smooth grid, or (b) clock the
grid with a pktgen **periodic timer** (steady ~100 pps ±1) instead of the shaper — at which point
the *maximum* clean rate and its jitter become an UNKNOWN that must be measured on silicon, because
TF1's pktgen inter-packet-gap floor is undocumented. Until that cadence is characterized on the
actual switch, the transcript's `release_time_i` regularity — the whole point of the defense — is
the unproven quantity.

Second-order risks, already priced: input-buffer-17 contention between high-rate chaff and the D4
recirc ring; and, if combined with D4 timing, the size-normalization ingress state (TCP seq
translation) that lands on the saturated ingress tail.

---

## 12. Note handed to the transport agent (out of scope here, flagged not solved)

Without encryption, real and chaff cells are **distinguishable by their contents** even when the
switch makes them identical in size, direction, timing and outer header. The TM/dataplane layer
cannot close this — it operates on headers and scheduling, not payload indistinguishability. The
fix (encrypting the cell body, or generating chaff that is well-formed benign DNP3 indistinguishable
at the application layer) belongs to the transport/crypto design and is a separate, load-bearing
claim. Recorded here so it is not silently assumed away by the fixed-transcript wire shape.

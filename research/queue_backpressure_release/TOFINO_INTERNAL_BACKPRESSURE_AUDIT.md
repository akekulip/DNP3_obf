# Tofino-1 Internal-Backpressure Capability Audit (READ-ONLY)

**Target:** Intel Tofino-1, BF-SDE 9.13.2, switch `decps@10.10.54.81` (hostname `ufispace`,
UFISpace S9180-32X). SDE at `/home/decps/Downloads/bf-sde-9.13.2`,
`SDE_INSTALL=$SDE/install`.

**Scope / method:** Pure documentation audit. I changed **nothing** on the switch. The
running microbench (`bf_switchd --conf-file /home/decps/queue_microbench/out/queue_microbench_abs.conf`,
PID 8442, uptime 18m39s at audit time) was left running and untouched. I did **not** attach a
bfrt/gRPC client, did not restart `bf_switchd`, and sent no traffic. All evidence below comes
from reading SDE headers (`$SDE_INSTALL/include/traffic_mgr/*.h`,
`$SDE_INSTALL/include/port_mgr/bf_port_if.h`), the fixed-function TM bfrt schema
(`$SDE_INSTALL/share/bf_rt_shared/bf_rt_tm_tf1.json`), and the TNA architecture P4
(`$SDE_INSTALL/share/p4c/p4include/tofino1_base.p4`). Files were copied off the switch with
`scp` (read) and inspected locally.

**Evidence tags used below:** `[SDE-VERIFIED]` = quoted verbatim from an SDE header/schema on
this switch; `[SILICON, prior]` = measured on this Tofino-1 in a prior session (cited from
agent memory); `[REASONING]` = architectural inference, not directly confirmed in the SDE.

---

## Framing: the two things "backpressure" can mean on Tofino-1

Reading the TM headers makes a hard distinction, and it is the spine of every answer below:

1. **A DROP threshold** (ingress admission limit, egress drop limit, queue tail-drop, color
   drop). When occupancy crosses the limit, the packet is **discarded**. This is *not* a hold.
   `[SDE-VERIFIED]` `traffic_mgr_port_intf.h:38-58` — ingress: "When buffer usage accounted on
   port basis crosses the limit, traffic is **not admitted** into traffic manager."
   `:127-145` — egress: "traffic **Will be dropped** on QAC stage."

2. **A PFC / pause hold** (lossless-treatment PPG + PFC, or an egress queue honoring received
   PFC). Here a packet is held **queue-resident** — *not* scheduled, *not* dropped — while the
   pause condition is asserted, and released when it clears. This is the *only* place in the TM
   where "downstream can't accept → original stays resident" is a real primitive, and it is the
   crux of this audit. `[SDE-VERIFIED]` `traffic_mgr_q_intf.h:546-567`
   (`bf_tm_q_pfc_cos_mapping_set`): "When egress queues need to honour received PFC from
   downstream, by mapping cos to queue using the API below, **queues will not participate in
   scheduling until PFC gets cleared.**"

Everything the task asks about resolves to: *which bucket does this mechanism fall in, and can
the hold bucket be driven by bounded data-plane packets without a control-plane call?*

The decisive data-plane constraint (why the answer is ultimately NO) is in the TNA arch itself.
`[SDE-VERIFIED]` `tofino1_base.p4` `ingress_intrinsic_metadata_for_tm_t`:
- line 135-136: `bit<3> ingress_cos` — "Ingress cos (iCoS) for PG mapping, ingress admission
  control, **PFC**" — the *only* data-plane field that touches PFC, and it merely **selects
  which PPG** a packet is accounted against at enqueue.
- line 139: `QueueId_t qid` — egress queue selection at enqueue.
- line 131-132: `bit<1> deflect_on_drop` — "Request for deflect on drop ... presented to TM to
  enable deflection."
- Egress side is post-dequeue read-only telemetry only: `enq_congest_stat` (233),
  `deq_congest_stat` (247), `app_pool_congest_stat` (250), `deflection_flag` (277).

So the data plane can *choose* a PPG/queue and *request deflect-on-drop*, but it has **no lever
to assert, deassert, or threshold a PFC/pause**, and no lever to reach an already-enqueued
packet. PFC/pause assertion is either HW-threshold-automatic or a control-plane register write
(`bf_tm_sched_q_egress_pfc_status_set`, `bf_tm_port_pfc_state_set`). This is consistent with the
prior full TM-primitive audit (memory `tofino1-tm-queue-release-primitives`).

---

## Mechanism 1 — MAC-near loopback: does it exert / can it be congested?

- **API / doc ref:** `[SDE-VERIFIED]` loopback mode enum `bf_loopback_mode_e` in
  `port_mgr/bf_port_if.h:93-105` (`BF_LPBK_MAC_NEAR` line 94); setter
  `bf_port_loopback_mode_set()` `:830`. bfrt equivalent: `$PORT.$LOOPBACK_MODE` field
  (`BF_LPBK_MAC_NEAR`), used in lab code `GridCloak/p4/gc_switch_setup_c.py` (memory
  `tofino1-dp68-recirc-selfclock`).
- **Config:** static (control-plane one-time per port).
- **Trigger:** n/a — a loopback is a data-path topology, not a triggered mechanism. It makes a
  port's TX re-enter its own RX at the MAC layer.
- **Where the original resides:** a MAC-near loopback port still has normal ingress-admission →
  TM-queue → egress-scheduling stages. A packet looped through it sits in the **egress TM queue**
  of that port like any other, subject to that queue's thresholds.
- **Result type:** the loopback itself is neither hold nor drop. It is a *carrier*. If the
  looped port's egress queue fills past threshold, the result is **DROP** (tail/color); it does
  not by itself back-pressure the source. `[REASONING]`
- **Backpressure question:** A MAC-near loopback *does* instantiate a real MAC, so in principle
  the MAC's IEEE-802.3x / PFC pause-generation logic exists on it (unlike the recirc port, which
  has no MAC). Whether a *self*-looped port feeds its own MAC-generated pause frame back into its
  own honoring logic (i.e., whether it can pause itself) is **`[REASONING]` / unverified in the
  SDE** — it depends on silicon MAC wiring that the headers do not describe.
- **Release / granularity / latency:** n/a for the carrier; inherits the egress queue's
  properties (per-queue).
- **Safety risk:** low as a carrier. If combined with PFC self-generation (see M5/M6), a
  self-loop is exactly the topology that can create a **PFC deadlock** — high risk. `[REASONING]`
- **Isolate one flow:** no (a loopback carries whatever is routed to it).
- **Requires external traffic:** no (internal MAC loop, no cable).
- **Low-rate testable:** yes as a carrier; but congesting it to produce backpressure needs
  threshold-crossing occupancy (not low-rate). `[REASONING]`

## Mechanism 2 — MAC-far loopback

- **API / doc ref:** `[SDE-VERIFIED]` `BF_LPBK_MAC_FAR` (`bf_port_if.h:95`), same setter.
- Everything else is identical to M1 in TM terms. MAC-far loops back at a different point in the
  MAC (further out toward the serdes) than MAC-near, but from the TM's perspective the packet
  still transits ingress-admission → egress-queue → scheduling, so the buffering/backpressure
  behavior and verdicts are the same as M1. `[REASONING]`
- **Verdict:** carrier, not a hold/backpressure primitive on its own. DROP on overflow.

## Mechanism 3 — Recirculation-port backpressure (dp68 oversubscribed)

- **API / doc ref:** dp68 = pipe-0 internal recirc port (memory `tofino1-dp68-recirc-selfclock`;
  GridCloak `gc_switch_setup_c.py`, `recirculation_enable=True` via `tf1.pktgen.port_cfg`).
  The recirc port has **no MAC** → no PFC, no 802.3x pause. Its queues are ordinary TM queues
  (`tf1.tm.queue.*`).
- **Config:** static enable; queue thresholds are control-plane.
- **Trigger:** packet-driven occupancy.
- **Where the original resides:** in dp68's egress TM queue.
- **Result type:** **DROP** when oversubscribed. `[SILICON, prior]` measured directly
  (memory `tofino1-strict-priority-not-absolute-recirc`, ibspg_mb.p4 on this switch): a
  continuously-backlogged recirc queue saturates at `use≈126, wm=127` cells and additional
  enqueues are **dropped** — the backlog does not hold new packets, it discards them. There is no
  pause on the recirc path.
- **Release:** n/a (drops).
- **Granularity:** per-queue on dp68.
- **Latency:** sub-µs empties even when "saturated" — `[SILICON, prior]` the low queue still
  drained at 1.3–5.3 M passes/s behind a saturated high-priority ring (same memory). So even a
  "full" recirc queue does not hold a co-resident packet still.
- **Safety risk:** medium — oversubscribing the shared recirc port degrades the pipe the
  microbench uses.
- **Isolate one flow:** no. **External traffic:** no. **Low-rate testable:** the drop threshold
  is only reached at high rate, so "backpressure" is not observable at low rate. `[SILICON,prior]`
- **Verdict:** recirc oversubscription = DROP, never a queue-resident hold.

## Mechanism 4 — Internal port flow control (scheduler advanced FC: credit / XOFF)

- **API / doc ref:** `[SDE-VERIFIED]` `bf_tm_sched_q_adv_fc_mode_set()`
  (`traffic_mgr_sch_intf.h:789-792`), enum `bf_tm_sched_adv_fc_mode_t {CRE=0, XOFF=1}`
  (`traffic_mgr_types.h:240-244`), pipe-level enable `bf_tm_sched_adv_fc_mode_enable_set()`
  (`:808-810`). The header states its purpose explicitly: "Scheduler Advanced Flow Control
  Mechanism, 0 = Credit 1 = Xoff **used for TM Visibility Implementation**" (`:774-776`).
- **Interpretation:** this is the internal signaling mode between the queue scheduler and the
  QSTAT / queue-visibility subsystem (paired with `bf_tm_q_visible_set`,
  `traffic_mgr_q_intf.h:450`), **not** a general per-packet hold knob. It selects *how* the
  internal FC is signaled (credit vs xoff) for the depth-reporting feature.
- **Config:** static, control-plane, per-queue + per-pipe enable.
- **Trigger / residence / result:** not a data-plane-triggerable packet-hold primitive.
  `[REASONING]` — I found no evidence it can be driven by a data-plane packet, and its documented
  role is visibility, not packet holding.
- **Isolate one flow / external traffic / low-rate:** n/a — not a usable hold lever.
- **Verdict:** not a candidate. (Recorded so it is not mistaken for a backpressure knob later.)

## Mechanism 5 — PFC (priority flow control): config and triggering

- **API / doc ref (control-plane):** `[SDE-VERIFIED]`
  - Mode: `bf_tm_port_flowcontrol_mode_set()` (`traffic_mgr_port_intf.h:221-223`),
    `bf_tm_port_flowcontrol_rx_set()` (`:246-248`), types `BF_TM_PAUSE_{NONE,PFC,PORT}`
    (`traffic_mgr_types.h:207-211`). bfrt: `tf1.tm.port.flowcontrol` (key `dev_port`;
    data `mode_tx, mode_rx, cos_to_icos`).
  - CoS mapping: `bf_tm_port_pfc_cos_mapping_set()` (`:268-270`),
    `bf_tm_q_pfc_cos_mapping_set()` (`traffic_mgr_q_intf.h:564-567`). bfrt:
    `tf1.tm.queue.cfg` (key `pg_id,pg_queue`; data `mirror_drop_destination, pfc_cos`).
  - Direct state write: `bf_tm_port_pfc_state_set(dev,port,icos,state)`
    (`traffic_mgr_port_intf.h:283-286`) and `bf_tm_sched_q_egress_pfc_status_set(dev,port,queue,
    status)` (`traffic_mgr_sch_intf.h:827-830`) + `_clear` (`:845-847`).
  - Lossless PPG that *generates* PFC: `bf_tm_ppg_lossless_treatment_enable()`
    (`traffic_mgr_ppg_intf.h:134`), skid/headroom
    `bf_tm_ppg_skid_limit_set()` (`:264`) — "Before consuming skid or head room buffer, **PFC
    would be asserted** for lossless flows" (`:250-251`); pool `tf1.tm.pool.app_pfc`
    (key `pool,cos`; data `pfc_limit_cells`), `tf1.tm.pool.skid` (`resume_limit_cells`).
    "When buffer space usage spills into skid pool, **PFC is asserted**"
    (`traffic_mgr_types.h:91-93`).
- **Config:** static setup (lossless PPG, thresholds, cos maps, rx honor) is all control-plane.
- **Trigger:** **threshold-driven in HW** — ingress PPG headroom/skid occupancy crossing a limit
  causes the switch to emit a PFC pause on that ingress port. Honoring is frame-driven: a
  received PFC pause frame for a mapped CoS stops the honoring egress queue.
- **Where the original resides:** two roles —
  (a) *Generating side*: in-transit lossless packets sit in the ingress PPG's **skid/headroom
  buffer** (queue-resident) while pause is asserted, **then are DROPPED once skid limit is
  reached** — `[SDE-VERIFIED]` `traffic_mgr_ppg_intf.h:247-250` "Once skid limit is reached,
  even lossless traffic will be dropped."
  (b) *Honoring side*: a packet in an egress queue mapped to the paused CoS stays **queue-
  resident and unscheduled** until PFC clears — `[SDE-VERIFIED]` `traffic_mgr_q_intf.h:548-552`.
- **Result type:** HOLD (honoring egress queue) → then DROP if the generating side's skid
  exhausts. So PFC gives a *bounded-duration* hold backed by a finite buffer, not an indefinite
  one.
- **Release:** PFC XON / pause-clear (HW when occupancy falls below hysteresis; or CP via
  `_state_clear` / `_egress_pfc_status_clear`). Hysteresis: `tf1.tm.ppg.cfg.hysteresis_cells`,
  `bf_tm_ppg_guaranteed_min_skid_hysteresis_set()` (`traffic_mgr_ppg_intf.h:306`).
- **Granularity:** **per-priority-class (CoS/iCoS 0..7) per port** — 8 classes. Not per-flow,
  not per-packet.
- **Latency:** pause reaction is HW-fast (sub-µs to µs). Hold *duration* is bounded by
  skid/headroom depth on the generating side.
- **Safety risk:** **HIGH.** PFC asserted and honored around a loop on the same chip is the
  classic **PFC deadlock / pause-storm** failure mode; lossless headroom exhaustion causes
  head-of-line blocking that can spill across queues/PPGs sharing a pool. On a shared switch
  running the microbench in other pipes this can wedge ports. `[REASONING]` (well-established
  PFC behavior; not a Tofino-specific claim).
- **Isolate one flow:** no — coarsest usable unit is one CoS on one port (a whole traffic class).
- **External traffic:** to *self*-generate PFC internally you need a physical loopback/hairpin
  (M1/M13) so a generating port's emitted pause frame reaches the honoring port; a MAC-near
  self-loop feeding its own honoring logic is `[REASONING]`/unverified.
- **Low-rate testable:** **no.** PFC generation requires crossing a buffer (skid/headroom)
  threshold of tens–hundreds of cells; DNP3-cadence (~5 Hz, tiny frames) never approaches it.
  This mirrors the measured TM starvation floor (`[SILICON, prior]`, GridCloak `exp_tm_floor.py`:
  a TM queue did not drain / did not engage below ~1200 pps). To observe PFC you must inject a
  burst — not a low bounded rate in the occupancy sense.

## Mechanism 6 — Pause-frame handling (802.3x link-level, port pause)

- **API / doc ref:** `[SDE-VERIFIED]` `BF_TM_PAUSE_PORT` mode via
  `bf_tm_port_flowcontrol_mode_set/rx_set` (`traffic_mgr_port_intf.h:221,246`); MAC-level
  `bf_port_flow_control_link_pause_set()` (`bf_port_if.h:697`),
  `bf_port_xoff_pause_time_set/xon_pause_time_set` (`:824-829`),
  `bf_port_flow_control_frame_src_mac_address_set()` (`:1089`).
- **Config:** static, control-plane.
- **Trigger:** threshold-driven (port ingress occupancy) for generation; frame-driven for honor.
- **Residence / result:** same shape as PFC but **whole-port, all classes** — coarser than PFC.
  A received port-pause stops the port's egress; queued packets stay resident until pause clears
  or buffers overflow → then DROP.
- **Release / latency / safety:** as M5 but port-granular; same deadlock hazard on a loop.
- **Granularity:** **per-port** (no class distinction).
- **Isolate one flow:** no (coarser than PFC). **External traffic:** yes (a self-loop or a peer).
  **Low-rate testable:** no (threshold crossing). `[REASONING]`
- **Verdict:** strictly coarser than M5; same fundamental limits.

## Mechanism 7 — PPG thresholds (ingress admission)

- **API / doc ref:** `[SDE-VERIFIED]` `bf_tm_ppg_app_pool_usage_set()`
  (`traffic_mgr_ppg_intf.h:198-203`, params `base_use_limit`, `dynamic_baf`, `hysteresis`),
  `bf_tm_ppg_guaranteed_min_limit_set()` (`:242`), `bf_tm_ppg_skid_limit_set()` (`:264`),
  BAF enum `bf_tm_ppg_baf_t` (`traffic_mgr_types.h:147-158`). bfrt `tf1.tm.ppg.cfg`
  (key `ppg_id`; data `icos_0..7, guaranteed_cells, hysteresis_cells, pool_id, pool_max_cells,
  dynamic_baf, ppg_counter_id`). Port ingress limit: `bf_tm_port_ingress_drop_limit_set()`
  (`traffic_mgr_port_intf.h:56`), bfrt `tf1.tm.port.buffer.ig_limit_cells / ig_hysteresis_cells`.
- **Config:** static, control-plane thresholds.
- **Trigger:** packet occupancy vs limit.
- **Where the original resides / result type:**
  - *Lossy* PPG (default): crossing the limit → **traffic not admitted = DROP** at ingress
    (`traffic_mgr_port_intf.h:39-41`). No hold.
  - *Lossless* PPG: crossing headroom → **assert PFC** (M5) and hold in skid → DROP when skid
    exhausts.
- **Release:** hysteresis (`hysteresis_cells`) clears the drop/pause condition.
- **Granularity:** per-PPG (a PPG groups one or more iCoS on a port); up to 256 extra PPGs/pipe
  (`traffic_mgr_types.h:43-47`).
- **Latency / safety:** admission decision is immediate; lossless path carries M5's deadlock
  risk. **Isolate one flow:** partially — a PPG can be dedicated to a chosen iCoS, but it is a
  class, not one transaction. **External traffic:** to fill it, yes (sustained). **Low-rate
  testable:** no (threshold). `[REASONING]` + `[SDE-VERIFIED]` thresholds.
- **Verdict:** DROP (lossy) or PFC-hold-then-DROP (lossless). Not an indefinite per-flow hold.

## Mechanism 8 — Queue hysteresis

- **API / doc ref:** `[SDE-VERIFIED]` `bf_tm_q_hysteresis_set()` (`traffic_mgr_q_intf.h:512`),
  `bf_tm_q_color_hysteresis_set()` (`:314`), bfrt `tf1.tm.queue.buffer.hysteresis_cells`.
  PPG/port equivalents: `tf1.tm.ppg.cfg.hysteresis_cells`,
  `tf1.tm.port.buffer.{ig,eg}_hysteresis_cells` (default 32 cells,
  `traffic_mgr_port_intf.h:101,157`).
- **What it is:** hysteresis is the *release/clear* offset for a drop-or-pause condition — "When
  usage of cells goes below hysteresis value port pause or drop condition **will be cleared**"
  (`traffic_mgr_port_intf.h:96-99`). It is a **modifier** on M5/M6/M7/M9, not a standalone
  hold/drop mechanism.
- **Config:** static, control-plane. **Trigger:** occupancy falling below (limit − hysteresis).
- **Residence/result/granularity:** inherits the mechanism it modifies (per-queue / per-PPG /
  per-port). **Isolate one flow:** no. **External traffic:** no (it is a threshold parameter).
  **Low-rate testable:** only in combination with the thing it gates.
- **Verdict:** a knob, not a mechanism. Relevant because it governs *release* timing of any
  pause/drop condition, so it would shape the release edge of a PFC-hold if one were built.

## Mechanism 9 — Egress buffer thresholds (per-queue / per-port)

- **API / doc ref:** `[SDE-VERIFIED]` per-queue: `bf_tm_q_app_pool_usage_set()`
  (`traffic_mgr_q_intf.h:205`), `bf_tm_q_guaranteed_min_limit_set()` (`:257`),
  `bf_tm_q_tail_drop_enable/disable()` (`:336,357`), color limits `bf_tm_q_color_limit_set()`
  (`:288`), `bf_tm_q_color_drop_enable()` (`:378`). bfrt `tf1.tm.queue.buffer`
  (`guaranteed_cells, hysteresis_cells, tail_drop_enable`), `tf1.tm.queue.color`. Per-port egress
  limit `bf_tm_port_egress_drop_limit_set()` (`traffic_mgr_port_intf.h:143`), bfrt
  `tf1.tm.port.buffer.eg_limit_cells`.
- **Config:** static, control-plane.
- **Trigger:** egress queue/port occupancy vs limit; packet color vs color limit.
- **Where the original resides / result type:** packets accumulate **queue-resident** in the
  egress queue **up to** the limit — this *is* a transient hold while the queue fills — then:
  - tail-drop enabled (default): **DROP** at egress (`traffic_mgr_q_intf.h:320-338`).
  - tail-drop **disabled**: egress does not drop, but "This **will lead to Ingress drops
    eventually**" (`:340-344`) — i.e., the backlog propagates to ingress-side drop, still a DROP,
    just relocated. It is **not** an indefinite hold.
- **Release:** normal scheduling once occupancy falls (hysteresis). Not event-releasable.
- **Granularity:** per-queue and per-port. **Latency:** the hold lasts only as long as it takes
  the queue to hit its limit at the incoming rate. **Safety:** medium (buffer pressure on shared
  pools). **Isolate one flow:** a dedicated queue can isolate a class, not one transaction.
  **External traffic:** to build occupancy, yes (sustained). **Low-rate testable:** no — at low
  rate the queue drains faster than it fills, so it never reaches the threshold and never holds.
  `[SDE-VERIFIED]` semantics + `[SILICON, prior]` TM floor.
- **Verdict:** transient fill-then-DROP, governed by drain rate. Not a controllable hold.

## Mechanism 10 — Port/queue scheduling disable (make a queue non-serviceable)

- **API / doc ref:** `[SDE-VERIFIED]` `bf_tm_sched_q_disable()` (`traffic_mgr_sch_intf.h:362-364`)
  / `bf_tm_sched_q_enable()` (`:342`) — "If disabled, **queue will not participate in
  scheduling**" (`:347-348`); port-level `bf_tm_sched_port_disable/enable()` (`:771,757`).
  bfrt `tf1.tm.queue.sched_cfg.scheduling_enable` (also `min/max_priority`, `dwrr_weight`,
  `min/max_rate_enable`). Egress-PFC-status write
  `bf_tm_sched_q_egress_pfc_status_set()` (`:827`).
- **Config:** static/dynamic but **control-plane** (bfrt/gRPC).
- **Trigger:** control-plane call only. **No data-plane path** sets `scheduling_enable` or
  `egress_pfc_status` (confirmed by the arch-metadata review above — the data plane has no such
  field).
- **Where the original resides:** **queue-resident HOLD** — packets stay enqueued and
  unscheduled indefinitely, up to buffer limits, then tail-drop. This is the **cleanest true
  hold** on Tofino-1.
- **Result type:** HOLD (until buffer exhaustion → DROP).
- **Release:** re-enable scheduling (or clear egress-pfc-status). **Releases the WHOLE backlog**,
  then paced by the shaper — not one packet. (memory `tofino1-tm-queue-release-primitives`.)
- **Granularity:** per-queue (`sched_q_disable`) or per-port (`sched_port_disable`).
- **Latency:** control-plane call latency (ms-scale gRPC).
- **Safety:** low if scoped to an unused queue; the operation is deterministic.
- **Isolate one flow:** only if the flow is alone on a dedicated queue (per-queue, not
  per-transaction unless one transaction owns the queue). **External traffic:** no.
  **Low-rate testable:** **yes** — this is the one hold that works regardless of rate, *because
  it is control-plane, not occupancy-driven.*
- **Verdict:** real, reliable, per-queue HOLD/RELEASE — but **control-plane**, so it fails the
  "bounded data-plane packet, no CP op" requirement. It is the CP baseline the data-plane family
  is trying (and failing) to replace.

## Mechanism 11 — Port-down behavior (does a down egress port hold or drop?)

- **API / doc ref:** `[SDE-VERIFIED]` — note `bf_tm_port_all_queues_flush()` "**Only available on
  tofino2. Otherwise no-op, returns success**" (`traffic_mgr_port_intf.h:381-393`). So on TF1
  there is no explicit port-queue flush.
- **Config / trigger:** link event (physical) or admin disable.
- **Where the original resides / result:** `[REASONING]` — with the egress port not scheduling
  (down), packets destined to its queues **accumulate queue-resident** until buffer/queue limits,
  then **tail-drop** (same fill-then-DROP as M9/M10). The SDE does not document an automatic
  drain-on-down for TF1, and there is no TF1 flush API, which is consistent with "hold until
  buffers fill, then drop." Not independently verified on silicon this session.
- **Release:** port back up / scheduling resumes → whole backlog drains. Whole-queue, not
  per-packet.
- **Granularity:** per-port. **Latency:** link-event-driven (uncontrolled). **Safety:** medium —
  a downed port that holds then drops can back up shared buffers. **Isolate one flow:** no.
  **External traffic:** a physical link event is not a bounded data-plane packet. **Low-rate
  testable:** the hold-vs-drop transition still depends on filling buffers.
- **Verdict:** effectively M10 triggered by a link event; hold is transient (fill-then-drop) and
  the trigger is not a bounded data-plane packet.

## Mechanism 12 — Destination-port congestion → source-queue residence

- **API / doc ref:** emergent behavior of M9 + M5, no dedicated API.
- **Trigger:** a slow/blocked/paused egress destination.
- **Where the original resides / result:** `[SDE-VERIFIED]` semantics — packets to the slow
  destination fill that destination's **egress queue** (queue-resident) until its threshold, then
  **tail-drop**; if tail-drop is disabled, backlog propagates to **ingress drop**
  (`traffic_mgr_q_intf.h:340-344`). With a *lossless* PPG in the path, the fill instead **asserts
  PFC upstream** (M5) and holds in skid → DROP when skid exhausts.
- **Result type:** transient HOLD → DROP (lossy) or PFC-hold-then-DROP (lossless).
- **Release / granularity / latency:** per-queue; hold duration bounded by buffer depth ÷
  arrival rate.
- **Isolate one flow:** only via a dedicated queue/class. **External traffic:** sustained load
  needed to keep the destination congested. **Low-rate testable:** no (drain outpaces fill).
- **Verdict:** a slow internal destination holds packets **only until its buffer fills, then
  drops.** It cannot indefinitely hold a single low-rate transaction.

## Mechanism 13 — Internal loopback congestion propagation

- **API / doc ref:** composition of M1/M2 (loopback carrier) + M9/M5 (thresholds/PFC).
- **Trigger:** filling the looped path's queues.
- **Where the original resides / result:** `[REASONING]` — congestion on an internal loop
  propagates as buffer fill on the loop's egress queue → **tail-drop**, unless the loop's ingress
  side is a lossless PFC PPG, in which case it can **assert PFC** back toward whatever feeds the
  loop (M5). Whether that self-emitted PFC reaches and pauses the *intended* honoring queue on a
  single chip is the unverified silicon question from M1. Congestion state itself is real and
  packet-drivable; its *effect* is DROP unless the lossless-PFC path is engineered.
- **Result type:** DROP by default; PFC-HOLD only if the lossless-PFC loop actually closes.
- **Granularity:** per-queue / per-CoS. **Safety:** HIGH if the lossless loop closes (deadlock).
  **Isolate one flow:** no. **External traffic:** the loop must be fed (sustained). **Low-rate
  testable:** no.
- **Verdict:** the only way internal-loopback congestion becomes a *hold* (not a drop) is by
  building the M5 lossless-PFC loop — which is the high-risk, non-low-rate, class-granular
  candidate, not a clean primitive.

## Mechanism 14 — THE CRUX: congested internal destination → REMAIN resident or DROPPED?

- **Answer (from the SDE, not reasoning):** an internally congested destination holds the
  original **queue-resident only transiently — up to the queue/PPG/port buffer limit — and then
  DROPS it.** `[SDE-VERIFIED]`:
  - egress tail-drop enabled (default): drop at QAC (`traffic_mgr_q_intf.h:320-338`,
    `traffic_mgr_port_intf.h:127-145`);
  - egress tail-drop disabled: "will lead to **Ingress drops** eventually"
    (`traffic_mgr_q_intf.h:340-344`);
  - lossless path: skid holds briefly then "even lossless traffic will be **dropped**"
    (`traffic_mgr_ppg_intf.h:247-250`).
- The **only** way "remain resident" wins over "dropped" indefinitely is if the destination
  queue is **not scheduled** (M10 `scheduling_enable=false`) or **PFC-paused** (M5
  `egress_pfc_status`/received PFC). Both keep it resident with no drop *as long as the pause/
  disable holds and the buffer has not overflowed*. Both are **control-plane or HW-threshold**,
  not per-packet data-plane.
- **Net crux answer:** congestion alone = DROP. Queue-resident-hold requires a scheduling-stop
  (CP) or a PFC-pause (HW-threshold / CP), neither of which a data-plane packet can assert on a
  chosen already-enqueued packet.

## Mechanism 15 — Can congestion state be CREATED and REMOVED by bounded data-plane packets (no CP op)?

- **Create:** partially. Data-plane packets *can* build queue/PPG occupancy (that is just
  traffic), and can steer themselves into a chosen PPG/queue via `ingress_cos`/`qid`
  (`tofino1_base.p4:135,139`). So the *congestion condition* is data-plane-creatable — **but only
  as a sustained backlog**, because occupancy decays as the queue drains. A single bounded packet
  cannot hold occupancy above a PFC/drop threshold; you need continuous fill for the whole hold
  window. `[SDE-VERIFIED]` thresholds + `[SILICON, prior]` (a low-rate flow never reaches the
  threshold; below ~1200 pps the queue simply drains).
- **Remove:** yes — stop feeding it and hysteresis clears the condition (`hysteresis_cells`).
- **The catch:** what the congestion *produces* is a **DROP** (M7/M9/M14), not a hold, unless the
  lossless-PFC apparatus is pre-built (control-plane) and the pause frame physically reaches the
  honoring queue (M1/M13, unverified). And even then it holds a **whole CoS**, not one
  transaction, and needs sustained (not bounded) backlog.
- **Verdict:** congestion is data-plane creatable/removable, but (a) it needs *sustained* load
  not a *bounded* event, (b) its native result is DROP, and (c) turning it into a HOLD needs
  control-plane PFC/lossless setup. So the strict requirement ("bounded data-plane packets, no CP
  op, produces a hold") is **not met.**

## Mechanism 16 — Is any such mechanism per-port / per-priority-class / per-queue?

- `[SDE-VERIFIED]` granularity map:
  - **Per-port:** port pause (M6), port ingress/egress limits, `sched_port_disable`, port-down.
  - **Per-priority-class (CoS/iCoS 0..7):** PFC (M5), `pfc_cos` map (`tf1.tm.queue.cfg`),
    `bf_tm_port_pfc_state_set` (per icos), egress-queue PFC honor.
  - **Per-PPG:** ingress admission / lossless / skid (M7) — a PPG groups ≥1 iCoS on a port.
  - **Per-queue:** `sched_q_disable` / `egress_pfc_status` (M10), queue buffer/color/tail-drop
    (M9), queue hysteresis (M8).
- **None is per-flow or per-transaction.** The finest unit is one queue or one CoS. To "isolate a
  transaction" you would have to give that transaction a private queue/CoS — possible in
  principle, but it is queue-granular, not packet-granular.

## Mechanism 17 — Can the data plane INDIRECTLY influence it without changing TM config?

- `[SDE-VERIFIED]` The data plane's only TM-facing levers are set **at enqueue** in
  `ingress_intrinsic_metadata_for_tm_t`:
  - `ingress_cos` (`:135`) → chooses the **PPG** (and thus which PFC/admission thresholds apply);
  - `qid` (`:139`) → chooses the **egress queue**;
  - `packet_color` (via a Meter) → interacts with **color-drop** limits;
  - `deflect_on_drop` (`:131`) → requests **deflection instead of drop**.
- These let a packet *select which pre-configured threshold regime it is subject to* and *steer
  itself into a congested/lossless PPG or queue*. They **cannot** change a threshold, assert or
  clear PFC/pause, set `scheduling_enable`, or set `egress_pfc_status`. So the data plane can
  *feed* a mechanism that a control-plane setup already armed, but cannot *actuate the hold* on a
  chosen packet.
- **Verdict:** indirect influence = yes, but only "which lane I enter," never "hold this packet
  now."

---

## Ranked summary (viability × safety × low-rate-testability)

"Viability" = does it actually hold the original queue-resident (not drop)? "DP-triggerable" =
can bounded data-plane packets create/remove it with no control-plane call? Scores are relative,
1–5 (5 best).

| Rank | Mechanism | True HOLD? | DP-triggerable (no CP)? | Low-rate testable? | Safety | Per-txn isolable? | Overall |
|---|---|---|---|---|---|---|---|
| 1 | **M10 scheduling-disable / egress_pfc_status (CP)** | **Yes (clean)** | **No (control-plane)** | Yes (rate-independent) | High (4) | Queue-granular | Best *hold*, but CP — fails the DP constraint |
| 2 | **M5 PFC egress-queue honor (self-generated via loopback)** | Yes, bounded by skid | Partially — needs *sustained* backlog + prebuilt lossless/PFC setup | **No** (threshold) | **Low (1)** — deadlock risk | Per-CoS | Only DP-influenceable *hold*, but risky + not low-rate |
| 3 | M6 port pause (802.3x) | Yes, bounded | Partially (sustained) | No | Low (1) | Per-port | Coarser M5, same limits |
| 4 | M7 lossless PPG (ingress) | Brief (skid) → DROP | Partially (sustained) | No | Low–Med | Per-PPG | Holds only until skid exhausts |
| 5 | M9 / M12 egress-buffer fill (slow destination) | Transient → DROP | Yes (sustained fill) | No | Med | Per-queue | Fill-then-drop, not a controllable hold |
| 6 | M11 port-down | Transient → DROP | No (link event) | No | Med | Per-port | M10 by link event; drops on overflow |
| 7 | M13 internal-loop congestion | DROP (HOLD only if M5 loop closes) | Sustained | No | Low if lossless-loop | No | Reduces to M5 to become a hold |
| 8 | M3 recirc-port oversubscription | **No — DROP** | Yes (sustained) | No | Med | No | Measured: saturates then drops |
| 9 | M1 / M2 MAC loopback | Carrier only | n/a | Yes (as carrier) | Low–High if looped w/ PFC | No | Not a hold by itself |
| 10 | M4 adv-FC (CRE/XOFF) | No (visibility feature) | No | n/a | — | No | Not a packet-hold knob |
| — | M8 hysteresis | modifier | — | — | — | — | Governs release edge only |

---

## Crux answers (explicit)

**Q: Is there ANY supported TF1 mechanism where a downstream-internal-can't-accept condition
holds the original packet queue-resident (not dropped), created and removed by bounded
data-plane packets, testable at low rate, isolable per transaction?**

**No.** The audit resolves the family into a clean impossibility with a specific reason:

1. The *only* mechanisms that hold a packet **queue-resident without dropping it** are
   (a) **scheduling-disable** (`bf_tm_sched_q_disable` / `scheduling_enable=false`) and
   (b) **PFC/pause** (`egress_pfc_status`, or a received PFC on a honoring egress queue). Every
   other "backpressure" surface (ingress admission, egress drop, tail/color drop, recirc
   oversubscription, slow-destination fill) is a **DROP** once a threshold is crossed
   (`[SDE-VERIFIED]`, M7/M9/M14).
2. Hold (a) is **control-plane only** — there is no data-plane field that sets `scheduling_enable`
   or `egress_pfc_status` (`[SDE-VERIFIED]` arch-metadata review; the DP has `ingress_cos`, `qid`,
   `packet_color`, `deflect_on_drop` and nothing else TM-facing).
3. Hold (b) is **threshold-driven or control-plane**. To self-drive it from the data plane you
   must (i) pre-arm a lossless/PFC apparatus in the control plane, (ii) sustain a backlog above a
   buffer threshold for the *entire* hold window (not a bounded one-shot event), (iii) rely on a
   loopback closing the pause path on one chip (unverified silicon, M1/M13), and (iv) accept that
   it pauses a **whole CoS**, not one transaction. It is **not low-rate testable** (thresholds
   are tens–hundreds of cells; a ~5 Hz DNP3 flow never reaches them — consistent with the
   measured ~1200 pps TM engagement floor), and it carries a **HIGH PFC-deadlock/storm risk** on
   a shared switch.

So the backpressure family fails on the same wall as the earlier strict-priority and
queue-resident-release results (memory `tofino1-strict-priority-not-absolute-recirc`,
`tofino-queue-resident-release-infeasible`): a data-plane event cannot make TM hold a chosen,
already-enqueued packet resident on demand. Backpressure adds nothing that strict priority did
not — its only *true* hold (PFC) is coarse, threshold/CP-gated, not low-rate, and unsafe to
self-loop.

**Q: Single most promising mechanism + smallest experiment.**

Most promising *in principle* (the only one that is both a genuine queue-resident hold **and**
even partially data-plane-influenceable): **M5 — a PFC-paused egress queue, with the pause
self-generated internally via a lossless PPG on a looped port.** It is the honest "steel-man" of
the whole family. I rank it low overall only because of its safety and low-rate failures, not
because it isn't a hold.

**Smallest experiment to confirm/refute it** (HW, gated on explicit authorization — do **not**
run against the shared microbench; needs a controlled 2-port setup and is a config change):

1. Cable a hairpin: egress port **P** ↔ ingress port **R** (external DAC), or use `BF_LPBK_*` on
   one port. Both on a spare pipe, microbench pipe untouched.
2. Control-plane arm (one-time): on **R**, allocate a PPG, `lossless_treatment_enable`, set a
   **low** headroom/skid + `pfc_limit_cells` (tens of cells) via `tf1.tm.ppg.cfg` /
   `tf1.tm.pool.app_pfc`; set `tf1.tm.port.flowcontrol` `mode_tx=PFC` on R and `mode_rx=PFC` on
   P; map P's **target egress queue** to the CoS via `tf1.tm.queue.cfg.pfc_cos` so it honors the
   received pause.
3. Park one **test packet** in P's target queue (route a single DNP3-sized frame to it).
4. Inject a **bounded burst** into R (enough to cross the low headroom threshold), then stop.
5. **Read-only** observation (no CP writes in the measurement loop):
   `tf1.tm.counter.queue` `usage_cells`/`watermark_cells` on P's queue (does the test packet stay
   resident, 0 dequeue, while pause is up?), `tf1.tm.counter.ppg` on R, and port PFC/pause
   counters. Then confirm the packet **dequeues exactly when the burst stops and PFC clears**
   (hysteresis).
- **Predicted outcome (`[REASONING]`, and the reason to expect refutation):** the hold works
  *only while the burst sustains the threshold* — i.e., it is a sustained-backlog pace, not a
  bounded-event hold, and the minimum burst rate to cross the threshold will be far above DNP3
  cadence. That would **refute** low-rate / bounded-event viability while **confirming** PFC is a
  real (but unusable-for-us) hold. A cheaper, zero-risk refutation is already in hand from the
  architecture: holds (a)/(b) have no data-plane actuation lever, so the family is refuted
  without any HW run.

---

## Change-control confirmation

I changed **nothing** on the switch. Actions taken this session were read-only: `find` / `ls` /
`grep` over the SDE tree, `scp` copies **from** the switch to a local scratchpad, `python3` run
on the **local** copies of the schema JSON, and a `pgrep`/`ps` check confirming the microbench
`bf_switchd` (PID 8442, `queue_microbench_abs.conf`) is still running. No bfrt/gRPC client was
attached, no bfrt table was written, `bf_switchd` was not restarted, no P4 program was loaded,
and no traffic was generated. The switch is exactly as found.

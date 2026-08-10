# Tofino-native slot-grid scheduling — feasibility of a request-synchronized fixed-transcript pattern on one Tofino-1

**Role:** Tofino parser / pipeline / pktgen / TM specialist (Family 5 — same-switch implementation
techniques + resource budget).
**Mode:** architecture / feasibility, read-only. No production P4, no load, no switch contact.
**Testbed (binding):** `Master ↔ Tofino-1 ↔ Outstation`. No gateways, proxies, second switch,
tunnels, split-TCP, SmartNICs, or endpoint edits. Master and outstation are unchanged plaintext
DNP3/TCP peers. Internal Tofino mechanisms (pktgen, TM queues, multicast, mirror, recirc, loopback)
are permitted; the control plane configures at startup and reads counters, it does not pace packets
or sit in the data path.
**Objective under test:** can this one switch produce a bounded, request-synchronized public slot
pattern `P_c = [(δ_i, S_i, d_i)]` for a public class `c` (δ = release offset, S = size, d = slot
descriptor / direction / dwell), on unchanged endpoints, with no encryption and no decoding peer,
where no pattern parameter depends on device identity or on the natural response size/timing/readiness?

Every finding is labelled **[verified fact]** (measured on this silicon or read from SDE source /
compiler output), **[inference]** (follows from verified facts), **[hypothesis]** (plausible,
unmeasured), **[falsification]** (a claim disproven by a measurement), or **[open question]**.

---

## 0. Bottom line

- **A native, protocol-valid, size-carrying slot grid is NOT realizable on TF1 under these
  constraints.** The blocker is not primarily silicon resources — it is that **every slot the real
  response does not fill has to be filled by a cover packet the unchanged master will accept without
  breaking TCP or polluting the DNP3 SOE, and no such variable-size cover packet exists.** The only
  frame the switch can emit toward the master with byte-transparent, session-safe semantics is a
  pure-ACK-shaped token of **fixed** size, which carries the timing dimension but not `S_i`, and even
  that risks tripping the master's duplicate-ACK / fast-retransmit machinery. **[inference]**, resting
  on **[verified fact]** below and to be co-signed by the DNP3-safety analysis.

- **The single biggest feasibility risk is cadence regularity (risk R13), and it is unproven.** The
  only mechanism that can clock a public periodic grid at DNP3 rates is the **pktgen periodic timer**,
  whose inter-packet-gap floor and jitter are **undocumented in the SDE** — the TM max-rate shaper is
  falsified as a low-rate metronome. The grid's regularity — the entire point of the construction — has
  never been measured. Experiment 2 (§5) specifies the measurement. **The D4 deadline-release result
  must NOT be cited as proof the periodic grid works: it is a reactive, event-anchored release, a
  different mechanism.**

- **pktgen can source protocol-valid DNP3 *bytes* continuously and indefinitely, but not live-TCP-valid
  cover on the master's real connection.** A pktgen buffer template can hold byte-exact DNP3 (D4 already
  ships one whose template is a real relay→master ACK), and a periodic app fires indefinitely. But the
  template's TCP seq/ack are frozen at author time; the moment the live connection's sequence space
  advances, that segment is stale and the master's TCP drops it or dup-ACKs. Making cover live-valid
  needs per-connection ingress seq/ack rewrite — which lands exactly on the saturated ingress tail and
  the exhausted 32-bit PHV group. **[verified fact]** + **[inference]**.

- **Resource verdict: the preserved D4 timing core + one *functional* (observer-non-strippable) size
  mechanism + the slot machinery + the *required* correctness/privacy counters does NOT fit one TF1
  ingress pipe.** The live core is already 12/12 ingress, tail stages 8–11 all at 16/16 logical table
  IDs, and the 32-bit ingress PHV group W0-15 at 512/512 bits — no room for a 32-bit seq-translation
  field or for slot-arbitration tables on the tail. An **egress-only** size axis fits at zero ingress
  cost, but the egress size axis is the *strippable* one that was falsified as a defense; the functional
  size mechanism is ingress work and does not fit. **[verified fact]** (measured audit) + **[inference]**.

- **What *does* fit and *is* proven:** a request-synchronized **release grid for the real packets
  only** — D4 already releases the real ACK/RESPONSE at `t_trigger + D` with D a public runtime
  constant, giving public δ for the slots the real packets occupy — with **no** cover fill and **no**
  size axis. That is a timing-only, real-packet-only subset of `P_c`, not the full pattern.

Deliverable file: `/home/philip/Projects/DNP3_fixed_transcript/analysis/tofino_native_scheduling.md`.

---

## 1. The governing law: the TM never manufactures a packet

**[verified fact]** On Tofino-1 the traffic manager dequeues packets that were enqueued; it does not
synthesise a packet when a queue is empty. The only data-plane→TM handle is the ingress
`ingress_intrinsic_metadata_for_tm_t` (`qid`, `ucast_egress_port`, `packet_color`, `ingress_cos`,
mcast fields), all chosen once at enqueue; egress sees the queue read-only, post-dequeue. There is no
"emit at absolute time T" primitive and no time-based calendar scheduler in the TM — scheduling is
strict-priority + DWRR + rate-shaping only. (SDE audit:
`research/queue_backpressure_release/TOFINO_INTERNAL_BACKPRESSURE_AUDIT.md`; TM release audit and the
full bfrt/C API map in project memory `tofino1-tm-queue-release-primitives`.)

**[inference]** Therefore a slot grid is a sequence of *moments*; a packet appears on the wire in slot
`i` only if some real or synthetic packet already exists and is steered to leave at `t_epoch + δ_i`.
Consequences that shape everything downstream:

1. **Every slot needs a source.** A slot with neither a real response segment nor a standing cover
   packet is **silent** — a hole in the grid. Silent slots are device-distinguishing (they reveal that
   the real response had fewer/smaller segments than the grid), so they violate the "no parameter
   depends on natural response size" requirement. Hence a *standing cover inventory* is mandatory, not
   optional.
2. **The metronome and the packet source are two separate problems.** Something has to *tick* at the
   slot cadence (the clock), and something has to *be at the head of a queue* when the tick fires (the
   inventory). TM shaping is neither; it only caps a rate.

---

## 2. Per-technique feasibility for filling the grid

Verdict labels: **supported** (native, no loopback), **needs-loopback** (works only with a recirc /
internal loopback port), **not-supported**, **must-be-priced** (works but consumes a scarce resource
that must be charged against the saturated core in §7).

| Technique | Can it fill a slot? | Verdict | Basis |
|---|---|---|---|
| **pktgen (timer periodic)** | Mints new frames from a static buffer; the clock for a public grid | **supported (clock)** / **must-be-priced (cover parse)** | 8 apps/pipe (`app_id` = 3 bits, `defense4_caseA.p4:717,876`); IPG floor unknown (§5). Generated frames re-enter ingress → must be parsed+classified = ingress MAU cost |
| **pktgen (one-shot / recirc-pattern / port-down)** | Mints new frames on an event | **supported** | Four triggers only (`tofino1-internal-packet-multiplication`); one-shot does not auto-disable |
| **TM max-rate shaper** | Caps a rate; cannot pace a sparse flow | **not-supported (as metronome)** | **[falsification]** clumps ≤~600 pps, pass-through when input<R; starves ≤200 pps (`GRIDCLOAK_TM_QUEUE_AUDIT.md`, memory `tofino1-tm-shaper-pacing-and-dp9-pgmap`, `tofino1-dp68-recirc-selfclock`) |
| **Strict-priority queues** | Give a real packet precedence over a backlogged cover queue | **needs-loopback**, and **not absolute** | **[falsification]** on the recirc/loopback port a low SP queue behind a saturated high SP ring still drains at MHz (`research/ibspg_root_cause_repair/...AUDIT.md`, memory `tofino1-strict-priority-not-absolute-recirc`). Buys the *hold*, not one-slot-at-a-time gating |
| **Round-robin / DWRR queues** | Interleave real + cover at a weight ratio | **must-be-priced** | Default `max_priority=HIGH`, `dwrr_weight=1023` gives a 50/50 split, not a deterministic per-slot choice; no per-slot control |
| **Multicast (PRE) replication** | Mint N copies of one real frame, per-copy size in egress | **needs-loopback / must-be-priced** | `$pre` N-node = N copies, K fixed at group-install; **ingress** work, lands in the saturated tail (`tofino1-internal-packet-multiplication`; audit §5.5) |
| **Mirror session (→ egress or → mcast grp)** | Clone a real frame onto another port/qid; carries its own qid | **supported (clone)** / **must-be-priced** | `$mirror.cfg` carries `$egress_port_queue`,`$mcast_grp`,`$max_pkt_len`; two bf-p4c ctor constraints; session id must be a PHV field, not a constant |
| **Recirculation / internal loopback (dp8, dp68)** | Loop a frame so it can be re-emitted later; the D4 hold substrate | **needs-loopback** | dp8 = pipe-0 loopback, dp68 = pipe-0 recirc/pktgen port (`defense4_caseA.p4:319,341`); reservoir sizing K=rate×RTT (`tofino1-recirc-reservoir-sizing`) |
| **Egress replica id / `egress_rid`** | Distinguish PRE copies in egress to size them differently | **supported (in egress)** | free discriminator on `eg_intr_md.egress_port`/rid; but only *sizes* copies that ingress already minted |
| **Fixed calendar / slot tokens** | A TM time-wheel that emits at slot times | **not-supported** | No TM calendar exists (§1). "Slot tokens" must be pktgen-timer ticks + token frames, not a TM primitive |

**[inference]** The only viable *clock* is the pktgen periodic timer. The only viable *inventory* is
pktgen-minted frames (or recirculating/mirrored real frames). Strict priority and shaping — the two
things one instinctively reaches for — are respectively non-absolute and unusable at this rate.

---

## 3. How each slot is actually filled, and the two ways it breaks

The parent's model: *a real packet wins its slot by strict priority over an always-backlogged source.*
Grounding that on this silicon:

**[falsification]** Strict priority over a backlogged cover ring does **not** give clean one-slot
gating. On the recirc/loopback port a low-priority queue behind a continuously saturated high-priority
ring still drains at 1.3–5.3 M passes/s (`tofino1-strict-priority-not-absolute-recirc`). So "real in
Q_high, cover always-backlogged in Q_low, strict priority picks the winner each slot" leaks cover
continuously rather than exactly once per slot. What *does* hold perfectly is the **release-gating
invariant**: route a frame back into the loop unless a register says release. So the correct data-plane
construction is not priority-starvation, it is: **the metronome tick releases exactly one inventory
frame per slot, and a register decides real-vs-cover for that tick** — the same gated-release pattern
D4 already uses for its held ACK/RESPONSE (`defense4_caseA.p4:1787-1808`), not a priority race.

So each slot `i` is filled by one of:

- **The real response**, if a segment is eligible at the tick (D4's `t_wire = min{τ_j ≥ t_eligible}`
  makes it eligible at a public offset — §6). Fills at most as many slots as the real response has
  segments (typically one, since the tested scope is single-segment,
  `D4_UPSTREAM_CONTRACT.md:47-48`).
- **A cover frame**, for every other slot. This is the crux.

**Break #1 — the cover must be protocol-valid on an unchanged endpoint, and no variable-size such
frame exists.** The constraint bars encrypted chaff (no decoding peer to strip it). A cover frame
emitted toward the master therefore lands in the master's real TCP + DNP3 stack:

- *Same live connection:* inserting any TCP payload byte advances the outstation→master sequence
  space; the master's ACKs then no longer match what the outstation believes it sent, and the outstation
  sees ACKs for bytes it never transmitted → the connection desynchronises. Preventing that needs the
  switch to run a **per-flow TCP seq/ack translator** (the exact "hard part" already identified for the
  size line, `dnp3-size-normalization-research`). Even with translation, any cover *payload* byte is
  DNP3 application data the master did not solicit → spurious SOE entries / application errors. There is
  no DNP3 application function that is byte-carrying yet SOE-neutral. **[inference]**
- *Pure TCP ACK (zero payload):* idempotent, does not advance the outstation's send sequence, does not
  pollute the DNP3 SOE — this is why D4's own blocker/hold template is a real relay→master pure ACK
  (`defense4_caseA.p4:199,212-221`). **But a pure ACK has a fixed ~54–66 B size** and cannot be grown
  to an arbitrary `S_i` without adding payload (which re-enters the previous bullet). And a stream of
  duplicate pure ACKs to the master presents as outstation dup-ACKs → the master's fast-retransmit
  fires → the live connection is perturbed. So pure-ACK cover yields a **fixed-size timing grid**, never
  a size-varied one, and even the timing grid has a TCP side-effect to bound. **[inference]**
- *Separate decoy connection:* the master would have to already hold an open connection to that
  endpoint and accept unsolicited DNP3 — it does not (unsolicited responses are OFF; an unexpected
  listener/port yields a RST). **[verified fact]** (project posture, DNP3 CLAUDE.md safety defaults).

**Conclusion (Break #1):** the `S_i` (size) dimension of `P_c` cannot be carried by cover on unchanged
endpoints without a decoding peer. The timing dimension (δ_i) can be carried by fixed-size pure-ACK
cover, subject to the dup-ACK side-effect. **This is a protocol-transparency wall, not a silicon wall,
and it is the dominant blocker.** It must be co-signed by the DNP3-safety analysis; from the Tofino
side the mechanism is exactly as above.

**Break #2 — cadence (R13), covered in §5.**

---

## 4. Can pktgen source protocol-valid DNP3 cover, continuously and indefinitely?

**Bytes: yes. [verified fact]** A pktgen application emits byte-identical copies of one buffer template
(≤ ~16 KB payload after the 6-byte generator header; the header is stripped at the ingress deparser).
The template can hold exact, protocol-valid DNP3 — D4's synthetic build ships a template that *is* a
real relay→master pure TCP ACK, parsed by the real, unmodified parse chain
(`defense4_caseA.p4:198-221`). Counts are zero-based, up to 65535 packets/batch
(`tofino1-internal-packet-multiplication`).

**Continuity: yes. [verified fact]** `trigger_timer_periodic(timer_nanosec)` fires indefinitely;
`trigger_timer_one_shot` fires once and does **not** auto-disable (`tofino1-pktgen-control-plane` §5).
GridCloak's shipped "Mechanism C" uses the pktgen periodic timer as its cadence clock precisely because
TM shaping could not (`tofino1-dp68-recirc-selfclock`).

**Rate/batch limits. [verified fact]/[open question]** Up to 8 apps per pipe (`app_id` is 3 bits,
`defense4_caseA.p4:717`); D4's synthetic build already consumes apps 2, 3, 4 (`:189,279,893`). Each app
has **one** buffer template → **one** cover size per app, so M distinct cover sizes need M apps/buffers
→ ≤ 8 distinct templates per pipe is a hard inventory ceiling to price. Per-batch count ≤ 65535. The
**inter-packet-gap floor and jitter are undocumented in the SDE** and unmeasured (`[open question]`,
`tofino1-internal-packet-multiplication`: "there is NO documented or code-visible minimum inter-packet
gap for TF1 pktgen … Emission time for a batch is not derivable from the tree"). That unknown is R13.

**Live-TCP validity: no, not without ingress rewrite. [inference]** The template's TCP seq/ack are
fixed at author time; only `packet_id` varies between copies and it is stripped at the ingress deparser
(`tofino1-pktgen-control-plane` §6). A pktgen frame therefore cannot carry the live connection's current
seq/ack. On the master's real connection it is a stale-seq segment (dropped or dup-ACK-inducing);
making it live-valid requires a per-connection seq/ack rewrite in ingress — the saturated-tail /
exhausted-W0-15 cost of §7. So pktgen sources protocol-valid-*looking* DNP3 cover indefinitely, but not
*session-live* cover on the unchanged master connection.

---

## 5. The cadence risk (R13) and Experiment 2

**Why R13 is the headline. [verified fact] + [open question]** The grid's regularity is the whole
point. The only candidate metronome at DNP3 slot spacing is the pktgen periodic timer (the TM shaper is
falsified, §2). Its IPG floor and jitter are undocumented. **D4's measured release tail (p5–p95 spread
0.05–0.12 ms, `D4_UPSTREAM_CONTRACT.md:130-132`) does NOT transfer** — that is a *reactive* release at
`min{τ_j ≥ t_eligible}` off a per-transaction deadline, quantised to the reservoir loop, not a
free-running absolute periodic grid. The periodic-grid jitter is unmeasured. Do not borrow the D4
number.

**Experiment 2 — periodic slot-grid jitter and inventory characterisation (silicon; specify, do not
run here).**

*Setup.* One TF1, a minimal loaded program: one pktgen periodic app on dp68 emitting a fixed-size
token template at a target period `Δ`; the tokens routed out a host-facing port (dp9/Hulk) so a
capture and the MAC-TX counter both see them. Ground-truth dequeue = the dp9 MAC-TX counter
(`$FramesTransmittedOK` / `$FramesTransmittedLength_*`), read live; host tcpdump timestamps are a
cross-check only (NIC coalescing makes them unreliable for fine cadence —
`tofino1-tm-shaper-pacing-and-dp9-pgmap`). Second app (app 2) present as a "real eligible" injector to
test real-vs-cover arbitration. All measurement on the switch counters, none in the release path.

*Sweep* `Δ` across the DNP3-relevant band (e.g. 2, 5, 10, 20, 50, 100 ms per slot) and across per-batch
sizes (1, 4, 16, 64 tokens/batch).

*Metrics (the parent's list, made concrete):*
1. **Slot jitter** — release-error distribution `τ_measured − τ_ideal` at **p50/p95/p99/p99.9**, from
   inter-departure gaps at the MAC-TX counter. The p99.9 tail is the acceptance gate (a public grid is
   only public if the tail does not leak the epoch phase).
2. **Missed / duplicated slots** — count ticks with 0 or ≥2 departures in the slot window.
3. **Queue-empty behaviour** — deliberately let the inventory run dry (stop refilling); confirm the
   slot goes **silent** (validates §1) and measure how a hole manifests at the observer.
4. **Chaff-inventory exhaustion** — run a finite batch to depletion; measure the transition from
   full-grid to silent-grid and whether a refill batch reintroduces a phase discontinuity.
5. **Burst clumping** — at batch>1, measure intra-batch IPG vs inter-batch gap (the pktgen analogue of
   the shaper's ≤600 pps clumping); establish whether batch=1 is required for grid regularity.
6. **Eligibility-to-slot latency** — inject a "real eligible" frame (app 2 / a real host frame) at a
   random phase; measure the delay from eligibility to the next grid slot it actually leaves in
   (the δ error the real packet inherits).
7. **Overlapping epochs** — start a second request-epoch before the first grid completes; measure
   whether the two grids interleave cleanly or the metronome phase collides.
8. **Sustained operation** — hours-long run; check for period drift / long-timescale jitter growth.
9. **Behaviour under competing traffic** — offer background load on the same pipe/port group; measure
   whether the grid's p99.9 jitter degrades (shared TM scheduler contention).

*Pass criteria (proposed):* p99.9 release error ≪ the smallest inter-slot spacing used, zero missed
slots at batch=1, silent-slot behaviour exactly as §1 predicts, and no phase discontinuity across a
refill. **Until Experiment 2 passes, the periodic slot grid is unproven regardless of resource fit.**

---

## 6. D4 as an eligibility engine only (no modification to the frozen implementation)

**What D4 exposes. [verified fact]** `D4_UPSTREAM_CONTRACT.md:104-138`: the frozen core recognises the
DNP3 transaction, computes two request-anchored deadlines `T_A = t_A + D_A` and `T_RESP = T_A + D_R`
with `D_A, D_R, budget` as **runtime parameters** (`defense4_caseA.p4:86-88`), holds the real ACK and
RESPONSE queue-resident (qid6/qid4) behind a K=64 blocker reservoir (qid7/qid5), and releases each at
`t_wire = min{τ_i : τ_i ≥ t_eligible}` — never early, with a small bounded positive tail (reservoir loop
K/rate).

**Can it feed a public slot scheduler unmodified?**

- **The real packets' slots: yes, and it already does. [inference]** Because the deadline is anchored to
  the READ (the request) and `D_A/D_R` are class constants set by the control plane at startup, the real
  ACK/RESPONSE are released at **public, request-synchronized offsets** that do **not** depend on the
  device's natural response timing (that is exactly the CLRT-normalization D4 proves,
  `D4_UPSTREAM_CONTRACT.md:19-23,63-64`). So D4 already supplies the δ for the slots the real packets
  occupy, unmodified.
- **The empty (cover) slots and the size axis: no. [inference]** D4 has no cover generator, no
  slot-index table, and no sizing table; its pktgen use is the K=64 blocker reservoir (internal 0x88C1
  tokens that are **never emitted**, `defense4_caseA.p4:712-713`), not a master-facing cover source. A
  full `P_c` grid (cover fill + `S_i`) is a **superset program**, not "D4 used as a library." Building
  that superset *is* modifying/extending the frozen implementation, which the constraint forbids for the
  frozen artifact.
- **Clean interface that respects the freeze. [inference]** The reusable contract is exactly
  `t_wire = min{τ_i ≥ t_eligible}` with `D` a public runtime constant: a downstream scheduler treats D4
  as an **eligibility/release-timing oracle for the real packets** and sets `D_A/D_R` to place them on
  public grid slots. It may **not** assume D4 fills cover slots, normalizes size, or generates the grid
  ticks. Those are new mechanisms in a new build.

**Net:** D4-unmodified gives you a request-synchronized *release grid for the real packets only*. It is
a genuine, proven subset of `P_c` (timing-only, real-only). It is not the cover-filled, size-carrying
public transcript.

---

## 7. Experiment 3 — resource budget (specify, do not run the production build)

**The starting point is a full pipe. [verified fact]** (`research/size_timing_coresidency/reports/
p4-resource-audit.md`, re-derived offline on bf-p4c 9.13.1): the live `defense4_caseA.p4` is **12/12
ingress stages, 0/12 egress, critical path 10, 107 logical tables**; **tail stages 8–11 all at 16/16
logical table IDs**; ingress PHV **B0-15 16/16 containers** and **W0-15 16/16 containers, 512/512 bits**
(both 32-bit and one 8-bit ingress group exhausted); **12 stateful (Meter) ALUs, 9 stats ALUs**;
tagalong 4/8 collections; ingress parser 19 states / 103 of 256 TCAM rows. H0-15 (16-bit) has the only
slack: 13/16 containers, 176/256 bits (≈3 containers / 80 bits free).

**What Experiment 3 must compile (all real, no inert stand-ins).** A single build carrying:
1. **The preserved D4 semantic core** — classification, EXP_ACK/seq SALUs, `reg_tag` generation,
   `tbl_resp_authorise`, the two deadline registers, release decision, fail-open (the 9-deep safety
   chain, audit §2.2). Non-negotiable; this is what makes the timing request-synchronized and safe.
2. **One *functional* size mechanism** — one that a passive observer cannot strip. Per the falsification
   (audit §5.5, memory `size-timing-coresidency-egress`), sub-IP egress padding is strippable and does
   **not** count; a functional mechanism moves `ip.len`/`tcp.len`, which for DNP3 means either
   CROB-style in-application volume or CRC-boundary splitting — **both require per-flow TCP seq/ack
   translation, i.e. ingress 32-bit state**.
3. **The slot machinery** — a pktgen periodic cover app (control-plane/pktgen resource) **plus its
   ingress cost**: new parser states to classify the returning cover frames, a slot-index → (size, qid,
   real-vs-cover) table, and the gated-release logic of §3.
4. **The required counters** — correctness counters (hold/release/bypass buckets — the D4 privacy-
   failure `RESP_BYPASS`/`RELEASE_FAILOPEN` accounting, `D4_UPSTREAM_CONTRACT.md:134-138`) **and**
   slot-grid counters (missed/duplicated/silent slots, cover-exhaustion). Stats-ALU consumers. An inert
   table, unused metadata, a trailer-padding hook, or an idealized egress normalizer **does not count**.

**Budget in real compiler categories, and where each lands.**

| Addition | Real category | Lands on | Fit |
|---|---|---|---|
| Preserved D4 core | 12 ingress stages, tail 8–11 @16/16 LTID, 12 SALU / 9 stats ALU | the whole ingress pipe | already full |
| Functional size = per-flow seq/ack translate | **32-bit ingress PHV** (2× seq + ack ≈ 3×32b) + SALU + tail tables | **W0-15 (512/512, exhausted)** and the **saturated tail 8–11** | **[inference] does NOT fit** — no 32-bit ingress container is free (audit §1.1) |
| Cover-frame parse + slot-index/arbitration tables | ingress parser states + ingress MAU tables (logical table IDs) | **tail 8–11 @16/16** | **[inference] does NOT fit** without freeing ≈19 LTIDs = 1 stage (audit §3.1), and the only way measured to free a stage is deleting the counters you are required to keep |
| Privacy/correctness + slot counters | **Stats ALUs** (4/stage) + one LTID each | stages with LTID room (head) | **must-be-priced**; feasible only where LTIDs and the keyed data coexist — not on the tail |
| pktgen cover apps (≤8/pipe; D4 uses 3) | pktgen application slots + buffers | control-plane / pktgen | **supported**, bounded to ≤ (8−3) distinct cover templates |
| Egress-only *strippable* size axis (reference) | 0 ingress, +2–3 egress stages, +2 stats ALU | shared LTID pool stages 0–1 | **fits** — but does not satisfy requirement 2 (strippable) |

**Escape-hatch analysis.** The measured escape hatch is "relocate a secondary stateful tier to the idle
egress pipe reading bridged keys" (audit §5.2; `gridfeint-paper3-tofino`). It works for **emit/pad**
shapes. It does **not** rescue the two ingress-bound parts here: (a) the cover-frame **parse** is
inherently ingress (the parser runs before the MAU), and (b) the **functional** size mechanism needs
per-flow seq state that must be read *and updated* in ingress. So the escape hatch relocates the wrong
things.

**Experiment 3 verdict. [inference]** **A native slot grid + one functional size mechanism + the
required real counters does NOT fit one TF1 ingress pipe alongside the preserved D4 core.** The 32-bit
PHV wall (W0-15 512/512) blocks the seq translator outright, and the 16/16-LTID tail blocks the
slot-arbitration tables; the only measured way to free a stage destroys the counters the experiment is
required to keep. The **timing-only, real-packet-only** subset (§6, no cover fill, no size axis) is the
largest construction that plausibly fits — and even it is gated on the unproven cadence (§5) and, for
any cover at all, on the protocol-transparency wall (§3).

**Whether to actually run a compile probe.** I did **not** run one. The two binding numbers are already
measured on this exact program (W0-15 = 512/512 bits, tail = 16/16 LTIDs), so a probe adds nothing but a
step toward implementing the forbidden production pipeline. A legitimately *small* probe that would
settle a still-open sub-question is: *"does one new 16-bit ingress slot-index field + one 32-entry
`slot_index → size` table compile on the live core?"* — that tests whether the H0-15 slack (≈3
containers / 80 bits) can absorb a **timing-only** slot index without a stage. It stays inside the
timing-only subset (no seq translator, no cover parser) and would confirm/deny the one favourable case.
Anything wider re-confirms an already-measured wall.

---

## 8. Consolidated verdicts and open questions

**Realizable?**
- Full `P_c = [(δ_i, S_i, d_i)]` cover-filled, size-carrying public grid: **NO** on unchanged endpoints
  without a decoding peer — **[inference]**, dominated by the protocol-transparency wall (§3, Break #1),
  independent of silicon.
- Timing-only, real-packet-only request-synchronized release grid (δ only, from D4 unmodified):
  **YES and proven** for the real ACK/RESPONSE (§6), but that is a subset, not the transcript.
- Timing grid with fixed-size pure-ACK cover: **conditionally**, gated on (a) the dup-ACK/retransmit
  side-effect on the master (DNP3-safety), and (b) the unproven cadence (§5).

**Single biggest feasibility risk:** the protocol-transparency wall on cover (§3) is the dominant
*structural* blocker; **cadence regularity R13 (§5) is the biggest *unproven* risk** for even the
fixed-size timing grid and must be settled by Experiment 2.

**pktgen sourcing protocol-valid DNP3 cover continuously:** **bytes yes, indefinitely yes, live-TCP
validity no** without ingress seq rewrite (§4).

**Resource verdict:** **does not fit** — native slot grid + functional size + required counters exceeds
the already-full ingress pipe (32-bit PHV W0-15 512/512 and tail 8–11 16/16 LTIDs; §7).

**Open questions (labelled):**
- **[open question]** pktgen periodic-timer IPG floor and jitter at DNP3 slot spacing (R13) — Experiment
  2. Undocumented in SDE.
- **[open question]** the dup-ACK/fast-retransmit side-effect on the master of a fixed-size pure-ACK
  cover stream — DNP3-safety analysis to co-sign.
- **[open question]** whether the H0-15 16-bit slack can absorb a *timing-only* slot-index field+table
  with no stage cost — the one small, in-bounds compile probe worth running (§7).
- **[open question]** overlapping-epoch metronome-phase collision when requests arrive faster than one
  grid completes (§5 metric 7).

**Not to be repeated as fact:** the D4 deadline-release jitter is a *reactive event-anchored* number and
must **not** stand in for periodic-grid jitter (§5).

---

### Artifacts cited
- `research/size_timing_coresidency/reports/p4-resource-audit.md` — live-core resource measurements
  (12/12, tail 16/16 LTID, W0-15 512/512, egress-size-axis-zero-ingress, ≈19 LTID/stage, size-axis
  falsification note §5.5).
- `defense4/timing/p4/defense4_caseA.p4` — four-queue ladder (`:328-335`), blocker reservoir/qids
  (`:296-299,712-713,1787-1808`), pktgen synthetic build + app_id width + real-ACK template
  (`:189-269,717,876,893`), PORT_L/dp8/dp68 (`:319,341`).
- `DNP3_fixed_transcript/D4_UPSTREAM_CONTRACT.md` — the `t_wire = min{τ_i ≥ t_eligible}` interface,
  runtime `D_A/D_R/budget`, tested scope, bypass accounting (§3–§6, `:104-138`).
- `research/queue_backpressure_release/TOFINO_INTERNAL_BACKPRESSURE_AUDIT.md`,
  `research/ibspg_root_cause_repair/TOFINO1_STRICT_PRIORITY_SEMANTICS_AUDIT.md`,
  `GRIDCLOAK_TM_QUEUE_AUDIT.md`, `research/case_a_read_anchored_dual_release/p4/case_a_dual_min.p4` —
  TM release / strict-priority / shaper-floor / pktgen-clock evidence.
- Project memory (silicon-measured): `tofino1-tm-queue-release-primitives`,
  `tofino1-tm-shaper-pacing-and-dp9-pgmap`, `tofino1-strict-priority-not-absolute-recirc`,
  `tofino1-internal-packet-multiplication`, `tofino1-pktgen-control-plane`,
  `tofino1-recirc-reservoir-sizing`, `tofino1-dp68-recirc-selfclock`,
  `tofino1-defense4-caseA-resource-profile`, `tofino1-internal-backpressure-audit`.

*Scope: read-only architecture/feasibility. No P4 was loaded, no switch contacted, no compile run.
Every resource figure is quoted from the pinned offline audit at commit `7c4a5a7`; every silicon
behaviour is quoted from a prior measured audit, not re-measured here.*

# GridCloak TM-Queue Audit — reuse/avoid before building the DNP3 Case-A timing queue

**Audited:** `/home/philip/Projects/GridCloak/` (read-only; nothing changed).
**Audience:** the DNP3 Case-A Ditto-inspired TM-queue timing mechanism (Defense 1 =
delay the ACK, Defense 2 = delay the response) targeting the shared Tofino-1
`decps@10.10.54.15`.
**Method:** every claim below cites `file:line` in the GridCloak tree. Where the repo
does not actually record something (e.g. a per-stage resource breakdown), I say so
rather than invent it.

> **One-line orientation.** GridCloak is a Ditto-style **SIZE-normalization + constant-rate
> cover** gateway. Its headline lesson for us is a *negative* one: the Tofino-1 TM PPS
> shaper **cannot pace traffic at DNP3 cadence** — it starves below ~1200 pps — so the
> shipped design abandoned TM shaping and used **pktgen as the clock** plus a **recirc
> hold-loop** for per-frame delay. That pktgen-clock + recirc-hold + arm/release-register
> machinery is exactly what our timing queue should lift; the entire size/pad/chaff stack
> is dead weight for a byte-preserving timing defense.

---

## 0. Three implementations exist — know which is which

The repo contains **three** distinct designs. The task brief says "reuse what's good";
the good parts are spread across them, and two of the three were *not* what shipped. Getting
this wrong will send us down an abandoned path.

| # | Design | Files | TM role | Status |
|---|--------|-------|---------|--------|
| A | **DWRR 4-queue calendar** (most Ditto-faithful) | `p4/bfrt_gridcloak_setup.py`, design doc §8 | 4 queues Q0/1/2=A, Q3=B, equal-weight DWRR, byte-fair weight correction (95/223) | **Abandoned** — never validated on HW; latent bug (§3) |
| B | **Constant-rate baseline** | `p4/gridcloak.p4`, `p4/gc_switch_setup.py` | 2 queues, `min==max` PPS shaper pinned 900/300 @ 1200 pps; recirc chaff reservoir | Works **only at ~1200 pps**; superseded |
| C | **Mechanism C (shipped)** | `p4/gridcloak_c.p4`, `p4/gc_switch_setup_c.py` | **No TM cadence shaping.** pktgen periodic timer = metronome; recirc-hold + arm/release registers | **PASS on HW** (2026-06-05/06/08) |

The reason C exists at all is that the TM shaper failed the Phase-1 decision gate
(`p4/exp_tm_floor.py`, §3). That single result is the most important thing in this repo for us.

---

## 1. What GridCloak is / does — the TM-queue architecture

**Purpose.** A SCADA-WAN traffic-obfuscation gateway connecting the Formby NDSS-2016
fingerprinting attack to the Ditto NDSS-2022 line-rate obfuscation mechanism
(`CLAUDE.md:5-8`, design doc §1-2). It normalizes an outstation's WAN-visible traffic to a
**fixed A,A,A,B calendar of two frame sizes at a constant cadence**, so size, timing,
direction and volume are all gateway-controlled (`DEMO.md:72-85`).

**Target = SIZE/volume AND timing, but the enforcement is "constant-rate cover," not
per-flow timing control.** It pads every frame to one of two sizes (A=128 B, B=384 B) and
emits one frame per slot regardless of load, filling empty slots with chaff
(`gridcloak_c.p4:89-104`, `DEMO.md:77-80`). Timing is hidden as a *side effect* of the fixed
cadence, not by delaying a specific flow to a specific deadline.

**Topology — single switch is both gateways** (`gridcloak_c.p4:6-13`, `CLAUDE.md:18-24`,
`DEMO.md:216-232`):
- `LAN_PORT = dp9` → Hulk (`10.0.2.10`), DNP3 **master**.
- `WAN_PORT = dp8` → Vision (`10.0.2.20`), **outstation + WAN observe tap**.
- `WANSEG_PORT = dp68` → internal **recirculation** port = the "WAN segment" (no cable);
  pktgen `pg_id=17` (`gc_switch_setup_c.py:40-44`).

**Queues / priorities / rates.** Depends on which design (see §0):
- **Design C (shipped):** the only TM queue actually used is `QID_PASSTHRU = qid 5` on dp68,
  and it is used **only as a churn cap** (`max_rate = 100000 PPS`), *not* for cadence
  (`gridcloak_c.p4:78`, `gc_switch_setup_c.py:44-47,158-177`). Cadence comes entirely from a
  **pktgen periodic timer app** firing one template every slot interval S
  (`gc_switch_setup_c.py:122-143`). The A,A,A,B pattern is generated in the **MAU** by a
  2-bit slot counter (`gridcloak_c.p4:322-328,401-413`), not by the scheduler.
- **Design B:** `QID_A=qid0` (190 B), `QID_B=qid3` (446 B), each pinned `min==max` PPS
  (900/300 at 1200 total, 3:1) via `tf1.tm.port.sched_shaping` + `tf1.tm.queue.sched_shaping`
  (`gc_switch_setup.py:49-53,128-159`). Chaff reservoir seeded once and looped forever.
- **Design A:** 4 DWRR queues (Q0/1/2 rotate A, Q3=B), equal weight, byte-fair-corrected
  weights `W_A=95 / W_B=223` so byte-fair DWRR yields a 3:1 *packet* ratio
  (`bfrt_gridcloak_setup.py:79-98,251-292`). Explicitly documented as a "Tofino-practical
  approximation, not a deterministic per-slot calendar" (`bfrt_gridcloak_setup.py:30-34`).

**Chaff / loopback / recirculation.**
- Design B: a fixed pool of chaff frames (N=4 per state) is seeded once by a one-shot pktgen
  burst and **re-injected on every recirc pass**, so each state queue is always backlogged and
  the TM drains it at the pinned rate (`gridcloak_c.p4:34-40` doc comment,
  `gc_switch_setup.py:17-26,161-194`). Real frames share the queue and displace chaff "in the
  rate sense."
- Design C: the pktgen **tick itself is the chaff** — each tick becomes the slot's cover
  frame unless a real frame of that state is pending, in which case the tick is dropped and the
  real "graduates" into the slot (`gridcloak_c.p4:393-418`). The recirc loop here is the
  **real-frame hold loop**, not a chaff pool (`CLAUDE.md:60-65`).

**Ingress / TM / egress split.**
- **Ingress (MAU) does almost everything:** classify size→state (range table,
  `gridcloak_c.p4:372-382`), encap/pad (`:469-493`), run the slot counter and pattern
  (`:401-413`), run the hold/release state machine (`:419-454`), steer to the recirc port or a
  host port (`:503-507`). Egress is a **pure pass-through** — empty control and deparser
  (`gridcloak_c.p4:561-577`).
- **The "Traffic Manager" in the paper's sense is realized in the parser+MAU+pktgen+recirc,
  not in the TM scheduler.** This is the single biggest structural takeaway: on Tofino-1 they
  could not get the TM block to do the timing, so timing moved into the pipeline.

**How Ditto maps to queues.** Ditto's "chaff fills every gap, real payloads ride fixed-size
slots at a fixed schedule" maps to: two size-classes (A/B) → padded frames; the A,A,A,B
calendar → a per-slot pattern; "never leak silence/bursts" → chaff in every empty slot
(design doc §7-8, §10.1). Crucially, Ditto in the paper is a **per-egress-port constant-rate
shaper over an aggregate**; GridCloak inherits that "aggregate constant cover" assumption,
which is where the low-rate mismatch with a single DNP3 flow originates (§4).

---

## 2. What was GOOD (reusable, with exact file:line)

**G1 — pktgen periodic timer as a hardware clock (the keystone reusable).**
`gc_switch_setup_c.py:122-143`. One `tf1.pktgen.app_cfg` entry, action
`trigger_timer_periodic`, `timer_nanosec = S_NS` fires one template every S. Verified cadence
**p50 = 5.000 ms / 10.000 ms exactly** on HW (`CLAUDE.md:104-106`, `DEMO.md:126-136`). Key
gotchas already solved here: `timer_nanosec` is an *action field* in the data list, not a 3rd
positional arg (`gc_switch_setup_c.py:124-125`); pktgen prepends a 6 B header that lands in the
Ethernet dst-MAC, so `pkt_len = wire - 6` and the template ethertype sits at `buf[6:8]`
(`:54-66,126-129`). **This is our release-clock primitive for both defenses.**

**G2 — recirc + pktgen enable on dp68.** `gc_switch_setup_c.py:106-111` via
`tf1.pktgen.port_cfg` (`recirculation_enable=True`, `pktgen_enable=True`). dp68 is an internal
recirc port — no cable, no DAC. This is the confirmed place to **park a held frame**.

**G3 — TM queue shaper bfrt call sequence (works as a rate CAP).**
`gc_switch_setup_c.py:163-177` and `gc_switch_setup.py:141-159`: `tf1.tm.queue.sched_shaping`
(`unit="PPS"`, `provisioning="UPPER"`, `max_rate`, `max_burst_size`) + `tf1.tm.queue.sched_cfg`
(`scheduling_enable`, `max_rate_enable`), keyed by `pg_id=17` and
`pg_queue = PG_PORT_NR*8 + qid`. **TM tables are pipe-specific → `Target(pipe_id=0)`**, while
port/pktgen/mirror tables take `pipe_id=0xffff` (`gc_switch_setup_c.py:90,163`;
`bfrt_gridcloak_setup.py:263-267` documents that wildcard returns `INVALID_ARGUMENT` on TM
queue entries). The `100000 PPS` hold-loop cap on qid 5 demonstrably tamed the recirc churn
that was crowding out pktgen ticks (`gc_switch_setup_c.py:158-162`).

**G4 — port bring-up, idempotent add-then-mod.** `gc_switch_setup_c.py:92-104`: `$PORT` table
with `$SPEED=BF_SPEED_25G`, `$FEC=BF_FEC_TYP_RS`, `$AUTO_NEGOTIATION=PM_AN_DEFAULT`,
`$LOOPBACK_MODE=BF_LPBK_NONE`, `$PORT_ENABLE=True`, wrapped `try entry_add / except entry_mod`.
Copy this verbatim.

**G5 — mirror-session config for an observe tap.** `gc_switch_setup_c.py:145-156`:
`$mirror.cfg` with `$sid=1`, `$direction=INGRESS`, `$ucast_egress_port=dp8`,
`$session_enable`, `$max_pkt_len=16384` (no truncation), plus the ingress-deparser
`Mirror().emit()` (`gridcloak_c.p4:522-527`). Reusable to clone the delayed frame to a tap for
timing measurement without perturbing the delivered flow.

**G6 — the arm/release **counter** register pattern (not a saturating flag).**
`gridcloak_c.p4:330-356`. `pendX_add` / `pendX_take` and `relX_set` / `relX_take` are 8-bit
**balanced counters**: every take produces exactly one durable token, every graduation consumes
one. The commit comment (`:345-348`) records *why*: a 1-bit flag saturated when a TCP handshake
put 3 small State-A frames in flight and stranded a held frame forever. **This is the correct
primitive for "hold N frames, release exactly N" — directly reusable for Defense-2 response
holding.** Note the Tofino constraint it encodes: a `RegisterAction` needs a *constant* index,
so per-state state is split into separate 1-entry registers rather than one register indexed by
state at runtime (`:330-336`).

**G7 — the seq hold→release→deliver state machine on the recirc loop.**
`gridcloak_c.p4:92-104,419-454`: `SEQ_ENTER` (register pending, start looping) → `SEQ_HELD`
(loop until this state's release token is set, then mirror-clone and mark graduated) →
`SEQ_GRAD` (decap and deliver). This is a working, HW-proven **"delay a real frame in the
dataplane until a clock event releases it"** template — the exact shape of our timing defense,
minus the encap/decap.

**G8 — verified HW behaviour to trust.** (`CLAUDE.md:102-120`, `DEMO.md:121-150`,
`results/gridcloak_hw_finish_2026-06-06.md`, `results/counters_2026-06-06.json`):
- Cadence **p50 exactly S**; **27/27 TCP connects, 0 retransmissions**; WAN sizes strictly
  **{128, 384} B**.
- DNP3 application RTT within the analytical `≤4S`-each-way bound (S5 p50 14.5/p95 40.9 ms;
  S10 p50 29.7/p95 79.6 ms — `CLAUDE.md:169-171`).
- `ctr_chaff` = 189.2 fps vs 200 expected at S=5 ms (~5% shortfall from ticks displaced by
  reals + snapshot windowing — `results/…finish…md:35-38`).
- Real frames graduate end-to-end: `ctr_decap` exactly matched real-frame count, no frames
  stranded in the hold loop at window close (`…finish…md:44-47`).

**G9 — resource fit: compiles and fits Tofino-1.** `plan/gridcloak_plan.md:254-260`: a fresh
`bf-p4c --arch tna --target tofino` of the pipeline built with **0 errors, 3 benign warnings**
and a full artifact (fits Tofino-1), verified 2026-06-04. **Caveat (honest gap):** the repo
does **not** record a per-stage / SRAM / TCAM / PHV breakdown anywhere I could find (grepped
`plan/`, `results/`, `SUMMARY.md`, the P4). "Fits Tofino-1" is the only resource claim on
record. The design C P4 is ~592 lines and its heaviest parser cost is the nibble-decode pad
ladder (§3), which we will not carry, so our timing-only pipeline should be comfortably lighter.

**Exact reusable snippets:** `gc_switch_setup_c.py` functions/blocks — `main()` port loop
(`:92-104`), pktgen port_cfg (`:106-111`), tick template builder `_tick_template` (`:54-66`),
periodic app `_set` (`:138-142`), mirror cfg (`:145-156`), hold-loop shaper cap (`:163-177`).

---

## 3. What was BAD (avoid — with evidence)

**B1 — THE central finding: the Tofino-1 TM PPS shaper starves at low rate.**
`p4/exp_tm_floor.py` (the Phase-1 decision gate G1) plus `CLAUDE.md:52-58` and
`plan/gridcloak_plan.md:96-100`:
> "At ~100 pps (S=10 ms) and 200 pps (S=5 ms), the TM PPS shaper starves State B: depth pinned
> at 24 cells, 0 dequeue at both rates. Only above ~1200 pps do both queues drain exactly."
> The shaper quantized a 75 pps request to **58 pps**; port-only + equal DWRR *also* starved B
> at 100 pps.

**Consequence (their words):** "Mechanism C does **NOT** use TM shaping at all" and the
constant-rate baseline had to run at **1200 pps** to be exact (`CLAUDE.md:55-58`). This is the
reason the whole design pivoted to pktgen-as-clock. **For us this is decisive:** a single
SEL-751 poll/response flow is ~5 Hz. We must **not** try to pace a lone DNP3 frame with the TM
PPS shaper at DNP3 cadence — that is precisely the documented failure regime. (See §4.)

**B2 — constant-rate chaff cover is expensive and never idle-quiet.** Design B loops chaff at
~1200 fps forever; even Design C emits one cover frame every slot whether or not there is real
traffic, giving **307 kbps (S5) / 154 kbps (S10) of constant cover** (`CLAUDE.md:108-109`,
design doc §9.4). The reservoir "only clears on reload" and re-running the seed script **adds
more chaff to the loop** (not idempotent for the seed — `gc_switch_setup.py:24-26`). A pure
timing defense should carry **no cover traffic at all**, so this whole cost disappears if we
don't copy it.

**B3 — recirc-hold at line rate crowds out pktgen injection (doubled-slot gap).**
`gc_switch_setup_c.py:44-47,158-162`: a held real looping the recirc at line rate caused a rare
doubled-slot gap in the calendar; the fix was the `100000 PPS` cap on the hold-loop queue.
Lesson: **a self-clocked recirc loop and a pktgen clock contend for the same pipe** — budget
the hold-loop rate explicitly (this ties to our own recirc self-clock notes).

**B4 — counter double-count.** `ctr_encap` increments twice per real frame (host-port entry +
first recirc pass), so "real frames = Δ(ctr_encap)/2" (`results/…finish…md:42-43`,
`gridcloak_c.p4:428,493`). A telemetry-hygiene trap: count must-happen events at a **single**
site. (This mirrors my standing Tofino counter-read lesson.)

**B5 — the positional A,A,A,B conformity metric is a measurement trap.**
`CLAUDE.md:116-120`: the strict positional metric (`sizes[i]==pattern[i%4]`) is hypersensitive
to a single tcpdump drop — one drop flips the phase and it reads ~52-64% on any drop-affected
capture. The robust signal is the **A:B count ratio (~3.0)** + run-length histogram. If we
measure release-slot conformity, use a drop-robust metric, not positional equality.

**B6 — `gc_eval.py` is stale/misleading.** `CLAUDE.md:125-126`: it crashes
`KeyError: sender_ctr` and prints wrong wire sizes (A=190/B=446); the **pcap-based `demo.sh`
summary is authoritative**. Do not resurrect `gc_eval.py` as an evaluation harness.

**B7 — abandoned DWRR path has a latent bug and was never HW-validated.**
`bfrt_gridcloak_setup.py:299-308`: `_print_tm_manual_steps()` references an **undefined**
`DWRR_WEIGHT` (the real names are `DWRR_WEIGHT_A/_B`) — it would `NameError` if the TM config
ever hit its except branch. The DWRR 4-queue calendar (Design A) is documented as an
*approximation* (`:30-34`) and there is no HW result for it. **Do not adopt DWRR byte-fair
weighting** as a timing mechanism.

**B8 — size inconsistency across programs.** Design B uses `WIRE_A=190 / WIRE_B=446`
(`gc_switch_setup.py:56`); Design C uses the doc-exact `128 / 384` (`gc_switch_setup_c.py:42`,
`gridcloak_c.p4:89`), yet several **comments in the C setup script still say 190/446**
(`gc_switch_setup_c.py:8,56,126-129`). Stale comments like this cost debugging time — if we
fork any of this, purge the mismatched numbers.

**B9 — stale compiled artifact committed.** `p4/gridcloak.tofino` predates a size retarget and
must be recompiled before any reload (`CLAUDE.md:78-84`). Never trust the committed `.tofino`.

**B10 — the pad ladder / nibble-decode decap parser is heavy and fiddly.**
`gridcloak_c.p4:27-32,150-162,252-299`: an 8-header power-of-2 pad ladder plus a 32-state
nibble-decode parser exists *only* because Tofino-1's parser match-register budget could not
hold a per-bit pad decode (`:29-32`). It is clever but it is the heaviest part of the program
and it exists purely to serve **size** normalization. For a byte-preserving timing defense it is
**pure dead weight** — dropping it removes the program's biggest parser/PHV cost.

---

## 4. What TRANSFERS to our DNP3 Case-A **timing** queue vs what does NOT

Our problem is *different in kind* from GridCloak's: **one low-rate SEL-751 request/response
flow, byte-preserving, ACK-before-response ordering, fail-open**, delaying a *specific* frame to
a target release slot — not normalizing an aggregate to two sizes at constant cover.

### Transfers (lift these)
- **pktgen periodic timer as the release clock** (G1). This is our metronome for both defenses —
  and, critically, it is the design's answer to B1: *don't pace with the shaper, clock with
  pktgen.*
- **recirc dp68 as the hold buffer** (G2) + **seq hold→release→deliver state machine** (G7):
  the shape of "park a frame in the dataplane until a clock event releases it" is exactly
  Defense-2 (delay the response) and Defense-1 (delay the ACK).
- **arm/release balanced-counter registers** (G6): reuse directly for "hold this frame, release
  it when its deadline/slot fires," with the saturating-flag bug already burned in.
- **The full bfrt call inventory** (G3, G4, G5): port bring-up, pktgen `port_cfg`/`app_cfg`,
  `$mirror.cfg`, `tf1.tm.queue.sched_*` with the `pipe_id=0` vs `0xffff` distinction and the
  `pg_queue = pg_port_nr*8 + qid` mapping. This is the single most valuable liftable asset —
  it's the "how do I talk to this switch" knowledge, pre-debugged.
- **The TM queue shaper as a coarse rate *cap* only** (G3/B3): fine to bound recirc-hold churn;
  not fine as the timing source.
- **Measurement discipline:** pcap cadence percentiles as ground truth, the A:B-ratio
  robustness lesson (B5), counter-at-single-site (B4), and "pcap beats stale eval script" (B6).
- **Ditto's conceptual "release on the calendar slot" = our Defense-2 "release the response at
  the target slot."** The *idea* ports; the mechanism (global A,A,A,B) does not (below).

### Does NOT transfer / unnecessary (do not copy)
- **The entire size-normalization stack**: pad ladder `pad1..pad256`, nibble-decode decap
  parser, `classify_state` range table, the `gc_obf` encap header
  (`gridcloak_c.p4:116-162,252-299,358-382,469-493`). We are **byte-preserving**; all of this is
  dead weight and the program's heaviest cost (B10).
- **Constant-rate chaff cover / the chaff reservoir** (B2). A pure timing defense holds a single
  real frame and forwards it unchanged; it does not manufacture cover. No chaff, no reservoir,
  no seed idempotency trap.
- **The fixed 2-size A,A,A,B calendar** and its slot counter (`gridcloak_c.p4:322-328`). We
  release on a **per-flow deadline / CLRT target**, not a global size calendar.
- **DWRR byte-fair weighting** (Design A, B7) — irrelevant to per-flow timing and buggy/unproven.
- **ENCAP/DECAP round-trip and the observe-tap-as-slot-frame** cloning of an *obfuscated* copy
  (`gridcloak_c.p4:435-437`) — we forward the original bytes; a tap clone is only for
  measurement, not part of the delivery path.

### Suitability caveats we must respect (these are where GridCloak's assumptions break for us)
- **Low-rate regime (B1) is our normal, not an edge case.** GridCloak only worked because it ran
  a high-rate aggregate (≥1200 pps of chaff+real). Our flow is ~5 Hz. Any design that relies on
  a queue being *continuously backlogged* to drain correctly will misbehave for a lone sparse
  frame. Whether a burst-1 `max_rate` shaper paces a single sparse frame at all is **still
  unverified** (my own `dp68-recirc-selfclock` note flags this) — GridCloak never tested it
  because it always had backlog. **We must probe-confirm single-frame pacing before relying on
  it.**
- **Ordering + byte-preservation are new constraints.** GridCloak is deliberately
  *event-agnostic* — it does not distinguish poll/ACK/response (design doc §10.3). Our Defense-1
  vs Defense-2 split *requires* telling the pure ACK from the response and enforcing
  ACK-before-response. That logic is **net-new**; nothing in GridCloak does it.
- **Fail-open** is not a GridCloak concept (chaff always fills). Our defense must forward
  unchanged if the hold logic can't fire. Net-new.

---

## 5. Concrete reusable artifacts (lift list)

| Artifact | Location | Use for |
|---|---|---|
| pktgen periodic timer app (metronome) | `gc_switch_setup_c.py:122-143` (`_tick_template` `:54-66`, `_set` `:138-142`) | Defense-1/2 release clock |
| recirc + pktgen enable on dp68 | `gc_switch_setup_c.py:106-111` (`tf1.pktgen.port_cfg`) | Hold-buffer bring-up |
| Port bring-up (25G/RS-FEC/AN, add-then-mod) | `gc_switch_setup_c.py:92-104` | dp8/dp9 host ports |
| TM queue shaper cfg (cap only) + `pipe_id=0` rule | `gc_switch_setup_c.py:163-177`; `gc_switch_setup.py:141-159`; `bfrt_gridcloak_setup.py:263-267` | Bound recirc-hold churn |
| Mirror session ($mirror.cfg) + deparser emit | `gc_switch_setup_c.py:145-156`; `gridcloak_c.p4:522-527` | Timing observe tap |
| arm/release **balanced-counter** registers | `gridcloak_c.p4:330-356` | Hold-N / release-N tokens |
| seq hold→release→deliver state machine | `gridcloak_c.p4:92-104,419-454` | Per-frame dataplane delay |
| slot counter → pattern (adapt to deadline) | `gridcloak_c.p4:322-328,401-413` | Release-decision skeleton |
| Config values | `pg_id=17`, `PG_PORT_NR=0`, dp9/dp8/dp68, mirror sid=1, ethertype `0x88B5`, hold-loop `qid5 @ 100000 PPS` | Reuse **or deliberately avoid colliding** (§6) |
| bfrt gRPC connect boilerplate | `gc_switch_setup_c.py:87-90` (`localhost:50052`, `bind_pipeline_config`, `Target`) | Control-plane entrypoint |
| Reload/launch discipline | `p4/launch_switchd.sh` (LD_LIBRARY_PATH, `tail -f /dev/null \|`, `--init-mode=cold`) | Only if we ever restart bf_switchd (gated) |

**bfrt call sequence to lift for our timing bring-up** (from `gc_switch_setup_c.py`):
1. `$PORT` add/mod dp8, dp9 at 25G RS-FEC (`:92-104`).
2. `tf1.pktgen.port_cfg` on dp68: `recirculation_enable`, `pktgen_enable` (`:106-111`).
3. `tf1.pktgen.pkt_buffer` write template; `tf1.pktgen.app_cfg` action `trigger_timer_periodic`,
   `timer_nanosec = period`, `pkt_len = wire-6`, then `_set(False); _set(True)` to arm
   (`:113-143`).
4. `$mirror.cfg` sid=1 → dp8 for the measurement tap (`:145-156`).
5. `tf1.tm.queue.sched_shaping` + `sched_cfg` on the hold-loop qid, **`Target(pipe_id=0)`**,
   `max_rate` cap only (`:163-177`).

---

## 6. Coexistence + safety (shared switch)

**Important correction to the brief.** The task frames GridCloak as a "co-resident
`gc-switchd`/`gridcloak` program our new program must coexist with." On the evidence, **true
simultaneous co-residency is not how this switch works** with GridCloak loaded:

- `gridcloak.tofino/gridcloak.conf:13-27` declares **one** program `gridcloak` with
  **`pipe_scope: [0,1,2,3]`** — it claims **all four pipes**. `launch_switchd.sh` loads that
  conf `--init-mode=cold`. A second P4 program **cannot be added to the same conf/ASIC** while
  gridcloak owns every pipe.
- Therefore "coexist" in practice means a **gated swap**, not concurrency: stop/mask the
  `gc-switchd` systemd unit (`DEMO.md:200`, `CLAUDE.md:14`), then restart `bf_switchd` with our
  own conf. Our DNP3 program **replaces** gridcloak; loading it is a **destructive, approval-gated
  bf_switchd restart** (`CLAUDE.md:86` "Never restart bf_switchd without explicit approval";
  `:129`). P4Runtime `SetForwardingPipelineConfig` would still fight `gc-switchd`'s respawn — do
  not rely on a hitless swap; none exists in this tree.
- **Practical implication for us:** if we ever need our timing program and gridcloak *live at the
  same time*, gridcloak must first be recompiled to a **narrower `pipe_scope`** to free pipes —
  that is new work, and a switch-config change, i.e. **gated on explicit Philip authorization**.
  (Note: recent DNP3 on-switch work displaced `decoy_paper3`, not gridcloak — do not assume which
  program is currently loaded; check before acting.)

**Resource ownership to respect / avoid colliding with** (if any co-residency is engineered):
- Ports: **dp9, dp8, dp68** (`CLAUDE.md:20-22`).
- TM: `pg_id=17`, `PG_PORT_NR=0`, queues **qid 0/3/5** on dp68 (`gc_switch_setup*.py`).
- pktgen app id 0 on dp68; mirror **sid 1**; ethertype **0x88B5** (`gc_switch_setup_c.py:48-51`,
  `gridcloak_c.p4:55`).
- **Never restart bf_switchd, recompile, or run experiments during a session without explicit
  approval** (`CLAUDE.md:128-134`). This maps directly to the `tofino-p4` shared-chip landmines.

**Safe path for our work:** develop and compile-check our timing P4 **locally / in `/tmp`**
(no reload), stage the artifact, and only load it on the switch under an explicit, gated
bf_switchd restart with gridcloak/`gc-switchd` stopped first — exactly the discipline the DNP3
memory already records for prior on-switch bring-ups.

---

## ~6-line summary

**Biggest GOOD:** a HW-proven **pktgen-clock + recirc-hold + balanced arm/release-register**
machinery that delays a real frame in the dataplane until a clock event releases it
(`gridcloak_c.p4:419-454`, `gc_switch_setup_c.py:122-177`) — this is almost exactly our
Defense-1/2 shape, minus encap. **Biggest BAD (and most important lesson):** the Tofino-1 **TM
PPS shaper starves below ~1200 pps** (State-B queue: 0 dequeue at 100/200 pps;
`exp_tm_floor.py`, `CLAUDE.md:52-58`), so we **cannot pace a ~5 Hz DNP3 flow with the TM shaper**
— GridCloak itself abandoned TM shaping for exactly this reason. Everything size-related (pad
ladder, decap parser, chaff reservoir, A/B calendar) is dead weight for our byte-preserving
timing defense. **Top-3 reusable artifacts:** (1) the pktgen periodic timer as the release clock
(`gc_switch_setup_c.py:122-143`); (2) the recirc-hold + seq state machine + balanced
pend/rel counter registers (`gridcloak_c.p4:330-356,419-454`); (3) the full pre-debugged bfrt
call inventory — ports, pktgen, mirror, and the `pipe_id=0` TM-queue shaper cap
(`gc_switch_setup_c.py:92-177`). **Coexistence caveat:** gridcloak claims all 4 pipes
(`gridcloak.conf` `pipe_scope:[0,1,2,3]`), so "coexist" is really a **gated bf_switchd swap**,
not concurrency — approval-gated.

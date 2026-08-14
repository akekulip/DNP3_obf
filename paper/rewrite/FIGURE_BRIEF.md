# Figure Design Brief — Defense 4 (NDSS rewrite)

Source study of the five target PDFs in `paper/target/`, rendered at 110 dpi and read page
by page. This brief records (1) the most instructive figures in each target and *why the
layout works*, and (2) a concrete, label-exact spec for the seven figures the writing prompt
(`writing.md` §9) calls for. All labels below are grounded in `writing.md` §7 and project
memory; nothing technical is invented. Where a port role is not fixed by §7, it is flagged
"CONFIRM against P4/control source" rather than asserted.

**Hard rule (see §3 at the end): reproduce the explanatory *role* of these figures, never the
target artwork, layout, color, or captions.**

---

## Part 1 — What the target figures do well

### DefRec (10139606.pdf, Hui Lin et al.)
- **Fig. 3 "Design overview" (p.4)** — a two-tier block diagram with the **trusted computing
  base drawn as a dashed red box** enclosing exactly the components the defender owns (Template
  of virtual nodes, Packet hooking, Profiles, PFV, Edge Switch) and the untrusted Control
  Network (RTU/PC/RTU) *outside* it. *Why it works:* the trust boundary is a single visual
  container, so a reviewer sees at a glance what is defended and what is adversarial. This is
  the model for our TCB/deployment boundary.
- **Fig. 4 "Components of PFV" (p.4)** — flows between the Edge Switch and Real/Seed Device are
  drawn as **lettered arrows (a)–(f) with a compact legend** ("(a)(b) request/response to/from
  real devices; (c)(d) …virtual nodes; (e)(f) forwarded…"). *Why it works:* labeling each
  arrow with a letter keyed to a legend keeps a dense datapath readable without cluttering the
  drawing. Use this for any figure with more than three distinct message types.
- **Fig. 18 "Probabilistic dropping protocol" (p.16)** — a minimal linear state chain
  `0 → 1 → 2 → … → k → … → δ` with the adversary's position marked above. *Why it works:* a
  process that is really a sequence of steps is drawn as a sequence, nothing more.

### Cyber-Physical Testbed (10336809.pdf, Hui Lin et al.)
- **Fig. 1 "Hierarchical network infrastructure" (p.2)** and **Fig. 4 "Cyber-physical testbed"
  (p.5)** — the *same* system is shown first as a conceptual hierarchy and later as the concrete
  evaluation rig. *Why it works:* the reader maps the abstract topology onto the physical
  testbed one-to-one because the two figures share layout and naming. Our threat figure and our
  implementation/topology figure should share port names and box positions for the same reason.

### RAINCOAT (RAINCOAT (2).pdf, Hui Lin et al.)
- **Fig. 1 "Three stages of attacks" (p.1)** — a single horizontal arrow with a **dot at each
  stage (Penetration → Preparation → Execution) and a one-line definition under each dot.**
  *Why it works:* an attack lifecycle is a timeline; the arrow *is* the argument, and the
  captions carry the meaning. Directly reusable for a SELECT→OPERATE lifecycle strip.
- **Fig. 3 "Raincoat approach" (p.4)** — a **numbered-step data-flow**: circled steps ①…⑥ across
  the top, a **vertical Time axis on the left spanning the period T**, and columns
  (SCADA | Edge Switch | Edge Switch | End Device) with request/response arrows and colored
  square tokens for per-device messages. *Why it works:* it combines *step numbering* (walk the
  mechanism) with a *time axis* (when each step happens) and *observation columns* (where each
  actor sits). This is the single best template for our native-vs-defended and BOR timelines.
- **Fig. 2 "Control network setup" (p.2)** — Control Center → WAN → Substations → Field Site
  laid out left-to-right with a **legend separating IP-based network / hardwired connection /
  edge switch** and an attacker icon at the penetration point. *Why it works:* link *type* is
  disambiguated by a legend instead of prose, and the attacker's location is explicit.

### Ditto (2022_NDSS_ditto…pdf, NDSS 2022) — the closest analog to our system
- **Fig. 1 "padding + chaff" concept (p.1)** — a **before/after strip**: `size` axis on the
  left, three panels `input → pattern → output` shown as **bar heights**, with a legend
  (real / padding / chaff) and a `t0 … t` time axis. *Why it works:* it shows the transform
  (variable shape in, fixed shape out) in one horizontal read, with color = packet class. This
  is the template for our `[49] → [28,21]` carve/segment figure.
- **Fig. 3 "ditto overview" (p.4)** — the **gold-standard one-program pipeline**: the whole
  switch datapath left-to-right (unprotected traffic → decrypt → parser → ingress pipeline →
  queue selection → **priority queues drawn as stacked FIFOs** → traffic manager with
  **round-robin scheduling** → egress pipeline → add padding → deparser → protected traffic),
  with **high/low priority queue *pairs* per state (q_i,r real / q_i,c chaff)** and a
  **recirculation/clone path along the bottom**, plus an inset panel for the offline
  pattern-computation step. *Why it works:* stage order is the reading order; queues are drawn
  as actual FIFOs so "reservoir" is literal; the recirculation loop is a visibly separate path.
  This drives both our pipeline figure and our queue-reservoir figure.
- **Fig. 4 "hierarchical queueing / loopback" (p.8)** — real+chaff → queue selection →
  priority queues → round-robin scheduling → obfuscated traffic, with the **loopback port
  explicitly drawn** as the mechanism that sends each packet through the switch twice.
  *Why it works:* it isolates *one* structural idea (the second pass) into its own small figure
  instead of overloading the overview. Model for our shared-scheduler-vs-two-domain figure.

### Formby et al. (who-control…pdf, NDSS 2016) — the fingerprinting foundation
- **Fig. 2 "Points of attack in a power substation network" (p.4)** — a hierarchical topology
  (Station / Bay / Process levels; Control Center; RTU/PLC/IEDs; field devices) with
  **numbered attack points 1/2/3 keyed to a legend** (Control-Data Attack / Control-Data+Data-
  Response / Data-Response). *Why it works:* one drawing carries *both* the topology and an
  enumerated adversary taxonomy; the numbers let the prose reference exact observation points.
- **Fig. 3 "Measurement of cross-layer response time" (p.4)** — **the template for our timing
  figures.** A sequence diagram with columns **RTU | Network Tap | IED**, a **vertical Time
  axis**, arrows for **SCADA Read, TCP ACK, SCADA Response**, and the measured interval marked
  as a **bracket labeled "IED processing time (m)"** on the right. *Why it works:* (i) the
  observation point is its own column (the Network Tap), so the reader sees *where* the
  adversary measures; (ii) the quantity of interest is a bracket between two arrivals, not a
  number floating in space; (iii) it visually states that CLRT is measured between two
  consecutive same-direction packets. This is exactly the CLRT our defense normalizes — reuse
  the *structure* (observer column + bracketed interval), not the drawing.
- **Fig. 1 "two methods augment IDS" (p.2)** — a small block diagram splitting the fingerprint
  into Data-Response (cross-layer) and Physical-Response branches. Modest; useful only as a
  compact "how the pieces relate" inset.

**Cross-cutting lessons the targets agree on:** (1) put the observation point *in the drawing*
as its own column or node (Formby Fig 3, RAINCOAT Fig 3); (2) draw the trust boundary as one
container (DefRec Fig 3); (3) a lifecycle/mechanism is a numbered strip with a time axis
(RAINCOAT Fig 1/3); (4) a transform is a before→after with color = packet class (Ditto Fig 1);
(5) the full datapath reads left-to-right with queues drawn as real FIFOs (Ditto Fig 3);
(6) isolate one hard idea into its own small figure rather than overloading the overview
(Ditto Fig 4); (7) disambiguate link/message types with a legend, not prose (RAINCOAT Fig 2,
DefRec Fig 4).

---

## Part 2 — Spec for OUR figures

Global conventions (apply to all seven):
- **Sizing:** design each to read at **3.3 in single-column**; only the pipeline (fig. g) and
  optionally the timeline (fig. b) may span **7 in double-column**. Body labels ≥ 7 pt at final
  size; axis/tick labels ≥ 6 pt; no text smaller than a footnote reference.
- **Evidence marking (one legend, reused verbatim across figures):**
  - **Measured on hardware** — solid line / solid fill / filled marker.
  - **Modeled / offline-verified** — dashed line / hatched fill.
  - **Designed but not directly observed (UNOBSERVED)** — dotted line / gray fill, plus an
    explicit "UNOBSERVED" tag at the element.
  This tri-state legend is mandatory (`writing.md` §9: "Mark measured, modeled, and unobserved
  events differently"). It is the single most important cross-figure convention.
- **Notation, fixed everywhere:** `T0` (request timestamp), `T0+A` with `A = 20 ms`,
  `T0+R` with `R = 24 ms`, `CLRT = R − A = 4 ms`; BOR release `T0+J`; master-visible
  `echo − ACK ≈ 4 ms` invariant across `J`. Size: `[49] → [28,21]`, byte 28 = existing DNP3
  CRC-block boundary. RRC = Release-Replicate-Carve; BOR = Block OPERATE, then Release; PRE =
  packet replication engine. Queues `qid7…qid2`. Ports: **dp8 = RRC queue ladder domain**,
  **dp10 = BOR queue-pair domain** (both from §7.5); **dp68 = in-switch pktgen source port**
  (pipe_local_source_port=68, project memory). **dp64 and dp9 roles: CONFIRM against the P4 /
  control source before labeling** — do not assert a role these do not have.

---

### (a) System / threat-model figure — observation point + trusted boundary
- **Type:** architecture (topology) diagram. **Templates:** Formby Fig 2 (numbered observer) +
  DefRec Fig 3 (dashed TCB container) + Ditto Fig 2 (trust boundary).
- **Must show:** the physical chain **Master ⇄ observed WAN link ⇄ Tofino switch ⇄ physical
  SEL-751 relay**, with the **passive master-facing observer drawn as its own node/tap on the
  master-side link** (Formby's Network-Tap idea). Draw the **TCB as one container** around
  {Tofino switch + loaded P4 program + control plane}; the relay is READ-only inside the
  physical testbed; the master and the observed link are outside the defender's trust for the
  observation claim.
- **Exact labels:** `Master`; `SEL-751 relay (READ-only)`; `Tofino-1 (one P4 program)`;
  `master-facing observer (passive)`; boundary tag `TCB: switch + program + control plane`.
  Mark on the observed link what the adversary sees: `TCP segments, timing, payload length,
  transaction class (READ vs SELECT)`. Add a distinct marker on the **relay-facing link**:
  `relay-facing link — UNOBSERVED (no tap)`.
- **Measured vs modeled vs unobserved:** the master-facing observer and its visible features =
  measured (solid); the relay-facing link = UNOBSERVED (dotted + tag). This single mark stops
  any reviewer from reading relay-facing delivery as captured.
- **Caption must bound:** passive observer at the master-facing link; single SEL-751; the
  relay-facing side is not tapped.

### (b) Native-vs-defended packet timeline — T0, T0+A, T0+R, R−A
- **Type:** timeline / sequence diagram (two stacked lanes: **Native** above, **Defended**
  below, same time axis). **Template:** Formby Fig 3 (observer column + bracketed interval),
  RAINCOAT Fig 3 (time axis + step order).
- **Must show:** columns `Master | observer | Tofino | SEL-751`; a horizontal time axis
  anchored at `T0` (request). **Native lane:** ACK then RESPONSE at the relay's own small
  native CLRT (label the native gap as the *measured native CLRT*, e.g. READ ≈ 1.27 ms /
  SELECT ≈ 2.11 ms — CONFIRM exact values against the final CSV before printing). **Defended
  lane:** ACK released at `T0+A` (A = 20 ms), RESPONSE released at `T0+R` (R = 24 ms), with the
  **bracket `CLRT = R − A = 4 ms`** between the two arrivals (Formby's bracket device).
- **Exact labels:** `T0`, `T0+A (A=20 ms)`, `T0+R (R=24 ms)`, bracket `CLRT = R−A = 4 ms`;
  note `defended median ≈ 4.001 ms`; annotate the documented **master-facing path/capture
  offset** where absolute A/R placement is shown (§7.1).
- **Measured vs modeled vs unobserved:** ACK/RESPONSE arrivals at the master-facing observer =
  measured (solid). If any internal release instant is shown at the Tofino column, mark it
  modeled (dashed). Do not draw a relay-facing timestamp here.
- **Caption:** contrast native CLRT spread vs the fixed 4 ms defended interval; state that
  timing is measured at the master-facing observer with TCP timestamps absent.

### (c) RRC response-shaping queue reservoirs — qid7/6/5/4 as blocker/hold pairs
- **Type:** data-flow / block diagram. **Template:** Ditto Fig 3 priority-queue block (FIFOs
  drawn literally, high/low pairs) — but our pairing is **blocker/hold**, not real/chaff.
- **Must show:** the **RRC ladder on the dp8 domain** as **strict-priority queue pairs**: draw
  `qid7…qid4` as stacked FIFOs grouped into **blocker/hold pairs** (a blocker reservoir holds
  the real ACK/response; its paired hold queue releases at the policy offset). Show the three
  RRC steps as annotations on the flow: **Release** (hold real ACK/response in the blocker
  reservoir; release ACK at `T0+A`, response at `T0+R`), **Replicate** (PRE makes two
  master-facing copies of the eligible released response), **Carve** (egress emits `[28,21]`).
- **Exact labels:** `dp8 — RRC queue ladder`; `qid7`, `qid6`, `qid5`, `qid4` with
  `blocker` / `hold` on each pair (CONFIRM which specific qid = blocker vs hold against the
  control-plane `counter_map` / queue config before finalizing the pairing); `strict priority`;
  `release ACK @ T0+A`, `release RESP @ T0+R`; `PRE ×2`; `carve → [28,21]`.
- **Measured vs modeled:** queue occupancy/release behavior is a design mechanism — draw the
  queue structure as modeled (implementation-verified, hatched header); tie only the resulting
  master-facing arrivals to measured evidence in fig. (b). Do not imply queue-internal timing
  was captured.
- **Caption:** name the three RRC steps and that the reservoirs are strict-priority; blockers
  hold, hold-queues release at absolute offsets.

### (d) 49-byte DNP3 response and [28,21] carve
- **Type:** before/after data diagram (byte-strip). **Template:** Ditto Fig 1 (input→output,
  color = class).
- **Must show:** top strip = one **49-byte** DNP3 application response as a byte bar; a marked
  tick at **byte 28 labeled "existing DNP3 CRC-block boundary"**; bottom = two segments
  **`[28]` prefix and `[21]` suffix** (28+21 = 49). State visually that **reassembly = 49
  bytes** (an arrow `28 ⊕ 21 → 49 (reassembled)`).
- **Exact labels:** `49-byte DNP3 response`; `byte 28 = DNP3 CRC-block boundary (not a TCP
  requirement)`; `segment vector [28,21]`; `reassembled length = 49 B (unchanged)`.
- **Claim bounds (critical, §7.2 / §13):** caption must say the defense **normalizes the
  observed TCP *segment vector* for the eligible class**; it **does NOT hide the total 49-byte
  reassembled length**; reconstruction is **sequence-contiguous, DNP3-block-CRC-valid,
  IP/TCP-checksum-valid**; **no claim of byte-identity to a source frame** (no paired source
  oracle). Use the final defended eligible count only after verifying it from the final size
  reconstruction/verdict files (the prompt cites 1,280; project memory cites 1,100 — resolve
  against the authoritative verdict file, do not print an unverified count).
- **Measured vs modeled:** the `[28,21]` reconstruction is measured (solid, checksum-valid);
  mark it as validated from captures.

### (e) BOR control-command SELECT→OPERATE timeline — relay-facing gap = UNOBSERVED
- **Type:** timeline / sequence diagram. **Templates:** RAINCOAT Fig 1 (stage strip) + Formby
  Fig 3 (observer column + bracket), extended with an explicit UNOBSERVED region.
- **Must show:** columns `Master | observer | Tofino | SEL-751`. Lifecycle strip
  **SELECT → OPERATE** on the time axis. On the **master-facing** (measured) side: `ACK` and
  `echo` arrivals with the **bracket `echo − ACK ≈ 4 ms`**, shown **invariant across
  J = 2, 6, 12**. On the **relay-facing** side: the intended BOR release at **`T0+J`** and the
  relay-facing delivery multiplicity drawn in the UNOBSERVED style, inside a shaded box tagged
  **"relay-facing T0+J and delivery count — UNOBSERVED (no tap)"**.
- **Exact labels:** `SELECT`, `OPERATE`; `T0+J`; `ACK`, `echo`; bracket `echo−ACK ≈ 4 ms
  (J-independent)`; `J ∈ {2,6,12}`; UNOBSERVED shaded region as above. BOR = "Block OPERATE,
  then Release".
- **Three evidence levels made visual (§7.4):** master-visible ACK/echo placement + 4 ms gap =
  **measured** (solid); BOR state machine / intended `T0+J` release = **modeled** (dashed);
  relay-facing timestamp + multiplicity = **UNOBSERVED** (dotted, tagged). Caption must state
  the master issued **one OPERATE per transaction** but **exactly-once relay delivery is not
  demonstrated**.
- **Safety note (optional inset or caption):** guarded driver permitted only CROB `{1,3}`,
  refused breaker-close index 6, all 32 relay outputs stayed OPEN — nothing was actuated.

### (f) Shared-scheduler failure vs two-domain fix
- **Type:** process / comparison diagram (two small panels side by side). **Template:** Ditto
  Fig 4 (isolate one structural idea — the scheduler path — into its own figure).
- **Must show:** **Panel A "shared strict-priority ladder (fails)":** RRC queues and BOR
  blocker/hold queues on **one** strict-priority ladder; annotate that after OPERATE the higher
  RRC queues **starve** the BOR queues, shifting BOR release toward `A` or `R`. **Panel B
  "two domains (fix)":** RRC ladder on **dp8**, BOR queue pair on **dp10**, drawn as **two
  separate internal scheduling domains in the same physical Tofino and same P4 program**.
- **Exact labels:** Panel A `shared strict-priority ladder → BOR starvation after OPERATE`;
  Panel B `dp8: RRC ladder` and `dp10: BOR pair`, footnote `both internal loopback paths, one
  Tofino, one program`.
- **Measured vs modeled:** the starvation failure and the fix are implementation facts — draw
  as modeled/implementation-verified; if the fix's effect (J-independent 4 ms gap) is the
  evidence, reference fig. (e) rather than re-plotting numbers here.
- **Caption:** explain the *hardware reason* (strict-priority coupling), not only the topology
  (§7.5); stress dp8/dp10 are internal, not extra inline devices.

### (g) One-program P4 pipeline
- **Type:** architecture / pipeline diagram, **7 in double-column**. **Template:** Ditto Fig 3
  overview (left-to-right datapath, stages = reading order, recirculation as a separate path).
- **Must show:** the datapath in stage order:
  `ingress port → parser (transaction classification: READ / SELECT / OPERATE) →
  timestamp/deadline compute (T0, A, R, J) → pktgen trigger (dp68) + blocker reservoirs →
  RRC queue ladder (dp8, qid7…qid4) → PRE replication → egress carve ([28,21]) →
  BOR queue pair (dp10) → tbl_commit → egress port`, with the **in-switch pktgen /
  recirculation loop drawn as a distinct bottom path** and the **one-outcome/one-commit**
  structure shown (`meta.outcome` computed upstream, terminal `tbl_commit` applies
  port/queue/drop/bypass/multicast). Note the **12-ingress-stage** fit as an annotation.
- **Exact labels:** `parser: READ | SELECT | OPERATE`; `compute T0, A=20, R=24, J`;
  `pktgen dp68`; `blocker reservoirs`; `RRC ladder dp8: qid7…qid4`; `PRE ×2`; `carve [28,21]`;
  `BOR pair dp10`; `meta.outcome → tbl_commit`; `12 ingress stages, one program`.
  (dp64 / dp9: label only after CONFIRMing their role in the P4/control source.)
- **Measured vs modeled:** this is a design/implementation figure — mark it modeled/
  implementation-verified throughout; it is the map from prose to code, not an evidence plot.
- **Caption:** one P4 program, one commit point; internal loopback domains dp8/dp10; stage-fit.

---

## Part 3 — Do NOT copy

Reproduce the **explanatory role** of the target figures, never their artwork or layout.
Specifically:
- Do not reuse Ditto's green/yellow bar palette, its exact pipeline box arrangement, or its
  `q_i,r / q_i,c` glyphs — our queues are **blocker/hold** on `qid7…qid4`, a different mechanism.
- Do not redraw Formby Fig 3 with the same three columns/arrow set; take only the *device*
  (observer column + bracketed interval) and rebuild it for `T0/A/R` and `echo−ACK`.
- Do not copy RAINCOAT's circled-step tokens or DefRec's lettered-arrow legend styling verbatim;
  adopt the *idea* (number the steps / key arrows to a legend) with our own notation.
- Do not copy any caption sentence, contribution-bullet phrasing, or figure title from the
  targets (`writing.md` §6.4, §9). Captions must be original, self-contained, and claim-bounded.
- Never present inferred **relay-facing** behavior as captured: the UNOBSERVED tri-state mark is
  the guardrail that keeps our figures honest where the targets did not face this ambiguity.

**Verify-before-print checklist for every figure:** exact numeric values (native CLRTs,
defended eligible count, J set) pulled from the **final verdict/CSV**, not this brief; dp64/dp9
roles and the per-qid blocker/hold assignment confirmed against the P4/control source; the
tri-state (measured / modeled / UNOBSERVED) legend present and correct.

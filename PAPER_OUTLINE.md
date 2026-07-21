# PAPER_OUTLINE.md — Working paper outline

_Expansion of the advisor's §16 skeleton (`meeting.md`) into an actionable writing plan.
Grounded only in `meeting.md`, `meeting_direction.md`, `CURRENT_STATE_AUDIT.md`,
`CASE_A_TERMINOLOGY.md`, `case_b_defense_design.md`, and `paper/dnp3_obfuscation_paper.tex`.
Living document — update as experiments land. Produced 2026-07-21._

## 0. Frame, format, and hard constraints

- **Working title (broaden the current size-only .tex title):** _In-Network Obfuscation of DNP3
  Response Size and Timing Fingerprints on a Programmable Switch._
- **Format:** IEEE double-column `conference` (IEEEtran), ~12 pages before references.
- **Two technical parts (both must appear):** **Part 1 = packet-SIZE obfuscation** (CRC-boundary
  splitting; existing `paper/dnp3_obfuscation_paper.tex` is Part-1-only today). **Part 2 = TIMING
  obfuscation** (Case A / SEL-751; Defense 1 + Defense 2; recirculation baseline + planned queue).
- **Device cases (do not rename):** **Case A = separate-ACK, SEL-751** — CURRENT SCOPE, has two
  defenses. **Case B = combined-ACK, AB1400 / ION7550** — OUT OF SCOPE, future-work framing only.
- **Case A's two defenses:** **Defense 1 = delay the ACK** (`dcrn_defense1.p4`, gap → ~0);
  **Defense 2 = delay the response** (`dcrn_defense2.p4`, gap → target G). **Never call Defense 2
  "Case B."** **CLRT** (ACK→response) is a **Case-A-only** term.
- **Exact device names only:** SEL-751, AB1400, ION7550. Never `device1/device2`.
- **Language discipline (`meeting_direction.md` §12/Phase 1):** "the evidence supports", "the
  experiment demonstrates", "remains unproven". Never "erases the fingerprint", "defeats all
  classifiers", "zero overhead", "the queue is deterministic".

### Evidence tag legend (used per section)
- **[REAL-DEVICE-CAPTURE]** — passive captures of physical devices, `Traffic Trace/` (`SEL751.pcap`
  n=299, `SEL751L.pcap` n=3999, AB1400, ION7550). No defense applied. Native distributions only.
- **[CAPTURE-REPLAY]** — two-host rig, live TCP, capture-derived replay. Part-1 OpenDNP3 size harness
  (`dnp3_split_harness/`) and Part-2 SEL-751 timing replay (`evidence/sel751_replay/`). Label all
  such numbers "SEL-751 capture-derived live-TCP replay," **never** "physical device."
- **[MEASURED-ON-TOFINO]** — recirculation on real Tofino-1 silicon / bf-p4c compile-fit.
  `evidence/continuous_campaign_PASS/`, `evidence/defense2_hardware/`, `evidence/defense1_9.13.2/`,
  `evidence/formby_eval/`. This is the **proven feasibility baseline** — do not oversell.
- **[PLANNED-UNPROVEN]** — queue/Ditto Traffic-Manager mechanism and the physical SEL-751 experiment.
  Not yet run. Every such item is an open placeholder.

### Page budget (before references)
| § | Section | Pages |
|---|---|---|
| I | Introduction | 1.0 |
| II | Background & motivation | 1.25 |
| III | Device trace analysis | 1.5 |
| IV | Threat model & goals | 0.75 |
| V | Design | 2.0 |
| VI | Implementation | 1.75 |
| VII | Evaluation | 2.25 |
| VIII | Security analysis | 0.75 |
| IX | Related work | 0.75 |
| X | Conclusion | 0.25 |
| — | figures/tables inline | (counted above) |

### Baseline number to lock everywhere (see §III, §VII notes)
- **Native SEL-751 ACK-to-response cluster = 12–13 ms** (median **12.90 ms**, n=299 / **12.18 ms**,
  n=3999), **milliseconds**, IQR ~12–14 ms, small tail to ~166 ms. **[REAL-DEVICE-CAPTURE]**
- The rig value **17.35 ms** is **SEL-751 capture-derived live-TCP replay** native (loopback/replay
  overhead ≈ +4.5 ms). Paper **baselines** must cite 12.9 ms; before/after defense figures may use
  the 17.35 ms replay value **only if labeled replay**. Reconcile explicitly in §VII notes.

---

## I. Introduction

**Purpose.** Motivate that encrypted/unencrypted DNP3 metadata still fingerprints legacy grid devices
and that a programmable switch is the right inline, device-agnostic place to obfuscate size and timing.

**Key content.**
- Passive metadata (size, segmentation, timing, ACK mode) fingerprints ICS devices even without payload
  decode; ties to grid reconnaissance risk (reuse the Ukraine-2015 recon framing from the current .tex).
- Two exposed features this paper attacks: **response size/segmentation** (Part 1) and **ACK-to-response
  timing / CLRT** (Part 2). State they are complementary.
- Legacy devices (SEL-751 relay) cannot be modified; OS/kernel ACK tricks were rejected by the advisor —
  motivate the **in-network** data-plane defense on a Tofino switch.
- Scope statement: Case A (separate-ACK, SEL-751) only; Case B combined-ACK deferred.
- Contributions (rewrite the current 4 size-only bullets into a two-part list):
  1. Trace-grounded characterization of the DNP3 size **and** CLRT fingerprint across SEL-751 /
     AB1400 / ION7550.
  2. Byte-preserving **CRC-boundary splitting** for size obfuscation (Part 1).
  3. Two Case-A **timing** defenses (Defense 1 hold-ACK, Defense 2 hold-response) with a Tofino
     recirculation feasibility implementation (Part 2).
  4. A Ditto-inspired **queue** design and a recirculation-vs-queue evaluation plan (partly unproven).

**Figures/tables.** `fig:teaser` — one-column schematic: native vs defended timeline (ACK/response) +
native vs split size row. TODO (compose from existing `pcap_before_after.png` +
`fig2_baseline_vs_split.pdf`).

**Evidence.** [REAL-DEVICE-CAPTURE] for the fingerprint claim; [MEASURED-ON-TOFINO] for "feasible in
the data plane." Keep contribution 4 hedged ([PLANNED-UNPROVEN]).

**Open placeholders.** Physical-SEL-751 result (deferred to §VII); classifier-accuracy-drop headline
number (not yet computed across devices).

---

## II. Background and motivation

**Purpose.** Give the reader the DNP3 message/ACK structure, the Formby CLRT feature, and the Tofino
constraints (Traffic Manager queues vs recirculation) needed to follow the design.

**Key content.**
- DNP3 request/response; layered framing; **292-byte link-frame ceiling**; per-16-byte-block CRCs
  (the reason byte-preserving splitting works) — condense from current .tex §II-A.
- **Pure TCP ACK vs ACK-bearing response:** define Case A (separate ACK) vs Case B (combined). State
  CLRT is defined only for the separate-ACK case.
- **Formby fingerprinting:** CLRT = cross-layer response time (ACK→response); cite precisely (read
  `who-control-your-control-system…pdf`; do not paraphrase from memory).
- **Programmable-switch constraints:** 12-stage ingress wall, PHV/SALU limits, recirculation vs
  Traffic-Manager queue shaping; note shapers are "correct on average," bursts possible (Ditto).

**Figures/tables.** `fig:dnp3_frame` — DNP3 link-frame + CRC-block layout (TODO, redraw). `tab:notation`
— CLRT / Case A / Defense 1 / Defense 2 definitions (TODO, from `CASE_A_TERMINOLOGY.md`).

**Evidence.** Citations (Formby, Ditto, IEEE 1815) + [REAL-DEVICE-CAPTURE] to assert SEL-751 emits a
separate pure ACK. Tofino limits: cite SDE docs + local compile facts (`evidence/COMPILE_FACTS.md`,
`evidence/defense1_9.13.2/table_summary.log`) [MEASURED-ON-TOFINO].

**Open placeholders.** Exact Formby CLRT definition/measurement window pending a close read of the PDF.
Queue/TM capability claims must be hedged until the microbenchmark runs [PLANNED-UNPROVEN].

---

## III. Device trace analysis

**Purpose.** Establish, from real captures, the native size and timing fingerprints that motivate both
defenses and fix the SEL-751 baseline numbers.

**Key content.**
- **Case A — SEL-751 (separate ACK + response):** native CLRT cluster **12–13 ms** (median 12.90 ms
  n=299 / 12.18 ms n=3999, IQR ~12–14 ms, tail ~166 ms). Report median, IQR, p10/p90, outliers, and
  that both captures agree (`meeting.md` §4 checklist).
- **Case B — AB1400 / ION7550 (combined ACK-bearing response):** no standalone ACK ⇒ **CLRT undefined**;
  proper measurement is request→response. Present as the reason Case B is deferred (future work), not
  as a defended target. Report their native size/segmentation (AB 37/54 B; ION 37/61 B multi-segment).
- **Native packet-size distributions:** DNP3 response size grows ~linearly with database read; large
  Class-0 poll → long, highly segmented response (Part-1 fingerprint).
- **Native timing distributions:** CLRT histogram (SEL-751) + request→response for the combined devices.

**Figures/tables.** `tab:sel751_baseline` — SEL-751 CLRT stats table (n / median / IQR / p10–p90 /
min–max / outliers), **build from** `evidence/sel751_replay/sel751_real_distribution.txt` +
`CURRENT_STATE_AUDIT.md` §3 (TODO table, numbers exist). `fig:clrt_hist` — SEL-751 native CLRT
clustering: **exists** `evidence/visualization/clustering_before_after.png` (use the "before"/native
panel). `tab:size_range` — size-vs-read-range: **exists as data** in current .tex `tab:range` (reuse).
`fig:device_sizes` — SEL-751 vs AB1400 vs ION7550 native size/segmentation (TODO).

**Evidence.** SEL-751 CLRT + all three device size/timing distributions: **[REAL-DEVICE-CAPTURE]**
(`Traffic Trace/SEL751.pcap`, `SEL751L.pcap`, AB1400, ION7550). Part-1 OpenDNP3 native segmentation
(12,204 B, 9 fragments, 49 link frames, 20 TCP segs): **[CAPTURE-REPLAY]** rig.

**Open placeholders.** Physical-SEL-751 native distribution (to confirm the replay-vs-real gap) —
[PLANNED-UNPROVEN]. Per-device n is small (n=1 profile) — state as a limitation.

---

## IV. Threat model and goals

**Purpose.** Define the passive on-path observer and the byte-preserving, device-agnostic, fail-open
inline defense contract.

**Key content.**
- **Attacker:** passive WAN/on-path observer; sees timestamps, sizes, direction, ACK mode, volume,
  encrypted metadata; cannot read payload; does not inject/modify (reuse current .tex threat model,
  extend with the ACK-mode and timing axes from `meeting_direction.md` §3).
- **Defender contract:** inline; no SEL-751/master/TCP/DNP3 modification; **preserve DNP3 bytes**;
  preserve valid TCP; **preserve ACK-before-response ordering**; **fail open** on ambiguity; minimize
  operational impact.
- **Goals stated per feature:** reduce size/segmentation discriminability (Part 1); reduce/normalize
  CLRT (Part 2, Defense 1 / Defense 2). Name residual features explicitly: request→ACK, request→
  response, ACK mode, total bytes, packet count, direction, and any defense-induced pattern.
- Explicit non-goal: not claiming all fingerprinting is defeated.

**Figures/tables.** `fig:threat` — observer vantage point (switch → master side) + protected perimeter
(TODO). `tab:goals_features` — feature × (attacked / residual) × (which defense) matrix (TODO).

**Evidence.** Conceptual — grounded in `meeting_direction.md` §3 and §I trace evidence. No new numbers.

**Open placeholders.** Adaptive-attacker definition (trained on defended data) forward-referenced to
§VIII; grouped-split protocol named there.

---

## V. Design

**Purpose.** Present the two-part design: byte-preserving CRC-boundary splitting (size) and the two
Case-A timing defenses, plus the timing-target selection question and fail-open behavior.

**Key content.**
- **Part 1 — Packet-size defense (CRC-boundary splitting).** Cut only on existing CRC block
  boundaries; `b"".join(chunks) == response`; no CRC recompute, no field/length edit; blocks-per-chunk
  knob; per-chunk delay knob; request-aware replay + CONFIRM handshake preservation. (Reuse current
  .tex §III wholesale.)
- **Part 2 — Case A timing defense.**
  - **Defense 1 (delay the ACK):** identify the matching pure TCP ACK, hold it, release it just before
    the response; CLRT gap → small hardware guard; minimize added request→response latency. Event-driven
    (release on response arrival).
  - **Defense 2 (delay the response):** forward the ACK immediately, hold the DNP3 response to an
    ACK-relative deadline `t_ack + G`; CLRT gap → target G (increase/normalize); quantify added latency.
  - **Ordering + byte invariants** apply to both; **fail-open** on FIN/RST/keepalive/dup-ACK/
    window-update/multi-fragment/ambiguity.
- **Timing-pattern selection (the open research question, `meeting.md` §10–11).** Present the candidate
  policies as design alternatives, **not** a solved choice: (1) fixed common gap — calibration only;
  (2) common bounded distribution; (3) Ditto-style repeating schedule / next-valid-slot. Justify the
  final target from native SEL-751 distribution + TCP RTO bound + latency budget + classifier
  performance, **never** "40 ms slowest → pick 60 ms."
- **Ditto-inspired queue mechanism (design, PLANNED-UNPROVEN).** Two-level priority/round-robin
  Traffic-Manager queues; how the event-driven Defense 1 maps onto periodic queue slots
  (`meeting.md` §12 — hybrid: recirc detects event, queue controls release). State it is a design, to
  be measured.
- **Fail-open behavior** as a first-class design property (grid-safety).

**Figures/tables.** `fig:split_arch` — **exists** `paper/figures/fig1_architecture.pdf` (Part 1).
`fig:defense1` — Defense 1 hold-ACK schematic: **exists** `evidence/visualization/
defense1_hold_ack_SEL.png`. `fig:defense2` — Defense 2 hold-response schematic: **exists**
`evidence/visualization/defense2_hold_response_SEL.png`. `fig:queue_design` — Ditto-inspired two-queue
slot design (TODO). `tab:timing_policies` — candidate policy comparison (security rationale / latency /
detectability / queue need / complexity / load sensitivity) (TODO, from `meeting.md` §11).

**Evidence.** Part-1 design: [CAPTURE-REPLAY] proven. Defense 1/2 design corresponds to
[MEASURED-ON-TOFINO] recirculation implementations (`dcrn_defense1.p4` / `dcrn_defense2.p4`). Queue
design + timing-target justification: **[PLANNED-UNPROVEN]**.

**Open placeholders.** Final timing target/pattern undecided; Defense-1-event-to-queue-slot mapping
unresolved; queue design not yet compiled/measured.

---

## VI. Implementation

**Purpose.** Describe the software feasibility harness and the Tofino recirculation implementation, and
scope the (not-yet-built) queue implementation and its resource budget.

**Key content.**
- **Software feasibility study.** OpenDNP3 master/outstation + request-aware split-replay server
  (`split_server.py`); live-TCP replay used to evaluate timing policies before moving into the data
  plane. Frame the advisor-approved sentence: "We first evaluated timing policies using live TCP replay
  and host-based scheduling, then moved the defense into the network data plane to avoid changing legacy
  devices or their OS" (`meeting.md` §5). Note kernel/eBPF ACK work was **dropped** by direction.
- **Tofino parsing and state.** TCP/DNP3 parse; pure-ACK qualification (exact flags + expected ACK
  number); per-transaction registers; single outstanding transaction; no cold reload between txns.
- **Recirculation implementation (PROVEN feasibility baseline).** Defense 1 recirculates the held ACK
  until response arrival; Defense 2 holds the response to `t_ack + G` via recirculation. Report the
  bf-p4c fit honestly (9/12 ingress stages, not the earlier ~7 estimate) and the qid/shaper detail.
- **Queue-based Ditto-inspired implementation (NOT built).** Present as planned; separate P4 program;
  microbenchmark-first. Do not present as done.
- **Resource constraints.** Stages, SRAM, TCAM, SALUs, parser rows, recirculation bandwidth, ports.

**Figures/tables.** `tab:resources` — Tofino resource fit for `dcrn_defense1/2.p4`: **build from**
`evidence/defense1_9.13.2/table_summary.log`, `table_dependency_summary.log`, `metrics.json`,
`evidence/COMPILE_FACTS.md` (TODO table, data exists) [MEASURED-ON-TOFINO]. `fig:recirc_flow` — ingress
detect → recirculate-hold → release flow (TODO). `fig:pipeline_split` — ingress(timing)/egress mapping
(TODO, if the two-part single-binary discussion is kept).

**Evidence.** Software harness + replay: [CAPTURE-REPLAY]. Recirculation on silicon + resource report:
[MEASURED-ON-TOFINO] (`continuous_campaign_PASS`, `defense2_hardware`, `defense1_9.13.2`). Queue
implementation: [PLANNED-UNPROVEN].

**Open placeholders.** Queue/TM P4 program does not exist yet; microbenchmark (`meeting.md` §18) not
run; on-switch resource numbers for the queue variant unknown.

---

## VII. Evaluation

**Purpose.** Quantify size distortion (Part 1), CLRT reduction/normalization (Part 2, both defenses),
transport safety, latency/overhead, and — where available — classifier separability, distinguishing
proven recirculation results from planned queue and physical-device experiments.

**Key content.**
- **Part 1 — size/segmentation (proven, rig).** Master accepts every splitting granularity; delivers
  identical measurements (byte / protocol / measurement levels); 2,407-byte response → up to 141 chunks
  (≤18 B) vs native 9 frames; sweep 1/2/4/8 blocks/chunk, 800 measurements, CONFIRM, 0 retx / 0 resets.
  (Reuse current .tex §V tables.)
- **Part 2 — timing (proven recirculation, replay).** Defense 1: CLRT gap → small guard; Defense 2:
  CLRT gap → target G. Report before/after CLRT distributions from the SEL-751 replay + on-Tofino
  recirculation campaign.
- **★ Baseline-vs-replay reconciliation (must be explicit).** State that the **native baseline is the
  real-device 12–13 ms** [REAL-DEVICE-CAPTURE]; the **17.35 ms** appearing in defense before/after
  figures is **SEL-751 capture-derived live-TCP replay** native (replay overhead ≈ +4.5 ms), never the
  physical device. Any before/after using 17.35 ms is labeled replay.
- **Added latency / overhead.** Defense 2 adds response latency (report G + drain offset honestly,
  e.g., the ~107 ms observed = 60 ms target + ~47 ms drain); do not claim zero overhead.
- **Transport safety.** Retransmissions, resets, duplicates, reordering, byte identity — per run.
- **Classifier evaluation.** CLRT separability before/after (Formby-style); grouped splits (by capture
  run/session); report AUROC / balanced accuracy / CI; use "reduced/weak/near-chance residual
  separability," never "chance" for a CI above 0.5.
- **Background-load sensitivity + queue-vs-recirc comparison (planned).** Recirc vs queue delay under
  idle/low/moderate/high load; variance, loss, reordering, internal bandwidth (`meeting.md` §9).

**Figures/tables.** `tab:size_sweep` — **exists as data** in current .tex `tab:sweep` (reuse).
`fig:size_distort` — **exists** `paper/figures/fig2_baseline_vs_split.pdf`. `fig:defense1_gap` —
**exists** `evidence/visualization/defense1_gap_before.png` / `defense1_gap_after.png` (+ `_zoom`).
`fig:defense1_hold` — **exists** `defense1_hold_before/after.png`. `fig:defense2_gap` — **exists**
`defense2_before/after.png` (+ `_zoom`). `fig:pcap_timeline` — **exists** `pcap_before_after.png`.
`fig:clrt_collapse` — **exists** `evidence/formby_eval/formby_clrt_collapse.png` (classifier CLRT
collapse). `tab:transport_safety` — retx/resets/dup/reorder/byte-identity per condition (TODO,
compose from `continuous_campaign_PASS/continuous_analysis.txt`, `defense2_hardware/defense2_analysis.txt`).
`tab:queue_vs_recirc` — **TODO/PLANNED** (mean/median/std/percentiles/worst-case/loss/reorder/resource).

**Evidence.** Size sweep + acceptance: [CAPTURE-REPLAY]. CLRT before/after + transport safety +
continuous campaign: [MEASURED-ON-TOFINO] (recirc) over [CAPTURE-REPLAY] SEL-751 replay input.
Classifier CLRT collapse: [MEASURED-ON-TOFINO] input, `evidence/formby_eval/`. Physical-SEL-751,
queue-vs-recirc, background-load: **[PLANNED-UNPROVEN]**.

**Open placeholders.** Physical-SEL-751 native + defended timing; queue microbenchmark and load sweep;
cross-device classifier accuracy-drop headline; Defense-2 latency under the eventual defensible target.

---

## VIII. Security analysis

**Purpose.** Enumerate residual channels the defenses do not close and reason about adaptive attackers
and limits, honestly.

**Key content.**
- **Residual timing channels.** Request→ACK and request→response timing survive Defense 1/2; a
  fixed-gap Defense 2 creates a **new constant fingerprint** (argue for bounded/pattern policy).
- **Request-to-ACK leakage** under Defense 1 (ACK held) — quantify or flag.
- **ACK-mode leakage.** Separate (SEL-751) vs combined (AB1400/ION7550) still separates the population;
  byte-preserving normalization is only possible toward combined (cite the `case_b_defense_design.md`
  reasoning as future work).
- **Packet-size leakage.** CRC-boundary splitting does not change **total** payload bytes; a byte-count
  observer still estimates read size. State plainly (from current .tex Discussion).
- **Adaptive attacker.** Attacker trained on defended data; detector for machine-regular timing;
  grouped-split evaluation prevents session leakage.
- **Limitations.** n=1 device profiles; replay ≠ physical; recirculation load-dependence; queue not yet
  measured; MAXPASS/fail-open events reported, not hidden.

**Figures/tables.** `tab:residuals` — feature × closed/residual × evidence status (TODO). Optionally a
residual-separability bar (reuse a `formby_eval` panel).

**Evidence.** [MEASURED-ON-TOFINO] classifier residuals where available; otherwise reasoned limits.
ACK-mode/Case-B residual is **[PLANNED-UNPROVEN]** (future work).

**Open placeholders.** Adaptive-attacker experiment on defended data; request→ACK leakage quantification;
combined-device (Case B) analysis deferred.

---

## IX. Related work

**Purpose.** Position the contribution against device fingerprinting, line-rate obfuscation, classic
padding defenses, anonymity systems, and programmable-dataplane shaping.

**Key content (required citations).**
- **Formby et al.** — physical-device fingerprinting / CLRT cross-layer response time (the attack this
  paper's Part 2 targets).
- **Ditto (NDSS 2022)** — WAN traffic obfuscation at line rate via Traffic-Manager queues/chaff; the
  design inspiration for the planned queue mechanism; note its own caveat that shaper rates are correct
  only on average (motivates our measurement).
- **BuFLO / CS-BuFLO** — constant-rate/buffered fixed-length obfuscation; contrast their fixed schedule
  and overhead with our byte-preserving, device-agnostic, fail-open constraints.
- **TARANET** — anonymity/traffic-shaping with fixed-size cells; contrast cooperative endpoints vs our
  non-cooperative inline defense.
- **Programmable-dataplane traffic shaping** — P4/Tofino shaping and timing work; position our
  DNP3-specific, byte-preserving, ordering-preserving inline defense.
- Retain the lab's ICS-recon line (RAINCOAT, DefRec) and DNP3 IDS/CPS-safety work from the current .tex
  as the "complements content-level obfuscation / not a detector" framing.

**Figures/tables.** `tab:related` — axes: cooperative? / byte-preserving? / line-rate? / device-agnostic?
/ closes-which-feature (TODO, optional).

**Evidence.** Citations only. Read primary PDFs (Ditto, Formby present in repo root) before writing;
do not invent citation details.

**Open placeholders.** Fill BuFLO/CS-BuFLO, TARANET, and a representative P4-shaping citation into the
bibliography (current .tex bib is placeholder-only).

---

## X. Conclusion

**Purpose.** Summarize the two-part, byte-preserving, inline obfuscation result and the honest boundary
between proven and planned.

**Key content.** Restate: size fingerprint distorted with byte preservation (proven, rig); Case-A CLRT
reduced (Defense 1) / normalized (Defense 2) and demonstrated feasible in the Tofino data plane via
recirculation (proven); a more defensible queue mechanism and physical-SEL-751 validation remain future
work; Case B (combined-ACK) deferred. No overselling.

**Figures/tables.** None.

**Evidence.** Recap only.

**Open placeholders.** None (mirror the true state at submission).

---

## XI. Cross-cutting writing tasks (living)
- Replace placeholder bibliography in `dnp3_obfuscation_paper.tex` with verified entries (esp. Formby,
  Ditto, BuFLO/CS-BuFLO, TARANET, IEEE 1815, OpenDNP3, Ukraine-2015).
- Broaden the canonical title/abstract from size-only to the two-part size+timing paper.
- Add `ASSUMPTIONS_AND_UNKNOWNS.md`-driven limitations paragraph.
- Every result paragraph carries: traffic source, physical vs replayed, implementation version, n,
  metric, central value, spread, safety result, limitation (`meeting_direction.md` §12).

---

## XII. `paper/` consolidation recommendation (recommendation only — do not delete)

**Files present in `/home/philip/Projects/DNP3/paper/`:**
| File | Size | Role |
|---|---|---|
| `dnp3_obfuscation_paper.tex` | 29.5 KB | **CANONICAL** — IEEE `conference` LaTeX, compiles, has `figures/`. |
| `dnp3_obfuscation_paper_desmoothed.tex` | 29.2 KB | humanizer-pass variant of the .tex. |
| `dnp3_obfuscation_paper.md` | 28.0 KB | Markdown source of the same paper. |
| `dnp3_obfuscation_paper_desmoothed.md` | 27.8 KB | humanizer-pass Markdown variant. |
| `dnp3_obfuscation_paper_idiom.md` | 28.8 KB | idiom-pass Markdown variant. |
| `HUMANIZE_NOTES.md` | 5.4 KB | notes on the humanizing passes. |
| `figures/` | — | `fig1_architecture.{pdf,svg}`, `fig2_baseline_vs_split.{pdf,svg}`, `make_figures.py`. |

**Recommendation.**
- **Keep as canonical:** `dnp3_obfuscation_paper.tex` + `figures/`. All new writing (the two-part
  expansion above) lands here. Note its current title/scope is **Part-1 (size) only** — broaden it, do
  not start a new file.
- **Archive (move to `paper/archive_variants/`, keep in git history), do not keep as live drafts:**
  `dnp3_obfuscation_paper_desmoothed.tex`, `dnp3_obfuscation_paper.md`,
  `dnp3_obfuscation_paper_desmoothed.md`, `dnp3_obfuscation_paper_idiom.md` — near-duplicates that will
  diverge from the canonical .tex and cause drift.
- **Keep for reference:** `HUMANIZE_NOTES.md` (style guidance for future passes).
- **Rationale:** one canonical LaTeX source avoids the multi-variant drift `CURRENT_STATE_AUDIT.md` §5
  already flagged. This is a recommendation; nothing is deleted here.

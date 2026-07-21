# ASSUMPTIONS_AND_UNKNOWNS.md

_Required living deliverable per `meeting_direction.md` §6 ("Maintain an ASSUMPTIONS_AND_UNKNOWNS.md
file. Every assumption must have: description; why it matters; evidence; validation method; current
status.") and §16. Seeded from `CURRENT_STATE_AUDIT.md` §7 (5 assumptions) and expanded._

**Purpose.** This file exists to *surface* uncertainty, not hide it. Every claim that could reach the
paper is tracked here with the exact measurement it rests on (or "none yet"), the experiment that would
resolve it, and an honest status. It is updated as gates close.

**Terminology (locked — `CASE_A_TERMINOLOGY.md`, `meeting_direction.md` §1).** *Case A* / *Case B* are
**device traffic cases** (SEL-751 separate-ACK vs AB1400/ION7550 combined-ACK). *Defense 1* / *Defense
2* are the two **holds under Case A** (delay-the-ACK vs delay-the-response). Defense 2 is **never** "Case
B." **CLRT** (the Formby ACK→response feature) applies **only to Case A / separate-ACK**.

**Evidence base path.** Unless noted, cited files live under
`research/tofino_dcrn_feasibility/p4/ack_delay/`. Real device captures live under `Traffic Trace/`.

**Status vocabulary.** OPEN · GATED-ON-HARDWARE · PARTIALLY-VALIDATED · VALIDATED · RESOLVED.

---

## A. Traffic-source fidelity (rig replay vs live device)

### 1. All Tofino results are single-host loopback REPLAY, not a live physical SEL-751
- **Description.** Every "on-Tofino" result to date was produced on the single-host Hulk loopback rig
  replaying captured SEL-751 timing/bytes. The live SEL-751 relay has never been wired to the DCRN
  switch. Phase 5 (physical SEL-751) is not done.
- **Why it matters.** The core claim "the switch controls SEL-751 timing" is only demonstrated on
  replayed traffic. `meeting_direction.md` §12/§13 forbids calling replay "live physical SEL-751." No
  paper result may claim device validation from replay.
- **Evidence.** `evidence/sel751_replay/RESULT.md`: "The live SEL-751 relay is NOT on the DCRN testbed
  (10.0.0.1:20000 refuses; switch has only dp8/dp9; SEL751.pcap is a June-2019 capture)." Rig hosts both
  master and outstation netns on Hulk (no Vision).
- **Validation method.** Physical SEL-751 direct connectivity + native capture (Phase 5), then Tofino
  insertion — `SEL751_DIRECT_CONNECTIVITY_REPORT.md`. Requires the relay, lab topology, and a gated
  hardware window.
- **Status.** GATED-ON-HARDWARE.

### 2. Baseline number reconciliation — real SEL-751 12.9 ms vs rig-replay 17.35 ms
- **Description.** The real device's native CLRT median is **12.90 ms** (SEL751.pcap) / 12.18 ms
  (SEL751L.pcap); the rig replay's native CLRT median is **17.35 ms**. Which number the paper uses, and
  where, is not yet fixed.
- **Why it matters.** Using the wrong number mislabels the baseline. The ~4.5 ms gap is not noise: the
  replay outstation quickacks promptly and does **not** reproduce the SEL-751's own ~4 ms kernel ACK
  delay, so rig-native CLRT reflects response latency (~17 ms) while the real device CLRT (~13 ms)
  includes that ACK delay. The paper *baseline* must cite 12.9 ms (real); before/after defense figures
  may cite 17.35 ms but must be labelled "capture-derived live-TCP replay."
- **Evidence.** `CURRENT_STATE_AUDIT.md` §3 (real: SEL751.pcap n=299 median 12.90 ms IQR [11.98,14.39];
  SEL751L.pcap n=3999 median 12.18 ms). `evidence/formby_eval/RESULT.md` caveat 3 and
  `evidence/sel751_replay/RESULT.md` fidelity caveat (rig-native 17.35 vs capture 12.90; replay omits
  ~4 ms kernel ACK delay). `evidence/native_clrt_baseline.txt` (request→ACK median 3.70 ms).
- **Validation method.** Documentation decision now (fix the convention in `PAPER_OUTLINE.md`); live-SEL-751
  capture (Phase 5) confirms the real distribution end-to-end.
- **Status.** PARTIALLY-VALIDATED (both values measured; offset cause understood; live confirmation gated).

### 3. SEL-751 capture provenance, age, and single-device generalization
- **Description.** The SEL-751 fingerprint rests on captures from one physical device, one session,
  dated June 2019 (single TCP connection). We assume it represents "the SEL-751" for the paper's timing
  distribution and for the physical device we will connect.
- **Why it matters.** Firmware, configuration, and load can shift the CLRT distribution; a 2019 single-
  session capture may not match the physical relay in the lab in 2026. The heavy tail (max 165.98 ms)
  and the p99 (35.8 ms) drive the Defense-2 target choice, so a stale/atypical tail biases policy.
- **Evidence.** `evidence/sel751_replay/RESULT.md` ("SEL751.pcap is a June-2019 capture"), 1 connection.
  `evidence/native_clrt_baseline.txt` (SEL751: connections=1, n=299, max 165.98 ms).
- **Validation method.** Physical SEL-751 capture (Phase 5); compare live distribution against the 2019
  capture; record device firmware/config settings.
- **Status.** GATED-ON-HARDWARE.

---

## B. Timing mechanism (recirculation) properties

### 4. Recirculation delay is load-dependent
- **Description.** Defense 2's measured "constant" CLRT of ~107 ms is `G_i` (60 ms nominal) plus a
  systematic recirculation-drain/path offset of ~47 ms. The offset was ~21 ms for a single transaction
  and grew under continuous load; it is not a compiled constant.
- **Why it matters.** Dr. Lin's stated reason for moving off recirculation: delay may vary with switch
  load, passes are not deterministic, and it consumes internal bandwidth (`meeting.md` §6, §9). If the
  offset drifts with background traffic, the "device-independent constant CLRT" property could weaken
  under real load — the whole justification for the queue study.
- **Evidence.** `evidence/defense2_hardware/RESULT.md`: "measured constant exceeds G_i by ~47 ms: a
  systematic recirc-drain/path offset under continuous load (single-txn offset was ~21 ms; larger under
  load)." `meeting.md` §6 (Dr. Lin's questions), §9 (Ditto shapers correct-on-average, bursts).
- **Validation method.** Recirculation delay sweep under idle/low/moderate/high background load (Phase
  8 metrics); Traffic-Manager queue microbenchmark for the comparison arm (Phase 4).
- **Status.** PARTIALLY-VALIDATED (offset measured single-txn and under continuous single-flow; full
  background-load sweep OPEN).

### 5. Fine per-transaction timing control via recirculation is masked by the drain offset
- **Description.** Defense 2's bounded-target variant (`B2_COMMON_BOUNDED`, `G_i ~ U[55,65] ms`) did
  **not** produce the expected ~[102,112] ms spread on the wire; the middle 50% collapsed to 107.0 ms
  (IQR [107,107]). The recirc-drain offset dominates and masks per-transaction `G_i` control.
- **Why it matters.** A Ditto-style *repeating timing pattern* (meeting §11 Pattern 3) needs fine per-
  packet slot control. This is direct evidence that recirculation cannot deliver it — motivating the
  queue study, but also warning that the queue's per-slot precision is itself unproven on our silicon.
- **Evidence.** `evidence/defense2_hardware/RESULT.md` "HONEST LIMITATION": bounded `G_i` distribution
  "does NOT manifest as the expected ~[102,112] ms spread ... the recirculation-drain offset (~47 ms
  under load ...) DOMINATES and masks the fine per-transaction G_i control."
- **Validation method.** Queue microbenchmark measuring residence time, jitter, and per-slot error
  (Phase 4); compare against recirculation (Phase 8).
- **Status.** PARTIALLY-VALIDATED (measured on Tofino silicon for recirc; queue alternative unmeasured).

### 6. MAX_PASS is a fail-open safety valve and must never be the normal release path
- **Description.** In both holds the normal release is event- (Defense 1) or deadline-governed (Defense
  2). `MAX_PASS` forwarding exists only to guarantee the frame is never dropped if the recirc clock
  fails to refresh. We assume every normal transaction releases before MAX_PASS.
- **Why it matters.** `meeting_direction.md` §13 forbids "treat MAXPASS as normal release." If MAX_PASS
  ever becomes the routine release, the timing property is not actually being enforced and the pass-count
  ceiling would be a hidden, uncharacterized fingerprint.
- **Evidence.** `evidence/continuous_campaign_PASS/RESULT.md`: egress evstat over 120 txns
  ACK_MAXPASS=0, RESP_MAXPASS=0 (every hold event-governed). `ACK_DELAY_DEFENSE2_DESIGN.md` §4 ("MAX_PASS
  is fail-open ONLY"); `evidence/defense2_hardware/RESULT.md` (CLRT 107 ms << MAX_PASS 65536 ticks).
- **Validation method.** Assert `release_reason == deadline`/`event` and `MAXPASS == 0` in every
  campaign; re-check under background load and on the physical device.
- **Status.** PARTIALLY-VALIDATED (held on the rig; re-verify under load and live).

### 7. Exact pure-ACK qualification on silicon (fragility + a conflicting root-cause record)
- **Description.** Defense 1's hardened build uses exact ACK matching (`(flags & 0x17)==0x10 &&
  reg_expected_ack == tcp.ack_no`, first-only) rather than the broad `armed && payload==0` of the tagged
  C3-pass baseline. Whether exact matching is robust on silicon is not fully settled: two evidence files
  give **different** root causes for the same continuous-campaign FAIL.
- **Why it matters.** If exact qualification silently rejects the real ACK on hardware, Defense 1 fails
  open (no hold) while transport looks clean — a defense failure that is easy to miss. The matching rule
  is load-bearing for both defenses.
- **Evidence — conflict, both preserved (`meeting_direction.md` §6).**
  `evidence/continuous_campaign_FAIL/FINDING.md` blames the P4: "the hardened FIX 1 exact-qualification
  rejects the pure ACK on silicon (qual==0) ... the regression is in the ADDED conditions."
  `evidence/continuous_campaign_PASS/RESULT.md` (same sha `6e1b659b`) blames the control plane: "NOT a
  P4 regression. `ackA_setup.py` crashed ... BEFORE installing the fc_allowlist -> nothing armed -> no
  hold. With the setup script fixed ... the hardened hold works" (CLRT collapsed to 0.026 ms, 120/120).
  The PASS supersedes the FAIL hypothesis, but the exact-match path is proven only through one corrected
  setup path, and the FAIL diagnosis was never independently closed by the gated reg-probe it proposed.
- **Validation method.** The gated fixed-source-port probe from `FINDING.md` (read `reg_armed` +
  `reg_expected_ack` for the flow during the readiness window, compare to `seq+22` from the pcap);
  re-run on the physical device.
- **Status.** PARTIALLY-VALIDATED (exact match passed once with a corrected control plane; root-cause
  conflict recorded, probe not yet run).

---

## C. Queue / Ditto direction (design not yet built)

### 8. Queue / Traffic-Manager timing on OUR Tofino-1 silicon is unmeasured
- **Description.** The queue-based timing mechanism does not exist yet (no queue/TM P4 program). Its
  delay, jitter, drain, and loss behavior on our switch are assumed, not measured.
- **Why it matters.** The entire next research direction (meeting §7–9) bets that queues are more
  defensible and load-stable than recirculation. If the queue is not measurably better, the direction
  changes. `meeting_direction.md` §5A: "queue timing must be measured on our hardware."
- **Evidence.** none yet (no queue P4). `CURRENT_STATE_AUDIT.md` §5: "No queue/TM microbenchmark P4
  exists yet (Phase 4, not started)."
- **Validation method.** The Traffic-Manager microbenchmark (Phase 4 / `QUEUE_MICROBENCH_PLAN.md`):
  configured-vs-actual rate, residence time, jitter, depth, loss, ordering, drain, first-packet and
  sparse-packet behavior, under idle→high background load.
- **Status.** OPEN (measurement gated on a hardware window).

### 9. Ditto's "correct on average" applies to Ditto's hardware, not automatically to ours
- **Description.** Ditto reports that switch shaping rates hold *on average* with short bursts, and that
  inaccurate queue-rate control contributed to drops at high load. We must not assume our queue inherits
  either Ditto's accuracy or its failure modes.
- **Why it matters.** `meeting_direction.md` §5A: "Do not claim that Ditto provides exact deterministic
  per-packet delay." Copying Ditto's numbers as if they were ours would be an invented hardware fact
  (§6, §13 "claim queue timing is deterministic without measurement").
- **Evidence.** `meeting.md` §9 (Ditto: shapers correct on average, bursts occur, rate inaccuracy →
  drops at high load). Source map now produced: `DITTO_QUEUE_RECONSTRUCTION.md` §5 S10/S13 quotes the
  exact passages (§IX-B p9, §IX-C p12) — "rate is only correct 'on average'", error "more error-prone
  for small packets" (and DNP3 packets are small).
- **Validation method.** Ditto source map (Phase 2) — **done**; remaining is the Phase-4
  microbenchmark on our silicon to confirm/deny the same behavior for our small-packet DNP3 regime.
- **Status.** OPEN (source-grounded; hardware measurement still pending).

### 10. Mapping event-driven Defense 1 onto a periodic Ditto-style schedule is unresolved
- **Description.** Defense 1 releases the ACK on the *event* of the response arriving; Ditto releases
  packets into *predefined queue slots*. How to reconcile an event trigger with a periodic schedule
  (while preserving ACK-before-response ordering) is the major open design question, with several
  candidate architectures and no hardware evidence favoring one.
- **Why it matters.** `meeting.md` §12 calls this "the most important technical issue." Picking a
  mapping without evidence risks a design that the Tofino cannot safely support (linking response
  arrival to ACK eligibility), or that reorders/adds unjustified latency.
- **Evidence.** `meeting.md` §12 and `meeting_direction.md` Phase 3 Q1 list the candidates (hybrid
  event+queue; queue-resident ACK with response-triggered eligibility; adjacent-slot release). No
  measurement yet.
- **Validation method.** `CASE_A_QUEUE_DESIGN.md` (Phase 3) enumerating alternatives with hardware/doc
  support; Phase-4 microbenchmark to test feasibility of response-triggered slot eligibility.
- **Status.** OPEN.

---

## D. Timing-policy justification

### 11. The Defense-2 60 ms target is a provisional calibration value, not a defensible policy
- **Description.** `G_i = 60 ms` was chosen because the slowest observed rig profile was ~40 ms and 60
  ms adds margin while staying below the TCP retransmit timeout. This is a calibration baseline, not a
  justified policy.
- **Why it matters.** `meeting.md` §10 and `meeting_direction.md` Phase 3 Q2 explicitly reject "the
  slowest response was 40 ms, so use 60 ms." The final target must be defensible from the SEL-751 timing
  distribution, DNP3 operational constraints, TCP limits, queue precision, latency budget, classifier
  performance, and a device-independent principle.
- **Evidence.** `meeting.md` §10; `ACK_DELAY_DEFENSE2_DESIGN.md` §9 (B1_FIXED G_i=60 ms, "chosen from
  the tail (40 ms), not the median (35 ms)"). Readiness tails measured: rig dev2 max 40.3 ms, real
  SEL-751 p99 35.8 ms / max 170.8 ms.
- **Validation method.** Candidate-pattern study (Phase 3, meeting §11: fixed / common-bounded /
  Ditto-style) evaluated on the physical SEL-751 distribution against the criteria above.
- **Status.** OPEN.

### 12. TCP RTO_MIN ~207 ms is the retransmit ceiling any hold must stay under (rig-measured)
- **Description.** The measured minimum TCP retransmit backoff is ~207 ms. Any response hold target must
  satisfy `max(readiness relative to ACK) < G_i < RTO_MIN − margin`, or the outstation retransmits while
  the switch is holding.
- **Why it matters.** A hold target above RTO_MIN triggers retransmissions/resets — a hard STOP
  condition (`meeting_direction.md` §14) and a transport-safety failure. Critically, the **real** SEL-751
  readiness tail (170 ms) sits close to RTO (207 ms), so tail-coverage and retransmit-safety are in
  tension on the real device — the 60 ms rig value must not be reused for real-device policy without
  re-measuring.
- **Evidence.** `ACK_DELAY_DEFENSE2_DESIGN.md` §9 (RTO_MIN measured 207 ms; constraint stated; "the real
  SEL-751 readiness tail (170 ms) sits near RTO (207 ms) ... do not reuse the 60 ms rig value for
  real-device B2 without re-measuring"). Rig campaigns report 0 retransmits/resets at G_i=60 ms.
- **Validation method.** Measure RTO and readiness on the physical SEL-751 (Phase 5); re-derive the safe
  `G_i` band; confirm 0 retransmits under a real-device hold.
- **Status.** PARTIALLY-VALIDATED (rig-measured; real-device RTO and tail unverified).

### 13. The added response latency is assumed operationally acceptable for DNP3 — budget unknown
- **Description.** Defense 2 adds ~60–107 ms of response latency. We assume this is within the operational
  tolerance of DNP3 Class-0 polling; we have no stated latency budget from the application/operator side.
- **Why it matters.** `meeting_direction.md` Phase 3 Q2 lists "DNP3 operational impact" and "acceptable
  latency overhead" as required justification inputs. If the polling application or protocol timers do
  not tolerate the added delay, the policy is unusable regardless of its security properties.
- **Evidence.** none yet (no operational latency budget documented). Native request→response median 16.98
  ms (`evidence/native_clrt_baseline.txt`); added delay pushes it to ~107 ms in the current rig result.
- **Validation method.** Document DNP3 master polling/timeout configuration on the physical setup (Phase
  5); confirm the master tolerates the added latency without session issues.
- **Status.** OPEN.

---

## E. Security / attacker model

### 14. Formby CLRT is now source-grounded — but the attack is a DISTRIBUTION over a window, and SEL-751 CLRT is our application (not the paper's literal experiment)
- **Description.** The Formby paper is now transcribed to `FORMBY_SOURCE_MAP.md` (all 15 pp., §/page-
  cited). Our "CLRT = ACK→response gap, Case-A/separate-ACK only" **matches** the source (the term
  "CLRT" is Formby's own, §IV-A/Fig 3 p4; the quick-ACK/no-piggyback precondition, §VI-C p13, is exactly
  our Case B). **Two residual caveats remain OPEN for the evaluation**, so this is not fully resolved.
- **Why it matters.** `meeting_direction.md` §5B / Phase 9: we must reproduce *the* Formby attack, not a
  strawman. Two ways our current eval could understate it: (a) Formby classifies a **histogram / mean+
  variance of many CLRT samples over a 5-min–1-day time slice** (Eq 1, §IV-A p4–5) with FF-ANN/naïve-
  Bayes/GMM — **not** a single-gap threshold; our `formby_eval` used a **1-D per-transaction AUROC**, a
  weaker attacker. (b) Formby's large-scale CLRT results are on **anonymized Vendor A/B/C** devices; the
  **SEL-751A appears only in the physical operation-time Method 2** (§IV-B-2 p8–9) — so our SEL-751 CLRT
  is a faithful **application** of Method 1, which the paper must state precisely (not "we replicate the
  SEL-751 CLRT experiment").
- **Evidence.** `FORMBY_SOURCE_MAP.md` (definition MATCH; distribution-over-window; SEL-751 is Method 2;
  Formby metrics = accuracy/precision/recall, not AUROC). `evidence/formby_eval/RESULT.md` (1-D AUROC +
  ACK-mode control — the weaker per-gap attacker).
- **Validation method.** Phase-9 classifier that consumes the **CLRT distribution over a window** with
  **grouped splits** (by run/session), not per-transaction random splits; frame SEL-751 as an
  application of Method 1; report accuracy/precision/recall alongside AUROC/balanced accuracy.
- **Status.** PARTIALLY-VALIDATED (definition source-grounded and MATCHES; window-distribution attacker
  and SEL-751-application framing OPEN for Phase 9).

### 15. Anonymity set of one — only the SEL-751 has a real CLRT in our corpus
- **Description.** On the real device corpus, only the SEL-751 is separate-ACK and therefore has a CLRT;
  AB1400 and ION7550 are combined-ACK (Case B, no CLRT). The second device in the separability test
  (E2) is rig-synthesized (35 ms), not a real relay.
- **Why it matters.** A device-fingerprinting *defense* needs at least two real separate-ACK devices to
  claim it hides *which* device. With one real Case-A device, "the CLRT fingerprint is neutralized" rests
  on a synthetic second device for the separability number.
- **Evidence.** `evidence/formby_eval/RESULT.md` caveat 1 ("Anonymity-set-of-one: only SEL-751 has a
  CLRT ... device2 is RIG-SYNTHESIZED"); `evidence/native_clrt_baseline.txt` (AB1400/ION7550 pure_ACKs=0,
  combined-dominant). E2 native AUROC 1.000 → Case-A 0.571 [0.507,0.648].
- **Validation method.** Obtain/capture a second real separate-ACK device; re-run the separability test
  on a real 2+-device anonymity set (Phase 9). Otherwise state the limitation explicitly.
- **Status.** OPEN.

### 16. ACK-mode and response size are residual cross-device discriminators the timing defenses do not touch
- **Description.** Neither Defense 1 nor Defense 2 removes the separate-ACK structure or changes response
  size. A passive observer can still key on ACK mode (separate vs combined) and on packet size; these
  survive the timing defense.
- **Why it matters.** `meeting_direction.md` §3 requires every claim to state which feature it addresses.
  The timing defense neutralizes the CLRT *value* only. ACK mode is a perfect discriminator between Case
  A and Case B devices, and size is the residual floor (~0.50 balanced accuracy in the prior joint eval).
  Overclaiming "fingerprint erased" is forbidden (§12).
- **Evidence.** `evidence/formby_eval/RESULT.md`: "ACK-mode positive control: recall native 1.00 /
  Case-A 1.00 (Case-A does NOT remove the separate ACK)"; caveat 2 ("ACK-mode and response SIZE survive
  ... size is the residual floor, ~0.50"). SEL-751 sizes {37 B, 54 B} (`native_clrt_baseline.txt`).
- **Validation method.** Report ACK-mode and size features alongside CLRT in every classifier result
  (Phase 9); the size channel is addressed by the separate Part-1 size-normalization line (see #18).
- **Status.** PARTIALLY-VALIDATED (measured on replay/rig; live-device and multi-device confirmation
  pending).

### 17. The guard-delta residual leaves a near-chance separability, and an adaptive attacker is not evaluated
- **Description.** After Defense 1, CLRT-value separability is AUROC ~0.571 (>0.5): the collapsed CLRT is
  near-constant but not perfectly so (guard-delta jitter). An adaptive attacker could instead key on
  "separate ACK with near-zero CLRT ⇒ defended." No adaptive-attacker evaluation exists yet.
- **Why it matters.** `meeting_direction.md` Phase 9 mandates an adaptive attacker trained on defended
  data and forbids calling a >0.5 AUROC "chance." The defense may create a *new* signature (near-zero
  CLRT) that is itself detectable — an unaddressed residual channel.
- **Evidence.** `evidence/formby_eval/RESULT.md`: "residual AUROC 0.57 > 0.5 is guard-delta jitter ... an
  adaptive attacker could key on 'separate ACK with near-zero CLRT = defended.'"
- **Validation method.** Train an adaptive classifier on defended traffic; grouped splits by hardware
  run / connection / session; report AUROC + CI, balanced accuracy, confusion matrix (Phase 9).
- **Status.** OPEN.

---

## F. Scope, integrity, and resources

### 18. Byte-preservation is validated for the timing (recirc) path; Part-1 size-normalization is byte-MODIFYING and out of the current timing scope
- **Description.** The recirculation timing holds preserve the DNP3 payload byte-for-byte. The separate
  Part-1 size-normalization line (padding/segment-geometry) deliberately *modifies* bytes (prepend/seq-
  space translation) and is governed by a different integrity regime; it is not part of the current
  Case-A timing scope.
- **Why it matters.** `meeting_direction.md` §3 requires byte-preservation for the inline timing defense.
  Conflating the two lines would either (a) wrongly claim the timing path modifies bytes, or (b) wrongly
  claim byte-preservation for the size line. The two must not be combined in one binary before the timing
  design is understood (§2: "Do not combine all mechanisms into one P4 binary").
- **Evidence.** Timing path byte-identity measured: `evidence/continuous_campaign_PASS/RESULT.md`
  (120/120 byte-identical), `evidence/defense2_hardware/RESULT.md` (99/99 byte-identical),
  `evidence/sel751_replay/RESULT.md` (99/99). Part-1 byte-modifying design and its risks are documented
  separately (`research/inline_dnp3_size_normalization/`, per memory index — a distinct phase).
- **Validation method.** Keep the two lines as separate P4 programs; assert `join(chunks)==response` on
  the timing path; evaluate the size line's integrity (TCP seq translation, retransmit/SACK safety)
  under its own gate.
- **Status.** PARTIALLY-VALIDATED (timing-path byte-preservation VALIDATED on rig; Part-1 size line OPEN /
  out of scope here).

### 19. Tofino-1 is stage-bound — Part 1 (size) and Part 2 (timing) cannot share one binary
- **Description.** Defense 1 compiles to 12/12 ingress stages, Defense 2 to 10/12, on bf-p4c 9.13.1.
  The pipeline is stage- and parser-bound (not memory-bound). There is no stage headroom to add size +
  split logic to the timing binary.
- **Why it matters.** The paper describes size (Part 1) and timing (Part 2) as complementary. If they
  cannot co-reside on Tofino-1, the "combined defense" must be framed as separate programs (or a
  different platform), and the queue redesign must budget stages carefully. Over-estimating headroom
  would break a hardware plan late.
- **Evidence.** `evidence/COMPILE_FACTS.md`: Case A 12/12 ingress, Case B 10/12; "stage-bound +
  parser-bound, NOT memory-bound (SRAM ≤7%, TCAM 0%). No stages left for size+split." Parser range-match
  171/256 (Case A). Local-compile only; on-switch fit not re-measured this session.
- **Validation method.** Local bf-p4c resource report for any combined/queue design before requesting a
  window (`meeting_direction.md` §10); stage/resource regression test.
- **Status.** PARTIALLY-VALIDATED (per-defense stage counts measured locally; combined/queue fit unknown).

### 20. Current switch and hardware state is unverified without a gated window
- **Description.** Phase 0 involved no hardware, so the live switch program, running processes, loaded
  ports, SDE/compiler version on the switch, and available cabling are not verified in this session.
  Last-known state is whatever `RESUME_STATE.md` recorded.
- **Why it matters.** `meeting_direction.md` §6/§10: do not assume the current switch program, an
  available port, or a device IP. A previous GO does not apply to a modified P4 source. Acting on a stale
  assumption of switch state risks displacing a co-resident experiment (a STOP condition, §14).
- **Evidence.** `CURRENT_STATE_AUDIT.md` §7 item 4 ("Switch state not verified this session (Phase 0 =
  no hardware). Last known = RESUME_STATE") and §0 ("no switch was touched").
- **Validation method.** In an authorized window: snapshot the running program, ports, TM/queue config,
  loopback, and SDE version (`meeting_direction.md` §10 pre-GO checklist) before any change; restore
  after.
- **Status.** GATED-ON-HARDWARE.

---

## Summary of statuses
- **OPEN:** #8, #9, #10, #11, #13, #14, #15, #17.
- **GATED-ON-HARDWARE:** #1, #3, #5*, #20 (*#5's queue alternative is gated; recirc part measured).
- **PARTIALLY-VALIDATED:** #2, #4, #5, #6, #7, #12, #16, #18, #19.
- **VALIDATED:** none stands fully alone yet — timing-path byte-preservation (#18) is the closest, but is
  validated only on the replay rig, not the live device.
- **RESOLVED:** none.

_Every entry above is validated against a real file or measurement in this repository. No measurement
was invented; where evidence is absent the entry says "none yet." This file is updated as each gate
closes._

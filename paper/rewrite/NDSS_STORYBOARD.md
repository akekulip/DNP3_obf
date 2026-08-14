# NDSS storyboard

Proposed section and paragraph sequence for the reader-first rewrite. One purpose sentence per
paragraph; the "→ sets up" line shows how each paragraph's last sentence creates the reason for the
next. Conclusion is the final argumentative section; Related Work precedes it. One running example
(a READ, then a SELECT-before-OPERATE, on the SEL-751) is used throughout. Target: a developed NDSS
two-column paper (Introduction ~1.5–2.5 pp), not a compressed summary.

## 1. Introduction (8–10 developed paragraphs — reconnaissance-to-defense arc)

- **¶1 Reconnaissance before damage.** Purpose: an attacker must learn the target before choosing
  effective actions; grid intrusions begin with observation. → sets up: *what can a quiet observer
  actually learn?*
- **¶2 Fingerprinting as passive reconnaissance.** Purpose: repeated timing, size, and protocol
  behavior let an observer infer device identity, device type, or which transaction is running,
  without acting. → sets up: *is this real even without reading the payload?*
- **¶3 Timing and size are informative even without semantics.** Purpose: traffic-analysis work shows
  size and timing recover content on encrypted or opaque flows. → sets up: *unencrypted ICS traffic
  hands over the same channel — but ICS has its own rules.*
- **¶4 Existing obfuscation defenses.** Purpose: padding, morphing, adaptive/constant-rate shaping,
  differential privacy, and in-network shaping each reshape observable traffic under specific
  assumptions. → sets up: *do those assumptions hold for ICS/DNP3?*
- **¶5 Why ICS and DNP3 are different.** Purpose: introduce the master/outstation polling model,
  long-lived repeatedly-polled devices, unchangeable firmware, and correctness/timing constraints. →
  sets up: *given that setting, what exactly leaks?*
- **¶6 The concrete fingerprint (running example).** Purpose: on one READ, show the request, the first
  TCP ACK-bearing segment, and the DNP3 response; define CLRT from those two packets; introduce the
  49-byte response and the segment vector `[49]`; connect to Formby. → sets up: *why can't a generic
  defense just fix this?*
- **¶7 Why existing defenses do not directly solve it.** Purpose: derive requirements — padding can
  break protocol validity; endpoints are unchangeable; a controller fast-path adds timing/deployment
  cost; size-only shaping leaves timing; timing-only leaves shape; a valid ordered DNP3/TCP exchange
  must be preserved. → sets up: *therefore the defense must sit in the network and preserve the
  protocol.*
- **¶8 Key insight and design.** Purpose: name the switch as the enforcement point; one sentence on
  timing normalization, one on segment-shape normalization (then name response shaping); then explain
  that an outbound OPERATE creates a different causal problem and introduce the control-command hold. →
  sets up: *building this on real hardware is not free.*
- **¶9 Implementation challenges.** Purpose: delayed release without a controller timer; anchoring
  several events to one request timestamp; splitting a valid response without claiming byte identity;
  separating the two mechanisms' scheduling; fitting one Tofino pipeline; operating safely on a
  physical relay. → sets up: *and here is what we measured.*
- **¶10 Results, boundaries, contributions.** Purpose: preview the strongest measured results, then
  state the single-device and missing-relay-facing-tap limits; contribution bullets map to verified
  artifacts. → sets up: *the reader now needs the background to follow the mechanism.*

## 2. Background and Design Overview (reader-first bridge, before any code)

- **¶1 The native READ transaction.** Purpose: walk the request → ACK → response on the running
  example. → sets up: *control is a second, two-step transaction.*
- **¶2 The native SELECT-before-OPERATE transaction.** Purpose: SELECT arms, OPERATE actuates, the
  outstation echoes. → sets up: *where does the attacker stand?*
- **¶3 The master-facing observation point.** Purpose: the observer sees the master-side link only. →
  sets up: *what two features does it read?*
- **¶4 The two leaked features.** Purpose: CLRT (timing) and the segment vector (shape). → sets up:
  *what would defended traffic look like?*
- **¶5 The desired defended timeline.** Purpose: fixed ACK/response offsets → constant CLRT. → sets
  up: *and the desired shape change.*
- **¶6 The desired `[49]→[28,21]` transformation.** Purpose: same 49 bytes, fixed two-segment shape,
  cut on a CRC boundary. → sets up: *what mechanisms produce these?*
- **¶7 High-level role of the two mechanisms.** Purpose: response shaping (timing+shape) and the
  control-command hold (operation timing), by function, no port/queue names. → sets up: *why do they
  need to be kept apart?*
- **¶8 Why two internal scheduling domains.** Purpose: state the failure a shared scheduler causes,
  then the two-domain fix — conceptually. → sets up: *the threat model that bounds all of this.*
- *(First architecture figure here — understandable with NO port/queue numbers.)*

## 3. Threat Model, Assumptions, and Goals (order per prompt §7)

- ¶1 system model + native transaction → ¶2 observation point → ¶3 adversary objective → ¶4 adversary
  capabilities/knowledge (passive, master-facing; distinguishes device id / type / transaction-class;
  encrypted vs unencrypted; semantics vs metadata) → ¶5 trusted components → ¶6 deployment assumptions
  (incl. no TCP timestamps, verified) → ¶7 security goals (testable) → ¶8 non-goals and evidence
  limits (relay-facing unobserved; single device; no byte identity; no active adversary; state what
  changes if the observer sees the relay-facing link). Each paragraph ends by naming the property the
  next one refines. No mechanism repetition.

## 4. Related Work (before Conclusion; organized by problem, per prompt §9)

- One paragraph per category, each: *what it protects against → representative mechanisms → strongest
  relevant result → assumption/remaining leak → exact distinction from this defense.* Categories:
  (a) remote/passive device fingerprinting; (b) ICS/CPS device fingerprinting; (c) cross-layer timing
  fingerprints; (d) website/encrypted-traffic fingerprinting; (e) morphing/size defenses; (f)
  adaptive/constant-rate padding; (g) differential-privacy shaping; (h) in-network/programmable-switch
  obfuscation; (i) P4 scheduling/replication; (j) ICS reconnaissance/MTD; (k) DNP3 security/IDS/
  in-switch processing; (l) standards + incident reports. Each paragraph's last sentence is the
  contrast that motivates the next category.

## 5. Implementation (order per prompt §8; concept-before-symbol)

- ¶overview (one-page end-to-end walkthrough) → (1) physical topology and packet paths → (2)
  end-to-end READ example → (3) timing mechanism → (4) replication + `[28,21]` carving → (5)
  SELECT-before-OPERATE example → (6) control-command state lifecycle → (7) shared-scheduler failure
  then two-domain correction → (8) one-outcome/one-commit pipeline → (9) control-plane/pktgen/PRE/TM/
  readback → (10) retransmissions/stale-state/watchdog/ineligible traffic/failure behavior → (11)
  safety guard and restoration → (12) compiler/resource fit and limitations. Each subsection answers:
  problem it solves, exact trigger packet/state, observable effect, failure behavior, verifying
  evidence. Code symbols only after the concept is taught; port/queue names only in the detailed
  figure.

## 6. Evaluation → 7. Discussion → 8. Conclusion (last argumentative section)

- Evaluation: testbed; timing; segmentation+reconstruction; control-command J-invariance; fingerprint
  suppression (MI/JS/classifier); safety; resource fit — each result carrying its measured/modeled/
  unobserved status. Discussion: bounds and the strongest open item (relay-facing tap). Conclusion
  last, summarizing the argument and the bounded contribution.

## Figures (storyboarded, taught by caption; measured/modeled/unobserved marked)
F1 native running example (request, ACK, response, CLRT) · F2 native-vs-defended (variable timing +
`[49]` vs policy timing + `[28,21]`) · F3 threat model (observer, trusted boundary, missing
relay-facing tap) · F4 response-shaping concept (reservoirs as timers, no code names) · F5
control-command concept (SELECT prep, OPERATE hold, modeled T0+J, measured T0+A/T0+R, evidence
boundary) · F6 shared-scheduler failure vs two-domain fix · F7 detailed implementation (ports, queues,
pktgen, PRE, pipeline, commit).

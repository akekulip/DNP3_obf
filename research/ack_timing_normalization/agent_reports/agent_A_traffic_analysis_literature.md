# Agent A — Network-Privacy & Traffic-Analysis Literature Evidence Report

**Scope:** RQ1, RQ3, RQ4, RQ8 for the ACK-bearing DNP3 response timing-normalization
study. Tiers 1 & 2 owned. This is a cited evidence report; no code was written or modified.

**Verification method & honesty note.** Every citation below was checked against DBLP,
Semantic Scholar, ACM DL / IEEE Xplore / USENIX / NDSS / PETS landing pages, and doi.org
via WebSearch + WebFetch this session. **I read titles, authors, venues, years, pages,
DOIs, and abstracts — I did NOT read the full text of any paper.** Where a claim is a
paper-reported result it is drawn from the abstract or landing-page summary and is marked as
such; where a claim is my inference about relevance to our study it is marked "our
inference." Two items (Jeon 2016, Ahmed 2024) are **arXiv preprints with no verified
peer-reviewed version** and are labeled accordingly. I did not find any published work that
does exactly what we propose (byte-preserving release-timing normalization of an ACK-bearing
DNP3 response to defeat device fingerprinting); that gap is the basis of the RQ8 answer.

---

## 1. RAINCOAT differentiation (verified citation — do this first)

**Verified metadata (DBLP + IEEE Xplore + Semantic Scholar, cross-checked):**

- Title: *RAINCOAT: Randomization of Network Communication in Power Grid Cyber
  Infrastructure to Mislead Attackers*
- Authors: **Hui Lin, Zbigniew T. Kalbarczyk, Ravishankar K. Iyer**
- Venue: **IEEE Transactions on Smart Grid**, Vol. **10**, No. **5**, pp. **4893–4906**
- Year: **2019** (published online Sep 2018; issue Sept 2019)
- DOI: **10.1109/TSG.2018.2870362**

Dr. Lin is the **first author** — confirmed. This is the advisor's own work and the
mandatory differentiation target.

**What RAINCOAT does (paper-reported, from abstract):** it randomizes the control center's
data-acquisition schedule, transforming one acquisition into multiple rounds and dynamically
manipulating network flows so that randomly selected "online" devices return real
measurements while "offline" devices are given intelligently spoofed measurements. Goal:
**misdirect** an attacker's preparation about grid state. Reported effect: probability of a
successful FDI/control attack reduced from ~70% to ~5% with small overhead.

**Structural differentiation (our inference, three axes — lead with axis A):**

| Axis | RAINCOAT | This work |
|---|---|---|
| **Mechanism** | Randomization → misdirection (inject entropy / spoof) | **Normalization → indistinguishability** (remove a leak, build an anonymity set) |
| **Leaked quantity** | Grid **state/content** (measurements, topology posture) | **Device identity** (model / DB-size / load), via processing-time signature |
| **Locus** | Cooperating endpoints (control center reshapes its own acquisition) | **In-network bump-in-the-wire**, endpoint-agnostic; byte-preserving pass-through |
| **What it touches** | Synthesizes/spoofs measurement content across rounds | Touches **only when an existing packet is released** — no byte, CRC, or field change |

These are different problems with different threat models. RAINCOAT is the nearest
same-lab/same-venue prior work, and the "normalization not randomization / device-identity
not grid-content" wedge is defensible and structural, not cosmetic.

---

## 2. RQ1 — Prior research using timing normalization / delay padding / release
scheduling / traffic shaping against fingerprinting

The design space splits into five lineages. Each entry is classified **[R] directly
reusable / [C] only conceptually related / [U] unsuitable for low-latency SCADA control.**

### 2.1 Website-fingerprinting (WF) defenses — the reference lineage for timing/shape defenses

- **Peek-a-Boo / BuFLO** (Dyer, Coull, Ristenpart, Shrimpton, IEEE S&P 2012, DOI
  10.1109/SP.2012.28). Showed coarse countermeasures fail and proposed **BuFLO**:
  constant-rate, fixed-size transmission. Paper-reported: even BuFLO leaves total
  volume/time leaks. **[U]** as a mechanism (constant-rate + padding, prohibitive
  latency/bandwidth for control), **[C]** as the canonical statement of "make flows look
  identical," which is our normalization goal.
- **Tamaraw** (Cai, Nithyanand, Wang, Johnson, Goldberg, CCS 2014, DOI
  10.1145/2660267.2660362). Constant-rate defense with separate up/down rates; near
  information-theoretic bound at high overhead. **[U]** (constant-rate + dummy packets;
  latency), **[C]** (the "declare a target distribution and match it" template — our V1/V4).
- **CS-BuFLO** (Cai, Nithyanand, Johnson, WPES 2014, DOI 10.1145/2665943.2665949).
  Congestion-sensitive BuFLO; paper-reported ~2.3–2.8× overhead. **[U]/[C]** same as above,
  but the *congestion-awareness* idea maps to our TCP-RTO constraint (our inference).
- **WTF-PAD** (Juarez, Imani, Perry, Díaz, Wright, ESORICS 2016, DOI
  10.1007/978-3-319-45744-4_2). **Adaptive padding**: low-overhead, "zero-delay" — it inserts
  dummy packets to fill statistically-unlikely gaps rather than delaying real packets.
  **[C]** — conceptually close (fill the timing distribution) but its lever is *dummy
  packets*, which we cannot add (breaks DNP3 CRC/length). Also broken by deep learning (see
  Deep Fingerprinting).
- **Walkie-Talkie** (Wang, Goldberg, USENIX Security 2017, pp. 1375–1390). Half-duplex +
  burst molding so pages produce **collision** (supersequence) traces → provable
  indistinguishability within a set. **[C]** — the *anonymity-set / collision* idea is
  exactly our "make devices look alike," but it requires browser cooperation and molding
  packet direction; not a byte-preserving in-network primitive.
- **FRONT / GLUE** (Gong, Wang, USENIX Security 2020, pp. 717–734). Zero-delay padding
  concentrating dummies in the trace front; obfuscates trace *feature* not just volume.
  **[C]/[U]** — padding-based, cannot add bytes here.
- **RegulaTor** (Holland, Hopper, PoPETs 2022(2):344–362, DOI 10.2478/popets-2022-0049).
  Shapes traffic to **regular surge patterns**; strong defense at moderate overhead.
  **[C]** — surge-regularization is a timing-shape idea; mechanism still adds/pads packets.
- **Surakav** (Gong, Zhang, Zhang, Wang, IEEE S&P 2022, pp. 1558–1573, DOI
  10.1109/SP46214.2022.9833722). Uses a **GAN to generate realistic reference traces** and
  regulates real traffic to follow them. **[C]** — the "generate a realistic decoy trace and
  follow it" concept is a direct analog of our **V3 decoy-match**; but it reshapes
  send-rate/bursts with dummy traffic, not release-timing-only.

**Attacks that motivate why timing matters (adversary-strength context, not defenses):**

- **Tik-Tok** (Rahman, Sirinam, Mathews, Gangadhara, Wright, PETS 2020(3):5–24, DOI
  10.2478/popets-2020-0043). Shows **raw packet timing** is a strong WF feature in deep
  learning. **[C]** — motivates why timing (not just size) must be normalized; artifacts on
  GitHub.
- **Deep Fingerprinting** (Sirinam, Imani, Juarez, Wright, CCS 2018, pp. 1928–1943, DOI
  10.1145/3243734.3243768). CNN attack; >90% accuracy against WTF-PAD. **[C]** — sets the
  A3 "defense-aware deep classifier" bar for our evaluation.
- **k-fingerprinting** (Hayes, Danezis, USENIX Security 2016, pp. 1187–1203). Random-forest
  WF attack with feature importance. **[C]** — the A2 supervised-classifier baseline and a
  source of per-feature importance methodology.

### 2.2 Timing-channel defenses & latency padding — the closest *timing-only* lineage

This lineage is the most directly reusable because, like us, it manipulates **when** an
output is released (not what it contains) to bound information leakage.

- **Predictive black-box mitigation of timing channels** (Askarov, Zhang, Myers, CCS 2010,
  pp. 297–307, DOI 10.1145/1866307.1866341) and **Predictive mitigation of timing channels
  in interactive systems** (Zhang, Askarov, Myers, CCS 2011, pp. 563–574, DOI
  10.1145/2046707.2046772). A **timing mitigator delays output events** to a
  *predicted* schedule so outputs carry only a bounded amount of timing information; leakage
  grows only logarithmically in run time. **[R] directly reusable** — this is the formal
  backbone of our candidate policy `release = max(ready, deadline)`: releasing on a
  predicted/scheduled deadline rather than when-ready is exactly predictive mitigation, and
  gives a provable leakage bound. Software prototypes only.
- **A Provably Secure and Efficient Countermeasure against Timing Attacks** (Köpf, Dürmuth,
  CSF 2009, pp. 324–335, DOI 10.1109/CSF.2009.21). **Bucketing**: quantize response times
  into a small set of discrete buckets; leakage bounded by |O|·log(n+1) bits; tunable
  security/performance trade-off. **[R] directly reusable** — bucketed/quantized release is a
  concrete, low-overhead instantiation of our size-decorrelation (V4): release only at a few
  discrete deadlines so processing time reveals a bounded number of bits.
- **Reducing Timing Channels with Fuzzy Time** (Hu, IEEE S&P 1991, pp. 8–20, DOI
  10.1109/RISP.1991.130768; extended in J. Computer Security 1(3-4):233–254, 1992). Adds
  noise to clocks/event timing to reduce covert-channel bandwidth. **[C]** — foundational
  jitter approach; important as the *randomization* baseline that averageability defeats (RQ4).
- **A Pump / A Network Pump** (Kang, Moskowitz, CCS 1993, pp. 119–129, DOI
  10.1145/168588.168604; Kang, Moskowitz, Lee, IEEE Trans. Software Engineering 22(5):329–338,
  1996, DOI 10.1109/32.502225). The Pump bounds the **covert timing channel carried by ACK
  timing** between a low and a high process by inserting a buffer and driving ACK release from
  a **moving average** of service times rather than the true completion time. **[R]/[C]** —
  the single closest *prior mechanism to manipulating ACK timing to bound an information
  leak*. Different threat (colluding-process covert channel, not passive device fingerprint),
  but "release ACKs on a smoothed schedule decoupled from true processing time" is precisely
  our lever; strong precedent to cite (our inference).
- **An information-theoretic and game-theoretic study of timing channels** (Giles, Hajek,
  IEEE Trans. Information Theory 48(9):2455–2477, 2002, DOI 10.1109/TIT.2002.801405). Capacity
  of a timing channel under **delay jammers** with max/average-delay or buffer constraints;
  min-max optimal jammer vs max-min input. **[R] as theory** — quantifies exactly the
  question in RQ4 (how much timing information survives a delay/normalization budget) and
  gives the framework for the averageability argument.
- **Timing Analysis in Low-Latency Mix Networks: Attacks and Defenses** (Shmatikov, Wang,
  ESORICS 2006, pp. 18–33, DOI 10.1007/11863908_2). Origin of **adaptive padding** —
  statistical fill of inter-packet gaps to break timing correlation under a delay budget.
  **[C]** — adaptive padding is our conceptual cousin, but again adds packets.

### 2.3 Constant-rate / bounded-delay / mix-network scheduling

- **Dependent link padding algorithms for low latency anonymity systems** (Wang, Motani,
  Srinivasan, CCS 2008, pp. 323–332, DOI 10.1145/1455770.1455812). Provides a **strict delay
  bound** while making flows on a link indistinguishable; covering-traffic rate O(log m) for m
  Poisson users. **[R] conceptually + [C] mechanism** — the *bounded-delay* framing is
  directly our RTO-bounded budget; the mechanism pads with cover traffic (not byte-preserving).
- **The Loopix Anonymity System** (Piotrowska, Hayes, Elahi, Meiser, Danezis, USENIX Security
  2017, pp. 1199–1216). **Poisson mixing**: each message delayed by an independent
  exponential delay; cover loops. **[C]/[U]** — per-message exponential delay is the canonical
  randomized-release scheduler, but tuned for second-scale anonymity, unsuitable at OT
  latency; useful as the theory of "release-time as the privacy lever."
- **Stop-and-Go MIXes** (Kesdogan, Egner, Büschkes, Information Hiding 1998, LNCS 1525, pp.
  83–98, DOI 10.1007/3-540-49380-8_7). Each message assigned an individual delay drawn from a
  distribution with a time window. **[C]** — earliest per-message randomized-release scheduler.
- **Timing Attacks in Low-Latency Mix Systems** (Levine, Reiter, Wang, Wright, FC 2004, LNCS
  3110, pp. 251–265, DOI 10.1007/978-3-540-27809-2_25). Introduces **defensive dropping**
  against timing correlation. **[C]** — shows i.i.d.-style timing countermeasures are limited
  against a correlator with many samples (feeds RQ4).

### 2.4 In-network / systems traffic-shaping (the platform-and-systems analogs)

- **ditto: WAN Traffic Obfuscation at Line Rate** (Meier, Lenders, Vanbever, NDSS 2022). Pads
  packets and injects chaff **on Intel Tofino programmable switches at 100 Gbps** to make
  obfuscated traffic independent of production traffic in size/timing/volume. **[C]/[U]** —
  the *closest platform precedent* (Tofino, in-network, line-rate) and our nearest systems
  neighbor, BUT it is **not byte-preserving** (adds padding+chaff) and targets WAN
  volume/timing not a device-identity processing-time leak. Artifacts: GitHub (nsg-ethz/ditto),
  Tofino P4, SDE 8.9. This is the paper a reviewer will compare us to on the systems axis.
- **Pacer: Comprehensive Network Side-Channel Mitigation in the Cloud** (Mehta, Alzayat, De
  Viti, Brandenburg, Druschel, Garg, USENIX Security 2022). Shapes guest traffic in the
  hypervisor so shape is secret-independent by design; respects congestion/flow control.
  **[C]/[U]** — "shape traffic to be independent of the secret" is our exact goal, but
  hypervisor-based padding, heavy, endpoint-side.
- **NetShaper: A Differentially Private Network Side-Channel Mitigation System** (Sabzi, Vora,
  Goswami, Seltzer, Lécuyer, Mehta, USENIX Security 2024). **DP traffic shaping** in a
  middlebox tunnel; tunable privacy/bandwidth/latency trade-off. **[C]/[R-metric]** — the
  **differential-privacy formalization of shaping** and the explicit privacy-vs-overhead
  trade-off is a directly reusable evaluation framing for our Pareto frontier; mechanism adds
  padding (not byte-preserving).
- **Random Segmentation: New Traffic Obfuscation against Packet-Size-Based Side-Channel
  Attacks** (Alyami, Alghamdi, Alkhowaiter, Zou, Solihin, MDPI Electronics 12(18):3816, 2023,
  DOI 10.3390/electronics12183816). **Splits large TCP segments into random-sized chunks** to
  obfuscate packet-length distribution *without adding dummy bytes*. **[C] — very close to our
  existing CRC-boundary splitting primitive** (byte-preserving size reshaping by segmentation),
  though on the size axis not timing; good comparison for the "split" contribution.
- **Traffic Morphing: An Efficient Defense Against Statistical Traffic Analysis** (Wright,
  Coull, Monrose, NDSS 2009). Uses convex optimization to make one class's packet-size
  distribution **match a target class's** at minimal overhead. **[C] — the closest conceptual
  ancestor of distribution-matching normalization** (our V3 decoy-match / V4). Operates on
  sizes via padding; the *distribution-matching objective* is exactly ours, transplanted to
  the timing axis.

---

## 3. RQ3 — Mechanisms closest to "bounded randomized normalization" of an ACK-bearing
response

Ranked by closeness (our inference), with the gap each leaves:

1. **Predictive mitigation (Askarov/Zhang/Myers, CCS 2010/2011)** — *closest formal match.*
   Release outputs on a predicted schedule to bound timing leakage under a budget. Our policy
   `release = max(ready, request_time + target_delay)` is a predictive mitigator with a
   deadline schedule. **Gap:** they mitigate a program's own covert channel; we normalize a
   device-identity fingerprint in-network, and we bound by TCP RTO not a security-lattice
   requirement.
2. **The Pump / Network Pump (Kang/Moskowitz, 1993/1996)** — *closest ACK-timing match.*
   Smooths ACK release from a moving average, decoupling ACK timing from true service time.
   Exactly our "the ACK carries the response, so normalize its release." **Gap:** covert-
   channel threat between colluding endpoints, not passive fingerprinting; a buffering
   endpoint, not a byte-preserving bump-in-the-wire.
3. **Köpf–Dürmuth bucketing (CSF 2009)** — *closest low-overhead instantiation.* Quantize
   response time into k buckets → bounded bits leak, tunable overhead. Directly realizes our
   V4 size-decorrelation as "release only at discrete deadlines." **Gap:** designed for crypto
   timing side channels; no live-protocol RTO/handshake constraint.
4. **Traffic Morphing (NDSS 2009) / Surakav (S&P 2022)** — *closest distribution-matching
   match.* Make one device's observable distribution match a target/decoy device's. Our V3
   decoy-match and V4. **Gap:** both reshape via *added packets/padding*; we forbid byte
   changes, so we match distributions using **release timing only**.
5. **Giles–Hajek (T-IT 2002)** — *closest theoretical match.* Timing-channel capacity under a
   delay-jammer budget; gives the achievable leakage floor for any bounded-delay normalizer.
   **Gap:** pure theory, no protocol/system.

**No prior work combines all four of our defining properties:** (i) target = device-identity
processing-time leak, (ii) mechanism = release-timing-only and **byte-preserving** (no
padding/chaff/CRC recompute), (iii) medium = live TCP/DNP3 with an RTO/handshake correctness
bound, (iv) deployment = in-network pass-through. That four-way intersection is empty in the
verified literature.

---

## 4. RQ4 — Normalization vs additive i.i.d. jitter: averageability

**Claim (supported by theory + attack literature, our synthesis):** under a passive observer
that can repeat the same query many times (exactly the SCADA polling model), **additive i.i.d.
jitter is averageable and normalization is not.**

- **The averaging argument.** Suppose the true processing time for request class c is a fixed
  T_c (our measured near-deterministic linear map, R²>0.99). Additive i.i.d. jitter releases at
  T_c + J_i with E[J]=μ, Var[J]=σ². The observer's sample mean over n polls converges to
  T_c + μ with error ∝ σ/√n; μ is a known constant offset, so **T_c (hence CROB count /
  DB-size proxy) is recovered to arbitrary precision as n grows.** Jitter raises the number of
  samples needed but does not change what is asymptotically learnable. This is the classical
  result behind **Crosby, Wallach, Riedi, "Opportunities and Limits of Remote Timing Attacks"
  (ACM TISSEC 12(3):17, 2009, DOI 10.1145/1455526.1455530)** and **Brumley & Boneh, "Remote
  Timing Attacks Are Practical" (USENIX Security 2003; Computer Networks 48(5):701–716, 2005,
  DOI 10.1016/j.comnet.2005.01.010)**: remote timing attacks defeat network jitter precisely
  by averaging many samples. **Levine et al. (FC 2004)** make the same point for mix timing
  correlation.
- **Why normalization is different.** Distribution-matching / bounded-deadline normalization
  changes the *released distribution itself* to a **class-independent** target (constant,
  bucketed, or a decoy device's distribution), so that the released timing is (approximately)
  statistically independent of T_c. When the released variable's distribution does not depend
  on the secret, no amount of averaging recovers the secret — the estimator converges to the
  same target for every class. This is the information-theoretic guarantee behind **BuFLO/
  Tamaraw** (identical flows), **predictive mitigation** (bounded leakage regardless of run
  length), **bucketing** (|O|·log(n+1) bound), and **Giles–Hajek** (capacity floor under a
  delay budget). Formally the target is **I(released_time ; request_class) → 0**, which is our
  stated `I(processing_time; size) → 0` objective.
- **Attacker-model dependence (important caveat).** The distinction bites only for an observer
  who gets **many samples of the same class** (the SCADA case: fixed poll schedule, repeated
  identical integrity polls — our measured setting). Against a **single-shot** observer,
  sufficiently large jitter can be adequate. Against an **adaptive/deep** attacker (Deep
  Fingerprinting, Tik-Tok), even jitter with structure leaks through learned features, whereas
  a normalizer that provably flattens the class-conditional distribution does not. So: **for a
  repeated-query passive observer, normalization dominates jitter; the head-to-head baseline
  B2 (RAINCOAT-style i.i.d. jitter) will show a residual I(T;S) that V4 removes** — this is a
  measurable, publishable result, not just an assertion.
- **Cost nuance.** Pure jitter is cheap but averageable; full constant-time is un-averageable
  but maximal-latency; **bucketing / size-decorrelation (V4) is the sweet spot** — it removes
  the *class-dependence* (the averageable-secret) at far lower added latency than constant-time,
  because it need only make the distribution class-independent, not degenerate. This matches
  Köpf–Dürmuth's tunable bound and is the paper's punchline.

**Verdict:** Normalization is better than additive i.i.d. jitter **against the repeated-poll
passive observer that our threat model assumes.** State the attacker model explicitly — the
claim is model-dependent, and over-claiming it universally would not survive review.

---

## 5. RQ8 — Genuinely novel contribution vs repackaging

**What would be repackaging (and would not survive review):**
- "Port WTF-PAD / Tamaraw / FRONT to DNP3." All WF defenses rely on **adding dummy packets
  and/or padding sizes**; we cannot (breaks DNP3 CRCs and length fields, violates the phase
  rule). A straight port is both infeasible and unoriginal.
- "Add random jitter to responses." Averageable (RQ4); and conceptually adjacent to RAINCOAT's
  randomization — the advisor's own work — so it is neither novel nor differentiated.
- "Constant-rate shaping like ditto/BuFLO." Prohibitive latency/bandwidth for low-latency
  control, and ditto already owns the Tofino-line-rate-WAN framing.

**The delta that survives review (contribution statement):**
> The first **byte-preserving, release-timing-only** normalization defense that destroys a
> **measured device-identity processing-time leak** (near-perfect linear
> processing-time↔request-complexity signature, R²>0.99 on a real OpenDNP3 outstation) in a
> **live DNP3/SCADA** session, deployable as an **in-network bump-in-the-wire**, under a
> correctness/stealth budget set by **TCP RTO** rather than any application timer.

Four things make it novel against the verified state of the art:

1. **Byte-preserving constraint as the contribution, not a limitation.** Every WF/traffic-
   shaping defense (WTF-PAD, Tamaraw, FRONT, Surakav, ditto, Pacer, NetShaper) reshapes by
   **padding sizes and/or injecting chaff**. The DNP3 CRC + live-master transparency
   constraint forbids that, so **timing release is the only axis we can touch without altering
   a byte** — `b"".join(chunks) == original` still holds. No prior fingerprinting defense
   operates under this constraint; it is a genuinely different design point.
2. **A measured, information-theoretic ICS leak as the target.** We are not defending a
   generic "make traces look alike" objective; we target a **specific, regression-recoverable
   leak we measured** (β = 0.179–0.214 ms/CROB, R²>0.99) and drive **I(processing_time; request
   complexity) → 0**. Formby et al. (NDSS 2016) established that this CLRT leak *exists* and is
   an *attack*; **no published work provides the byte-preserving in-network defense that
   removes it.** We close the loop Formby opened.
3. **Normalization/anonymity-set vs RAINCOAT's randomization/misdirection** (Section 1) —
   different locus, leak, and mechanism from the nearest same-lab prior work.
4. **In-network per-packet timing normalization is impractical in general but tractable for
   OT/SCADA.** ditto/Pacer show general in-network per-packet absolute-delay normalization is
   costly; our traffic is single-digit-kbps, small-frame, sub-second-cadence, so a
   held-frame/recirc-deadline approach that is prohibitive for datacenter TCP becomes cheap
   here. That inversion is itself a paper-worthy systems framing.

**Nearest prior work to acknowledge head-on:** RAINCOAT (same lab, differentiation Section 1);
Formby et al. NDSS 2016 (the attack we defend); ditto NDSS 2022 (the in-network/Tofino systems
neighbor); Traffic Morphing NDSS 2009 + predictive mitigation CCS 2010/2011 (the mechanism
ancestors). Position as: *the byte-preserving, release-timing realization of
distribution-matching normalization, specialized to a measured DNP3 device-identity leak.*

---

## 6. Tier classification summary (verified counts)

- **Tier 1 (DNP3/SCADA/ICS fingerprinting or ICS timing/deception):** 8 verified peer-reviewed
  + 2 preprints. Formby NDSS 2016 (attack we defend), RAINCOAT TSG 2019, DefRec NDSS 2020,
  DecIED CPSS@AsiaCCS 2020, HoneyPLC CCS 2020, Barbosa IJCIP 2016, GTID TDSC 2015 (wired-side
  device fingerprinting), TIDF NPC 2025; **preprints:** Jeon 2016 (arXiv, not peer-reviewed),
  Ahmed "Time Constant" 2024 (arXiv, not peer-reviewed).
- **Tier 2 (WF defenses, adaptive padding, constant-rate/latency, timing-channel defenses,
  in-network shaping):** 24 verified peer-reviewed works (WTF-PAD, Tamaraw, CS-BuFLO,
  Walkie-Talkie, FRONT, RegulaTor, Surakav, Peek-a-Boo/BuFLO, Traffic Morphing, Deep
  Fingerprinting, k-fingerprinting, Tik-Tok, Shmatikov-Wang adaptive padding, dependent link
  padding, Loopix, Stop-and-Go, Levine FC2004, predictive mitigation ×2, Köpf-Dürmuth, Fuzzy
  Time, Pump/Network Pump ×2, Giles-Hajek, Crosby TISSEC, Brumley-Boneh, ditto, Pacer,
  NetShaper, Random Segmentation, Sivanathan TMC). Kohno TDSC 2005 (clock-skew device
  fingerprinting) also verified.

**Total verified peer-reviewed works: ~32; preprints flagged: 2.** All metadata verified;
none read in full text.

---

## PAPER_MATRIX_ROWS
RAINCOAT: Randomization of Network Communication in Power Grid Cyber Infrastructure to Mislead Attackers | Hui Lin, Zbigniew T. Kalbarczyk, Ravishankar K. Iyer | 2019 | IEEE Transactions on Smart Grid 10(5) | 10.1109/TSG.2018.2870362 | https://ieeexplore.ieee.org/document/8466028 | yes | 1 | Power-grid SCADA control-center acquisition | Reconnaissance attacker preparing FDI/control attacks | Randomize acquisition schedule + spoof offline-device measurements (misdirection) | Randomized multi-round acquisition, per-round device selection | sw | Control-center software + simulation | Power-grid CPS testbed/simulation | Attack success prob reduced 70% to 5% | Endpoint-cooperative, targets grid state not device identity, randomization not normalization | Advisor's own work; the mandatory differentiation target (misdirection vs normalization) | high
Who's in Control of Your Control System? Device Fingerprinting for Cyber-Physical Systems | David Formby, Preethi Srinivasan, Andrew M. Leonard, Jonathan D. Rogers, Raheem A. Beyah | 2016 | NDSS | 10.14722/ndss.2016.23142 | https://www.ndss-symposium.org/ | yes | 1 | ICS/SCADA (DNP3, Modbus) devices | Passive on-network fingerprinter (IDS augmentation) | Cross-layer response time (CLRT) fingerprinting + physical device fingerprinting | Attack: measures response processing time distributions | sw+testbed | Real ICS relays/PLCs + OpenDNP3 | Substation/testbed captures | Accurate device-type fingerprints from low-latency dedicated ICS timing | This IS the attack; also shows crafted response packets can spoof timing | The exact leak we destroy; measured CLRT is our processing-time signal | high
DefRec: Establishing Physical Function Virtualization to Disrupt Reconnaissance of Power Grids' Cyber-Physical Infrastructures | Hui Lin, Jianhui Zhuang, Yih-Chun Hu, Ravishankar K. Iyer, Zbigniew T. Kalbarczyk | 2020 | NDSS | 10.14722/ndss.2020.24365 | https://www.ndss-symposium.org/ndss-paper/defrec-establishing-physical-function-virtualization-to-disrupt-reconnaissance-of-power-grids-cyber-physical-infrastructures/ | yes | 1 | Power-grid CPS network | Reconnaissance adversary building attack knowledge | Physical function virtualization: lightweight virtual decoy nodes following real device behavior | Deception via virtual nodes, not timing normalization | sw+testbed | Software PFV + power-grid simulation | Power-grid CPS testbed | Delays reconnaissance >100 years with <=20% added virtual nodes | Deception/decoys, not device-identity timing normalization | Same lab; MTD/deception neighbor, complementary framing | high
DecIED: Scalable k-Anonymous Deception for IEC61850-Compliant Smart Grid Systems | Dianshi Yang, Daisuke Mashima, Wei Lin, Jianying Zhou | 2020 | CPSS@AsiaCCS | 10.1145/3384941.3409592 | https://dl.acm.org/doi/10.1145/3384941.3409592 | yes | 1 | IEC 61850 smart-grid substation IEDs | Reconnaissance attacker scanning substation | k-anonymous decoy IEDs mimicking device+communication models | Mimic device/communication model of real IEDs (k-1 decoys) | sw | Single industrial PC hosting 200+ decoys | Substation network emulation | k-anonymous smokescreen, 200+ decoys per host | k-anonymity via decoys (mimicry), not release-timing normalization of a real device | k-anonymity/anonymity-set concept maps to our normalization framing | high
HoneyPLC: A Next-Generation Honeypot for Industrial Control Systems | Efren Lopez-Morales, Carlos Rubio-Medrano, Adam Doupe, Yan Shoshitaishvili, Ruoyu Wang, Tiffany Bao, Gail-Joon Ahn | 2020 | ACM CCS | 10.1145/3372297.3423356 | https://dl.acm.org/doi/10.1145/3372297.3423356 | yes | 1 | PLC-based ICS | Reconnaissance attacker / scanner | High-interaction honeypot passing as a real PLC to reconnaissance tools | Deception, device impersonation | sw+testbed | Software honeypot on AWS | Internet-facing deployment | Fingerprinted as real device by recon tools; engaged attackers | Deception, not a timing-normalization defense for real devices | Conceptually related (device indistinguishability), not timing | med
Exploiting traffic periodicity in industrial control networks | Rafael Ramos Regis Barbosa, Ramin Sadre, Aiko Pras | 2016 | International Journal of Critical Infrastructure Protection 13 | 10.1016/j.ijcip.2016.02.004 | https://www.sciencedirect.com/science/article/abs/pii/S1874548216300221 | yes | 1 | Industrial control networks (SCADA) | Anomaly/IDS context (attacker uses periodicity) | Learn periodic timing/message-repetition models (whitelist) | Timing/periodicity modeling of ICS traffic | sw | Real ICS traffic traces | 3 real-world industrial traces | Automatically learns periodic traffic models for IDS | Attacker-side timing model, not a defense; shows ICS timing is highly regular | Establishes that ICS timing is regular/learnable (why our leak is exploitable) | high
GTID: A Technique for Physical Device and Device Type Fingerprinting | Sakthi Vignesh Radhakrishnan, A. Selcuk Uluagac, Raheem Beyah | 2015 | IEEE Transactions on Dependable and Secure Computing 12(5) | 10.1109/TDSC.2014.2369033 | https://ieeexplore.ieee.org/document/6951398 | yes | 1 | Networked devices (802.11, wired-side) | Passive/active device fingerprinter | Inter-arrival-time statistics + ANN classification for device/type ID | Attack: inter-arrival-time signatures | sw+testbed | Testbed + live campus network, 37 devices | Isolated + live network | Accurate device/type fingerprints from inter-arrival timing | Attack (timing-based device ID), the fingerprint class we defend against | Confirms inter-arrival/timing is a strong device-ID feature | high
TIDF: Timing-Based Device Fingerprinting for PLCs | Lei Xiang, Hao Han | 2026 | Network and Parallel Computing (NPC 2025), LNCS 16306 | 10.1007/978-3-032-10466-3_11 | https://link.springer.com/chapter/10.1007/978-3-032-10466-3_11 | yes | 1 | PLC-based ICS | Detect unauthorized/rogue PLCs | Timing fingerprint from processing time + clock pulse period (DBSCAN+OCSVM) | Attack/authentication via processing-time timing | sw+testbed | Real 13-PLC testbed (Siemens, Xinje) | Lab testbed | 96% anomaly detection of unauthorized PLCs | Recent proof that PLC processing-time timing fingerprints devices | Directly reinforces our processing-time leak on real PLC hardware | high
Passive Fingerprinting of SCADA in Critical Infrastructure Network without Deep Packet Inspection | Sungho Jeon, Jeong-Han Yun, Seungoh Choi, Woo-Nyon Kim | 2016 | arXiv preprint (no verified peer-reviewed version) | 10.48550/arXiv.1608.07679 | https://arxiv.org/abs/1608.07679 | preprint | 1 | SCADA field devices/masters | Passive fingerprinter without DPI | Port/role inference from passive traffic, no DPI | Attack: passive fingerprinting | sw | Real network traffic (6 weeks) | Real ICS network | High F-score (~1) device/role inference | Preprint, not peer-reviewed; abstract-only verification | Passive SCADA fingerprinting w/o DPI motivates our passive-observer model | med
Time Constant: Actuator Fingerprinting using Transient Response of Device and Process in ICS | Chuadhry Mujeeb Ahmed et al. | 2024 | arXiv preprint (no verified peer-reviewed version) | 10.48550/arXiv.2409.16536 | https://arxiv.org/abs/2409.16536 | preprint | 1 | ICS actuators/physical process | Command-injection/replay attacker | Physical transient-response fingerprint (copy-resistant) | Physical-process transient timing | sw+testbed | ICS testbed | Water/process testbed | Copy-resistant actuator fingerprint resisting replay | Physical-process fingerprint, not network-timing device-identity; only conceptually related | Preprint; conceptually related (physical timing), unsuitable as our target | low
Remote Physical Device Fingerprinting | Tadayoshi Kohno, Andre Broido, K. C. Claffy | 2005 | IEEE Transactions on Dependable and Secure Computing 2(2) | 10.1109/TDSC.2005.26 | https://ieeexplore.ieee.org/document/1453519 | yes | 2 | Internet hosts | Remote passive fingerprinter | Clock-skew estimation from TCP timestamps | Attack: exploits clock-skew microdeviations | sw | Real Internet measurement | Cross-Internet | Consistent device fingerprints across hops/locations | Timing/clock-skew fingerprint class; our TCP timestamps expose similar signal | Motivates a timing/clock-skew leak beyond processing time | high
Classifying IoT Devices in Smart Environments Using Network Traffic Characteristics | Arunan Sivanathan, Hassan Habibi Gharakheili, Franco Loi, Adam Radford, Chamith Wijenayake, Arun Vishwanath, Vijay Sivaraman | 2019 | IEEE Transactions on Mobile Computing 18(8) | 10.1109/TMC.2018.2866249 | https://ieeexplore.ieee.org/document/8440758 | yes | 2 | IoT devices | Passive traffic classifier | Statistical/ML classification from traffic characteristics incl. timing | Attack: supervised device classification | sw+testbed | 28-device smart-environment testbed | Instrumented smart environment | Accurate IoT device classification from traffic features | Attack; the device-fingerprinting task class our defense must break | Sets the supervised-classifier attacker template (T1/A2) | high
Peek-a-Boo, I Still See You: Why Efficient Traffic Analysis Countermeasures Fail | Kevin P. Dyer, Scott E. Coull, Thomas Ristenpart, Thomas Shrimpton | 2012 | IEEE S&P | 10.1109/SP.2012.28 | https://ieeexplore.ieee.org/document/6234422 | yes | 2 | Encrypted web traffic (WF) | Passive traffic analyst | BuFLO constant-rate fixed-size transmission | Constant-rate + padding | sw | Simulation over WF datasets | WF dataset | Coarse countermeasures fail; BuFLO near-limit at high overhead | Canonical constant-rate defense; unsuitable latency/bandwidth for control | Defines the constant-time endpoint of our design space | high
A Systematic Approach to Developing and Evaluating Website Fingerprinting Defenses | Xiang Cai, Rishab Nithyanand, Tao Wang, Rob Johnson, Ian Goldberg | 2014 | ACM CCS | 10.1145/2660267.2660362 | https://dl.acm.org/doi/10.1145/2660267.2660362 | yes | 2 | Tor web traffic (WF) | Passive WF attacker | Tamaraw: constant-rate with distinct up/down rates + padding | Constant-rate release + dummy packets | sw | Simulation over WF datasets | WF dataset | Near information-theoretic bound at high overhead | Constant-rate normalization template; padding-based, not byte-preserving | Conceptual target distribution (declare + match); unsuitable mechanism | high
CS-BuFLO: A Congestion Sensitive Website Fingerprinting Defense | Xiang Cai, Rishab Nithyanand, Rob Johnson | 2014 | WPES | 10.1145/2665943.2665949 | https://dl.acm.org/doi/10.1145/2665943.2665949 | yes | 2 | Tor web traffic (WF) | Passive WF attacker | Congestion-sensitive BuFLO (rate adapts to congestion) | Constant-rate + congestion adaptation + padding | sw | Simulation over WF datasets | WF dataset | ~2.3-2.8x overhead; 6x closer to trade-off bound | Congestion-awareness maps to our RTO constraint; padding-based | Conceptually related; congestion-adaptive idea reusable, mechanism not | med
Walkie-Talkie: An Efficient Defense Against Passive Website Fingerprinting Attacks | Tao Wang, Ian Goldberg | 2017 | USENIX Security | NA | https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/wang-tao | yes | 2 | Tor web traffic (WF) | Passive WF attacker | Half-duplex + burst molding to create collisions (supersequences) | Burst molding, direction control, added padding | sw | Simulation + browser | WF dataset | Provable indistinguishability within collision set at moderate cost | Anonymity-set/collision idea = our "make devices alike"; needs endpoint cooperation | Conceptual (collision/anonymity set); not byte-preserving in-network | high
Toward an Efficient Website Fingerprinting Defense | Marc Juarez, Mohsen Imani, Mike Perry, Claudia Diaz, Matthew Wright | 2016 | ESORICS (LNCS 9878) | 10.1007/978-3-319-45744-4_2 | https://link.springer.com/chapter/10.1007/978-3-319-45744-4_2 | yes | 2 | Tor web traffic (WF) | Passive WF attacker | WTF-PAD adaptive padding: fill unlikely inter-packet gaps with dummies | Adaptive (zero-delay) padding | sw | Simulation over WF datasets | WF dataset | Low overhead; later broken by deep learning | Adaptive padding = conceptual cousin; lever is dummy packets (forbidden here) | Conceptual; mechanism (padding) infeasible under byte-preservation | high
Zero-delay Lightweight Defenses against Website Fingerprinting | Jiajun Gong, Tao Wang | 2020 | USENIX Security | NA | https://www.usenix.org/conference/usenixsecurity20/presentation/gong | yes | 2 | Tor web traffic (WF) | Passive WF attacker | FRONT/GLUE zero-delay padding concentrated at trace front | Zero-delay dummy padding | sw | Simulation over WF datasets | WF dataset | Strong obfuscation of trace features at low delay | Zero-delay appealing but adds packets (forbidden); trace-front idea informative | Conceptual; padding-based, not applicable to byte-preserving timing | high
RegulaTor: A Straightforward Website Fingerprinting Defense | James K. Holland, Nicholas Hopper | 2022 | PoPETs 2022(2) | 10.2478/popets-2022-0049 | https://petsymposium.org/popets/2022/popets-2022-0049.php | yes | 2 | Tor web traffic (WF) | Passive WF attacker | Shape traffic into regular surge patterns | Surge-regularized send schedule + padding | sw | Simulation over WF datasets | WF dataset | Strong defense at moderate overhead | Surge-regularization is a timing-shape idea; mechanism pads | Conceptual (regularize timing shape) | med
Surakav: Generating Realistic Traces for a Strong Website Fingerprinting Defense | Jiajun Gong, Wuqi Zhang, Charles Zhang, Tao Wang | 2022 | IEEE S&P | 10.1109/SP46214.2022.9833722 | https://ieeexplore.ieee.org/document/9833722 | yes | 2 | Tor web traffic (WF) | Passive WF attacker | GAN-generated reference traces; regulate real traffic to follow them | Follow a generated decoy trace (rate regulation + padding) | sw | Simulation + prototype | WF dataset | Strong defense; realistic decoy traces reduce overhead | Direct analog of our V3 decoy-match; reshapes rate/bursts with dummies | Conceptual (decoy-trace matching), mechanism not byte-preserving | high
Deep Fingerprinting: Undermining Website Fingerprinting Defenses with Deep Learning | Payap Sirinam, Mohsen Imani, Marc Juarez, Matthew Wright | 2018 | ACM CCS | 10.1145/3243734.3243768 | https://dl.acm.org/doi/10.1145/3243734.3243768 | yes | 2 | Tor web traffic (WF) | Deep-learning passive attacker | CNN WF attack (breaks WTF-PAD) | Attack, not defense | sw | Simulation over WF datasets | WF dataset | >98% no-defense; >90% vs WTF-PAD | Defines the deep-classifier (A3) attacker bar for our evaluation | Sets adversary strength; motivates provable normalization over heuristic padding | high
k-fingerprinting: A Robust Scalable Website Fingerprinting Technique | Jamie Hayes, George Danezis | 2016 | USENIX Security | NA | https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/hayes | yes | 2 | Tor / hidden-service traffic (WF) | Passive WF attacker | Random-forest attack with feature importance | Attack, not defense | sw | Simulation over WF datasets | WF dataset | Robust scalable WF; identifies key features | Supervised RF baseline (A2) and feature-importance methodology | Reusable attacker baseline for our evaluation | high
Tik-Tok: The Utility of Packet Timing in Website Fingerprinting Attacks | Mohammad Saidur Rahman, Payap Sirinam, Nate Mathews, Kantha Girish Gangadhara, Matthew Wright | 2020 | PoPETs 2020(3) | 10.2478/popets-2020-0043 | https://petsymposium.org/popets/2020/popets-2020-0043.php | yes | 2 | Tor web traffic (WF) | Deep-learning passive attacker | Timing-based features (bursts, raw/directional timing) in DL WF | Attack, not defense | sw | Simulation over WF datasets; GitHub artifacts | WF dataset | Packet timing materially improves WF accuracy | Proves timing (not just size) leaks; motivates timing normalization | Directly motivates the timing axis; artifacts available | high
Timing Analysis in Low-Latency Mix Networks: Attacks and Defenses | Vitaly Shmatikov, Ming-Hsiu Wang | 2006 | ESORICS (LNCS 4189) | 10.1007/11863908_2 | https://link.springer.com/chapter/10.1007/11863908_2 | yes | 2 | Low-latency mix / anonymity | Passive timing correlator | Adaptive padding: statistically fill inter-packet gaps under a delay budget | Adaptive padding (bounded delay + dummies) | sw+sim | Simulation | Mix-network simulation | Adaptive padding reduces timing-correlation success | Origin of adaptive padding; conceptual ancestor, adds packets | Conceptual (fill timing distribution under budget) | high
Dependent link padding algorithms for low latency anonymity systems | Wei Wang, Mehul Motani, Vikram Srinivasan | 2008 | ACM CCS | 10.1145/1455770.1455812 | https://dl.acm.org/doi/10.1145/1455770.1455812 | yes | 2 | Low-latency anonymity systems | Passive traffic analyst | Dependent link padding with strict delay bound; indistinguishable flows | Bounded-delay release + cover traffic | sw+sim | Analysis + simulation | Anonymity-network model | O(log m) covering rate for full anonymity of m Poisson users | Bounded-delay-with-indistinguishability = our RTO-bounded normalization framing | Conceptual+metric (strict delay bound with indistinguishability) | high
The Loopix Anonymity System | Ania M. Piotrowska, Jamie Hayes, Tariq Elahi, Sebastian Meiser, George Danezis | 2017 | USENIX Security | NA | https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/piotrowska | yes | 2 | Anonymous messaging | Global passive (+active) adversary | Poisson mixing: independent exponential per-message delay + cover loops | Randomized per-message release (exponential) + cover traffic | sw+testbed | Prototype network of mix nodes | Deployed prototype | 300+ msg/s, <1.5ms mixing overhead, second-scale latency | Canonical randomized-release scheduler; second-scale latency unsuitable for control | Conceptual (release-time as privacy lever); shows randomized delay is averageable-adjacent | high
Stop-and-Go-MIXes Providing Probabilistic Anonymity in an Open System | Dogan Kesdogan, Jan Egner, Roland Buschkes | 1998 | Information Hiding (LNCS 1525) | 10.1007/3-540-49380-8_7 | https://link.springer.com/chapter/10.1007/3-540-49380-8_7 | yes | 2 | Mix networks | Passive global adversary | Per-message individual delay from a distribution within a time window | Randomized per-message release schedule | sw | Analysis | NA | Probabilistic anonymity via per-message delay windows | Earliest per-message randomized-release scheduler | Conceptual ancestor of randomized normalization | med
Timing Attacks in Low-Latency Mix Systems | Brian N. Levine, Michael K. Reiter, Chenxi Wang, Matthew Wright | 2004 | Financial Cryptography (LNCS 3110) | 10.1007/978-3-540-27809-2_25 | https://link.springer.com/chapter/10.1007/978-3-540-27809-2_25 | yes | 2 | Low-latency mix systems | Passive timing correlator | Defensive dropping against timing correlation | Bounded countermeasure + drops | sw+sim | Simulation | Mix simulation | Defensive dropping limits timing-correlation attacks | Shows i.i.d.-style timing countermeasures limited vs many-sample correlator | Supports RQ4 averageability argument | high
Predictive black-box mitigation of timing channels | Aslan Askarov, Danfeng Zhang, Andrew C. Myers | 2010 | ACM CCS | 10.1145/1866307.1866341 | https://dl.acm.org/doi/10.1145/1866307.1866341 | yes | 2 | General timing channels | Recipient observing output timing | Delay outputs to a predicted schedule; bound timing leakage | Scheduled release (predict-then-enforce) | sw | Prototype | NA | Bounded leakage; grows slowly (log) with run time | Formal backbone of release=max(ready,deadline) with provable bound | Directly reusable defense framework | high
Predictive mitigation of timing channels in interactive systems | Danfeng Zhang, Aslan Askarov, Andrew C. Myers | 2011 | ACM CCS | 10.1145/2046707.2046772 | https://dl.acm.org/doi/10.1145/2046707.2046772 | yes | 2 | Interactive multi-client systems | Clients observing response timing | Generalized predictive mitigation to request/response systems | Scheduled response release | sw | Prototype | NA | Bounds timing leakage across multiple clients | Extends predictive mitigation to request/response (our exact shape) | Directly reusable | high
A Provably Secure and Efficient Countermeasure against Timing Attacks | Boris Kopf, Markus Durmuth | 2009 | IEEE CSF | 10.1109/CSF.2009.21 | https://ieeexplore.ieee.org/document/5230634 | yes | 2 | Crypto timing side channels | Unknown-message timing attacker | Bucketing: quantize response time into k buckets; tunable leakage bound | Bucketed (quantized) release deadlines | sw | Analysis + implementation | NA | Leakage <= |O| log(n+1) bits; tunable trade-off | Bucketing = low-overhead instantiation of our size-decorrelation V4 | Directly reusable mechanism | high
Reducing Timing Channels with Fuzzy Time | Wei-Ming Hu | 1991 | IEEE S&P | 10.1109/RISP.1991.130768 | https://ieeexplore.ieee.org/document/130768 | yes | 2 | Covert timing channels (VAX VMM) | Colluding processes | Add noise to clocks/event timing (fuzzy time) | Randomized timing perturbation | sw | VMM implementation | Secure VMM | Reduces covert timing channel bandwidth | Foundational jitter approach; the randomization baseline averaging defeats | Supports RQ4 (jitter is averageable) | high
A pump for rapid, reliable, secure communication | Myong H. Kang, Ira S. Moskowitz | 1993 | ACM CCS | 10.1145/168588.168604 | https://dl.acm.org/doi/10.1145/168588.168604 | yes | 2 | MLS communication (ACK timing channel) | Colluding low/high processes | Buffer + release ACKs on moving-average of service times (decouple ACK timing) | ACK-release smoothing (moving average) | sw | Prototype (NRL Pump) | NA | Bounds the ACK-timing covert channel low<->high | Closest prior mechanism manipulating ACK timing to bound a leak | Strong precedent for smoothed ACK release; different threat | high
A Network Pump | Myong H. Kang, Ira S. Moskowitz, Daniel C. Lee | 1996 | IEEE Transactions on Software Engineering 22(5) | 10.1109/32.502225 | https://ieeexplore.ieee.org/document/502225 | yes | 2 | MLS networks (ACK timing) | Colluding processes + DoS | Network-scale Pump balancing covert channel vs congestion/fairness | Buffered ACK-release scheduling | sw | Prototype architecture | NA | Extends Pump to networks; bounds covert channel | Networked ACK-timing mitigation; congestion/fairness trade-off like our RTO budget | Precedent for network ACK-timing normalization | high
An information-theoretic and game-theoretic study of timing channels | James Giles, Bruce Hajek | 2002 | IEEE Transactions on Information Theory 48(9) | 10.1109/TIT.2002.801405 | https://ieeexplore.ieee.org/document/1027777 | yes | 2 | Abstract timing channels | Jammer/defender (delay budget) | Delay-jammer under max/avg-delay or buffer constraint; capacity min-max | Bounded-delay jamming (theory) | theory | Analysis | NA | Characterizes timing-channel capacity under delay budgets | Quantifies leakage surviving a delay/normalization budget (RQ4 theory) | Directly reusable theoretical framework | high
Opportunities and Limits of Remote Timing Attacks | Scott A. Crosby, Dan S. Wallach, Rudolf H. Riedi | 2009 | ACM Transactions on Information and System Security 12(3) | 10.1145/1455526.1455530 | https://dl.acm.org/doi/10.1145/1455526.1455530 | yes | 2 | Remote timing side channels | Remote passive timing attacker | Attack analysis: filtering network jitter by many-sample statistics | Attack (defeats jitter by averaging) | sw | Real network measurement | LAN/WAN | Extracts fine timing despite network jitter with enough samples | Direct evidence that additive jitter is averageable (RQ4) | Core support for normalization > jitter | high
Remote timing attacks are practical | David Brumley, Dan Boneh | 2005 | Computer Networks 48(5) (also USENIX Security 2003) | 10.1016/j.comnet.2005.01.010 | https://www.usenix.org/conference/12th-usenix-security-symposium/remote-timing-attacks-are-practical | yes | 2 | Remote crypto timing side channel | Remote passive attacker | Attack: extract RSA key via response-time timing | Attack (averages many timed queries) | sw | Real server measurement | LAN | Extracts private key over the network via timing | Practical proof remote timing attacks average out noise | Supports RQ4 averageability | high
ditto: WAN Traffic Obfuscation at Line Rate | Roland Meier, Vincent Lenders, Laurent Vanbever | 2022 | NDSS | 10.14722/ndss.2022.24326 | https://www.ndss-symposium.org/ndss-paper/ditto-wan-traffic-obfuscation-at-line-rate/ | yes | 2 | WAN encrypted traffic | Passive traffic analyst | Pad packets + inject chaff so obfuscated traffic independent of production | Constant-rate padding + chaff at line rate | hw | Intel Tofino programmable switch (P4, SDE 8.9) | Testbed, 100 Gbps | Runs at 100 Gbps line rate; negligible overhead to 70 Gbps | Closest platform/systems neighbor (Tofino in-network); NOT byte-preserving | Systems baseline; our byte-preserving/OT-specialized angle differentiates | high
Pacer: Comprehensive Network Side-Channel Mitigation in the Cloud | Aastha Mehta, Mohamed Alzayat, Roberta De Viti, Bjorn B. Brandenburg, Peter Druschel, Deepak Garg | 2022 | USENIX Security | NA | https://www.usenix.org/conference/usenixsecurity22/presentation/mehta | yes | 2 | Cloud tenant network traffic | Colocated tenant / passive observer | Shape guest traffic outside guest so shape is secret-independent | Deterministic traffic shaping (paced release + padding) | sw | Hypervisor + guest-kernel extension | IaaS cloud testbed | Eliminates network side channel end-to-end; respects flow/congestion control | "Shape independent of secret" = our exact goal; hypervisor padding, heavy | Conceptual+metric framing (secret-independent shape) | high
NetShaper: A Differentially Private Network Side-Channel Mitigation System | Amir Sabzi, Rut Vora, Swati Goswami, Margo I. Seltzer, Mathias Lecuyer, Aastha Mehta | 2024 | USENIX Security | NA | https://www.usenix.org/conference/usenixsecurity24/presentation/sabzi | yes | 2 | Network traffic (web, video) | Passive size/timing side-channel observer | Differentially private traffic shaping in a middlebox tunnel | DP-bounded padded release schedule | sw | Middlebox tunnel endpoints | Testbed (video stream, web) | DP guarantee with tunable privacy/bandwidth/latency trade-off | DP formalization + privacy-vs-overhead trade-off reusable for our Pareto | Directly reusable evaluation framing; mechanism pads | high
Random Segmentation: New Traffic Obfuscation against Packet-Size-Based Side-Channel Attacks | Mnassar Alyami, Abdulmajeed Alghamdi, Mohammed Alkhowaiter, Cliff Zou, Yan Solihin | 2023 | MDPI Electronics 12(18) | 10.3390/electronics12183816 | https://www.mdpi.com/2079-9292/12/18/3816 | yes | 2 | Encrypted TCP traffic | Passive packet-size analyst | Split large TCP segments into random-sized chunks (no dummy bytes) | Byte-preserving random segmentation (size axis) | sw | Software implementation | Testbed | Obfuscates packet-length distribution without added bytes | Very close to our CRC-boundary splitting (byte-preserving segmentation) | Direct comparison for the split primitive; size not timing | high

## BIBTEX

@article{lin2019raincoat,
  title={{RAINCOAT}: Randomization of Network Communication in Power Grid Cyber Infrastructure to Mislead Attackers},
  author={Lin, Hui and Kalbarczyk, Zbigniew T. and Iyer, Ravishankar K.},
  journal={IEEE Transactions on Smart Grid},
  volume={10},
  number={5},
  pages={4893--4906},
  year={2019},
  doi={10.1109/TSG.2018.2870362}
}

@inproceedings{formby2016whos,
  title={Who's in Control of Your Control System? Device Fingerprinting for Cyber-Physical Systems},
  author={Formby, David and Srinivasan, Preethi and Leonard, Andrew M. and Rogers, Jonathan D. and Beyah, Raheem A.},
  booktitle={Network and Distributed System Security Symposium (NDSS)},
  year={2016},
  doi={10.14722/ndss.2016.23142}
}

@inproceedings{lin2020defrec,
  title={{DefRec}: Establishing Physical Function Virtualization to Disrupt Reconnaissance of Power Grids' Cyber-Physical Infrastructures},
  author={Lin, Hui and Zhuang, Jianhui and Hu, Yih-Chun and Iyer, Ravishankar K. and Kalbarczyk, Zbigniew T.},
  booktitle={Network and Distributed System Security Symposium (NDSS)},
  year={2020},
  doi={10.14722/ndss.2020.24365}
}

@inproceedings{yang2020decied,
  title={{DecIED}: Scalable k-Anonymous Deception for {IEC61850}-Compliant Smart Grid Systems},
  author={Yang, Dianshi and Mashima, Daisuke and Lin, Wei and Zhou, Jianying},
  booktitle={Proceedings of the 6th ACM on Cyber-Physical System Security Workshop (CPSS@AsiaCCS)},
  pages={11--22},
  year={2020},
  doi={10.1145/3384941.3409592}
}

@inproceedings{lopezmorales2020honeyplc,
  title={{HoneyPLC}: A Next-Generation Honeypot for Industrial Control Systems},
  author={L{\'o}pez-Morales, Efren and Rubio-Medrano, Carlos and Doup{\'e}, Adam and Shoshitaishvili, Yan and Wang, Ruoyu and Bao, Tiffany and Ahn, Gail-Joon},
  booktitle={Proceedings of the 2020 ACM SIGSAC Conference on Computer and Communications Security (CCS)},
  pages={279--291},
  year={2020},
  doi={10.1145/3372297.3423356}
}

@article{barbosa2016exploiting,
  title={Exploiting traffic periodicity in industrial control networks},
  author={Barbosa, Rafael Ramos Regis and Sadre, Ramin and Pras, Aiko},
  journal={International Journal of Critical Infrastructure Protection},
  volume={13},
  pages={52--62},
  year={2016},
  doi={10.1016/j.ijcip.2016.02.004}
}

@article{radhakrishnan2015gtid,
  title={{GTID}: A Technique for Physical Device and Device Type Fingerprinting},
  author={Radhakrishnan, Sakthi Vignesh and Uluagac, A. Selcuk and Beyah, Raheem},
  journal={IEEE Transactions on Dependable and Secure Computing},
  volume={12},
  number={5},
  pages={519--532},
  year={2015},
  doi={10.1109/TDSC.2014.2369033}
}

@inproceedings{xiang2025tidf,
  title={{TIDF}: Timing-Based Device Fingerprinting for {PLCs}},
  author={Xiang, Lei and Han, Hao},
  booktitle={Network and Parallel Computing (NPC 2025), LNCS 16306},
  year={2025},
  doi={10.1007/978-3-032-10466-3_11}
}

@misc{jeon2016passive,
  title={Passive Fingerprinting of {SCADA} in Critical Infrastructure Network without Deep Packet Inspection},
  author={Jeon, Sungho and Yun, Jeong-Han and Choi, Seungoh and Kim, Woo-Nyon},
  year={2016},
  note={arXiv preprint, not peer-reviewed},
  doi={10.48550/arXiv.1608.07679}
}

@misc{ahmed2024timeconstant,
  title={Time Constant: Actuator Fingerprinting using Transient Response of Device and Process in {ICS}},
  author={Ahmed, Chuadhry Mujeeb and others},
  year={2024},
  note={arXiv preprint, not peer-reviewed},
  doi={10.48550/arXiv.2409.16536}
}

@article{kohno2005remote,
  title={Remote Physical Device Fingerprinting},
  author={Kohno, Tadayoshi and Broido, Andre and Claffy, K. C.},
  journal={IEEE Transactions on Dependable and Secure Computing},
  volume={2},
  number={2},
  pages={93--108},
  year={2005},
  doi={10.1109/TDSC.2005.26}
}

@article{sivanathan2019classifying,
  title={Classifying {IoT} Devices in Smart Environments Using Network Traffic Characteristics},
  author={Sivanathan, Arunan and Gharakheili, Hassan Habibi and Loi, Franco and Radford, Adam and Wijenayake, Chamith and Vishwanath, Arun and Sivaraman, Vijay},
  journal={IEEE Transactions on Mobile Computing},
  volume={18},
  number={8},
  pages={1745--1759},
  year={2019},
  doi={10.1109/TMC.2018.2866249}
}

@inproceedings{dyer2012peekaboo,
  title={Peek-a-Boo, I Still See You: Why Efficient Traffic Analysis Countermeasures Fail},
  author={Dyer, Kevin P. and Coull, Scott E. and Ristenpart, Thomas and Shrimpton, Thomas},
  booktitle={IEEE Symposium on Security and Privacy},
  pages={332--346},
  year={2012},
  doi={10.1109/SP.2012.28}
}

@inproceedings{cai2014systematic,
  title={A Systematic Approach to Developing and Evaluating Website Fingerprinting Defenses},
  author={Cai, Xiang and Nithyanand, Rishab and Wang, Tao and Johnson, Rob and Goldberg, Ian},
  booktitle={Proceedings of the 2014 ACM SIGSAC Conference on Computer and Communications Security (CCS)},
  pages={227--238},
  year={2014},
  doi={10.1145/2660267.2660362}
}

@inproceedings{cai2014csbuflo,
  title={{CS-BuFLO}: A Congestion Sensitive Website Fingerprinting Defense},
  author={Cai, Xiang and Nithyanand, Rishab and Johnson, Rob},
  booktitle={Proceedings of the 13th Workshop on Privacy in the Electronic Society (WPES)},
  pages={121--130},
  year={2014},
  doi={10.1145/2665943.2665949}
}

@inproceedings{wang2017walkietalkie,
  title={{Walkie-Talkie}: An Efficient Defense Against Passive Website Fingerprinting Attacks},
  author={Wang, Tao and Goldberg, Ian},
  booktitle={26th USENIX Security Symposium},
  pages={1375--1390},
  year={2017}
}

@inproceedings{juarez2016wtfpad,
  title={Toward an Efficient Website Fingerprinting Defense},
  author={Juarez, Marc and Imani, Mohsen and Perry, Mike and D{\'i}az, Claudia and Wright, Matthew},
  booktitle={European Symposium on Research in Computer Security (ESORICS), LNCS 9878},
  pages={27--46},
  year={2016},
  doi={10.1007/978-3-319-45744-4_2}
}

@inproceedings{gong2020front,
  title={Zero-delay Lightweight Defenses against Website Fingerprinting},
  author={Gong, Jiajun and Wang, Tao},
  booktitle={29th USENIX Security Symposium},
  pages={717--734},
  year={2020}
}

@article{holland2022regulator,
  title={{RegulaTor}: A Straightforward Website Fingerprinting Defense},
  author={Holland, James K. and Hopper, Nicholas},
  journal={Proceedings on Privacy Enhancing Technologies},
  volume={2022},
  number={2},
  pages={344--362},
  year={2022},
  doi={10.2478/popets-2022-0049}
}

@inproceedings{gong2022surakav,
  title={{Surakav}: Generating Realistic Traces for a Strong Website Fingerprinting Defense},
  author={Gong, Jiajun and Zhang, Wuqi and Zhang, Charles and Wang, Tao},
  booktitle={IEEE Symposium on Security and Privacy},
  pages={1558--1573},
  year={2022},
  doi={10.1109/SP46214.2022.9833722}
}

@inproceedings{sirinam2018deepfingerprinting,
  title={Deep Fingerprinting: Undermining Website Fingerprinting Defenses with Deep Learning},
  author={Sirinam, Payap and Imani, Mohsen and Juarez, Marc and Wright, Matthew},
  booktitle={Proceedings of the 2018 ACM SIGSAC Conference on Computer and Communications Security (CCS)},
  pages={1928--1943},
  year={2018},
  doi={10.1145/3243734.3243768}
}

@inproceedings{hayes2016kfp,
  title={k-fingerprinting: A Robust Scalable Website Fingerprinting Technique},
  author={Hayes, Jamie and Danezis, George},
  booktitle={25th USENIX Security Symposium},
  pages={1187--1203},
  year={2016}
}

@article{rahman2020tiktok,
  title={{Tik-Tok}: The Utility of Packet Timing in Website Fingerprinting Attacks},
  author={Rahman, Mohammad Saidur and Sirinam, Payap and Mathews, Nate and Gangadhara, Kantha Girish and Wright, Matthew},
  journal={Proceedings on Privacy Enhancing Technologies},
  volume={2020},
  number={3},
  pages={5--24},
  year={2020},
  doi={10.2478/popets-2020-0043}
}

@inproceedings{shmatikov2006timing,
  title={Timing Analysis in Low-Latency Mix Networks: Attacks and Defenses},
  author={Shmatikov, Vitaly and Wang, Ming-Hsiu},
  booktitle={European Symposium on Research in Computer Security (ESORICS), LNCS 4189},
  pages={18--33},
  year={2006},
  doi={10.1007/11863908_2}
}

@inproceedings{wang2008dependent,
  title={Dependent link padding algorithms for low latency anonymity systems},
  author={Wang, Wei and Motani, Mehul and Srinivasan, Vikram},
  booktitle={Proceedings of the 15th ACM Conference on Computer and Communications Security (CCS)},
  pages={323--332},
  year={2008},
  doi={10.1145/1455770.1455812}
}

@inproceedings{piotrowska2017loopix,
  title={The Loopix Anonymity System},
  author={Piotrowska, Ania M. and Hayes, Jamie and Elahi, Tariq and Meiser, Sebastian and Danezis, George},
  booktitle={26th USENIX Security Symposium},
  pages={1199--1216},
  year={2017}
}

@inproceedings{kesdogan1998stopandgo,
  title={Stop-and-Go-{MIXes} Providing Probabilistic Anonymity in an Open System},
  author={Kesdogan, Dogan and Egner, Jan and B{\"u}schkes, Roland},
  booktitle={Information Hiding (LNCS 1525)},
  pages={83--98},
  year={1998},
  doi={10.1007/3-540-49380-8_7}
}

@inproceedings{levine2004timing,
  title={Timing Attacks in Low-Latency Mix Systems},
  author={Levine, Brian N. and Reiter, Michael K. and Wang, Chenxi and Wright, Matthew},
  booktitle={Financial Cryptography (LNCS 3110)},
  pages={251--265},
  year={2004},
  doi={10.1007/978-3-540-27809-2_25}
}

@inproceedings{askarov2010predictive,
  title={Predictive black-box mitigation of timing channels},
  author={Askarov, Aslan and Zhang, Danfeng and Myers, Andrew C.},
  booktitle={Proceedings of the 17th ACM Conference on Computer and Communications Security (CCS)},
  pages={297--307},
  year={2010},
  doi={10.1145/1866307.1866341}
}

@inproceedings{zhang2011predictive,
  title={Predictive mitigation of timing channels in interactive systems},
  author={Zhang, Danfeng and Askarov, Aslan and Myers, Andrew C.},
  booktitle={Proceedings of the 18th ACM Conference on Computer and Communications Security (CCS)},
  pages={563--574},
  year={2011},
  doi={10.1145/2046707.2046772}
}

@inproceedings{kopf2009provably,
  title={A Provably Secure and Efficient Countermeasure against Timing Attacks},
  author={K{\"o}pf, Boris and D{\"u}rmuth, Markus},
  booktitle={22nd IEEE Computer Security Foundations Symposium (CSF)},
  pages={324--335},
  year={2009},
  doi={10.1109/CSF.2009.21}
}

@inproceedings{hu1991fuzzytime,
  title={Reducing Timing Channels with Fuzzy Time},
  author={Hu, Wei-Ming},
  booktitle={IEEE Symposium on Security and Privacy},
  pages={8--20},
  year={1991},
  doi={10.1109/RISP.1991.130768}
}

@inproceedings{kang1993pump,
  title={A pump for rapid, reliable, secure communication},
  author={Kang, Myong H. and Moskowitz, Ira S.},
  booktitle={Proceedings of the 1st ACM Conference on Computer and Communications Security (CCS)},
  pages={119--129},
  year={1993},
  doi={10.1145/168588.168604}
}

@article{kang1996networkpump,
  title={A Network Pump},
  author={Kang, Myong H. and Moskowitz, Ira S. and Lee, Daniel C.},
  journal={IEEE Transactions on Software Engineering},
  volume={22},
  number={5},
  pages={329--338},
  year={1996},
  doi={10.1109/32.502225}
}

@article{giles2002information,
  title={An Information-Theoretic and Game-Theoretic Study of Timing Channels},
  author={Giles, James and Hajek, Bruce},
  journal={IEEE Transactions on Information Theory},
  volume={48},
  number={9},
  pages={2455--2477},
  year={2002},
  doi={10.1109/TIT.2002.801405}
}

@article{crosby2009opportunities,
  title={Opportunities and Limits of Remote Timing Attacks},
  author={Crosby, Scott A. and Wallach, Dan S. and Riedi, Rudolf H.},
  journal={ACM Transactions on Information and System Security},
  volume={12},
  number={3},
  pages={17:1--17:29},
  year={2009},
  doi={10.1145/1455526.1455530}
}

@article{brumley2005remote,
  title={Remote timing attacks are practical},
  author={Brumley, David and Boneh, Dan},
  journal={Computer Networks},
  volume={48},
  number={5},
  pages={701--716},
  year={2005},
  doi={10.1016/j.comnet.2005.01.010}
}

@inproceedings{meier2022ditto,
  title={{ditto}: WAN Traffic Obfuscation at Line Rate},
  author={Meier, Roland and Lenders, Vincent and Vanbever, Laurent},
  booktitle={Network and Distributed System Security Symposium (NDSS)},
  year={2022},
  doi={10.14722/ndss.2022.24326}
}

@inproceedings{mehta2022pacer,
  title={Pacer: Comprehensive Network Side-Channel Mitigation in the Cloud},
  author={Mehta, Aastha and Alzayat, Mohamed and De Viti, Roberta and Brandenburg, Bj{\"o}rn B. and Druschel, Peter and Garg, Deepak},
  booktitle={31st USENIX Security Symposium},
  year={2022}
}

@inproceedings{sabzi2024netshaper,
  title={{NetShaper}: A Differentially Private Network Side-Channel Mitigation System},
  author={Sabzi, Amir and Vora, Rut and Goswami, Swati and Seltzer, Margo I. and L{\'e}cuyer, Mathias and Mehta, Aastha},
  booktitle={33rd USENIX Security Symposium},
  year={2024}
}

@article{alyami2023random,
  title={Random Segmentation: New Traffic Obfuscation against Packet-Size-Based Side-Channel Attacks},
  author={Alyami, Mnassar and Alghamdi, Abdulmajeed and Alkhowaiter, Mohammed and Zou, Cliff and Solihin, Yan},
  journal={Electronics},
  volume={12},
  number={18},
  pages={3816},
  year={2023},
  doi={10.3390/electronics12183816}
}

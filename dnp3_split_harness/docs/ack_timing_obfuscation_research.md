# ACK-Delay / Response-Timing Manipulation — Research Brief

_Scoping brief for the third obfuscation primitive (the timing axis). Synthesis of
DNP3-protocol, in-network-dataplane, evaluation-methodology, and research-framing
analyses, 2026-07-10. This is a research/design artifact — no code or spec has been
changed. The current phase rule (no CRC recompute, no field/length edit, no padding,
no proxy/MITM) still stands; nothing here is authorized to be built yet._

---

## 0. Bottom line

1. **"ACK delay" is a misnomer for what actually matters.** The real leak is the
   outstation's **processing time** — request→response ≈ 1.01 ms — and because this
   outstation **piggybacks the response on the TCP ACK for 9/9 requests**, the ACK
   time and the response time are the *same wire observable*. So the primitive is
   **response-time normalization**, not "delay the ACK."

2. **The contribution is normalization, not randomization.** Make many
   devices/configurations look alike (kill the processing-time fingerprint), rather
   than add entropy to mislead. This is the philosophical wedge that separates it
   from RAINCOAT (H. Lin et al., IEEE TSG — the advisor's own prior work, ref [3]),
   which randomizes acquisition/communication schedules to misdirect. Different
   locus, different leak, different mechanism.

3. **The single strongest, cheapest, most honest result is killing the
   size↔processing-time correlation** (drive mutual information `I(processing_time;
   response_size) → 0`). That is the actual device/database-size leak, and it can be
   removed at far lower added latency than full constant-time normalization.

4. **The binding safety constraint is TCP RTO (~200 ms), not any DNP3 timer.** Every
   DNP3 application/link timer in this stack is 5–60 s (verified against the OpenDNP3
   source in-repo). Overshoot the master's TCP retransmit timeout and you get spurious
   retransmits — which are the loudest tell to *both* a passive observer and a DNP3
   IDS. "Stay under RTO" is simultaneously the correctness bound and the stealth bound.

5. **Timing-only manipulation stays inside the byte-preserving phase.** It changes
   *when* bytes leave, never *which* bytes, so `b"".join(chunks) == response` still
   holds. The moment you must *synthesize* a DNP3 message (spoof a CONFIRM, forge a
   bare TCP ACK to decouple it from the held response) or *suppress* one, you leave the
   byte-preserving regime and become an active middlebox — out of scope this phase and
   a decision only Philip/Dr. Lin can authorize.

---

## 1. The WHAT — "ACK" disambiguated across every DNP3/TCP layer

"ACK" conflates several mechanisms. Verified against the OpenDNP3 community fork in
`/home/philip/Projects/opendnp3-community/`, only two of them exist on this wire:

| Mechanism | Layer | Present in this deployment? | Notes |
|---|---|---|---|
| **TCP ACK** (pure or piggybacked) | L4 / TCP | **Yes** — piggyback-dominant (9/9) | Response rides the ACK; ~0.24 ms to ACK, ~1.01 ms to respond |
| **Data-link confirmation** (CONFIRMED_USER_DATA + SEC_ACK) | L2 / DNP3 link | **No** — verified absent | OpenDNP3 transmits only `PRI_UNCONFIRMED_USER_DATA`; the confirmed-data formatter is compiled but never called. **There is no link-layer ACK to delay.** |
| **Transport function** | Transport | n/a | Segmentation/reassembly only; **no ack semantics** |
| **Application CONFIRM** (FC `0x00`) | L7 / DNP3 app | **Yes** — the multi-fragment handshake | Outstation sets the CON bit → master must CONFIRM before the outstation sends the next fragment. Also gates event-buffer flush. |
| **Unsolicited-response CONFIRM** | L7 / DNP3 app | **Off by default** | `allowUnsolicited=false`, `disableUnsolOnStartup=true` (verified). Not on the wire unless enabled. |
| **Link keep-alive** (REQUEST/RESPOND link status) | L2 / DNP3 link | Only when idle > 1 min | Not on the read path |

**Consequence:** the manipulable timing surface reduces to exactly two things —
**(a) the TCP-ACK-fused response time**, and **(b) the application CONFIRM handshake
timing** for multi-fragment reads. Everything else ("delay the link-layer ACK") does
not exist here.

---

## 2. The WHY — what the timing leaks, and to whom

Threat model (unchanged from the paper): a **passive on-path observer** doing
reconnaissance, reading unencrypted DNP3, not injecting or blocking. It fingerprints
the outstation from response **size, segmentation, and timing** without decoding the
payload.

What each timing signal leaks, ranked by fingerprint strength:

| Signal | Baseline | What it reveals | Strength |
|---|---|---|---|
| **Request→response (processing delay)** | 1.01 ms | Object-DB scan + encoding time — scales with **database size** and CPU; the *distribution tail* tracks **load**. Software outstation ⇒ ~1 ms; a PLC/RTU with thousands of points ⇒ 10–100 ms. | **Strongest** — device model + DB size + load in one signal |
| **Piggyback ratio** | 9/9 piggyback | Whether the response is ready before the delayed-ACK timer. High ⇒ fast software stack; an embedded RTU emits a pure ACK first, then a separate response (low ratio). | **Strong discriminator** — software vs embedded |
| **Fragment / frame / segment structure** | 9 APDU / 49 link / 20 TCP | `maxTxFragSize` (2048 B default), 250 B link user-data max, MSS packing; fragment count for a Class 0 read ∝ point count. | Strong — config + DB size |
| **Inter-fragment / continuation-after-CONFIRM delay** | — | How fast the outstation regenerates the next fragment after the CONFIRM ⇒ CPU + handshake signature. | Strong |
| **Request→ACK delay** | 0.24 ms | TCP-stack/NIC/OS turnaround. 0.24 ms ⇒ server-class Linux, **not** an embedded RTU. | Medium — stack class |
| **Master→outstation CONFIRM latency** | — | Master-side stack + RTT; less outstation-specific. | Weak–medium |

**The crown-jewel leak is the processing-delay-vs-database-size correlation.** It is
the one signal an attacker cannot get from static frame inspection, it is monotone in
DB size, and its *distribution* (not just mean) leaks the device model and its load.
The CRC-splitting primitive already reshapes the structure/inter-frame axis; the
timing primitive is the complementary lever on the **processing-time axis**, which is
exactly what "size, segmentation, **and timing**" in the paper's title has so far
under-delivered on.

---

## 3. The HOW — manipulation surface, primitives, and platform feasibility

### 3.1 What is byte-preserving (allowed) vs state-touching (forbidden this phase)

| Manipulation | Byte-preserving? | Verdict this phase |
|---|---|---|
| Delay / pace the response (and its piggybacked ACK) as a unit | Yes | **Allowed** — the core primitive, within RTO |
| Normalize inter-fragment gaps / continuation timing | Yes | **Allowed** — bounded by the 5 s app timer |
| Delay the master→outstation CONFIRM | Yes | Allowed but state-sensitive (< 5 s confirm timeout, < RTO to avoid retransmits) |
| Delay a link-layer confirm | — | **N/A** — no confirmed link service exists here |
| **Suppress** a CONFIRM/response | you send nothing | **Forbidden** — outstation aborts; for event data, the event buffer never flushes |
| **Synthesize/inject** a CONFIRM, keep-alive, or link status | **No** (new APDU + CRCs) | **Forbidden** — unauthorized DNP3 speaker, sequence desync |
| **Spoof a bare TCP ACK** to decouple it from a held response | **No** (injects a segment; rewrites ACK/seq) | **Forbidden this phase** — this is TCP splitting / proxy territory (see §4 and §6) |
| Reorder segments below DNP3 | Yes | **Useless + fragile** — TCP reassembles anyway and ≥3 out-of-order triggers fast-retransmit |

The byte-preserving lever is **hold / delay / pace of frames that already exist on the
wire.** Because the ACK is piggybacked on the response, holding the response
necessarily holds the ACK — which is what puts TCP RTO on the critical path. You cannot
decouple them without forging a TCP ACK, which leaves the byte-preserving regime.

### 3.2 Primitive taxonomy (what each kills, what it costs)

| Primitive | Kills which fingerprint | Latency cost | Residual leak |
|---|---|---|---|
| **Fixed added delay** | Shifts the *mean* of the processing-time signal | +Δ constant | Weak — variance/shape of the distribution still fingerprints |
| **Randomized jitter** (RAINCOAT-style) | Obscures a single sample | +E[jitter] + variance | Medium-weak — i.i.d. noise is **averageable**; an observer with many polls deconvolves it and recovers the mean |
| **Response-time normalization (constant-time / pad-to-deadline)** | **Eliminates** the processing-time leak | +(D − t_proc), D ≥ worst case | **Strong / information-theoretic** — zero processing-time info leaks; max latency |
| **Size-decorrelation** (delay so `t_resp ⟂ size`) | Kills the size↔time correlation (`I(T;S)→0`) | Lower than constant-time (removes only the correlation, not all variance) | **Strong and cheap — the punchline variant** |
| **Constant-rate / token-bucket pacing** | Burst shape + inter-frame rate | Queueing delay | Medium-strong on the rate/segmentation channel |
| **Inter-frame-gap normalization** | Segmentation-timing fingerprint | +gap padding | Pairs directly with CRC-splitting (defined on the frames splitting produces) |
| **ACK-timing normalization** | Request→ACK specifically | +hold on first segment | Strong; the clean version = delay the real segment (the forge-an-ACK version is forbidden) |
| **Intra-burst reordering** | Segmentation order | Reorder-buffer latency | **A trap** — triggers fast-retransmit; low value |

### 3.3 Platform feasibility (Tofino vs DPU vs the current replay server)

The two capability tiers map onto the two platforms:

- **Pacing / rate / inter-frame-gap control** (when frames leave *relative to each
  other*) is **native and cheap on Tofino 1** via the Traffic Manager (per-flow egress
  queue + max-rate shaper). Byte-preserving, spec-clean, low risk. **But TM shaping
  limits sustained rate, not first-packet latency** — a lone frame in an empty shaped
  queue leaves almost immediately, so this does **not** by itself normalize the
  first-response processing latency.

- **Per-packet absolute delay / response-time normalization** (hold a specific frame
  until a wall-clock deadline) is **not a native Tofino primitive** — the ASIC has no
  packet sleep, no per-packet buffer timer. It can be **emulated** with a self-clocked
  **recirculation + register-deadline loop** (store a 32-bit relative deadline in a
  SALU, recirculate the frame through a shaped queue until the deadline, then emit).
  This is non-idiomatic and resource-touchy, but — crucially — it is **affordable only
  because DNP3 is low-rate and small-frame** (see §4.3). It gives ms-scale holds with
  ~100 µs resolution.

- **On a DPU / SmartNIC** (NVIDIA BlueField Arm/DOCA, or Netronome Agilio NFP) you have
  real DRAM buffering and timers, so constant-time normalization and precise per-flow
  delay are **straightforward**. BlueField is the recommended clean home (and the
  natural place to *fuse* split + timing into one element); Netronome is viable but its
  toolchain is aging (good as a "does it generalize to a second target" data point, not
  the primary platform).

- **The current split-replay server is a replay *endpoint*, not an in-path proxy.** It
  *generates* the response bytes, so it schedules emission directly and has **no
  "hold a live packet" problem at all.** The existing `DEFAULT_CHUNK_DELAY_MS = 10` knob
  is exactly this. Generalizing it from a uniform per-chunk delay into a principled
  per-response schedule (constant-time / size-decorrelation / decoy-match) is a **pure
  software change requiring no data-plane hold** — this is the immediate, zero-hardware
  first deliverable.

Platform → primitive home:

| Primitive | Tofino 1 | BlueField DPU | Software replay server |
|---|---|---|---|
| Pacing, gap-normalization | **Native (best)** | Easy | Easy |
| Fixed / jitter delay | Emulated (recirc-hold) | **Native** | **Native (scheduling)** |
| Response-time normalization / size-decorrelation | Emulated, scrappy | **Native (best)** | **Native (scheduling)** |
| Fused split+timing (payload reconstruction) | No (can't store payload) | Yes | Yes |

---

## 4. The RISKS — correctness, safe envelope, compliance

### 4.1 The binding constraint is TCP RTO, not DNP3 timers

Verified OpenDNP3 defaults (community fork, this repo — file:line in the source):

| Timer | Default | Trips when |
|---|---|---|
| Master application response timeout | **5 s** | No response/next fragment in 5 s ⇒ task fails |
| Outstation solicited-confirm timeout | **5 s** | Master's CONFIRM missing ⇒ outstation **aborts the response to Idle, no retransmit** |
| Master task retry period | 5 s (→ 1 min max) | Delay before retrying a failed task |
| Outstation select timeout | 10 s | OPERATE must follow SELECT — not on the read path |
| Link confirmed-service timeout | 1 s | **Not exercised** (unconfirmed link only) |
| Link keep-alive | 1 min | Idle link |
| Max APDU / fragment | 2048 B | Governs the 9-fragment count |
| **TCP RTO (initial / min)** | ~1 s initial, **200 ms floor** (Linux `TCP_RTO_MIN`) | Unacked segment ⇒ **TCP retransmit** + backoff |

Every DNP3 timer is 5–60 s; **TCP RTO (~200 ms) fires two-plus orders of magnitude
sooner.** So the master spuriously retransmits at the TCP layer long before any DNP3
session timer notices.

### 4.2 Safe delay envelope

- Keep every per-segment hold **and** the cumulative added latency of a transaction
  **below the master's effective TCP RTO** — conservatively **< 200 ms** (verify the
  actual value on the master host Vision: `sysctl net.ipv4.tcp_retries2` and the RTO
  observed in a capture).
- Hard ceiling before the session actually fails: **5 s** (app response / confirm
  timeout).
- **Multi-fragment reads compound:** the CONFIRM handshake serializes fragments, so
  per-fragment delay adds up. `D_max per-fragment ≈ 5 s / n_fragments`, and each hop
  still must stay under RTO.
- The current **10 ms/chunk** default is safe by ~20× against RTO.
- **The failure you hit first — and the only one a passive observer sees — is TCP
  retransmission from overshooting RTO,** not a DNP3 session drop.

### 4.3 The "don't go too deep" rule, quantified

Dr. Lin's intuition (avoid deep multi-pass payload manipulation on an ASIC) is correct
in general and *inverted here* by DNP3's traffic class:

- Per-outstation offered load ≈ a few hundred bytes every ~1 s ≈ **single-digit kbps**
  (≈ 1e-7 of a 100 G recirc pipe).
- With hold time (ms) ≪ poll interval (≥ 1 s), the **expected number of
  simultaneously-held frames is < 1** per outstation; a 64–256-entry held-frame table
  is 1–2 orders of margin.
- Recirc bandwidth while held (100 µs self-clock, 200 B frame) ≈ 16 Mbps per held frame
  ⇒ ~10 held frames ≈ 0.16 % of a 100 G pipe. **Negligible.**
- Timing obfuscation needs only a **shallow parse** (5-tuple + optionally the first DNP3
  bytes to tell a response from an ACK) — no deep L7 walk, no field rewrite, no CRC
  recompute. This *is* the "classify shallow, hold cheap, modify nothing" discipline.

**The recirc-hold technique that is prohibitively expensive for data-center TCP is
cheap here precisely because DNP3 is low-rate and small-frame** — itself a
paper-worthy framing (in-network per-packet timing normalization is impractical in
general but tractable for OT/SCADA).

### 4.4 Spec-compliance and IDS visibility

- **Compliant (transparent latency element):** pure delay/hold/pace of existing frames.
  Valid CRCs, legal function codes, intact sequence, handshake still completes. IEEE
  1815 has no minimum-latency requirement. Same posture as CRC-splitting.
- **A correctness IDS (Zeek/Bro `dnp3` analyzer) is blind to timing-only manipulation** —
  it reassembles fragments and validates CRCs and sees a well-formed session. The one
  thing it *will* flag is **TCP retransmits** from overshooting RTO. So the RTO bound is
  a stealth requirement, not just a correctness one.
- **Non-compliant (forbidden this phase):** suppressing a required CONFIRM/response
  (breaks flow control / event-buffer flush), or injecting/synthesizing any DNP3 frame
  or a spoofed TCP ACK (unauthorized speaker, sequence desync; and under DNP3 Secure
  Authentication an injected APDU fails the HMAC and is logged).

---

## 5. The OPTIONS — evaluation design and a ranked build path

### 5.1 The sharpened adversary and the metrics that prove success

Adversary: passive, extracts a per-exchange timing feature vector (request→ACK,
request→response, piggyback indicator, inter-frame gap stats, CONFIRM latency,
fragment counts) aggregated per session, and runs one of three tasks — device-type
classification (T1), **database-size regression (T2 — the fully-real task)**, or
session linkage (T3) — with attacker models from a statistical matcher (A1) to a
supervised RF/GBM (A2) to a defense-aware deep classifier (A3).

Metrics:

- **(a) Classification-accuracy / AUC drop** — the gold standard; report Privacy Gain
  `= (Acc_native − Acc_obf)/(Acc_native − Acc_chance)`, with McNemar/DeLong significance.
- **(b) Distributional distance to a declared target** — Wasserstein-1 (in ms),
  Kolmogorov–Smirnov, Jensen–Shannon; toward a *declared target* (constant / uniform /
  decoy device).
- **(c) Mutual information `I(processing_time; size) → 0`** (KSG estimator + bootstrap
  CI), complemented by the interpretable **regression slope β and R²** — β is exactly
  what the T2 attacker exploits. **This is the fully-real, information-theoretic result
  that needs only one physical device** (vary its DB size to create the signatures).
- **(d) Correctness/transparency** — identical measurements, DNP3 CONFIRM, 0
  retransmits / 0 resets, byte-preservation asserted, no timeout (same bar as splitting).
- **(e) Cost** — added latency (mean/p95/max, and × the ~1 ms baseline), poll
  completion time, throughput, and timeout margin.

### 5.2 The policies to evaluate (the "options" as knobs)

- **B2 RAINCOAT-style pure randomization** (i.i.d. jitter, no target) — the head-to-head
  baseline.
- **V1 constant-hold** — max privacy, max latency.
- **V2 uniform-within-budget** — max emission-time entropy under a latency cap.
- **V3 decoy-match** — shape the timing distribution to *impersonate* a decoy device.
- **V4 size-decorrelation** — pad processing time to a size-independent schedule so
  `I(T;S)→0` at *lower* latency than V1. **The punchline: killing the DB-size leak is
  cheap; flattening the whole distribution is expensive.**

The core deliverable is the **privacy-vs-latency Pareto frontier** with a shaded **safe
operating region** = {added latency < RTO/timeout margin ∧ correctness = 100%}, and the
finding that V4 dominates B2 (equal privacy at lower latency, and B2's i.i.d. jitter
leaves a *residual* `I(T;S)` that V4 removes).

### 5.3 Ranked build path

| # | Option | Platform | Effort | Risk | Demonstrates |
|---|---|---|---|---|---|
| **0** | **Timing-policy scheduler in `split_server.py`** (generalize `chunk_delay_ms` → const/uniform/decoy/decorrelate) + extend `analyze_ack.py` (inter-frame gaps, CONFIRM latency, feature export) + an attacker/metrics module | Software (no hardware) | **Low** | **Low** | The honest first result: the leak, the normalization, `I(T;S)→0`, the timing budget, the Pareto — all byte-preserving, all rig-validatable now |
| **A** | TM queue pacing + inter-frame-gap normalization | Tofino 1 | Low | Low | In-network timing reshaping on the ASIC, byte-preserving; normalizes the segmentation-rate fingerprint. (Does **not** fix first-response latency) |
| **C** | First-segment response/ACK-timing normalization via recirc-hold | Tofino 1 | Medium | Medium | Kills the exact request→first-byte fingerprint measured (0.24/1.01 ms), on the ASIC |
| **B** | Full per-response constant-time normalization | Tofino 1 | Med-high | Med-high | The strong claim — information-theoretic processing-time closure on a fixed-function ASIC |
| **D** | Constant-time normalizer (+ optional fused split+timing) | BlueField DPU | Medium | Low (gated on hardware) | The clean reference implementation **and** the ground-truth baseline the Tofino approximations (A/C) are measured against |

Suggested sequence: **0 now** → A (validates in-network control) → C (hits the measured
signal) → B (the strong ASIC claim), with D on the DPU as a parallel track that doubles
as the correctness baseline.

---

## 6. Novelty and the RAINCOAT differentiation (read before drafting)

The overlap with RAINCOAT is real and a reviewer (or the advisor) will raise it. The
differentiation must be structural, not cosmetic. Three axes, strongest first:

- **A — Normalization vs randomization / device-identity vs grid-content.** RAINCOAT
  randomizes *when the control center acquires* to mislead an attacker about grid
  state/topology. This primitive normalizes *the outstation's per-exchange response
  latency* to suppress a **device-identity** leak (model/DB-size/load). Different locus
  (in-network bump-in-the-wire vs cooperating endpoints), different leak, different
  mechanism (indistinguishability/anonymity-set vs misdirection). **Lead with this.**
- **B — Transport-ACK decoupling as a device-agnostic in-network primitive.** Works for
  any TCP outstation without endpoint cooperation. *Caveat:* full decoupling rewrites
  seq/ack ⇒ proxy territory ⇒ a phase-rule decision (below).
- **C — Unifying size + segmentation + timing into one transparent byte-preserving
  layer.** The framing that elevates the whole paper from "a splitting trick" to "an
  in-network DNP3 obfuscation layer with three orthogonal knobs." Use as the paper's
  top-line; use A as this contribution's specific novelty.

Against generic traffic-shaping / website-fingerprinting defenses (WTF-PAD, Tamaraw):
the DNP3 CRC structure + live-master transparency is a constraint the WF literature
never faces — we cannot pad/reshape sizes without breaking CRCs, so **timing is the one
axis we can reshape without touching a byte.** That constraint *is* the contribution;
do not present it as "a WF defense ported to DNP3."

Composition note: the three-knob story is **split (working) + timing (working) + padding
(characterized-but-constrained)**. Per prior multi-CROB results, invalid-index padding
is *observable* (OUT_OF_RANGE) and cannot be cleanly inserted into a real control
transaction, so contribution 2 is honestly a **characterization / negative result**, not
a working padding primitive.

---

## 7. Decisions for Philip + Dr. Lin (not mine to make)

1. **Advisor / RAINCOAT framing.** Confirm Dr. Lin ↔ RAINCOAT and get sign-off on the
   "complementary, not competing; normalization not randomization" framing *before*
   drafting. Academically correct, socially delicate.
2. **Phase rule.** Restrict this contribution to **pass-through response-delay**
   (byte-preserving, tighter latency budget), or relax the rule to allow **ACK-decoupling
   / seq-ack rewrite** (proxy-adjacent, more capability). The current spec forbids
   proxy/MITM — this is a scope decision, not just technical.
3. **One paper or two.** Recommendation: **add the timing characterization + the
   software-validated normalization primitive + the timing budget to THIS paper now**
   (low marginal cost, makes the title's "and timing" honest); hold the **Tofino
   line-rate realization + a real multi-device classifier study** for a follow-on
   (a genuine data-plane systems result, NDSS/CCS/NSDI/ToN).
4. **Second device.** Can a second outstation stack (e.g., a different DNP3
   implementation, or the real SEL relay) be obtained for even a gestural cross-device
   result? It materially strengthens the evaluation.
5. **Target venue** for the current paper (drives journal adaptation): TSG/TDSC/ToN
   short vs a security workshop.

---

## 8. Recommended immediate next step

Build **Option 0** — the software timing-policy scheduler in `split_server.py` plus the
extended `analyze_ack.py` and a small attacker/metrics module — because it is
zero-hardware, byte-preserving, rig-validatable on the existing Vision↔Hulk setup, and
produces the honest headline results (the processing-time leak, `I(T;S)→0` under V4, the
measured timing budget, and the privacy-vs-latency Pareto) that make the paper's timing
claim real. Everything on Tofino/DPU is a follow-on that this de-risks first.

_First, though, decisions 1–3 above should be settled with Dr. Lin, since they change
what gets built and how it is framed._

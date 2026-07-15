# Agent C — Traffic-Analysis & Fingerprinting: Per-Observable Leak Map, Residual Fingerprints, and Attacker Design

**Scope (analysis only, no code changed):** RQ1 per-observable leak map on the three
taxonomy axes; RQ2 what each mechanism (split / pad / timing-normalization) closes, what
**remains**, and what **new** fingerprints it creates; RQ3 the strongest attacker set.
Feeds `split_analysis.md`, `timing_analysis.md`, `combined_decision_policy.md`, and the
attacker ladder in `evaluation_plan.md`. Builds on `agent_A_traffic_analysis_literature.md`
(102-paper matrix) — I reuse its citekeys and do not re-derive its results.

**Evidence tags:** **[M]** measured on this rig · **[S]** DNP3/TCP standard · **[V]** vendor doc ·
**[P]** paper-reported (abstract/landing-page only) · **[I]** inference · **[H]** hypothesis.

---

## Verdict (lead with the outcome)

1. **The size channel is the dominant residual leak, and none of the three byte-preserving
   mechanisms closes it.** Total transaction bytes encode CROB count at **14.6 B/CROB,
   R²=0.9999** [M] and read-plane point count at **~5.7 B/analog point** [M]. Split preserves
   total bytes exactly (sum-the-chunks) [M]; timing normalization touches only *when*, not
   *how many bytes*; safe in-band DNP3 padding does not exist yet (invalid-index CROB is a
   proven dead end) [M]. **Only a future padding phase can close the size leak.**
2. **Timing normalization is the only leak our current tools fully close** (the
   req→first-response CLRT channel), and it is closeable **only against the right attacker
   class**: additive i.i.d. jitter is **averageable** (AT-2), class-independent normalization
   is **not** — this is a testable, publishable dichotomy, not an assertion.
3. **Every mechanism, applied to one device with fixed parameters, manufactures a *new*
   "I-am-defended" fingerprint** (a shaped "beacon"). A fixed split emits a deterministic
   chunk train; a fixed deadline emits a constant-time answer; both are separable from
   un-shaped peers by a detection attacker (AT-4) even when they hide the secret. The
   defense's *presence*, not just its content, is a leak — and a lone defended device is
   plausibly the *critical* device, so beacon-detection is itself reconnaissance.
4. **DNP3 semantics leak in plaintext and are out of scope for all three mechanisms.** Timing
   normalization does **not** hide visible payload content; FC, object/variation, and CROB
   indices are read directly off the wire. Closing that needs encryption or a protocol change
   (future phase).

_Plain language: counting the bytes is the attack that beats everything we can do today.
Splitting reshuffles packets but not the byte total; normalizing timing kills the "how long"
leak but not the "how many bytes" leak or the plaintext contents; and a device that is
obviously being shaped stands out from the ones that aren't._

---

## RQ1 — Per-observable leak map (three axes)

For each observable: **what it leaks** → **evidence tag**. Grounded on our rig measurements
where possible; leaks that are structural but unmeasured are marked [I]/[H].

### Axis 1 — SHAPE / SIZE (the loud channel)

| Observable | What it leaks | Tag |
|---|---|---|
| **Total bytes / transaction** | Transaction magnitude → **CROB count** (14.6 B/CROB, R²=0.9999, 37→256 B for N=1→16) on the control plane [M]; **point count** (~5.7 B/analog pt; 129→1211 B for 10→200 pts) on the read plane [M] → **device DB configuration/complexity** and operational payload size. **The single cleanest leak.** | [M] |
| **Largest packet** | Natively capped by DNP3 (292 B max link frame [M]) / app fragment (~250 B) / TCP MSS (1448 [M]) → weak native leak (whether the response exceeds one frame = a magnitude threshold). **After split it inverts**: an unnaturally small max frame (≤18 B at bpc=1 [M]) becomes a *defense* fingerprint. | [M]/[I] |
| **Size distribution (per-packet histogram)** | Native: device fragmentation config (clusters at 292 B). **After split: the chunk-size histogram is a defense signature** (uniform ≤18 B). | [M]/[I] |
| **#packets** | Transaction magnitude (more points → more frames/segments): large READ = **20 TCP segments** for 12,204 B [M]. Correlated with total bytes but also with the split/pacing policy. | [M] |
| **App-fragment count** | Magnitude vs the DNP3 ~250 B app-fragment limit: **9 app fragments** for 12,204 B [M] → DB size + configured max fragment size. | [M] |
| **DNP3 link-frame count** | Total bytes / 292: **49 link frames** for 12,204 B [M]. Protocol-capped frame size makes this the **cleanest structural proxy for payload size**. | [M] |
| **TCP-segment count** | Total bytes / MSS **plus TCP stack behavior** (GSO/TSO/coalescing). 20 segments for 12,204 B; **DNP3 frame and TCP segment boundaries do not align** [M] → leaks the stack, not only the payload. | [M] |

_Plain language: the byte total, and every count that tracks it (frames, fragments, segments),
tells the observer how many points or CROBs the device handles and roughly how big its
database is. This is the leak the whole study is fighting._

### Axis 2 — TIMING

| Observable | What it leaks | Tag |
|---|---|---|
| **req→first-response** | **Processing time → CROB count** (SELECT 0.179 ms/CROB R²=0.9985; OPERATE 0.214 ms/CROB R²=0.9954 [M]); large READ req→response 1.014 ms [M]. → device-**configuration** complexity, CPU/network load, device impl. This is the CLRT fingerprint Formby established [P, formby2016whos]. **Caveat: n=1 per N-level; one device; CROB-count ≠ DB-size.** | [M]/[P] |
| **Inter-packet gap** (inter-chunk / frame / segment) | Native: device frame-emission cadence + TCP timers (Nagle/delayed-ACK). **After split/pacing: the imposed gap is the defense's timing fingerprint.** | [M-partial]/[I] |
| **Burst duration / response completion time** | ≈ #frames × gap + processing → magnitude + processing time. | [M-partial]/[I] |
| **CONFIRM→next-fragment** | Device inter-fragment processing latency for multi-fragment responses (present in our CONFIRM-triggered continuation path [M]) → device impl + load. | [M]/[I] |
| **Transaction duration** | Total work = processing + transmission → magnitude. For SBO, SELECT+OPERATE round trips → also **control semantics** (SBO vs direct) and operator dwell for real controls. | [M]/[I] |
| **Polling interval** | Master's **acquisition cadence / poll schedule**, **role** (which master polls which outstation), **operational state** (event bursts perturb cadence). ICS traffic is highly periodic/predictable [P, barbosa2016exploiting] → many clean repeated samples. | [P]/[I] |
| **Silence duration** | Operational state (quiescent vs active); post-shaping, the boundaries of shaped bursts. | [I] |

_Plain language: how long the device takes to answer leaks how many points/CROBs it is handling
(the same secret the size channel leaks); how often it is polled leaks the control schedule and
who is talking to whom. Because SCADA polls on a fixed clock, the attacker gets many clean
repeats to average over._

### Axis 3 — SEMANTICS / SAFETY (plaintext — out of scope for all three mechanisms)

DNP3 is unencrypted, so these are read **directly off the wire**. **Timing normalization,
split, and (non-tunnel) padding do NOT hide any of them.**

| Observable | What it leaks | Tag |
|---|---|---|
| **Function code (type)** | Transaction type directly: READ / SELECT / OPERATE / CONFIRM / unsolicited → monitoring vs control vs event. | [M]/[S] |
| **Object group / variation** | Point types (binary, analog, counter, CROB) → device role and what is being read/actuated. | [S] |
| **CROB indices / count / point indices** | Number **and identity** of controlled points, visible per-index; even **OUT_OF_RANGE (12) / TOO_MANY_OPS (8)** statuses are visible per index [M]. | [M] |
| **Internal indications (IIN)** | Device operational state (restart, buffer overflow, need-time, class-events-pending). | [S] |
| **Link/transport addresses** | Role (master=1, outstation=10) and topology. | [M]/[S] |
| **Physical criticality** | **NOT leaked by any DNP3 field** — operation *type* is visible, physical *criticality* is not; requires an operator allowlist (per GROUNDING safety constraint). | [S]/[I] |

_Plain language: because DNP3 is not encrypted, the packet literally says "READ" or "OPERATE
breaker N," and no timing or splitting trick hides that. Semantic leakage is conceded here — it
belongs to a future encryption/protocol phase._

---

## RQ2 — What each mechanism closes, what REMAINS, and what NEW fingerprint it creates

### Consolidated table

| Mechanism | Closes | **Remains (residual leak)** | **New fingerprint it creates** |
|---|---|---|---|
| **SPLIT** (CRC-boundary, byte-preserving) | per-packet size, native size distribution, native #packets | **Total bytes (sum-the-chunks) → CROB/point count [M]**; processing time (split is downstream of it); all semantics | **Chunk count / chunk-size train** (fixed bpc → deterministic ⌈frames/bpc⌉ = 141/71/36/18 [M]); **packet-count inflation** (301/161/91/55 pkts [M]); unnaturally small max frame; fixed inter-chunk gap if paced |
| **PAD** — *no safe byte-preserving DNP3 padding exists yet* [M] | (hypothetically) total bytes / size distribution → could hide CROB/point count | Semantics (padding ≠ encryption); processing time unless also timed | Fixed target size → over-uniform "shaped" size; cover/decoy transactions add count+timing structure that must match a plausible device; out-of-DNP3 padding may be stripped/flagged by a Zeek `dnp3` IDS |
| **TIMING NORMALIZATION** (release at max(ready, req+target)) | **req→first-response CLRT channel**; inter-packet gaps if normalized; completion time | **Total bytes / size channel → CROB/point count [M]** (touches *when*, not size); **all semantics** (does NOT hide payload content); master's polling interval if only outstation release is normalized | Constant/bucketed release deadline → a device that always answers exactly on the deadline (or at k discrete times) is separable from an un-normalized device; absence of timing variance is itself detectable |

### Detail and the load-bearing negatives

- **Split does not reduce total-volume leakage.** `Σ chunks == original` [M], so CROB count
  (14.6 B/CROB) and point count (5.7 B/pt) survive split intact. Worse, at **bpc=1 the chunk
  count equals the original CRC-block count (141)**, which is itself ∝ total bytes — so split
  **re-leaks size through the chunk count** even without reassembly. [M]/[I] Split's honest role
  is reshaping the *per-packet size distribution* and defeating a naive largest-packet or
  fixed-segment-count classifier, **not** hiding magnitude.
- **Timing normalization and size leakage are orthogonal.** This is the central asymmetry of
  the whole study: **timing is closeable now, size is not.** A timing normalizer drives
  I(processing_time; class)→0 but leaves I(total_bytes; class) at its measured R²=0.9999. [M]/[I]
- **Padding is the only lever that could close the size residual, and it is future work.**
  In-band invalid-object padding fails (OUT_OF_RANGE; partial SELECT blocks OPERATE) [M]. Any
  workable padding (tunnel / cover traffic / out-of-DNP3) is a protocol-modifying phase and
  imports the WF-defense problem of making the padded profile match a *plausible* device rather
  than an over-uniform tell.
- **New "beacon" fingerprints are the reviewer's counter-attack.** Combining split + timing on
  **one** device with **fixed** parameters produces two constant signatures (a fixed chunk
  train and a fixed answer clock). Wang et al. showed obfuscation systems are themselves
  detectable by DPI/traffic analysis at low false-positive rates [P, wang2015seeing]; the same
  logic applies here (AT-4). **Design consequence: shape fleet-wide and/or match a decoy-device
  profile — never shape a lone device with static parameters.**

_Plain language: splitting hides nothing that matters (byte total survives, and the chunk count
can even re-leak the size); normalizing timing kills the "how long" leak but not the "how many
bytes" leak or the plaintext; padding is the only thing that could hide the byte count and we
can't do it safely yet; and any of these, done to one device with fixed settings, makes that
device obviously "the shaped one."_

---

## RQ3 — Strongest attacker set (feeds the A1–A8 ladder)

Threat model baseline for all: **passive, on-path, single-vantage observer.** Because DNP3 is
plaintext, a trivial attacker reads FC/CROB count directly (Axis 3); the attackers below are
the ones our **byte-preserving metadata mechanisms are actually meant to defeat** — they use
**only size / timing / count metadata**, which is (a) the future encrypted-payload case and
(b) the cross-transaction configuration-inference case that survives even plaintext.

### AT-1 — Sum-the-chunks size attacker *(the primary reviewer attack; defeats SPLIT)*
- **Feature vector:** `[ Σ(O→M payload bytes) per transaction, largest frame, app-fragment count ]`.
- **Assumptions:** can delimit transaction boundaries via visible request FCs or silence gaps; no repetition needed.
- **Effect:** defeats split **completely** — total bytes are split-invariant [M] → recovers CROB count (14.6 B/CROB) and point count (5.7 B/pt). Timing normalization does not touch it. **Only padding stops AT-1.**

### AT-2 — Repeated-poll averaging attacker *(defeats additive jitter; the timing-claim test)*
- **Feature vector:** sample mean `T̄_c = (1/n) Σ req→first-response` over n identical polls of class c; per-class mean vector.
- **Assumptions:** SCADA fixed poll schedule → many clean repeats of the same class [P, barbosa2016exploiting]; class identifiable by FC or size.
- **Hypothesis under test [H]:** additive i.i.d. jitter `J` (mean μ, var σ²) → `T̄_c → T_c + μ` with error ∝ σ/√n → **T_c (hence CROB count) recovered as n grows** (Crosby [P, crosby2009opportunities]; Brumley–Boneh [P, brumley2005remote]). A **class-independent** normalizer makes the released-time distribution the same for every class → `T̄_c → target` for all c → **not averageable**.
- **Measurable prediction:** attacker AUC vs n — **jitter rises toward 1**; **normalization stays flat at 0.5**. Residual `I(T; class)` → jitter: >0 and n-insensitive in the limit; normalization: →0. **This is the experiment that justifies "normalize, don't jitter."**

### AT-3 — Packet-count + timing structural attacker *(defeats fixed split / fixed pacing)*
- **Feature vector:** `[ #packets, #chunks, chunk-size histogram, inter-chunk-gap distribution, burst duration, largest frame ]`.
- **Assumptions:** passive; **single transaction suffices** (structural, no averaging).
- **Effect:** a **fixed-bpc** split yields a deterministic chunk count = ⌈frames/bpc⌉ (141/71/36/18 [M]); since the native frame count ∝ size, **chunk count re-leaks magnitude** and the fixed gap/uniform chunk size fingerprint the *defense configuration*. Defeated only by randomizing split granularity/pacing per transaction, or by padding to a common count.

### AT-4 — Shaped-vs-unshaped detector *("beacon" / defense-detection attacker)*
- **Feature vector:** regularity/variance features — `[ CoV(req→response), presence of a fixed release deadline, chunk-size uniformity, constant inter-packet-gap indicator, size-distribution entropy ]`.
- **Assumptions:** passive; **open-world** (shaped and unshaped devices coexist on the segment).
- **Goal:** not to read the secret but to **identify which devices run the defense.** Anchored on Wang et al., who detect protocol obfuscation at low false-positive rates against background traffic [P, wang2015seeing]. A lone shaped device is separable from unshaped peers, and the shaped device is plausibly the *critical* one → **beacon-detection is reconnaissance in itself.**
- **Mitigation implication:** fleet-wide deployment and/or decoy-profile matching; never static shaping of one device.

### AT-5 — Defense-aware deep classifier *(the upper-bound / ceiling attacker)*
- **Feature vector:** raw packet-size + directional inter-arrival sequence fed to a CNN — Deep Fingerprinting [P, sirinam2018deepfingerprinting] / Tik-Tok [P, rahman2020tiktok] style; trained **on shaped traffic** (Carlini defense-aware discipline, already in matrix).
- **Assumptions:** knows the defense, has labeled shaped traces; **closed-world** (few device classes — realistic for SCADA).
- **Purpose:** the ceiling. If a class-independent normalizer + size padding truly drives
  I(features; class)→0, even AT-5 is at chance; **any residual it exploits will be the size
  channel** (AT-1's feature surviving inside AT-5). **Open-world honesty:** Juarez et al. show
  WF attacks succumb to the base-rate fallacy in open-world settings [P, juarez2014critical] —
  **but SCADA is near-closed-world** (few device types, fixed schedule, no user diversity), so
  that escape hatch is *weaker* here and the attacker is correspondingly *stronger*. **SCADA is
  harder to defend than the web on exactly this axis** — state this explicitly rather than
  borrowing WF's optimism.

### AT-6 — Cross-transaction configuration profiler *(survives split AND timing normalization)*
- **Feature vector:** aggregate of response sizes across transaction types over time (integrity-poll, event, range-read sizes) → total DB point count / device **configuration**.
- **Assumptions:** long passive observation.
- **Effect:** recovers device **configuration/complexity** (not identity — one-device caveat) from the size channel; unaffected by split (sum) and timing normalization (size untouched). Reinforces that **only padding closes the size-based config leak.**

### Attacker → mechanism defeat matrix

| Attacker | Beats SPLIT? | Beats TIMING-NORM? | Beaten by (needs) |
|---|---|---|---|
| AT-1 sum-the-chunks | **Yes** (size invariant) | Yes (size untouched) | **Padding** |
| AT-2 poll-averaging | n/a (timing) | **Yes vs jitter; No vs class-indep. norm** | **Class-independent** normalization |
| AT-3 count+timing structural | **Yes** (fixed split) | partial | Randomized granularity / padding-to-count |
| AT-4 beacon detector | **Yes** (creates the tell) | **Yes** (creates the tell) | Fleet-wide + decoy-profile matching |
| AT-5 deep defense-aware | via residual size | via residual size | I(features;class)→0 on **all** axes (needs padding) |
| AT-6 config profiler | **Yes** (size) | **Yes** (size) | **Padding** |

_Plain language: the strongest cheap attacker just adds up the bytes (AT-1) and beats splitting
outright; the strongest timing attacker averages many polls (AT-2) and beats random jitter but
not true normalization; a detector can spot the shaped device itself (AT-4); and a deep or
long-horizon attacker (AT-5/AT-6) mops up whatever size leak is left. Four of the six are only
stopped by padding, which we cannot do safely yet — so the honest headline is that our current
tools close the timing axis and leave the size axis open._

---

## Single most important caveat

The whole positive story is **timing-only**. Split and timing normalization leave the
**measured size leak (14.6 B/CROB, R²=0.9999; 5.7 B/pt) fully intact** [M], and four of six
attackers (AT-1, AT-3-partial, AT-5-residual, AT-6) win on that channel; closing it needs a
**future padding phase** that does not yet exist safely. Do not let the clean timing result
(AT-2) imply the size problem is solved — it is the study's honest negative.

---

## NEW_PAPER_MATRIX_ROWS
Seeing through Network-Protocol Obfuscation | Liang Wang, Kevin P. Dyer, Aditya Akella, Thomas Ristenpart, Thomas Shrimpton | 2015 | ACM CCS | 10.1145/2810103.2813715 | https://dl.acm.org/doi/10.1145/2810103.2813715 | yes | 2 | NA | Passive DPI/traffic analyst detecting circumvention | Detects protocol obfuscators (obfs, FTE, meek) via traffic analysis | NA | sw | Framework over real traffic captures | Real network captures | Obfuscation tools detectable at low false-positive rate vs background traffic | Detection of obfuscation, not a defense; motivates the shaped-vs-unshaped/beacon attacker (AT-4) | Academic anchor that a shaping defense is itself fingerprintable — the AT-4 "beacon detector" threat | high
A Critical Evaluation of Website Fingerprinting Attacks | Marc Juarez, Sadia Afroz, Gunes Acar, Claudia Diaz, Rachel Greenstadt | 2014 | ACM CCS | 10.1145/2660267.2660368 | https://dl.acm.org/doi/10.1145/2660267.2660368 | yes | 2 | Tor web traffic (WF) | Passive WF attacker (realistic open-world) | Attack-evaluation critique: base-rate fallacy, open-world, drift | NA | sw | Simulation over WF datasets | WF dataset | WF attacks succumb to base-rate fallacy in open-world; verification cuts FPs >63% but does not solve it | Attacker-realism discipline for AT-5; SCADA is near-closed-world so this escape hatch is weaker (attacker stronger) | high

## NEW_BIBTEX
@inproceedings{wang2015seeing,
  title={Seeing through Network-Protocol Obfuscation},
  author={Wang, Liang and Dyer, Kevin P. and Akella, Aditya and Ristenpart, Thomas and Shrimpton, Thomas},
  booktitle={Proceedings of the 22nd ACM SIGSAC Conference on Computer and Communications Security (CCS)},
  pages={57--69},
  year={2015},
  doi={10.1145/2810103.2813715}
}

@inproceedings{juarez2014critical,
  title={A Critical Evaluation of Website Fingerprinting Attacks},
  author={Juarez, Marc and Afroz, Sadia and Acar, Gunes and D{\'i}az, Claudia and Greenstadt, Rachel},
  booktitle={Proceedings of the 2014 ACM SIGSAC Conference on Computer and Communications Security (CCS)},
  pages={263--274},
  year={2014},
  doi={10.1145/2660267.2660368}
}

<!-- Deliverable authored by Agent I (statistical evaluation & optimization; includes the multi-objective optimization / Pareto section) for the split/pad/timing combined-policy study (2026-07-13), grounded in GROUNDING.md + measured_evidence.md, building on the prior ack_timing_normalization package, and integrated by the synthesizing lead. Research/design only — no source code changed. Citations merged into paper_matrix.csv (new works) + bibliography.bib. Reviewed in the Agent-J skeptical pass; surviving caveats in research_gaps_and_novelty.md. -->

<!-- Deliverable authored by Agent I (statistical-evaluation & optimization specialist) on the
split/pad/timing combined-policy study (2026-07-13), grounded in GROUNDING.md + measured_evidence.md
and EXTENDING research/ack_timing_normalization/evaluation_plan.md (Agent F: attacker ladder A1–A8,
claim ladder C1–C3, metrics). Research/design artifact only — NO harness source code was changed.
Every NEW cited work is verified and appears in ## NEW_PAPER_MATRIX_ROWS + ## NEW_BIBTEX. Evidence
labels: [M] measured-this-rig · [S] standard · [V] vendor-doc · [P] paper-reported · [I] inference ·
[H] hypothesis. A plain-language line follows each technical block. -->

# Agent I — Evaluation Methodology, Overhead Model, and Multi-Objective Optimization for the Combined Split + Pad + Timing DNP3 Policy
## (Spec §13 overhead model + §14 optimization; extends Section 10 / `evaluation_plan.md`)

_Design-only. This report does NOT redo Agent F's timing-only plan — it inherits A1–A8, C1–C3, and
the metric machinery, and extends them to the combined policy, where **split** and **pad** move
leakage onto the SHAPE/SIZE axis (Axis 1) that a timing-only plan barely touched. All rig numbers
are the measured facts in `measured_evidence.md`: size↔CROB **14.6 B/CROB, R²=0.9999 (n=1/N)**;
timing↔CROB **0.179/0.214 ms/CROB, R²>0.99 (n=1/N)**; split **2407 B / 141 CRC blocks →
141/71/36/18 chunks** (bpc 1/2/4/8), byte-preserving, 0 retransmit/reset; **no safe DNP3 padding
demonstrated (negative)**. Methodology citations reused from the matrix are named inline._

---

## 0. Bottom line for the lead (what I add beyond Agent F)

1. **Split does NOT reduce N-leakage — it RELOCATES it from byte-size to packet-count, and adds real
   wire-bandwidth cost through headers.** [M-grounded/I] With a class-independent chunk policy,
   `n_chunks = ⌈n_crc_blocks / bpc⌉` is a deterministic monotone function of response size, hence of
   N. So `I(packet_count; N) ≈ I(size; N)` after splitting: the R²=0.9999 leak simply changes axis.
   To actually hide N on the shape axis you need a **fixed, N-independent chunk count** — i.e.
   dummy chunks — which is **padding = future phase**. This is the single most important
   combined-policy finding and it is a NEGATIVE one. It must anchor the paper's honest scope.
2. **The combined policy needs two attackers Agent F did not have.** **A9 (sum-the-chunks)** reverses
   split by summing per-packet sizes to recover total bytes — it demonstrates that split leaves
   total-byte leakage untouched (measured invariant). **A10 (detect-the-defense / distinguish-shaped)**
   is the "beacon" attacker: a 141-chunk response where native is 9 frames is trivially separable, so
   an aggressively-split or held-then-released device becomes MORE identifiable, not less. Both are
   primary for the combined claim.
3. **The leakage must be decomposed across three carriers, not one.** Report the joint residual
   `I((T, Σ_bytes, Π_packets); S)` AND the five marginals/conditionals — `I(T;S)`, `I(Σ;S)`,
   `I(Π;S)`, **`I(T;S|Σ)`** (Agent F's timing-defense target) and **`I(Σ;S|T)`** (the size residual
   the study is named for). A timing-only readout silently hides that size and packet-count still
   leak N.
4. **The target-selection variable is formalized and made checkable.** Policy may depend on the
   observable, safety-required **function-code class Y** (READ / event / SELECT / OPERATE / …) but
   MUST NOT depend on the secret **S = (N, DB-size, device)**. Verify with a self-leak test:
   `I(policy_choice ; S | Y)` must sit in a permutation-null band. A policy whose own parameters
   encode N is a self-inflicted leak.
5. **Overhead is a parametric model, not a single number, and split+timing latency is NOT additively
   independent** — the first-response hold and the inter-chunk pacing both consume the same TCP-RTO
   budget and must be constrained *cumulatively*. §9 gives the model; §10 turns it into a
   constrained multi-objective program with an **uncertainty-aware Pareto frontier** (objectives are
   noisy attacker estimates, so dominance uses CIs) and **per-platform operating points**
   (software / Tofino / DPU / FPGA) via ε-constraint + NSGA-II/III (pymoo), compared by hypervolume.

**Plain language:** cutting a response into more packets does not hide how big it was — the packet
count now gives it away, and you pay in extra headers. Only inserting fake data (padding, a future
step) can hide size, and no safe way to do that in DNP3 has been found yet. My job is to measure all
of this honestly and to pick the best knob settings per hardware platform without cheating on the
secret.

---

## 1. What I inherit vs. what I add (scope map)

| From Agent F (`evaluation_plan.md`) — REUSE unchanged | Agent I adds (this report) |
|---|---|
| Attackers A1–A8 (threshold → GBM → 1D-CNN → defense-aware A7 → averaging A8) | **A9 sum-the-chunks**, **A10 detect-the-defense/distinguish-shaped**, and a **packet-count-only** attacker variant |
| Claim ladder C1 (timing leak+closure, 1 device), C2 (policy Pareto), C3 (device-type, ≥2 stacks) | **C4** (size/packet-count residual — negative), **C5** (combined-policy correctness), **C6** (detectability/beacon), **C7** (per-platform operating points) |
| Metrics: β/R²/MAE, KSG MI, `I(T;N|size)`, W1/KS/JS, PG, McNemar/DeLong, TOST, BH-FDR | **packet-count leakage**, **total-byte leakage**, **profile-bypass leakage**, **policy self-leak** `I(choice;S|Y)`, and the 3-carrier information decomposition |
| Timing policies P0–P8 on one axis | **Combined modes CM0–CM5** = {split bpc, split gap-norm, first-response timing, pad} as an orthogonal knob vector, per transaction class |
| Software scheduler CPU/mem note (Agent D); Tofino recirc/register math (Agent E) | **Unified parametric overhead model** (§9, = `overhead_model.md`) feeding a **constrained multi-objective optimizer** (§10, spec §14) |

**Plain language:** Agent F built the timing-only evaluation. I bolt on the size/packet-count side
that splitting and padding create, two new attackers that break split, an overhead formula, and the
optimizer that chooses settings per platform.

---

## 2. Extended claim ladder (C1–C7) — scope every claim to its diversity

| Claim | Statement | Min. data | Status now |
|---|---|---|---|
| **C1** (inherit) | On this outstation, processing time encodes N (β,R²); timing normalization drives `I(T;N|size)→0` | 1 device × K configs, R reps | Supportable **after** replication (E1/E1′) |
| **C2** (inherit) | Among timing policies, size-decorrelation reaches equal privacy at lower latency + no averageability | 1 device, full timing sweep | Supportable as a tested hypothesis |
| **C3** (inherit) | Timing/shape distinguishes device *stacks*; defense collapses the anonymity set | **≥2 (ideally ≥3) stacks**, device-disjoint CV | **NOT** supportable on 1 stack — scope as preliminary |
| **C4** (NEW, negative) | **Byte-preserving split reshapes per-packet size + segmentation but does NOT reduce total-byte or packet-count leakage of N; it relocates the leak to packet-count and costs header bandwidth. Only (future) padding closes the size channel.** | 1 device (measured invariants + one split sweep) | **Fully supportable now** — grounded in the R²=0.9999 size leak + byte-preservation [M] |
| **C5** (NEW) | Split + gap-norm + first-response hold preserves 100% DNP3 correctness at the rig bar (byte-identical, CONFIRM, 0 retransmit/reset/timeout, no missed deadline, no unintended op) | 1 device, rig run per setting | Supportable now (correctness is device-local) |
| **C6** (NEW, limitation) | A single shaped device is separable from unshaped traffic (A10 AUC ≫ chance); the anonymity-set benefit requires a fleet shaped to a common target | 1 device for the negative; ≥2 for the benefit | Negative supportable now; benefit needs fleet |
| **C7** (NEW, design) | For each platform (software/Tofino/DPU/FPGA) there is a recommended operating point on the privacy–latency / –bandwidth / –hardware Pareto frontier under the hard constraints | Software measured; hardware = inference from Agents E/G | Software supportable; hardware labelled [I]/[V] |

**Rig-specificity caveat (inherit F).** Absolute constants (0.24/1.01 ms, 14.6 B/CROB) are
OS/NIC/stack-specific; the transferable finding is the *structure* (linear-in-N on both size and
timing; split relocates rather than removes), and even that is one implementation.

**Plain language:** we can prove now that splitting alone cannot hide the secret and does not break
DNP3. We cannot claim to tell device *models* apart, or to fix the size leak, without a second
device and a future padding step. Say exactly that.

---

## 3. Mechanism × observable-axis interaction matrix (the design's core table)

Each cell: does the mechanism *reduce* (↓), *not affect* (–), or *worsen/relocate-into* (↑) that
observable's leakage of the secret S. Grounded in measured facts where marked [M].

| Observable (Axis) | SPLIT (byte-preserving) | PAD (future) | TIMING-NORM |
|---|---|---|---|
| **Axis 1 · total bytes** `Σ` | – (invariant, sum-the-chunks recovers it) [M] | ↓ (pad to class-worst-case) [H] | – |
| **Axis 1 · per-packet size distribution** | ↓ (uniform small chunks) [M] | ↓/↑ (depends on pad target) [H] | – |
| **Axis 1 · packet count** `Π` | **↑ leak relocates here**: `Π=⌈blocks/bpc⌉ ∝ Σ ∝ N` [M/I] | ↓ **only if fixed N-independent chunk count** (=padding) [H] | – |
| **Axis 1 · fragment/segment/link-frame count** | ↑ (more, size-proportional) [M] | ↓ if padded to constant | – |
| **Axis 2 · req→first-response delay** | – (split acts after first byte) | – | ↓ (the crown-jewel closure) [M-target] |
| **Axis 2 · inter-chunk / inter-frame gaps** | **↑ creates new observable** (gaps between the chunks split just made) [I] | – | ↓ (P8 gap-norm must now cover them) |
| **Axis 2 · completion time / duration** | ↑ (pacing inflates it) [I] | ↑ (more bytes to send) | ↑ (hold) |
| **Axis 3 · semantics (FC/class)** | – (class stays on the wire; required) | – | – |
| **NEW · defense-detectability** | **↑ loud** (141 chunks vs 9 = obvious) [M/I] | ↑ (dummy objects/bytes are a tell) [H] | ↑ mild (constant/bucketed release is a tell) |

**Two interference facts the evaluation must make legible.** (a) **Split creates timing work:** the
inter-chunk gaps it introduces are a NEW Axis-2 observable, so a split-then-timing policy must add
gap-normalization (P8) or it has traded a size signature for a timing signature. (b) **Only padding
touches total bytes**, and no safe DNP3 padding exists [M-negative], so in the current phase
total-byte leakage of N is a **structural residual** — the combined policy's honest ceiling.

**Plain language:** every mechanism fixes one leak and can open another. Splitting quiets per-packet
size but shouts on packet count and creates new timing gaps; timing-normalization quiets the delay
but a constant delay is itself noticeable; only fake data hides total size and we have no safe way to
add it yet. The table is the map of these trade-offs.

---

## 4. Extended attacker roster (adds A9, A10, packet-count variant)

Inherit A1–A8 verbatim (shared passive on-path threat model; A7 = defense-aware/Kerckhoffs, A8 =
repeated-observation averaging). The combined policy requires:

| Attacker | Model | Feature use | What it demonstrates | Role |
|---|---|---|---|---|
| **A9 — sum-the-chunks / reassembly** | reassembles the response from its chunks (attacker knows DNP3 framing) → recovers **total bytes** and **fragment count**; regresses on N | total-byte, reassembled-size features | **Split does NOT hide size** — the R²=0.9999 size leak survives byte-preserving split (measured invariant) | **primary** (defeats split) |
| **A10 — detect-the-defense / distinguish-shaped** | binary classifier: shaped vs. native, on packet-count, gap-regularity, chunk-size-uniformity, release-time quantization | full shape+timing vector | **the beacon risk (C6, H3/E7)** — is a lone shaped device separable, and does splitting/holding make it *more* identifiable? | **primary** (detectability) |
| **A11 — packet-count-only** (variant of A1) | single feature = packet count, one boundary | `Π` only | isolates the relocated leak: shows `Acc(Π-only) ≈ Acc(size-only)` after split | floor/diagnostic |

**A9 protocol.** Train on native traces; test whether reassembled total-byte features recover N at
native R² even when the classifier is *denied* per-packet size (split's supposed protection). H1:
A9's N-recovery under split ≈ A9's N-recovery on native (split gives ≈0 privacy on the total-byte
channel). This is the measurable proof of C4.

**A10 protocol.** Closed-world {shaped, native} and open-world (one shaped device hidden among
several native ones). Report AUC and the **anonymity-set size** the shaped device sits in. Expected:
aggressive split (bpc=1) → AUC≈1 (loud); mild policies → lower AUC; a *fleet* shaped to a common
target → AUC→chance (the only regime where shaping helps identity). This operationalizes E7.

**Plain language:** A9 proves splitting doesn't hide size by simply adding the pieces back up. A10
asks the uncomfortable question — does defending one box just paint a target on it? — and answers it
with a number.

---

## 5. Combined-policy experiment matrix (what × baseline × metric)

**Combined modes** (a knob vector `(bpc, gap_norm, first_resp_timing, pad)`; pad∈{none, FUTURE}):

| Mode | Split | Gap-norm (P8) | First-resp timing | Pad | Phase |
|---|---|---|---|---|---|
| **CM0** native | – | – | – | – | now |
| **CM1** split-only | bpc∈{1,2,4,8} | off | off | – | now |
| **CM2** timing-only | – | – | P1..P7 | – | now (=Agent F) |
| **CM3** split+timing | bpc∈{1,2,4,8} | on | P3/P4/P6 | – | **now (primary combined)** |
| **CM4** pad-where-safe | – | – | P3/P6 | FUTURE | future/negative |
| **CM5** split+pad+timing | bpc | on | P3/P6 | FUTURE | future |

**Independent variables (crossed, one-at-a-time for attribution; full-factorial only where cheap):**

| Axis | Levels | Why |
|---|---|---|
| Transaction class Y | Class-0 integrity READ (large), event READ (C1/2/3), small status READ, multi-fragment READ, SELECT, OPERATE(SBO), DIRECT_OPERATE, unsupported/urgent-bypass | classes leak on different axes and have different safety gates (Agent H) |
| Request complexity | **N_CROB {1,2,3,4,5,6,8,10,12,16}**; DB point count {10,50,100,200,300}; single/multi-fragment; small/large payload | the secret S axes; both size (5.7 B/pt; 14.6 B/CROB) and timing leak these [M] |
| CPU load | idle vs concurrent-poll | tail p95/p99 of processing time and scheduler error |
| Mode | CM0–CM5 above | the defense |
| bpc (split) | 1/2/4/8 | granularity ↔ overhead ↔ detectability curve [M anchors] |
| timing knob | Δ / σ / D / budget / bucket / decorr-granularity / decoy | the P0–P8 knob sweep (inherit) |
| Repetition | **R ≥ 30 polls per cell** | MI/distributional estimation, A8 averaging, within-N σ (precondition, §8.1) |
| Devices/stacks | 1 (have) → 2 → ≥3 | gates C1/C4/C5 (1 dev) vs C3/C6-benefit (≥2) |

**Dependent variables / metric → mode mapping** (each mode measured on the full metric grid §6–7).
Baselines: **CM0 native** (leak ceiling) and **P1 fixed-delay** (the deliberately-weak "adds latency,
removes nothing" trap — inherit) and **P2 additive-jitter** (the averageable randomization baseline).

**Expected outcomes under H0/H1** for the NEW combined hypotheses (§ below).

**Plain language:** we run every transaction type at every complexity under each defense setting,
repeated ≥30 times, and score them all on the same metrics. Two obvious wrong answers (add-a-constant,
add-noise) are kept as baselines so the good policies have something to beat.

---

## 6. Extended hypothesis table (combined policy; pre-register before defended runs)

Inherit HA–HG (F). Add:

| ID | H1 | H0 | Endpoint | Test | Primary? | Decision rule |
|---|---|---|---|---|---|---|
| **HI** (split relocates) | After split, `I(Π;N)` ≈ native `I(Σ;N)`; `Acc(A11 packet-count)` ≈ `Acc(size)` | split reduces packet-count leak too | `I(Π;N)`, A11 acc, β of Π on N | KSG MI + permutation null; McNemar A11 vs size-attacker | **primary (C4)** | conclude relocation iff `I(Π;N)` NOT below native `I(Σ;N)` band |
| **HJ** (size survives split) | A9 recovers N under split at ≈ native R² | split lowers A9's N-recovery | A9 R², MAE, `I(Σ;N)` | paired bootstrap on R²; TOST *equivalence to native* | **primary (C4)** | conclude survival iff 90% CI(R²_split) ⊂ ±margin of native |
| **HK** (fixed-count needed) | Only an N-independent fixed chunk count drives `I(Π;N)→0` (=padding) | variable-bpc split suffices | `I(Π;N)` fixed-count vs variable-count | permutation-null MI, paired | secondary (design) | fixed-count in null band, variable-count not |
| **HL** (gap signature) | Split without gap-norm raises `I(gaps;N)`; P8 restores it to null band | split gaps carry no N info | `I(inter-chunk gap; N)` | KSG + null | primary (CM3) | CM1 gaps leak; CM3 (P8) gaps in null band |
| **HM** (latency model) | Cumulative completion latency = L_hold + (n_chunks−1)·gap, but the RTO constraint binds on the *per-hop* gap and the initial hold, NOT the sum (three-inequality model, §9.1) | split+timing violates a single cumulative-vs-RTO bound | measured p95 completion + per-hop ACK latency vs model; retransmit count | paired bootstrap vs model; retransmit count = 0 | primary (overhead) | model predicts completion within CI AND 0 retransmits at the tested bpc (bpc=1 measured feasible) |
| **HN** (beacon) | A10 AUC(shaped vs native) ≫ chance for a lone device; falls to chance only under fleet-common-target | shaping is undetectable | A10 AUC, anonymity-set size | DeLong AUC vs 0.5; open-world sweep | **primary (C6)** | AUC CI excludes 0.5 for lone device |
| **HO** (self-leak) | Deployed policy choice does not encode S: `I(choice;S|Y)≈0` | choice leaks S | `I(policy_choice; S | Y)` | KSG conditional MI + permutation null | primary (integrity) | must be in null band, else redesign |
| **HP** (bandwidth cost) | Split wire-byte increase ≈ (Δpackets)·H_hdr, growing as bpc→1 | split is bandwidth-free (DNP3 bytes unchanged) | measured wire bytes vs model | regression vs `54·Δpkt` | secondary | model fits; report the inflation curve |

Equivalence margins, attacker roster, feature set, and primary endpoints are declared here and
**frozen before defended-trace collection** (pre-registration). Primary combined endpoints: **HI/HJ
(C4), HL (CM3), HM (overhead), HN (C6), HO (integrity)** — pre-registered so they are not diluted by
the exploratory grid.

**Plain language:** these are the yes/no bets we place *before* seeing the data. The key ones: does
splitting just move the leak (HI/HJ), do the new gaps leak (HL), does the latency add up dangerously
(HM), does the defense become a beacon (HN), and does our own policy accidentally leak the secret
(HO).

---

## 7. Metric catalogue for the combined policy (Section 10 deliverable)

### 7.1 Correctness (hard gate — any failure voids the privacy result)
Byte-preservation `b"".join(chunks) == original` asserted per response; valid CRCs on every chunk
(Zeek/Bro `dnp3` clean parse, legal FCs, intact app-sequence); SELECT/OPERATE status = native and
final DB state = native; DNP3 CONFIRM present for every multi-fragment read; measurement count =
native (the 800-measurement rig bar); **0 TCP retransmits, 0 RST, 0 duplicate/reorder, 0 retry, 0
session timeout, 0 missed deadline, 0 unintended control**. Split adds: **no CRC recompute, no
in-block cut** (phase-boundary assertion).

### 7.2 Privacy (organized by the three carriers + detectability + integrity)

| Group | Metric | Estimator / test | New vs F |
|---|---|---|---|
| Timing→N | slope β (ms/CROB) + 95% CI, R², MAE, Spearman ρ | OLS + bootstrap; LRT nested-F; **TOST** ±0.02 ms/CROB | inherit |
| **Total-byte→N** | `I(Σ;N)`, β_size (B/CROB), R², A9 recovery R²/MAE | KSG + null; TOST *equivalence to native* (survival) | **NEW** |
| **Packet-count→N** | `I(Π;N)`, A11 acc, β_Π | KSG + null; McNemar A11 vs size-attacker | **NEW** |
| Fragment/segment/frame counts→N | `I(#frag;N)` etc. | KSG + null | **NEW** |
| Conditional (attribution) | **`I(T;N|Σ)`** (timing marginal), **`I(Σ;N|T)`** (size residual), joint `I((T,Σ,Π);N)` | KSG conditional MI + permutation null | inherit + extend to full 3-carrier decomposition |
| Device/config classification | accuracy, **balanced accuracy, macro-F1, ROC-AUC** | McNemar (paired), DeLong (AUC), Wilson/Cohen's h | inherit (needs ≥2 stacks) |
| Privacy Gain | `PG = (Acc_nat−Acc_obf)/(Acc_nat−Acc_chance)` per attacker A1–A11 + task; `PG_MI=1−I_obf/I_nat` | bootstrap CI; **flag PG<0** (defense helped attacker) | extend to A9–A11 |
| Averageability | PG-vs-M slope, **half-life M½** | regression on log M (A8) | inherit |
| Defense-aware residual | A7 acc/AUC retrained on obfuscated traffic | grouped CV; Carlini 2019 standard | inherit |
| **Detectability (beacon)** | **A10 AUC(shaped vs native), anonymity-set size, open-world identifiability** | DeLong vs 0.5; open-world sweep | **NEW** |
| Distributional match | **W1 (ms/B)** twice (to native, to target), **KS-D + test**, **JS** between per-class post-defense dists | Peyré-Cuturi W1; two-sample KS; Lin JS; bootstrap CI | inherit, apply to size dist too |
| **Profile-bypass leakage** | fraction of `I(·;S)` recoverable from **bypassed** transactions alone; is the *bypass event itself* class-identifying (`I(bypass_indicator; class)`) | KSG + null on the bypass subset | **NEW** |
| **Policy self-leak** | **`I(policy_choice; S | Y)`** | KSG conditional MI + permutation null (HO) | **NEW** |

### 7.3 Overhead (feeds §9 model and §10 Pareto)
Added latency per exchange: mean/median/**p95/p99/max** and ×baseline; **first-response hold** vs
**inter-chunk pacing** decomposed; end-to-end completion time; SELECT→OPERATE interval; **packet-count
increase** (Π−Π_native); **bandwidth increase** (wire bytes, header-driven); CPU %, memory (RSS);
**held-packet count / queue occupancy** (E[held], max); **scheduler error** |release−target| dist;
**Tofino recirc bandwidth / register entries / MAU stages**; **DPU/FPGA resource** (send-queues, DRAM,
LUT/BRAM); **deadline-miss rate**; **policy-bypass rate** (released-immediately fraction);
**RTO-overshoot rate**.

**Plain language:** three privacy scorecards — one each for how much the timing, the total size, and
the packet count still reveal N — plus a beacon score, a "did our policy leak the secret itself"
score, and a cost sheet covering delay, extra packets, extra bytes, CPU, memory, and hardware.

---

## 8. Statistical design (extends F §7)

### 8.1 Precondition #0 — replicate the n=1/N sweeps BEFORE any "law"
Both headline lines are **n=1 per N** (size R²=0.9999; timing R²>0.99). A slope/R²/MI from one
sample per level is a 10-point line, not a replicated law, and has **no within-N σ**, so every
CI, TOST margin, and power calc below is undefined until this is fixed. **Gate:** run **E1
(timing/CROB) and E1′ (Class-0 read-plane point-count)** with **R ≥ 30 polls per N-level**, report
within-N σ_resid and **bootstrap CIs (B≥2000, Efron & Tibshirani)** on β and R² for BOTH the size
and timing channels, *before* collecting any defended (CM1–CM5) data. This is non-negotiable and is
the reason the whole plan is pre-registered: the σ that sets sample size does not yet exist.

### 8.2 Sample size / power
- **C4 total-byte survival (HJ):** the binding test is a **TOST equivalence to native** on A9's R².
  With the N-grid spread s_N≈4.7 and a real σ_resid from E1′, `SE(β)≈σ_resid/(s_N·√n)`. Minimum sane
  design ≥3 N-levels × R reps; R fixed by the MI floor, not the (degenerate) closed-form β count.
- **MI/distributional floor:** KSG MI CI and KS/W1 scale ~1/√n. To bound a residual `I(·;N)<0.05 bits`
  with a tight bootstrap CI and to power a small-effect KS test → **n≥300–500 exchanges per
  (class, config, mode) cell → R≥30 polls/N.** Same floor feeds A8, A9, A10.
- **T1/C3 classification (≥2 stacks):** McNemar on discordant pairs — a large drop (0.90→0.50) needs
  ~30–50 test exchanges; a subtle drop (0.90→0.85) needs several hundred → **test-set floor ≥200
  sessions/class.** A10 detectability uses the same floor for its DeLong AUC CI.

### 8.3 Cross-validation (leakage is the killer, and worse under split)
- **GroupKFold by session/capture is mandatory** — all exchanges (and, under split, **all chunks**)
  of one response go entirely to train OR test. Chunks of one response are NOT independent; ungrouped
  CV leaks catastrophically for A9/A11. For C3/C6 and any linkage, split by **disjoint
  device/config groups** (a device in train must not appear in test) — else "fingerprinting" is
  memorization.
- **Nested CV** for A3–A6/A9/A10 hyperparameters (inner tune, outer estimate).
- **A7 defense-aware protocol:** train on obfuscated traces at known params under the same grouped
  CV; report as the primary security number (Carlini 2019).

### 8.4 Tests, CIs, effect sizes, multiplicity
- **CIs:** bootstrap percentile (Efron & Tibshirani, B≥1000; ≥2000 for MI) for MI/R²/β/PG/W1/JS;
  DeLong CI for AUC; Wilson CI for accuracies.
- **Effect sizes over bare p:** Δacc+CI, Cohen's d/h, MI-drop in bits+CI, β+CI, W1 in ms/B.
- **Equivalence for closure claims:** **TOST** (β into ±margin; A9 R² into native band).
- **Significance:** McNemar (paired classifier), DeLong (paired AUC), **permutation-null** for every
  MI (shuffle labels ≥1000×), nested-F/LRT for "does N improve the model".
- **Multiplicity:** the family is (6 modes × ~11 attackers × ~6 metric groups) + Pareto pairings →
  control **FDR at q=0.05 via Benjamini–Hochberg (1995)**; report raw AND BH-adjusted p. Pre-registered
  primary endpoints (HI/HJ/HL/HM/HN/HO) are protected from dilution.

### 8.5 Seeds / traceability
Stochastic policies (P2/P4/P7, split-seed if any randomized chunk padding is ever added) and
stochastic learners (A3–A6/A9/A10): **≥5 policy seeds × ≥5 learner seeds**; report mean ± variance
across seeds AND folds. Every number → **(config + seed + git commit)**; record `pip freeze`, TCP
option signature, the **measured effective RTO on Vision**, poll interval, and capture SHA-256.

**Plain language:** first re-run the two leak measurements 30× each so we actually have error bars —
nothing downstream is valid without them. Never let pieces of the same response land in both training
and test, or the attacker looks stronger than it is. Prove "the leak is gone" with equivalence tests,
not by finding a big p-value, and correct for running many comparisons.

---

## 9. Overhead model (spec §13 — the `overhead_model.md` content)

A **parametric** model predicting each overhead objective from the policy knobs, per platform, so the
optimizer (§10) does not need to measure every point. Anchored to measured facts; inference labelled.

### 9.1 Added latency (the RTO-critical objective)
```
L_total(txn) = L_hold + L_pace
  L_hold  = max(0, target_release − response_ready)      # timing normalization
          = (D − t_proc)          for constant-time D
          ≤ budget                for bounded/decorrelated
  L_pace  = (n_chunks − 1) · chunk_delay                  # split inter-chunk pacing (total transfer span)
  n_chunks(bpc) = ⌈ n_crc_blocks / bpc ⌉                  # measured: 141→141/71/36/18 @bpc 1/2/4/8 [M]
HARD CONSTRAINTS — THREE separate inequalities, NOT one cumulative sum (measured-grounded):
  (i)   L_hold                 <  effective_RTO_margin   (= κ·measured_RTO on the holding side)  [S/I]
  (ii)  each inter-chunk / inter-fragment gap  <  effective_RTO_margin   (per-hop ACK latency)   [S/I]
  (iii) L_hold + L_pace        <  operational deadline (5 s app-response timeout; 10 s SBO select) [S]
```
**Key result (HM) — corrected to match the measured evidence.** TCP RTO fires on a *single unacked
segment*, and each paced chunk is ACKed as it arrives, so the binding limit is the **max inter-ACK
gap (ii)** and the **initial hold (i)**, NOT the cumulative sum. This is why the measured **bpc=1,
141-chunk, 10 ms/gap split — total transfer ≈ 1.41 s — ran with 0 retransmits / 0 resets [M]**: no
segment ever waited longer than one gap for its ACK. The cumulative span is bounded instead by the
DNP3 app/select timeout (iii), which is 25×–70× looser. **Therefore bpc=1 is measured-feasible and is
NOT excluded** — the earlier "cumulative < RTO ⇒ bpc bounded from below" claim was wrong. (Caveat,
Agent B: for a *split*, chunk 1 ACKs the master's request, so inequalities (i)/(ii) are governed by
the **outstation/replay-side tail-RTO (Hulk)**, not the master-side RTO; both must be measured. This
tail-ACK-within-RTO behavior is inferred and must be confirmed by one mid-path capture — see the RTO
feasibility sweep in §14.) What still bounds aggressive split from *above* is bandwidth/packet-count
overhead and the defense-detectability (beacon) leak, not the RTO budget.

### 9.2 Bandwidth (the non-obvious cost of split)
```
Δwire_bytes ≈ (Π − Π_native) · H_hdr,   H_hdr ≈ 54 B (Eth14+IP20+TCP20)   [S/I]
```
DNP3 payload bytes are unchanged [M], but split multiplies **packets**, and each packet pays a fixed
header. Worked from measured anchors: 2407 B / 9 native frames, split at bpc=1 → ~141 chunks (≈141
TCP segments + master ACKs, measured 301 total pkts). Δpkt on the order of 10²  → **Δwire ≈ 10²·54 ≈
several–15 KB of headers on a 2.4 KB payload = 3–7× wire inflation at bpc=1, ≈2× at bpc=8** [M/I].
**So split is "free" on DNP3 bytes but expensive on wire bytes — and that same packet multiplication
is the packet-count leak (C4) and the A10 beacon.** One knob, three costs.

### 9.3 Packet-count and structural
`Π_increase = ⌈n_crc_blocks/bpc⌉ − Π_native`; fragment/segment/frame counts scale likewise. Because
`n_crc_blocks ∝ size ∝ N` [M], `Π ∝ N` — this is `I(Π;N)` (§7.2), not a mere cost.

### 9.4 CPU / memory (software)
Per transaction ≈ a few `monotonic_ns` reads + one RNG draw + comparison chain + O(1) timer-wheel
insert ≈ **single-digit µs CPU**, **few KB memory** (Agent D [I]); the ms-scale *delay* is sleep, not
CPU. Negligible vs the network cost at kbps.

### 9.5 Held packets / queue occupancy
`E[held] ≈ (mean_hold / poll_interval) · concurrency`. At ms holds and ≥1 s polls, **E[held] < 1 per
outstation** (Agent E [I]) → held-frame table sized in the 64–256 range with 1–2 orders of margin;
sets the Tofino register floor and DPU/FPGA queue count.

### 9.6 Scheduler error (a privacy cost, not just an overhead)
`ε_sched = |release_actual − release_target|`. Software: ~0.1–1 ms jitter (clock_nanosleep under CFS
load, Agent D [I/S]); Tofino recirc self-clock ~100 µs (Agent E [I]); DPU Accurate Send Scheduling /
FPGA calendar queue: sub-µs (Agent E [V/P]). **Larger ε_sched widens the release distribution → worse
W1-to-target → measurable privacy loss.** This couples platform choice to privacy and is the crux of
the privacy–hardware-cost frontier (§11.3): cheaper platform → coarser clock → residual leak.

### 9.7 Hardware resource (from Agents E/G, labelled)
- **Tofino 1:** recirc bandwidth ≈ 16 Mbps/held-frame @100 µs self-clock (1.6 Gbps @1 µs); <1 % of a
  100 G pipe given E[held]<1; held-table 64–256 SALU-register entries; deadline compare = sliced
  across MAU stages (bf-p4c gateway/range tax). **Cannot store/reconstruct payload → cannot host
  split+pad fusion** (Agent E [I/V]).
- **BlueField DPU:** Accurate Send Scheduling native (per-SQ PTP fence, ~12 ns) → first-response hold
  is a primitive; DDR + ARM → the natural home for **fused split+pad+timing** (Agent E [V]).
- **FPGA:** >10k HW queues, µs-precision calendar/TDMA (Corundum) — determinism ceiling, highest dev
  cost (Agent E [P]).
- **Software replay server:** zero hardware; schedules emission directly (generating endpoint, no
  hold problem) — the immediate deliverable.

**Plain language:** the model turns knob settings into predicted delay, extra packets, extra bytes,
CPU, memory, held packets, and hardware use. The two headlines: split+timing delay adds up and can
blow the retransmit budget, so you cannot split too finely; and a cheaper, coarser-clock platform
literally leaks more because it can't hit the target time precisely.

---

## 10. Multi-objective optimization (spec §14)

### 10.1 Decision variables and the class-independence rule
Policy is a function of the **observable, safety-required class** `Y ∈ {Class-0 read, event read,
small status, multi-frag read, SELECT, OPERATE, DIRECT_OPERATE, unsupported/urgent}` only:
```
π(Y) = ( bpc_Y , gap_norm_Y , timing_policy_Y , timing_param_Y , pad_Y )
```
**Hard integrity rule (HO):** π may depend on `Y` (necessary for safety routing) but **must NOT
depend on the secret `S=(N, DB-size, device)`**. Concretely, every target is set to the **class
worst-case**, not the instance: `timing_param_Y = D_Y` (constant over configs in Y), and any size/
chunk target is the class maximum — because a target that *tracks* N re-encodes N in the choice
itself. **Verification metric:** `I(π_choice ; S | Y)` must sit in a permutation-null band (HO); a
policy that fails this is a self-inflicted leak and is rejected regardless of its Pareto position.
*Consequence:* true size-hiding requires padding every response in class Y up to the class-worst-case
size — the future padding phase; split cannot do it. This is the formal reason C4 is negative.

### 10.2 The constrained multi-objective program
Minimize the objective vector (all "lower = better", per class then aggregated):
```
f1 = privacy leakage        = WORST-over-attackers residual  = max_{A∈A1..A11} I_obf(·;S)  (or 1−PG)
f2 = classification acc      (≥2 stacks; else config-acc, scoped)
f3 = added p95 latency
f4 = bandwidth increase      (wire bytes, §9.2)
f5 = packet-count increase   (§9.3)
f6 = CPU + memory
f7 = hardware cost           (recirc bw / registers  |  DPU send-queues+DRAM  |  FPGA LUT/BRAM)
f8 = deadline-miss rate
f9 = defense-detectability   (A10 AUC)
subject to HARD CONSTRAINTS g(π) (feasible or infeasible, no trade-off):
  c1: 100% DNP3 correctness (0 retransmit / reset / timeout / reorder / retry / missed deadline)
  c2: no unintended control op ; c3: FIFO / no reorder ; c4: byte-preservation (join == original)
  c5: critical-control bypass respected (operator allowlist; Agent H)
  c6: (i) initial hold < RTO_margin AND (ii) each inter-chunk/inter-fragment gap < RTO_margin AND
      (iii) cumulative added latency < operational deadline (5 s app / 10 s SBO) — the three-inequality
      model of §9.1 (NOT a single cumulative-vs-RTO bound; bpc=1 is feasible, per measured 0-retransmit split)
  c7: policy self-leak I(choice;S|Y) in null band (§10.1)
```
**Using the worst-attacker as f1 is deliberate** — it prevents Goodharting the optimizer against a
single overfittable model (A7 defense-aware is always in the max). Objectives are **empirical, noisy
attacker estimates**, so each carries a bootstrap CI and dominance is CI-aware (§10.4).

### 10.3 Solution methods (matched to problem size)
- **Per-platform frontier from a knob sweep → ε-constraint method (Haimes, Lasdon & Wismer 1971).**
  Fix the hard constraints, minimize `f1` subject to `f3 ≤ ε` (or `f4 ≤ ε`, `f7 ≤ ε`), sweep ε. This
  is exactly Agent F's knob sweep given a principled name; it yields weakly-Pareto-optimal points
  deterministically and is ideal for the low-dimensional single-platform frontiers (§11).
- **Combined policy space (per-class assignment × 5 knobs) → NSGA-II (Deb, Pratap, Agarwal &
  Meyarivan 2002)**, or, because we have **≥4 simultaneous objectives (many-objective)**, **NSGA-III
  (Deb & Jain 2014)** with reference-point-based nondominated sorting, implemented via **pymoo (Blank
  & Deb 2020)**. Hard constraints handled by **constrained domination** (a feasible solution always
  dominates an infeasible one; among infeasible, less-violating dominates) — this cleanly enforces
  c1–c7.
- **Frontier comparison → the hypervolume indicator (Zitzler & Thiele 1999)** as a single Pareto-
  compliant scalar to rank platforms/policies and to compare against the WF-defense lower-bound
  framing already in the matrix (Cai 2014 Tamaraw; NetShaper DP Pareto).

### 10.4 Uncertainty-aware Pareto (the methodological honesty)
Because f1/f2/f9 are attacker estimates on finite data, a naive frontier over-fits noise. Rules:
(a) every objective plotted with its **bootstrap CI**; (b) **probabilistic/robust dominance** — point
p dominates q only if p's CI-favorable bound beats q's CI-unfavorable bound on all objectives (a
conservative frontier band, not a razor line); (c) select operating points by **information gain /
robustness**, reporting a *region* of near-optimal knobs, not a single fragile setting; (d) report the
frontier's **hypervolume with a CI** across seeds/folds. This is the pre-registration / no-cherry-
picking discipline applied to optimization.

**Plain language:** we frame policy choice as "get the most privacy you can without breaking DNP3,
without blowing the retransmit budget, and without the policy itself leaking the secret." For a single
platform we just sweep one knob (ε-constraint); for the full per-class combined policy we run a
standard many-objective optimizer (NSGA-III via pymoo). Because privacy is a *measured, noisy* number,
we draw the trade-off curve with error bands and pick a robust region, not a lucky point.

---

## 11. Pareto frontier designs + recommended operating points per platform (C7)

### 11.1 Privacy–latency frontier
x = **added p95 latency** (also mean/max); y = **privacy** = worst-attacker PG (twin plot `PG_MI`).
Points = knob sweeps (P1 Δ, P2 σ, P3 D, P4 budget, P5 bucket, P6 decorr, P7 decoy, P8 gap, split bpc).
**Third dimension = averageability** (color by A8 M½: small M½ = fake privacy). **Shaded safe region**
= {initial hold < RTO_margin AND max inter-chunk gap < RTO_margin AND cumulative added p95 <
operational deadline (5 s app / 10 s SBO) AND correctness=100%} — the three-inequality model (§9.1),
with the RTO measured on the *holding side* (Hulk for splits, Vision for holds). Inherit F's
pre-registered **HE (P6 size-decorrelation beats P2 jitter at matched privacy)**. **bpc=1 is inside the
safe region** (measured 0-retransmit split); aggressive split is bounded from above by bandwidth/
packet-count overhead and the beacon leak (A10), NOT by the RTO budget.

### 11.2 Privacy–bandwidth frontier (NEW — split's real trade)
x = **wire-byte increase** (§9.2, header-driven); y = privacy. This frontier exposes C4 visually:
splitting moves *right* (more bandwidth) with **little upward privacy movement** on the total-byte/
packet-count channel (A9/A11), because the leak relocates rather than disappears. A padding point
(future) would be the only one that moves *up* on the size channel — at its own bandwidth cost. The
contrast between "split spends bandwidth for ~0 size-privacy" and "pad spends bandwidth for real
size-privacy" is the frontier's punchline.

### 11.3 Privacy–hardware-cost frontier (NEW — couples §9.6 to privacy)
x = **hardware cost** (Tofino recirc bw+registers | DPU send-queues+DRAM | FPGA LUT/BRAM); y = privacy,
with the key twist that **cheaper platforms have larger scheduler error ε_sched → worse W1-to-target →
residual leak** (§9.6). So this is not a flat "same privacy, cheaper hardware" line — it slopes:
software (cheapest, coarsest clock, some residual) → Tofino recirc (~100 µs) → DPU/FPGA (sub-µs, near-
ideal match). The frontier tells you **how much privacy each hardware dollar buys** for this workload.

### 11.4 Recommended operating points (design output; software [M-testable], hardware [I]/[V])
| Platform | Recommended point | Rationale |
|---|---|---|
| **Software replay server** | CM3 with **moderate bpc (4–8)** + P6 first-response decorrelation + P8 gap-norm; timing target = class worst-case | generating endpoint (no hold problem); bpc=1 is RTO-feasible (measured 0-retransmit), so moderate bpc is chosen to bound **bandwidth, packet-count leak, and beacon detectability** (not RTO), while gap-norm covers the new gaps; the immediate, rig-validatable deliverable |
| **Tofino 1** | **pacing + recirc first-response hold**, **no split-fusion, no pad** (cannot store/reconstruct) | native pacing/gap-norm; recirc-hold affordable at kbps (<1 % pipe); payload store/reconstruct off-ASIC |
| **BlueField DPU** | **fused CM5 candidate** (Accurate Send Scheduling hold + DRAM-backed split, pad when future phase opens) | native absolute-delay + storage → the only platform that can host the full stack and the correctness baseline |
| **FPGA** | determinism ceiling (calendar-queue exact release) for a TSN-style claim | sub-µs ε_sched, best W1-to-target; highest dev cost — reference, not first target |

**Plain language:** three trade-off curves. Delay-vs-privacy (with a shaded "safe from retransmits"
zone), bandwidth-vs-privacy (which shows splitting spends bandwidth for almost no size-privacy), and
hardware-cost-vs-privacy (where cheaper, coarser clocks quietly leak more). Recommended settings:
software does moderate split + timing now; Tofino does pacing + a timing hold; the DPU is the only box
that can eventually do the whole split+pad+timing stack.

---

## 12. Reproducibility checklist (extends F §10)
- [ ] Seeds set (random/numpy/torch, `PYTHONHASHSEED`); ≥5 policy × ≥5 learner seeds for stochastic
      cells.
- [ ] **Precondition #0 done:** E1 (timing/CROB) AND E1′ (Class-0 read point-count) replicated
      R≥30/N; within-N σ and bootstrap CIs on β/R² for **both size and timing** channels recorded
      BEFORE any defended run.
- [ ] Hydra config + overrides per run; output dir `{mode}_{class}_{config}_{seed}_{timestamp}`.
- [ ] Environment captured (`pip freeze`, scapy/sklearn/pymoo versions, OS/NIC, TCP option signature).
- [ ] **Effective RTO measured on Vision** (`sysctl net.ipv4.tcp_retries2`, `ip route … rto_min`,
      observed request→first-retransmit) and recorded — every latency budget is provisional until this.
- [ ] Capture SHA-256; N-grid, point-count grid, poll interval, class, bpc, timing knob logged.
- [ ] Every number → (config, seed, git commit).
- [ ] Analysis plan (§6 hypotheses + margins + primary endpoints) frozen before defended-trace
      collection.
- [ ] Feature extractor + MI/W1/KS + attacker code (incl. A9/A10) versioned; **CV = GroupKFold by
      session, chunks grouped to their response, device-disjoint for C3/C6**.
- [ ] Optimizer run recorded: objective definitions, constraint predicates, ε-grid / NSGA-III config,
      hypervolume + CI, per-platform operating point with its knob region.

## 13. Threats to validity (extends F §11)
- **Single device / rig (C1/C2/C4/C5).** Information/regression/correctness/relocation claims are
  per-device; the structure (linear-in-N on size AND timing; split relocates) is one implementation.
- **One stack ⇒ no device-type (C3) and only a lower-bound beacon (C6).** T1/A10 open-world numbers
  on one stack are config-, not device-, results; the anonymity-set *benefit* needs a fleet.
- **KSG bias near determinism.** Native `I(·;N)` near-deterministic (R²>0.99) → MI unstable; mitigate
  with β/R² primary, binned-MI cross-check, permutation null for the obf side.
- **A9/A10 completeness.** A9 must genuinely reassemble (not just see per-packet sizes); A10 must be
  retuned per policy (a weak A10 fakes stealth). Report tuning effort (Carlini 2019).
- **Optimizer over-fits noisy objectives.** Mitigated by worst-attacker f1, CI-aware dominance,
  robust operating regions, hypervolume-with-CI (§10.4) — but the frontier is estimated, not exact.
- **Size channel not closed (byte-preserving phase).** Report `I(Σ;N|T)` and A9 so the size residual
  is never hidden behind a timing-only closure.
- **Hardware inference.** Tofino recirc-hold and DPU/FPGA points are [I]/[V] (unbuilt on our chip);
  software is the only [M]-testable frontier now.
- **Scheduler-error → privacy coupling (§9.6)** is itself a modeled/inferred link until measured on
  each platform.

## 14. Recommended experiment sequence (extends F E1–E7)
0a. **A0 — direct-payload-read baseline (THE most important missing experiment; answers threat-model
   F1).** Quantify how much CROB count a passive observer recovers by simply **parsing the cleartext
   SELECT/OPERATE objects** (no side channel). Without this number the marginal value of the entire
   metadata (size/timing) defense in the current cleartext phase is unquantified. Report CROB-count
   recovery accuracy of the direct-read observer vs the metadata-only observer; this sets the honest
   "what is the current-phase defense worth" baseline (`terminology_and_threat_model.md`).
0b. **RTO-feasibility sweep (settles the C1 model empirically).** Cross bpc∈{1,2,4,8} × inter-chunk gap,
   capture on a **mid-path tap**, and report **retransmit/reset counts** to confirm which inequality
   binds (per-hop gap vs cumulative). Measure the effective RTO on **Vision (holds) and Hulk (splits)**
   first. *Expected (per measured 0-retransmit bpc=1): the per-hop gap binds, not the sum.*
0c. **Tunnel-phase mechanism-feasibility probe.** Confirm whether the in-network classifier/splitter can
   operate at all once DNP3 is tunneled/encrypted, or whether shaping must relocate to the endpoints —
   deciding whether the "buildable now" in-network line and the "future" size-hiding line are one system
   or two (the F1 discontinuity).
1. **E1 / E1′ (precondition, refutes C1/C4 if the leaks don't replicate):** timing/CROB AND Class-0
   read point-count sweeps, R≥30/N, with CIs on β/R²/MI for size and timing. *Gate for everything.*
2. **E-CM1 (C4, primary):** split-only sweep bpc∈{1,2,4,8} — measure `I(Σ;N)` (A9), `I(Π;N)` (A11),
   `I(gaps;N)`, wire-byte increase, byte-preservation. *Expected: size R² survives (HJ), leak
   relocates to Π (HI), gaps leak without P8 (HL), bandwidth ↑ per §9.2 (HP).*
3. **E-CM3 (primary combined):** split+P8+P6 on the grid — TOST `I(T;N|Σ)→0`; confirm gaps back in
   null band; **cumulative-latency vs RTO (HM)**; correctness gate (C5).
4. **E3 (A8 averageability, inherit):** M∈{1…300}, P2 vs P3/P6, half-life M½.
5. **E-A10 (C6/beacon, primary):** shaped-vs-native AUC per mode; open-world anonymity-set sweep.
6. **E-HO (integrity, primary):** measure `I(policy_choice; S | Y)` for the deployed per-class map.
7. **E4 (Pareto):** ε-constraint knob sweeps → the three frontiers (§11) + safe region; NSGA-III via
   pymoo for the per-class combined policy; hypervolume + CI; per-platform operating points.
8. **E5 (correctness gate, all settings used above):** rig run — 0 retransmit/reset/timeout, byte-
   preserved, measurement count = native.
9. **E6 (C3/C6-benefit, future/≥2 stacks):** device-type + fleet anonymity-set with device-disjoint
   CV.
10. **E-CM4/CM5 (future, padding phase):** only if a safe byte-preserving/protocol-modifying padding
    is authorized — the only experiments that can move the privacy–bandwidth frontier *up* on the
    size channel.

**Plain language:** first re-measure both leaks with error bars (gate). Then prove splitting only
relocates the leak and costs bandwidth (E-CM1), test the real combined policy for correctness and the
compounded-delay danger (E-CM3), measure averaging and the beacon risk, check our own policy doesn't
leak the secret, then draw the trade-off curves and pick per-platform settings. Padding experiments
wait for a future phase.

---


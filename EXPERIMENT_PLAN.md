# Experiment Plan — DNP3 Fixed-Transcript Defense

> **REVISED for the one-Tofino constraint (`CORRECTION_LOG.md`).** The statistical machinery below
> (deterministic MI, permutation/bootstrap with valid clustering, leave-one-flow/session/device-out, the
> analytic 1/C plus Bayes-optimal chance baseline, more than one capture session) stands. Under the
> binding testbed the three required first experiments are the following. Design them now; do not execute
> them (hardware steps are gated on Philip's authorization).

## Required first experiments (one-Tofino, revised order)

This order is corrected (documentation correction, this commit) to lead with the unresolved TCP-header
question rather than a cadence measurement. Design these now; do not execute them (Experiments 2 and 3
are separately authorized hardware/compile steps).

### Experiment 1 — TCP-option attribution and canonical transformation (read-only / offline)

> **EXECUTED 2026-08-10 — verdict `PROMISING` (offline, TCP-header axis only), conditional.** Full
> results in `experiments/exp1_tcp_header_attribution/` (README, METHODOLOGY, RESULTS, TOFINO_REQUIREMENTS,
> VERDICT; machine-readable `out/*.json`, transformed pcaps `pcaps/`). The outstation `data_offset`
> fingerprint was attributed to exact TCP option bytes over three physical stacks; a canonical-option-
> layout transform (T2) removed the dominant header fingerprint offline (handshake-captured distinct
> signatures 3 -> 1) with byte-exact DNP3 payload and valid checksums, while length-only IP normalization
> (T0) and timestamp-origin translation (T1) did not. Residual: the TCP window value; out of scope:
> size/count/timing. Corrected in Experiment 2A: the realizable, endpoint-safe mechanism is **handshake
> normalization** (suppress TS/WScale/SACK in SYN/SYN-ACK; endpoints fall back per RFC 7323/1122), which
> is stateless / packet-bounded, not the per-segment strip the offline T2 used and not a per-flow
> translation. `PROMISING` authorizes only a later request for Experiment 2 (standalone compile probe of
> the handshake normalizer); it does not authorize implementation, hardware, or Experiment 3.
Attribute the observed `tcp.data_offset` fingerprint to the exact TCP options present, across every
capture session and every device in the corpus, so the fingerprint is explained at the level of specific
options (Timestamps, window scale, SACK-permitted, NOP/EOL padding) rather than a bulk data-offset value.
Then test deterministic, PCAP-level canonical transformations offline: suppress or canonicalize the
options, pad shorter headers to a public data offset, and validate that IPv4/TCP lengths and checksums
remain correct after the transformation. This is read-only and offline; it establishes whether a
canonical option layout is even well defined for this corpus before any hardware step.

### Experiment 2 — Standalone Tofino TCP-header normalizer (compile-only, separately authorized)
Specify and compile a standalone Tofino TCP-header normalizer targeting handshake option suppression
(Timestamps, window scale, SACK-permitted during SYN/SYN-ACK), a canonical data offset with NOP/EOL
layout, and IPv4/TCP checksum correction. Compile this **separately, before** attempting any Defense 4
co-residency, so the target's own feasibility is measured in isolation. Budget the real compiler
categories (stages, logical tables, PHV groups and container widths, stateful and statistics ALUs, parser
resources, queues, packet buffer, and any per-flow state the timestamp/ISN translation needs). A compile
failure here is a **bounded target result for these specific mechanisms**, not a universal impossibility
proof.

> **Experiment 2A EXECUTED (design, reviewed) and Experiment 2B EXECUTED (compile gate): COMPILE_PASS.**
> `experiments/exp2_handshake_normalizer/`. The standalone normalizer compiles `0 errors` on bf-p4c
> 9.13.1 to a loadable `tofino.bin`, **stateless** (0 registers, 29 logical tables, 1 TCAM,
> ~162-cycle ingress). The early bf-p4c ICE was diagnosed to three coding-shape faults, each fixed
> with a standard idiom (`COMPILE_RESULTS.md`) — not a feasibility wall. **The functional model run
> (tofino-model + PTF) was NOT executed** this turn; harness ready (`tests/ptf/test.py`,
> `MODEL_TESTS.md`). Verdict + scope in `experiments/exp2_handshake_normalizer/VERDICT.md`. Running
> the model to reach COMPILE_PASS_MODEL_PASS/_FAIL is the next (separately authorized) step; Exp 3
> stays gated behind it.

### Experiment 3 — Endpoint safety of the surviving normalizer (after authorization)
Test whatever normalizer survives Experiment 2 on ordinary TCP first and then an isolated OpenDNP3
environment, covering connection establishment, retransmission, loss, sequence wraparound, PAWS/RTTM
behavior, and sustained transfer. Only after that passes should read-only SEL-751 testing be considered,
and only under explicit authorization, with the physical relay READ-only.

### Deferred — periodic cadence measurement
The pktgen periodic-timer cadence measurement (slot jitter p50/p95/p99/p99.9, missed/duplicated/silent
slots, exhaustion, clumping, eligibility latency, overlapping epochs, sustained and competing traffic) is
moved later. It becomes decision-relevant only if a fixed number of safe real or cover packets can
actually populate the slots; until such a slot-population mechanism exists, cadence is not on the critical
path.

### Co-residency compile — an unresolved experiment-selection gate (correction)
The earlier "functional size mechanism" co-residency probe is withdrawn as under-specified. A co-residency
compile is admissible only once an **exact endpoint-safe mechanism** is named, with its concrete packet
transformations and recovery semantics stated (what bytes are added, removed, or rewritten, and how the
unchanged endpoints recover the correct stream). Until such a mechanism is named, this is an open
experiment-selection gate, not a scheduled experiment. It must not be run against a placeholder "size
mechanism."

**Author:** research-scientist (measurement specialist) · **Date:** 2026-08-10
**Upstream (READ-ONLY):** `/home/philip/Projects/DNP3` pinned at `7c4a5a7` (`PROVENANCE.md`).
**Discharges:** the obligations in `PROOF_OBLIGATIONS.md` (A functional, B invariance, C accounting).
**Reuses:** the offline leakage harness at
`research/size_timing_coresidency/evidence/leakage/scripts/` — deterministic Miller–Madow MI, the three
permutation nulls, cluster/stratified/paired bootstraps, leave-one-flow-out (`leakage_lib.py`). This
plan **extends** that harness in three ways it does not yet cover: (1) equivalence testing (TOST /
(ε,δ)) instead of one-sided leak detection, because invariance is a null-shaped claim; (2) leave-one-
session-out and leave-one-device-out in addition to leave-one-flow-out; (3) a per-transaction state
filter driven by the byte-diff scorer so B is evaluated only over `PATTERN_NORMAL`.
No hardware in this file except the two probes named in §7 and §8, which are gated on Philip's explicit
authorization per upstream `CLAUDE.md`.

---

## 1. Design under test and secrets

- **Design:** the fixed-transcript template `T*` (constant `K`, `S_i`, `d_i`; `X`-independent schedule
  `t_i`; normalized rewritable header `h_rw`), calibrated to the six-capture corpus.
- **Secret `X`:** device identity (SEL-751 / AB1400 / ION7550) and response content (byte-total `L`,
  point values, control-vs-read). Evaluated at fixed public `C` (same polls, cadence, request sizes).
- **Response direction only.** Request-direction leaks (request size, window trajectory) are upstream of
  the switch and out of scope by topology (`PROOF_OBLIGATIONS.md §0.1`); the plan states this in every
  invariance readout rather than silently including request features.

---

## 2. Analysis plan (pre-registered before any data is collected)

### 2.1 Deterministic mutual-information encoding

- Discrete features encoded exactly; continuous features (gaps, duration, `t_i`) discretised into 16
  equal-frequency bins via `quantile_bin` with the fixed seed. MI is Miller–Madow-corrected plug-in
  propagated through `I = H(X)+H(Y)−H(X,Y)` (`leakage_lib.mi_mm`). Every encoding is a pure function of
  the input and the seed — no learned bins, no RNG state read from the global.
- Effect size for small effects is **MI minus the permutation-null mean**, never raw MI (plug-in MI has a
  positive bias floor ~0.5 bits on a jittered 16-bin joint, `leakage-measurements.md:§8.8`).

### 2.2 Permutation nulls, matched to the secret's structure

Reuse the three schemes from `leakage_lib.py`, chosen by what the secret is — using the wrong one is the
classic error this corpus punishes:

- Secret varies **within** a flow (response size / content): **circular block-shift within flow**
  (`perm_null_block`). Preserves the alternating control/read serial structure.
- Secret is **constant within** a flow (device label): **exhaustive flow-label permutation**
  (`perm_null_flowlabel`), exact not sampled.
- i.i.d. row permutation is used only where rows are genuinely exchangeable (rare here) and is flagged at
  the call site.

### 2.3 Bootstrap confidence intervals with valid clustering

- **Cluster the resampling unit by the dependence structure, not by the row.** Flows within a session are
  not independent; sessions of the same unit are not independent; units of the same model are not
  independent. Three nested resampling levels:
  - `cluster_bootstrap_ci` over **flows** for a within-session statement (existing).
  - a **session-level** cluster bootstrap (resample whole capture sessions) for a cross-session statement.
  - a **device-model-level** cluster bootstrap (resample whole physical units) for a cross-unit statement
    — only meaningful once >1 unit per model exists (§4).
- Within-flow statistics use `stratified_bootstrap_ci` with the pivotal (basic) interval, because
  resampling with replacement thins the joint support and biases plug-in MI upward
  (`leakage-measurements.md:§1`).
- Paired deltas (design vs native, or design-A vs design-B) use `paired_bootstrap_delta` on the same
  resampled clusters.

### 2.4 Equivalence testing — the extension the invariance proof needs

Leak-detection asks "is there a difference?" Invariance asks "is it the same?" Non-significance in a
detection test is **not** invariance. For every randomized feature (B4, and any jittered gap), register:

- a **margin Δ** (max tolerable TV/KS distance between `P(f|x)` and `P(f|x')`) or an **(ε, δ)** budget;
- a **TOST** two-one-sided-test procedure at level α = 0.05 that must **reject** "distance ≥ Δ";
- a **power target** 1−β ≥ 0.8 to detect exactly Δ, with the sample size (number of sessions) chosen to
  meet it. The six-flow corpus cannot (its flow-level null bottoms at p = 0.0769,
  `leakage-measurements.md:§8.2`); this is the quantitative driver for §4.
- for the (ε, δ) route, an **empirical-ε lower bound** from a distinguishing attack (§5), reported
  alongside the analytic ε — an unaudited ε is not accepted.

Exact-equality features (B1, B2, B3, B5, B6) skip TOST and use the **byte-diff scorer**: assert the
feature collapses to one value across all `x`, and `MI(feature ; X) = 0` inside its null.

### 2.5 The correct chance baseline

**Chosen baseline: the analytic no-information balanced accuracy `1/C` under a uniform prior — `0.5` for a
two-secret (pairwise) indistinguishability test, `0.3333` for the three-device task — reported jointly
with the Bayes-optimal balanced accuracy computed analytically from the empirical class-conditional
transcript distribution `P(feature | class)`.** The Bayes-optimal number (e.g. size-only device BA =
**0.5082**, `leakage-measurements.md:§7.1`) upper-bounds *every* classifier and is the number a
fixed-transcript defense must collapse to `1/C`; the `1/C` line is the target it must reach.

**Why not a classifier's fold-majority result.** Under leave-one-*-out CV with an uninformative feature
set, a trained classifier does **not** sit at `1/C`. Unweighted, it collapses to the training-majority
class and scores balanced accuracy **0.000** on the held-out class (`leakage_lib.make_model` docstring;
`leakage-measurements.md:§1`); class-weighted, it drifts to ~0.3888 with a wide CI (the all-features-
blanked control). Both numbers are artifacts of the CV construction and the class prior, they move run to
run, and using either as "chance" credits the *defense* with the *classifier's* weakness. The analytic
`1/C` and the Bayes-optimal ceiling are properties of the distribution, computed with zero training, and
are the only defensible references. For MI the analogue of "chance" is the **permutation-null band**
(mean and p95), not zero, for the same bias reason.

### 2.6 Models (sensitivity only, never the baseline)

Random forest (300 trees, `class_weight="balanced"`) primary; depth-6 decision tree and multinomial
logistic regression as sensitivity (`leakage_lib.make_model`). Classifiers are used to show an *attacker*
cannot exceed the Bayes-optimal ceiling — they are never the chance reference.

---

## 3. Cross-validation: three generalization axes

| axis | holds out | answers | when valid |
|---|---|---|---|
| **leave-one-flow-out** | one TCP flow | does invariance survive a flow-constant nuisance not seen in training? | now (6/12 flows) |
| **leave-one-session-out** | one whole capture session | does it survive session-specific latency / cold-poll / clock offset? | needs >1 session (§4) |
| **leave-one-device-out** | one physical unit | does the transcript template generalize to a device the calibration never saw? | needs the third device held out; **needs >1 unit/model to claim families** |

Leave-one-device-out is the sharpest test of a *fixed* transcript: if `T*` is calibrated on two devices
and a held-out third departs it, the template is device-specific and the invariance claim is local.

---

## 4. Independent sessions and physical units (hard requirement)

- **More than one independent capture session is mandatory**, not optional. It is the cheapest possible
  strengthening of every interval and the only fix for the flow-level null bottoming at p = 0.0769
  (`leakage-measurements.md:§8.2, §9.3`). Target ≥ 5 sessions per device, captured on different days /
  connection instances, so the session-level cluster bootstrap and leave-one-session-out have degrees of
  freedom. No new hardware needed — just more runs.
- **Eventually more than one physical unit per device model.** Every 1.000 in the upstream stack result
  is a statement about three specific units in one lab configuration, not three device *families*
  (`leakage-measurements.md:§8.1`, the R10 ceiling). A cross-family invariance or leakage claim is
  unprovable until a second SEL-751 (different firmware) and a second unit of each model exist. Until
  then every claim is scoped "these units, this configuration".

---

## 5. Attack models (adversary side of the invariance test)

Each attack is a Bayes-optimal-bounded discriminator over one observable axis, evaluated on `PATTERN_NORMAL`
transactions, against secret `X`. Axes and the specific upstream leak each targets:

| id | axis | observable | targets |
|---|---|---|---|
| K1 | **count** | segment count `K` | the split "beacon" (`leakage-measurements.md:§4.2`, count MI 0.0687→1.0678) |
| K2 | **sizes** | `{S_i}`, `Σ S_i`, per-packet length | invertible-sum leak; `ip.len` |
| K3 | **gaps** | inter-segment gaps `δ_i` | jitter-attenuated timing channel (`§6.3`) |
| K4 | **duration** | `t_K − t_1` | the 60.6%-of-H re-encoding (`§6.2`) |
| K5 | **direction** | `d` sequence, ACK-mode pattern | ACK-mode (SEL-751 separate-ACK, `adversary-model.md:B-2`) |
| K6 | **headers** | `h_rw` and `h_endpoint` (TSval, ip.id, window, seq/ack, PSH) | stack channel 1.000 + endpoint-stamped leaks (`adversary-model.md:F2,T-7..T-12`) |
| K7 | **request features** | request size, window trajectory | topological residual, reported as out-of-switch-reach, not as a defense failure |
| K8 | **cross-axis composition** | K1..K6 jointly | the composed size+timing vector (`§6`); a per-axis pass with a joint fail is the failure mode to catch |

K8 is run because upstream showed a defense can normalize one axis while a mechanism refills another in
the same pass. The joint discriminator is the real adversary; per-axis passes are necessary, not
sufficient.

---

## 6. Experiment matrix

### 6.1 Functional (Class A) — offline replay + HIL

| exp | discharges | method | pass |
|---|---|---|---|
| FA-1 | A1,A2,A3 | replay all six captures + fc matrix through the `T*` shaper model; assert byte identity, 0 malformed DNP3, 0 `tcp.analysis` flags on recovered stream, SOE parity per fc | 0 mismatches, count reported |
| FA-2 | A4 | replay the 12,204-byte large READ; recover byte-identical | transport sequence continuous, CONFIRM handled |
| FA-3 | A5 | interleave a DIRECT_OPERATE with a READ (concurrent outstanding) | 0 cross-assignment |
| FA-4 | A6,A7,A8 | scapy fault injection: drop, reorder, duplicate, retransmit, seq-wrap, RTO/idle | recover byte-identical **or** book `AVAILABILITY_BYPASS`; 0 silent corruption; 0 indefinite hold |
| FA-5 | A1-A9 (HIL) | **hardware-in-the-loop**: master ↔ switch ↔ physical SEL-751 (READ-only), rig run, ≥ 800 measurements, clean pcap 0 resets/retransmits | rig-grade byte identity + SOE parity (loopback is smoke only, `CLAUDE.md`) |

### 6.2 Invariance (Class B) — offline MI/equivalence, then HIL confirmation

| exp | discharges | method | pass |
|---|---|---|---|
| IB-1 | B1,B2,B3,B5,B6 | byte-diff scorer + `MI(feature ; X)` inside matched null, on `PATTERN_NORMAL` | feature collapses to one constant; MI inside null |
| IB-2 | B4 | TOST / (ε,δ) equivalence on `t_i`, gaps, duration; power ≥ 0.8 for margin Δ | equivalence rejected-in-favour at α=0.05, powered |
| IB-3 | B5e | measure `MI(TSval, ΔTSval, ip.id, window, seq/ack, PSH ; X)` on the real relay | **expected FAIL**; quantify residual and scope the claim (this is §7) |
| IB-4 | B7 | overflow / large-READ + integrity poll; measure continuation-epoch count vs `X` | invariant continuation, else booked `PATTERN_OVERFLOW` |
| IB-5 | B8 | idle vs busy window transcript two-sample | idle transcript == busy transcript |
| IB-6 | B (attacks) | run K1..K8 vs Bayes-optimal chance baseline; LOFO + LOSO + LODO | every axis and the joint at `1/C`; ceiling collapses to `1/C` |

### 6.3 Accounting (Class C)

| exp | discharges | method | pass |
|---|---|---|---|
| CC-1 | C states | run FA/IB while logging the five data-plane counters; reconcile to host byte-diff scorer | conservation identity holds; two counts agree |
| CC-2 | C consume | recompute B only over `n_normal`; report coverage `n_normal/n_total` | headline carries coverage; no privacy on bypass/overflow/drop |
| CC-3 | C stress | reservoir-depletion + burst + loss; drive `AVAILABILITY_BYPASS` deliberately | 0 `PATTERN_DROP`; mixture reported as a mixture, never a median |

### 6.4 Overhead (reported with every design point, not separately)

Bandwidth (added bytes/s and % over native), latency (added first-byte and total per transaction),
packet count (emitted vs native). Fixed-K overhead is set by `L_max`; the corpus max (183 B) is
unrepresentative — the 12,204-byte READ exists (`leakage-measurements.md:§8.3`), so overhead is reported
both for the corpus mix **and** projected for a template that must cover the large READ (≈ two orders of
magnitude), stated as a floor for this traffic mix, not the deployment cost.

---

## 7. FIRST FALSIFICATION EXPERIMENT (cheapest test that could kill the leading design)

**One line:** on the existing SEL-751 and D-sweep pcaps, run the deterministic-MI + matched-null
equivalence test on the endpoint-stamped outer-header sub-vector of `h_i` — `ΔTSval`, `ip.id`
increments, and the advertised-window trajectory — against the secret; the switch cannot rewrite these
without breaking the endpoint's PAWS/RTT (no-proxy constraint), so if any carries `X` above its null
(upstream already measures `ΔTSval` rejecting at ≈10^−51 on d16, `ip.id` at 82/82 unit deltas, window at
`W(n)=W0−s·n`), the fixed-transcript claim over `h_i` is falsified for the price of one read-only tshark
pass — no shaper, no compile, no hardware.

Why this one: it attacks the single clause the leading design cannot satisfy in principle at this
vantage, it needs zero new code (tshark + `leakage_lib`), and unlike a template-overflow failure it has
**no** in-network mitigation. If it fails (it is expected to), the honest claim narrows to `(K, S_i, d_i,
t_i, h_rw)` invariance with the endpoint-stamped fields as a stated residual — and that narrowing must
happen before any build. The immediate second-cheapest falsification is the template-capacity test:
replay the 12,204-byte READ through a corpus-calibrated `T*` and check whether the outer transcript stays
shape-identical to a 37-byte response — it overflows, forcing `PATTERN_OVERFLOW` (privacy lost) or a
12 kB template (~100× overhead).

Inputs (all READ-ONLY, hashes in upstream `ENVIRONMENT.json`): `Traffic Trace/SEL751.pcap`,
`defense3/evidence/physical_repaired/20260730T194855Z/pcaps/blk_r*_native.pcap` and `…_d16.pcap`.

---

## 8. FIRST RESOURCE-ONLY COMPILE PROBE

**One line:** graft onto a *copy* of the live `defense4/timing/p4/defense4_caseA.p4` the minimal fixed-K
emitter — ingress multicast/mirror replication to `K` egress copies + per-copy pad/truncate to constant
`c` + an epoch slot counter — and read the stage / logical-table-ID / tagalong / PHV deltas from the
compiler logs; compile-only, no switch.

Why this primitive: the resource audit found the egress *size* graft is free (12/2 ingress/egress,
`p4-resource-audit.md:§5.2`), but flagged that **replication/splitting is ingress work landing in stages
8–11, which are at 16/16 logical table IDs — "the one place where the zero-ingress-cost result does not
transfer" and must be priced with its own compile before any design commits** (`p4-resource-audit.md:§5.5`).
The fixed-transcript emitter needs exactly that replication path, so this is the first thing that can
prove the design infeasible on resources.

- **Compiler:** `/home/philip/bf-sde-9.13.1/install/bin/bf-p4c --target tofino --arch tna -g` (p4c
  9.13.1, SHA e558d01), in a scratch dir; nothing under `defense4/` modified.
- **Read only** `table_summary.log` (ingress/egress stages, critical path, logical tables),
  `mau.resources.log`, `phv_allocation_summary_0.log`, `table_dependency_summary.log` — the same
  compiler-produced logs `summarize.py` consumes.
- **Kill criterion:** if replication pushes ingress past 12 stages or exhausts the tail LTIDs (measured
  exchange rate ≈19 tables/stage, `p4-resource-audit.md:§3.1`), the fixed-K emitter does not co-reside
  with the live timing core and the design is resource-infeasible as drawn — a full negative result.
- **Baseline to diff against:** the live core at 12 ingress / 0 egress, tagalong 4/8 collections
  (`p4-resource-audit.md:§1.2, §4.1`), with 1 free ingress stage and 2 free tagalong collections of
  headroom (`§5.4`).

---

## 9. Provenance every result must carry

Mirror `evidence/leakage/out/ENVIRONMENT.json`. Each result (a JSON + a log) records:

- **seed** (single, threaded explicitly — reuse `SEED = 20260810` or a declared new one; no global RNG);
- **interpreter + packages**: `$RESEARCH_PYTHON` = `~/.venvs/research/bin/python` (3.12.13), numpy/scipy/
  pandas/scikit-learn/scapy/matplotlib versions;
- **input pcap SHA-256** and byte counts;
- **analysis script SHA-256** (16-hex) for every script that produced the number;
- **upstream pin**: commit `7c4a5a7` and the relevant blob SHAs from `PROVENANCE.md`;
- **for compile probes**: bf-p4c version + SHA (e558d01), source `.p4` SHA-256, and the exact log
  file:line each resource number came from;
- **the state label** (`PATTERN_NORMAL` / overflow / bypass / drop / recovery) each transaction was
  filtered on, so any invariance number is traceable to the `n_normal` subset it was computed over.

A number destined for a paper must be traceable to config + seed + upstream commit + script hash. Nothing
is reported from memory; every resource number cites a log line; every leak/invariance number cites its
null and its clustering level.

---

## 10. Reproducibility checklist

- [ ] Single explicit seed threaded through every estimator; no global RNG state read.
- [ ] MI is Miller–Madow-corrected; small effects reported as MI-minus-null-mean.
- [ ] Permutation null matched to secret structure (block-shift for within-flow, flow-label for
      flow-constant); stated at each call site.
- [ ] Bootstrap clustered at the correct level (flow / session / device), never at the row.
- [ ] Invariance uses equivalence (TOST / (ε,δ)) with a pre-registered margin and power ≥ 0.8, not
      non-significance.
- [ ] Chance baseline = analytic `1/C` + Bayes-optimal ceiling; never a classifier fold-majority number.
- [ ] LOFO + LOSO + LODO all reported; claims scoped to the axis actually tested.
- [ ] ≥ 5 independent sessions/device before any powered invariance claim; >1 unit/model before any
      family claim.
- [ ] B computed only over `PATTERN_NORMAL`; coverage `n_normal/n_total` in the headline.
- [ ] Class-C counters reconciled to the host byte-diff scorer; conservation identity checked.
- [ ] Overhead (bandwidth, latency, packet count) reported at each design point, corpus mix and
      large-READ projection.
- [ ] Provenance block (§9) attached to every JSON result.
- [ ] Hardware steps (FA-5 HIL, §8 compile probe) gated on Philip's explicit authorization; physical
      SEL-751 stays READ-only; no git run in either repo.

# Proof Obligations — DNP3 Fixed-Transcript Defense

**Author:** research-scientist (measurement specialist) · **Date:** 2026-08-10
**Upstream (READ-ONLY):** `/home/philip/Projects/DNP3` pinned at `7c4a5a7` (see `PROVENANCE.md`).
**Scope:** proof obligations only. No hardware contact. No switch, no relay, no compile in this file.
This working repo is not ADTA, GridCloak, or Defense 4; those are frozen upstream results referenced,
never rewritten.

---

## 0. What must be proven, stated once

A DNP3 fixed-transcript defense sits on one switch at the outstation edge. It reshapes the wire so the
observable outer transcript

```
O = [ (d_i, S_i, t_i, h_i) ],  i = 1 .. K
      d_i = direction of packet i        S_i = outer size of packet i
      t_i = release time of packet i      h_i = outer-header feature vector of packet i
```

carries nothing about the protected secret. Write `X` for the secret (which device this is, and what
its response said — point values, control action, response length), and `C` for everything public and
fixed by design (the polling profile, the request stream, the deployment parameters, the defense design
and its constants — Kerckhoffs). The target is

> **P( O | X = x, C = c ) = P( O | X = x', C = c )   for all secrets x, x' at fixed public c.**

Three separate things must hold for that sentence to mean anything, and they fail independently. They
are proven separately, by different methods, and a pass on one is not evidence for the others:

- **(A) Functional correctness** — the reshaped wire still delivers every inner byte, exactly. A
  perfectly invariant transcript that corrupts the relay's response is not a defense, it is an outage.
- **(B) Transcript invariance** — in a declared steady state (`PATTERN_NORMAL`), `O` does not depend on
  `X`. This is the privacy claim proper.
- **(C) Privacy-failure accounting** — every departure from the canonical transcript is counted, and no
  privacy is claimed over any transaction that departed. Without this, a defense that silently fails
  open on a third of transactions can still report a clean median (this exact failure is on the upstream
  record: `CHARTER.md:54-59`, D4 held 160/240 and bypassed 80/240, and the median hid it).

### 0.1 The vantage asymmetry that scopes every obligation

The observer is on the WAN **between the master and the switch** (`defense4/README.md:10`, quoted at
`adversary-model.md:F1`). So for the relay→master (response) direction the observer is **downstream** of
the defense and sees the shaped stream; for the master→relay (request) direction the observer is
**upstream** and sees the raw stream. Consequences that bound what any transcript claim can cover:

- Any request-direction leak is **out of the switch's reach at this vantage**. The request size already
  separates control from read at balanced accuracy 1.000 (`leakage-measurements.md:§2.2`), and the
  advertised-window trajectory reflects the *request* payload size back into the response direction
  (`adversary-model.md:T-7`). A response-shaping transcript claim must therefore be stated over the
  response direction only, or it is false on arrival.
- `C` includes the request stream. Invariance is proven **at fixed `C`**: same polls, same cadence, same
  request sizes. Varying the operator's action is varying part of `X` that lives upstream, and the
  transcript defense cannot cover it. State this boundary in every claim.

### 0.2 The leading design these obligations are written against

The only mechanism consistent with all five upstream leakage results (`leakage-measurements.md:§9`) is
**fixed-transcript / fixed-K quantised emission**: a constant canonical transcript template `T*` —
constant count `K`, constant per-slot outer sizes `S_i`, constant direction sequence `d_i`, a release
schedule `t_i` that does not depend on `X`, and an outer-header vector `h_i` normalized to a constant.
Adaptive-K still leaks (4.0% of H, `leakage-measurements.md:§6.4`); only *fixed* K gives exact zero.
Obligations B and C are written to test `T*` specifically, and the first falsification experiment
(EXPERIMENT_PLAN §7) attacks its weakest clause.

---

## (A) Functional-correctness obligations

The defense may reorder, split, pad, delay, or add outer packets, but the master must reconstruct the
exact inner TCP/DNP3 byte stream the relay produced. The invariant is byte identity, extended from the
existing splitter's `b"".join(chunks) == data` (`dnp3_split_harness/split_server.py`, exercised
read-only in `leakage-measurements.md:§4`) to the whole delivered stream.

| id | obligation | pass criterion (falsifiable) | evidence artifact |
|---|---|---|---|
| A1 | **Byte-identical inner recovery.** Decapsulating `O` yields the exact inner byte stream the relay emitted, per transaction. | `reconstruct(O) == inner_bytes` for **every** transaction in the test corpus; 0 mismatches. Report the count, not a rate. | per-txn byte-diff log |
| A2 | **No loss / dup / reorder / corruption of inner data.** | Recovered TCP stream has 0 gaps, 0 duplicate payload bytes, monotone sequence, all DNP3 CRC-16/DNP blocks intact (**no CRC recompute**), 0 malformed frames under the DNP3 dissector. | tshark `dnp3` + `tcp.analysis` on recovered stream |
| A3 | **Function-code coverage.** Correct behavior under READ (fc 1), DIRECT_OPERATE (fc 5), and SELECT (fc 3)/OPERATE (fc 4) SBO. | Master SOE parity: recovered point values and command statuses match the native run byte-for-byte, per fc. SBO SELECT must precede OPERATE and neither is dropped. | SOE CSV parity per fc |
| A4 | **Multi-segment responses.** A response spanning multiple DNP3 transport fragments / TCP segments (FIR/FIN, transport sequence) reassembles. | The 12,204-byte / 49-link-frame / 20-TCP-segment large READ (`PROVENANCE.md` large-READ blob; `baseline_segmentation.md`) recovers byte-identical; transport sequence continuous; app-layer CONFIRM handled. | large-READ recovery log |
| A5 | **Concurrent transactions.** Two or more outstanding request/response pairs (pipelined polls, or a control interleaved with a poll) do not cross-contaminate. | Each transaction's inner bytes recovered and attributed to its own request; 0 cross-assignment. | interleaved-replay log |
| A6 | **Loss and retransmission.** Under packet loss and TCP retransmission on either leg, the shaper does not desynchronize its state or emit inner bytes twice. | Inject loss/retransmit (scapy); recovered stream still byte-identical **or** the transaction is booked `AVAILABILITY_BYPASS` (Class C) — never silently corrupted. | fault-injection matrix |
| A7 | **Sequence-number wraparound.** The shaper's per-flow state survives the 32-bit TCP seq wrap. | Drive seq across the 2^32 boundary; state (reservoir index, epoch counter) remains consistent; recovery byte-identical. | wrap test log |
| A8 | **Timeouts.** On master RTO / no response / connection idle, the shaper releases or fails open within a bounded time; it never holds a protection-relay packet indefinitely. | Every held inner packet is released or bypassed within the declared bound `RTO_max`; 0 indefinite holds. Ties to the upstream deadline/fail-open budget (`retirement-defect.md:§2`). | hold-time distribution |
| A9 | **Availability-first fail-open.** When the shaper cannot place inner data (buffer/PHV/reservoir pressure), it forwards native rather than drops. | 0 `PATTERN_DROP` events on the protection link; any inability to shape becomes `AVAILABILITY_BYPASS`, counted in Class C. | Class-C counter reconciliation |

**A is a gate on B.** Invariance is only claimed over transactions that passed A1-A5 in `PATTERN_NORMAL`.
A transaction that fell to `AVAILABILITY_BYPASS` (A6/A9) is correct-by-forwarding but carries **no**
privacy claim (Class C). The two verdicts are reported side by side, never merged.

---

## (B) Transcript-invariance obligations (state = PATTERN_NORMAL)

For each transcript feature, the canonical transcript `T*` must be invariant to `X` at fixed `C`. The
obligation splits by feature type into **exact-equality** features (discrete, meant to be a single
constant) and **randomized-design** features (continuous, where hardware makes exact equality
impossible). The distinction is not cosmetic — it changes the statistical test from a byte-diff to an
equivalence test, and it changes what "indistinguishable" is allowed to mean.

### B.0 When exact equality is required, and when a randomized design is acceptable

- **Exact equality (Δ = 0) is required** for every feature the switch fully controls in the emitted
  (response) direction: count `K`, per-slot outer sizes `S_i`, direction sequence `d_i`, epoch length,
  and the *rewritable* part of `h_i`. These are set by construction, so the only honest target is a
  single constant value across all secrets. The test is a support-collapse / byte-diff check plus
  `MI(feature ; X) = 0` empirically inside its permutation null. Any spread across secrets is a fail.

- **A randomized (fixed-distribution) design is acceptable** only for the release schedule `t_i` and any
  jitter, because a real switch cannot emit a byte-exact clock (queueing, TM, loopback-RTT variance —
  upstream measures loop RTT at (1036,1176] ns, `ksweep` memory note). Here the mechanism draws `t_i`
  from a distribution `D` that is **fixed and independent of `X`**. Indistinguishability is then defined,
  and must be one of these two, declared in advance:
  - **(Δ)-transcript-indistinguishable:** for every secret pair `(x, x')` and every randomized feature
    `f`, a two-one-sided-test (TOST) equivalence procedure **rejects** "distance(P(f|x), P(f|x')) ≥ Δ" at
    level α with pre-registered power ≥ 1−β, where distance is total-variation or the KS statistic and Δ
    is a pre-registered margin. **Non-rejection of a difference-null is not acceptable** — absence of a
    detected difference in an under-powered test is not invariance (the six-flow corpus already bottoms
    the flow-level null out at p = 0.0769, `leakage-measurements.md:§8.2`; that is why power is part of
    the obligation).
  - **(ε, δ)-transcript-indistinguishable:** the mechanism satisfies
    `P(O ∈ S | x) ≤ e^ε · P(O ∈ S | x') + δ` for all `S`, with `ε, δ` declared and validated by an
    empirical-ε distinguishing-attack **lower bound** (a membership/attribute inference attack that
    lower-bounds ε), not merely asserted from the noise calibration.

  Exact equality is the Δ = 0 / ε = 0 special case, and is what the discrete features must meet.

- **The header sub-vector `h_i` is split** into a *rewritable* part (fields the switch can normalize in
  the response direction without breaking the endpoint: e.g. IP TTL, DF, DSCP) and an
  **endpoint-stamped** part the switch cannot touch without a full proxy (which the constraints forbid):
  the TCP timestamp `TSval`/`TSecr`, the strictly-incrementing `ip.id`, the advertised-window trajectory,
  the sequence/ack advance, and PSH boundaries (`adversary-model.md:T-7..T-12, IP-3`). The invariance
  claim over `h_i` **must be scoped to the rewritable part**, and the endpoint-stamped part must be
  either (i) proven already invariant to `X` on the real relay (it is not — see §B.2), or (ii) declared
  out of scope with the resulting privacy loss stated. This is the load-bearing scoping decision.

### B.1 Feature-by-feature obligations

| id | transcript feature | type | pass criterion | null / clustering |
|---|---|---|---|---|
| B1 | **count K** | exact | single constant `K` for all `x`; `MI(K ; X)=0` inside null | flow-label perm (device-constant secret) / block-shift (size secret) |
| B2 | **per-slot sizes S_i** | exact | each `S_i` a single constant; joint `MI(S_{1..K} ; X)=0` inside null; and `MI(Σ S_i ; L)=0` (the invertible-sum leak that killed splitting, `leakage-measurements.md:§4.2`) | block-shift within flow |
| B3 | **direction sequence d_i** | exact | one constant direction string; `MI(d ; X)=0` | flow-label perm |
| B4 | **release schedule t_i** | randomized | `(Δ)`- or `(ε,δ)`-indistinguishable per B.0; **and** duration `= t_K − t_1` carries nothing: `MI(duration ; L)` inside null (this is where splitting re-encoded 60.6% of H, `leakage-measurements.md:§6.2`) | equivalence TOST + block-shift |
| B5 | **rewritable header h_i** | exact | normalized fields constant across `x`; `MI(h_rw ; X)=0` | flow-label perm |
| B5e | **endpoint-stamped header** | scoping | either proven invariant on the real relay, or declared out of scope with quantified residual | flow-label perm; **expected FAIL, see B.2** |
| B6 | **epoch length** | exact | inter-epoch interval a single constant; `MI(epoch_len ; X)=0` | block-shift |
| B7 | **continuation behavior** | exact/acct | number and shape of continuation epochs invariant, **or** the transaction is booked `PATTERN_OVERFLOW` (Class C) | conditioned on state |
| B8 | **silence / busy behavior** | exact | the transcript in an idle period is identical to a busy period (no duty-cycle / activity leak, `adversary-model.md:B-7`); cover emission if required | two-sample over idle vs busy windows |

### B.2 The obligation that is expected to fail, stated up front

B5e (endpoint-stamped header) is expected to **fail** on the real SEL-751 and the failure has no
in-network fix under the "no proxy" constraint. Upstream already measured it: `ΔTSval` rejects the
concealment hypothesis at p ≈ 10^−51 on d16 (`adversary-model.md:F2`); `ip.id` advances by exactly 1 on
82/82 frames and preserves the relay's true transmit order/count through any hold (`adversary-model.md:IP-3`);
the advertised window walks `W(n) = W0 − s·n` (`adversary-model.md:T-7`). A fixed-transcript claim over
the *full* `h_i` is therefore false. The honest form of the claim is invariance over `(K, S_i, d_i, t_i,
h_rw)` **with the endpoint-stamped fields declared residual**, and the residual quantified. Recording
this as a named, expected-fail obligation is what stops it from being discovered late.

### B.3 What "supports the claim" requires here

Invariance is a *null-shaped* claim, so a single dataset can only ever be *consistent with* it. The
proof strengthens from "consistent with" to "supports" only when B is discharged with (i) exact equality
for discrete features, (ii) a powered equivalence test for randomized features, (iii) valid clustering
so within-flow dependence is not mistaken for evidence, and (iv) generalization across **flow, session,
and device** (EXPERIMENT_PLAN §3). It reaches "supports across device families" only with more than one
physical unit per model (§B threat, `leakage-measurements.md:§8.1`).

---

## (C) Privacy-failure accounting

Every departure from the canonical transcript is an event that must be counted in the data plane and
reconciled offline. The counters mirror the upstream lifecycle counters (`ACK_REL_RETIRE`, `RESP_BYPASS`,
`retirement-defect.md:§1.4`) so the same audit that caught the D4 mixture catches ours.

### C.1 The five states

| state | when the mechanism enters it | privacy claim | counter (data-plane register) counts |
|---|---|---|---|
| **PATTERN_NORMAL** | inner response fits `T*`; reservoir and epoch aligned; shaping applied | **yes** — the only state with a privacy claim | `n_normal`: transactions emitted as the canonical transcript |
| **PATTERN_OVERFLOW** | inner response exceeds template capacity (`Σ slot budget`, e.g. a large READ or integrity poll) | **no** for the overflowing txn | `n_overflow` (+ `n_overflow_epochs`): transactions that needed continuation beyond `T*`, and how many extra epochs — a secret-dependent count by construction |
| **AVAILABILITY_BYPASS** | shaper forwards native to protect relay availability — reservoir depletion, buffer/PHV pressure, RTO deadline, unknown fc, malformed frame | **no** for the bypassed txn | `n_bypass`: native-forwarded transactions. Reuses the upstream `RESP_BYPASS` semantics |
| **PATTERN_DROP** | shaper withholds inner data it could not place (must be ~0 on a protection link) | **no**, and it is **also a Class-A failure** | `n_drop`: inner-data-loss events. Any nonzero value fails A9 |
| **RECOVERY_MODE** | after any departure, the mechanism re-locks epoch/reservoir; transcript may differ during re-lock | **no** for txns emitted before re-lock | `n_recovery_txn`: transactions emitted while not yet re-locked |

### C.2 The auditable identity

The counters must conserve:

```
n_normal + n_overflow + n_bypass + n_drop + n_recovery = n_total
```

This identity is checked two ways that must agree: the data-plane registers read at experiment end, and
an **independent host-side byte-diff scorer** that classifies each transaction from the pcap alone (did
its outer transcript equal `T*`?). Disagreement between the two counts is itself a defect (it is how the
upstream `ACK_REL_RETIRE == RESP_BYPASS` identity exposed the retirement bug, `retirement-defect.md:§1.4`).
No scorer that reports only a median or a mean is admissible — the mixture must be reported as a mixture
(MEMORY: "don't headline a median over a mixture").

### C.3 How a proof consumes the counters

- The invariance claim (B) is evaluated **only over the `n_normal` subset**. The `PATTERN_NORMAL` filter
  is applied before any MI or equivalence test, using the byte-diff scorer's per-transaction state label.
- The headline privacy statement carries its coverage explicitly:
  *"P(O|x) = P(O|x') over PATTERN_NORMAL, at normal-state coverage `n_normal / n_total = XX%`."*
  A defense with `n_bypass > 0` claims **no** privacy on that mass; the coverage number is part of the
  result, not a footnote.
- `n_drop > 0` fails A9 and voids the run for both A and C.
- `n_overflow` and `n_overflow_epochs` bound the large-READ threat directly: if the real polling profile
  contains integrity polls or large READs (it does — `PROVENANCE.md` large-READ blob), `n_overflow` is
  the rate at which the transcript departs, and the first falsification experiment measures whether that
  rate is nonzero under a corpus-calibrated template.

---

## Cross-reference map (upstream evidence these obligations rest on, all READ-ONLY at 7c4a5a7)

| obligation | upstream anchor |
|---|---|
| A1/A2 byte identity | `dnp3_split_harness/split_server.py` assertion; `leakage-measurements.md:§4` |
| A4 large READ | `PROVENANCE.md` large-READ blob; `baseline_segmentation.md` |
| A8/A9 fail-open, hold bound | `retirement-defect.md:§2`; `CHARTER.md:54-59` |
| B2 invertible-sum leak | `leakage-measurements.md:§4.2` (ΔMI = 0, splitting relocates the leak) |
| B4 duration re-encoding | `leakage-measurements.md:§6.2-6.4` (60.6% of H; fixed-K = 0) |
| B5e endpoint-stamped headers | `adversary-model.md:F2, IP-3, T-7..T-12` |
| B (device ceiling) | `leakage-measurements.md:§3` (stack channel = 1.000, deterministic) |
| C states/counters | `retirement-defect.md:§1.4`; upstream `RESP_BYPASS`/`ACK_REL_RETIRE` |
| chance baseline | `leakage-measurements.md:§7.1` (Bayes-optimal 0.5082, not a classifier number) |

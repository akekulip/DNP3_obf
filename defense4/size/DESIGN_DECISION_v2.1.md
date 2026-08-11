# Design & Decision v2.1 — non-destructive correction of v2

**This corrects `DESIGN_DECISION_v2.md` (committed as `246630e`). v2 is preserved unchanged as a
review checkpoint and historical evidence; it is NOT the authoritative decision.** v2's adversarial
review (v2 §11) contained a material D4 error and several overcorrections. Where v2.1 conflicts with
v2, **v2.1 governs.** Numbers below are verified against the committed
`defense4/paper/METHODS_RESULTS.md`.

---

## 1. The D4 deadline correction (the central fix)

**The coverage horizon is `H = D_A + D_R`, not `D_R`.** D4 holds *both* deadlines:
`T_A = t_A + D_A`, `T_RESP = T_A + D_R = t_A + D_A + D_R`. A native response with CLRT `C` (measured
from the ACK) is held to the public deadline **iff `C ≤ H = D_A + D_R`**. The *observed* CLRT the
attacker sees is `T_RESP − T_A = D_R` (the plateau); an overtaking response (`C > H`) is released on
arrival and observed at `C − D_A`.

**The tested policy** (`METHODS_RESULTS.md:34`) is `D_A = 4 ms, D_R = 10 ms` → **H = 14 ms**. Campaign A
native OFF is `p99 = 13.67 ms, max = 15.65 ms` (`:75`). So **H = 14 ms is ≈ 0.33 ms above native p99** —
a thin but positive guard that covers roughly the native p99. **The review's claim "10 ms is below p99,
therefore D4 was misconfigured" is FALSE**: it compared p99 to `D_R` alone instead of to the horizon
`H = D_A + D_R`.

**The measured D4 result** (`:80–81`, `:95–97`) is a correct, honestly-reported bounded normalization,
not a misconfiguration:
- 237/240 within ≈10.2 ms; three late-safe-release observations ≈ 12.20, 16.70, 18.77 ms (**≈1.25% tail**).
- p5–p95 spread 5.69 → **0.05 ms** (118×); entropy 3.63 → **1.10 bits** (~12 → ~2 states).
- `METHODS_RESULTS.md` already states this: "a late safe release, not deadline normalization, and we
  never describe the population by its median or as an exact fixed value" (`:90–93`).

**The contribution this exposes — the principled answer to Dr. Lin's parameter question.** The three
parameters decompose cleanly and independently:
- **`H = D_A + D_R`** — the native-tail **coverage horizon**. Raising `H` covers more of the native tail
  (fewer late-safe releases).
- **`D_R`** — the **public observed CLRT** (the plateau the attacker sees). Independent of `H`.
- **`D_A`** — buys coverage (larger `H`) at the cost of **ACK delay + TCP risk** (holding the ACK longer
  interacts with the master's RTO and retransmit behavior).

This is a **privacy–latency–TCP tradeoff surface**, selectable from measured native quantiles per
deployment: choose `H` to cover the deployment's native CLRT to a target quantile, `D_R ≤ H` for the
public plateau (and the residual late-tail rate `= P(C > H)`), and `D_A = H − D_R` bounded by the RTO
margin. **This supersedes v2 §5's "10 ms ≈ p99 + guard on `D_R`," which was wrong.**

## 2. Baseline: stratified registry, not one forced distribution

v2 §11 (M2) said "reconcile to one distribution." **Corrected:** the 12.9 ms (outline), ~2.92 ms
(`METHODS_RESULTS`), and 1.4–1.9 ms steady / cold ~25 ms (memory) figures are **not one distribution
mis-measured** — they are different **capture regimes** (cold vs steady, workload, session, device
state). Do not average them. **Build a stratified native-CLRT baseline registry** keyed on the
covariates (state, workload, session), report each stratum, and derive `H`/`D_R` **per stratum /
deployment**. The multimodal cold-state tail (up to ~166 ms) is exactly what produces the D4
late-safe-release tail, and it must be characterized, not collapsed.

## 3. Theorem language corrected (precise bounded results, not universals)

- **"Device identity is invariant to timing+size" is NOT a theorem.** `m1_oracle` shows that in this
  small corpus `(TTL, TCP data_offset)` identifies the three **individual devices**. With one physical
  unit per model, that is an **empirical residual-channel result** (n=1/model), not a device-*class*
  impossibility. State it as such.
- **The cover-frame "strip" result is bounded**, not universal: it holds only for **additive,
  self-identifying** cover frames observed by a **reassembling DNP3-parsing** observer. It does **not**
  prove all size obfuscation is impossible.
- **The genuine bounded impossibility results** (state these precisely):
  1. **Byte-preserving splitting cannot hide aggregate transaction size from an aggregating observer.**
  2. **Publicly-identifiable additive cover cannot hide the original size from a parsing observer.**

  These two are real and defensible; the over-general "size obfuscation is null" language is not.

## 4. Restore the timing+size goal (do not narrow yet)

**The defensible goal remains:** *a unified Tofino-1 mechanism that reduces DNP3 timing- and size-based
fingerprint leakage while preserving operational semantics, with residual stack and application
features reported explicitly.*

The **"timing mechanism + two bounded impossibility results"** is a **strong fallback paper** if the
positive size mechanism fails its gates — **not** the declared final contribution. v2 §0.1 and §11
narrowed the project prematurely; **that narrowing is withdrawn.** The size mechanism is decided by its
gates (§5), not by assumption.

## 5. Both size candidates stay GATED (v2's "reject decoy-CROB" is withdrawn)

Two candidate size primitives remain live; neither is rejected, both are gated:

- **Address-scoped cover framing** (prepend a CRC-valid DNP3 link frame to a reserved/unused
  non-endpoint address; endpoint discards it, real frame unchanged). Semantics-preserving; helps a
  **non-parsing** observer. Gate: the C1–C8 endpoint-discard test + the unused-individual vs
  reserved-range address question (the two experts disagree — the test resolves it).
- **Configured inert decoys (encoding A)** — a *separate trailing* G12V1 header of decoy CROBs at
  **configured, valid, unwired** indices (execute SUCCESS, no physical action). Commit `92b8d3e` is
  bounded **software** evidence that an unmodified OpenDNP3 master **accepts the trailing decoy header
  and still emits the real OPERATE** (encoding B, merged into the real header, is rejected). This is a
  **legitimate candidate**, gated on physical validation and the master-acceptance caveats. v2's blanket
  "reject" is withdrawn.

Both sit on the safe-vs-indistinguishable tension (cover framing = strippable but never touches the app
layer; decoys = not trivially strippable but reach the app layer). Keep both until their gates decide.

## 6. Reachability corrected

"Every target reachable in ≤2 frames" is **not universal**: two cover frames add **at most 584 bytes**
(2 × max single-frame `L(250) = 292`). Reaching targets far above native needs more frames.
**Scoped to the observed support `{37,54,61,74,122,183}`**, every size reaches the common target
**183 B using zero or one cover frame** (verified: 37→+146, 54→+129, 61→+122, 74→+109, 122→+61,
183→+0, each a single legal frame). State the reachability result **for the measured support**, not as
a universal ≤2-frame claim.

## 7. Handshake normalizer status (fixing the v2 §3-vs-§11 inconsistency)

Accurate status: **standalone-built** (silicon byte-identical in isolation), **not integrated** into
the unified Defense 4 program, and **not yet validated** as a device-fingerprint defense (no measured
device-BA drop from ~1.0 to ~1/k on ≥2 devices). v2 §3 ("already built") and §11 ("unbuilt") were both
imprecise; this is the correct status.

## 8. Corrected decision & next steps

- **Keep the unified timing+size goal.** Timing-mechanism + two bounded impossibility results is the
  **fallback**, not the ceiling.
- **Both cover framing and configured inert decoys remain gated candidates.**
- **Report residual stack + application features explicitly** (device ID via `(TTL, data_offset)`;
  application structure/variation; request-direction activity) — as residual channels, honestly.

**Gates, in leverage order (all pre-hardware except where noted):**
1. **Characterize the H / D_R / D_A tradeoff** from a **stratified** native baseline (§1, §2) — the real
   Dr. Lin deliverable; also fixes v2's deadline error in the paper.
2. **Cover-frame endpoint-discard test** (C1–C8, software `split_server` first) — settles the size
   primitive's safety and the address question.
3. **Configured-decoy physical validation** (encoding A) — lifts `92b8d3e` from software to hardware.
4. **Reachability oracle** committed + the six hardcoded paths fixed (reproducibility, unchanged from v2 §9).
5. **Overhead / availability**: added latency, master-RTO margin, retransmit behavior, and reconcile the
   Case-C fail-open against the "0 bypass" headline (NIST SP 800-82 envelope).
6. **Second physical Case-A device** — lifts the mechanism claim off n=1 (hardware, authorization-gated).

**Provenance:** v2 (`246630e`) is retained as historical evidence. v2.1 is the corrected authoritative
decision. Nothing here is built or on hardware.

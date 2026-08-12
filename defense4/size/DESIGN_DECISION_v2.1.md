# Design & Decision v2.1 — non-destructive correction of v2

**This corrects `DESIGN_DECISION_v2.md` (committed as `246630e`). v2 is preserved unchanged as a
review checkpoint and historical evidence; it is NOT the authoritative decision.** v2's adversarial
review (v2 §11) contained a material D4 error and several overcorrections. Where v2.1 conflicts with
v2, **v2.1 governs.** Numbers below are verified against the committed
`defense4/paper/METHODS_RESULTS.md`.

---

## 1. The D4 deadline correction (the central fix)

**Definitions & equations.** Native CLRT `C = t_R − t_A`. D4 holds *both* deadlines with small
release/measurement errors `ε_A, ε_R`:
- `T_A ≈ t_A + D_A + ε_A`
- `T_RESP ≈ max(t_R, t_A + D_A + D_R) + ε_R`
- **`CLRT_out ≈ max(C − D_A, D_R) + (ε_R − ε_A)`**

**The coverage condition is `C ≤ D_A + D_R = H`** — the correct comparison is native `C` vs the horizon
`H`, NOT native `C` vs `D_R`. A covered transaction (`C ≤ H`) is observed at **≈ `D_R`** (approximately,
not exactly, because of `ε_R − ε_A`); an overtaking one (`C > H`) is released on arrival and observed at
`≈ C − D_A`.

**The tested policy** (`METHODS_RESULTS.md:34`) is `D_A = 4 ms, D_R = 10 ms` → **H = 14 ms**. Campaign A
native OFF is `p99 = 13.67 ms, max = 15.65 ms` (`:75`). So **H = 14 ms is ≈ 0.33 ms above native p99 —
approximate empirical p99 coverage with a measured late tail; NOT universal coverage, NOT exact
normalization, NOT an optimal policy.** The v2 review's "10 ms is below p99, therefore D4 was
misconfigured" is FALSE: it compared p99 to `D_R` (10 ms) instead of to the horizon `H = D_A + D_R`
(14 ms).

**The measured D4 result** (`:80–81`, `:95–97`) is a correct, honestly-reported bounded normalization,
not a misconfiguration:
- 237/240 within ≈10.2 ms; three late-safe-release observations ≈ 12.20, 16.70, 18.77 ms (**≈1.25% tail**).
- p5–p95 spread 5.69 → **0.05 ms** (118×); entropy 3.63 → **1.10 bits** (~12 → ~2 states).
- `METHODS_RESULTS.md` already states this: "a late safe release, not deadline normalization, and we
  never describe the population by its median or as an exact fixed value" (`:90–93`).

**The parameters are COUPLED, not independent: `H = D_A + D_R`.** The principled parameter-selection
contribution (Dr. Lin) is the tradeoff on this constraint surface:
- **`H = D_A + D_R`** sets native-tail **coverage** — covered fraction `P(C ≤ H)`, residual late-tail
  rate `P(C > H)`.
- **`D_R`** sets the **public observed CLRT** (plateau ≈ `D_R`).
- **`D_A = H − D_R`** couples them: *with `D_R` fixed*, raising `D_A` enlarges `H` (more coverage) but
  adds ACK delay + TCP/RTO risk; *with `H` fixed*, raising `D_A` lowers `D_R`, moving the public CLRT
  target. There is no "more coverage without moving `D_A` or `D_R`."

Select `(D_A, D_R)` from the deployment's measured native quantiles on this coverage / visible-target /
latency / TCP-risk surface. **This supersedes v2 §5's "10 ms ≈ p99 + guard on `D_R`."**

**Three distinct outcomes — do NOT conflate them:**
1. **deadline-covered** (`C ≤ H`) — released at the deadline, observed ≈ `D_R`.
2. **late-safe-release** (`C > H`) — RESPONSE unavailable at the deadline, released safely on arrival
   (observed ≈ `C − D_A`). Designed behavior, **not a bypass**.
3. **mechanism fail-open** — an exceptional bypass (timeout, invalid state, missing counterpart,
   resource failure, teardown). The **only** "bypass."

The D4 late tail is outcome 2, not outcome 3. **Case-A (protected-path) zero-unplanned-bypass and the
deliberate Case-C fail-open experiment are SEPARATE campaigns, reported separately** — a deliberate
Case-C fail-open does not invalidate the Case-A result, but the paper must not merge them into an
unqualified "zero bypass."

## 2. Baseline: stratified registry, not one forced distribution

v2 §11 (M2) said "reconcile to one distribution." **Corrected:** the reported 12.9 ms (outline),
13.67 ms (OFF p99) and ~2.92 ms (OFF p50) (`METHODS_RESULTS`), 1.4–1.9 ms steady, and cold ~25 ms
figures are **not one distribution mis-measured** — they come from different capture regimes, workloads,
sessions, and states. Do NOT average them.

**Build a stratified native-CLRT baseline registry**, one entry per dataset, recording the covariates:
dataset & campaign; device & physical unit; firmware/configuration; cold vs steady state; READ vs SBO;
request/object type; capture location; definitions of `t_A`, `t_R`, `C`; timestamp source; topology &
polling conditions; sample size; filtering/exclusions. **Any statistic not traceable to committed raw
evidence is marked `UNPINNED` and is NOT used for policy selection.**

**Cause of the D4 late tail is UNASSIGNED.** v2.1 does **not** claim the old ~166 ms trace produced the
three late D4 observations — that requires transaction-level correspondence (shared transaction IDs,
timestamps, or a shared campaign record). Until the raw records establish that join, the cause of the
measured late tail is **unassigned**.

**Stratification is for analysis, not for per-stratum policy.** The DEPLOYED policy must be **common
across the protection domain being claimed** — a per-device or visibly per-stratum timing target would
itself become a new fingerprint. Any future adaptation is limited to **global / epoch-wide** adaptation;
**no per-packet ML or per-device tuning now.**

## 3. Theorem language corrected (precise bounded results, not universals)

- **Do NOT claim device identity is invariant to every timing-plus-size transformation** — that is not a
  theorem. What the corpus shows is an **empirical residual-channel result**: `(TTL, TCP data_offset)`
  identifies the three **individual devices** in a corpus of **one physical unit per model**. It does
  not support a device-*model* classification claim and it is not an impossibility theorem.
- **The genuine bounded impossibility results** (use exactly these, scoped to their observer):
  1. **Byte-preserving TCP segmentation cannot hide aggregate transaction size from an observer that
     reassembles or aggregates the segments.**
  2. **Publicly-identifiable additive cover frames cannot hide the original size from a parsing observer
     that recognizes and removes the cover frames.**

  Both are bounded to their stated observer; the over-general "size obfuscation is null" language is not
  used. The timing-plus-size system stays the primary goal (§4); these two negatives plus the timing
  mechanism are a **fallback paper only if both positive size candidates fail their gates**.

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

**The length domain is not yet established — the `{37,…,183}→183` claim is PROVISIONAL.**
`L_cover(k) = 10 + k + 2·⌈k/16⌉` is the **serialized DNP3 LINK-layer** byte length for `k` bytes of link
user data. It is **not** directly the TCP-payload length, the IP length, or the Ethernet frame length.
The arithmetic that every size in `{37,54,61,74,122,183}` reaches 183 in 0–1 frame (37→+146, 54→+129,
61→+122, 74→+109, 122→+61, 183→+0) is a **link-layer** result and must **not** be asserted as a
reachability claim until the repository evidence establishes that those observed sizes and the target are
expressed in the **same** length domain. Establishing the applicable domain is a gate, not a done result.

## 7. Status of existing implementations (accurate record)

- **The joint P4 files (`defense4_joint.p4`, `defense4_joint_canon.p4`) are feasibility PROBES, not a
  validated integrated defense.**
- **`defense4_joint_canon.p4` contains INCOMPLETE transport translation and must NOT be loaded as the
  final design.**
- **G30 V1→V3 conversion is REJECTED** — it deletes real DNP3 analog quality flags.
- **The vendored SBO encoding-A test proves bounded OpenDNP3 MASTER ACCEPTANCE, not real relay
  execution** (`92b8d3e` is software evidence only).
- **The handshake normalizer is standalone-built, NOT integrated into the unified Defense 4 program and
  NOT validated as a device-fingerprinting defense** (no measured device-BA drop from ~1.0 to ~1/k on
  ≥2 devices). v2 §3 ("already built") and §11 ("unbuilt") were both imprecise.
- **Cover framing and configured inert decoys remain GATED candidates** (§5).

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

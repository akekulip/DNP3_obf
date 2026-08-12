# Size-candidate decision record (audit-corrected)

Corrected in place per an independent audit of commit `e6e1517`, which overclaimed; then corrected
again after the independent audit of `31b630f` (branch `defense4-size-transport-kernel-repair`,
software/compile-only). Every result below was re-run and verified by the main session. **Evidence is
classified** so no reader mistakes a model or a component test for a demonstrated integrated defense.
The `31b630f` repair (a) rebuilt the transport oracle after a false-green gate was found (audit B1),
(b) corrected the P4 cover bytes and **honestly downgraded** the kernel to one insertion per
connection — a fixed +16 B enlargement, **not** normalization (B2–B5, see `REPAIR_DECISION.md`), and
(c) rewrote the observer scorer to be evidence-driven (M1). No physical action was taken or is
recommended (see the withdrawn-recommendation section below).

## Evidence classes
- **DEMONSTRATED (software):** a real stack/parser run, re-verified, on committed inputs.
- **COMPONENT:** one isolated layer exercised (not a full transaction).
- **PREDICTED (computed):** derived by formula, not captured/measured.
- **SYNTHETIC (model):** a state-machine model, not wire/silicon behaviour.
- **HYPOTHESIS / REQUIREMENT:** assumed, needs future evidence (e.g. endpoint preconfig).
- **PROHIBITED:** claims explicitly NOT made.

## Per-candidate scorecard (corrected)

| Property | **Cover framing** | **Configured decoy — READ** | **Configured decoy — SBO (enc-A)** |
|---|---|---|---|
| Endpoint — link component | individual/reserved/self discarded, broadcast accepted (263 assert) — **COMPONENT** | — | — |
| Endpoint — full transaction | in-memory master↔outstation completes byte-identical to baseline, cover→app=0 (130 assert) — **DEMONSTRATED (software)** | full SBO round-trip: legit actuates once, decoys inert, master completes (323 assert) — **DEMONSTRATED (software)**; callback = **SYNTHETIC** (simulated inert mapping, not a relay) | same round-trip — **DEMONSTRATED (software)** |
| Semantic preservation | real frame byte-identical — **DEMONSTRATED** | real values + quality flags per-object byte-identical as decoys grow (327 assert) — **DEMONSTRATED** | real CROB executes exactly once — **DEMONSTRATED** |
| O_count (packet-length) | 2 native sizes 18/45 B → one 63 B target — **DEMONSTRATED** (DNP3-link=TCP-payload); IP/Eth **PREDICTED** | 2 profiles 29/59 B → one 89 B target — **DEMONSTRATED** | padded to target — DEMONSTRATED |
| O_parse_struct | **STRIPPED → native 18/45 B recovered** (covers removed by link address) — **DEMONSTRATED zero benefit** | **structural ambiguity** — both = G30V1 [0..15] ×16; cannot separate real/decoy by structure — **DEMONSTRATED** | **detectable** vs the tested one-header request baseline (echo has 2 G12V1 headers) — **DEMONSTRATED (bounded)** |
| O_parse_profile | (n/a — already stripped) | constant-valued sentinel decoys are a **temporal residual** — **DEMONSTRATED** (not zero-leak) | — |
| O_config_known | recovers native | removes known decoy indices → recovers real counts 4/10 — **DEMONSTRATED** | — |
| Endpoint cooperation | **none** (individual/reserved) | **REQUIRED** (configured points) — **REQUIREMENT** | **REQUIRED** |
| TCP translation | **yes** — per-flow seq/ack; modeled by `transport_oracle.py` (repaired: **84/84**, gate **PASS**, **12/12 mutants killed**) — **SYNTHETIC**; **P4 kernel compiles** (0 errors, egress 12/12, golden cover bytes, 49-vector conformance) — **DEMONSTRATED (compile)**; kernel is a **one-insertion-per-connection +16 B enlargement**, not normalization | none for the switch (outstation emits natively; switch timing-only) | yes (switch injects) |
| Honest limits | broadcast = hazard; a parsing/aggregating observer strips it; even-length cover required for the deparser checksum | **fail-safe-fragile**: a single non-succeeding decoy drops the real SBO command (READ path unaffected); temporal-residual; requires preconfig | detectable; request direction untouched; fail-safe-fragile |

## Prohibited claims (explicitly NOT made)
Device anonymity / device-model classification (one physical unit per model); cover framing defeating a
parsing observer; "no in-switch insertion can defeat a parsing observer" (only the two bounded results
in `DESIGN_DECISION_v2.1` §3 are claimed); "two G12V1 headers are something no native device emits"
(only detectability *relative to the tested request baseline*); "normalization" of any layer not measured
(IP/Ethernet are PREDICTED); silicon validation (the P4 kernel is a **compile**, not silicon); an
integrated defense (the kernel is a composed compile-probe).

## Decision (from the corrected evidence)
- **Against O_count**, both candidates DEMONSTRATE convergence (cover 63 B; READ decoy 89 B). Cover
  framing is the in-switch mechanism (no endpoint cooperation; the P4 kernel compiles), scoped to a
  counting observer only.
- **Against a parsing observer**, cover framing is STRIPPED (device recovered — demonstrated). The
  **only** candidate not trivially strippable by structure is the **configured READ decoy** (structural
  ambiguity; removable only by an observer that *knows* the decoy indices, with a temporal-profile
  residual), and it preserves real values/flags per-object — at the cost of endpoint preconfiguration.
- **SBO decoys** are detectable and fail-safe-fragile; not selected as a covert mechanism.
- **No in-switch byte-insertion mechanism was shown to defeat a parsing observer** — a valid negative.
- The **timing axis stands alone** (`DESIGN_DECISION_v2.1` §1): the coupled `(D_A,D_R)` policy on the
  `H=D_A+D_R` surface, with `(4,10)` DEMONSTRATED (hardware-measured) and `(2,12)`
  **analysis-selected, hardware-unmeasured**.

## Physical-experiment recommendation — WITHDRAWN (2026-08-12, per `31b630f` audit B6/M4)
The prior edition recommended loading `defense4_cover_kernel.p4` on Tofino-1 against the physical
SEL-751 as "the smallest justified physical experiment." **That recommendation is withdrawn.** The
independent audit of `31b630f` established that the size kernel is a **fixed +16 B first-response
enlargement** (one insertion per connection after the honest downgrade — see `REPAIR_DECISION.md`),
**not** a size-normalization mechanism, and that a parsing observer strips the cover (demonstrated
zero benefit). A physical load would therefore validate the deparser-checksum and endpoint-discard
assumptions of a mechanism that is **not** the selected covert defense. **No physical action is
recommended by this record.** Silicon validation, if ever pursued, is a hardware-gated decision for
a later, separately scoped effort — not a follow-on from this software/compile-only repair. The
configured-READ-decoy path likewise remains a deployment/config question requiring endpoint
preconfiguration, not a switch mechanism, and is not recommended here.

## Corrected evidence index (all re-run + verified; `31b630f` repair state)
- Impl A timing: `defense4/timing/analysis/` — 38/38; `L_master=a+max(C,H)+ε_R` direct from paired timestamps for measured policies (ε_R UNKNOWN for analysis-only); `(2,12)` analysis-selected, no candidate ≥99% at 95%; 2000 ms provenance→UNKNOWN; RTO/fail-open margins UNKNOWN.
- Impl B transport oracle (**repaired**, audit B1): `defense4/size/offline/{transport_oracle,stream_reconstruction}.py` + `test_transport_oracle.py` (46) + `test_transport_repairs.py` (38) + `mutation_harness.py` — **84/84, gate PASS, 12/12 mutants killed** (per-packet epoch discriminator fails closed on tuple reuse, retransmit re-emission, template-id conflict, SYN-learned SACK, wall-clock retirement, TIME_WAIT quarantine). Manifests: `defense4/size/gate_results/`.
- Impl C cover gate: `defense4/size/evidence/cover_frame_gate/` — 263 (component) + 130 (app-context, "by construction not measured") + a real single-process OpenDNP3 TCP loopback (`real_channel/`, READ+SBO, 7-segment transport reassembly). Full-stack cover-injection **PARTIAL** — blocked by a sandbox SIGSTKFLT kill of loopback relays (native stack clean; `real_channel/evidence/sigstkflt_root_cause.txt`).
- Impl D decoy gate: `defense4/size/evidence/decoy_gate/` — SBO round-trip + READ 29/59→89 B convergence with per-object serialized comparison.
- Impl E observer scoring (**rewritten**, audit M1): `defense4/size/evidence/observer_scoring/observer_scoring.py` — evidence-driven (parses committed JSON vectors, real 50000+idx decoys), Gate D 4/4; O_config_known recovers real counts; **O_parse_profile FPR=1.0 on a quiescent plant** (constant legit points misclassified) — a demonstrated limit, not zero-leak.
- P4 kernel (**repaired**, audit B2–B5): `defense4/size/p4/defense4_cover_kernel.p4` (source sha256 `8074374…`) + `evidence/cover_kernel_repair/` + `REPAIR_DECISION.md` — bf-p4c 9.13.1 **0 errors**, egress **12/12** stages, tofino.bin produced; ingress/timing core byte-identical (caseA unchanged); golden cover bytes `05 64 09 44 32 00 01 00 50 C7 C0 C1 02 00 D8 2E` (2 CRC impls); 49-vector reference↔emulator conformance (`offline/{cover_frame_golden,p4_cover_emulator,conformance_corpus,test_cover_conformance}.py`). **Honest downgrade:** one cover insertion per connection = a fixed +16 B enlargement of the first response, **not** normalization; FUNCTIONAL-PASS + COMPILE-PASS, **not silicon-integrated**.

# Size-candidate decision record (audit-corrected)

Corrected in place per `defense4/dir.md` after an independent audit of commit `e6e1517`, which
overclaimed. Every result below was re-run and verified by the main session. **Evidence is classified**
so no reader mistakes a model or a component test for a demonstrated integrated defense.

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
| TCP translation | **yes** — per-flow seq/ack; modeled by `transport_oracle.py` (46/46, gate **PASS**) — **SYNTHETIC**; **P4 kernel compiles** (0 errors, composed) — **DEMONSTRATED (compile)** | none for the switch (outstation emits natively; switch timing-only) | yes (switch injects) |
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

## Smallest justified next PHYSICAL experiment (hardware-gated, NOT authorized here)
- **Cover-framing path:** load `defense4_cover_kernel.p4` on Tofino-1 and capture one covered
  transaction to the physical SEL-751 — to promote the IP/Ethernet convergence numbers from PREDICTED
  to MEASURED, confirm the endpoint discards the individual-addressed cover on silicon, and validate the
  even-cover deparser-checksum assumption on the wire. (The compile is DEMONSTRATED; silicon is not.)
- **Configured-READ-decoy path:** no new switch P4 — it needs a physical outstation preconfigured with a
  common decoy set and a wire capture confirming the two profiles converge and the master decodes the
  real points. This is a deployment/config experiment, not a switch mechanism.

## Corrected evidence index (all re-run + verified)
- Impl A timing: `defense4/timing/analysis/` — 29/29; `L_master=a+max(C,H)+ε_R` (max 19.24 ms, not H-bound); `(2,12)` analysis-selected; RTO/fail-open margins UNKNOWN.
- Impl B transport oracle: `defense4/size/offline/{transport_oracle,stream_reconstruction,test_transport_oracle}.py` — 46/46, gate **PASS** (retransmit re-emission, final-ACK retirement, SACK eligibility, ownership); mutation-checked.
- Impl C cover gate: `defense4/size/evidence/cover_frame_gate/` — 263 (component) + 130 (full transaction) + convergence 18/45→63 B.
- Impl D decoy gate: `defense4/size/evidence/decoy_gate/` — 729 assertions; SBO round-trip + READ 29/59→89 B convergence with per-object serialized comparison.
- Impl E observer scoring: `defense4/size/evidence/observer_scoring/observer_scoring.py` — 9/9 scorer-logic (measured from parsed frames, not asserted).
- P4 kernel: `defense4/size/p4/defense4_cover_kernel.p4` (+ `evidence/cover_kernel_compile/`) — composed probe, bf-p4c 9.13.1 **0 errors**; ingress 12/12 (timing core unchanged), egress 10/12; caseA source byte-identical.

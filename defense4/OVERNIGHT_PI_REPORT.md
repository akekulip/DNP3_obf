# Overnight PI report — `31b630f` audit repair

**Branch:** `defense4-size-transport-kernel-repair` (from `31b630f`, immutable; not merged to `main`).
**Scope:** software / compile-only. No hardware, switch, relay, SEL-751, network-lab, load, deploy, or
live capture. `31b630f` was never amended; no history rewrite, no force-push.
**Author/committer:** `akekulip`. No AI/co-authored attribution.

---

## OVERALL: PARTIAL

Both P0 gates pass for their **bounded** claims, every audit false-green is eliminated, and every
result is re-verified by the main session. The disposition is PARTIAL — not PASS — because the P4 gate
passes only as an honestly **downgraded** mechanism (a fixed +16 B first-response enlargement, not
size-normalization), the full-stack gate is PARTIAL (sandbox-blocked), and **nothing is on silicon**.
No physical action was taken; no physical action is recommended.

| Gate | Disposition | Evidence |
|---|---|---|
| **P0 — Transport oracle** | **PASS** | 84/84 tests + 12/12 mutants killed; `size/offline/`, `size/gate_results/` |
| **P0 — P4 cover-kernel semantics** | **FUNCTIONAL-PASS** (49-vector reference↔emulator agreement, golden cover bytes, fail-closed eligibility) | `size/offline/test_cover_conformance.py`, `size/evidence/cover_kernel_repair/` |
| **P4 compile** | **COMPILE-PASS** — bf-p4c 9.13.1, 0 errors, egress 12/12 stages, `tofino.bin` produced (NOT silicon) | `size/p4/defense4_cover_kernel.p4` (sha256 `8074374…`), `REPAIR_DECISION.md` |
| **OpenDNP3 full-stack** | **PARTIAL** — real single-process TCP loopback (READ+SBO) captured; cover-injection blocked by a sandbox SIGSTKFLT kill of loopback relays (native stack clean) | `size/evidence/cover_frame_gate/real_channel/` |
| **Observer** | **PASS** (evidence-driven; O_config_known recovers counts; O_parse_profile FPR=1.0 on a quiescent plant — a demonstrated limit) | `size/evidence/observer_scoring/` |
| **Timing** | **PASS** — 38/38, byte-identical registry; honest verdicts | `timing/analysis/` |
| **Remote branch / SHA** | see the closing "Remote" line | `git ls-remote` |
| **Physical action taken** | **NONE** | — |

---

## Constraints honored
- Branched from `31b630f`; merge-base equals `31b630f` exactly; `31b630f` unmodified.
- No hardware / switch / relay / capture. bf-p4c is a **compile** (fit-for-source), not silicon behaviour.
- No failing safety test was weakened, skipped, xfailed, or relabeled to get green. Three legacy transport
  tests were **corrected to drive the repaired mechanism** (their safety assertions are unchanged); the
  repair adds 38 new tests + a mutation harness.
- The private directive (`dir.md`) is **not committed**. A sanitized reproducible checklist
  (`AUDIT_REPAIR_CHECKLIST_31b630f.md`) is committed instead. Build trees are gitignored; build logs are
  not staged; no secrets, no absolute `/home` paths in committed deliverables.

## Findings → resolution (audit references)

| Audit | Finding | Resolution |
|---|---|---|
| **B1** | Transport "46/46 gate PASS" was a **false-green**: retransmit set `inserted=0` (never re-emitted the pad); reused 4-tuple translated new-epoch data through the old ledger. | Per-packet epoch discriminator that **fails closed** (new incarnation stays native until the old epoch retires); retransmit re-emits committed pad; **84/84 + 12/12 mutants**. |
| **B2** | P4 cover bytes invalid (placeholder CRCs `0xABCD`/`0xEF01`, byte-reversed addresses). | Golden `05 64 09 44 32 00 01 00 50 C7 C0 C1 02 00 D8 2E`, verified by two independent CRC-16/DNP impls + a parser + a corrupted-frame negative control. |
| **B3** | Ledger cannot implement the offline oracle (claimed "runs the offline oracle"). | **Honest downgrade** to one insertion per connection = depth-1 restriction (`{reg_delta, reg_b0}`); stopped claiming it runs the oracle. |
| **B4** | Eligibility not fail-closed (fragments / IP options / TCP options / SACK / malformed / non-owner / MTU). | All ineligible packets bypass native with **no register access**; destructive ops gated on owner match. |
| **B5** | "+16 B common-target normalization" unsupported. | Relabeled a **fixed +16 B enlargement** of the first response; not normalization. |
| **M1** | Observer scorer never opened the evidence file; invented zero decoys. | Rewritten evidence-driven — parses committed JSON vectors, real 50000+idx decoys; Gate D 4/4. |
| **M2** | `test_full_transaction.cpp` mislabeled "full TCP". | Reclassified as app-context + link ("by construction, not measured"); a real single-process `DNP3Manager` TCP loopback added. |
| **M3** | Differential ε treated as absolute latency. | `L_master` taken directly from paired timestamps for measured policies; ε_R UNKNOWN for analysis-only. |
| **M4** | Band tolerance overstated; physical-load recommended. | Band tolerance labeled conditional; **physical-load recommendation withdrawn** (see below). |
| **M5** | 2000 ms tied to "this campaign" as protocol default. | Provenance → UNKNOWN; 4000 ms recv timeout cited from `campaign_driver.py`. |
| **M6** | "No native device emits two G12V1 headers" — universal overclaim. | Removed; SBO detectability stated **relative to the tested request baseline only**; SBO "retransmission" relabeled an APDU **duplicate** (not TCP retransmission); availability tradeoff noted. |

## Per-workstream detail

**A — Transport (P0, PASS).** `size/offline/{transport_oracle,stream_reconstruction}.py`; tests
`test_transport_oracle.py` (46) + `test_transport_repairs.py` (38); `mutation_harness.py` (12 mutants);
`gate_a.py` orchestrator → `size/gate_results/gate_a_manifest.json{,.sha256}` + `mutation_results.json`.
Run: `python3 size/offline/gate_a.py`. A per-flow seq/ack **SYNTHETIC** model, not wire behaviour.

**B — P4 (P0, FUNCTIONAL-PASS + COMPILE-PASS).** `size/p4/defense4_cover_kernel.p4` (egress-only edits;
ingress/timing core byte-identical, caseA unchanged). Reference + emulator + corpus:
`size/offline/{cover_frame_golden,p4_cover_emulator,conformance_corpus,test_cover_conformance}.py` — 49
vectors agree on seq/ack/bytes/state/outcome/checksum; all IPv4+TCP checksums valid. Compile:
`bf-p4c --target tofino --arch tna --std p4-16 -g` → 0 errors, egress 12/12, `tofino.bin`. `REPAIR_DECISION.md`
records the depth-1 downgrade and the enlargement relabel.

**C — Full-stack (PARTIAL).** `size/evidence/cover_frame_gate/`: `test_full_transaction.cpp` reclassified
(app-context+link, 130 assertions); `real_channel/` builds a real single-process OpenDNP3 `DNP3Manager`
TCP loopback (READ `read_success=1`, SBO `sbo_success=1`, `out_num_select=1`/`out_num_operate=1`), with a
7-segment transport reassembly over real SYN/FIN/RST. Full-stack **cover-injection** is blocked: the
sandbox sends SIGSTKFLT (exit 144) to loopback proxy/relay processes and the pydnp3 binding stack; the
native single-process stack is clean (`real_channel/evidence/sigstkflt_root_cause.txt`). This is an
environment limit, not a DNP3 defect — but the end-to-end covered transaction is **not measured**.

**D — Observer (PASS).** `size/evidence/observer_scoring/observer_scoring.py` rewritten evidence-driven
(parses `vectors/*.json`; real 50000+idx decoys); `test_alter_evidence.py` Gate D 4/4. O_config_known
recovers real point counts; **O_parse_profile FPR=1.0 on a quiescent plant** (constant legit points are
misclassified) — recorded as a limit, not zero-leak.

**E — Timing (PASS).** `timing/analysis/` — `tpa/{policy,registry,stats}.py`, `timing_policy_analysis.py`,
`make_registry.py`, `tests/test_timing_policy.py` (38/38); regenerated `registry.yaml`/`results.json`
byte-identical. `L_master` direct from `read_to_resp_ms` for measured policies (ε_R UNKNOWN for
analysis-only); band tolerance conditional; selector reports "no candidate ≥99% at 95%"; 2000 ms → UNKNOWN.

**F — Decoy docs.** `size/evidence/decoy_gate/README.md` — both universal "no native device" claims removed
(→ "detectable relative to the tested one-header request baseline, NOT a universal claim"); SBO "exact
retransmission" → "duplicate (APDU replay — NOT TCP retransmission)"; availability tradeoff noted.

**G — Reproducibility.** `size/offline/DEPRECATED_v1.md` deprecates 5 v1 scripts (+ stale `p4/baseline.err`)
that hard-code absolute sibling-repo paths; the reproducible workflow is the current gate set only.

## Integration gates
- **Reference correctness + mutation kills:** 12/12 mutants killed (transport). ✓
- **Packet-vector conformance (ref vs P4 emulator):** 49 vectors, exact agreement, checksums valid. ✓
- **Serialization/checksum (2 independent impls):** golden cover bytes match across two CRC-16/DNP impls;
  IPv4+TCP checksums independently validated. ✓
- **Endpoint bounded pass + full-stack class recorded:** app-context bounded PASS; full-stack PARTIAL. ✓
- **Compile:** bf-p4c 0 errors (COMPILE-PASS, not silicon). ✓
- **Doc claim-scan:** no prohibited/universal overclaim survives; all "silicon" references attach to the
  copied timing core only. ✓
- **Reproducibility:** gate manifests bind SHAs + commands; build trees ignored; no abs paths in
  deliverables. ✓

## Claims — supported / withdrawn / prohibited
- **Supported:** transport oracle correctly re-emits pad and fails closed on tuple reuse (84/84 + mutants);
  the repaired kernel compiles and its modeled semantics match an independent reference on 49 vectors; the
  kernel enlarges the first response by a fixed +16 B; a parsing observer strips the cover; configured READ
  decoys are structurally ambiguous with a temporal residual; O_config_known recovers counts.
- **Withdrawn:** the recommendation that loading `defense4_cover_kernel.p4` on Tofino-1 is "the smallest
  justified physical experiment" (audit B6/M4) — see `SIZE_CANDIDATE_DECISION.md` and
  `DESIGN_DECISION_v2.1.md` §9.1. **No physical action is recommended.**
- **Prohibited (not claimed):** size normalization; that the kernel runs the offline oracle; silicon
  validation of the size path; an integrated size defense; any universal "no native device" statement; a
  measured full-stack covered transaction.

## Resource deltas (P4)
Egress recompiles at **12/12** stages (was reported 10/12 pre-repair); ingress/timing core unchanged and
byte-identical (caseA source untouched). One inert `tbl_predecessor` re-placement; SACK folded into the
`reg_delta` poison path; flow-index hash inlined.

## Physical action: NONE.

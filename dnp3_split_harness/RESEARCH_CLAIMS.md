# RESEARCH_CLAIMS.md

The claim ledger for the DNP3 traffic-obfuscation research line. Every non-trivial
result claim is recorded here with its evidence class, evidence file, scope caveats,
and a verdict. Established in Phase 00 by an independent claims review (worklog:
`worklogs/agents/phase_00/research_reviewer.md`) and cross-checked by the lead.

**Evidence classes** (never blur): `measured` (real device wire capture) · `replayed`
(replay server on the wire) · `simulated` (feature-space model, no live wire) ·
`inferred` · `projected` (computed from a scheduler plan, not observed on the wire).

**Verdicts:** `SUPPORTED` (evidence backs it, with caveats) · `PARTIALLY SUPPORTED`
(backed only in a narrower sense than stated) · `UNSUPPORTED-BY-EVIDENCE` (claim
exceeds what any committed artifact shows — must be reproduced or relabeled).

> No number below was copied from a markdown report into a "verified" column. Where a
> report's prose lacks a machine-readable backing file, the claim is flagged, not
> promoted. Numbers here are transcribed from raw csv/json or from a live check this
> session; they are re-derived in Phase 01+, not trusted from prior reports.

---

## Claim ledger

| # | Claim | Class | Evidence file(s) | Verdict | Scope caveats |
|---|---|---|---|---|---|
| C1 | ~22,988 reconstructed request→response transactions from the six device PCAPs | measured | `reports/ack_trace_characterization.{csv,json}` (raw, 22,988 rows), `ack_trace_summary.md` | SUPPORTED | The **device-specific** working set is **11,494** (excludes the shared reference outstation `10.0.0.2`); 22,988 counts all reconstructed transactions incl. the reference. Regenerable: `python3 characterize_ack_traces.py`. |
| C2 | SEL-751 emits a **separate** pure TCP ACK before the DNP3 response; AB1400 & ION7550 **piggyback** the ACK on the payload-bearing DNP3 RESPONSE | measured | `reports/ack_trace_summary.md` + `ack_trace_characterization.{csv,json}` | SUPPORTED for the **captured devices only** | One capture per model ≠ product family. Terminology: "the TCP ACK is piggybacked on the payload-bearing DNP3 RESPONSE" (not "combined ACK"). |
| C3 | A Linux ACK-separation transition occurs around **~40 ms** | measured (rig, raw pcap) | `reports/ack_separation_rig_results.md` + raw `reports/ack_separation_rig/acksep_refine.pcap` | SUPPORTED, **explicitly non-universal** | Holds only for the tested host/kernel/socket-config/traffic pattern. The committed client-matrix CSV records `pure_ack_emitted=undetermined`, so the threshold rests on manual tshark reading — Phase 03 must reproduce it from fresh captures with packet-field ACK detection. |
| C4 | RTO floor **~211 ms** | measured, **loopback-only** | `reports/rto_probe_notes.md` + `rto_probe_results.{csv,json}` | PARTIALLY SUPPORTED | This is a loopback Linux `RTO_MIN` observation, **not** a wire RTO. Must be reproduced on the rig before any RTO-safe bound is asserted for the real path. |
| C5 | Fixed & bounded timing normalization run successfully and are **byte-preserving** | replayed (rig) | `reports/rig_timing_matrix_results.md` + raw `reports/rig_timing/*.jsonl,*.pcap`; loopback byte-identity in `reports/timing_experiment_results.csv` | SUPPORTED **for mechanism / safety / byte-preservation only** | Replay server ≠ real device. This supports "the timing mechanism works and preserves bytes", NOT "the defended real device looks like X on the wire". Does **not** claim size is hidden. |
| C6 | 22 timing-policy unit tests pass | verified this session | `tests/test_timing_policy.py`; live run 2026-07-16 → **22 passed** on Python 3.8.10 | SUPPORTED | Pure-function timing tests only; not a rig/integration pass. |
| C7 | Attacker device-classification results | simulated (trace feature space) | `reports/attacker_eval.md` + `attacker_eval_results.json` (raw) | SUPPORTED | **Capture-level split** (not random-row): native accuracy ≈ **0.897**, leave-one-PCAP-out ≈ **0.722**; device-ID residual stays ≈ **0.90** after the timing defense (size/ACK-mode channels remain). This is feature-space simulation, not a live defended capture. |
| C8 | `plan_ack_response_release()` performs ACK/response timing manipulation | **projected** (pure planner) | `timing_policy.py:331-387`; usage grep; `RESUME_STATE.md:128-129` | **UNSUPPORTED-BY-EVIDENCE** | The function is a pure scheduler with **no packet-control enforcement** and **no PCAP** proving any packet moved. It is NOT wired into `split_server.py` or any probe — only unit tests and a `trace_before_after.py` projection call it. For its ACK-**advancing** modes it is not even user-space-realizable (the kernel owns the already-emitted pure ACK). |

---

## Overclaiming flags (must relabel before reuse)

1. **Top priority — the Phase-2 ACK-delay "before/after" is projected, not achieved.**
   `reports/trace_before_after.md` (≈L33) describes "the literal ACK-delay manipulation
   applied to the real trace", and the tutorial/briefing render a 40 ms slider with
   gap numbers. These are **projected** outputs of the unwired `plan_ack_response_release`
   (C8), not a wire-validated manipulation. Relabel as **PROJECTED / not wire-validated**
   and drop "literal manipulation applied". A user-space app cannot advance/hold a
   kernel-owned pure ACK; only a real packet-control mechanism (Phase 03/04 feasibility
   table) could enforce it.
2. **`pad_rig_results.md` device-ID drop 0.90→0.797** is an explicit projection with no
   raw backing file — keep labeled projected.
3. Do not state (per §H): that timing normalization hides response **size**; that
   splitting hides **total bytes**; that the ~40 ms threshold is universal; that
   host-side capture equals exact wire timing; or any P4 resource figure without
   compiler/hardware evidence.

## Carry-forward status

- **Safe to carry as SUPPORTED (with caveats):** C1, C2, C5 (mechanism/bytes), C6, C7.
- **Reproduce before relying on:** C3 (rig, packet-field ACK detection), C4 (rig RTO).
- **Do not reuse until a real enforcement mechanism + PCAP exist:** C8 and the Phase-2
  before/after narrative.

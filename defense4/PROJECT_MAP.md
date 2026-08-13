# Defense 4 — project map (authoritative index)

The single index for the Defense 4 unified **BOR + RRC** timing/size obfuscation primitive on one
Tofino-1. Prefer this map over guessing paths. Provenance labels are load-bearing: **[silicon]**
physical relay/switch, **[compile]** bf-p4c only, **[offline]** emulator/model, **[synthetic]**
bootstrapped. *A compile is not silicon; two physical pipes are not one pipe; software-endpoint traffic
is not a physical relay operation.*

## The result, in one paragraph

RRC (Release–Replicate–Carve) normalizes the **response** of a DNP3 outstation — it holds the response
to a timing deadline (collapsing the Formby **CLRT** fingerprint) and, via the Tofino Packet Replication
Engine, carves a native 49-byte READ/SELECT response into two byte-preserving TCP segments `[28,21]`
(equalizing size/segmentation) — **proven on the physical SEL-751 [silicon]**. BOR (Bounded OPERATE
Release) additionally holds the master's **OPERATE request** for a bounded, per-transaction *random*
delay `J` so the observed physical-operation time becomes `J + T_physical`, *convolving* the Formby
**physical-operation-time** fingerprint. The faithful unified BOR+RRC does not fit one 12-stage pipe (the
hold core is an irreducible +1), so it is realized across the **two on-chip pipes** of the BFN-T10-032D
(`num_pipes = 2`): pipe 0 = 12 stages (RRC + T0-admission + cross-pipe route + SELECT-prepare), pipe 1 =
10 stages (faithful SELECT-prepares-epoch hold) — **compile-proven on bf-p4c 9.13.1 and the switch's
9.13.2 [compile]**, offline-acceptance-proven (24/24 gates [offline]). The two-program hardware **load
is prepared but gated** on a watched deployment window; physical OPERATE is **BLOCKED** (no odd-point
electrical-isolation proof).

## Current authoritative artifacts

| what | path | provenance |
|---|---|---|
| **Frozen proven RRC kernel** (the restore baseline; never edit) | `size/native_parity/p4/defense4_rrc_kernel.p4` | silicon |
| **Pipe 0 program** (RRC + T0-admission + cross-pipe route + SELECT-prepare) | `size/native_parity/p4/defense4_twopipe_pipe0_probe.p4` | compile |
| **Pipe 1 program** (faithful BOR: epoch readiness + Random J + hold/release) | `size/native_parity/p4/defense4_twopipe_pipe1_faithful_probe.p4` | compile |
| **Two-program control plane** (pipe_scope, ms-deadline validation, rollback) | `size/native_parity/p4/defense4_bor_twopipe_setup.py` | offline-validated |
| **RRC control plane** (proven; reused by the above) | `size/native_parity/p4/defense4_rrc_setup.py` | silicon |
| Design (mechanism, invariants, faithful readiness, anti-subtraction) | `size/native_parity/BOR_RRC_DESIGN.md` | — |
| Two-pipe feasibility + faithful result | `size/native_parity/BOR_TWO_PIPE_PROPOSAL.md`, `BOR_TWO_PIPE_FAITHFUL_RESULT.md` | compile |
| Control-plane doc (ops, port/pipe map, bring-up sequence) | `size/native_parity/BOR_CONTROL_PLANE.md` | — |
| Run state / resume anchor | `OVERNIGHT_STATE.md` | — |

## Offline emulators + acceptance (all [offline])

| what | path |
|---|---|
| Faithful BOR-in-RRC lifecycle + 17 mutants | `size/native_parity/offline/bor_rrc_emulator.py` |
| Two-pipe faithful cross-pipe lifecycle | `size/native_parity/offline/bor_twopipe_faithful_emulator.py` |
| Consolidated Phase-6 acceptance (24 gates) | `size/native_parity/offline/test_bor_acceptance_gate.py` |
| RRC response emulator (CRC-split/carve) | `size/native_parity/offline/rrc_emulator.py`, `crc_split_emulator.py` |
| Verified pcap analyzer (TCP-ACK pairing) | `size/native_parity/analyze_rrc_pcaps.py` |

## Compile probes + resource evidence (all [compile]; bulky `out/` trees gitignored)

| what | path |
|---|---|
| Additive one-pipe probe (14 stages) + stage-recovery matrix (SR1–SR4, 13) | `size/native_parity/p4/defense4_rrc_bor_compile_probe.p4`, `defense4_rrc_bor_sr_probe.p4`; `size/native_parity/evidence/bor_stage_recovery/` |
| Two-pipe compile matrices + logs | `size/native_parity/evidence/bor_two_pipe/`, `evidence/bor_two_pipe_faithful/` |
| Reports | `size/native_parity/BOR_COMPILE_PROBE_RESULT.md`, `BOR_STAGE_RECOVERY_RESULT.md` |

## Hardware evidence [silicon] (RRC — the proven half)

| what | path |
|---|---|
| Joint RRC READ vs SELECT pcaps (`[28,21]` + ~22 ms D4 hold) | `size/native_parity/evidence/hw_rrc_joint_20260812T223342Z/` |
| Size-only (native-timing) pcaps | `size/native_parity/evidence/hw_rrc_readsbo_20260812T212234Z/` |
| RRC hardware result + gate history | `size/native_parity/RRC_HW_RESULTS.md`, `READSBO_NORMALIZATION_RESULT.md` |
| Existing silicon figures (size/timing/CLRT) | `size/native_parity/figures/fig_{size,timing,clrt}.pdf` |

## Evidence / figures / explainer (Phase 10–13)
- Analysis + figures: `defense4/figures/`, `defense4/evidence/analysis/`, `defense4/PHASE10_RESULTS.md` *(finalized as Phase 10/11 lands)*.
- Beginner explainer (final deliverable): `defense4/EXPLAINER.md` *(written last)*.

## Archived / superseded (labeled history, not the current result)
- `defense4_twopipe_pipe1_probe.p4` — the **fail-open-first** pipe-1 (6 stages) = a *resource probe*,
  NOT faithful BOR (it never holds the first OPERATE). Kept as the control.
- SR4 "faithful 13-stage" one-pipe claim — **relabelled a resource probe** (fail-open bypass).
- Size-insertion / multi-boundary-ledger negative results — see project memory + `RRC_DESIGN.md` §0.

## Honest claim boundary
Proven [silicon]: RRC CLRT normalization + `[28,21]` size/segmentation parity on the SEL-751, for
READ vs SELECT-echo. Proven [compile]: faithful two-pipe BOR+RRC fits both pipes on both toolchains.
Proven [offline]: exactly-once, T0-anchoring, first-OPERATE-held, all mutants. **Not** proven: the
two-program silicon load; physical OPERATE (BLOCKED); multi-device fingerprint defeat; anything about
request-size or DPI. Physical-fingerprint mitigation is demonstrated only as an **[offline/synthetic]
convolution model** until real operation-time data exists.

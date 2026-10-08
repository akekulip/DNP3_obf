# Case 4 timing+size integration contract

One decision record for the combined timing-and-size obfuscation work requested in
`DNP3_Timing_Size_Integration_Prompt.md` (2026-10-08, audited HEAD `85c9f8cbfdd047c511997a988c5209df65eb3684`).
Every later phase and every agent dispatched into this work reads this file first instead of re-deriving the
source map or re-litigating a decision already made here. Nothing in this file authorizes hardware action;
see "Authorization boundary" at the end.

## 1. Protected direction, observer vantage, supported profile set

- **Protected direction:** master-to-outstation request traffic and the matching outstation-to-master
  response, for the three DNP3 roles this effort supports: READ, SELECT, OPERATE (as the SBO pair). Pure TCP
  ACKs are covered where they interact with the timing queues. DIRECT_OPERATE is explicitly a different,
  unsupported role (see §5) and must never be relabeled as SELECT/OPERATE in any corpus or test.
- **Observer vantage:** a passive network observer positioned to see frame sizes, segment counts, TCP
  sequence/ack numbers, and plaintext DNP3 content (no claim of confidentiality against a parser is made or
  needed — the goal is operation/transaction-class indistinguishability through size and timing, not
  encryption).
- **Supported profile set:** one shared public size pattern (vector of states, in TCP-payload bytes) that
  READ and control (SELECT/OPERATE) traffic both reach through a legal transformation (padding and/or
  byte-preserving splitting), combined with the existing blocker/hold-queue release schedule. The pattern
  itself is Phase B's output, not fixed by this document.
- **Concurrency bound:** one session at a time has been demonstrated (RRC hardware evidence, Case 4 model
  evidence). General multi-flow independence from a shared blocker ladder is unverified and must not be
  claimed until measured.

## 2. Byte convention — do not cross this line

Two different units appear throughout this repository's history and must never be compared directly:

| Value | Unit | Source |
|---|---|---|
| `128`, `256` (old size-pattern-builder candidates) | **Ethernet-frame bytes, no FCS, 60-byte minimum applied** | `2ce9910a`, `SIZE_PATTERN_BUILDER_REPORT.md` |
| `49`, `28`, `21` (historical RRC carve) | **TCP-payload bytes** (includes DNP3 framing + CRC) | `9ffa9102`, `RRC_HW_RESULTS.md` |
| `35`, `55`, `57`, `29` (current Case 4 software profile) | **TCP-payload bytes** | `framework/size/case4_padding.py`, `CASE4_SOFTWARE_EVIDENCE.md` |

Any pattern selected in Phase B states its unit explicitly and does not get compared against the old
128-byte Ethernet target without an explicit, shown conversion (Ethernet frame = TCP payload + 14 (Eth) +
20 (IPv4, no options) + 20–32 (TCP, options-dependent), no FCS).

## 3. Source/commit map per capability

| Capability | Status | Evidence identity |
|---|---|---|
| Blocker/hold queue timing (ACK + response) | **implemented, hardware-measured** (historical build) | `defense4/timing/implementation/exact_experiment_source/defense4_rrc_bor_unified12.p4` lines 372–385 (qid7/6/5/4 ladder); corrected request-anchor variant at `defense4/timing/anchor_fix/src/defense4_rrc_bor_unified12.p4` |
| Response-aware release (ACK waits for an admitted response) | **implemented, source-tested**, not yet re-verified against the current queue source | `defense4/timing/response_ready/` (`analyze.py`, `verify_build.py`, `HARDWARE_TEST.md`) |
| Smaller/alternate timing candidate (stage-reduced) | **compiled, not adopted as base** | `defense4/timing/stage_reduction/` |
| Full-packet heartbeat/recirculation timing (reference only, NOT the base architecture) | **compiled, 12/12 stages, model-tested** | `case4_architecture/integration/read/read_timing.p4` (818 lines) — see §6 conflict 1 |
| Native connection role (N) | **compiled 12/0 stages, differential-tested** (590,976 cases) | `integration/connection/binding/generate.py`, `native_binding.p4`, current source `native_19` |
| READ timing role (T) | **compiled 12/0 stages, model-tested** (40–50 cases), built on the heartbeat design — a correctness reference, not the adopted queue base | `integration/read/read_timing.p4`, `read_timing_05` |
| First-SELECT (padding only, no ACK/window mapper) end-to-end | **compiled + local-model-tested**, both local SDK 9.13.1 and compile-only on switch host SDK 9.13.2 | `HANDOVER.md`, pipes N(0)+M(1, baseline)+E(3), pipe2 reserved for T |
| M's extended ACK/window mapper | **refuted for the tested two-trip recirculation design only** (narrow — see §6 conflict 2) | `integration/core/M_RECIRCULATION_VERDICT.md` (corrected 2026-10-08), `integration/core/ordinary/evidence/stage_fit_m{13,16-23}*` |
| Historical size-pattern candidates (`single128`, `cover_larger_corpus`, `two_state_round8`, `ack_data_split`) | **offline-evaluated only** (MI/bootstrap/grouped-CV), not hardware-realized as a deployed pattern | `2ce9910a:research/tofino_dcrn_feasibility/p4/queue_microbench/size_pattern_builder/` |
| RRC (Release-Replicate-Carve) split mechanism | **hardware-proven on real Tofino-1 silicon** (R1–R6 pass; physical OPERATE not run) | `9ffa9102:defense4/size/native_parity/{RRC_DESIGN,RRC_HW_RESULTS,READSBO_NORMALIZATION_RESULT}.md`, 4 verified PCAPs |
| Current Case 4 control padding (in-stream insertion, 35→55 request, 57→[28,29] response) | **software-tested**, bounded helpers only, not hardware-realized | `framework/size/{case4_padding,case4_transport,case4_preprocess}.py`, 37/37 tests passing (confirmed this turn) |
| DNP3/transport correctness codec and oracle | **source-tested, 37/37 passing** (re-run this turn) | `framework/tests/{test_rrc_split,test_case4_padding,test_case4_transport}.py` |
| Production-software endpoint gate | **component-tested**, decoy-SELECT-failure → later NO_SELECT finding stands | `framework/size/endpoint_gate/` |
| Security scorecard (cover framing / configured decoys) | **evaluated against the specific candidates tested**, not a general prohibition (see §6 conflict 3) | `ed4ee3b8e:defense4/size/{DESIGN_DECISION_v2.1.md,SIZE_CANDIDATE_DECISION.md}` (recoverable; removed from working tree by the later allowlist reduction) |
| 2026-10-06 hardware bring-up/smoke (OFF only) | **physically measured**, no holding/size proof | `audit_current/framework_20261005/HARDWARE_SMOKE_20261006.md` |

## 4. Timing anchor and convention

- The current shipped build is **request-anchored** (both read-lane deadlines anchor at the request's arrival
  `t_0`, not the acknowledgment `t_A`) — `campaign_v1` was acknowledgment-anchored; `campaign_v2` and all
  current Case 4 work is request-anchored. Source: `defense4/timing/NOTATION_MAPPING.md`.
- The code field `D_R_ms` means the paper's **configured `CLRT_new`** (the release-gap parameter), not the
  paper's `D_R` (unmeasured full outstation-to-master response latency). Do not reuse the old `D_R_ms` field
  name to mean anything else.
- `response_eligibility = a_commit + configured_CLRT_new`; `measured_CLRT_new = master_first_response_arrival
  - master_ACK_arrival` is a different, derived quantity that includes release/serialization/path/capture
  effects — never substitute one for the other in a report.
- The measured "epsilon candidate" interval (≈1,705–1,706 ns) is **not** a bound on epsilon in either
  direction — an earlier claim to that effect was withdrawn; treat epsilon as unmeasured for this effort
  until a new instrumented run says otherwise.

## 5. Accept / supersede / unresolved — every named conflict in the prompt

| Conflict | Resolution |
|---|---|
| `REPOSITORY_MAP.md` location | **Corrected**: it lives at the repo root (`/home/philip/Projects/DNP3/REPOSITORY_MAP.md`), not under `defense4/timing/`. |
| m16/m17 table mislabeled "fits" | **Corrected in `M_RECIRCULATION_VERDICT.md`** (2026-10-08): both were `compile_failed`; the 9/8 numbers are dependency-graph critical-path lengths, not stage counts. Scope of the correction: narrow (see next row), no new compiler runs performed. |
| "Recirculation is refuted" — how far does that go | **Narrowed, not reopened.** The evidence proves the *tested* m13–m23 two-trip implementations failed. It does not prove every recirculation arrangement, every shared-register table arrangement, or the original queue-plus-carve timing mechanism is infeasible. Do not re-run m16–m23 unchanged; a genuinely different structural approach is not precluded. |
| "No in-switch byte insertion defeats a parsing observer" (`DESIGN_DECISION_v2.1.md`) | **Scoped, not a prohibition.** This describes the specific candidates evaluated there (cover framing, configured decoys, encoding A/B). It is evidence to weigh when choosing Phase B's pattern and Phase D's mechanism, not a reason to avoid building the padding mechanism this effort requires if the selected pattern needs it. |
| `[28,21]` (READ, historical RRC) vs `[28,29]` (current control profile) | **Unresolved — this is Phase B's job.** As long as these differ, operation is visible through size under the stated common-pattern objective. No default resolution is assumed here; Phase B picks one pattern both roles reach, or documents why a role split is unavoidable. |
| CRC/padding wording ("not splitting at the CRC boundary" vs "splitting along existing CRC boundaries") | **Preserve the latest wording**: no mandatory CRC-aligned cut. The surviving technical requirement: preserve the existing DNP3 byte stream and its CRC bytes exactly; do not reconstruct DNP3 frames merely to change TCP segmentation. A cut through a DNP3 block or its CRC bytes is still legal as a TCP-level split as long as `prefix || suffix == B` exactly. |
| `M_STRUCTURAL_OPTIONS.md`'s recommendation of recirculation (option a) | **Superseded** by the m23 result for the tested design; options B (egress-resident registers) and C (ground-up redesign) remain open per the verdict document, and are out of scope unless the Phase B/D work independently needs them. |
| Heartbeat/full-packet-circulation design in `read_timing.p4` vs the queue-resident mechanism | **Not interchangeable, and not a default to reconsider.** `defense4_rrc_bor_unified12.p4`'s queue ladder (qid7/6/5/4, qid3/2) is the base for all further timing work. `read_timing.p4` is a source of correctness fixes to port over (response-readiness, lifecycle handling), never the base architecture. |

## 6. Authorization boundary (unchanged, restated here for every dispatched agent)

Offline code, local-model work, and compile-only remote use of the switch host's installed SDK 9.13.2 are
authorized under the existing CLAUDE.md Case 4 scope. No SDK update, no chip activation, no port/TM/PRE/
pktgen/mirror configuration change, no traffic generation, no physical OPERATE — any of those need Philip's
own separate, recorded authorization. Never edit frozen sources
(`defense4/timing/implementation/`, the three named `raw_pcaps/` trees, `paper/rewrite/`), Case 1–3 history,
or Philip's own uncommitted `CLAUDE.md` edit. Work on `main`, no new branch, no push, lead-only commits
(`akekulip <akekulip@gmail.com>`, author and committer, zero trailers).

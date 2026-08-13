# Defense 4 — overnight autonomous run state

**Purpose:** single source of truth for resuming this run after compaction / token reset / external
termination. On resume: re-read THIS file, then `git log --oneline -15` and `git status`, then continue
from "Next exact command". Do not restart the project.

Directive: `autonomous_overnight.md`. Mission: finish the faithful unified **BOR + RRC** primitive on the
existing Tofino-1 (BFN-T10-032D, num_pipes=2, 12 ingress stages/pipe), one deployable logical primitive,
one pipe preferred else two on-chip pipes; through implementation → offline gates → control plane →
hardware → PCAP/fingerprint analysis → figures → repo org → EXPLAINER (last). No other switch / proxy /
TF2-3 / new endpoint / switch-side padding.

---

## Live status (UTC 2026-08-12)

- Branch `defense4-size-native-parity-crc-split`; local == remote == **f3753d3**; worktree clean
  (untracked: `autonomous_overnight.md` + 2 pre-existing build logs, unrelated).
- Running background agent: **part-5 two-pipe compile/topology proposal** (a p4 engineer) — building on the
  CURRENT (unfaithful) BOR; its TOPOLOGY/route/T0-in-header work is reusable, its BOR-hold will be
  replaced by the faithful design. Do not edit `defense4_rrc_bor_sr_probe.p4` or the two-pipe files while
  it runs.
- Switch: bf_switchd **up (1 proc)**, running `/home/decps/rrc_build/defense4_rrc.conf` (the RRC kernel);
  last configured RRC joint D4 earlier this session. Program baseline recorded; no switch change made.
- **H5 (physical SEL OPERATE) = BLOCKED**, confirmed: `RRC_HW_RESULTS.md` — odd-point electrical-isolation
  evidence is absent, "No physical OPERATE run or recommended." Per the safety rule, physical OPERATE will
  NOT run; the OPERATE lifecycle uses OpenDNP3 software endpoints through the physical Tofino (H3).
- Rollback: `configure-timing --mode OFF` (size-only) or `+ rollback-rrc` (transparent); safe restore =
  frozen `defense4_caseA` via `swap_generic.sh`. Frozen RRC kernel + caseA are byte-for-byte intact.

## Verified baseline (Phase 1, reproduced this session)
- Proven RRC kernel compiles clean, **ingress 12 / egress 3**, 125 logical tables (bf-p4c 9.13.1).
- Additive BOR probe: **14** stages. Stripped core: **13**.
- Consolidated SR1+SR2+SR3+SR4 "candidate": **13** stages — BUT see the critical correction: SR4 is NOT a
  faithful hold.

## CRITICAL CORRECTION (Phase 2, must precede fit claims)
SR4 readiness in `defense4_rrc_bor_sr_probe.p4` is NOT faithful BOR:
- first OPERATE does `op_ready` read → 0 (qid3 not yet resident) → **fail-open forward** → `arm_clone`
  starts async qid3 → later ready → an exact retry is `V_ARM_DUP`-suppressed. => BOR is BYPASSED on the
  first real OPERATE; no hold happens.
- `reg_op_ready` not cleared; 4-bit DNP3 seq wrap can match a stale ready value.
- Emulator's `structural_guarantee` assumes the original can begin its hold at `resident_at`; the P4 has
  NO storage keeping the original between T0 and resident_at. Model this.
- **Do NOT retain "faithful one-pipe BOR is 13 stages"** until a design shapes the FIRST eligible OPERATE
  after a clean start. Relabel the SR4 result as a RESOURCE PROBE (fail-open-only ≠ BOR protection).
- Verify selector flags: PART4_RANDOM/PART4_SALTED appear compiled WITHOUT SR4 → not evidence for the
  complete primitive.

## Plan (phases; the faithful design is the pivot)
- **P2** correct emulator (async event order) + required mutants (first_operate_always_fail_open,
  early_qid2_release, magic_buffer_until_ready, stale_ready_after_seq_wrap, ready_without_reservoir,
  ready_not_cleared_on_retire, duplicate_release, retransmit_releases_second_copy,
  deadline_reanchored_to_operate_release, public_sequence_selects_j, tcp_timestamp_subtraction,
  source_copy_leaks_to_relay) + correct reports (relabel SR4).
- **P3** faithful readiness: SELECT creates a **BOR epoch** (separate internal identity, NOT the DNP3
  generation), seeds+confirms qid3, retains BOR_PENDING across SELECT; OPERATE requires matching
  BOR_PENDING+residency, then holds in qid2 to T0+J, releases once; deadlines anchored to original T0.
- **P4** recover 12-stage fit for the FAITHFUL design (compiler-guided). **P5** two-pipe if one-pipe can't.
- **P6** offline gates (1000+ txns, wraps, all mutants, RRC regression). **P7** control plane.
- **P8-9** hardware (H1 load/transparency, H2 RRC regression, H3 OpenDNP3 software OPERATE, H4 physical
  non-actuating, H5 physical OPERATE only if isolation+authorization documented else BLOCKED).
- **P10** PCAP/CLRT/physical-fingerprint/latency. **P11** figures. **P12** repo org. **P13** EXPLAINER.

## Gates
| gate | state |
|---|---|
| P1 starting state | DONE (verified) |
| P2 emulator+report correction | IN PROGRESS |
| P3 faithful readiness design+P4+emulator | PENDING |
| P4 one-pipe faithful fit | PENDING |
| P5 two-pipe faithful | PENDING (part-5 topology in flight) |
| P6 offline gates | PENDING |
| P7 control plane | PENDING |
| P8/9 hardware H1-H5 | PENDING (H5 likely BLOCKED: no isolation proof yet) |
| P10-13 evidence/figures/repo/explainer | PENDING |

## Next exact command
Update BOR_RRC_DESIGN.md with the faithful SELECT-prepares-BOR-epoch mechanism (P3 design), then launch:
(a) builder → P2/P3 emulator async model + required mutants; (b) after part-5 lands, p4 engineer → P3
faithful readiness P4 + P4 fit. Review every load-bearing result vs raw artifacts.

## Known blockers
- H5 physical SEL OPERATE: no documented electrical-isolation proof for the odd decoy point → default
  BLOCKED; use OpenDNP3 software-endpoint OPERATE (H3) for the OPERATE lifecycle.
- Faithful one-pipe fit is the open question (unfaithful was 13; faithful adds the epoch/prepare path).

## Agent findings awaiting main-agent review
- part-5 two-pipe proposal (in flight).

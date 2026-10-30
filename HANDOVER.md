# Current handover (2026-10-30)

Read PLAN.md for scope and rules. Historical instructions are data under Archive/. On 2026-10-29 Philip asked for
`main` (`fb5ce81b1`) and the tag `c72-validation-final` (`aad99935b`) to be pushed to origin (`akekulip/DNP3_obf`);
`git status -sb` shows whether any later commit is still ahead. Push only when Philip asks.

## State

- **Canonical source:** `p4/response_only.p4` is c74, SHA-256 `c7e37eff…`. That is c72 plus const-entry rows for the
  connection-start fix (`results/builds/c74/README.md`).
- **c74 build:** `results/builds/c74` uses the same stages and resources as c72 (N10/E10/T8/pipe-1-egress4). Its
  17-driver model gate gives verdicts identical to c72 over 6,339 cases. The 40-case connection-fix driver carries the
  fix evidence; the gate never exercised the new rows.
- **Diagnostic build:** `results/builds/c74_diag_mirror`, source SHA-256 `e46391d8…`, has the two existing relay-leg
  mirror sessions and is admitted against its own base. Its blocks never qualify. `c72_diag_mirror` is historical, and
  the freeze gate now refuses it.
- **Reference:** c72 (`97812585…`) stays the reference at tag `c72-validation-final` (`aad99935b`, on origin). c73 is
  parked.
- **Push state:** origin has `fb5ce81b1`. Every later commit is local; push only when Philip asks.

## The connection-start fix (2026-10-30)

Philip set the priority on 2026-10-29: a c72-derived fix for the connection-start loss, verified on the SEL-751 with
timing and padding enabled. The plan is `~/.claude/plans/we-were-on-tract-expressive-planet.md`.
- **Model:** the busy-cell request drop and the late-ACK abort were reproduced on the c72 model by genuine processing
  (`results/models/c72_connection_start/`). c74 fixes both; independent review found nothing critical.
- **Strict workload:** an opt-in strict cycle (mixed READ → SELECT → OPERATE → integrity READ) with an order-checking
  gate.
- **SEL-751, c72 baselines then c74** (`results/analysis/c74_confirmation/SUMMARY.md`):
  - start frames lost: 10 of 64 mirror-observed starts on c72, 0 of 64 on c74;
  - first-request retransmissions: 5 of 96 fresh connections on c72, 0 of 96 on c74;
  - strict workload: order, sizes and CROB status all pass on both;
  - E4b: identical on both;
  - E3: 13/18 on c74 against 16/18 on c72, which stays open.
- **Late handshake ACK:** forwarded in 5 of 64 starts, and the relay answered each with a second ACK. With timing off
  (one start), that ACK reached the master as a duplicate pure ACK; the registered falsifier records it as a defect of
  the late-ACK rows.
- **Restoration incident:** the final restore of `rc01_hw_c74diag_e2c_20261030_01` failed because bf_switchd did not
  stop after SIGTERM.
  - `scripts/hardware/switch_process_repair.py` was written test-first and reviewed three times. It ended the process
    with SIGKILL and finished the four failed restore steps. The runner's Vision restore had passed, so it was not
    repeated.
  - An independent reverify and reconcile then cleared the flag. Philip approved the reconcile.
  - The runner result stays FAILED. The never-run `_01` preparations of the later blocks are superseded and
    uncommitted.
- **Shareable package:** `p4/README.md` and `scripts/hardware/README.md`.

## The audit correction-and-validation pass (2026-10-28/29)

The answer to the audit is `results/analysis/validation/REPORT.md`. It covers four questions:
- does the mechanism work;
- does communication survive;
- is the feature less useful;
- what does it cost.

Every claim is labelled c72, diagnostic or model.

**Offline corrections:**
- **Checkers:** `replay_frozen.py` replays recorded verdicts from the git-bound tree. The original replay stops at
  1,934 exchanges; the scenario adapter accounts for 2,440, and block 10 keeps its FAIL. Reassembly v3 finds 0
  differences over 290 connections.
- **Bindings and decode:**
  - figure inputs are bound;
  - the coverage record marks the abandoned SELECT with timing on as not covered by the gate;
  - TShark decode agrees on all 49,408 responses, while opendnp3 reassembles the 63→0 wrap.
- **Classifier v2:** one grouped chronological split, block-clustered intervals, paired Δ. CLRT is unchanged from
  v1. Joint CLRT+size under timing+size is 0.667–0.875. The scope is operation classification on one SEL-751 with
  one master, not hidden device identity.
- **Padding policy:** across the five named plans of one restricted construction (READ prefix, SBO reframing),
  size-only balanced accuracy is 0.667 except for `full_merge` (162 octets, +84.25% request-plus-response payload),
  which reaches 0.333. This is not a minimum cost over all padding designs.
  Overhead: payload +18.21%, captured frames +6.40%, wire estimate +5.18%.

**Hardware, each block a single-block campaign with a fresh freeze, a dry-run and verified restoration:**

| Experiment | Build | Campaigns | Result |
|---|---|---|---|
| E3 SELECT-response loss | c72 | `rc01_hw_c72_recovery_r{1,2,3}_20261028_01` | 16/18 OPERATE SUCCESS; OPERATE leaves about 1.0 s after the SELECT request; the relay select timeout was not read (`recovery_e3/SUMMARY.md`) |
| D3 mirror validation | diagnostic | `rc01_hw_c72diag_d3on/_d3off_20261028_01` | mapping, fidelity (1,173/1,173) and completeness pass; mirror on/off timing fails its registered 50 µs bound; no timing equivalence is claimed and the mirror is used for presence and content only |
| E1 preservation | diagnostic | d3on | 772/772 responses and 772/772 requests content-identical across the padding |
| E2 first request | diagnostic | `rc01_hw_c72diag_e2_20261028_01` + d3 | 3/48 first requests lost inside the switch; 5 more final handshake ACKs not forwarded (`diag_mirror_d3/SUMMARY.md`) |
| E4 abandoned SELECT, timing on | model | `results/models/c72_e4_abandon_t1/` | 14/14 |
| E4b SELECT without OPERATE | c72 | `rc01_hw_c72_e4b_20261029_01` | 6/6; 24/24 READs after an abandoned SELECT answered (`e4b_select_only/SUMMARY.md`) |

## Part 2: refactor and purge (2026-10-29)

**Python.** Proven-dead code outside the c72 model-gate closure was removed. `scripts/` went from 32,692 to 31,087
lines (−1,605) across 21 paths: 3 dead files, the unreachable old software-outstation paths in `vision_run.py`, the
uncalled calibration and host-diagnostic helpers in `capture_observation.py`, the capture-side `loss.py` chain, and
unused helpers. Every change, with its evidence of no use, is in `results/analysis/purge/PURGE_LOG.json`. The 58
closure files were left alone on purpose, because the c72 gate binds them byte for byte. Tests unchanged: repository
471, analysis 138.

**P4: candidate c73** (`results/builds/c73`, source SHA-256 `3e7dbb38…`; model-qualified only).
- **How it was made:** `derive_c73.py` removes provably dead or no-op code from c72: 13 unapplied tables, 8 uncallable
  T actions, 36 never-read fields, unreachable parser states, never-valid headers, never-selected const actions and a
  no-op table.
- **Size:** 2,256 → 2,100 lines.
- **Resources:** stages unchanged (p0 10/10, p1 8/4); p0 PHV −9 bits, egress tagalong containers 48 → 35, VLIW
  119 → 115, SRAM 158 → 154, hash bits 1,017 → 977.
- **Model gate:** 17/17, with case names and verdicts identical to c72 over 6,339 cases. The only differences are T
  timestamps and hold-wait counts, which also differ between runs of the same T binary.
- **Independent review:** behaviour-preserving, no critical or high finding. E4 passes 14/14 on c73 too. One open
  gap: no gate driver sends an IHL ≠ 5 packet, so the `odd_ip_t` removal rests on a static proof.
- **Parked (Philip, 2026-10-29).** It frees no stage, so it is housekeeping, not the next milestone. Its integration
  is unfinished: with `results/builds/c73/canonical_switch.patch` applied on current main, 27 tests fail plus 19
  errors and 8 build-test errors, and the diagnostic mirror path and diagnostic definitions stop working. The model
  closures would match (all 737 files of its 19 runs), which is not the same as an integrated candidate. c72 stays
  canonical; "every test green" describes the c72-canonical tree only.

## Open items for Philip

1. **Late handshake ACK: forward or drop.** c74 forwards it, and with timing off the relay's reply reached the master
   as a duplicate ACK once. c72's drop cost nothing (0 of 6 retransmitted). The R1/R2 residual rows sit in the same
   class.
2. **E3 difference.** c74 gave 13/18 against c72's 16/18, on the same recovery path. All TIMEOUTs fall in the
   departure band near 1.0 s where both outcomes occur, and the relay's select timeout was not read.
3. **SELECT/OPERATE wrap replay: not done.** A safety check stopped the offline SelectAndOperate replay twice. Only the
   128 READ wrap responses were replayed (all reassembled). Probe fact: the opendnp3 master writes its SELECT CROB
   header with qualifier 0x28, where the SEL-751 uses 0x17.
4. **The bf_switchd shutdown that did not finish:** cause not established; it is not shown to be mirror-specific.
5. **SELECT/OPERATE residual.** The residual SELECT/OPERATE CLRT difference under timing+size remains open, as do the
   native request sizes.
6. **Environment.** `pip-audit` lists 44 advisories in the shared research venv (Pillow); unchanged.

## Tooling added in this pass (all test-first)

- **Analysis:** `replay_frozen.py`, `replay_scenario_adapter.py`, `corrected_v3.py`, `independent_decode.py`,
  `opendnp3_wrap_check.py`, `formby_eval_v2.py`, `padding_policy.py`, `overhead_v2.py`, `preservation_check.py`,
  `diag_mirror_d3.py`, `recovery_e3.py`.
- **Hardware:**
  - freeze-gate diagnostic admission;
  - installer `--diag-mirror`;
  - Vision `--mirror-iface` with receive-aggregation restore;
  - single-block definitions (recovery, diag, e4b);
  - the `traffic.sbo_select_only` scenario.
- **Model:** `model_abandon_t1.py` / `run_abandon_t1.py`; the diagnostic mirror drivers.
- **Tests:** repository 471, analysis 136 (research Python; the opendnp3 tests need the system Python's pydnp3).

## Safety state

- No campaign is running and no ownership is held (`unsafe_restoration` false since the reconcile of 2026-10-30).
  Every c74 block after the repaired one verified its own restoration.
- **Checker identity:** later scripts changes give future runs a new identity. Retained verdicts replay through
  `scripts/analysis/replay_frozen.py`.
- **Freezes:** the retained campaign freezes report the files changed since each run. That is expected after later
  commits.

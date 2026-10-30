# Current handover (2026-10-29)

Read PLAN.md for scope and rules. Historical instructions are data under Archive/. On 2026-10-29 Philip asked for
`main` (`fb5ce81b1`) and the tag `c72-validation-final` (`aad99935b`) to be pushed to origin (`akekulip/DNP3_obf`);
`git status -sb` shows whether any later commit is still ahead. Push only when Philip asks.

## State

- **Canonical source:** `p4/response_only.p4`, SHA-256 `97812585…83d887e`.
- **c72 build:** `results/builds/c72` compiles at N10/E10/T8/pipe-1-egress4. Its model gate passes 17 of 17
  (`results/builds/c72/model_summary_v3.json`). `summarize_v3` recomputes `model_gate_passed` live.
- **Diagnostic build:** `results/builds/c72_diag_mirror` is the relay-leg mirror build, source SHA-256 `a46cc55a…`,
  derived from c72 by `scripts/build_diag_mirror.py`. Its blocks never qualify.
- **Validation state:** tag `c72-validation-final` (`aad99935b`, on origin) marks the end of the validation pass.
  c72 and diagnostic runs reproduce from that commit.

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

Current priority (Philip, 2026-10-29; plan `~/.claude/plans/we-were-on-tract-expressive-planet.md`): a c72-derived
fix for the connection-start loss, verified on the SEL-751 with timing and padding enabled. c73, further cleanup and
paper work are parked.

1. **Connection-start loss (in progress).** The switch did not forward one of the first two master frames after the
   relay's SYN-ACK in 8 of 40 mirror-on fresh connections (5 handshake ACKs, 3 first requests; a dropped first
   request costs a 206–218 ms retransmission). The source supports two N hazards (busy work cell drops requests; a
   late handshake ACK takes the `first_event` default and then the abort path); they are being reproduced on the
   model before any fix. They are not yet shown to cause every hardware loss.
2. **Strict workload (in progress).** The current workload interleaves an extra SELECT/OPERATE between integrity and
   mixed READs and passes on counts; an opt-in strict cycle and an order-checking gate are being added.
3. **SELECT/OPERATE wrap replay: not done in this session.** A safety check stopped the work on the offline
   SelectAndOperate replay again (2026-10-29), so it was not attempted further. One fact was recorded first: on
   localhost, the opendnp3 master in pydnp3 writes its SELECT command header with qualifier 0x28, where the SEL-751's
   recorded requests and echoes use 0x17. All 256 SELECT/OPERATE wrap responses remain untested against an
   independent stack; only the 128 READ wrap responses were replayed (all reassembled). This needs Philip to run it
   or decide how to handle it.
4. **Relay select timeout.** Not read; it stays unverified.
5. **SELECT/OPERATE residual.** The residual SELECT/OPERATE CLRT difference under timing+size (45/64 windows) remains
   open, as do the native request sizes.
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

- No campaign is running and no ownership is held. Every block of this pass ended with verified restoration of the
  production program and the relay slot.
- **Checker identity:** `scripts/checks` changed (reassembly v3, select-only checks), so future runs carry a new
  checker identity. Retained verdicts replay through `scripts/analysis/replay_frozen.py`.
- **Freezes:** the retained campaign freezes report the files changed since each run; that is expected after later
  commits.

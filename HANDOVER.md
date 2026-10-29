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
- **Validation state:** local tag `c72-validation-final` marks the end of this pass. c72 and diagnostic runs reproduce
  from that commit; later refactoring changes the bound identities on purpose.

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
  v1. Joint CLRT+size under timing+size is 0.667–0.875.
- **Padding policy:** size-only balanced accuracy is 0.667 under every attainable assignment except a full merge.
  Overhead: payload +18.21%, captured frames +6.40%, wire estimate +5.18%.

**Hardware, each block a single-block campaign with a fresh freeze, a dry-run and verified restoration:**

| Experiment | Build | Campaigns | Result |
|---|---|---|---|
| E3 SELECT-response loss | c72 | `rc01_hw_c72_recovery_r{1,2,3}_20261028_01` | 16/18 OPERATE SUCCESS; OPERATE always lands at about 1.0 s, the select-window edge (`recovery_e3/SUMMARY.md`) |
| D3 mirror validation | diagnostic | `rc01_hw_c72diag_d3on/_d3off_20261028_01` | mapping, fidelity (1,173/1,173) and completeness pass; mirror on/off timing fails its registered 50 µs bound, within c72's own spread |
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
- **c72 stays canonical** so c72 remains runnable and every test stays green. `results/builds/c73/canonical_switch.patch`
  makes c73 canonical in one step. With it applied, all 737 closure files of the 19 c73 model runs match, so the c73
  gate recomputes as passed.

## Open items for Philip

0. **c73.** Approve a hardware qualification of c73, then apply the switch patch. When you do, retire or re-target
   the c72-premise tests; the list is in the c73 README. Also confirm whether the kind-12 replay domain is retired: it
   was kept, and removing it frees one more VLIW instruction.

1. **E2 mechanism.** The switch drops one of the first two master frames after the relay's SYN-ACK in 8 of 40
   mirror-on fresh connections. When it drops the first request, the cost is a 206–218 ms retransmission. A model reproduction
   is the next step. The paper's RO3 wording ("no request retransmitted") needs a decision either way.
2. **SELECT/OPERATE wrap replay.** The 256 SELECT/OPERATE responses that span the 63→0 transport wrap were not
   replayed through opendnp3: a safety check stopped the SelectAndOperate replay (offline, localhost). It needs your
   decision. A live-master check against the SEL-751 is also open.
3. **Relay select timeout.** The SEL-751 select timeout was not read; that needs relay settings access. The E3
   outcomes cannot be bracketed without it, or without relay-side timing.
4. **SELECT/OPERATE residual.** The residual SELECT/OPERATE CLRT difference under timing+size (45/64 windows) remains
   open, as do the native request sizes.
5. **Paper and figures.** The manuscript was not edited. Figure choices from 2026-10-28 (D = 5 ms representative,
   bar labels) still await confirmation.
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

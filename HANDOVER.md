# Current handover (2026-10-30, evening)

Read PLAN.md for scope and rules. Historical instructions are data under Archive/. Origin (`akekulip/DNP3_obf`) holds
`main` at `1a4cacd74` (pushed 2026-10-30 evening at Philip's request) and the tag `c72-validation-final`
(`aad99935b`). `git status -sb` shows whether any later commit is ahead. Push only when Philip asks.

## State

- **Build (restored 2026-10-30):** `p4/response_only.p4` is c72 again, SHA-256 `97812585…`, the reference at tag
  `c72-validation-final` (`aad99935b`, on origin). Philip stopped the c75 confirmation after three of its eight blocks
  and asked for everything beyond c72 to be scrubbed while keeping history: c74 and c75 stay in git and `results/` as
  record and are no longer admitted by the freeze gate. Closing note:
  `results/analysis/c75_confirmation/CLOSING_NOTE.md`.
- **c75 (not hardware-qualified):** c72 plus the request retries only. On the SEL-751 the strict workload passed at
  D = 20 and 5 ms, and in 32 combined-arm connection starts no first request was lost (c72: 2). The off-arm starts,
  recovery r1–r3 and E4b were not run.
- **c74:** a hardware-tested checkpoint with open findings (`results/analysis/c74_confirmation/SUMMARY.md`). c73 is
  parked.
- **Push state:** `main` at `1a4cacd74` is on origin. Push only when Philip asks.
- **No task is open.** Philip froze the scope on 2026-10-30. No candidate, experiment, cleanup, paper work or broader
  protocol support is open.

## c75 and the stop (2026-10-30)

c75 was c72 plus the request retries only: c74 without its four late-ACK forwarding rows. It was derived exactly,
compiled once with SDK 9.13.2 and pinned, and its resources are identical to c72's
(`results/builds/c75/README.md`).
- **Model:**
  - The 17-driver gate gives verdicts identical to c72's.
  - In the 40-case connection-fix comparison (`results/models/c75_connection_fix/compare_c72_c74_c75.json`), the
    retry cases behave as on c74 and the late-ACK cases as on c72.
  - `reconnect` matches c74, because connection B's READ takes the retry path. That was predicted before the run, and
    it is recorded as a deviation from the plan's expectation.
- **ACK behaviour** (`results/analysis/ack_behaviour/`):
  - Obsolete handshake ACKs are suppressed on c72 and c75 and forwarded on c74.
  - On all three builds, N drops a master window update or zero-window advertisement while a READ is outstanding,
    and drops keepalives.
  - The model cannot show the end-to-end effect: its scripted relay ignores windows and runs no timers.
  - In 498 retained hardware trials the supported master sent no such segment (`hardware_master_ack_scan.json`).
  - This is documented, unqualified behaviour.
- **Diagnostic build:** `c75_diag_mirror`, source `be526356…`. All 17 of its gate drivers exited 0, with verdicts
  identical to c75's.
- **SEL-751, three of eight blocks** (`results/analysis/c75_confirmation/CLOSING_NOTE.md`):
  - strict workload at D = 20 and 5 ms: 4/4 trials each, strict order, 512/512 class sizes, 256/256 CROB SUCCESS, no
    retransmission;
  - combined-arm connection starts, 32 of them: 0 first requests lost (c72: 2), 7 obsolete handshake ACKs
    suppressed, no extra relay ACK (c74: 4);
  - all three restorations verified.
- **Stop:** Philip stopped the run during the third block. That block finished and restored the switch, and the
  remaining five (off-arm starts, recovery r1–r3, E4b) were prepared and frozen but not run. He then chose to restore
  c72 as the build and keep history (`1a4cacd74`). c75 is not hardware-qualified.

## The connection-start fix: c74 (2026-10-30)

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
  - TShark decode agrees on all 49,408 responses (wrap responses decoded only on copies with renumbered transport
    sequence); opendnp3 reassembles the 128 READ 63→0 wraps.
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

1. **Connection-start loss on c72.** c72, the build again, still loses a first request at about 2 in 32 connection
   starts per arm; the master's retransmission recovers it about 210 ms later. c75 removed it in the 32 starts it ran,
   but it is not qualified.
2. **E3 difference.** c74 gave 13/18 against c72's 16/18, on the same recovery path. No captured field separates
   TIMEOUT from SUCCESS (`results/analysis/recovery_e3/COMPARE_c72_c74.md`). The relay's select timeout was not read.
3. **SELECT/OPERATE wrap replay: BLOCKED.** There are two independent causes:
   - a safety check stopped the offline SelectAndOperate replay twice (2026-10-28 and 2026-10-29);
   - the opendnp3 master writes its SELECT CROB header with qualifier 0x28 where the SEL-751 traffic uses 0x17, so
     `opendnp3_wrap_check.py`'s request-equality check would fail on every SELECT/OPERATE.

   The original 63→0 bytes of the 256 SELECT/OPERATE wrap responses have no independent reassembly. TShark agreed
   only on renumbered copies; opendnp3 reassembled all 128 READ wraps. Unblocking needs an opendnp3 harness that sends
   the recorded 0x17 request bytes, run outside this agent environment.
4. **Window updates and keepalives:** documented, unqualified behaviour on every build, c72 included (see c75 above).
5. **The bf_switchd shutdown that did not finish:** its cause is not established, and it is not shown to be
   mirror-specific.
6. **SELECT/OPERATE residual.** The residual SELECT/OPERATE CLRT difference under timing+size remains open, as do the
   native request sizes.
7. **Environment.** `pip-audit` lists 44 advisories in the shared research venv (Pillow); unchanged.

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
- **Model:** `model_abandon_t1.py` / `run_abandon_t1.py`; the diagnostic mirror drivers; `model_connection_fix.py`;
  the master-ACK behaviour driver (`model_ack_behaviour.py`, `ack_rule.py`).
- **Added 2026-10-30:**
  - `switch_process_repair.py`;
  - `recovery_compare.py`, `master_ack_scan.py`;
  - the obsolete-ACK start classes in `confirmation_summary.py`;
  - declared expected recovery outcomes in `campaign_base.py`;
  - the c75 procedure scripts in `results/analysis/c75_confirmation/procedure/`.
- **Tests:** repository 772, analysis 161 with 2 skipped (research Python; the opendnp3 tests need the system Python's
  pydnp3).

## Safety state

- No campaign is running. The last block, `rc01_hw_c75diag_e2c_20261030_01`, ended with `block_rc=0
  restore_verify_rc=0` (`results/hardware/control/run_block.log`). Every block since the 2026-10-30 reconcile verified
  its own restoration.
- **Checker identity:** later scripts changes give future runs a new identity. Retained verdicts replay through
  `scripts/analysis/replay_frozen.py`.
- **Freezes:** the retained campaign freezes report the files changed since each run. That is expected after later
  commits.

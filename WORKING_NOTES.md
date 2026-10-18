# Working notes

## Task (2026-10-05, evening): testbed re-verification, then READ response-ready offline gates

### Testbed (verified, no DNP3 sent)
- Rack move fixed: breakout DAC in cage 15 (15/1 dp9 Vision UP, 15/2 dp10 UP, 15/3 dp11 Hulk UP, 25G);
  relay leg 33/0 dp64 UP at 1G via a 25G DAC into the *other* unmanaged switch (Netgear GS748T SFP
  slots are 1G-only and never linked, ports 45 and 48 tried). SEL 192.168.10.7 answers through the
  Tofino only (20/20 pings, 0.5 ms avg; TCP 20000 handshake opens). ION 7550 is OFF (expected).
- Vision isolation applied: 192.168.10.1 removed from eno1 (NM profile eno1-dhcp),
  /etc/sysctl.d/90-dnp3-lan-isolation.conf (arp_ignore=1, arp_announce=2, arp_filter=1 on eno1/eno2).
  Revert: nmcli con mod eno1-dhcp +ipv4.addresses 192.168.10.1/24; delete that sysctl file.
- Vision mgmt is 10.10.54.19 (eno1), eno2 .166 also on the Netgear. Hulk .158, ufispace .81.
- Loaded program on the switch is still rrc_bor_build_v2 (frozen_abs.conf, bringup_20261005);
  that is the pre-test state to restore. The response-ready candidate is NOT loaded.

### Response-ready gates
- Found 1 failing offline test (test_commit_parity). Root cause: fused tbl_decide_deq mapped
  OUT_AB_TMO/OUT_RB_TMO with read_release=1 to finish_path_0 (drop); build 22 sends the timeout
  note (role=254, to_block) via cmt_timeout_note, which is how timeout escapes are reported.
- Fix 1 (src/defense4_response_ready.p4): 9 tbl_decide_deq rows changed to finish_path_2 and
  finish_path_2 added to the table's action list. Pre-edit copy and hash 8c44bc55... kept in scratchpad.
- Fix 2 (tests/test_commit_parity.py): narrow exemption for the intentional watchdog-priority
  repair already asserted by test_p4_recovery.test_enabled_watchdog_priority_and_domain (read_release=1,
  owner valid, budget_zero=1, pending blocker: TMO instead of DL). Effects still compared to build 22.
- Results: 45/45 tests OK; control.py --da-ms 5 OK; local_build_33 (SDE 9.13.1) and
  evidence/sde_9_13_2_build_01 (SDE 9.13.2, built on ufispace in ~/response_ready_build_20261005)
  both 7 ingress / 0 egress / 88 tables; verify_build passes on both; build 32 correctly rejected as stale.
- New source sha256: ceececa36be84e8ef1691e3d957bf2069133c18ead6b76d4549560d17d238d73.

### Not done
- No candidate loaded on the Tofino; no hardware traffic; nothing committed (response_ready is untracked).
- code-reviewer not yet run on the 9-row P4 change + test exemption.

Next action: wait for Philip's go for step 6 (read-only live snapshot, restoration procedure for
rrc_bor_build_v2, then bounded READ-only validation). Needs the restoration plan written first.

## 2026-10-06 — framework track (branch codex/framework-implementation-20261005)
- Reviewer found the 2026-10-05 nine-row timeout-note change loops in MODE_OFF/FAIL_OPEN; reverted test-first
  (test_timeout_note_terminates_in_every_mode), orphan finish_path_2 deleted. Source sha cedded03...
  (supersedes ceececa3... above). 46 response_ready tests OK; SDE 9.13.1 build 34 is 7/0. 9.13.2 build on
  the switch host is STALE and must be redone before any deployment step.
- framework/ created: contract, independent model, 26 scenario tests, run_tests.sh (261 offline tests green).
- campaign_v2 reproduction done; gate noise is path-only. Commits e8cc2d148, d787d6756, 8e15e73b5, f56e0b662. Not pushed.
- Next: model-vs-P4 trace diff harness (Phase 2), then per-type policies (Phase 3), BFRT adapter (Phase 5).

## 2026-10-06 (later) — framework track status
- All phases done to the extent possible without hardware; see defense4/timing/audit_current/framework_20261005/HANDOVER.md and CLAIMS_RECONCILIATION.md.
- 349+ offline tests green (run_tests.sh: 58+98+39+47+132). Commits through 6a356678e; NOT pushed. 9.13.2 build of source 6387c588 done on ufispace in ~/framework_build_20261006 (7/0 stages).
- Hardware NOT run. Blockers: restoration of the running bf_switchd (frozen_abs.conf) never rehearsed; no candidate bring-up for ports/TM/pktgen/PRE; live adapter paths never run.
- Open decisions for Philip: push; CLAUDE.md scope-change line; unattended cold restart of the Tofino.

## 2026-10-06 (end of day) — framework track
- Pushed branch codex/framework-implementation-20261005 to origin (see git log). STATUS.md under defense4/timing/audit_current/framework_20261005/ is the entry point.
- Hardware: 4 sessions, 4 restores, lab on frozen_abs.conf / defense4_rrc_bor_unified12, one daemon. Candidate source df5991016285 (two const-table sizes fixed after the driver rejected the first load).
- OFF smoke 30/30 READ (median CLRT 2.240 ms). Master RTO on the candidate build: kernel 201 ms, first repeat 204.4 ms. Admission verdict provisional: detect_ms, release_tail_ms, outstation_feedback_path_ms unavailable.
- Next: decide how to clear admission (operator acceptance for a bounded smoke / instrumented build / relay-facing tap). CLAUDE.md scope line still pending; CLAUDE.md carries Philip's own uncommitted edit.
- Pushes go in Philip's name only; no co-author trailers.

## 2026-10-06 (merged) — standing rule
- Framework track merged to main by PR #6 (merge commit 20eef2019). Work and commit directly on main from now on; no new branches. Remote branch codex/framework-implementation-20261005 is kept (no remote branch deletion without being told).
- All commits and pushes are Philip's name only: akekulip <akekulip@gmail.com>, no Co-Authored-By.

<!-- AUTO-HANDOFF (PreCompact/auto) 2026-10-07T02:16:27Z -->
### Compaction handoff — 2026-10-07T02:16:27Z
- Git: branch `main`, 98 uncommitted file(s): CLAUDE.md .drawio-tmp/ Codex_Implementation_and_Experiment_Prompt_2026-10-05.txt WORKING_NOTES.md bf_drivers.log defense4/Codex_Case4_Hardware_Architecture_Prompt.md defense4/timing/audit_current/MEETING_20261005_DIRECTION.md defense4/timing/response_ready/evidence/sde_9_13_2_build_01/out/ defense4/timing/response_ready/evidence/sde_9_13_2_build_02/out/ defense4/timing/response_ready/slides/ model_20261006_125053.log paper/rewrite/OBfus_defense/ 
- Last verification run recorded: 2026-10-07T02:12:39Z	ls /home/philip/bf-sde-9.13.1/install/bin | grep -i "model\|tofino\|veth\|run_"; ls /home/philip/bf-sde-9.13.1 | head; u
- RESUME: re-read the Task/Status/Next-action sections above; trust this file over recollection.

<!-- AUTO-HANDOFF (PreCompact/auto) 2026-10-08T15:11:06Z -->
### Compaction handoff — 2026-10-08T15:11:06Z
- Git: branch `main`, 276 uncommitted file(s): .drawio-tmp/ WORKING_NOTES.md bf_drivers.log defense4/Codex_Case4_Hardware_Architecture_Prompt.md defense4/timing/audit_current/MEETING_20261005_DIRECTION.md defense4/timing/case4_architecture/integration/core/ordinary/transport_model_select.py defense4/timing/case4_architecture/integration/evidence/model_02/run10/bf_drivers.log defense4/timing/case4_architecture/integration/evidence/model_02/run10/model_20261006_223250.log defense4/timing/case4_architecture/integration/evidence/model_02/run10/zlog-cfg-cur defense4/timing/case4_architecture/integration/evidence/model_02/run2/ defense4/timing/case4_architecture/integration/evidence/model_02/run3/ defense4/timing/case4_architecture/integration/evidence/model_02/run4/ 
- Last verification run recorded: 2026-10-08T03:49:57Z	git -c user.name=akekulip -c user.email=akekulip@gmail.com commit -q -m "Close M3/M6/L3: port cross-check test, correct 
- RESUME: re-read the Task/Status/Next-action sections above; trust this file over recollection.

<!-- AUTO-HANDOFF (PreCompact/auto) 2026-10-08T19:34:45Z -->
### Compaction handoff — 2026-10-08T19:34:45Z
- Git: branch `main`, 277 uncommitted file(s): .drawio-tmp/ DNP3_Timing_Size_Integration_Prompt.md WORKING_NOTES.md bf_drivers.log defense4/Codex_Case4_Hardware_Architecture_Prompt.md defense4/timing/audit_current/MEETING_20261005_DIRECTION.md defense4/timing/case4_architecture/integration/core/ordinary/transport_model_select.py defense4/timing/case4_architecture/integration/evidence/model_02/run10/bf_drivers.log defense4/timing/case4_architecture/integration/evidence/model_02/run10/model_20261006_223250.log defense4/timing/case4_architecture/integration/evidence/model_02/run10/zlog-cfg-cur defense4/timing/case4_architecture/integration/evidence/model_02/run2/ defense4/timing/case4_architecture/integration/evidence/model_02/run3/ 
- Last verification run recorded: 2026-10-08T19:33:39Z	git -c user.name="akekulip" -c user.email="akekulip@gmail.com" commit --author="akekulip <akekulip@gmail.com>" -m "$(cat
- RESUME: re-read the Task/Status/Next-action sections above; trust this file over recollection.

## 2026-10-08 — Case 4 timing+size integration (`DNP3_Timing_Size_Integration_Prompt.md`)

Current authority for this track: `defense4/timing/case4_architecture/HANDOVER.md` (read first),
`LEDGER.md` (dated history), `integration/INTEGRATION_CONTRACT.md`, `integration/size/SELECTED_PATTERN.md`
+ `selected_pattern.json`. This section is a pointer, not a duplicate — see those files for detail.

**Phase A** (verdict correction + integration contract) and the earlier **Phase C** work (T's queue-resident
timing role, `read_queue_timing.p4`, 18/18 invariants at the interpreter level) are committed. T's real
`bf-p4c` compile is blocked by an undiagnosed internal compiler crash in PHV allocation, confirmed on both
local SDK 9.13.1 and the switch's installed 9.13.2, four independent mitigation attempts exhausted — see
`integration/read/TIMING_QUEUE_MIGRATION_STATUS.md`. Not resumed without new diagnostic signal.

**Phase B (the decisive phase) is still open — three candidates tried today, all via the proven
`endpoint_gate` real-master validation pattern, same lesson twice now: clean unit tests and clean byte
arithmetic are not sufficient, only a real pinned-OpenDNP3-master/outstation run tells the truth:**
- **Option A** (request-side qualifier rewrite `0x28`→`0x17`, converge on 49B pre-carve, `[28,21]` split via
  the proven RRC mechanism): built, tested, **failed** real-master validation —
  `TypedCommandHeader::ApplySelectResponse`'s count-mismatch guard silently declines to select.
- **Option B** (`case4_pad58.py`, uniform 58B pad via G41V2/qualifier-`0x27` filler): built, tested
  byte-exact, **failed** real-master validation worse than A — qualifier `0x27` isn't one of the pinned
  library's seven implemented qualifier codes, so `APDUParser` aborts the whole fragment parse and the real
  native data (all 23 READ points; the whole SELECT/OPERATE echo) is lost too, not just the filler.
- **Option B′** (filler restricted to the library's seven whitelisted qualifiers `0x00,0x01,0x06,0x07,0x08,
  0x17,0x28`): dispatched to a bounded agent, in progress as of this note — CONTROL's 19-byte gap has a
  clean single-object arithmetic fit (`0x07`-qualified, no-index G41V2, 5 points); READ's 9-byte gap needs
  two header-only, count=0 objects, untested territory. Result pending.

**Housekeeping this session:** pushed `main` to `origin` (13 commits, clean fast-forward, `85c9f8cbf..
a1c84e3d0`) at Philip's explicit instruction. One commit (`a1c84e3d0`) carries a `Co-Authored-By` trailer
added by mistake (this repo's CLAUDE.md bars trailers) — flagged to Philip, not amended, since the
pre-tool-guard hook correctly blocks amends without his live explicit approval in chat, and it is already
pushed. Needs his go-ahead to amend + force-push if he wants it scrubbed.

**Not yet reached: the first-complete-packet-path milestone** (one READ and one SELECT/OPERATE transaction
through timing + size + transport, on the local model). Blocked on both T's real compile and a size pattern
that actually clears `endpoint_gate`. Do not report a standalone component fit as equivalent progress.

**Update 2026-10-08, later: Option B′ CLEARED.** The dispatched agent's result was independently re-run in
this session (fresh output dir, same pinned commit `4648fcb898`) and confirmed: `62/62 assertions pass`,
real OPERATE + genuine SBO actuation on CONTROL, all 23 real points delivered on READ, clean recovery
afterward. Committed `5e848351c`. Phase B's software model is resolved for the first time today, after two
prior candidates failed the same gate. Docs updated: `SELECTED_PATTERN.md`, `selected_pattern.json`,
`HANDOVER.md`, `LEDGER.md`.

RESUME: Phase D is next — the P4 data-plane realization of `case4_pad58b.py`'s exact filler bytes on all
three roles, including the combined pipe-0 egress compile (sharing with `installed_nf_05`). This is new,
substantial engineering scope, and T's queue-timing compile crash (PHV allocation, undiagnosed) is still
open and could recur here. Not yet started as of this note.

**Superseded by the section below — this "Phase D not started" framing is stale as of 2026-10-08 late.**

## 2026-10-08 (late) — external review (`DNP3_5e848351c_Review_and_Continuation.md`), F1–F4 fixed, Stream 3 done

An external review of `5e848351c` found four real bugs (F1 Mirror metadata set but never emitted; F2 OPERATE
deadline reuse; F3 `wgen` parsed-never-read — investigated, no fix needed, N's own admission already
prevents the stale-response path, pinned by `H_NRealisticAssociation` tests; F4 endpoint gate's READ-recovery
assertion passed regardless of real data) plus two doc overclaims (F5/F6). All fixed and verified this
session, committed and **pushed** to `origin/main` (now at `2c205fc15`):
- `23dc0ec51` F2 fix (unconditional `op_t0_arm` overwrite, RESET clears preserved) + F3 investigation (133
  tests, 132 pass + 1 `expectedFailure` for RESET-near-wrap).
- `a6f087e84` B′ endpoint gate hardened 62→165 real assertions.
- `ea2d16f39` doc corrections (B′ scope, T status, two overclaims).
- `dff615339` F1 Mirror clone emission implemented, **verified on the local Tofino-1 model** (not just
  simulator): destination, tag, bytes, blocker admission all correct (`evidence/mirror_f1_01/`). Standalone
  compile only — whole-file `read_queue_timing.p4` compile still crashes (exit 4); new diagnostic lead found:
  `op_done_reg`/`ack_done_reg`/`resp_done_reg` each read-compare-then-dependent-write, which a single
  register's placement stage can't satisfy; `outcomes` register has an analogous, separate conflict.
- `2c205fc15` `case4_pad58b_wire.p4` now validates incoming DNP3 link CRCs before transforming (matches
  Python codec's reject/pass-through-unchanged behavior exactly); 8 egress stages, PHV allocation succeeds;
  49/49 local-model cases incl. 14 deliberately-corrupted-CRC pass-through cases (`evidence/pad58b_wire_02/`).

## 2026-10-09 — Overnight execution: complete the mechanism, verify, run on physical hardware

Driving document: `DNP3_Overnight_Core_Mechanism_Prompt.md` (root). Plan approved and active at
`~/.claude/plans/make-a-plan-first-logical-abelson.md` (read that file for the full plan — this entry is
the checkpoint, not a duplicate).

**Objective:** classification → blocker-queue timing → selected size transform → valid TCP delivery, on the
physical Tofino-1, measured READ and SELECT→OPERATE, four-arm comparison (baseline/timing-only/size-only/
combined). Treat as an ongoing fix-and-improve loop, not a single pass.

**Authorization basis:** Philip supplied the Overnight brief and explicitly asked, this conversation, for a
plan that runs on hardware — treated as the specific recorded authorization `INTEGRATION_CONTRACT.md` §6
requires for chip activation/port/TM/PRE/pktgen/mirror config/traffic generation, scoped to this mechanism
only. Physical OPERATE stays attended-only (software command-handler fallback otherwise). No SDK change, no
edits to frozen sources/`paper/rewrite/`, no push without Philip's fresh explicit instruction each time.

**Two open blockers carried in:** `read_queue_timing.p4` whole-file compile still crashes (see diagnostic
lead above); no sequence/ACK transport mapper exists yet for the size transform, even response-only no-split.

**Hardware state, last two recorded notes disagree and need live re-verification before any contact:**
2026-09-25 README says the 7-stage `defense4_timing` candidate (source `16050715`, sha256
`d2306158f59e69c622654b0577e4518e5be7a69eb927f80c3727f07f8c553090`, matches `loaded_identity.json` and
`candidate_sde9132/manifest.json`, 7 ingress/0 egress) was left loaded, MVM not restored. 2026-10-06
`PHASE0_INVENTORY.md` says original `rrc_bor_build_v2` is loaded, candidate not loaded, no traffic since the
rack move, relay SFP must be in E1/33. `SWITCH_LAYOUT.md`: switch is `ssh decps@10.10.54.81` (`ufispace`),
Vision/master is `ssh decps@10.10.54.166`, outstation SEL-751A at 192.168.10.7 (relay-side, not reachable
from mgmt subnet). Restoration procedure: `stage_reduction/hardware/20260925/switch/restore_mvm.sh` +
`PHASE8_HARDWARE_RUNBOOK.md` + `RESTORATION_REHEARSAL_20261006.md` (rehearsed cold-restart-with-no-candidate).

**Active streams (dispatched in parallel per the plan's immediate-kickoff section):** 1) timing route A-vs-B
investigation (`p4-dataplane-engineer`), 2) transport mapper construction, 3) `[28,30]` split-candidate
evaluation, 4) hardware prep/live-state re-verification (main session, direct SSH), 5) review
(`code-reviewer`/`research-scientist`). Status of each tracked below as streams report back.

**Hardware state, LIVE-VERIFIED 2026-10-09 ~03:33 (read-only, no config/traffic changes):**
- Switch (`ssh decps@10.10.54.81`, `ufispace`): `bf_switchd` running since Oct06 (`frozen_abs.conf`,
  `bringup_20261005`), config confirms loaded program is **`defense4_rrc_bor_unified12`**
  (`rrc_bor_build_v2/out/...`) — the original baseline, **no candidate loaded**. This resolves the
  09-25-vs-10-06 discrepancy in favor of the 10-06 `PHASE0_INVENTORY.md` account.
  `restore_mvm.sh`/candidate-specific restore scripts found under `stage_reduction/hardware/20260925/switch/`
  only — not yet needed since no candidate is loaded.
- Master/Vision: `SWITCH_LAYOUT.md`'s `10.10.54.166` is **stale** (pre-rack-move; that IP is now Vision's
  secondary/dynamic `eno2`, unreachable/flaky). Live correct mgmt address is **`10.10.54.19`** (`eno1`),
  confirmed reachable, host up 3 days (consistent with post-rack-move reboot). Vision's relay-side NIC
  `enp59s0f0np0` carries `192.168.10.1/24` and reaches the SEL-751 outstation at `192.168.10.7` with 0% loss,
  ttl=255 (through the Tofino, as expected) — full master→switch→outstation path is live and verified.
- This sandbox environment is directly on the `10.10.54.0/24` management network (src `.133`) and can reach
  both the switch and Vision directly — no jump host needed.
- Not yet checked (deferred to immediately before actual load, per plan): live front-panel port/link status,
  exact current cabling at the relay leg (expected E1/33 per the 10-06 note, not re-confirmed live).

**Route decision (2026-10-09 ~03:55): Route B (repair `read_queue_timing.p4`), not Route A.** Route A's
7-stage hardware-tested source (sha256 confirmed `d2306158f...3090`) does not transfer: it parses its own
Ethernet/TCP/DNP3 with no N event header/kinds/epochs/generations, protects only single-segment responses
(multi-segment forwarded **unprotected**), has no shared-release or transport-mapper hooks, and would need
its parser/classification replaced to fit behind N (pipe-0 ingress already 12/12, 32-bit PHV 62/64 with N) —
exactly the part its hardware validation covered. `test_t_queue_invariants.py` doesn't apply to it at all
(26/27 fail at load, different struct). Route B's blockers, by contrast, now have names and are partly fixed.

**Route B progress (uncommitted in the working tree as of this note — pending qa-verifier + code-reviewer,
both dispatched, before commit):** `defense4/timing/case4_architecture/integration/read/read_queue_timing.p4`
+ `make_operate_slice.py`/`operate_slice.p4`/`operate_slice_capture.p4`, evidence in
`integration/evidence/route_ab_01/`. Nine changes: `op_done_try`/`ack_done_try`/`resp_done_try` (atomic
`RegisterAction`s, confirmed behavior-preserving); `outcomes` consolidated into one `outcome_count` table fed
by `md.outcome_code`; four bit-31 sign-slices replaced with one-entry ternary tables (the `~delta[31:31]`
pattern was forcing 40 fields to split, including the hardware timestamp — this is what turned five earlier
"internal compiler error" attempts into dead ends); `admit_request_gen` split out `make_request_tag`
(invalid-container-op fix); `quarantine_reg` read/write consolidated into one `quarantine_access` call site.
**Result so far:** isolated OPERATE slice compiles clean (exit 0, 9 ingress/0 egress — tight against the
12-stage budget); `test_t_queue_invariants.py` still 132 passed + 1 expected failure (RESET-wrap, untouched).
**Still open, both named with reproducible starting points:** (a) a genuine 3-register circular dependency
`resp_done_reg`→`resp_mask_reg`→`ack_done_reg`→back that the single-RegisterAction pattern can't resolve —
needs a design decision (folding "response released" state into the mask register is the proposed next
try); (b) the port-0 token branch still crashes the full file even with (a) stubbed out — "Table placement
cannot make any more progress," N-input-branch tables unplaced. Agent `a61f1fb3640511b07` resumed to continue
on both. No 9.13.2 (switch) compile attempted yet — local 9.13.1 only so far.

**Split-candidate `[28,30]` result (2026-10-09 ~04:10, qa-verifier dispatched to confirm, not yet landed):**
Built, compiled, and rigorously tested (`defense4/timing/case4_architecture/protocol/case4_pad58b_carve28_30.p4`
+ evidence in `evidence/pad58b_carve28_30_01/`, untracked) — 729/729 local-model checks (exact byte match,
`prefix||suffix==padded_frame`, correct IP/TCP headers+checksums, DNP3 CRC cut lands exactly at the end of
the first data block in both READ and CONTROL so no CRC spans it, FIN/unselected/7-corrupted-frame safety
cases all correct), a deliberately-broken mutant correctly fails 76 checks (real discriminating power), and
184/184 real-Linux-kernel TCP-socket reassembly runs delivered the correct 58 bytes in both observed and
reversed replica-arrival order, with both negative controls correctly delivering nothing. Clarifies the
mechanism: **replication happens before padding** — each egress replica gets the native unpadded frame and
runs its own CRC check and its own padding/carve slice.

**Recommendation: keep `[58]` as the baseline for tonight, not `[28,30]`.** Measured cost is worse on every
axis (critical path 7 vs 6, 30 SRAM blocks vs 8, +57% wire bytes, two egress passes vs one) — and critically,
**`[28,30]` needs an ingress table that `[58]` does not**, while pipe-0 ingress is already saturated (12/12
with N alone, and Route B's repaired T is separately using 9/12 just for the isolated OPERATE slice). Combining
`[28,30]` with Route B's T is very unlikely to fit tonight on resource grounds alone, independent of any
remaining correctness work. `[58]` stays the response-only, no-split baseline per standing instruction; the
historical `9ffa9102` evidence is correctly scoped in the new `STATUS.md` as not covering this composition —
these new 729+184 runs are the actual evidence for `[28,30]` specifically.

**Route B diff independently verified (2026-10-09 ~04:20):** qa-verifier confirmed 5/6 claims directly against
real re-runs (op_done_try source matches claim exactly; outcome_code reset-every-packet + single count() call
site confirmed, no double-count/staleness path; isolated OPERATE slice re-compiled, exit 0, 9 ingress/0
egress, matches exactly; full-file compile re-run, still exit 4 same internal-compiler-error, byte-identical
log; resp_done_reg's 3-register circular dependency independently re-derived from source — `resp_done_reg` <
`resp_mask_reg` < `ack_done_reg` < `resp_done_reg`, a genuine stage-ordering contradiction, not a missed
simple fix). code-reviewer separately confirmed the whole diff is semantically equivalent to HEAD across all
27 test scenarios (0 differences) via direct mutation testing, EXCEPT one real gap: mutating `op_done_try` to
never write passes every existing test — the OPERATE exactly-once-release property has no regression test.
Asked the agent to add that test (inject a duplicate `ROLE_OP_HELD` token with the same op_gen after a first
release, assert `OUT_OP_RELEASE` stays 1) before this lands. One loose end: the agent's own evidence claims
174 tests pass "with harness tests added," unreproducible on the current tree (27 single-file / 132 whole-dir
both confirmed correct) — asked for clarification before treating that number as real. **Not yet committed**
pending both of these.

**`[28,30]` split-candidate committed `6630c9fcf`** (2026-10-09 ~04:35) — all 5 qa-verifier claims independently
re-confirmed from scratch (fresh compile, fresh 729-case model run, fresh mutant reproduction, fresh kernel
reassembly run, baseline-number cross-check). 43 files, `.gitignore` clean (no raw logs staged). Not pushed.

**Transport mapper: real working result, but a serious stage-budget collision found (2026-10-09 ~04:50,
not yet committed, qa-verifier + code-reviewer dispatched):**
`defense4/timing/case4_architecture/protocol/TRANSPORT_MAPPER_SPEC.md` +
`defense4/timing/framework/size/case4_response_mapper.py` (software ref, 14 tests + 44 total w/ existing
suites) + `case4_transport_mapper.p4` (P4). One padding "image" slot per connection (6 registers/200 bits:
native frontier N, wire frontier W, U=W-A unacked wire bytes, e_start, e_end, wire-end of image); commits
only when U==0 (always true under DNP3 request/response, since the next request carries the ACK); exactly-once
via `s==N` with N monotonic; a second eligible response while one is unacked is refused and sent native
(leaks that one response's size, never corrupts the stream). **Deliberately departs from the `case4_transport.py`
oracle** for ACKs inside an active image: holds back ANY partial ACK until the whole image is acked (oracle
releases all-but-one-byte, which a P4 pipeline can't reconstruct) — claimed always conservative/safe relative
to the oracle; code-reviewer specifically checking this. P4: 12 egress stages, critical path 12, 6 stateful
registers each touched by exactly one table (deliberately avoiding the read-compare-then-dependent-write
shape that sank `read_queue_timing.p4` and the old "M" stage). Model: 111/111, byte-identical to software
output, sequence-wraparound case included and passing, exactly 6 commits for 6 eligible responses, two
partial-ACK-no-stranded-tail cases both correct.

**Critical open problem: the mapper alone uses all 12 egress stages; `case4_pad58b_wire.p4` needs 8 more —
they cannot share one egress pass as currently built.** This blocks the combined compile regardless of
anything else landing clean. Also found: the padder currently pads every eligible frame unconditionally,
needs to pad only on the mapper's commit/replay signal; the standalone mapper build used a shape-only
verdict stand-in instead of the padder's real CRC validation (untested in combination); a checksum-residual
interaction if the two share a parser. Sent back to the agent as the next priority — fuse into 12 total
stages if genuinely possible, report plainly if not (would mean moving a piece elsewhere, e.g. ingress,
which is itself tight: Route B's T uses 9/12 ingress for its OPERATE slice alone).

**qa-verifier confirmed all mapper claims from scratch** (2026-10-09 ~05:10): 14/14 + 44/44 tests, 2 of the 6
mutations independently reproduced and caught, 12-stage/critical-path-12 compile confirmed from
`table_summary.log`, each of the 6 registers confirmed one-apply-call-site, 111/111 model run with a true
byte comparison against the software mapper's own computed seq/ack/window (not just a plausibility check),
and `transport_mapper_01`'s failure independently reproduced as genuine (not a relabeled duplicate). Still
waiting on code-reviewer's deeper correctness pass (pipelined-master edge case, oracle-departure safety,
refusal/exhaustion path, cross-register ordering) before commit.

**code-reviewer BLOCKS the transport mapper (2026-10-09 ~05:25) — two real liveness bugs the 111-case suite
missed, fixes sent back to the agent, NOT committed:**
- **[HIGH]** A real TCP stack's default retransmission-merge behavior (`tcp_retrans_collapse=1`) produces a
  segment shape the mapper's replay path rejects forever (`drop_overlap`), permanently stalling the
  connection — the test harness only ever retransmitted with idealized original segment boundaries, which is
  why this was invisible. Needs either accepting merged-replay-plus-tail, or an explicit, checked deployment
  constraint on the outstation's stack.
- **[HIGH]** The 6 registers are per-pipe; nothing states or enforces that the master-facing and
  outstation-facing ports must be in the same pipe. If they aren't, the mechanism breaks silently in both
  directions. The model run only passed because both test ports happened to share pipe 0 — not yet checked
  against this project's real port map.
- Mediums: an offset-6 TCP-options segment passes untranslated (violates the "drop what can't translate"
  safety promise); the model driver silently masks a real model/P4 disagreement on FIN-carrying retransmits;
  refusal triggers more broadly than the spec documents (wording fix, not a bug).
- **Confirmed sound, not at risk**: register placement genuinely avoids the M-stage structural failure (real
  verification, not superficial), exactly-once commit, the ACK-holdback oracle departure's safety, and
  wraparound arithmetic.

RESUME: read this section + the plan file; check for agent results; advance the next bounded sub-task per
the plan; update this checkpoint; schedule next wakeup via `ScheduleWakeup` if mid-flight.

**Route B: internal-compiler-error fully eliminated, replaced by a named, ordinary stage-budget problem
(2026-10-09 ~05:50, qa-verifier + code-reviewer dispatched, not yet committed):** Both named blockers
resolved — the resp_done/resp_mask/ack_done loop broken by reordering (response marks its mask bit before
resp_done_reg is read; argued unobservable since any already-released generation takes the passthrough
branch first — being checked), and the port-0 crash root-caused to a masked-width comparison bug
(`tok_diff = batch_id ^ (bit<16>)gen`, tested `!=0`, replacing a mismatched 16-vs-32-bit inequality). Several
N-input table consolidations beyond that (quarantine split by `hdr.tev.kind`, `gen_access`/`epoch_access`
one-apply ternary tables, modular `(now-X)-t0` arithmetic to shorten chains, `ack_go_check` consolidation).
OPERATE slice now 8/0 stages (down from 9). **Whole file now fails with an ORDINARY table-placement error —
needs more ingress stages than the 12 available for the ACK-commit→response dependency chain — not an
internal-compiler-error.** Same status on both 9.13.1 and the switch's 9.13.2. Tests: 175 passed + 1 xfail
(132 `read/tests` + 42 `core/harness/tests` + 1 new — the earlier "174 unreproducible" finding was a scope
gap in how qa-verifier invoked pytest, not a real discrepancy, now resolved with the exact command recorded).
New regression test closes the OPERATE-exactly-once gap code-reviewer found earlier, confirmed to fail under
the same mutation. Two untested candidate fixes for the remaining 2-3-stage overage sent back to the agent:
moving the response gap check off `ack_commit_at_reg`'s late stage, and moving the outcome-counter bump off
the critical decision path.

**code-reviewer's second pass (2026-10-09 ~05:55, after a mid-task rate-limit interruption and resume) found
something that may matter more than the stage-count framing:** `ack_commit_at_reg` is accessed twice in one
pass — `read_gap_delta()` runs unconditionally for every role, `mark_ack_commit_at()` separately runs in the
ROLE_ACK_HELD branch, and these aren't mutually exclusive. The exact compile error names these same tables —
this may be a real structural double-access conflict, not purely a stage-count shortfall. Sent back as the
first thing to try (move `read_gap_delta()` into just the ROLE_RESP_BLK/ROLE_RESP_HELD branches that actually
need it). Also found: the new exactly-once test overclaims — the "copy" does eventually reach the relay via
the already-known `flush_operate_stale()` path once a later OPERATE arrives (consistent with this project's
standing "exactly-once is not claimed" position, not a new bug) — needs renaming, an inverted assertion
message fixed, and a companion test for the stale-flush case. The status doc's "Current state" section also
cites a stale source hash from an earlier version of the file. All three sent back. Everything else
(resp_mask reordering safety, tok_diff equivalence, N-input table changes, RESET invariant) independently
re-confirmed sound with added rigor (named the previously-undocumented ACK-gate consumer of `resp_seen_mask`).

**qa-verifier's second pass (2026-10-09 ~06:05, frozen against the `64cedc0d...` snapshot since the agent had
already moved on) confirms 5/6 claims with reproduced evidence** (whole-file exit 2 ordinary placement error
exact match; both slices byte-identical regen + exit 0 with exact stage counts; 175/1-xfail test count exact;
exactly-once test's mutation evidence exact). **Claim 6 (resp_mask reordering) marked FAIL as a verification
claim, though no actual bug was found**: the agent's safety proof named only 3 of at least 4 `resp_mask_reg`
consumers; qa-verifier independently checked the missing 4th (the ACK_BLK stop-blocking gate) and confirmed
the reordering is safe there too, for an independent reason — but the agent's original reasoning didn't cover
it. This is the same consumer already requested to be documented in the last message sent; no new action
needed beyond what's already in flight. The agent has since moved on (observed live, working on
`b25_gap_read_resp_only`, file hash already changed to `d0ac8a68...`) — consistent with it already acting on
the `ack_commit_at_reg` double-access fix sent earlier.

## ⚠ DECISION NEEDED FROM PHILIP: Route B's full-file compile hits a genuine architectural wall, not a bug

**2026-10-09 ~06:20.** After the `ack_commit_at_reg` double-access fix (confirmed real, applied) plus several
more structural consolidations (quarantine/`t0` merged into one table, moving it stage 3→2; a too-wide
32-bit epoch check split across stages, now one register action; the response-mask conflict this produced is
gone) — **the whole file still fails the identical table-placement error**: `ack_commit_at_reg`'s read must
be at stage ≤6 and its write at stage ≥6, pinning it to exactly stage 6 with **zero slack** across the whole
ACK-commit→response dependency chain. This is now a well-understood, crisply diagnosed resource/structural
limit, not a mystery — qa-verifier dispatched to confirm this final round before commit.

**The two ways forward both have real tradeoffs; this needs a decision, not another local repair:**
1. **Remove the RESET-time clears on `ack_commit_at_reg` (and the same pattern recurs on `resp_deadline` and
   `op_t0_reg`), replacing them with generation-tagging** so a stale value is recognized by generation instead
   of by being zeroed. This is exactly the kind of RESET-semantics change Philip corrected twice during this
   session's earlier plan-approval cycle (requiring any later cleanup to still satisfy: "RESET invalidates the
   affected timing association, releases held originals per the recovery policy, and prevents stale tokens
   from affecting the next transaction" — not just "don't touch the clears" permanently). It is observably
   different today: "after a fallback ACK commit, the response's timing uses whatever is in
   `ack_commit_at_reg`" per the agent's own report. Doable, but needs real design work and new tests proving
   the contract still holds, not just a quick patch.
2. **Move part of the response gating off this ingress pipeline** (e.g., to egress, or to a different pipe) —
   not yet scoped or attempted.
3. (Not proposed by the agent, but consistent with the Overnight brief's own instruction that T's compiler
   crash "must not become the sole definition of progress for the whole project"): **accept this as a reported,
   evidence-backed hardware-fit limitation for tonight** and continue the other streams (transport mapper,
   size, hardware prep, N's producer work) on their own merits, revisiting T's full compile as a named open
   item in the morning report rather than continuing to spend the night searching for a fix to a wall this
   well-diagnosed.

**Not deciding this unilaterally** — it's a genuine architecture fork with a RESET-semantics tradeoff on one
side, consistent with how carefully Philip has supervised exactly this kind of change in this file before.
Continuing other streams (transport mapper, hardware prep, N-handoff, B' socket test) in parallel rather than
blocking the whole run on this one decision.

**Committed `8fe093c91`** (2026-10-09 ~06:35) — all 8 final-round claims independently re-confirmed by
qa-verifier before commit (hash match, exit-2-not-ICE, both slices, 176/1-xfail, both new tests + mutation,
the resp_mask comment, the status doc's current hash/result, the double-access fix's actual scoping). Evidence
directory `.gitignore` extended to also exclude `frontend-ir.json`/`tofino.bin`/`context.json`/`bfrt.json`
(reproducible compiler artifacts across ~30 iteration rounds, 9.3MB → 52KB after exclusion). Not pushed.

**MAJOR RESULT: padder + transport mapper fused into one combined egress program (2026-10-09 ~06:50, not
yet committed, qa-verifier + code-reviewer dispatched):** `case4_architecture/protocol/case4_response_path.p4`
(new) + `response_path_cp.py` (new control-plane connection-entry builder) + `model_drive_response_path.py`.
**12 egress stages, critical path 11 — fits in the full budget with zero headroom — 163/163 model checks
pass.** The key structural trick: the reverse (ACK/mapper) branch became the `else` of the forward
(response/pad) branch, letting the compiler see the two never run on the same packet (13→12 stages). All of
last round's findings addressed:
- **[HIGH] same-pipe requirement: fully fixed** — `response_path_cp.py` is now the only way connection entries
  get built and raises `PipeMismatch` for a cross-pipe pair, tested. Confirmed against this rig's actual
  wiring: master dev_port 9, relay dev_port 64, both pipe 0 (matches this session's own earlier cabling
  findings).
- **[HIGH] merged retransmission: fixed in the software model, partially in the P4** — a merged retransmission
  carrying native bytes AFTER the padded image can't get a correct one-pass TCP checksum (an odd/odd
  byte-parity issue); rather than emit a bad checksum, the P4 explicitly drops that one case
  (`OUT_DROP_MERGED`) and a later plain retransmission still completes delivery. Honestly flagged, not
  overclaimed: whether the real SEL-751 stack ever produces exactly this collapse pattern is unverified and
  named as needing a real capture on the rig.
- Mediums (offset-6 options, FIN-masking in the test driver, refusal-scope wording) all fixed and tested.
- Pad-gate, real CRC verdict (stand-in removed), and checksum-residual fix (extracted payload headers added
  back) all done as requested.
- **Two previously-unknown, silent Tofino/bf-p4c defects found and fixed along the way**: a parser field copy
  that silently loaded the wrong 16-bit half of a 32-bit field with no compiler warning, and the deparser's
  checksum silently including containers from absent/overlaid headers (fixed with `@pa_no_overlay`). Both
  worth remembering for any future P4 work in this codebase — real footguns, not one-off typos.
- Old standalone `case4_transport_mapper.p4` + driver deleted as superseded (source preserved in evidence
  snapshots); `case4_pad58b_wire.p4`/`case4_transport.py`/`transport_model_select.py` confirmed untouched.

**qa-verifier confirmed all 7 claims from scratch** (2026-10-09 ~07:10, fresh namespace, fresh compile, fresh
163/163 model run, all named cases present). **code-reviewer: no critical issues, but 3 warnings to fix
before hardware** (2026-10-09 ~07:20, not yet committed): [W1, most important] the checksum-fix comment
doesn't match what's actually compiled — invalidated tail-header containers aren't cleared, only correct by
coincidence on the model, flagged as possibly failing on real hardware; [W2] a reconnecting master can trigger
a partial table install (`odd_ip_t` keyed on IP pair only, no removal path, never exercised by the test
driver); [W3] the same-pipe check validates the declared ports, not the separately-installed forwarding table
— enforced by convention only. Confirmed safe: the branch-exclusivity structural trick for stage-sharing is
genuinely sound (every packet gets exactly one of 4 classified outcomes, all accounted for); the pad-gate's
four exclusion cases all verified correct; the merged-retransmission drop never corrupts mapper state (no
register write happens before the drop). All three warnings sent back, with the stage-headroom-zero risk
flagged for W1's fix.

**All 3 warnings fixed (2026-10-09 ~07:45, `fused_12`, final verification dispatched, not yet committed):**
stage budget holds — still 12 egress stages, critical path 11, zero regression. W1: explicit field-zeroing
confirmed present in the compiled actions themselves (not just source), decoupling correctness from the
compiler's own invalidated-header handling. W2: `response_path_cp.py` rewritten as a real registry — checks
every row before writing, rolls back on any failure mid-install, a reconnect reusing an old slot is now
correctly refused rather than partially installing. W3: `Ingress.forwarding` rows now generated from the
same `Endpoint` objects as connection rows (one source of truth), reference-counted, refuses a port already
forwarding elsewhere. 165/165 model, 60 total tests (50 software + 10 control-plane). One limit honestly
documented, not fixed: a forwarding entry written outside the registry is invisible to the check (spec says
so explicitly). Unchanged: the merged-retransmission-with-trailing-bytes drop still needs a real rig capture
to confirm the SEL-751 never produces that exact pattern.

**Committed `f23150933`** (2026-10-09 ~08:05) — all 7 final claims re-confirmed from scratch before commit
(compiled `.bfa` zeroing, atomic rollback test injecting failure at each of 6 writes, forwarding reference-
counting, 60/60 total tests). Evidence `.gitignore` extended the same way as `route_ab_01` (compiler-artifact
exclusions) across `transport_mapper_01`/`_02` — 1.9MB total for 12 iteration rounds. Not pushed. **This is
the single biggest result of the night**: a real, working, hardware-fit TCP transport mapper fused with the
size transform, something this project never had before (the earlier "M" stage attempts never reached a
working implementation).

## Consolidated synthesis — where the four plan streams actually stand, 2026-10-09 ~08:10

1. **Timing route (T).** Route B selected and committed in two rounds (`8fe093c91` latest). All four
   register-placement conflicts found after the Mirror work are fixed and independently re-verified; the
   whole-file compile went from an unexplained internal-compiler-error to a crisply-diagnosed, named
   stage-budget wall (`ack_commit_at_reg` pinned to stage 6, zero slack). **Blocked on a real architecture
   decision, parked for Philip** (see the flagged section above) — not resolved, not silently worked around.
   OPERATE slice alone still compiles clean at 8/0 stages; 176 tests pass, 1 expected RESET-wrap failure still
   open by design.
2. **Transport/size.** **This is the night's strongest result.** `case4_response_path.p4` (committed
   `f23150933`) fuses the `[58]` response-padding transform with a real, working TCP sequence/ACK/window
   mapper into one 12-egress-stage program (zero headroom), 165/165 model checks, two full adversarial review
   rounds closing every finding (one honestly left as a documented, bounded limitation rather than
   overclaimed). The `[28,30]` split candidate was separately built, tested (729 + 184 real-kernel checks),
   and correctly NOT adopted — it needs an ingress table pipe-0 doesn't have room for. **This stream is
   essentially complete for the response-only, no-split baseline** — the next real step is combining it with
   whatever T state exists, or loading it alone on hardware to validate independently.
3. **Hardware prep.** Live-verified (read-only): the switch currently runs only the original baseline
   (`defense4_rrc_bor_unified12`), no candidate loaded; Vision's actual live management address was found
   (`10.10.54.19`, not the stale `SWITCH_LAYOUT.md` address) with a confirmed, working path all the way to the
   SEL-751 outstation. Ready for a load attempt once there's a compiled candidate to load — not yet attempted,
   since no single buildable combined candidate exists yet (T is blocked; the fused response-path alone could
   be loaded independently to validate the size/transport piece on real hardware before T is resolved).
4. **N's real OPERATE handoff + timing anchor.** Both parts done (2026-10-09 ~08:30, not yet committed,
   qa-verifier + code-reviewer dispatched): N now hands an accepted OPERATE to T as a real `tev` (kind 12) on
   port 325 instead of forwarding its own copy — a 3-line change in each N source, mirroring the existing
   READ/ACK/RESPONSE pattern. **Duplicate handling needed no new code**: N's existing state machine (sequence
   tracking, busy-pin, idle-state refusal) already covers retransmission, late-after-exchange, late-during-a-
   second-exchange, and in-flight-duplicate cases — demonstrated with 8 new tests replaying real N output,
   7 of which fail against the pre-change sources (proving they test something real). **Honestly scoped
   limit**: `n.p4` (the real production pipeline) can't actually reach an OPERATE from real packets *yet*,
   because the protected-SELECT response path isn't built in `core/ordinary/` — the full path only runs
   through the `native_binding.p4` test harness today; a new test explicitly pins this as a known, expected-
   to-change gap rather than hiding it. Three EXISTING tests were modified (not just added to) because N's
   actual output format changed — flagged by the agent itself for extra scrutiny, now under review.
   **Timing-anchor part**: the cross-pipe clock test ran on the model and confirmed the pipes share one clock
   (never goes backwards across 160 inter-pipe hops, bound ±2-3ms) — but the model's own clock granularity
   (~1ms) is too coarse to measure the actual N→T transit delay, and the suggested fallback (measuring it from
   real replays) turned out to be impossible too (the test harness has no real clock). Rather than leaving
   this as "provisional, undetermined," a structural answer was derived instead: `T.md.now = N.t0q + X` where
   X is N's fixed internal path (3 recirculations + 1 hop + queueing), and since READ and OPERATE take the
   same passes, X is structurally identical for both — meaning the anchor choice makes T systematically late
   by X (never early), the ACK is effectively held for D_A+X instead of the contract's D_A, and variation in X
   reaches the master unmasked. Actually measuring X, or switching the anchor to `hdr.tev.t0q`, needs the real
   silicon cross-pipe test — correctly not attempted without the testbed.

## 2026-10-09 (later) — third external document, plan revised, three streams relaunched

Philip relayed `DNP3_Hardware_Implementation_and_Evaluation_Plan.md` (root), a much more detailed execution
spec superseding the second review's summary. Plan file (`~/.claude/plans/...`) rewritten to track it. Two
corrections to this session's own earlier framing: the 164-vs-176 test count is NOT a discrepancy (different
suite scopes, both real — second review's own document says don't investigate it); "final-pass qualification
is just ingress metadata" was incomplete per the new document ("ingress metadata does not automatically
become an egress control input") — needs a real parser-visible bridge/shim or port-classification mechanism,
consumed by an existing egress decision, not new logic.

**Live hardware re-verification (read-only, via `live_snapshot.py` — genuinely read-only, `entry_get`/
`default_entry_get` only, confirmed from its own source before running):** copied to the switch, run against
the currently-loaded `defense4_rrc_bor_unified12`, 292 tables dumped. Confirmed from the real `$PORT` table:
**dev_port 9 = cage 15/1 = UP (Vision/master); dev_port 64 = cage 33/0 = UP at 1G (relay)** — both <128, both
pipe 0. This matches the 2026-10-05 note and `PROVENANCE.md` exactly: **no topology drift since the rack
move**, confirmed live rather than assumed. Still running only the baseline, no candidate loaded.

**N-handoff: all 3 commit-blockers addressed (2026-10-09, final qa-verifier pass dispatched):** stale generated
artifacts handled with judgment, not force-fixed — `ne.p4`/`placement/n3.p4`/`placement/nf.p4` regenerated and
confirmed byte-identical/stage-matched; `placement/m3.p4`/`e3.p4`/`f.p4` correctly left alone (m.p4 changed
after their last verified placement, so regenerating would silently swap in different, unverified M/E drift —
a separate decision, not this agent's to make); `composed.p4` explicitly flagged "STALE: do not compile or
use" in RESULT.md rather than regenerated. Non-canonical-length bypass: claim narrowed, new test class added,
independently confirmed present at HEAD too (not a regression). Retransmission tradeoff: documented plainly
in three places. Full suite: 144+1xfail/42/73/85/17/20/33, all green. Self-disclosed: the agent itself (not a
separate stray process, as earlier suspected) made the in-place `differential.py` edit during its own teeth
check, caught and reverted it, and saved a memory note to use scratch copies going forward. Noted: Route B's
agent has already moved `read_queue_timing.p4` to a new hash since this round started — check that agent next.

**N-handoff committed `9311245ab`** (2026-10-09, qa-verified before commit) — not pushed. Flagged a live
regression to the Route B agent: `test_duplicate_ack_records_a_commit_once` now fails with `TypeError: 'int'
object is not subscriptable` on its current tree (evidence rounds `b28`-`b32` show it moved from the
`resp_deadline` audit into generation-tagging work: `b28_no_resp_deadline`, `b29_commit_at_gen_tag`,
`b30_commit_gen_reg`, `b31_merge_release_count`, `b32_reset_bumps_op_gen`) — sent back to fix before
continuing further.

**Real B′-over-real-TCP-sockets workload runner: built, verified twice, qa-verifier dispatched for a third,
independent pass** — `defense4/timing/framework/size/endpoint_gate/{SocketGatePad58B.cpp,pad58b_proxy.py,
run_sockets_pad58b.py}` + `socket_evidence_pad58b_01/`. Real master+outstation over real TCP sockets (not
mocks); 3 repeated READs + a full SELECT→OPERATE with B′ padding applied to live response bytes; all 23
points match the seeded pattern each read; SBO succeeds on the real index (1), not the decoy (201); an
independent wire-byte recomputation (not reusing the proxy's own decision) shows 0 mismatches. No raw packet
capture possible on this host (no `CAP_NET_RAW`/sudo, confirmed by a failed tcpdump probe) — used a JSONL
byte-level tee instead, explicitly flagged as the sanctioned alternative. Builder honestly disclosed finding
and fixing a bug in its own new code (a wrong Flags-byte assumption: true points carry `0x81` not `0x01`,
since the STATE bit folds in) — caught by the first run correctly failing, not by loosening the assertion.
**Committed `12a30b168`** — qa-verifier confirmed all 7 claims from a fresh independent run, including reading
the actual pinned OpenDNP3 source (`Group10.cpp`/`MeasurementFactory.h`/`MeasurementTypes.cpp`) to confirm the
0x81 Flags-byte explanation at the source level, not just on trust. Not pushed.

**MAJOR: generation-scoped RESET redesign lands, fixes the long-standing RESET-wrap defect as a side effect
(2026-10-09, qa-verifier + code-reviewer dispatched with extra skepticism given the stakes, not yet
committed):** `resp_deadline` confirmed genuinely dead weight (nothing ever read it for a real decision) and
removed; `ack_commit_at_reg`'s RESET-time zero-clear replaced with a generation tag (`ack_commit_gen_reg`) so
a stale value is recognized by generation mismatch instead of being cleared, closing the original stage-6
zero-slack conflict with real slack to spare (now reads stages 3-7, writes 6-11); the same pattern applied to
OPERATE (RESET bumps `op_gen` instead of zeroing `op_t0_reg`). **This incidentally fixed the RESET-near-clock-
wrap `expectedFailure` that's been open and explicitly tracked as "must stay visible until genuinely fixed"
for this entire session** — the test now actually passes, not removed or weakened (pending independent
confirmation, dispatched with maximum skepticism given how long this has been flagged as open). Release
timing confirmed unchanged in every measured scenario; new tests (`J_GenerationScopedReset`, 4 tests) pass on
the new tree and fail on the pre-redesign source. Full suite: 191 passed, **0 failed, 0 expected failures**
(the RESET-wrap xfail is gone for real, not just hidden). A TypeError regression the agent introduced mid-work
(b29→b30 transition, a test indexing a field layout that had changed) was caught and fixed, confirmed clean.

**Compile status changed again, now a different, well-understood wall**: the whole file still doesn't
compile, but the error is no longer about `ack_commit_at_reg`'s placement at all — it's now Tofino-1's
per-stage **logical table count limit** ("too many tables total" in stages 2-4; every bare action/assignment
in the apply block is its own table, and the file has 116 tables + 32 gateways). Two cheap mitigations tried
and didn't resolve it (merging release+count pairs: no change, reverted; removing early branches: reduces
pressure, same error). Per the pivot rule, the agent stopped and named two real next options rather than
searching further: (a) consolidate dispatch into a few mutually-exclusive decision tables (substantial
rewrite, not guaranteed to fit) — this is a pure engineering-structure question, not a semantics/RESET-design
question, so proceeding with it is a bounded judgment call, not something that needs Philip's sign-off the way
the RESET redesign did; (b) fall back to Route A composition (reopens the known DNP3-parsing/multi-segment
interface mismatches). Leaning toward (a) first, consistent with building on now-substantial, validated
progress rather than discarding it.

**qa-verifier confirmed all 9 claims with maximum scrutiny** (2026-10-09, ~1hr later) — the RESET-wrap fix is
real (decorator removed via git diff, assertions byte-identical including the exact 150µs number Philip
measured earlier this session, genuinely passes, fails on pre-redesign source along with all 4 new
generation-scoped tests). **But code-reviewer BLOCKED on one real, reproduced HIGH-severity bug**, not caught
by qa-verifier's broader checks: `admit_operate_held` tags a held OPERATE original with the generation current
*when its clone arrives* (`op_gen_peek()`), not the generation the clone itself carries
(`hdr.clone.tag`). Before this redesign RESET never moved `op_gen`, so this didn't matter — now a RESET
landing in the narrow window between `hold_operate` and the clone's return (reviewer measured ~`pktgen_ns/2`
in the simulator, real hardware window unmeasured) tags the held original with the *post-RESET* generation,
passes the stale check, and gets a full timed release instead of being flushed — exactly the behavior this
redesign exists to prevent. Reproduced directly: dt=1/3/4µs wrongly releases, dt≥6µs correctly flushes; every
existing RESET test uses ≥20µs offsets, which is why this was invisible. Fix (needs verification, not yet
applied): tag from `hdr.clone.tag` instead of a fresh `op_gen_peek()` read. Sent back now, along with 3 minor
fixes (scope the status doc's "150µs unchanged" claim to the tested offset — it's actually *earlier*, not
unsafe, at a shorter offset, just not literally unchanged; strengthen the clock-wrap test's own assertions
since it currently doesn't check the specific counters that prove the mechanism, only the timing; a stale
docstring). Confirmed otherwise sound: `resp_deadline` removal safe (only comment references remain
repo-wide), READ-side masquerade-trap closure fully traced and confirmed (single writer, gated by exact
generation match, no torn-pair risk since one pipe processes packets in order), OPERATE delivery still reaches
the relay even when classified as stale-flush instead of release. **code-reviewer fully satisfied with the fix** (2026-10-09, re-checked `hdr.clone.tag`'s generation-carrying
correctness including across wraparound, confirmed `op_gen_peek()`'s removal changed nothing else, confirmed
the READ-side closure untouched) — **and found a bonus**: the fix also incidentally repairs a separate,
pre-existing HEAD bug where two OPERATEs inside the clone window caused the first to be silently lost
entirely. Second test added (`test_two_operates_inside_the_clone_window_both_reach_the_relay`), fails on HEAD/passes on
new tree, 193 tests total. qa-verifier's final independent pass confirmed all 9 original claims plus this
fix, with one minor wording correction (only the one erroneous `op_gen_peek()` call site was removed; the two
legitimate ones correctly remain — exactly as intended). **Committed `730bb2212`** — two real, previously-
unknown bugs fixed (the clone-generation race, and the separate lost-OPERATE-in-clone-window defect it also
happened to repair) plus the long-standing RESET-near-clock-wrap defect genuinely closed, not hidden. Not
pushed. Compile wall unchanged in nature: still the Tofino-1 logical-table-count limit, now the sole remaining
blocker for T's full-file compile. Resumed Route B toward consolidating dispatch into decision tables.

## Hardware milestone: first installed-SDK (9.13.2) compile of the fused mechanism

**Committed `723bfd1ad`** (2026-10-09) — `case4_response_path.p4` compiled clean on the switch's own installed
bf-p4c 9.13.2 (not just local 9.13.1): exit 0, 0 errors, 6 warnings, **1 ingress / 12 egress stages, critical
path 11 — exact match to the local build**. Compiled read-only on the switch host (source copied to `/tmp`,
compiler run there, no chip activation, no BFRT/context binding, no port/TM/mirror/pktgen configuration,
nothing written to the switch's real program directories). Source confirmed byte-identical to the committed
file via direct hash comparison. Discovered along the way: `defense4/timing/case4_architecture/.gitignore`
already excludes `**/out/` and `**/table_summary.log`/`**/phv_allocation_summary.log` repo-wide — this
explains why prior evidence commits this session never actually included raw `out/` trees despite my
per-directory `.gitignore` additions; the established convention is `compile.log` (console output) +
`manifest.json` (hand-extracted key numbers) as the durable record, which this evidence dir now follows.
## MAJOR MILESTONE: case4_response_path.p4 is now actually loaded on the physical Tofino-1 chip

**2026-10-09 ~18:50 — first-ever physical chip activation of tonight's combined mechanism.** Executed directly
(not delegated), following the exact proven restoration pattern from `RESTORATION_REHEARSAL_20261006.md`
(Philip's own real-time-authorized 2026-10-06 rehearsal, which proved the switch returns to its exact baseline
state in ~1 minute via a plain cold-restart + port replay from snapshot):

1. Fresh pre-change read-only snapshot taken (`live_snapshot.py`, 292 tables) and saved locally as the
   restoration safety net, before touching anything.
2. Full deployable build artifacts (`bfrt.json`, `pipe/context.json`, `pipe/tofino.bin`) already existed from
   the earlier installed-SDK compile (`723bfd1ad`) — moved to a durable location
   (`/home/decps/Philip_repo/dnp3-defense4/case4_response_path_01/`), a new conf file written
   (`case4_response_path_conf.json`, mirroring `frozen_abs.conf`'s exact structure) and a matching launch
   script, both deployed alongside (not overwriting) the existing baseline files.
3. Current baseline daemon (pid 30291, `defense4_rrc_bor_unified12`) confirmed one more time, then stopped
   cleanly (`SIGTERM`, confirmed no listeners remain) — this was the actual point of no return.
4. Started with the new conf (new pid 55925). One expected, benign warning in the log (`ChkSum not matched for
   33`) — confirmed by checking the baseline's own historical startup log that this exact message (ports 33
   and 34) already occurs there too, a known pre-existing platform/transceiver-EEPROM cosmetic message,
   unrelated to tonight's new program.
5. All three listeners up (7777/9090/50052); bfrt_grpc client successfully bound to `case4_response_path` and
   read back **403 tables** (more than the baseline's 292, consistent with this being a substantially
   different, richer program).
6. Fresh `$PORT` table was empty (expected — brand-new program, no prior config). Used the project's existing,
   already-proven `restore_ports.py` tool to replay all 20 previously-configured ports from the pre-change
   snapshot. **Confirmed: dev_port 9 (Vision/master) UP, dev_port 64 (relay) UP — exactly matching the
   baseline state**, both still speed/FEC/autoneg-identical to before.
7. A plain ICMP ping from Vision to the SEL-751 through the switch correctly failed (`Destination Host
   Unreachable`) — **expected and correct**: unlike the baseline, this program has no default-forward
   behavior; `response_path_cp.py`'s connection/forwarding registry must be populated with an exact TCP
   4-tuple before any traffic (even ICMP/ARP) can cross, by design (prevents an unconfigured flow from ever
   reaching the mapper).
8. Read `response_path_cp.py` in full to understand its real interface (`Registry.install()`, `Endpoint`
   dataclass, the four row types it installs: `Egress.conn` forward+reverse, `Egress.odd_ip_t` both
   directions, `Ingress.forwarding` both directions). Wrote `install_connection.py`, a BFRT adapter wiring
   this registry's `add`/`delete` callbacks to real `bfrt_grpc` table writes — **written but not yet executed
   against the chip**.

**Current live switch state (as of this note): `case4_response_path` is loaded and running, both key ports
up, no connection/forwarding entries installed yet, no traffic has crossed the data plane.** The proven
restoration path (`restore_ports.py` + the rehearsed cold-restart-to-`frozen_abs.conf` sequence) remains ready
and untouched if needed.

**Why I stopped here rather than pushing to live traffic tonight**: generating real DNP3 traffic needs a
fixed-source-port TCP client (the switch has no dynamic connection-admission — the exact 4-tuple must be
installed *before* the SYN) and a decision about what to test against. A plain READ against the real SEL-751
would validate end-to-end connectivity but almost certainly wouldn't exercise the padding transform itself
(the real relay's actual point configuration won't match the 23-point fixture shape `case4_pad58b.py`'s
eligibility check expects) — it would be a native-passthrough test, not a padding-mechanism test. Building this
correctly (DNP3 framing, fixed-port binding, safety-scoped to READ-only) deserves real care rather than a
rushed hand-rolled attempt at this hour, so it's dispatched to a power-systems-expert agent, explicitly scoped
to build and verify against a LOCAL SIMULATED outstation only (no real-network access, READ-only, SELECT/
OPERATE structurally absent from the script) — I will review it and be the one to actually run it against the
real lab hardware once it's verified safe.

Plan's own recommended first step ("Start with READ and software-handler SBO through the physical switch")
remains the right next action — this now has a clear, concrete path once the client is ready.

## ⭐ BIGGEST MILESTONE OF THE NIGHT: `read_queue_timing.p4` compiles as a whole program

**2026-10-09 ~19:10, qa-verifier + code-reviewer dispatched with real scrutiny, not yet committed.** After
closing the register-placement conflicts, the RESET redesign, and now the Tofino-1 logical-table-count limit,
`read_queue_timing.p4` (sha256 `b3470a690e89...`) **compiles clean on both local 9.13.1 and the switch's
installed 9.13.2: exit 0, 11 ingress / 0 egress stages, critical path 9.** This is the resolution of the
single longest-standing blocker of the entire project — this file has never compiled as a whole program
before tonight. All 193 tests still pass.

**What closed it**: consolidating dispatch into one ternary decision table per port (`tin_verdict`,
`token_verdict`, `held_verdict`, `hb_verdict`), rows kept in the original if/else priority order — logical
tables dropped from 116 to 49, gateways from 32 to 18. Plus: two register-placement deadlocks removed
(redundant sequential writes to one field serialized into `else if`; the held-return role chain reordered by
actual stage need); a header-read-after-invalidate bug the compiler itself caught and got fixed; and an
assembler-rejected masked-bitmask register test replaced with three separate single-word
`child_seen{0,1,2}_reg` registers, each holding the generation its child was last admitted in.

**Known, explicitly flagged gap, not yet closed**: the 193 tests run the P4 source through a Python
interpreter (`queue_sim.py`), not the actual compiled, stage-placed binary — a real local-model run of the
whole compiled program is the one remaining step before treating this as hardware-proven, not just
source-proven. Sent back to the agent as the immediate next task, in parallel with the independent reviews.
Stage headroom is tight: 11 of 12 ingress stages used, egress unused — any future addition on the ingress
critical path has exactly one stage of room.

## 🎉 FIRST REAL HARDWARE TRAFFIC THROUGH TONIGHT'S COMBINED MECHANISM

**Committed `1485c759a`** (2026-10-09 ~19:10) — executed and verified directly, not delegated. With
`case4_response_path.p4` loaded on the physical chip (see the hardware-milestone section above): built
`dnp3_read_client.py` (fixed-source-port DNP3 Class 0 READ client, structurally READ-only — no SELECT/OPERATE
code path exists at all, confirmed by grep) and `dnp3_sim_outstation.py`, verified first against a local
simulated outstation (caught and fixed a real framing bug — a hardcoded request control byte — by
cross-checking against this repo's own real captured OpenDNP3 traffic, not just the spec from memory). Found
the real rig's actual DNP3 link addresses (`master=1, outstation=0`, from `dnp3_wire.py` — the client's
default of `outstation=10` would have been wrong). Installed a real connection entry via
`response_path_cp.py`'s `Registry` (wired to real BFRT writes through a small adapter) for the exact TCP
4-tuple Vision↔SEL-751, confirmed the correct BFRT field names via live schema introspection (my first
mapping attempt was wrong and corrected). **Sent a real DNP3 READ request from Vision through the physical
switch to the real SEL-751A outstation (192.168.10.7:20000) — got back a valid, CRC-correct 134-byte
response.** Port counters on both links show zero drops, zero CRC/FCS errors; the egress program's own
table-hit counters confirm its classification logic genuinely processed this traffic (not a bypass). This is
a **native-passthrough result** — the real relay's actual response doesn't match the padding-eligible shape,
so it correctly took the pass-through path, not the padding transform. Demonstrating the padding mechanism
itself on real hardware still needs a software-handler outstation with the matching point shape, reachable
through the switch — not yet attempted.

**Current live switch state**: `case4_response_path` loaded and running, one connection slot (slot 0)
installed for Vision↔SEL-751 READ traffic, ports 9 and 64 up. Proven restoration path remains ready if needed.

**T's whole-file compile: real model run confirms it, qa-verifier confirms the compile — both clean.**
Route B ran the actual compiled binary (not just the Python interpreter) on the local Tofino-1 model: 20/20
checks pass across 7 phases (READ verdict/duplicate-drop, generation-scoped fallback classification, OPERATE
hold/release, the clone-window RESET fix specifically, quarantine bypass, generation-scoped RESET, policy-off
passthrough), matching the interpreter's predictions exactly, with real multi-lap holds (9-28 recirculations)
measured on the model. Honestly scoped as functional-only (model clock too coarse for timing claims; packet
generator/blocker-token residency and two-response-children not yet exercised). qa-verifier independently
confirmed the compile (both SDKs, 11/0 stages, critical path 9, switch's running `case4_response_path` daemon
confirmed completely untouched by the compile-only check) and hand-traced the `child_seen` register
equivalence and verdict-table row-order claims rather than taking them on faith. **code-reviewer's final pass (2026-10-09 ~19:45)**: no source-level defect found. Ran an independent
3,000-scenario differential fuzz test against the prior committed version (`730bb2212`) in the interpreter —
**zero behavioral differences**, with good coverage confirmed (every outcome code except `OUT_UNMATCHED`
reached in a 400-scenario sample, including duplicate drops, stale flushes, policy-off flushes, both ACK and
response fallbacks). Confirmed row order survives into the actual compiled `context.json` (priorities 0..N-1
in source order across all 7 decision tables). Three items sent back: one HIGH likely already closed by the
concurrent model-run result (asked for explicit cross-confirmation that the model run's duplicate/release/
RESET phases actually exercise the specific pre-write-vs-post-write register-timing risk the reviewer
flagged); one real MEDIUM (the `child_seen*_reg` 0xffffffff starting value is an unenforced safety rule — a
future control-plane reset that zeroes instead of restoring 0xffffffff would wrongly drop a genuine
generation-0 response as a duplicate); one real LOW (the OPERATE test slice generator now incorrectly routes
every event kind through `hold_operate()`, not just `KIND_OPERATE`, making the slice unrepresentative of the
full file for other event kinds). **Committed `fce869156`** (2026-10-09 ~19:55) — all three final items resolved with real engineering judgment,
not just applied mechanically: the HIGH register-timing concern confirmed by tracing through the existing
model run's actual per-phase counters (showing each phase would have produced a *different, wrong* result if
the suspected bug existed); the MEDIUM gen-0 gap fixed by investigating why the obvious "skip generation 0"
suggestion wouldn't actually work (generation 0 is live from power-up, not an edge case) and finding the real
mechanism that makes it safe instead (`resp_done_reg` also resets to 0, so a gen-0 response passes as
"already released" before the duplicate check runs) — pinned with a new test class; the LOW slice-guard bug
restored. 195 tests pass. **This is this project's single longest-standing blocker, closed tonight after
being open since before this session began.**

**Checked, ruled out for tonight**: whether Hulk could serve as a software-handler outstation on the
relay-side segment (to demonstrate the padding mechanism itself on real hardware, not just native
passthrough). Hulk is reachable on the management network but its other interfaces are on `10.0.2.0/16` and
`192.168.100.0/24`, not the SEL-751's `192.168.10.0/24` segment — not physically positioned to serve this
purpose without a cabling change, which is out of scope without separate authorization. Demonstrating the
padding transform on real hardware (vs. the already-proven native-passthrough result) stays an open item for
a future session with the right physical topology, or a more involved local-namespace workaround.

**Dispatched next**: the real combined compile of `read_queue_timing.p4` (11 ingress/0 egress) +
`case4_response_path.p4` (1 ingress/12 egress) — combined would be exactly 12/12 if nothing else is needed,
the tightest possible fit. This is the critical path to the actual "complete combined mechanism" milestone.
Also needs a real composition plan (where do the two programs' data flows actually join; does a
held/released packet from T need to pass through the padding decision on its way out — which directly
reopens the "final-pass qualification" work deliberately deferred pending T's compile, now unblocked).

**Resolved, then corrected after adversarial review**: Route B found T and the response path don't share a
pipe at all (N=pipe0, M=pipe1, T=pipe2 per `STEP3_DESIGN.md`), built a multi-pipe composition, and
demonstrated a frame released by T getting correctly padded on the model (14/14). **A code-review pass
immediately caught that this conclusion overclaimed**: the real N sets `tm.bypass_egress=1` on its normal
forwarding path, so N's actual traffic never reaches pipe-0 egress at all — the padded-flow demo only worked
because its simplified N-stand-in happened to leave that flag clear. Also found: the real PHV wall is far
worse than first estimated (N's pipe-0 ingress alone already uses 62/64 32-bit containers, matching
`SELECTED_PATTERN.md` gate 4's known "2 of 64 free" finding); the drop-only M stand-in silently hides real
SELECT/replay traffic that would break SBO if left in place; the tested "OPERATE through T" leg was actually
a coincidental numeric collision with N's unrelated "replay" kind, not the real OPERATE handoff. Sent back
corrected direction: fix N's `bypass_egress` for real, decide M's actual role (flagged to me, not a
unilateral call), then attempt the real compile expecting a genuine PHV/stage problem on the scale of T's own
stage-reduction effort. **Nothing from this composition is committed** — correctly held back pending the
real-N version. What IS confirmed solid: the T↔response-path pipe separation, T's Ethernet-frame-only
release behavior on every path, and the mapper's exactly-once-per-segment property.

**Follow-up, confirmed against source directly** (2026-10-09 ~20:15): most review findings hold up exactly.
Two corrected by real measurement, not just accepted: PHV is ~67 (not 84) against 64 if the old emitter
retires, ~81 if it stays — still genuinely over budget either way, just a different number; and the
"duplicate response blocks the mapper's replay path" concern was refined — T only suppresses a duplicate
*while the original is still held*, not after release (confirmed by an existing test), so the real open
question moved to N: does N even forward a post-release retransmission to T, or does it route it with
`bypass_egress=1` and skip the mapper entirely (meaning that loss case has no recovery path either way, just
for a different reason than first thought). Status doc rewritten to honestly scope the composition as "proof
of concept for the T↔response-path join only." **Sent back for a bounded investigation on M's real necessity**
before deciding retire-vs-interface (not decided unilaterally) — in parallel, fixing N's `bypass_egress` can
proceed regardless of that decision.

**Three streams relaunched** per the new plan: (1) resumed the Route B agent to first audit whether
`resp_deadline` is actually fully redundant (a cheap check that might shrink/eliminate the stage-6 conflict
before attempting the bigger generation-tagging RESET redesign); (2) resumed the N-handoff agent to fix the
three commit-blockers code-reviewer found (stale generated artifacts, the non-canonical-length-OPERATE-bypass
test gap, the retransmission-loss-tradeoff documentation); (3) dispatched a new builder agent to construct the
real B′-over-real-TCP-sockets workload runner (neither of `endpoint_gate/run.py`'s existing modes is this —
confirmed by the new document, this is a genuine prerequisite for the hardware campaign, not a parallel
nice-to-have).

**Pushed to `origin/main`** (2026-10-09 ~08:40, Philip's explicit instruction): `2c205fc15..f23150933`, carrying
the `[28,30]` split-candidate evaluation (`6630c9fcf`), Route B's register-placement fixes (`8fe093c91`), and
the fused response-path transport mapper (`f23150933`). N's OPERATE handoff + timing-anchor work is still
under review, not yet committed.

**What this means for next steps**: the fused response-path is real, verified, hardware-fit work that doesn't
need to wait on T's architecture decision. A reasonable next move once N-handoff lands: attempt loading
`case4_response_path.p4` alone on the physical switch (size/transport mechanism only, no timing holding yet)
to get the first real hardware contact of the night, independent of T's blocked status — worth raising to
Philip alongside the T decision rather than waiting for both to resolve together.

<!-- AUTO-HANDOFF (PreCompact/auto) 2026-10-09T01:42:33Z -->
### Compaction handoff — 2026-10-09T01:42:33Z
- Git: branch `main`, 277 uncommitted file(s): .drawio-tmp/ DNP3_Timing_Size_Integration_Prompt.md WORKING_NOTES.md bf_drivers.log defense4/Codex_Case4_Hardware_Architecture_Prompt.md defense4/timing/audit_current/MEETING_20261005_DIRECTION.md defense4/timing/case4_architecture/integration/core/ordinary/transport_model_select.py defense4/timing/case4_architecture/integration/evidence/model_02/run10/bf_drivers.log defense4/timing/case4_architecture/integration/evidence/model_02/run10/model_20261006_223250.log defense4/timing/case4_architecture/integration/evidence/model_02/run10/zlog-cfg-cur defense4/timing/case4_architecture/integration/evidence/model_02/run2/ defense4/timing/case4_architecture/integration/evidence/model_02/run3/ 
- Last verification run recorded: 2026-10-09T00:48:33Z	git -c user.name="akekulip" -c user.email="akekulip@gmail.com" commit --author="akekulip <akekulip@gmail.com>" -m "$(cat
- RESUME: re-read the Task/Status/Next-action sections above; trust this file over recollection.

**SYN-ACK arming gap: root-caused with a real capture, fixed, and model-verified** (2026-10-09 ~23:55–00:20).
User corrected an earlier wrong conclusion ("no sudo on Vision") — `sudo -n -l` shows `decps` has
passwordless sudo for `tcpdump`/`python3`/`iptables`. Used `sudo tcpdump` on Vision's
`enp59s0f0np0` to capture the real SEL-751 relay's SYN-ACK: 44-byte TCP header (`tcp.offset==4w11`),
24 option bytes `02 04 05 b4 01 03 03 00 01 01 04 02 01 01 08 0a <TSval> <TSecr>` (MSS, NOP,
WScale(0), NOP, NOP, SACK-permitted, NOP, NOP, Timestamps) — a third shape the parser never handled
(it only recognized offset 4w5/no-options and 4w6/MSS-only), explaining why `hw_range_read_01`'s
real-relay `ScanRange(G10V2,0,22)` test (49-byte response, exactly the padding-eligible native
shape) never armed the mapper (all registers read zero at the time).

Fixed in `case4_response_path.p4`: new `mtail_h` header for the remaining 20 option bytes, a new
parser state `mss_long` for `tcp.offset==4w11`, and one new `shape_t` entry requiring an exact
match on `ws_kind/ws_len/sack_kind/sack_len/ts_kind/ts_len` (NOPs and TSval/TSecr wildcarded) before
classifying as `SH_SYNACK_OK` — narrowly scoped to this relay's exact shape, not "any unknown
options are safe," per the execution document's own instruction. Confirmed by tracing the `apply`
block: every `SH_SYNACK_OK` action is an `_arm` action; none sets `m.changed`/`m.pad`, so the
deparser's checksum recompute is skipped entirely and the packet leaves byte-identical — this is why
`mtail_h`'s fields didn't need adding to the `tcp_new.update(...)` checksum list.

**Verified, not just compiled**: bf-p4c 9.13.1 recompile — 0 errors, same 6 pre-existing warnings,
PHV allocation successful, 12 total MAU stages unchanged (matching the pre-edit baseline, critical
path 11) — no stage/PHV regression. Then ran the actual compiled binary on the local Tofino-1 model
(`protocol/evidence/syn_ack_arm_01/`, driver script in the session scratchpad) with three cases: (1)
the exact real captured bytes arm all six mapper registers to the expected seq+1 / seq+1-58
formulas AND the packet passes through byte-identical; (2) the pre-existing MSS-only shape still
arms identically — no regression; (3) a 44-byte-header SYN-ACK with garbage after the MSS does NOT
match the new entry — falls through to the table's pre-existing `SH_SYN` entry (SYN-bit-only match,
already there before this diff) which safely de-arms via the already-existing `do_mode_arm_nat()`.
All 3/3 PASS. Dispatched `code-reviewer` on the full diff before any hardware redeployment (agent
`aa5e61fece2a40604`, in progress) — standing discipline for a non-trivial P4 change, even though
model-verified.

**Not yet done**: redeploy this binary to the physical switch and repeat the real
`ScanRange(G10V2,0,22)` hardware test against the SEL-751 to confirm the mapper actually arms on
real hardware (not just the model) — blocked on the code-reviewer result above, then needs its own
explicit go-ahead before touching the live switch per standing hardware discipline. The
`hw_range_read_01` evidence directory (49-byte response finding, all-zero register readback,
TCP_INFO diagnostic) is still not populated with files — do that alongside the hardware retest, not
before, so it captures the real before/after. No follow-up sent yet to the Route B agent
(`a61f1fb3640511b07`) correcting the earlier "no raw-capture capability" claim — its own completion
report independently converged on "adding an arming row for that exact option set is the sensible
fix," confirming this work and its own N/M/PHV work don't overlap.

**SYN-ACK arming diff BLOCKED and REVERTED by code-reviewer** (2026-10-09 ~00:25, agent `aa5e61fece2a40604`).
Critical finding, caught before any hardware contact: arming the mapper (`mode=1`) for this connection
is actively dangerous, not just incomplete. RFC 7323 §3.2 requires a TCP peer to carry the Timestamps
option in every later segment once the handshake negotiated it (the master's SYN offered it, the
relay's SYN-ACK echoed it) — so every subsequent segment on this connection has a 32-byte TCP header
(`tcp.offset==4w8`), a shape the parser still doesn't handle (falls to `tcp_odd` -> `SH_ODD`). On an
armed (`mode=1`) connection, `settle_t`'s `(_, SH_ODD, 1):drop_odd()` entry then drops every one of
those segments — the connection dies right after the handshake, in both directions, including the
master's own third handshake ACK. This also silently reversed a documented rule
(`TRANSPORT_MAPPER_SPEC.md` §8: any SYN-ACK with window-scaling/SACK/timestamps must set
`mode = native`), which explains why the pre-fix mapper correctly fell through to `SH_SYN` ->
`do_mode_arm_nat()` and passed everything through natively (why `hw_first_traffic_01` worked and
every register read zero). The three model tests I ran only exercised the SYN-ACK itself, so none
could have caught a bug that only manifests on the NEXT packet — a real gap in that test's coverage,
not just bad luck. Reverted immediately: `git checkout -- .../protocol/case4_response_path.p4`,
confirmed clean against `f2315093397f8014768c176d2fcbc5d114014731` (zero `mtail` occurrences,
`git status` clean). Nothing of this fix survives in the tree.

Two ways forward, per the code-reviewer and independently confirmed already present in the execution
document's own Phase 1 step 5: (1) **recommended, already pre-authorized by the plan** — a controlled
Linux network-namespace profile on the TEST side (Vision), not a global host change, with TCP
timestamps/SACK/window-scaling disabled only inside that namespace; a peer can only echo options its
SYN offered, so the relay's SYN-ACK should then shrink back to the already-supported MSS-only shape
(`tcp.offset==4w6`), needing zero P4 changes. Report this as a "supported profile" result, distinct
from the real default-stack shape. (2) a genuine design extension to the mapper for timestamps/SACK/
window-scaling translation (window field is scaled units not bytes, SACK blocks carry outstation
sequence numbers needing translation, timestamp bytes would need to enter the incremental checksum) —
explicitly out of scope for tonight unless Philip asks for it.

**Route B's parallel finding, redirected** (same notification round): N's decoy registers and the
request-side +20/+55 sequence arithmetic are NOT dead code under B′ as hoped — removing them naively
would let pipe 0 compile but N would never correctly admit an OPERATE, since its SELECT/OPERATE
association is built entirely on the retired request-insertion design. Route B proposed inventing a
new padded-coordinate-aware scheme; redirected it instead to the execution document's own
already-specified `N_ACK_RETURN` architecture (an internal loopback that normalizes every master ACK
back to NATIVE coordinates via one reverse-mapper pass before N's ingress ever parses it) — this makes
N's SELECT/OPERATE arithmetic stay fully native throughout (ack at seq+35, OPERATE ack at the native
938 not the padded 959, matching the document's own test vector), which is what finally makes the
decoy state and the old insertion arithmetic genuinely, safely removable. Full reasoning and the
5-step next-action list sent to the agent; it's now building the N_ACK_RETURN loopback instead.

RESUME: build the Phase-1-step-5 network namespace on Vision (TCP timestamps/SACK/window-scaling
disabled inside it only, nothing global) and retest the real `ScanRange(G10V2,0,22)` request against
the SEL-751 through it — if the relay's SYN-ACK now comes back MSS-only, the existing (unmodified)
`case4_response_path.p4` should arm correctly with zero P4 changes, giving the first genuine
real-hardware padding-mechanism demonstration of the project. Populate `hw_range_read_01` with
whatever this produces (shrunk SYN-ACK capture, register readback, pass/fail). Continue monitoring
the Route B agent's N_ACK_RETURN build in parallel (unrelated files, no conflict).

**Rate-limit interruption, then a major Route B milestone** (2026-10-10 ~00:30–02:15). A session rate
limit killed the Route B agent mid-task (it had just started `make_e.py`); resumed cleanly after reset
with no lost context. It then completed the `N_ACK_RETURN` architecture I redirected it toward:

**Pipe 0 now compiles with REAL N (not a stand-in) in ingress + the unmodified `case4_response_path.p4`
in egress, on both SDKs (9.13.1 local, 9.13.2 switch), matching exactly**: p0 = 12 ingress / 11 egress
stages, critical path 11; p1 (M retired, drop-only stub) = 1/0; p2 (T, untouched) = 11/0, critical path
9. PHV is tight but fits with zero margin: 32-bit containers 64/64, 16-bit 72/96, 8-bit 60/64, no spare
ingress stage — any future pipe-0 metadata addition will likely need its own reduction pass.

What changed: `connection/binding/generate.py` gained a `profile='response_only'` parameter producing
N's SELECT/OPERATE arithmetic in pure native coordinates (SELECT end seq+35, not the legacy seq+55;
OPERATE server_start = ack-37) — fixed at the generator per the standing rule, not hand-patched P4;
default-profile output claimed byte-identical to the committed `native_binding.p4` (sha256-checked by
the agent, not yet independently re-verified). New `integration/core/response_only/` holds `make_n.py`/
`make_e.py`/`compose.py` and the derived `n_response_only.p4`/`e_response_only.p4`. The N_ACK_RETURN
loop: the `ports` table's ACK-bearing-master-port row sends the packet to port 70 with egress enabled
and none of N's state tables run on that pass; port 70's own ingress row is a plain `route` so it
cannot loop; trust is by arrival port only, never a packet field (per the document's explicit security
requirement). A new 11-test suite (`tests/test_response_only_binding.py`) reproduces the document's
own exact SELECT/OPERATE test vector (101→136, 901→938, 136→171 with ACK 938 not the legacy 959,
938→975) and rejects the legacy padded offsets and bad CRCs; existing suites (195 + 85 tests)
still pass. A real stage-placement problem (13 ingress stages, not a dependency-depth issue — Tofino-1
ingress/egress share each stage's 16 table slots/crossbar/hash units, and E's 9 CRC/profile tables
pushed N's tables out) was fixed by consolidating N's 5 duplicate CRC tables into one `crc_t` keyed on
packet kind.

**Explicitly NOT done yet, don't overclaim**: no model run of the actual compiled composite binary yet
(all 11 new tests are source-level interpreter only); the reverse mapper's handling of port-70-arriving
packets is "assumed from the existing code, not observed"; **port 70 for N_ACK_RETURN is UNCONFIRMED
against the live switch's real port inventory** and must not be used on hardware until checked. Nothing
committed. Dispatched `qa-verifier` (independently rerun the tests, recompile, confirm the sha256
byte-identical default-profile claim, confirm evidence directories exist) and `code-reviewer`
(port-provenance security property traced against actual table entries, no-loop claim verified against
real entries, CRC-consolidation coverage completeness, default-profile code-sharing risk) in parallel —
both running now, before anything here is treated as settled or committed.

**code-reviewer verdict on N_ACK_RETURN: 3 blocking bugs, 2 should-fix warnings** (2026-10-10 ~02:50,
agent `a60e5c3ca69b77f08`). Sequence arithmetic, CRC consolidation, default-profile isolation, and the
immediate no-loop property all checked out clean — but do NOT proceed to a model run until these are
fixed: **C1** the response profile silently dropped the legacy requirement that a SELECT response show
CROB status 0 before advancing N's state (generate.py:457-460 / n_response_only.p4:127-128) — a REFUSED
SELECT now still lets N admit a following OPERATE. **C2** the N_ACK_RETURN normalize row only fires for
the small set of IP lengths N's parser already recognizes (make_n.py:63 keys on `hdr.tcp.isValid()`,
which only extracts for lengths 40/44/75/77/60/89/41) — any other master TCP segment skips
normalization, reaches the outstation with a padded-coordinate ACK, and stalls the connection; this
directly contradicts make_n.py's own stated invariant. **C3** the port-70 pass trusts port but not
direction — a packet arriving on the MASTER link carrying the OUTSTATION's 4-tuple gets normalized,
then E's `conn` (keyed only on the 4-tuple, not port) treats it as a forward packet, corrupting mapper
state and double-forward-mapping on the return lap — a real hole against the document's own
port-provenance security requirement. **W1** ternary priority isn't modeled correctly (interpreter uses
first-installed-wins, not real TCAM priority; no control-plane installer exists yet for these rows at
all) — a real-hardware priority ordering bug could silently skip normalization for every packet with no
error. **W2** the "cannot loop" claim holds only by control-plane row discipline, not by the P4 itself;
no in-P4 guard against a port-70-input row re-entering `normalize_ack`. Full findings with exact
fixes sent back to the Route B agent; it's addressing C1-C3 and W1-W2 before any model run.

**qa-verifier independently reproduced every claim from scratch** (2026-10-10 ~03:10, agent
`a2db79a23eec41afd`) — not by trusting stored evidence: reran all three test suites (11/195/85, exact
match, zero skips/xfails), recomputed the default-profile sha256 directly (match:
`66e0be76...`), regenerated `n_response_only.p4`/`e_response_only.p4` from the generators and
confirmed byte-identical to the checked-in copies, and recompiled the regenerated source through the
repo's own `build.py` wrapper on a fresh scratch directory — independently reproduced the exact same
stage/PHV numbers (p0 12/11 cp11, p1 1/0, p2 11/0 cp9, PHV 64/64 32b, 72/96 16b, 60/64 8b) and
confirmed `response_only_03`/`_04`'s stored 13-stage compiler failure and `_05`'s fix verbatim. One
flagged item turned out to be a false alarm relative to Route B's actual diff: `dnp3_read_client.py`
is modified or (31 insertions/3 deletions) but this is MY OWN earlier `build_range_read()`/`--range`
CLI addition from Phase 1 tonight (confirmed via `git diff --stat`, matches the known scale of that
edit) — not part of Route B's N_ACK_RETURN work and not scope creep; qa-verifier correctly flagged an
unexplained diff since it only had Route B's self-report as context. This file's change remains
pending commit alongside `hw_range_read_01`'s evidence once the hardware retest happens, per the
Phase 1 thread above. Net result: Route B's functional claims are now fully, independently confirmed;
the C1-C3/W1-W2 design fixes from code-reviewer remain the only blocker before a model run.

**Route B fixed all 5 findings** (2026-10-10 ~03:45, `response_only_06`, 22 tests now, up from 11).
C1: response profile again requires `hdr.rtail.status==0`. C2: the normalize row now matches every
IPv4 TCP packet from the master port rather than only the lengths N's own parser recognized. C3: both
E's `conn` (keyed on `eg.egress_port`, forward only at port 9, reverse only at port 70) and N's own
connection table (keyed on ingress port) now bind direction to the real arrival/departure port — and
while fixing this, the agent found N's own recirculation passes arrive on port 68 and ALSO need
direction binding, growing that table from 2 to 4 entries (flagged as new surface worth a fresh look,
not assumed safe). W1: new `core/response_only/cp.py` gives every ternary row an explicit
`$MATCH_PRIORITY`; interpreter now ranks by priority and rejects an unprioritized ternary row. W2: the
P4 itself now drops any port-70-arriving packet that doesn't take a route row (reused an existing
gateway, no new table). W3/W4 documented in the status file rather than fixed. Pipe 0 unchanged at
12/11 stages, cp 11, on both SDKs; PHV essentially unchanged (32-bit still maxed 64/64 zero margin).
Model run explicitly NOT started, per instruction to wait for confirmation. Dispatched a second,
TARGETED code-reviewer pass (agent `a043c33164c7aa42f`) to verify each of the 5 fixes against current
source directly — not accept the self-report — especially the new port-68 table, before authorizing
the model run.

**Targeted follow-up review: all 5 fixes genuinely hold, but W2 left two residual loop paths**
(2026-10-10 ~04:20, agent `a043c33164c7aa42f`). C1/C2/C3/W1 all PASS, confirmed by independently
reverting each fix in a scratch copy and verifying exactly its named mutation test fails (status key,
`ip`->`tcp` validity swap, reverse-direction-on-70 grant, priority raised to 200), nothing else breaks.
C3's direction-by-port fix genuinely defeats the original spoofing attack (traced both the original
attack and its mirror against the current tables — both now get no direction and reach nothing). The
new port-68 table (needed because N's own recirculation passes also need direction re-checked) holds
as a *deployment* invariant, not a structural one — nothing in the composed program injects on port 68
today (T only emits to 9/64/pipe-2 ports, pipe 1 drops everything), but a future pipe-0 packet-generator
app, a mirror session, or T's `keep_blocking(port)` pointed at 68/70 could violate it; flagged for
G-PORTS. **W2 is real but narrower than claimed**: the guard only denies a port-70 packet that never
set `port_valid`; if a control-plane mistake ever installs `ports (70,*,*) -> route(70)`, `port_valid`
DOES get set, the guard doesn't fire, and with `bypass_egress` now 0 the packet crosses E and re-enters
on 70 indefinitely — confirmed by the reviewer actually installing that row and watching it loop. A
second, far-lower-probability path: a generation-0 envelope (only possible if N's 32-bit `allocate`
counter saturates) arriving on port 68 skips the main block and loops there too. Reviewer's verdict:
"safe to proceed to the model run" with three conditions — (1) build a real rule installer for `cp.py`'s
rows (nothing installs them via BFRT yet, only the interpreter-level tests), (2) close the two residual
loop paths (prefer a structural P4 fix: deny when arriving on `N_ACK_RETURN` and the route target is
70, extendable to also cover the stage-0/generation-0 case on 68), (3) add the pktgen/mirror/
`keep_blocking` port-68/70 exclusion to G-PORTS. Sent back to Route B to close item 2 before the model
run; items 1 and 3 folded into the model-run step itself / a documentation note.

**►► MAJOR MILESTONE: full composite (real N + T + E) passes 29/29 on the local Tofino-1 model**
(2026-10-10 ~05:40, `response_only_10`, two rate-limit interruptions survived cleanly in between).
Both residual loop paths closed with ONE unified guard at the head of N's chain (before `connection`
can rewrite the egress port): drops anything arriving on port 68/70 whose `ports` row targets 70, AND
an envelope on 68 that parses with `m.stage==0` (generation-0 case) — subsumes and replaces the
earlier narrower W2 clause. New tests for both sub-cases; mutation-confirmed (removing either half
fails its test).

**A genuine, hardware-relevant bug found only by running the real model, missed by every prior source
review**: pipe 0's 32-bit PHV containers are completely full (64/64), and under that pressure bf-p4c
9.13 silently ignored E's `@pa_no_overlay`/`@pa_solitary` pins, placing live metadata (`m.ina`, the
arriving ACK) into a container belonging to an absent padding header — Tofino's deparser sums a listed
container into the checksum regardless of whether its header is actually present. Every reverse-mapped
ACK left with its TCP checksum short by exactly the ACK value, so real N rejected the SELECT on
checksum and nothing after the handshake worked. Neither more pins nor late-zeroing fixed it (the
latter cost a 13th stage). Fixed by splitting the TCP checksum update into three mutually exclusive
cases (no padding / READ padding / control padding), each summing only the padding fields actually
present for that case — zero stage/PHV cost, confirmed on both SDKs.

**Model results, functional only** (not hardware, not timing): every frame matched the software
mapper/padder oracles byte for byte across the full SELECT->response->OPERATE(ack 959->mapped
938)->response sequence, with T observed actually holding and releasing OPERATE once
(`OUT_OP_RELEASE` +1). **Forged-packet attack traced in the model's own log**: a response carrying the
outstation's 4-tuple injected on the master port hits `normalize_ack`->port 70, misses E's `conn`
(no mapper action), recirculates, misses N's `connection` and `guard` (no direction, no work), and
exits unchanged on the OUTSTATION port — never reaches the master, E's six registers and N's owner/
epoch all unchanged. "Teeth" confirmed: the same composite without E's `egress_port` binding fails
exactly these 2 of 29 checks, the other 27 still pass.

Tests: 26 response-only (up from 22), 195+85+10 regression suites, all green; legacy generator output
still byte-identical to committed `native_binding.p4`.

**Explicitly NOT ready to commit — the agent itself said so and asked for one more review**: two
unreviewed changes (the checksum-split fix, the unified loop guard) plus an evidence-directory cleanup
concern (`response_only_03/_04/_08/_09` hold large failed/probe build outputs; `__pycache__` dirs need
excluding). Dispatched a FINAL adversarial code-review pass (agent `a221303d9ee2201b9`) specifically on
the checksum-split correctness (mutual exclusivity, completeness, no-padding-case cleanliness, same-bug
recurrence elsewhere, no regression on other packet classes) and the unified loop guard (actual boolean
condition traced, positioned early enough that nothing downstream un-does the deny, does NOT
false-positive on legitimate normalize_ack/recirculation traffic, actively hunted for a third
uncovered loop path) before any commit decision. This is the last gate.

**Still open, unrelated to the above**: the SYN-ACK timestamps/SACK/wscale fix for the real SEL-751
relay (my own diff was reverted after code-reviewer found it would kill every connection right after
the handshake — see above). Asked Philip to choose between a netns+macvlan approach, extending the
mapper, or pausing that thread; not yet answered (one attempt at the question came back with a garbled/
corrupted answer, re-asked in plain text). No action taken on Vision's networking either way.

**New execution document: `DNP3_Resume_to_Hardware_Completion_Prompt.md`** (2026-10-10, supersedes
`DNP3_Next_Phase_Claude_Execution_Prompt.md`). Explicitly selects the test namespace/macvlan path
for the SYN-ACK problem (resolving the open question above). Philip's plan-mode follow-up (after
rejecting a first draft that scoped this session to a smaller checkpoint) restructured execution into
**three concurrent workstreams**, not sequential phases: A) close the interrupted review + commit the
baseline; B) hardware — port inventory, netns/macvlan, active-padding demo, then load the N+T+E
composite; C) the four CRC/dependency efficiency edits on a separate scratch copy, starting immediately.
Deliverable is the complete mechanism on hardware + correctness + efficiency + four-arm eval, not a
partial checkpoint — continue directly into queue tuning/loss recovery/four-arm once hardware works.
Full plan: `~/.claude/plans/make-a-plan-first-logical-abelson.md`.

**Workstream B1 (port inventory) — DONE, resolved cleanly, real hardware, read-only BFRT query**
(2026-10-10 ~ plan execution start). Queried the live switch's (`decps@10.10.54.81`, `ufispace`,
`case4_response_path` still loaded, pid 55925 unchanged) `$PORT` table directly for dev_ports 64-71 and
9: **ports 68, 69, 70, 71 each exist as separate, independently-enabled entries with `port_name=recirc`**
(distinct from the "X/Y" front-panel-lane notation every other real port uses, e.g. dev_port 9 is
`15/1`, dev_port 64 is `33/0`) — and none of 68-71 appear anywhere in the `$PORT_STR_INFO` front-panel/
lane mapping table at all. This definitively resolves the W4 concern from tonight's review: on this
specific chip, ports 68 (N's own recirculation) and 70 (`N_ACK_RETURN`) are genuinely separate, dedicated
internal recirculation ports, not lanes of one shared interface — no reconfiguration needed, no conflict.
Feed this into Workstream A's review of the loop guard (its port-based reasoning is now confirmed sound).

<!-- AUTO-HANDOFF (PreCompact/auto) 2026-10-09T23:51:05Z -->
### Compaction handoff — 2026-10-09T23:51:05Z
- Git: branch `main`, 284 uncommitted file(s): defense4/timing/case4_architecture/integration/read/TIMING_QUEUE_MIGRATION_STATUS.md defense4/timing/framework/size/dnp3_read_client.py .drawio-tmp/ DNP3_Next_Phase_Claude_Execution_Prompt.md WORKING_NOTES.md bf_drivers.log defense4/Codex_Case4_Hardware_Architecture_Prompt.md defense4/timing/audit_current/MEETING_20261005_DIRECTION.md defense4/timing/case4_architecture/FOUR_ARM_DESIGN_REVIEW.md defense4/timing/case4_architecture/integration/core/ordinary/transport_model_select.py defense4/timing/case4_architecture/integration/evidence/model_02/run10/bf_drivers.log defense4/timing/case4_architecture/integration/evidence/model_02/run10/model_20261006_223250.log 
- Last verification run recorded: 2026-10-09T23:46:22Z	cd /home/philip/Projects/DNP3/defense4/timing/case4_architecture/integration/read && python3 - <<'EOF' from pathlib impo
- RESUME: re-read the Task/Status/Next-action sections above; trust this file over recollection.

**Workstream B2 — netns+macvlan built on Vision, LIVE RIGHT NOW (literal teardown runbook)**. Three
workstreams now running concurrently per the approved plan: A (review, agent `a92ace84de50fbd5e`), B
(this, hardware, main session), C (efficiency edits on scratch copy, agent `a25717f055a872926`).

NIC identification confirmed first, unambiguously, via two independent live checks on Vision
(`decps@10.10.54.19`): the current SSH session rides `eno1` (10.10.54.19/24, management,
`10.10.54.0/24 dev eno1`), completely distinct from `enp59s0f0np0` (`10.0.1.1/24` + `192.168.10.1/24`,
the real test-facing NIC reaching the switch/relay). No overlap, safe.

Kernel tunable-scoping go/no-go gate run BEFORE building anything real: a throwaway namespace had all
three of `tcp_timestamps`/`tcp_sack`/`tcp_window_scaling` set to 0 inside it, read back as 0 inside it,
and the DEFAULT namespace's values (1/1/1) were confirmed UNCHANGED both before and after, on this host's
actual kernel (5.15.0-139-generic). Genuinely per-namespace on this kernel — gate PASSED, no global leak,
proceeded.

**Live state right now** (exact teardown commands, run as `sudo python3` on Vision so they inherit root
without needing separate sudo for each sub-command):
- Namespace: `dnp3_padtest`
- macvlan: `mvtest0`, parent `enp59s0f0np0`, mode `bridge`, moved into the namespace
- IP inside namespace: `192.168.10.50/24` on `mvtest0` (confirmed unused beforehand: no ping response,
  no prior ARP entry on this subnet via `enp59s0f0np0`)
- Sysctls set inside `dnp3_padtest` only: `net.ipv4.tcp_timestamps=0`, `net.ipv4.tcp_sack=0`,
  `net.ipv4.tcp_window_scaling=0` — default namespace baseline was `1/1/1`, confirmed still `1/1/1`
  after creation.
- **Teardown** (in this order): `ip link del mvtest0` (deletes the macvlan; harmless if already gone
  since it's namespace-scoped) -> `ip netns del dnp3_padtest` (removes the namespace and all its
  namespace-scoped sysctl state automatically) -> remove the switch-side slot-1 table rows (see below)
  if they were added.
- Nothing on Vision's management NICs (eno1/eno2), existing routes, or `enp59s0f0np0`'s own
  `10.0.1.1/24`+`192.168.10.1/24` addresses was touched.

**Switch-side slot 1 (planned next, not yet done as of this note)**: read back current `Egress.conn`/
`Egress.odd_ip_t`/`Ingress.forwarding` on the live switch (still `case4_response_path`, pid 55925
unchanged) first — confirmed slot 0 uses host pair (192.168.10.1, 192.168.10.7) with dev_ports 9/64
already forwarding correctly in both directions. My new slot 1 will use host pair (192.168.10.50,
192.168.10.7) — distinct keys, no conflict with slot 0's `Egress.conn`/`odd_ip_t` rows. Deliberately
**NOT** reusing `response_path_cp.py`'s `Registry.install()` wrapper for this, since a fresh `Registry()`
object has no memory of slot 0's already-installed `Ingress.forwarding` rows (ports 9/64 already route
correctly and apply to ANY traffic on those physical ports regardless of IP) — calling the full
`install()` would try to re-add those and conflict. Instead: call `_conn_rows(1, outstation, master,
pad_enable=True)` directly (the private helper that returns only the 4 `Egress.conn`/`odd_ip_t` rows,
no forwarding rows) and add just those via BFRT.

**Workstream B2 result: the netns/macvlan TCP-profile technique WORKS exactly as designed — real
blocker is now the relay's application-layer access control, not the TCP/transport layer.** Real
tcpdump capture from inside `dnp3_padtest` against the real SEL-751 (`192.168.10.50:54322 <->
192.168.10.7:20000`, switch slot 1 installed and working — TCP handshake completed cleanly through the
real ASIC): **the SYN now offers only `[mss 1460]`** (no timestamps/SACK/wscale, confirming the
namespace's disabled sysctls actually changed the outgoing SYN) **and the relay's SYN-ACK correspondingly
echoes back only `[mss 1460]`** — the simplest, already-supported shape, needing zero further P4 changes.
The relay then ACKs the valid, CRC-correct DNP3 request (20 bytes, matches the known-good
`ScanRange(G10V2,0,22)` vector byte-for-byte) and 4.7ms later sends a bare RST — an application-layer
rejection, not a protocol/CRC/option problem. (Own bug along the way: first attempt used a hand-rolled
CRC with the wrong polynomial, 0x3D65 instead of the real 0xA6BC from `rrc.dnp3_crc`; fixed and
confirmed byte-identical to the known-good vector before concluding anything from the result.)

**Interpretation**: the SEL-751 almost certainly enforces an allowed-master-IP list that includes only
192.168.10.1 (Vision's real, native address) — a new source IP (192.168.10.50) gets its TCP handled
fine but is rejected at the DNP3/session layer. Checked for a ready-made fallback: the document's own
"production software outstation through an observed physical switch path" does NOT already exist in
this repo — `dnp3_sim_outstation.py` is explicitly a loopback-only test fixture with "no SELECT/OPERATE
handling at all," and `endpoint_gate/run.py` is an in-process semantic gate with "No sockets, switch
connection, relay connection or physical output" — neither can stand in for a real switch-crossing
software outstation. Building one would be substantial new infrastructure, not a quick fallback.

**This is a genuine blocker needing Philip's input, not something to route around unilaterally**:
either (a) get the SEL-751's allowed-master-IP list reconfigured to include 192.168.10.50 — a real
physical-relay configuration change, more invasive than what's pre-authorized tonight, or (b) stand up
a real production OpenDNP3-based software outstation on a host reachable via the switch's physical
ports — real new work, not yet scoped. Reported to Philip with both options; not deciding unilaterally.
**Netns/macvlan setup left live and untouched** (not torn down) since either path forward can reuse it
immediately — teardown commands are already recorded above if needed.

Other two workstreams continue in parallel: A was resumed with the review's findings (two gaps to close:
a third loop path through `connection`'s own direction-granting rewrite, and an untested READ-padding
checksum case) plus the composition-acceptance checklist, before commit. C (efficiency edits,
agent `a25717f055a872926`) still running independently on its own scratch copy.

**Philip's correction: `SocketGatePad58B.cpp` already exists** (`defense4/timing/framework/size/endpoint_gate/`) —
a real OpenDNP3 TCP outstation/master pair, 23 Binary Output Status points (index 0-22, matching the
`ScanRange(G10V2,0,22)` eligibility the mapper expects), real SELECT/OPERATE via `DecoyGateCommandHandler`,
outstation accepts `host port` as bind args. Currently only exercised over loopback with
`pad58b_proxy.py` as an application proxy (explicitly NOT what the document means by "traverse the
ASIC"). Also corrected: my single-sided namespace capture doesn't prove an allowed-master-IP
restriction — a reset can have several causes, and a one-sided capture can't show what the relay's own
stack actually did with the packet after switch processing. Ran the requested controlled test before
concluding anything further.

**Controlled test result: the reset is reproducible independent of TCP options profile, and switch-side
registers confirm the switch itself behaved correctly in both cases.** Same IP (192.168.10.50), same
port (54322, matching the installed slot-1 switch entry), same CRC-valid DNP3 request, two single-variable
runs:
- Run 1 (namespace's disabled timestamps/SACK/wscale): SYN offers only `[mss 1460]`; relay's SYN-ACK
  echoes only `[mss 1460]` (the simplest, already-supported shape); relay ACKs the 20-byte request, then
  RSTs 4.7ms later.
- Run 2 (same IP/port, sysctls restored to default 1/1/1 first): SYN now offers the full
  `[mss,sackOK,TS,wscale]` set (matching the real relay's normal negotiated profile exactly); relay's
  SYN-ACK echoes the full set back; relay ACKs the same request, then RSTs 4.8ms later — essentially
  identical timing and behavior.

This rules out the TCP-options profile as the cause (reset happens either way). Switch-side register
readback after run 2 shows `Egress.front`/`Egress.acct.lo` at slot 1 still holding the value armed
during run 1's successful MSS-only classification (`3109934518` = run 1's SYN-ACK seq+1, confirming the
mapper DID correctly classify and arm on the already-supported shape), while `Egress.mode` correctly
reads 0 for run 2 (its full-option SYN-ACK doesn't match a recognized arm shape, so it correctly fell
back through the existing `SH_SYN`/`do_mode_arm_nat()` native path) — the switch behaved exactly as
designed in both cases, which rules out switch-side corruption as the cause of the reset. **This does
not conclusively prove an IP-allowlist restriction** (no direct visibility into the relay's own
application-layer decision) but it does rule out two of the three most plausible alternate causes
(TCP option negotiation, switch-side mangling), leaving the new source IP and/or the relay's own
connection-identity logic as the remaining most likely explanation — stated as the strongest
available inference, not a proven fact.

**Topology question for deploying `SocketGatePad58B.cpp` as a real ASIC-crossing endpoint, not yet
resolved**: checked `SWITCH_LAYOUT.md` for an already-wired alternate host on the relay-side
192.168.10.0/24 segment — found none. The only hosts on that segment are Vision (dev_port 9) and the
real SEL-751 (dev_port 64); a second Tofino switch (10.10.54.141, Netberg Aurora) is QSFP-cabled to the
primary switch but is not a compute host and has no SDE running. Putting the outstation binary on a
macvlan SIBLING of the master's macvlan (same parent NIC, same dev_port 9) risks traffic never actually
leaving the physical NIC at all (kernel macvlan bridge-mode can deliver directly between sibling
macvlans without an external round-trip), which would silently fail the document's own requirement that
traffic "must traverse the ASIC, not an application proxy." Making it genuinely cross the ASIC the way
the real relay traffic does would need either a host on the far side of a different switch port, or
some substitution at the relay's own port — the latter being a real physical-cabling action, not
something to do unilaterally. Reported to Philip as an open question alongside the controlled-test
result; not yet acted on further. Namespace/macvlan from the earlier test left live and untouched
(TCP options currently at namespace default 1/1/1, the controlled test's final state).

<!-- AUTO-HANDOFF (PreCompact/auto) 2026-10-10T04:37:01Z -->
### Compaction handoff — 2026-10-10T04:37:01Z
- Git: branch `main`, 289 uncommitted file(s): defense4/timing/case4_architecture/integration/connection/binding/generate.py defense4/timing/case4_architecture/integration/read/TIMING_QUEUE_MIGRATION_STATUS.md defense4/timing/framework/size/dnp3_read_client.py .drawio-tmp/ DNP3_Next_Phase_Claude_Execution_Prompt.md WORKING_NOTES.md bf_drivers.log defense4/Codex_Case4_Hardware_Architecture_Prompt.md defense4/timing/audit_current/MEETING_20261005_DIRECTION.md defense4/timing/case4_architecture/FOUR_ARM_DESIGN_REVIEW.md defense4/timing/case4_architecture/integration/core/ordinary/transport_model_select.py defense4/timing/case4_architecture/integration/core/response_only/ 
- Last verification run recorded: 2026-10-10T04:36:26Z	cd /home/philip/Projects/DNP3/defense4/timing/case4_architecture/integration && sed -n 91,130p core/harness/vectors.py; 
- RESUME: re-read the Task/Status/Next-action sections above; trust this file over recollection.

**►► MAJOR, NEWLY DISCOVERED HARDWARE FACT: this real Tofino-1 chip has only 2 physical pipes, not
4.** (2026-10-10, during the VEPA reflection-probe hardware attempt.) Model-only work all night
(PORTS_PROPOSAL.md, xpipe_probe.p4, and tonight's N+T+E composition with T placed in "pipe 2") ran
against "SDE 9.13.1 tofino-model, chip type TofinoB0, 4 pipes" — the MODEL's assumed chip type. The
real board rejected a genuinely 4-pipe program outright: `BF_DVM ERROR - Program
"xpipe_reflect_probe" Pipeline "p2" cannot be assigned to device 0 pipe 2, only 2 pipe(s)
available` (and the same for p3) — `bf_device_add failed`, 0 devices initialized, nothing loaded on
the chip at all until restored. **This means T's own placement in "pipe 2" throughout the entire
N+T+E composition — proven only on the 4-pipe model, never on real hardware — is at the same real
risk this probe just hit.** `case4_response_path.p4` itself was unaffected because it declares a
SINGLE `Pipeline()` instance broadcast via `pipe_scope` in the conf (works with however many real
pipes exist); the probe's `Switch(p0,p1,p2,p3) main` declares 4 DISTINCT compiled pipeline binaries,
each individually bound to a specific physical pipe index, which is what actually tripped the
limit. This needs checking against the actual composed N+T+E program's own pipe declaration
structure before that composite is ever attempted on real hardware — do not assume the model's
4-pipe result transfers.

**Recovery, fully completed before anything else**: stopped the failed probe daemon (0 devices, so
nothing was ever "live" to disrupt), restarted `case4_response_path` via the exact proven launch
script, confirmed `bf_switchd: initialized 1 devices`, restored ports via `restore_ports.py` against
the pre-change snapshot (`/tmp/pre_vepa_probe_snapshot.json`, 403 tables, taken before touching
anything) — dp9 and dp64 confirmed up. Connection-table entries (volatile control-plane state, not
part of the compiled program, reset by any cold restart as expected) were empty after restore;
reinstalled slot 0 exactly as it was (`Egress.conn`/`odd_ip_t`/`Ingress.forwarding`, 6 rows,
Vision↔SEL-751). Switch is now back to its exact pre-probe-attempt baseline, confirmed, not assumed.

**Fresh, saved evidence closing the earlier evidence gap** (per the plan's first required action):
re-sent the exact byte-for-byte known request from Vision's REAL native IP (192.168.10.1) against
the real relay, this time with a real tcpdump capture saved to
`protocol/evidence/hw_range_read_01/native_ip_retest_20261010.pcap` (plus `STATUS.md` write-up).
Result: a complete, clean, normal exchange — full handshake, 20-byte request, 49-byte response
~25ms later, then an orderly FIN/FIN/ACK close. No RST anywhere. This is now a FRESH, directly
observed, saved-artifact confirmation (not a recalled claim) that the exact same request from .1
behaves completely differently from .50, which gets reset right after the same data ACK (per the
two .50 runs documented earlier tonight). This elevates the IP-identity explanation from "inference
from memory" to "freshly confirmed controlled comparison with saved captures on both sides" — still
not 100% certain of the relay's exact internal mechanism (no visibility into the relay's own config
or logs), but now resting on real, reproducible, saved evidence rather than recollection.

**VEPA reflection logic itself: fully validated on the model before any hardware attempt, 5/5
checks.** Extended `xpipe_probe.p4` (copied to a new file, `integration/core/xpipe/
xpipe_reflect_probe.p4`, "NEVER DEPLOY" header preserved) with one new table, `fwd_mac`, keyed on
`(ig.ingress_port, hdr.eth.dst)`, checked before falling back to the original port-only `fwd` table
unchanged. Found and fixed a real P4 correctness bug during model testing, not assumed clean:
`fwd_mac`'s first draft used `deny()` as its default action, which sets `drop_ctl` as a side effect
even on a miss — the subsequent fallback to `fwd.apply()` never cleared that flag, so any port with
no fwd_mac entry at all had its packets silently dropped regardless of what the fallback table
decided. Fixed by using `NoAction()` as the default instead. After the fix: both reflection
directions (A→B and B→A arriving on the shared port correctly come back out the SAME port, byte-
identical), an unmatched MAC on that port is correctly denied rather than misrouted, and the
original port-only forwarding for an unrelated port is completely untouched. Compiles clean on both
the local SDE (9.13.1, 3 ingress stages used of 12, critical path 2) and the switch's own installed
SDE (9.13.2, exit code 0) — evidence in `integration/evidence/vepa_reflect_01/`.

**Next action**: fix the probe to target only pipe 0 (a single `Pipeline()` instance, matching
`case4_response_path.p4`'s own working structure, since this test only needs dev_port 9 anyway —
no need for 4 pipes at all), recompile on the switch's SDE, and retry the real-hardware load +
negative-control test. Static ARP entries between the two VEPA namespaces (`ns_vepa_a`/`ns_vepa_b`)
are already installed and still valid. The switch is currently back on the confirmed-good
`case4_response_path` baseline — re-verify this live state fresh immediately before the next load
attempt, do not assume it's still true from this note alone.

**►► VEPA REFLECTION PROBE, REAL HARDWARE RESULT: the P4 logic is proven correct on real silicon,
but the reflected frame never arrives back on the physical wire — a real, localized, time-boxed
blocker, not a logic bug.** (2026-10-10, same session, after fixing the probe to a single broadcast
pipeline for the real 2-pipe chip — see above.)

Sequence, each step independently confirmed:
1. Loaded the fixed single-pipe probe (`xpipe_reflect_probe_02`, pipe_scope `[0,1]`) — `bf_switchd:
   initialized 1 devices`, dp9 confirmed up.
2. Installed `fwd_mac` rows on the real switch for the two VEPA macvlans' real MACs (`mvA`
   `d2:9d:1d:1c:f4:dd`, `mvB` `ee:df:16:18:b0:a5`), both reflecting to dev_port 9.
3. Sent a real synthetic frame (Ethernet type `0x88b5`, src=mvA, dst=mvB) from inside `ns_vepa_a` on
   `mvA`, through the physical switch, intended to come back to `mvB`.
4. **A Python listener on `mvB` inside `ns_vepa_b` received nothing (timeout).**
5. Checked the switch's own `arr_ig`/`arr_eg` registers (not just application-level success) before
   and after a fresh, isolated send: `arr_ig[9]` incremented (frame genuinely arrived at ingress
   port 9) and **`arr_eg[9]` incremented by exactly 1, precisely correlated with the one frame sent**
   — direct, counter-level proof that the P4 pipeline matched the new `fwd_mac` table, ran
   `go_reflect`, and set `tm.ucast_egress_port=9`, and that the ASIC's own egress-processing counted
   it as transmitted on port 9.
6. **tcpdump directly on Vision's physical parent interface (`enp59s0f0np0`), filtered to the probe's
   own ethertype, captured only the ONE outgoing frame — no second, reflected frame ever arrived
   back on the wire**, despite the switch's own egress counter saying it sent one.

**Conclusion**: the P4 logic itself is correct and proven on real hardware (the counter increment is
unambiguous, direct evidence, not an inference) — this is not the same class of problem as the
earlier `deny()`-default bug, which was a genuine logic error. The gap is physical: something between
the ASIC's egress-processing decision and the bits actually appearing on the wire does not complete
for a same-port loopback send, specifically. Two explanations considered, neither confirmed further
given the time-box: (a) the egress counter increments at the P4/pipeline logical-processing stage,
before the physical MAC/PHY actually drives the wire, and something at that layer silently drops a
same-port reflected frame; (b) some port/PHY-level loop-prevention or duplex timing behavior specific
to transmitting back out a port that just received, not exposed to or controllable from the P4
program. No further low-level PHY diagnosis was attempted — out of scope for the P4-logic probe this
was built to run, and squarely a hardware/PHY question instead.

**Per the plan's own time-box instruction, this is the point to stop and name one specific,
concrete hardware change to request, rather than keep searching**: a second, separate physical
switch port for one of the two VEPA endpoints (e.g. move `mvB`'s parent interface to a different
NIC/cable reaching a different switch port), turning this from a same-port loopback into ordinary
inter-port forwarding — the kind of operation every switch ASIC, including this one (proven all
night via the real Vision↔relay traffic on ports 9/64), handles as a matter of course. This is
the one recommendation to bring to Philip; same-port reflection on this specific chip is not
established as working, and should not be relied on for the `SocketGatePad58B` production endpoint
placement without either that cabling change or further PHY-level investigation neither pursued nor
authorized tonight.

**Recovery, fully completed**: probe daemon stopped cleanly (confirmed no real `bf_switchd` process
remained, only the diagnostic script's own embedded text matched), `case4_response_path` restarted
via the exact proven launch script (`bf_switchd: initialized 1 devices` confirmed), ports restored
from a fresh pre-change snapshot (dp9/dp64 up), slot 0 reinstalled (6 rows, Vision↔SEL-751). Switch
is back to its exact known-good baseline, confirmed via command output, not assumed.

**Status of Workstream B overall**: the netns/macvlan TCP-profile technique (B2, against the real
relay) is proven and gated on the relay's own access behavior, now resting on fresh saved evidence
(see above). The VEPA same-port placement for the production endpoint (the new B-probe sub-thread)
is now concluded, time-boxed, with a concrete hardware ask rather than an open-ended search. Neither
sub-thread currently has a path to the `SocketGatePad58B` production demonstration without either
(a) the relay's access restriction being resolved, or (b) a second physical port for the VEPA
approach. Both are now named, evidence-backed blockers for Philip, not vague unknowns.

**Baseline committed: `2cb6ecf9d`** (Workstream A). Verified directly, not from the report: author and
committer both `akekulip <akekulip@gmail.com>`, zero trailers, not pushed (origin/main still
`fce869156`), 525 files. Contents: T close/reset fix (stage-1 close to relay, stage-2 to master,
stage-0 synthetic reset still dropped; three separate tests with teeth), READ-timing driver fix with
dedicated late-traffic coverage kept (deterministic source-level test plus a 2s-late model READ),
composite 70/70 on the model, suites 199/85/27/10 passing. Reconnect explicitly pending. A real
defect caught along the way: a table with 15 const entries declared `size = 14` compiled cleanly in
bf-p4c and only failed at model load — fixed to `size = 15`. Evidence trimmed per Philip's policy
(manifests, logs, table/pa summaries, index `evidence/route_ab_01/RESPONSE_ONLY_BUILDS.md`; raw
compiler trees kept locally, gitignored).

**►► The committed composite cannot load on the real chip as committed.** It declares
`Switch(p0, p1, p2)` with T bound to `pipe_scope [2]`. Independent confirmation of the 2-pipe chip
via a read-only `$PORT` query on the live switch: dev_ports 68-71 (pipe 0 recirc) and 196-199 (pipe 1
recirc) PRESENT and enabled; **324-327 (pipe 2 recirc) ABSENT**. Forced fix, since M is already
retired to a drop stub in p1: T moves into pipe 1, program becomes `Switch(p0, p1)`, T's ports
324->196, 325->197, 326->198, 327->199; FORWARD=9, RELAY=64, N_ACK_RETURN=70, RETURN_PORT=68
unchanged. The retired M's N_TO_M=196/T_TO_M=197 constants in `read/ports.p4` collide with T's new
numbers and must be removed. Sent to Workstream A as priority before the rearm work, as its own
commit. Workstream C told the baseline landed and to merge CRC edits 1+2 (make_e.py only — no
overlap with the relocation's files).

**Efficiency committed: `17161e70b`** (Workstream C, CRC edits 1+2 on E). Verified directly: lead
identity author+committer, no trailer lines, every file within make_e.py / e_response_only.p4 /
efficiency_01/ / RESPONSE_ONLY_BUILDS.md / response_only_19 evidence, no EgDeparser or three-case
checksum lines touched, not pushed. Measured on both SDKs (identical): stages unchanged 12/11, cp 11;
PHV 196 -> 193 (8b 59->55, 16b 73->74, 32b 64->64); E tables 35 -> 31; hash units 27 -> 26. Model
70/70, emitted bytes identical to the baseline run on all 20 frame-capturing cases; verify_wire.py
recomputed IPv4/TCP/DNP3 checksums from emitted bytes for all three cases (3 READ-padded, 3
CONTROL-padded, 6 rewritten) — all valid, and it flags the earlier wrong-constant build. Suites pass
in a clean worktree at 2cb6ecf9d + this change; the shared tree's 9 read / 1 binding failures belong
to Workstream A's uncommitted pipe-1 relocation edits, not this commit. Edit 3 stays deferred.
Note: like 2cb6ecf9d, this still carries the 3-pipe composite; the pipe-1 relocation commit fixes both.

**Relocation committed: `979b38fd1`** (T -> pipe 1, `Switch(p0, p1)`, ports 196-199, retired M
constants removed, READ_HANDOFF_PORT=197 set at the generator). Verified: lead identity, no trailers,
not pushed. Exit 0 on both SDKs (p0 12/11, p1 11/0), model 70/70 (model simulates 4 pipes —
necessary, not sufficient), suites 201/85/27/10. Also fixed a root .gitignore rule that had kept every
compile.log out of 2cb6ecf9d against Philip's evidence policy.

Two of the agent's three self-reported issues were wrong, checked against git rather than accepted:
(1) "2cb6ecf9d contains the efficiency CRC edits" — false: 2cb6ecf9d has no 0x3b2f, and its own
generator from a clean `git archive` reproduces its committed E byte for byte (sha 0a32f97a...). The
edits enter at 17161e70b. The false claim is in 979b38fd1's message (left as is, no history
rewriting) and was in two docs, corrected in commit **`a3fb822fb`** (docs only). (2) "three _19
evidence files unrecoverable" — false: all three were committed in 17161e70b; restored from git with
`git restore --source=HEAD` after confirming the working-tree changes were only the agent's tracebacks.
Two untracked stragglers in _19 (compile_rc.txt, model_01.stdout) left alone.

**Open, real:** (a) the conf's pipe_scope is [0,2]/[1,3] (bf-p4c's default for two pipelines);
unverified on this 2-pipe chip — at deployment, edit to [0]/[1], which loaded cleanly for the
reflection probe. (b) **Pre-hardware blocker:** on silicon, pktgen tokens arrive on the pipe's local
port 68, which is now PKTGEN_RETURN=196 — the same port T uses to identify mirror clones, so tokens
would be misparsed as clones. Sent to Workstream A as next priority (content-based clone/token
discrimination, Defense 2's approach), before the rearm work.

**Pktgen clone/token fix committed: `69925ac6a`** (verified: lead identity, no trailers, not pushed,
scope = T, interp, tests, model driver, evidence). T now tells clones from tokens by a 0xE1 marker
byte (exact 8-bit lookahead match), and branches on header validity, not ingress port — which also
fixed a second silicon bug (the token branch tested `ingress_port == 0`, the model's port). T 11/0,
composite p0 12/11 p1 11/0, model 70/70 plus a 2/2 tokens-on-196 check with teeth.

**Latent defect found on review, sent back**: one of the two clone-tag writers uses
`md.op_gen | 32w0xE1010000` (the compiler rejected add and mask-then-OR). op_gen_alloc_reg is a
monotonic 32-bit counter never reset during a run, so after 2^24 OPERATE allocations the marker
breaks, the clone is parsed as a token, and a held OPERATE is silently never released. Fix proposed
to Workstream A: wrap the allocator 0xFFFF -> 1 (skip 0) — the ladder and clone tag already use only
the low 16 bits, so no real distinguishing power is lost — with wrap tests and teeth. Then rearm.

**In flight, all three in parallel**: (A) op_gen wrap fix, then N rearm; (review) independent
code-reviewer on the three unreviewed committed T/N changes — close forwarding, pipe-1 relocation,
clone marker — via `git show` only, verdict on whether the composite is safe to load; (bring-up) an
agent building `core/response_only/hw/` — real-BFRT installer for N+E+T state (mirror session,
pktgen app with Defense 2's silicon-proven pipe_local_source_port=68, TM queue priorities for T's
qids), a conf generator forcing pipe_scope [0]/[1], offline name-validation against bfrt.json, and a
model-vs-hardware state diff. Nothing touches hardware until the review clears and the op_gen fix
lands.

Hardware readiness of the composite after those three: B3 on the real relay from Vision's native IP
(.1) can test T's timing on silicon even though padding won't arm there (the relay's full-option
SYN-ACK falls through to native) — that's the next hardware milestone available without waiting on
Philip's two open questions.

<!-- AUTO-HANDOFF (PreCompact/auto) 2026-10-11T00:46:45Z -->
### Compaction handoff — 2026-10-11T00:46:45Z
- Git: branch `main`, 294 uncommitted file(s): defense4/timing/case4_architecture/integration/read/operate_slice.p4 defense4/timing/case4_architecture/integration/read/operate_slice_capture.p4 defense4/timing/case4_architecture/integration/read/read_queue_timing.p4 defense4/timing/case4_architecture/integration/read/tests/test_t_queue_invariants.py defense4/timing/framework/size/dnp3_read_client.py defense4/timing/framework/size/endpoint_gate/SocketGatePad58B.cpp .drawio-tmp/ DNP3_Next_Phase_Claude_Execution_Prompt.md DNP3_Resume_to_Hardware_Completion_Prompt.md WORKING_NOTES.md bf_drivers.log defense4/Codex_Case4_Hardware_Architecture_Prompt.md 
- Last verification run recorded: 2026-10-11T00:46:43Z	cd /home/philip/Projects/DNP3/defense4/timing && S=case4_architecture/integration/evidence/route_ab_01/clone_marker_comp
- RESUME: re-read the Task/Status/Next-action sections above; trust this file over recollection.

**►► 2026-10-11 ~00:50 — REFLECTION A/B RESULT: i40e source pruning CONFIRMED (supersedes the "wire/PHY" guess above).**
Probe `xpipe_reflect_probe_02` loaded (snapshot `/tmp/pre_ab_reflect_snapshot_20261010.json` on the switch, 403 tables),
fwd_mac rows mvA/mvB -> dev 9. Port-9 MAC counters, not only pipeline registers:
- A, src = mvA own MAC d2:9d:1d:1c:f4:dd -> mvB: switch `$FramesTransmittedOK` 0->1; Vision `port.rx_unicast` +1,
  `port.rx_bytes` +64, but NO `rx_packets`, no tcpdump copy, no delivery. The frame crossed the wire and the NIC dropped it.
- B, src = 02:00:00:00:00:5a -> mvB: switch TX +1; Vision `rx_packets` +1, tcpdump shows the reflection ~110 us
  after the send, and the listener on mvB in ns_vepa_b received it (`RECEIVED src=02000000005a len=60`).
Per Philip's pre-authorization ("Yes, if A/B confirms it"), NIC flag change on Vision's test NIC ONLY:
- apply:   `sudo ethtool --set-priv-flags enp59s0f0np0 disable-source-pruning on`
- RESTORE: `sudo ethtool --set-priv-flags enp59s0f0np0 disable-source-pruning off`  (original value: off)
- verify:  `ethtool --show-priv-flags enp59s0f0np0 | grep source-pruning`
Note: decps has NOPASSWD sudo for python3/tcpdump/iptables only; run ethtool through `sudo python3 -c subprocess...`.
**A/B completed 2026-10-11 ~00:52 (commit 02f0e7186, `evidence/vepa_reflect_01/hw_ab_20261011/STATUS.md`).**
With the flag on: own-source frame delivered to mvB; ping .61->.62 5/5 through the ASIC; negative control
(delete mvB fwd_mac row) -> 0 delivered, switch TX flat at 14; reinstall -> 5/5, TX +11. Flag set back OFF and
confirmed (`disable-source-pruning : off`), own-source delivery stops again. Baseline `case4_response_path`
restored (ports from the snapshot, slot 0 reinstalled, ping .1 -> relay 3/3). => NO SECOND PORT NEEDED for the
software endpoint; padding run = VEPA namespaces + flag on for the run + off after.
Gotcha: `pkill -f launch_case4...` over ssh kills your own remote shell (pattern is in its argv); use
`/tmp/swap.sh LAUNCH LOG` on the switch (kills by PID, waits for :50052).
Installer: `core/response_only/hw/` (10 files, offline dry-run PASS against clone_marker_composite_01 bfrt.json,
15/15 injected-error plans caught). Uncommitted; awaiting code review. Open: k=2 vs K>=44, real SEL CROB values,
pcie 0000:04:00.0, strict priority untested on recirc ports, pipe-1 pktgen no precedent, N no re-arm.

**►► 2026-10-11 ~01:20 UTC — ACTIVE PADDING THROUGH THE ASIC: DONE with controls (commits 94f363bd2, 4e1e50d88).**
Program `case4_response_path`, OpenDNP3 endpoints in ns_vepa_a/.61 and ns_vepa_b/.62 on dev 9 (forwarding 9->9),
clean TCP profile per namespace, NIC `disable-source-pruning on` during runs. persist10 and sustained300: every
response 49/37 -> 58 B, CRC/checksums valid, growth = 9/READ + 21/control, 1 real SELECT + 1 real OPERATE, 0 decoy.
Controls: policy off (enable=0) -> native 49/37, growth 0, mapper still translating; forwarding row removed ->
5 SYNs in, 0 out, no connection; recovery OK. Evidence `protocol/evidence/hw_vepa_padding_01` and `_02`.
Runner: `protocol/hw_vepa/run.py {deploy|setup|run LABEL --master-port P --reads N --out DIR|restore}`; new master
port per run (TIME-WAIT 60 s on a pinned port; ports used so far 54400-54404). Fixed `_forwarding_rows` dedup for
a shared port (724ce2a00). RIG RESTORED after the runs: relay slot + 9<->64 read back, ping .1 -> .7 3/3, flag off,
sysctls 1/1/1, range 32768 60999.
NEXT: (a) installer hw/ re-review then commit; (b) Workstream A: T timer/token qualification, then N `ports`
keyed by address for the shared port; (c) gate master 8-bit range READ (N admits only the 20-byte request);
(d) trace what N's data_connection configure() values must be for the gate's SELECT (installer says the defaults
are the decoy object's, index 201); then the combined run.

<!-- AUTO-HANDOFF (PreCompact/auto) 2026-10-11T01:18:04Z -->
### Compaction handoff — 2026-10-11T01:18:04Z
- Git: branch `main`, 315 uncommitted file(s): defense4/timing/case4_architecture/integration/core/response_only/cp.py defense4/timing/case4_architecture/integration/core/response_only/make_n.py defense4/timing/case4_architecture/integration/core/response_only/n_response_only.p4 defense4/timing/framework/size/dnp3_read_client.py .drawio-tmp/ DNP3_Next_Phase_Claude_Execution_Prompt.md DNP3_Resume_to_Hardware_Completion_Prompt.md WORKING_NOTES.md bf_drivers.log defense4/Codex_Case4_Hardware_Architecture_Prompt.md defense4/timing/audit_current/MEETING_20261005_DIRECTION.md defense4/timing/case4_architecture/FOUR_ARM_DESIGN_REVIEW.md 
- Last verification run recorded: 2026-10-11T01:17:47Z	cd /home/philip/Projects/DNP3/defense4/timing/case4_architecture/integration/core/response_only && git status --short . 
- RESUME: re-read the Task/Status/Next-action sections above; trust this file over recollection.

**2026-10-11 ~02:10 UTC — state before the combined run.**
Commits since the padding record: 3d6869c04 (gate master `[read-range 8|16] [gap-ms]`), d4ba3dd5b (Case-A emulation
`run.py casea on --delay-ms 25` + `clrt_check.py`; READ CLRT 25.313 ms median with padding on `case4_response_path`),
3c6138aaa (T token/clone admission by port AND format; verified: identity ok, read/tests 171 pass, response_only 32),
fbe12b137 (shared port: N `ports` keyed by hdr.ip.src, `compose.py --relay-port=9`; p0 12/11 stages, p1 11/0, both SDKs
exit 0; model shared 57/57). FINDING: software outstation natively piggybacks the ACK on the response (299/300), so
CLRT is undefined without the Case-A emulation.
ORIGIN WAS PUSHED TWICE DURING THIS SESSION (reflog: 21:01:30 -> 14d616641, 21:21:21 -> d4ba3dd5b local time), not by
me and by no agent transcript (0 `git push` commands in any). Reported to Philip; remote left as is.
Installer `hw/`: third revision, 29 offline tests pass, UNCOMMITTED, third cold review running (also covers fbe12b137).
Staged on switch (copies only): `/home/decps/Philip_repo/dnp3-defense4/response_only_shared_port_01/{out,src,response_only_hw.conf}`
(scopes p0 [0], p1 [1]; PCI vendor 0x1d1c). Dry-run ON THE SWITCH vs 9.13.2 schemas: PASS, 29 writes + 2 enables.
Hashes: bfrt d1ac5cf6..., p0/tofino.bin 1b4c740e..., p1/tofino.bin 5e7f3ebf...
Dry-run command args: --master-ip 192.168.10.61 --master-port 54410 --master-dev 9 --relay-ip 192.168.10.62
--relay-port 20000 --relay-dev 9 --read-dst 0x0a00 --read-src 0x0100. Master ports used so far: 54400-54405.
RIG: baseline `case4_response_path`, relay slot, flag off, sysctls original (verified after d4ba3dd5b).
NEXT: review verdict -> fix/commit hw/ -> snapshot, swap to composite (/tmp/swap.sh with a launch script for the new
conf), restore_ports, --apply, then run.py-style runs with casea on, range 8, gap 20, T enabled 0/1 blocks.

**►► 2026-10-11 ~06:15 switch time — COMPOSITE LOADED + INSTALLED ON SILICON; BLOCKED BY RECIRC PORTS (commit bd91edd99).**
- Composite `shared_port_01/shared_compile_switch_9132` loads on the 2-pipe chip with scopes [0]/[1] (`initialized 1
  devices`). Installer reached INSTALLED 31 writes after three first-contact fixes (c8244ce1b, a6074646e, fa9be2ebd).
  Installer committed f0c699676 (+9193b2a92). Teardown works on silicon.
- First connection FAILED: SYN to N_ACK_RETURN=70 never returns. MEASURED with the probe: ONLY dev 68 and 196
  recirculate. 69/70/71/197/198/199 do NOT (the old note "ports 68-71 are separate recirc ports, no reconfiguration
  needed" was an untested inference and is WRONG). $LOOPBACK_MODE cannot be set on them.
- MAC loopback on free front-panel ports WORKS (tested): 48 (pipe 0), 180/181/182 (pipe 1). New port map being built:
  N_ACK_RETURN 70->48, T_IN 197->180, HB_RETURN 198->181, HELD_RETURN 199->182; 68 and 196 stay.
  Free ports: 16, 48-51 (pipe 0); 164, 172, 180-183, 188-191 (pipe 1). In use: 9 Vision, 10, 11, 64 relay.
- Agents running: composite agent (port parameters + rebuild `loopback_ports_01`, runt/padding check for internal
  headers over a MAC hop), installer agent (ports from build, loopback step, set_enabled, default-app teardown).
- Switch staging dir: /home/decps/Philip_repo/dnp3-defense4/response_only_shared_port_01 (launch_response_only.sh,
  manifests 01-04 all torn down). Swap with /tmp/swap.sh. Probe tools: /tmp/recirc_probe.py, /tmp/port_list.py.
- Master ports used: 54400-54405, 54410.
- RIG RESTORED 06:13: case4_response_path, relay slot, ping .1->.7 ok, flag off, sysctls original, casea off.
- origin/main was pushed twice during the earlier part of this session by someone other than me/agents (see above).

<!-- AUTO-HANDOFF (PreCompact/auto) 2026-10-11T06:15:49Z -->
### Compaction handoff — 2026-10-11T06:15:49Z
- Git: branch `main`, 311 uncommitted file(s): defense4/timing/framework/size/dnp3_read_client.py .drawio-tmp/ DNP3_Next_Phase_Claude_Execution_Prompt.md DNP3_Resume_to_Hardware_Completion_Prompt.md WORKING_NOTES.md bf_drivers.log defense4/Codex_Case4_Hardware_Architecture_Prompt.md defense4/timing/audit_current/MEETING_20261005_DIRECTION.md defense4/timing/case4_architecture/FOUR_ARM_DESIGN_REVIEW.md defense4/timing/case4_architecture/integration/core/ordinary/transport_model_select.py defense4/timing/case4_architecture/integration/core/response_only/scratch_efficiency_01/ defense4/timing/case4_architecture/integration/evidence/model_02/run10/bf_drivers.log 
- Last verification run recorded: 2026-10-11T06:15:49Z	cd /home/philip/Projects/DNP3/defense4/timing/case4_architecture/integration && git log --oneline -3 | cat; grep -n "loo
- RESUME: re-read the Task/Status/Next-action sections above; trust this file over recollection.

**►► 2026-10-11 ~07:09 — FIRST COMBINED N+T+E RUN ON SILICON (commit 10e22cf2b, evidence/combined_silicon_01).**
Loopback build loopback_ports_01/shared_compile_switch_9132 (n_ack_return=48, t_in=180, hb_return=181,
held_return=182, relay=9; bfrt d1ac5cf6, p0 4a322a75, p1 bb58c2cb) loaded [0]/[1]; installer applied 35 writes
incl the 4 MAC-loopback ports first; teardown clean (35/36, loopback back to NONE, read back).
BOUND connection (master 54410): generator fired (READ app 3887 trig/15548 pkt), HELD_REWAIT 0->149833, queues
ACK_HOLD/RESP_HOLD held cells, all 10 READ responses 49->58 valid. BUT every READ via FALLBACK (ACK_FALLBACK=10,
RESP_FALLBACK=10, not commit) and OPERATE LOST (operate_real=0). 5/31 master->outstation frames dropped.
=> the clean-commit + OPERATE paths cross front-panel MAC loopback with frames that don't start with an Ethernet
header (RESULT.md item 2); proposed fix (keep eth header on OPERATE blocker, read_queue_timing.p4:506) NOT applied.
2nd connection same tuple FAILED to bind (N no re-arm) — needs fresh cold bring-up per connection.
set_enabled.py takes --enabled 0|1 (not positional). Runner MUST use the port the bring-up bound; an unbound port
passes natively with no padding.
Agents: composite agent resuming item C (timestamp profile; 2 negative tests failing in its uncommitted work).
Switch staging: /home/decps/Philip_repo/dnp3-defense4/response_only_loopback_01 (launch.sh, m02 torn down).
Master ports used: 54400-54405, 54410, 54411. RIG RESTORED 07:09: baseline, relay slot, ping .1->.7 ok, flag off.
NEXT: apply+test OPERATE eth-header fix; per-frame MAC-loopback check from RESULT.md; N re-arm or scripted cold
bring-up per connection; THEN clean paired OFF/ON blocks.

**►► 2026-10-11 ~13:08 — FIRST HARDWARE MILESTONE PASSED (commit b8a35c6c6, evidence/milestone_sbo_01).**
Build sbo_admission_01 (A+E+ports; bfrt ee998605, p0 741fee7e, p1 084e4963). Fixes landed: A IIN admission
8efae4002 (ternary 0x8100&&&0xff6f), B READ app0 818b4da0e, F fixture d2e987e00, tooling 98e330abc..32e275ac9.
- Test1 T-off (port 54430): master success, 10/10 reads match, 1 real SELECT + 1 real OPERATE 0 decoy, 12x58
  returned valid CRC. Test2/3 T-on 5ms fixture (port 54431): OUT_ACK_COMMIT=10, OUT_RESP_RELEASE=10, OUT_OP_RELEASE=1,
  ZERO fallback; ACK_BLOCK wm335 RESP_BLOCK wm334 OP_BLOCK wm5 (blockers circulate now, were 0); 12x58 valid CRC.
- OPEN: OUT_HELD_REWAIT=71310 for 10 reads+SBO = original rewait overhead (plan step 3), correctness separate & proven.
RIG RESTORED 13:08: baseline case4_response_path, relay slot, ping .1->.7 ok, flag off, sysctls+qdisc default.
Agents idle (all step-1 done). Master ports used incl 54430/54431. Switch staging: response_only_sbo_01.
NEXT (plan step 3): short diagnostic separating original returns (by role) from blocker admission/passes/termination,
measure loop turnaround + queue service on real links, size reservoir/K; then timing step 2 with 25ms + readiness
above measured child arrival; then loss/rearm; then four-arm campaign (campaign.py/campaign.json entry point ready).

**►► 2026-10-11 ~18:00 — RESIDENCY DIAGNOSED + FIX APPROVED (commits 508a2b00b diag build, 5e76676c4 finding).**
Role-split diag (residency_diag_01, bfrt 8c687b72) on silicon, T-on 5ms, 10 READs+SBO:
- held-ORIGINAL rewaits: ACK 59833 / RESP 8988 / OP 2999 (idx 14/15/1). BLOCKER laps: ACK 302k / RESP 166k / OP 15k (idx 16/17/18).
- K sweep 2/4/8: original rewaits FLAT (~59300 ACK), blocker laps GROW with K, zero fallback => K is wrong knob; cause is scheduling.
- Agent 2 feasibility: held original MUST loop (only pipeline packet reads global_tstamp; released bytes must BE the original;
  no TF1 dequeue-specific primitive). FIX = pace the hold queues via tf1.tm.queue.sched_shaping (max_rate PPS, set once at
  bring-up), cutting lap cadence ~1.7us -> ~1ms (~500x), release still data-plane, late-never-early, zero fallback while
  turnaround < (readiness-da ~10ms for ACK). Control-plane only, no P4 edit.
- Agent 2 implementing configurable --shape-ack-pps/--shape-resp-pps/--shape-op-pps in hw/ (default off). THEN I sweep R
  on silicon starting ACK-only on the diag build, confirm per-role rewait drop + zero fallback + release jitter, then fold
  chosen rates into production bring-up and re-run the 3 gate tests.
RIG at baseline (restored 17:38): case4_response_path, relay slot, ping .1->.7 ok, flag off, sysctls/qdisc default.
Switch staging dirs: response_only_diag_01 (diag), response_only_sbo_01 (prod milestone). Master ports used thru 54434.
NEXT: load diag build, apply --shape-ack-pps 1000 (then sweep), measure; then RESP, OP; then 25ms timing; loss/rearm; 4-arm.

**►► 2026-10-11 ~18:42 — RESIDENCY FIXED (commits 233a4650f shaper, 6df3b304b quant-tolerance, 13c0f53fc diag result, +prod confirm).**
Hold-queue PPS shaping (tf1.tm.queue.sched_shaping, control-plane only, no P4 edit) at 232 PPS achieved (request 200):
- diag build all200: original rewaits ACK 59833->29, RESP 8988->27, OP 2999->2 (71820->58, ~1240x), zero fallback, SBO OK.
- PRODUCTION sbo_admission_01 + --shape-ack/resp/op-pps 200: OUT_HELD_REWAIT 58 total, COMMIT 10/REL 10/OP_REL 1, zero
  fallback, 12x58 responses. Plan step 3.5 CLOSED on production. FOLD --shape-*-pps 200 into all future bring-ups.
- Rate granularity (measured): req 200->232 (ok), req 500->930 (gate refuses, >25%), req 1000->930. ~232 PPS is the
  useful low setting (4.3ms/lap, ~2-3 polls in the 10ms ACK window -> zero fallback, late-never-early).
- OPEN follow-up: blocker laps still ~500k (ACK 302k/RESP 214k/OP 15k) = blocker reservoir traffic, separate from
  originals. Now that pacing holds originals, is the blocker reservoir still needed for residency or only timing cover?
  Bounded test could remove pktgen/blocker complexity OR find it load-bearing. K stays 2 (min zero-fallback).
RIG restored 18:42 (case4_response_path, relay slot, ping .1->.7 ok, flag off, sysctls/qdisc default). Master ports thru 54461.
NEXT (plan 3.6): 25ms fixture with readiness above measured child-arrival+margin (two tests: on-time commit, late=bounded
fallback); then loss/retransmission + reset/reconnect; then four-arm campaign (campaign.py entry point). Also the blocker-
reservoir necessity test. All future prod bring-ups carry --shape-*-pps 200.

**►► 2026-10-12 ~00:20 — P2 RESULT: shape BOTH hold+blocker queues (commits 3eb3b273e diag, bf0343b6e production).**
TM shaper realizes only a x4 ladder: 58/232/930/3723/14892/59570/238281 PPS (burst 1) (quant_probe.py).
Production sbo_admission_01, 50 READs + 1 SBO, loop-port $PORT_STAT frames+octets (ports 48/180/181/182):
 unshaped 2,026,007 pkts / 148.1 MB; hold+blk 3723 -> 30,370 / 2.20 MB (66.7x), 14892 -> 43,295 / 3.15 MB (46.8x),
 59570 -> 84,416 / 6.2 MB (24x). CLRT median 809 (unshaped) vs 811/823/825, pop SD 16.7 vs 5.3/14.3/14.3;
 added latency ~half poll interval (+130us at 3723, none measurable at 14892+). 50 commit/50 release/1 op, zero fallback.
 DEFAULT CANDIDATE: 14,892 PPS (46.8x, no added latency); 3,723 PPS = low-traffic option (+130us).
 Hold-only shaping leaves ~486k blocker laps; blocker-only shifts work to other queues (shared port 182).
RESET-ENVELOPE CONFIRMED by counters: port 180 rx octets 15039 vs good 14959 = constant 80-byte gap = one 76B RESET
 event + FCS counted received-not-good (all 4 runs). Other loop ports gap 0.
Agents: Agent1 (a61f1fb) applying close fix (close_forward bypass_egress + seq_fin guard/first_event row) + RESET kind>=0x0600
 + builds; Agent2 (a4cf2c2) idle (hw/: pad-enable 4115ecda6, loop-port snapshot 4cc5952c5, blocker shaping 364aa3471);
 Agent3 (af0d026) done: campaign.py executable (112 tests, validate OK, per_trial_cold, presets unshaped/shape_3723/14892/59570/slow_232,
 fixtures separate_ack|piggyback, restore to case4_response_path+relay slot, endpoint pins set).
 25b063d79 carries Agent 1's 71 close-defect evidence files by commit race (message wrong, content fine).
RIG restored 00:2x (case4_response_path, relay slot, ping ok, flag off).
NEXT: (1) Agent1's close+RESET build -> load on silicon, verify clean close (no native FIN, FIN ACK delivered, port180 gap 0);
 (2) vary fixture delay / spacing / start phase and repeat blocks (campaign.py per_trial_cold) at 14892 and 3723;
 (3) small four-arm campaign block via campaign.py run (pad-enable 0/1 x T 0/1); (4) loss tests; (5) stage-recovery candidate.

**►► 2026-10-12 ~07:05 — ROOT CAUSE OF TRIGGER/STALE STORM FOUND + CONFIRMED ON SILICON (422b6ca4f); close fix verified (ebed668a2).**
- Close+RESET fix (b72285d13/4b228aa88, build close_reset_fix_01: bfrt 7c7e7f3b, p0 e15b6177, p1 7ab242e8) VERIFIED on silicon:
  outstation FIN returned at padded frontier, final ACK reverse-mapped, 1 FIN/direction, wire_check exit 0 (94/94), port-180 bad-octet gap 0.
- STORM: bf-p4c gives T's ingress-deparser 'no mirror' (mirror_type==0) entry a session id from a compiler temporary sharing a slot
  with md.cur_gen; every T pass is mirrored to session cur_gen[9:0]; only session 7 (->196) is configured => while READ generation == 7
  every T pass is copied to 196 (clones re-trigger the READ generator, copied tokens seed blockers). Silicon: shaped 6 READs = 6 trig/0 stale;
  7 READs = 3,335 trig/29,079 stale; 8 = 3,544/26,793; unshaped 7 = 20/14,260 (same storm, shorter).
  => ALL earlier runs with >=7 READs include the defect (10/20/50-READ blocks, shaped and unshaped). Correctness stands; trigger/stale/
  blocker-lap/loop-traffic figures and the shaped-vs-unshaped comparisons MUST BE REPEATED on the fixed build. The 24-67x claim is NOT final.
- FIX (Agent 1, token_stale_01/prototype/type1_fix.diff): non-cloning passes use clone entry with session 0 + @pa_no_overlay mirror_type/clone_ses;
  APPROVED, Agent 1 building full composite with all fixes (mirror_fix_01) + check_mirror_select.py guard. Prototype hashes (NOT to load): bfrt 4e24bc8a, p0 2290c420, p1 e0ad62df.
- Teardown bug found by first campaign.py run: pkt_buffer restore passed a list (real client rejects) -> exit 1; fixed by Agent 2 (3e6277da5), fake client now strict.
- campaign.py FIRST REAL RUN (smoke1, combined/separate_ack/shape_14892, 10 READs): whole flow worked on hardware (swap, ports, install, snapshots,
  traffic, wire_check, clrt_check, restore+ping); trial ok, all outcome checks passed; run marked failed only due to the teardown bug above.
- Tooling: Agent 3 commits 33b4557bb 739f5a900 a5508db39 8fb78fb14 223a3b4e0 122a3c16b 0b61ec30f (187 tests; close_reset_fix_01 bound; paired_blocks).
- Agent 2: hw tests split (ea1def14d), teardown fix 3e6277da5.
RIG restored 07:05 (case4_response_path, relay slot, ping ok, flag off).
NEXT: (1) Agent 1 fixed build -> silicon probe 4 (10/20/50 READs shaped: triggers == READs, stale 0, check_mirror_select), re-run unshaped vs shaped
  comparison with loop-port packets+bytes on the FIXED build; (2) campaign.py paired 14892 vs 3723 (varied delay/gap/start phase) on fixed build;
  (3) four-arm pilot; (4) deterministic loss/reconnect tests; (5) re-do the close verification on the fixed build (gap 0, wire_check 0).

**►► 2026-10-12 ~11:50 — MIRROR FIX VERIFIED ON SILICON (61271eadb, 0707bdb21); paired campaign pv2 RUNNING.**
- Build mirror_fix_01 (159daab6c+ef893db5d): bfrt 4e24bc8a, p0 aff15250, p1 296444ce, bfa eea04489. Shaped 14892 at 7/10/20/50 READs:
  triggers == READs, 4 tokens each, stale 0, correct, port-gap 0, wire_check 0, FIN at padded frontier. Unshaped 20 READs: 751,270 loop pkts
  vs 8,375 shaped (~90x), CLRT 805-813us SD 9-22us. Supersedes the storm-affected 24-67x.
- Installer: mirror guard before any write (b684bba04), --expect p1/response_only.bfa REQUIRED + guard locates .bfa from --build-out (113798782),
  teardown pkt_buffer fix (3e6277da5), hw tests split + ladder fake (ea1def14d). Campaign: report subcommand, mirror-fix trigger/stale checks,
  mirror_fix_01 bound, bfa pin (a6e8a4298), deploy closure incl check_mirror_select (1b7568e09). 234 hw_vepa tests.
- FIRST campaign.py runs: smoke1 OK (teardown bug since fixed); pv1 failed fast (check_mirror_select not deployed) -> fixed 1b7568e09;
  pv2 launched with manual stopgaps on the switch ONLY for this run: hand-copied core/response_only/check_mirror_select.py and symlink
  response_only_composite/out -> out_mirror_fix_01 (both unnecessary once the switch has the 113798782+1b7568e09 installer; REMOVE the symlink after pv2).
- pv2 = `campaign.py --config <scratch>/campaign_paired.json run --apply --paired p14892_vs_3723_varied --run-id pv2`: 7 conditions (fixture delay 3/5/8/10 ms,
  READ gap 0/5/20/50 ms, seeded start delay 0-50 ms) x presets shape_14892/shape_3723, 50 READs + 1 SBO each, alternating order. Evidence:
  integration/evidence/campaign_hw_vepa/pv2/. Scratch config: .../scratchpad/campaign_paired.json (reads_per_trial 50). ~2.3 min per block, 14 blocks.
- Agent 3 now building deterministic loss (iptables nth/delete-after-hit, class by IP len+flags) + reconnect scenario + gate/report for them.
NEXT: pv2 -> `campaign.py report --run-dir`; four-arm pilot (off/timing_only/size_only/combined x fixtures) small; loss + reconnect on silicon; then
  decide default rate (14892 vs 3723) from the report; scale. Remove the switch symlink/hand-copy after pv2.
RIG: baseline restored by orchestrator after each run; pv2 in progress (switch/Vision busy — do not touch).

<!-- AUTO-HANDOFF (PreCompact/auto) 2026-10-12T12:22:49Z -->
### Compaction handoff — 2026-10-12T12:22:49Z
- Git: branch `main`, 320 uncommitted file(s): defense4/timing/framework/size/dnp3_read_client.py .drawio-tmp/ DNP3_Combined_Hardware_Debug_and_Reproducibility_Prompt.md DNP3_Shaping_Timing_Precision_Correction_Prompt.md WORKING_NOTES.md bf_drivers.log defense4/Codex_Case4_Hardware_Architecture_Prompt.md defense4/timing/audit_current/MEETING_20261005_DIRECTION.md defense4/timing/case4_architecture/FOUR_ARM_DESIGN_REVIEW.md defense4/timing/case4_architecture/integration/core/ordinary/transport_model_select.py defense4/timing/case4_architecture/integration/core/response_only/scratch_efficiency_01/ defense4/timing/case4_architecture/integration/evidence/campaign_hw_vepa/ 
- Last verification run recorded: 2026-10-12T11:53:03Z	cd /home/philip/Projects/DNP3/defense4/timing/case4_architecture/protocol/hw_vepa && cat tests/pcaptk.py; grep -rn "\['l
- RESUME: re-read the Task/Status/Next-action sections above; trust this file over recollection.

### Active continuation — 2026-10-12

Resumed at the user's explicit request from commit190a4c603. Candidate55 fully compiles on local9.13.1 and installed9.13.2 with N12/E12/T12; mirror checks PASS,42 source tests PASS and private compiled-model80/80 plus382/382 PASS. Two silicon attempts stopped before application traffic at parser checks in installation and counters, and all five restores passed after each. Candidate-only installer/snapshot guards preserve baseline port checks and pass122 helper tests; fresh retry is pending. Baseline case4_response_path was read-only confirmed under PID282916. Independent N CRC-residue experiment compiles locally with N11/E12/T12; T sealed-lifetime places in11 but fails assembly, with bounded repair active. Experiments remain isolated from candidate55 and hardware. Root owns all hardware operations.

User approved implementation of bounded generation-safe N/E/T rearm. Current plan/status: `defense4/timing/case4_architecture/integration/evidence/rearm_01/{PLAN,CHECKPOINT}.md`. Unchanged failure captured first: installed c1 works, unknown-port c2 works natively, same-tuple c3 sends five SYNs and receives no packets; independently verified and baseline restored. Independent baseline experiments are now complete: six stale probes, rate/close-grace/READ-only controls, precision comparisons, twelve separate-ACK four-arm blocks, four piggyback arms plus one bounded failed-condition rate control, and three native reference blocks. Strict failures remain retained: 10ms/950us at14892 exceeded100us, pause0 produced28stales, and combined piggyback at14892 produced5stales. The corresponding59570 rate controls passed. Native RST archive03 passed three genuine kernel-RST connections and restoration; exact native49 FIN/RST replay fixtures are retained.

Preserved candidate55 hardware completes three protected same-tuple20READ+SBO connections for graceful800us (p99abs26/37/40us) and RST950us (69/71/53us), all freshmapping/padding/integrity/strictstale0 and lastmappergrowth222/unacked0. Graceful independent reverifyPASS preserves its failed raw harness report. All5restorespassed. Old-token01/external01 stopped before traffic; action-selected disabled app reconfiguration and fresh runparent fixes pass133helpertests, fresh02 retries next. Four-arm/seven-loss remain pending. Workepochs145/143 differ from ownerconnectiongeneration3 by design. Combinedstagefit11/12/11 remains localcompileproof; separate N398/398 and T491/491 compiledmodelPASS. N capturefailures resolved by removing internalallpipeloopback, samefrozenbinarypasses; initialfailuresretained. Combinedmodel and installedSDK pending. Root owns all hardware. Frozen baseline, publication artifacts and paper unchanged; no push.

<!-- AUTO-HANDOFF (PreCompact/auto) 2026-10-12T12:23:30Z -->
### Compaction handoff — 2026-10-12T12:23:30Z
- Git: branch `main`, 320 uncommitted file(s): defense4/timing/framework/size/dnp3_read_client.py .drawio-tmp/ DNP3_Combined_Hardware_Debug_and_Reproducibility_Prompt.md DNP3_Shaping_Timing_Precision_Correction_Prompt.md WORKING_NOTES.md bf_drivers.log defense4/Codex_Case4_Hardware_Architecture_Prompt.md defense4/timing/audit_current/MEETING_20261005_DIRECTION.md defense4/timing/case4_architecture/FOUR_ARM_DESIGN_REVIEW.md defense4/timing/case4_architecture/integration/core/ordinary/transport_model_select.py defense4/timing/case4_architecture/integration/core/response_only/scratch_efficiency_01/ defense4/timing/case4_architecture/integration/evidence/campaign_hw_vepa/ 
- Last verification run recorded: 2026-10-12T11:53:03Z	cd /home/philip/Projects/DNP3/defense4/timing/case4_architecture/protocol/hw_vepa && cat tests/pcaptk.py; grep -rn "\['l
- RESUME: re-read the Task/Status/Next-action sections above; trust this file over recollection.


## 2026-10-12 — stage cuts and candidate56 qualification

Current resume status (2026-10-12): candidate55 graceful/RST same-tuple hardware gates and four-arm smoke PASS; each restoration passed. Candidate56 preserves all counters while reducing stages to **N11/E12/T11** on local9.13.1 and installed9.13.2. Mirror/artifact checks and **519/519 compiled-model assertions PASS**; silicon qualification is separate and active. First56RST attempt stopped before traffic on an omitted Vision transitive helper; failed evidence and all five successful restores retained, deployment repaired. A fresh56RST retry is active. Separate bounded10s endpoint fixture is built and pinned; old-token gates now require split READ24/OP23 packet attribution, complete old batches, unchanged current authority and strict zero rejection suffix after the quiet window. Helper tests142PASS. Old external/token and seven-loss hardware gates remain pending. Counter-elision T10 is excluded from integration. Root alone owns hardware; frozen baseline, candidate55, historical evidence and paper preserved. No push.

## 2026-10-13 — directive f813bc089 (IEEE 1815 + completion): CURRENT CHECKPOINT

HEAD 0d3691501 (gate 1 committed). Plan: ~/.claude/plans/optimized-questing-moler.md. Loaded image on the switch: unchanged
(production `case4_response_path`; no hardware touched this session). Work dir:
`defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/read_reencode_01/`.
- Gate 1 DONE: IEEE checker + READ two-range oracle (18 tests), pinned OpenDNP3 endpoint PASS (evidence/endpoint_01).
  PDF verified: Table 4-8 p.35, Rule 8 p.51, Tables 12-6/12-8 p.354, 14-2 p.398, Annex E, A.20.1.
- P4 READ re-encoding (generate.py, E only; split native READ into 10 headers so no bytes move):
  full_01 (CRCs early) compiles N12/E12/T11 — N regressed; model 519/519 + 37/37 PASS with the re-encoding oracle.
  full_02 (--late CRCs after derive_t) compiles N11/E12/T11 = rearm_56r stages. Model suites running.
  full_03 (--late --strict: ctl_profile never matches -> controls native) compiling; oracle env CASE4_STRICT_CONTROLS=1.
- DEFECT REPRODUCED on model (rearm_56r): early duplicate OPERATE bypasses T (evidence/dup_model_01,_02). Recorded in
  rearm_01/STATUS.md. Builder subagent implementing fix in stage_experiments/dup_hold_01 on top of full_02 source
  (new N->T dup kind; T drops while held, forwards after release).
- Loss: loss.py class master_ack_of_padded_data (semantic data-ACK gate) + 4 tests; campaign preset added; 405 hw_vepa tests PASS.
- .gitignore exception for old-token evidence (secret scan clean); not yet committed.
NEXT: full_02/full_03 model results -> README; review builder diff (code-reviewer) -> compose candidate -> installed 9.13.2
compile -> pin sealed_profile -> silicon under existing authorization (restore after each block).
**2026-10-13 later — HW ACTIVE.** Philip authorized 9.13.2 compile + bounded silicon (strict first, then all-58), software
SBO only, restore after every block (recorded in rearm_01/STATUS.md). Build rearm_57s (dup_hold_01/evidence/full_02_strict,
commit ac1badc50) pinned; configs rearm_01/config/candidate57s_*.json. RUNNING: candidate_series graceful run-id
candidate57s_graceful_800_01 (log scratchpad hw_graceful_01.out). If interrupted: confirm restore (campaign_run.json restore[],
switch observe_program shows case4_response_path). Next blocks: rst_950, fourarm_smoke, single_loss (core preset incl.
master_ack_of_padded_data), old_tokens, old_external; then check_capture.py on every in.pcap; then all-58 candidate.
**2026-10-13 silicon progress (rearm_57s strict).** PASS: graceful_800_01, rst_950_01, fourarm_smoke_01, single_loss_01 (6 classes;
data-ACK n=2 hit FIN-ACK -> gate rejected as designed), single_loss_02 (data-ACK n=1 PASS, cumulative ACK 26.8 ms). Every capture IEEE
conformant (check_capture.py). dup_hold_500_01 retained FAIL (fixture: 500 ms hold > endpoint 500 ms timeouts) but early duplicate
dropped on silicon (OUT_OP_DUP_DROP 0->1). RUNNING: dup_hold_350_01. Then: old_tokens, old_external (pool args in Explore report /
campaign_run old_capture_identity of candidate56r_old_external_01), eval blocks b1..b3 (candidate57s_eval_b*.json), then all-58
(rearm_57a: compile dup_hold full_01 on switch, make_candidate57s.py --all58).
**2026-10-13 late checkpoint.** HEAD b7f22b952. Switch idle, production case4_response_path restored (every run verified).
DONE on silicon: rearm_57s (strict, IEEE-conformant) and rearm_57a (all-58, SBO Rule 8 non-conformant) pass every rearm gate
incl. dup-hold; repeated 3x4x500 eval on rearm_57s (|err| p99 88/60 us timed arms; open: sporadic ~1.1 ms one-packet release
overshoot, 6/3000, needs matched rearm_56r block -> NOT authorized yet, ask Philip). Real relay: BOTH candidates cannot carry a TS
connection (model, baseline 17/99). realrelay_native_01 full_01 passes native (99/99) but review BLOCKS hardware (wedge via stuck
phase, network-validation bypass, no-TS option profile). Builder fixing into full_02. Then: cold review -> switch compile -> pin ->
real-relay READ only with Philip's go (physical relay; SBO attended-only). Remaining directive items: §6 writing notes (audit
folder, not paper/rewrite), release entry point + fresh-checkout offline verification.
**2026-10-14 overnight checkpoint (61-octet compliant equal-size experiment).** HEAD 02f051445. Switch idle, production
case4_response_path restored (last hardware block today ended with a verified restore); no hardware run for seg61.
- Gate 1 (offline proof) PASS, commit 888c7783c: READ 61 (three G10V2 ranges q00/q00/q01, one frame) and SELECT/OPERATE as
  three transport segments (28+19+14) with byte-identical application octets; Clause 8 reassembly, all 64 seq incl. wrap,
  every LEN/CRC, Rule 8 exact vs real requests; mutations caught.
- Gate 2 (pinned OpenDNP3 endpoint) PASS, commit 4c0db6aa5: 20 persistent READs at 61, 3-segment SBO reassembled, one
  real callback each, 0 Clause 8 / Rule 8 failures. SBO completion 0.60 ms vs 0.79 ms strict (single runs).
- Tooling ready for a 61-octet build: image_len in loss/campaign/series/report (4c0db6aa5), multi-frame wire_check
  (14eae68b6), Vision --image-len (02f051445).
- Gate 3 (P4 in E) PAUSED: a safety classifier stopped the builder and then the main session while working on this step;
  per instruction the withheld content is not retried. Needs Philip's direction. Input pinned: dup_hold_01/evidence/
  full_01 sha256 c0ad6b4e...; known 58-specific E constants: r_IMAGE_LEN, start_arm (ISN+1-58), fwd_prep (p-58),
  classify_rev rows for -1..-58, acct leff rows 49/37, read/ctl pad actions (+9/+21, LEN, header-CRC XOR).
Strict rearm_57s remains the IEEE-conformant silicon-qualified baseline (READ 58, SBO native 37).

<!-- AUTO-HANDOFF (PreCompact/auto) 2026-10-14T04:22:22Z -->
### Compaction handoff — 2026-10-14T04:22:22Z
- Git: branch `main`, 635 uncommitted file(s): .drawio-tmp/ DNP3_Codex_Handoff_b066ec95a.md DNP3_Combined_Hardware_Debug_and_Reproducibility_Prompt.md DNP3_Shaping_Timing_Precision_Correction_Prompt.md bf_drivers.log defense4/DNP3_Claude_Completion_and_IEEE1815_Prompt_f813bc089.md defense4/ieee-standard-for-electric-power-systems-communicationsdistribut.pdf defense4/timing/audit_current/MEETING_20261005_DIRECTION.md defense4/timing/case4_architecture/FOUR_ARM_DESIGN_REVIEW.md defense4/timing/case4_architecture/integration/core/ordinary/transport_model_select.py defense4/timing/case4_architecture/integration/core/response_only/scratch_efficiency_01/ defense4/timing/case4_architecture/integration/core/response_only_rearm/evidence/incremental_55/model_01/bf_drivers.log 
- Last verification run recorded: 2026-10-14T03:28:21Z	cat >> WORKING_NOTES.md <<'EOF' **2026-10-14 overnight checkpoint (61-octet compliant equal-size experiment).** HEAD 02f
- RESUME: re-read the Task/Status/Next-action sections above; trust this file over recollection.


## 2026-10-14 — candidate61 checkpoint: stopped before silicon

Philip requested stopping execution and updating the plan/working notes. **No candidate61 silicon run occurred in this session.** Latest read-only switch observation: production/restore `case4_response_path`, PID 537002. No switch/offload settings were changed. No push or default promotion; changes remain uncommitted.

- Branch: `implement/seg61-qualified-20261014`; baseline `49201301439b260ba08455e192e1302a7663e92b`.
- Candidate: `defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/seg61_02/evidence/full_04/response_only.p4`, SHA256 `1b2d62d16d40427d8b7e5d4b93f9e57b75e721e6a6c7e4c184fb84a1dc3665aa`. E-only change against pinned strict source; N/T unchanged, replace-back equality verified.
- Whole-composite SDK9.13.1 and installed SDK9.13.2 compiles PASS **N11/E12/T11**; actual PHV/table/hash/mirror placement reviewed (`full_04/resource_review.json`). Earlier compiler failures retained.
- Compiled model PASS: padding-on smoke30/30 (`model_smoke_02`), padding-off/native30/30 (`model_native_01`), transport622/622 (`model_packets_04`), reverse-map/rearm399/399 (`model_rearm_02`), duplicates102/102 (`model_dup_02`). READ49→61 and SBO37→61 work in the model; each SBO image contains 28/19/14-byte frames with unchanged application bytes. **Silicon remains unverified.**
- Duplicate READ fixture C now sends actual server ACK/response after observing request delivery, proves their hold/release, and checks no repeated allocation/growth. Late duplicate READ correctly forwards with normalized ACK/window and only the expected reverse pending-distance marker change. Failed fixture `model_dup_01` retained.
- Checker repairs, shared `validate_standards`, physical capture/offload calibration, generation-headroom helper, sealed-profile registration and 17 hardware configs are implemented. Final review/testing is unfinished. Earlier integrated671PASS; latest broad687PASS/3FAIL during strict config alignment; subsequent config subset8PASS/1FAIL on stale `candidate61-only` status-string expectation. Do not claim the final tree is green. Independent smoke review was interrupted on the stop request.
- NEXT on resume: fix that obsolete test assertion, verify strict profile/capture flags, regenerate configs with final model refs, rerun integrated tests and finish smoke review; then bounded four-arm silicon smoke (20 READs + SELECT/OPERATE per arm) with qualified physical packet boundaries, headroom and verified restoration. Hardware plan commands: `seg61_02/hw/RUNBOOK.md`.
- Full remaining timing+size plan is now in `DNP3_Implementation_Directive_492013014.md` under “Execution checkpoint and remaining plan”: persistence, loss/reconnect, stale/held duplicates; repeated three-block four-arm and matched strict comparison at59570PPS/950µs; separate piggyback; repeated SBO timing where needed; then14892-vs59570PPS trade-off. Preserve tails/exclusions/callbacks/recovery/internal packets+bytes/external growth. These campaigns are planned, not executed. Real-relay support remains separate.

## 2026-10-14 (resumed) — candidate61 four-arm silicon smoke PASS

Philip authorized PLAN step 1 (offline) + step 2 (bounded four-arm smoke) and staying on branch
`implement/seg61-qualified-20261014`; no push.

- Offline: obsolete strict-status assertion fixed (now asserts profile/packet_boundary/scope on all three strict
  configs); 17 configs regenerate byte-identical and every pinned hash matches the on-disk build files; a
  `RESEARCH_PYTHON`-dependent interpreter filter in test_campaign.py fixed; new end-to-end fail-closed test
  (mutant-killing). code-reviewer: no blockers; fixed MAJOR (campaign-level Vision receive-offload baseline,
  restore re-applies + verifies, nonzero on mismatch; only differing keys written because lro/rx-gro-hw are
  `off [fixed]`), MAJOR (report padding coverage None for native-target arms), MINOR (READ answered by a
  non-G10V2 response now fails). Not done: headroom bfrt compare (install --expect already binds it), docstring
  rewording, stale `_notes` in the hash-bound smoke config. Suite 699 passed (with and without RESEARCH_PYTHON).
- Silicon (software endpoints only, no relay OPERATE):
  - `candidate61_fourarm_smoke_01` FAIL (off arm, one gate): capture_boundary read argv-list tcpdump commands as
    str(list) so '-Q in' never matched. Fixed in 48f81cb3a. Other off-arm gates passed.
  - `candidate61_fourarm_smoke_02` off/timing_only/size_only PASS; combined traffic correct but calibration out
    tcpdump received 4 / captured 0 (TPACKET_V3 block lost on terminate after fixed 1 s). Fixed fb244ee9f
    (--immediate-mode, wait for -c count).
  - **`candidate61_fourarm_smoke_03` PASS all four arms, campaign ok.** Per arm: 22 server data segments in
    in.pcap, no retransmissions; off/timing_only READ 49 x20 + SELECT/OPERATE 37; size_only/combined 22 x 61
    (one received segment per response). SELECT authorizes, OPERATE succeeds, check_capture conformant,
    calibration 2/2 both directions, GRO off during capture and restored, headroom 65496 remaining. Restore all
    rc 0 + ping; production `case4_response_path` observed afterwards.
- Evidence: `seg61_02/evidence/hw_campaigns/candidate61_fourarm_smoke_0{1,2,3}`.
- Vision mgmt is 10.10.54.19 again (.166 no route); `sudo python3` is NOPASSWD there.
- NEXT (not authorized yet): PLAN step 3 persistence/loss/reconnect/duplicate-OPERATE, then step 4 timing.

## 2026-10-14 (afternoon) — candidate61 PLAN step 3 PASS on silicon

Philip: "go ahead with step 3". All runs software endpoints, combined arm, restore + ping ok after each.
- Prerequisite: validator-rejection tests for candidate_series/isolation/external (a541ddfa8), mutation-checked.
- PASS: loss_core_950_01 (7 classes), reconnect_950_02, persistence_graceful_950_01, persistence_rst_950_01,
  stale_tokens_950_02, held_operate_350_01 (DUP_DROP 0->3, RELEASE 0->3), old_external_950_01 (82 old frames).
- Retained harness failures: reconnect_950_01 (c2 checked on c1's port; fixed 20e02e6bb + 631482edc — the
  former was committed with 35 failing tests because the gate read tail's rc; gate now reads pytest's rc);
  stale_tokens_950_01 (capture_observation missing from Vision pins; calibration's fixed 1 s sleeps moved c2
  from 4.92 to 7.04 s after c1, past the 4th old token at 2.5 s cadence; fixed d8b83014b).
- .gitignore `*_token*` had silently dropped candidate61_stale_tokens_950.json from 370d29449; narrow
  exception added (scanned, no secrets).
- Old-external archive pool = the 13 archives of candidate57s_old_external_04 (hashes re-verified).
- NEXT (needs authorization): PLAN step 4 timing/size evaluation at 59,570 PPS / 950 us, strict comparison,
  piggyback, 14,892-vs-59,570 rate comparison.

## 2026-10-14 (afternoon) — candidate61 PLAN step 4 complete on silicon

Philip: "go ahead with step 4". Results: `seg61_02/evidence/STEP4_RESULTS.md` + `step4_summary.json`
(analysis/step4_report.py, tested on committed evidence). Six interleaved blocks (candidate b1, strict b1, ...),
piggyback, 14,892 vs 59,570 PPS. All restored, production observed after each.
- Pooled abs p99: candidate61 timing_only 54 us, combined 51; strict 65 / 51. Lengths and growth exact everywhere.
- ~1.1 ms tails: CORRECTED by the step-5 audit — endpoints emit on time; the delay accrues between Vision's tx and
  rx taps (NIC, link or Tofino), in untimed arms and the strict build alike; component undetermined, ~every 128 exchanges.
- 14,892 PPS abs p99 147 us vs 90.5 us at 59,570 PPS with ~3.3x fewer internal packets.
- Harness fix 598473ebe: precision-only failures no longer re-flagged as hard standards failures (the test fake
  in test_campaign_run had masked it); compare_14892_950_01 retained.
- Not done: repeated SBO cycles per connection (SBO n = 3 per arm).
- NEXT: PLAN step 5 (final review + report).

## 2026-10-14 (late afternoon) — candidate61 PLAN step 5 done: review and report

- Report: `seg61_02/evidence/QUALIFICATION_REPORT.md`.
- Evidence audit (own pcap parser): every length/CRC/frame-layout/CLRT number reproduced; corrected my tail-origin
  claim (transit path, not endpoints). Code review: no blocker; fixed MAJOR (.gitignore re-asserts credential
  patterns after the evidence exceptions; verified with planted .env/credentials.json/id.key) and MINOR 1,4,5,6,7.
- Mistake to remember: `git stash -- .gitignore` inside a diagnostic command stashed my edit; popped and verified.
- Open: transit tail source (~every 128 exchanges), repeated SBO cycles, self-attested checker fields, class-level
  test fakes in test_campaign_run, real relay, promotion (Philip's decision). Nothing pushed.

- 2026-10-18 compiler milestone (Codex; Philip author/committer): implemented the bounded correctness/provenance/runner/config fixes and selected m11_09, source f1de2b30e9f00fb93b20df51c3ddfafd3fcfd18e9b6dfcaadd62146dddbe5af8. Both SDK9.13.1 and9.13.2 compile N11/E12/T11 versus m10 N12/E12/T11, with mirror guards PASS. N stage cut costs +1 SRAM/+1 TCAM; resource changes are measured separately in m11_09/compiler_comparison.json. E source is unchanged; selected T is byte-identical m11_05. Final T structural attempt remains11 stages on both SDKs (stage8 instruction-memory limit); stop that bounded family.
- Milestone evidence: exact final source contention/retry/reset53 tests PASS; current structural tests154 PASS; system3.8 integrated2133 PASS plus4 restricted-loopback failures, all covered by an unrestricted5-test rerun (2137 distinct passing cases,1 opt-in skip). The clean staged suite is the commit gate. Prepared55 configs and the same7 proposed recovery/reference blocks; no hardware activation, full campaign, manuscript changes or push.
- Model qualification remains BLOCKED: m11_09 control_timing01 passed207/211. Preserved model_driver_stall_01.json proves successful N admission, two ordinary unchanged E-action wall-time gaps totaling3.74s, then late T generation106->107 and OP_RELEASE; scheduling/log-I/O cause is an inference. No dataplane fix or weakened check. Next: after the isolated unit-test/commit gate, one unchanged-profile replacement control_timing run, then the remaining eight drivers, v3 enforcement and normal freeze. Original failed01 remains evidence. Historical m10 04/06 accepted dispositions, silicon restart NOT_EXERCISED, inherited host precision FAIL and deferred cleanup deadline remain unchanged.

- 2026-10-18 compiler milestone committed as 183308c63. Author and committer: akekulip <akekulip@gmail.com>; not pushed. The clean staged gate passed 2,185 tests with 21 artifact-dependent or opt-in skips in 663.89 seconds. Workspace and targeted evidence are retained in m11_09/verification. Control_timing attempt02 is the single documented replacement with unchanged source, profile and parameters, isolated from heavy unit tests. Failed attempt01 remains recorded.

- 2026-10-18 model progress: unchanged m11_09 control_timing attempt02 passed 211/211 after the isolated compiler commit gate; smoke passed. Attempt01 remains failed and its traced 3.74-second E-processing stall remains disclosed. The complete nine-driver gate is still pending.

- 2026-10-18 repeat gate blocked at 512/520: the driver only recognized SELECT-to-READ cancellation through raw milestone m10, although the source-bound m11 successor retains that behavior. The admitted 20-byte READ advanced N, while the wrong expectation left the driver TCP sequence stale; seven reset/reconnect failures followed. Evidence: m11_09/model_repeat_expectation_failure_01.json. Source/profile/compiler pins remain unchanged. A repeat-only driver fix makes control_timing02 stale; smoke30/30, packets622/622, rearm399/399 and dup102/102 executed closures remain valid. Next gates: repeat02, control_timing03, select_lifecycle01, contention01 and abort01 after the verified harness milestone.

- 2026-10-18 harness milestone: repeat expectations now resolve the existing source-bound semantic profile before model connection. Regression red reproduced seven branch failures; targeted root verification passed 34 tests, including m11 cancellation, historical m1/m2/m3/m10 behavior, legacy no-milestone behavior and rejected source/profile/label mismatches. Evidence logs are retained in m11_09/verification. Compiler/source/profile pins remain unchanged; model requalification is pending.

- 2026-10-18 harness milestone committed as 91204ef1b (author and committer akekulip <akekulip@gmail.com>, not pushed). Clean staged suite: 2,201 passed, 21 artifact-dependent/opt-in skips, 657.55 seconds. Root targeted profile regressions: 34/34; independent review approved after empty-PORT_MAP compatibility correction. Five required model runs started serially, with no heavy unit suite or compiler overlap; qualification remains pending until all latest closures pass.

- 2026-10-18 model/freeze milestone: exact m11_09 source f1de2b30 remains N11/E12/T11 on both SDKs. All nine latest offline model gates pass with fresh bound dependencies; repeat02 and control_timing03 requalify the corrected helper, and select_lifecycle01/contention01/abort01 complete the gate. V3 enforcement passed; the normal freeze qualifies all six named recovery/reference configs without a diagnostic exception. Original control01 and repeat01 failures, plus stale control02, remain disclosed. Raw trace hashes, reset postcheck, compiler/resource comparison, prepared55-config package and final verification are retained. No hardware activation, full campaign, manuscript changes or push. Baseline Part2 freeze remains an explicit stop gate; silicon restart, host-precision and cleanup limitations remain unchanged.

- 2026-10-18 hardware-supervision milestone (Codex): added Gambit-owned detached controller and independent per-block services, immutable order/state, once-only claims, original 24-hour deadline, shared persistent testbed ownership, restoration refusal and explicit incomplete-coverage reports. Independent review reproduced and corrected cross-campaign concurrency and queued-service deadline defects; rereview passed. Fresh focused verification:27 tests passed. Harmless real Gambit user-service checks passed launcher disconnect, controller loss with independent block completion, duplicate start, unchanged deadline on resume, once-only execution, expiry while active, and failed-restoration refusal. Proofs are retained under seg61_02/evaluation/verification/supervision_20261018. All fixture evidence is supervision-only. Hardware has not started; capture/analysis integration and its qualification remain pending. No manuscript changes or push.

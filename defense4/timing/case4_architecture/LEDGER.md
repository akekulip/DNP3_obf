# Execution ledger

## Checkpoint requested2026-10-06

Philip requested stopping experiments and saving plans/handover for weekly token
limits. All lanes froze. `PLAN.md` now prioritizes transparent forwarding, one
actual READ timing path, ordinary control integration, remaining assembly/lifecycle,
then complete qualification. Full scope stays required and unfinished.

Current wire06/selectedwire04 compile10/7; READ05 compiles6/0; payload forward03
and reverse12 compile10/0 and11/0; expected-phase holder02 compiles12/0; native
receipt04 compiles4/0. Ten current source/artifact milestones freshly verify in
`integration/evidence/verified_milestones_02.json`. Earlier entries below preserve
historical snapshots. Root checkpoint has27+7 passes; independent protocol review
has18 passes/33sealed hashes. Connection owner reports15 binding and17 controller
passes; rollback registry bypass repaired. Four native retry/ACK witnesses remain
unfixed. Current native8b2164a4 is uncompiled; historical authorities need17–18
stages. Assembly producer04 fails460PHV slices; fixed/staged workers fail48.
Shared cache and payload mapping still lack actual live owner pin/no-reuse gates.

No complete9.13.2 build, target-model packets, hardware actions, paper edits or push.
The checkpoint preserves exact failures, repairs and remaining dependency order.

## Earlier execution history

- Base verified: a96a8e32758d498c58a3772ee774596658aad2d9 on main.
- Preserved pre-existing CLAUDE.md modification and untracked user files.
- Tasks1–3: implementation in progress. Task4: independent review in progress,
  with concrete build and handshake defects repaired before integration.
- Qualified full target candidate: none. Local compiler is 9.13.1; deployment
  requires exact 9.13.2 artifacts and actual recorded hardware authorization.
- Dispatch ruling: the assignment explicitly calls for independent parallel lanes
  and main-only lead commits, overriding the generic skill's serial implementation
  and worktree/implementer-commit defaults. Exclusive directories prevent conflicts.
- Task 1: atomic owner CAS compiled (3 ingress), protected eight-byte resubmit
  record compiled (8 ingress), true four-pass recirculation compiled (12 ingress),
  heartbeat/deadline/actual commit primitive compiled (11 ingress). Complete
  association binding and holding integration remain in progress.
- Task 2: ten genuine protocol primitives compiled; actual image production,
  selected-object validation and carving added. Bounded fragment producer is now
  being implemented in a separate owned assembly directory.
- Task 3: five mutually exclusive wire roles coexist in source-current build
  `integration/evidence/wire_roles_03` (10 ingress/3 egress). Its writer and reader
  have separate banks, so this is resource coexistence, not autonomous repair.
  Actual shared-bank composition01 fails with eight CRC PHV slices; the distinct
  byte-serialized CRC experiment also fails with the same eight slices. Shared
  cache excluding carving and a real two-Pipeline Switch are now compiling.
- Structural ruling: eight bytes is the Tofino resubmit limit, not the true
  recirculation limit. A real 16-byte producer envelope carries observed owner
  expected state before a subsequent CAS, avoiding the later snapshot-bank read
  that cycles back to an earlier owner stage. It costs additional internal bytes
  and requires verified private-return topology and lifetime protection.
- Build verifier regressions repaired: absent required binary inventory, changed
  primary source identity, falsified resource counts, changed compiler identity,
  and orphan compiler children after timeout. Multi-pipe evidence now derives
  every context/binary from the actual compiler pipeline inventory. Twelve build
  tests and four model outcome-retention tests pass.
- Source-bound isolated model startup attempt `integration/evidence/model_01`
  failed before packet execution because CAP_NET_RAW is unavailable. No target
  execution, physical service, activation or campaign measurement is inferred.
- Independent review found actual handshake admission/close-qualification defects
  and a fixed-bank dependency cycle. Connection lane owns their repair in a new
  protected four-pass layout, preserving failed handshake01–07 evidence.07 removes
  the physical bank cycle but requires15 stages; structural compression underway.
- Configuration/workload implementation: 30 targeted tests passed; accepted44
  blocks/16,168 attempts preserved. Reviewable package still refuses activation
  because a complete source-bound qualified target/inventory is unavailable.
- 2026-10-06 step 1 (transparent connection path), source-fragment level only.
  Red first: a new `TransparentForwarding` suite (binding tests 15 -> 22) failed on
  native snapshot `8b2164a4…` for the stated reason (valid SYN/SYNACK/final-ACK
  retries and established ACKs ended with `drop_ctl=1`, event `0x01ff` at every
  stage). Repair in `generate.py`: a new `forward_event` table, applied only when
  first-contact matching left `0x01ff`, relabels qualified retry/established ACKs
  (exact owner phase + valid sequence) as private kind 8. Kind 8 takes no owner
  command, no carry and no CAS, advances the claimed work through the normal four
  passes, and leaves as the original. Unqualified or out-of-sequence frames still
  abort and drop without touching the owner. `work_record.p4` and the pinned
  ExpectedWorkRecord strings are unchanged. New snapshot `35bf9aa3…`; binding 22,
  root 27 and controller 17 tests pass.
  Correction to an earlier reading: reverse-direction pure ACKs are not minted
  (`direction_guard` has no (3,2) entry), so they bypass tracking and are forwarded
  untouched; a test now pins that. Not claimed: out-of-sequence duplicate ACKs are
  still dropped.
  Compile `integration/evidence/native_03` (9.13.1): source accepted (0 errors),
  FAILS fit, 19 stages against 12 (native_02 was 18). This is the known
  authority-placement blocker; no architecture search was started.
  Real-packet seed attempt (one, time-boxed): `protocol/egress/source_packets.py`
  stops at the first parser select (`ig.ingress_port` unsupported), and the control
  also needs `work.apply(args)`, range keys and multi-pass recirculation. The
  `integration/core/` packet harness is therefore still absent; step 1 is NOT
  target- or packet-verified.
- 2026-10-07 CORRECTION of the 2026-10-06 step-1 entry above. Its claim that kind 8 "leaves as
  the original" was FALSE at 78a0b50da: `network` had no kind-8 rows, so the private forwarding
  pass was denied on pass 2 (`else if(m.stage!=8w0){deny();}`). The fragment tests never applied
  `network`. Found by the whole-program harness; fixed in b977ad426 (rows for flags 2, 18, 16), with
  `test_network_admits_the_private_forwarding_pass_for_kind_8` so it cannot recur. The binding was
  also restructured there to 11 stages (`native_04`).
- 2026-10-07 native READ (kinds 9 REQ, 10 ACK, 11 RSP) and review fixes, `generate.py` ->
  `native_binding.p4` (sha c2352572...). Source-level and Tofino-compiler evidence only; no model,
  no hardware. Compile `integration/evidence/native_11`: 12 ingress stages (limit 12, critical path
  11, no margin), PHV 51.6 percent, ingress power 16.6, `verify_evidence` all True, static-entry scan
  clean. Failed compiles are kept: native_05 and native_06 (table applied twice), native_07 (condition
  too complex), native_09 (register action with two non-exclusive assignments), native_10 (13 stages).
  * READ: parser, network, guard, owner and first_event rows; owner 5->13->14 (request), nonmutating
    at 14 (ACK), 14->15->5 (response); the request application sequence is stored in its own
    register and the response is matched against it (wrong sequence is denied, owner unchanged).
    READ never enters the SELECT/OPERATE bank chain (`pk>=5` ordering predicates replaced by
    explicit {5,6,7} tests). The terminal builds the 16-byte `tev` (epoch, wgen, t0q, kind, stage 0,
    reserved 0) in front of the unchanged original and sends it to `READ_HANDOFF_PORT` (66,
    PROVISIONAL, gate G-PORTS); `t0q` is the pass-0 timestamp with its low 8 bits zero. A server pure
    ACK that is not an outstanding READ ACK is forwarded unchanged through the kind-8 passes.
  * H1 fixed: epoch register 0 no longer produces an envelope the parser rejects (snapshot writes a
    nonzero sentinel; `first_close` copies the envelope epoch). H2 fixed: a return pass the guard does
    not admit is aborted as kind 255 (work pin returned, denied at the terminal); a removed flow entry
    is denied immediately and QUARANTINES the work pin (no guard, no way to advance it; only the
    controller register reset frees it). Kind-255 passes are no longer gated on validation flags.
  * M1: `split.py`, `split_binding.p4` and `test_split_binding.py` were removed. `split.py` no longer
    regenerated (it needed ' action mint()') and its output described the pre-restructure two-pipe
    layout. `integration/REPORT.md` still mentions it; that text is historical.
  * M2 (pinned, not changed): when the WorkRecord is busy the claimed packet is not bound to a
    private pass. SELECT, OPERATE, response, READ request, ACK and response are forwarded
    transparently in one pass with no owner or bank change. This is silent (no counter) and is a design
    gap: a stuck pin therefore disables binding for all traffic. `test_native_invariants.BusyWorkRecord`
    pins it. A counted event needs a design note first.
  * Known limit shared with SELECT/OPERATE: `client_t` is not keyed on the epoch difference, so the
    client position bank is stored under a foreign epoch (the owner is not).
  * Model finding: native_04 declared `sequence_diff` size 8 with 9 const entries and would not load.
    Every table now has size >= const entries (`test_native_static_entries.py`).

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

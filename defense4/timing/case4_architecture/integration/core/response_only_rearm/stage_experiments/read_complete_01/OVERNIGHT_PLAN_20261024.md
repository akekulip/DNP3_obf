# SEL-751 overnight execution plan — 2026-10-24

Spec: repository-root `Claude_dd7741152_Verified_Assessment_and_Overnight_Command.md`,
with Philip's subsequent packetization corrections. Starting HEAD: dd7741152890efe7f02e153070f0db61c8411e34.

## Binding constraints

Physical SEL-751 only; no software outstation or proxy. Work on main, preserve dirty work and frozen evidence.
Keep READ 91→141 [50,91], 134→158 [24,134]; derive actual SBO 49→60 [28,32] preserving its 32 application bytes.
Preserve N/E/T, blocker timing, queues, ACK normalization and J. SDK/model/load use the same pinned 9.13.2 artifacts.
N/E highest physical index ≤10; T ≤11 occupied stages; pipe-1 egress ≤4. Keep the 100 µs timing criterion.
Only guarded research points {1,3} and established command parameters; successful complete SELECT before OPERATE.
Use existing ownership, frozen wrapper and independent restoration. Unsafe restoration stops hardware.
No reboot, kernel/firmware change, keep-alive masking, main D/J/attacker campaign, manual ownership edits,
weaker restoration, IEEE audit or paper work. Philip author/committer; no co-author; no push.

## Task 1: Trustworthy master and native verdicts

Ownership: active_harness and its tests. Reproduce prefix-only acceptance as failing session tests before repair.
Wire link framing to transport reassembly; validate complete application fragments with all original/padding objects,
both CROBs, IIN errors, CRC errors, sequence/gap/wrap, stale data, deadlines and reconnect state. Fail source binding
explicitly and record actual socket identities. Share completion/validation with baseline. Preserve six raw samples;
write corrected readout separately. Expose additive exact wire/application/frame metadata for campaign consumers.

## Task 2: Real-relay campaign profile and native observation

Ownership: active campaign/HW/VEPA helpers and tests; no P4/generator/master changes. Add explicit endpoint_profile=sel751
with verified .1/master1/dev9 → .7:20000/relay0/dev64 identity, guarded master, no outstation server/log requirement.
Preserve wrapper/freeze/restoration mechanism and hard destination/point guards. Native baseline uses verified
production pass-through, no carving, qualified full captures. Verify actual TCP options and packetization before
candidate selection. Historical sbo_j2 splitting was switch PRE carving; campaign_v2 native SBO provides whole49
offline fixtures. Observe ACK/tail causality if native splitting is found; do not infer causation from ordering alone.

## Task 3: Generator, mapper, lifecycle and model

Ownership: m12_fullsize generator/tests, ctl/seg model drivers and profile helpers; integrator owns reproduce/docs.
Fix shared template selection/nonempty checks; rerun corrected control_timing on existing sealed c30 first.
Reproduce specific c29 busy FIN race before repair; half-close retry_epoch clearing is a hypothesis, not a closure.
Preserve c30 byte identity. Opt-in successor actual two-CROB 45/49 control admission, shape association distinguishing
READ49, application-preserving 49→60 encoding, CRC/checksum, sequence/ACK accounting and J. Compile only once coherent.

Split input support is CONDITIONAL on fresh native evidence. Whole49 is the default; no speculative reassembly.
If required, head-first preserves real head ACK W+28→S+28; one49→60 commit/+11; tail-interior ACKs clamp; W+60→S+49
only after qualified tail publication. Orphan-tail originals reside in existing queue4/loop182 role15, never registers.
One global orphan including invalidated generations; explicit ownership/finite expiry/drop/reset/physical retirement.
No hold-both deadlock or generated ACK. Prove ACK-dependent tail, retransmission, complete delivery and complete timing.

## Task 4: Independent review and exact image gate

Review master/profile/P4 changes before qualification. Pin artifact bundle before model. Run all14 relevant drivers
plus actual SBO, packetization-if-needed and exact FIN regression. Enforce gates fail closed on missing evidence.
Retain physical stage indices/resources/passes. Source/helper/config changes require new identity and affected gates.

## Task 5: Physical qualification

Dry-run/hash/freeze every config and verify helpers in the actual run directory. Record existing standing authorization.
On one selected image: complete mixed/integrity acceptance; four arms (65 READ +64 SELECT +64 OPERATE per arm,
772 exchanges total); mixed/full loss; graceful/reset persistence; reconnect; held OPERATE. All planned connections
must execute. Timing failure does not prevent safe recovery checks; unsafe restore does.
Separate master RTT/CLRT/first/complete timing from native readiness, switch residence and actual J. Require genuine
observation anchors or label missing dimensions unproven; changing separate baseline samples are not same-packet proof.

## Task 6: Retain, reproduce, commit and report

Integrator owns active reproduce.sh, CURRENT/STATUS/COMPLETION_RECORD, ACTIVE_CODE_MAP and WORKING_NOTES.
Retain c30 local provenance/logs and all attempts. Correct premature end-to-end/FIN/global minimum claims without
rewriting raw evidence. Selected clean-worktree reproduce command, hashes, complete denominators, separate per-dimension
verdicts and restoration records required. Commit coherent reviewed milestones with notes; no push.

## Execution ledger

- 2026-10-24: Started implementation after explicit approval of revised plan. Recorded ownership says inactive,
  unsafe_restoration=false; this is not a fresh physical probe. No hardware mutation yet.
- Ruling: execute directly on main and use disjoint parallel implementation lanes, as explicitly required by the
  user/spec; these override skill defaults for isolated worktrees and sequential implementers. Cost if wrong:
  integration conflicts; the integrator owns shared files and commits to contain that risk.
- Baseline verification before implementation: wire_check13/13; generator identity10/10; active master69/69
  (the latter misses reproduced acceptance defects). No software outstation was launched.
- Task1: implemented, reviewed, three review findings fixed, scoped re-review approved. Fresh104tests/135subtests.
- Task2: baseline independent review found NIC offload restore and missing helper freeze pins; fixes implemented,
  scoped re-review pending. No physical traffic yet. Helper writes paused during review/freeze.
- Task3: corrected c30 control_timing04 passes415/415 on original artifacts. c29 fin_busy01 reproduces the specific
  half-close/busy retry stale-FIN failure. c31 compile fails target predicate lowering; c32 separate compile running.
- Ruling: opt-in real-relay profile admits the two specified READ workloads; obsolete G10 range49 is explicitly
  rejected by protocol shape, while c30/legacy modes retain behavior. This prevents length collision with SBO49
  without adding mapper state just to support a third, out-of-profile READ. Cost if wrong: that legacy workload
  is unavailable in the selected relay profile; the limitation and negative regression must be explicit.
- Ruling: fixed guarded command semantics are not expanded solely to preserve a variable-on-time legacy model
  fixture. Lifecycle tests use new/stale request identity plus out-of-profile command negatives. Cost if wrong:
  qualification is bounded to the selected guarded command; it makes no arbitrary-command replacement claim.
- Task2 native02: physical baseline COMPLETE rc0, READ91/134 and SBO49/49 accepted; both statuses SUCCESS,
  independent restore true and ownership safe. Native01 failure/restore retained separately. Current actual
  packetization is whole responses, with SYN40/SYNACK44/DATA32 timestamp-bearing TCP headers. No split code.
- Task3 c32 fails PHV; c33/c34 fit PHV but fail14stage assembly. Next work is timestamp support and justified
  resource/dependency repair. No candidate/model gate or padded hardware claim yet. All attempts immutable.
- Task4 summary gate now requires16drivers forsel751;61unit tests pass. Independent model-retarget review fixes
  are implemented; scoped re-review pending. Final review and real packet gates remain required.

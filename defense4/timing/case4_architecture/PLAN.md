# Case 4 architecture execution

Binding assignment: `../../Codex_Case4_Hardware_Architecture_Prompt.md`.
Current execution: `main`; accepted checkpoints and their exact artifacts are listed below.
Earlier assignment bases are historical.
This directory contains new engineering candidates; it is not deployment evidence.

## Current plan: core functionality and its tests

Philip requested a checkpoint on2026-10-06 to conserve weekly tokens. Stop broad
architecture searches and further packing/annotation experiments. Preserve all
results below; they are historical task assignments, not instructions to resume
parallel exploration. The full required Case4 scope remains unchanged.

The first deliverable is one candidate that forwards real packets through the
entire supported path: establish a connection, process READ with the required
timing, then perform matching SELECT/OPERATE with padding, carving and correct
TCP translation. Actual packet forwarding is the priority. Standalone fits and
passing source-fragment tests are reusable components, not that deliverable.

Use one implementation owner and one bounded reviewer. Reuse the sources listed
in [HANDOVER.md](HANDOVER.md). Resume at the execution checklist below; compile after a meaningful
integration change. Do not rerun unaffected legacy suites or failed layouts.

### Execution checklist — 2026-10-07

Philip's latest SDK instruction: use what the switch already has; no updates.
Read-only inspection confirms installed `p4c9.13.2 (SHA:1baf055)` at
`/home/decps/Downloads/bf-sde-9.13.2/install/bin/bf-p4c` on `decps@10.10.54.81`.
Use `installed_sdk_build.py` for compile-only work in exclusive temporary
folders. It does not install/update software, load a program or change chip state.
Local9.13.1 evidence stays tied to its original compiler. Final qualification
must use the existing switch version, not an upgrade.

Functional forwarding takes priority over a stage-number target. Stage reductions
must preserve actual owner/epoch/Work checks, full32 arithmetic, both insertion
boundaries and both receive-window edges. Twelve occupied ingress stages in one
pipe do not consume another pipe's ingress or that pipe's egress budget.

- [x] Audit current N/T/M/E sources, manifests and claim boundaries. N and T have
  source-current prerequisite model evidence; M/E are absent from the N/T
  composition. M is a resource canary. No complete core path is verified.
- [x] Correct stale plan/handover/README completion claims and the N static-entry
  evidence finder. Its5 targeted tests now pass without the historical discovery
  skip; retain historical aggregate counts with their original identities.
- [ ] **M admission and stage dependencies (staged SELECT fits; full mapping open).** Regress foreign tuple/IP
  mutation, noncontiguous OPERATE publication, zero wire-start rejection and the
  OPERATE ledger's unshifted position. Admit before mutable bank access; reject
  unknown kinds/phases. Separate produce/replay/map scratch and bank access;
  precompute independent window edges. Compile a fresh source-bound candidate.
  Current checkpoint:33 source tests pass; `m_replay_coordinate_02` is a failed15-stage
  candidate (critical11), not a replacement12-stage fit. Shared geometry SALUs
  still delay mapper reads. Full replay-coordinate and byte checks are repaired;
  zero uses a separate success result. Now split
  producer preflight from geometry/ledger activation in the protected composition
  below. Any added private pass must use an actual retained N Work identity and
  a protected expected-phase M reservation; a supplied stage flag is insufficient.
  The first staged SELECT slice now fits: `ordinary/m.p4`, `m_activate_06`,
  source `cf1eaaa4…46575`,10 ingress/0 egress, critical9, six stateful banks.
  Full producer identity and reservation checks precede a once-only activation
  receipt; actual geometry/position completion precedes ledger publication.
  A genuine stamped return alone frees M, with N still pinned and no later M
  bank access. Three activation methods and seven prerequisite methods pass;
  this is source/build evidence, with two spare M ingress stages. The old
  single-pass canary remains a failed15-stage layout. OPERATE, full mapping and
  composed-model validation remain open.
- [ ] **Protected SELECT N→M→E (first byte milestone passes).** Actual external
  handshake and native SELECT35 produce exactly one independent55-byte payload;
  genuine downstream completion retires N/M/E pins. Normal, zero and wrapped
  positions now pass6/6 each on existing switch SDK9.13.2 in
  `installed_select_normal_01`, `installed_select_zero_02` and
  `installed_select_wrap_03`. Exact NF `installed_nf_05` uses12/4, baseline M
  `installed_m_baseline_01`10/0 and E `installed_e_01`1/10, scopes0/1/3.
  [Installed-SDK verification](integration/core/ordinary/evidence/installed_select_verification_01/verification.json)
  binds sources/configuration/artifacts, raw MODEL logs and independent checksums.
  No proof presets or SDK updates. Extended mapper fit remains separate.
  Historical local9.13.1 positions pass6/6 each in `model_split_05`, `model_split_zero_06` and
  `model_split_wrap_07`. This covers first SELECT, not complete SELECT acceptance:
  duplicate/stale loaded-leg model cases and post-M cancellation/loss remain open.
  The accepted split placement is NF pipe0 (`nf_02`,12 ingress/4 egress,
  critical11), M pipe1 (`m3_01`,10/0, critical9), E cache pipe3
  (`e3_02`,1/10, critical7). Pipe2 is available for T. All three programs loaded
  together on model device0 with disjoint scopes; no state/cache proof presets.
  N's ingress still has no spare stage; M has two. E's cache relocation avoids
  the failed14-stage coupled layouts while retaining all14 image banks and
  full identities. The final emitter includes a full32 current-generation receipt.
  [Verification](integration/core/ordinary/evidence/split_verification_01/verification.json)
  binds sources/configuration/artifacts,52 source/config tests, model packets and
  independent checksums. Observed SELECT uses19 ingress visits,6 service egress
  visits and18 private TX records totaling2346 Ethernet bytes, plus the internal
  24-byte completion header. These are model counts, not physical wire occupancy.
  Final shared NF resources are tight: normal32 PHV62/64, SALUs4/4 at7–9
  and table IDs16/16 at1 and10. M peaks at2/4 SALUs and5/16 table IDs;
  E image SALUs occupy4/4 at4–6. The read-only transport leg should use M's
  existing geometry banks and separate typed return, rather than add N banks.
  [Lead resource checks](integration/core/ordinary/evidence/lead_split_verification_01/verification.json)
  record exact final per-stage SALU/table/crossbar/RAM/TCAM and PHV allocations.
- [ ] **Ordinary SBO transport (active).** Fresh source suite71/71 and19 focused
  methods pass, including168 ACK/window pairs; bounded review approves source only.
  Existing switch9.13.2 now builds extended NF `installed_nf_05` at12/4,
  critical11 (failed extension reduced15→13→12), and exact E `installed_e_01`
  at1/10, critical7. All identity/artifact and corrected per-pipeline static-entry
  checks pass. N still has no spare ingress stage. Readonly M now uses genuine
  snapshot/validation visits. Next14 captures actual full32 boundary/position in a
  20-byte snapshot, computes inverse early, then independently rereads full
  publication/identity and both coordinates before release. Paired-coordinate
  forgery and a negative reread canary prove geometry relation alone is insufficient.
  M10/M11 failed bank placement; M12 (`deceea36…94cd`) fails PHV allocation with36
  unallocated slices. Preserve failures and obtain extended M fit before its
  exact installed-version mapper model. Baseline first SELECT passes on9.13.2
  with original M, which does not implement this mapper.
  Source-counted ACK/response mapping is7 ingress visits and408/750 private bytes,
  separate from endpoint bytes and unmeasured until mapper model execution.
  Source parser consumption is at most153 bytes across roles (snapshot response147);
  compiled depth is unverified. Old12-byte snapshots carried400/742 private bytes.
  Latest next15 (`081b4122…fea25`) compares both full32 coordinates inside actual
  readonly scalar actions and requires both genuine grants; source review passes.
  Installed M13 removes the PHV error but fails table placement with no progress.
  Inspect that exact dependency before another repair. Consider unused M egress
  for stateless inverse arithmetic if it avoids the ingress dependency without
  weakening actual publication/identity authority; this alternative is not built.
  First normalize reverse ACK and both
  receive-window edges through actual published M geometry BEFORE N association.
  Require the full current epoch; preserve pins on lost cancellation returns.
  Remove legacy double subtraction and accept the completed SELECT owner state.
  Prove normal/zero/wrap/inside-insertion/zero-window from external frames, then
  forward the matching SELECT57 response. Use a separate next candidate so the
  accepted first-SELECT artifacts remain reproducible. Add matching OPERATE responses and
  OPERATE35→55 with the same object set. Carve57 into exactly two ordered28/29
  packets. Integrate both insertions, ACK clamps, both window edges, full32 wrap
  and sender-driven cached-tail repair. Preserve current replay Work identity
  separately from the cached-image producer identity. Every supported packet
  remains mapped after insertion, including policy-off and retransmissions.
- [ ] **Full timing join.** Route T releases through M197; keep READ unpadded.
  Integrate SELECT-response readiness and actual committed forwarding separately,
  and qualify delayed OPERATE against the current association and its deadline.
  Preserve finite fallback, independent heartbeat and genuine original credits.
- [ ] **Loss/lifecycle and fragments.** Complete supported fragmented OPERATE,
  overlap/resegmentation, reset/FIN/reconnect, exhaustion and no-reuse protection.
  Keep translation and replay until verified connection retirement. Controller
  reset/counter clearing is not a terminal or rearm proof.
- [ ] **Final offline qualification and hardware preparation.** Use the existing switch9.13.2 compiler for a complete
  source-current build, whole-target differential model packets, real schema and
  mutation/rollback inventory. Live loading, physical port/TM/PRE/mirror/pktgen
  changes and traffic retain their existing separate authorization gates.

Use the existing restricted source harness and independent byte/transport/schedule
oracles. Extend it where necessary; the compiled multipipe target model is the
whole-target gate. The first byte milestone SELECT35→55 now passes on the exact split model; it remains partial
until actual READ→SELECT→OPERATE, both boundaries and tail repair pass from external
frames without configured ownership/publication proof. Save current source/include
hashes, compiler/artifact identities, commands, packets/events and comparisons in
fresh evidence directories. Report ingress/egress stage span, dependency critical
path, SALU/PHV/table/crossbar costs and actual private bytes/passes per role.

Optimize M's dependency chain first, seeking spare ingress capacity while adding
functionality. Make only necessary N/T changes. If composition fails, isolate the
reported dependency and try one justified structural repair; preserve failures
and avoid unrelated layout sweeps. Private readiness returns intentionally add
bounded passes: measure their bandwidth and resource cost instead of assuming fit.

1. **Connection prerequisite races repaired; full connection acceptance still open.**
   Current N is `integration/connection/binding/evidence/task1_fix_n_01`
   (source `721fd4b7…`,12 ingress/0 egress,critical11). Actual terminal publication
   consumes full expected-owner and epoch results, including genuine close before
   READ9/10/11 terminals. The exact-source N0/T2 composition `task1_fix_nt_01`
   passes40 model cases in `task1_fix_nt_model_01`; its new cancellation cases
   include diagnostic paused returns, with genuine full-packet races independently
   derived by the source scheduler. Old N05/model34 evidence did not cover those
   races. Coalesced finalACK+SELECT and complete retirement remain mandatory gates.
2. **READ producer cancellation repaired; full timing qualification still open.**
   Current T is `integration/evidence/task1_fix_t_04` (source `52b43d5a…`,
   12 ingress/0 egress,critical12). Every pinned request return checks current
   quarantine/policy; cancelled stages12/13 drain genuine Work and forward the
   original once. Mint follows exact Work qualification; installed ACK receipt
   and minted cookie remain consumed after cancellation, with no anchor/binding
   publication. `task1_fix_t_model_02` passes50 model cases, including paused
   request boundaries, actual reset/policy controls, duplicate/foreign controls,
   old-cookie saturation and heartbeat/original debit. Full source suites pass
   N84(one compiler-evidence discovery skip) and T103; unaffected M19/controller17 remain prior results.
   The pre-review T selector pair12/12→11/11 is historical. Mandatory race guards
   make current T12/12; stage4 now has1 SALU/9 logical tables/63 ternary-crossbar
   bytes versus old0/9/59, an explicit resource concern requiring bounded review.
   No rearm authority is added. Model commit order proves no physical gap,
   heartbeat/drain bound or normal-path priority. Complete validated READ join,
   all timing populations and hardware gates remain open.
3. **Complete the ordinary unfragmented control path.** *(In progress 2026-10-07: pipe placement
   decided and model-verified feasible (`integration/core/STEP3_DESIGN.md`); N already binds
   SELECT/OPERATE/response to the live owner with the correct per-exchange ACK offset and
   busy-record drop-and-count. Role M's mapping/geometry/ledger core compiles at 12/12 stages in
   pipe 1 (historical M source), checked against the transport oracle. The corrected
   current `integration/core/m/m_skeleton.p4` has33 source tests but fails15 stages;
   use protected staged integration above. A separate staged M PREPARE candidate
   now builds35→55 privately; the protected E-ready/commit/geometry join,
   descriptor/carve decision and exact-byte replay remain unfinished. Task1 changed
   only the old canary's receiving ports196/197. Its old12-stage fit does not
   qualify current source.)* Bind validated native
   SELECT/OPERATE and successful matching response to that same live authority;
   integrate35→55 production,57→[28,29], payload mapping and shared replay banks.
   Require actual owner/work pin before cache access and no reuse until terminals.
   The configured proof/object/geometry seams must disappear from that path.
4. **Close the remaining required loss/lifecycle cases.** Add supported fragment
   assembly and full overlap/resegmentation/capacity coverage. Finish reset,
   reconnect, exhaustion and reuse protection across every asynchronous return.
   Keep translation and replay alive until verified connection retirement even
   after timing retires or policy disables new insertion. The existing
   assembler layouts do not fit. Make one separately justified structural change
   only after the ordinary path has executable source-current integration evidence.
5. **Qualify the complete program.** Run differential whole-target packets when
   the target model is legitimately available; obtain a complete exact9.13.2
   build and real schema/mutation inventory. Only then prepare/review the exact
   hardware package and request any missing live authorization. Campaign remains
   44blocks/16,168attempts, no implicit calibration or retries.

Two insertion boundaries, both window edges and full32 sequence arithmetic belong
in step3, not a later optional optimization. A single supported connection and
unfragmented requests can establish an intermediate path; bounded capacity and
fragment/lifecycle coverage remain mandatory for final completion.


Task1 evidence index: [integration/evidence/TASK1_VERIFICATION.json](integration/evidence/TASK1_VERIFICATION.json).
The direct SELECT native-end expression removes a source dependency, but its paired
N comparison remains12 stages/critical11; no N stage gain is claimed. Role M and
steps3–5 remain unfinished. Campaign accounting remains44 blocks/16,168 attempts
under18,360, with no acquisition or extra retries.

## Tests and acceptance for each step

| Step | Required tests | Acceptance |
|---|---|---|
| 1. Connection transparency | SYN, SYNACK and final-ACK retries; coalesced final ACK+SELECT; established pure ACKs in both directions; foreign tuple/epoch; malformed frame; stale/duplicate work return | Valid supported traffic is forwarded with correct bytes; unrelated traffic cannot change the active owner; no fake terminal or leaked work credit. All four retained retry/ACK witnesses become repaired regressions. |
| 2. READ timing | Early, late and absent response; D_A5/10/15/20ms; delayed actual ACK commitment; one/both blockers lost; independent heartbeat; duplicate originals; policy-off while held; clock wrap | Actual ACK/response originals forwarded once, response retains the full999,936ns committed gap, fallback is finite, and actual qualified terminals permit cleanup. Eligibility is separately reported from physical departure. |
| 3. Control path | Native35→55 exact SELECT and OPERATE bytes; real and inert CROB objects/statuses match; response57→ordered[28,29] reassembles exactly; wrong application/TCP/tuple association; both insertions; ACK clamps/both window edges/wrap; lost inserted tail | One supported successful SELECT→OPERATE exchange completes through the actual validator, live owner, image producer, mapper and renderer. CRC/checksums match an independent codec; replay repairs the lost tail using sender retransmission, without a manufactured ACK. |
| 4. Loss and lifecycle | Fragment boundaries/reordering/duplicates/conflicting overlap; resegmentation; stale cached descriptor; reset/FIN/reconnect; policy-off after insertion; capacity/generation exhaustion; delayed old original/producer returns | Exact repair and translation survive timing retirement/off until connection retirement; no stale publication, slot overwrite, premature reuse, early OPERATE or silent corruption. Unsupported outcomes are explicit. |
| 5. Qualification | Whole-target differential packets/events; source-current9.13.2 production build; real schema/inventory/rollback checks; authorized packet/timing campaign | Complete source fits, whole-target behavior passes, and the exact reviewed hardware package is qualified. Hardware measurement/physical inertness remain separate evidence gates. |

Complete one `integration/core/` multipipe candidate and its end-to-end packet test harness
as integration proceeds. A restricted N ingress source harness already exists;
the full N/M/T/E candidate and whole-target harness remain absent. The harness should consume
real frame bytes, drive the full parser/control/deparser, and compare packets plus
owner/terminal events against the existing independent codecs/transport oracle.
Include retained failure witnesses as negative regressions. Avoid another Python
implementation of the proposed P4 as the only expected-output reference.

Run targeted tests for the changed behavior first, then compile that integrated
source into a fresh evidence directory. Use legitimate target-model packet
execution when available. The local namespace model now runs source-current N/T functional cases;
source interpreters and component fits still cannot substitute for whole-target
execution. No complete-program target verification is claimed.
Run real pinned OpenDNP3/TCP loss tests against the completed path when the harness
supports it; historical software socket success does not qualify new target code.

For each step save only the necessary evidence: source/compiler identity, command,
actual packet/event outputs, expected comparison, failures/skips and stage/resource
result. If compilation fails, isolate that integration dependency and test one
justified structural repair; do not start unrelated variants. Preserve failed
runs. Instrumentation, efficiency tuning and publication work follow functional
correctness, rather than expanding the first deliverable.

Existing focused commands, from this directory:

```sh
python3 -m unittest discover -s integration/connection/binding/tests -p 'test_*.py' -v
python3 -m unittest discover -s tests -p 'test_*.py' -v
python3 -m unittest discover -s integration/controller/tests -p 'test_*.py' -v
```

The composed core harness must add all roles and target execution; these existing commands
alone do not establish it. [HANDOVER.md](HANDOVER.md) records exact current sources,
evidence and unresolved defects so the next session can resume directly.

## Shared contracts

Connection ownership lasts through verified connection retirement. Timing ownership
is a separate non-wrapping 16-bit generation, with expected-phase transitions.
Translation and exact image replay survive timing retirement, policy disablement,
capacity refusal and command quarantine. Full TCP sequences and clocks remain 32-bit.
The clock is low-32 nanoseconds masked to 256 ns; the committed gap is 999,936 ns.
Timing inputs are D_A 5/10/15/20 ms, readiness 30 ms, heartbeat requested 100 us,
policy cap 40 ms. Internal commitment and physical departure are different events.

Cross-pass producer identity is an eight-byte WorkRef: connection epoch32 and work
generation32. Resubmit carries at most those eight bytes. True recirculation may
carry a16-byte envelope containing the actual expectedCell32/event16/reserved16,
and immutable decoy/renderer/assembly extensions add their actual bytes separately. These transfer sizes
must be counted; they are not an expansion of the Tofino resubmit limit.
The identity references a protected work record, never an asserted validity flag.
Reset quarantines outstanding originals AND producers. Publication requires the
current work identity after every write; reuse requires actual terminal credits.
Policy-off forwards held ACK/response originals, aborts unsent OPERATE, and debits
actual terminal outcomes independently of the holding enable flag.

Required native SELECT/OPERATE35 becomes55 with a valid configured inert CROB.
Response57 becomes ordered [28,29]; historical49/[28,21] is a separate profile.
Exactly two insertion boundaries, exact-byte repair, both window edges, wrapped
sequence arithmetic and supported fragment assembly remain required. READ remains
supported without control padding. No CPU packet processing or proof seam is a final
implementation. No frozen source, existing evidence or paper file is edited.

## Earlier parallel tasks — reference only

These describe the completed investigation lanes. Do not restart them; use the
current core-functionality sequence and testing criteria above.

### Task 1: Ownership and timing primitives

Own `ownership/` exclusively. Implement genuinely new small Case4-only TNA
experiments for canonical immutable cookie placement, owner-qualified expected-phase
transition, separate work/original retirement credits, deadline and independent
heartbeat recovery. Do not concatenate old ingress or rename packed/scalar builds.
Compare same-pipe and bounded resubmit layouts, preserving original-packet resubmit
semantics and exactly eight bytes. Record a concrete cross-pipe authority/handoff
candidate or a verified topology/capability rejection. Compile executable P4 locally
against available 9.13.1. Every run uses a fresh directory and exact source hashes.
Independent reference tests must exercise stale scans, reset/rearm work returns,
policy-off terminal debit, cookie exhaustion, lost blockers and OPERATE deadline.
Report resource results and limitations; compile does not prove queue service.

### Task 2: Mapping, reconstruction and validation primitives

Own `protocol/` exclusively. Implement smallest meaningful new Case4-only executable
TNA mapping primitive grouping independent calculations, forward completion instead
of final drop, full32 sequences and both window edges with inverse tail clamp.
Compare exact image words versus canonical-object reconstruction including all
phase-specific bytes; compile real materialization/replay experiments. Reuse existing
verified byte codecs as libraries, not their old giant P4 composition. Build actual
full-frame/profile validator/padding/carving and supported fragment producer as
resource-conscious candidates where possible. No proof flag or asserted validation
is a complete producer. Include independent expected-byte tests and malformed input,
two boundaries, resegmentation, wrap, disablement and exact cached-tail recovery.
Preserve both current retransmission TCP headers and committed application image.

### Task 3: Integration, evidence and workload

Lead owns `build.py`, `integration/`, `tests/`, `README.md` and the ledger. Build
source-bound immutable evidence, count real resource/pass/bandwidth costs for the
bounded declared workload, integrate only compiler-supported meaningful primitives
incrementally, and retain every failed structural composition. Rank required behavior,
complete fit, worst transform passes, bandwidth, resources, complexity, simplicity.
Create exact-artifact/schema controller and inert deployment package only for a
complete candidate; never enroll an incomplete probe as qualified. Attempt isolated
model only with legitimate current permissions and preserve its failure evidence.

### Task 4: Independent review and final verification

Rotate implementers to review a different lane, with exact diff/report/requirements.
Resolve concrete correctness issues before dependent integration. Final evidence
distinguishes implemented/compiled/composition compiled/model verified/loaded/
configured/measured. Keep unqualified behavior explicit if structural alternatives
fail, including the precise irreducible conflict and additional capability needed.
Update canonical engineering handover, commit only owned changes using Philip as
author AND committer, no attribution trailers, no push. Physical activation and any
traffic remain outside this assignment's authorization. Hardware campaign remains
44 blocks/16,168 attempts, without implicit extra calibration or retries.

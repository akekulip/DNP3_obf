# Case 4 architecture execution

Binding assignment: `../../Codex_Case4_Hardware_Architecture_Prompt.md`.
Current execution base: `834372cbb`, main; earlier assignments below are historical.
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
- [ ] **M admission and stage dependencies (active).** Regress foreign tuple/IP
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
- [ ] **Protected SELECT N→M→E.** Extend N Work with an atomic transition from
  phase3 to DOWNSTREAM_PENDING; only the winning handoff emits. Carry the full
  WorkRef, actual expected owner and captured immutable decoy fields. M admits
  each full identity once and constructs native35→55. E completes all image
  words before publishing its identity tag and returning a genuine ready packet
  privately to N. N rechecks current owner/epoch/cancellation and commits release;
  M activates the relevant geometry and replay ledger before E emits. Actual downstream completion alone frees
  Work after the final dirty write. Lost completion keeps the pin. Deduplicate
  prepare, ready, commit and emit separately. Before commit cancellation aborts;
  after commit work drains without reuse. Incomplete publication cannot forward
  supported traffic with untranslated TCP values.
  N prerequisite exists in `integration/core/ordinary`: retained
  `n_local_abort_02` closes the pre-M abort race. Current `n_ready_03`, source
  `1be0eb09…33b8b`, fits12/0, critical11. Actual E0514 first qualifies full active
  generation/epoch/owner without Work mutation; genuine0614 then wins Work5→7
  and the late full owner CAS9→17 before handing0714 to M. Cached owner9 stays
  separate. The completed N/M/E preparation suites have25 source methods;
  M activation, E endpoint emission/terminal, post-M abort and subsequent ACK
  mapping still need integration; the checklist item remains open.
  M's separate PREPARE slice now constructs the exact55-byte payload from that
  actual N handoff and emits privately. Current `m_prepare_03`, source
  `2475f93b…ec9f3`, compiles12/0, critical8; three source packet tests verify
  independent payload bytes and actual source deparser checksums. Its format2
  prefix is24 bytes, preserving separate current/cached full identities.
  E PREPARE `e_prepare_03`, source `55c2bae9…06589`, compiles9 egress stages
  (1 ingress diagnostic drop stub), critical6. Three source tests verify all14
  image words, full identity, duplicate refusal and missing-store refusal.
  Actual final placement is stores3–6, owner/tag7, private ready8.
  M geometry activation and target-model endpoint emission
  remain unfinished; this is not complete SELECT acceptance.
- [ ] **Ordinary SBO transport.** Add matching SELECT/OPERATE responses and
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
- [ ] **Final offline qualification and hardware preparation.** Obtain a complete
  exact9.13.2 build, whole-target differential model packets, real schema and
  mutation/rollback inventory. Live loading, physical port/TM/PRE/mirror/pktgen
  changes and traffic retain their existing separate authorization gates.

Use the existing restricted source harness and independent byte/transport/schedule
oracles. Extend it where necessary; the compiled multipipe target model is the
whole-target gate. The first byte milestone is SELECT35→55; it remains partial
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

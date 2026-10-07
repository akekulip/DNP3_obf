# Case 4 architecture execution

Binding assignment: `../../Codex_Case4_Hardware_Architecture_Prompt.md`.
Base: `a96a8e32758d498c58a3772ee774596658aad2d9`, main.
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
in [HANDOVER.md](HANDOVER.md). Resume at step1; compile only after a meaningful
integration change. Do not rerun unaffected legacy suites or failed layouts.

1. **Restore a correct transparent connection path.** Fix native binding's SYN,
   SYNACK/final-ACK retries and established pure ACKs: the retained source currently
   turns them into event01ff and drops them. Keep malformed/foreign traffic from
   mutating an owner, while preserving ordinary supported forwarding. Use the
   complete-byte witnesses in `ownership/review/counterexamples.py` as the red
   regressions. Retain full expected-phase/generation qualification. This is the
   immediate next coding task; no new architecture search comes before it.
2. **Complete one real READ timing path.** Join the actual READ validator to the
   live connection identity and compiled expected-phase holder. Capture actual
   request arrival, preserve wire ACK observation before inverse mapping, and
   forward the actual released ACK/response. Prove independent heartbeat/fallback,
   full gap after actual ACK commitment, off-drain and actual terminal credits.
   This is the first complete timing milestone, not completion of control sizing.
3. **Complete the ordinary unfragmented control path.** Bind validated native
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

## Tests and acceptance for each step

| Step | Required tests | Acceptance |
|---|---|---|
| 1. Connection transparency | SYN, SYNACK and final-ACK retries; coalesced final ACK+SELECT; established pure ACKs in both directions; foreign tuple/epoch; malformed frame; stale/duplicate work return | Valid supported traffic is forwarded with correct bytes; unrelated traffic cannot change the active owner; no fake terminal or leaked work credit. All four retained retry/ACK witnesses become repaired regressions. |
| 2. READ timing | Early, late and absent response; D_A5/10/15/20ms; delayed actual ACK commitment; one/both blockers lost; independent heartbeat; duplicate originals; policy-off while held; clock wrap | Actual ACK/response originals forwarded once, response retains the full999,936ns committed gap, fallback is finite, and actual qualified terminals permit cleanup. Eligibility is separately reported from physical departure. |
| 3. Control path | Native35→55 exact SELECT and OPERATE bytes; real and inert CROB objects/statuses match; response57→ordered[28,29] reassembles exactly; wrong application/TCP/tuple association; both insertions; ACK clamps/both window edges/wrap; lost inserted tail | One supported successful SELECT→OPERATE exchange completes through the actual validator, live owner, image producer, mapper and renderer. CRC/checksums match an independent codec; replay repairs the lost tail using sender retransmission, without a manufactured ACK. |
| 4. Loss and lifecycle | Fragment boundaries/reordering/duplicates/conflicting overlap; resegmentation; stale cached descriptor; reset/FIN/reconnect; policy-off after insertion; capacity/generation exhaustion; delayed old original/producer returns | Exact repair and translation survive timing retirement/off until connection retirement; no stale publication, slot overwrite, premature reuse, early OPERATE or silent corruption. Unsupported outcomes are explicit. |
| 5. Qualification | Whole-target differential packets/events; source-current9.13.2 production build; real schema/inventory/rollback checks; authorized packet/timing campaign | Complete source fits, whole-target behavior passes, and the exact reviewed hardware package is qualified. Hardware measurement/physical inertness remain separate evidence gates. |

Implement one `integration/core/` candidate and its end-to-end packet test harness
as the integration work proceeds; neither exists yet. The harness should consume
real frame bytes, drive the full parser/control/deparser, and compare packets plus
owner/terminal events against the existing independent codecs/transport oracle.
Include retained failure witnesses as negative regressions. Avoid another Python
implementation of the proposed P4 as the only expected-output reference.

Run targeted tests for the changed behavior first, then compile that integrated
source into a fresh evidence directory. Use legitimate target-model packet
execution when available. The present CAP_NET_RAW startup failure is an explicit
test gap: source interpreters and compiled resources cannot substitute for full
pipeline execution. Do not mark a step target-verified while that gap persists.
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

The future core harness must add packet-level execution; these existing commands
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
and assembly snapshots add their actual bytes separately. These transfer sizes
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

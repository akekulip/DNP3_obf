# Integration workload and guarded preparation

## Task1 fix-round source-current prerequisites (2026-10-07)

Current identities are in [evidence/TASK1_VERIFICATION.json](evidence/TASK1_VERIFICATION.json).
N `connection/binding/evidence/task1_fix_n_01` SHA721fd4b7… compiles12/0,
critical11; T `evidence/task1_fix_t_04` SHA52b43d5a… compiles12/0,critical12.
N's direct expression still has no measured total-stage reduction. The earlier
T separate/common selector12→11 comparison remains historical; new mandatory
cancellation guards consume that gain. Current T stage4 is1 SALU/9 logical
tables/63 ternary-crossbar bytes versus old0/9/59, an explicit resource concern.
Source/include/compiler/artifact/resource identities and all static entries pass.

N consumes the full expected-owner/epoch result at terminal publication after
actual close. T rechecks quarantine/policy before request mint/receipt/association
boundaries, keeps cancellation on stages12/13, drains real Work and forwards the
original once. Already installed ACK receipts and consumed cookies are retained;
no counter rollback, new anchor or binding appears after cancellation.

Current composition `task1_fix_nt_01` binds exact N0/T2 sources. Models pass40
N/T cases (`task1_fix_nt_model_01`) and50 T cases (`task1_fix_t_model_02`).
New model races use explicitly seeded paused private-return boundaries; source
schedulers independently derive genuine in-flight races. The model has actual
reset/FIN packet controls and no front-port-loop bitmap. Full source suites pass
N84(one compiler-evidence discovery skip) and T103. That skip misses the current
N evidence directory; the coalesced finalACK+SELECT source test passes, while
complete target acceptance remains open. M19/controller17 are unchanged prior
results. Final logs are in `evidence/task1_fix_verification_01`. Old34/35 model
results lacked these races and are retained separately, never transferred.

Model clocks/padding remain functional limitations: ordered ACK/response commits
do not establish normal deadline priority, physical gap, heartbeat period or drain.
The raw-close parse token is epoch-derived, not actual Work generation. All
compile/test/model failures remain retained, including first T race layout13-stage
failure and a T driver filter failure after18 cases. No rearm/deployment authority
or hardware activity is added. M is still a12-stage receiving-port canary; full
M, Case4, retirement/loss and physical qualification remain open. Campaign44
blocks/16,168 attempts with18,360 ceiling remains unchanged and unacquired.

This slice implements offline accounting, an inert controller package planner, and new protected connection/context experiments.
It does not qualify a complete target. The production qualification registry is
empty, and there is no device connection or mutation interface. All paths below
are relative to `defense4/timing/case4_architecture/` unless stated otherwise.

## Executable accounting

`integration/performance/accounting.py` loads the unchanged campaign declarations
and calls their existing validation and budget functions. It recomputes, rather
than trusting a stored summary, **44 blocks and 16,168 attempted exchanges within
the 18,360 ceiling**: READ 12,868, SELECT 3,240 and OPERATE 60. Each arm contains
6,434 READs, 1,620 SELECTs and 30 OPERATEs. Warmups, state reads and attended SBO
phases remain included. The unused 2,192 attempts are not allocated.

Every declared trial interval is 400 ms. The 60 SBO pairs each occupy one trial
unit with two protocol phases; there are 16,108 trial units and 6,443,200 ms of
declared spacing. The existing conservative duration budget remains
14,571,200 ms including timeouts and setup. This accounting creates no acquisition
or extra retries. Native TCP repair packets are separate packet work.

Ethernet serialization includes IPv4/TCP headers of 20 bytes each, the Ethernet
header, FCS, minimum frame padding, eight preamble/SFD bytes and twelve IFG bytes.
The fixed successful-exchange scenario counts both external links, one pure ACK
on each link, and the complete response. READ uses request20/response49 and its
separate [28,21] carve; control uses native request35/response37 and transformed
request55/response57/[28,29]. TCP options, VLANs, combined ACKs and connection
handshakes are outside this fixed scenario.

| Operation | OFF bytes across both links | Case4 bytes across both links |
|---|---:|---:|
| READ | 618 | 696 |
| SELECT or OPERATE | 624 | 762 |

The declared fixed scenario totals **10,741,176 L1 bytes**. Dividing by declared
spacing yields about 13.34 kbit/s across both links. These are normal-profile
serialization calculations, not observed traffic or a loss bound. SBO can burst
between its two phases without 400 ms spacing. Retransmissions, fragments,
handshakes, holding and recovery add costs; the worst campaign bandwidth remains
unavailable.

The executable keeps separate fields for normal transform passes, extra native
repair/fragment packet scenarios, holding circulation and heartbeat. A path pass
count is the total traversals for one complete named message/event, including
any replica work; it must not omit carved pieces. Internal transfers require an
explicit link, frame size and count. Original-preserving resubmit retains its8-byte
limit. True recirculation separately records16-byte prefixes or48-byte assembly
snapshots. Prefix bytes are added before Ethernet minimum padding; already serialized
frame sizes cannot also declare a prefix. Missing16/48-byte costs are not charged as8. Missing path/transfer/count inputs remain
`null`; an explicit empty transfer list means a documented zero-transfer scenario.
Extra packet scenarios do not increment application attempts or become measured
loss frequencies.

Holding needs actual blocker multiplicity, frame size, achieved loop period and
hold duration. These inputs are unavailable for the full target. A test-only
scenario of three 64-byte blockers, a 2-us loop and a 40-ms hold yields 60,000
circulations per enabled exchange. It illustrates why holding service can dominate
normal endpoint traffic; it is not a physical bound. The 100-us heartbeat request
is separately 10,000 packets/s; assuming a minimum 64-byte frame would request
6.72 Mbit/s. Actual heartbeat size/service, per-link capacity, queue competition
and burst release remain unavailable. Holding loopbacks retain their egress
bypass; accounting does not route them through egress.

## Source-bound primitive resource snapshot

`performance.load_resources` rechecks current source, retained includes, compile
log, current compiler binary, required schema/context/binary artifacts, and all
resource-report hashes. It independently derives the resource counts from the
actual context and refuses manifest underreporting or missing binary identities.
Every compiler-declared pipeline retains its own context/binary and PHV inventory;
aggregate maxima do not imply shared state or actual physical handoff ports.
Explicit historical mode can report a verified retained snapshot when the current
source changes; that snapshot cannot qualify current source. SDK artifacts remain
local under ignored `out/`; a fresh checkout must compile with the installed
licensed SDK before verification. PHV summaries retain container class, field
placement, bit ranges, parser/deparser accesses and observed MAU stage spans.
They do not prove complete alignment/lifetime feasibility by summing bits.

The exclusive output `integration/performance/evidence/workload_01.json` captured
these local p4c 9.13.1 (e558d01) results, each independently artifact-checked by
the accounting code at generation time:

| Primitive snapshot | Ingress / egress stages | Critical path | Stateful layout | Report container bits / slices |
|---|---:|---:|---|---:|
| `ownership/evidence/owner_cas_05` | 3 / 0 | 3 | One 32-bit cell, one slot | 768 / 52 |
| `protocol/evidence/padding_02` | 11 / 0 | 6 | None | 1,488 / 142 |
| `protocol/evidence/exact_03` | 7 / 0 | 3 | Fourteen 32-bit image banks, two slots each | 1,408 / 111 |

Exact primary source hashes, retained include hashes, report hashes and container
placements are in the JSON and original manifests. Primary hashes are
`077ccb16a4cdfa78fc5bdc7a77b89d8288403645b86ae88a9b2ff7122e1dc47b`,
`5331f317b7a730964496c9d9845a859ffb0203c95aa9de385c50e5882d736914`,
and `b7de4426f1fe35c0de5c3182f26669c24beaf563bed7e6087aa318bde139f0c2`.
Each primitive has one ingress processing pass and bypasses egress. Padding takes
a 35-byte payload to 55 bytes, i.e. 113 to 133 L1 bytes per external transmission.
The replay primitive takes a validated one-byte tail to a 55-byte committed image,
i.e. 84 to 133 L1 bytes. The ownership wire is diagnostic, not a DNP3 endpoint path.
No internal handoff is used in these individual primitives. These costs cannot be
added to establish a full composition fit, producer lifetime, autonomous loss
repair or sustainable throughput. Exact replay's image is control-plane published
in the primitive; the autonomous qualified image producer remains required.

## Architecture comparison and remaining capabilities

Executable input examples under `integration/performance/examples/` keep the
complete message costs unknown for all three families. The pipe numbers in the
cross-pipe example are a topology hypothesis, not a configured port assignment.

| Family | Ownership and handoff requirement | Established cost | Decision boundary |
|---|---|---|---|
| Dedicated same pipe | One authority; full validation before mutation; original/work conservation and qualified publication | Individual one-pass ownership, padding and replay snapshots above | Full lifecycle, validator/image producer, mapping, carving and recovery composition still required |
| Bounded extra pass | Same authority; original-preserving8-byte resubmit WorkRef or actual16-byte recirculation envelope referencing a protected work record; recheck publication identity after writes; actual work terminal credits | Four-pass pure-handshake recirculation fits12/0; full transform/internal bandwidth unknown | Implement and compile bounded return paths; prove no stale write/publication/reuse and preserve original resubmit semantics |
| Cross pipe | Pipe-local state; physical ingress/egress handoff ports; explicit serialized typed envelope; explicit return to authority and failure/backpressure/credit handling | Ports, serialized handoff sizes, return service and full resource costs unknown | No shared-register assumption; require actual topology and capability evidence before selecting this family |

No family wins on complete correctness/fit yet. A compiler PASS for a diagnostic
component does not supply missing ownership, ports or queue service. Native
sender-driven tail replay and translation after policy-off remain required until
verified connection retirement in every family. Frozen sources, old controller
paths and the declared attempt budget are unchanged.

## Protected connection and selected-context experiments

`integration/handshake.p4` is generated by `integration/connection/generate_handshake.py`.
It validates actual network bytes, full tuple, MSS-only exact flags and full32 TCP
positions before connection owner mutation. Dropped/unconfigured ports cannot mint
work. A16-byte private prefix carries epoch32/workGeneration32/expectedCell32/event16/
reserved16 and preserves the original inner Ethernet/IP packet. Parser checks reject
stage zero, unknown event/stage, nonzero reserved, zero identities and a relabelled
original. FIN/RST require the exact supported sequence/ACK relation and quarantine
pending producers. There is no verified retirement/reuse or finite lost-work recovery.

The fixed stage ordering is WorkRecord then sequence/epoch banks then owner CAS.
Four passes reserve/snapshot, write/claim, publish and actually debit the terminal
WorkRecord. Banks require the return opcode and atomic matching work generation;
a read-only phase observation cannot authorize writes. Epoch stores return their
post-write value. The full-word owner CAS consumes its expected value from actual
recirculated bytes, avoiding the old snapshot-register placement cycle.

`integration/evidence/handshake_14` is a retained source-bound p4c9.13.1e558d01 PASS,
12 ingress/0 egress stages, criticalpath12, six stateful tables. Primary SHA is
`6cc2765c96af138d56c658902abd94bef1432fb5df95cae346b5b99695917c14`;
owned WorkRecord SHA is `500c0b69db371393fc3b578baef6a24a9f33caf5eacc3f4527dff7eb8b192124`.
Earlier01–04 failures remain intact. New05/06 isolated action/parser limits;
07/09 removed the old placement cycle but needed15/14 stages.10 fit12;11 failed
constant-derived parser selects,12/13 failed parser match-register lifetimes.
14 uses sequential prefix-word extraction and the existing network gate for actual
kind/flags qualification. Compiler logs retain warnings; a compile is not packet
execution. Target coalesced finalACK+SELECT remains missing. The independent byte
oracle supports it and explicitly does not transfer that support to the target.

`integration/connection/selected.p4` is a separate autonomous context experiment.
Actual native35 SELECT network/profile/allthree CRCs precede WorkRecord claim.
Stored real index/code/repeat/on/off, link/TCP/app context and configured decoy are
separate immutable fields; a controller expected-object table cannot publish them.
`selected_02` retained SELECT-only compiler PASS11/0, criticalpath8,16 stateful tables,
SHA `aa42657dbab1a0948c2d4f6a56814d4004502c5e3214cadf9942f705490e5217`.
That historical component uses a transaction nonce equal to allocated work generation,
not a source-produced live connection epoch. It has no response/OP association or
verified reset/reuse and is not current full-component fit.

The current extension decodes actual57 RESPONSE, validates allfour CRCs, both status
bytes and IIN, compares exact saved real/decoy objects, app sequence, reciprocal TCP
and link tuple and TCP positions, then records matching response acceptance. A native
OPERATE must match the saved objects and the explicit next app sequence. `selected_22` now compiles with local p4c9.13.1 (e558d01): **12 ingress /0 egress
stages, critical path11,12 stateful tables**, source
`12722350366d5c085c4152204ec98f83da05294472182e666fc8b933254761b3`.
Six paired64-bit cells and two scalar32-bit cells retain the14 saved words. Each
paired comparison checks both complete words and returns one mismatch result.
Application comparison preserves the exact next sequence, including CF→C0.
Acceptance retains an immutable full32 generation: initial phase4, matched
response phase5, matched OPERATE phase6. Phase6 is an observed Boolean, **not an
event count**; no trailing counter stage is counted as behavior. The response
compares wire ACK=native end+20 before reverse mapping; the independent reference
uses native ACK after mapping. This composition boundary remains explicit.

Actual source/artifact/compiler/report verification passes for selected22, while
`full_target` remains false. Its manifest binds BFRT/context/binary and raw report
hashes; proprietary outputs remain local. Preserved attempts03–13 failed
structural/PHV constraints. selected14 placed17 stages and selected21 placed13,
both above the12-stage limit. Attempts15–19 retain generation/SALU/return-selector
failures; selected20 was interrupted after a generator syntax error left the old
source unchanged, and has no completion manifest. No earlier fit is transferred
to the current source.

**The frozen handshake14/selected22 WorkRecord has a return limitation:** it
compares generation but accepts any stored phase below4. Duplicate or reordered
returns with the same generation can consume a later phase. Their compiler fits
therefore do not establish forked-return safety or safe retirement/reuse. New
binding work uses a separate frozen ExpectedWorkRecord, SHA
`26b2019ec6e549e22e98cf8361ee208952bd1cc94021d2ea56b9f8bc88571ef2`,
whose return action compares generation and the emitted expected phase together
in the same atomic cell. Inspection does not advance it; terminal requires an
actual expected-phase3 return. Earlier source/artifact evidence is unchanged.

Prefix epoch/work disagreement cannot advance work. This isolated source still
uses work generation as a transaction nonce, **not the installed connection
epoch**. It has no verified reset/reuse, two-slot producer, transformer, scheduler
or coalesced finalACK+SELECT composition. A fresh binding experiment must supply
actual connection authority, pins before writes, qualified publication and real
terminal/retirement accounting; selected22 evidence remains frozen.

`reference.py` and `selected_reference.py` independently validate real packet bytes
and model current connection ownership, stale-work refusal, reset during writes,
exact response statuses and SELECT→OPERATE relations. Their packet tests and narrow
source-SALU/table checks do not prove full P4 parser/queue execution. In the oracle,
physical connection epoch comes from actual SYN/SYNACK/finalACK state. In the isolated
selected P4, that producer composition remains missing; no supplied flag repairs it.

## Actual native connection binding experiments

`integration/connection/binding/generate.py` combines actual SYN-produced
connection epoch, the single existing owner, actual native35 SELECT (including
coalesced finalACK+SELECT), validated57 response and matching native OPERATE.
The prefix carries the installed epoch and a separate global work generation;
transaction work generation never substitutes for connection epoch. Real packet
network/DNP3 CRC/profile checks precede the lifetime grant. Stored selected
objects, reciprocal tuple, app relation and TCP positions qualify the later
response/OPERATE. Exact supported FIN/RST positions quarantine native producer
phases8–12. No per-packet controller writes or supplied valid flag admits them.

The old-helper monolithic `binding/evidence/native_02` performed PHV/table
placement but failed assembly: **18 ingress stages, over12**, source
`93312c121976c79f1542c3e714da4467f7e88d4c40c739540300cdffb4018569`.
It has no generated binary and no current fit. Native01 retains its earlier
unsupported multi-operation ACK arithmetic failure. The new owned helper and
source regressions reject duplicate/reordered phase consumption before further
composition.

`binding/split.py` generates a concrete two-pipeline alternative. The validation
pipeline checks actual network/profile/all DNP3 CRCs and transfers the unchanged
inner packet; it has no registers, proof header or authority mutation. Only the
authority pipeline holds connection/selected/work state. Its raw handoff port70
and return port68 are explicit private-port requirements, independently guarded
in source. Compiler coexistence cannot establish their physical mapping,
isolation, failure behavior or sustainable handoff bandwidth. No cross-pipe
shared register or metadata is assumed. Split01 retained a real authority
placement failure at17 ingress stages (critical16); split02 records cancellation
after a generator failure left the same source, not another completed result.
Split03 also failed assembly at18 ingress stages after restoring the actual
decoy configuration and moving object access before the sequence chain; source
`5e5074e92a6e184331e5b1d0e600166f71fc51288b0f5a73458982c8ee5d89b4`.
There is no fitted authority, generated authority binary or complete deployment
schema. No three-pipeline source or compiler experiment was started. The current
monolithic source is `8b2164a48bf4a8b0026f901fe4387952a0596ef0210730ba5a61a0093bd8b7be`;
it has not been compiled after the ExpectedWorkRecord change. Older native02
fit failure cannot qualify these edited bytes.

**Unfixed forwarding defect:** `ownership/review/counterexamples.json` preserves
four complete checksum-valid byte witnesses: SYN retry at ownerphase2, SYNACK
retry atphase4, finalACK retry atphase5 and established client pureACK atphase9.
The actual source snapshot/first-event tables produce abortkind255; the terminal
branch drops the original. ExpectedWorkRecord fixes duplicate phase consumption
but does not repair this forwarding behavior. A continuation must preserve these
ordinary native packets while checking actual sequence, full current epoch/owner
and genuine work lifetime. No application retries or campaign attempts may be
added. Experiments stopped at the user's token-conservation instruction; this
is a blocker, not a completed connection implementation.

Complete qualification is still absent: native receipt installation/retirement,
actual original/debt and writer lifetime composition, response-to-OPERATE
cumulative transport positions, final OPERATE response, established pure-ACK
handling, verified reset/rearm and finite quarantine/physical draining remain
required. The local declaration budget and controller refusal are unchanged.

## Guarded preparation and restoration

`integration/controller/preparation.py` creates a JSON plan only. It binds the
manifest, primary source and all includes, binary, whole BFRT schema, full profile
and exact mutation inventory. It requires current source and compiler hashes,
actual context/report costs, both directions within 12 stages, and deployment SDE
9.13.2. A separately reviewed complete qualification must cover every required
behavior and the exact profile/inventory. Caller-supplied manifest flags and
primitive compilation cannot enroll a full candidate. Mock fixtures are explicitly
mock-only and cannot create real packages.

The whole schema inventory is validated before exposing actions: disable holding
and packet generation first, configure with a readback after every write, then
enable last. Runtime preconditions include exact loaded identity, an exclusive
configuration snapshot before writes, stopped traffic, retired connections and
actual original/work credits at zero, applicable feedback/release/SBO admission,
captures, attended inert OPERATE authorization and saved-workload verification.
Preparation never grants hardware authorization.

`configuration_rollback` requires the same exact identity and inventory, validates
all saved configuration targets once, disables first, restores saved configuration
and reenables saved values last. It rejects runtime owner/connection/translation/
image/work/original snapshots, including runtime entries relabeled by the caller.
It cannot resurrect stale owners, prove physical draining or restore a loaded
program. A previously absent keyed entry has an explicit delete/readback-absent
plan; unreadable default/register values are refused.

Both preparation and rollback now consult the same reviewed qualification
registry and bind the entire source/artifact/schema/profile/semantic inventory
identity. Relabeling both a runtime snapshot and its caller supplied inventory
cannot authorize restoration. Mock rollback requires explicit `mock=True` and
a registered mock identity. The production registry is empty; no real rollback
actions or hardware authorization are available. Two concrete red regressions
passed after this repair; the controller suite is17/17.

The actual padding snapshot CLI produced
`integration/controller/evidence/refusal_01.json`, with no actions and no hardware
authorization. It refuses the local 9.13.1 deployment identity and the unavailable
complete inventory. `examples/unavailable_inventory.json` is deliberately empty;
it is not a pretend full mapping. The production registry remains empty. Output
writers use exclusive creation and refuse overwriting existing evidence.

## Verification and reproducible commands

From `defense4/timing/case4_architecture/`:

```sh
python3 -m unittest discover -s integration/performance/tests -p 'test_*.py'
python3 -m unittest discover -s integration/controller/tests -p 'test_*.py'
python3 -m unittest discover -s integration/connection/tests -p 'test_*.py'
python3 integration/performance/accounting.py accounting_new.json \
  --layout integration/performance/examples/same_pipe.json \
  --evidence ownership/evidence/owner_cas_05 \
  --evidence protocol/evidence/padding_02 \
  --evidence protocol/evidence/exact_03 --allow-historical
python3 integration/controller/preparation.py protocol/evidence/padding_02 \
  integration/controller/examples/full_profile.json \
  integration/controller/examples/unavailable_inventory.json refusal_new.json
```

Fresh owned verification: **20 performance/resource tests,15 controller tests and
31 connection/selected-context tests pass**, zero skips. The final preparation command intentionally exits 1 and writes
a blocked package; accounting does not compile or qualify the primitive inputs.
Tests exercise actual budget arithmetic, L1 serialization, unknown-cost refusal,
source/artifact/compiler/report tampering, manifest cost underreporting, separate
retained/current evidence, schema/inventory mismatch, runtime restore refusal and
exclusive evidence output. New gaps were first observed as failing regressions.
Mock schema/compiler fixtures are not compiler evidence. This report is the
implementation lane's verification, not an independent review certification.

Remaining integration requires a complete source-current composition, supported
producer/fragment/mapping paths, independent target-model packet/event evidence,
measured queue/drain/heartbeat/admission inputs and a reviewed exact schema
inventory. Physical activation, inert-point qualification and the 44-block campaign
remain external gates; no hardware contact or acquisition occurred in this slice.

# Ownership and timing experiments

Eleven current-source executable primitives compile with local `bf-p4c 9.13.1
(SHA e558d01)`. Thirty-six independent event/byte reference tests pass. These are
primitive results: native association installation, complete coexistence,
model behavior, physical service and the exact 9.13.2 gate remain unverified.
Every manifest reports `full_target: false`.

All work is confined to `ownership/`. No device, traffic, model, commit or push
was initiated by this lane. Sources and SDK-output hashes are snapshotted per
fresh build. SDK `out/` artifacts remain local/ignored; numeric derived resource
results are retained in [resources.json](resources.json).

## Executable results

| Experiment / evidence | Ingress stages | Critical path | Allocated ingress PHV bits | Conservative endpoint-span maximum bits |
| --- | ---: | ---: | ---: | ---: |
| [Full-cell CAS](evidence/owner_cas_05/manifest.json) | 3 | 3 | 392 | 360 |
| [Protected exact-eight-byte resubmit](evidence/protected_pair_04/manifest.json) | 8 | 8 | 568 | 528 |
| [Protected owner and actual sixteen-byte recirculation](evidence/protected_recirc_06/manifest.json) | 12 | 12 | 768 | 720 |
| [Atomic full epoch/cookie binding](evidence/association_binding_01/manifest.json) | 3 | 2 | 320 | 304 |
| [Independent deadline clock](evidence/deadline_service_01/manifest.json) | 8 | 5 | 560 | 472 |
| [Epoch-qualified one-shot timing service](evidence/timing_service_02/manifest.json) | 11 | 11 | 632 | 544 |
| [Full-key one-shot timing service](evidence/timing_bound_01/manifest.json) | 9 | 9 | 640 | 544 |
| [Actual held originals and policy-off terminal receipts](evidence/held_original_04/manifest.json) | 8 | 7 | 928 | 864 |
| [Native receipt setter and actual-outcome total debt](evidence/original_credit_native_04/manifest.json) | 4 | 4 | 336 | 320 |
| [Real holder and independent heartbeat snapshot](evidence/held_timing_snapshot_02/manifest.json) | 12 | 11 | 1632 | 1352 |
| [Phase-qualified holder and heartbeat snapshot](evidence/held_timing_expected_02/manifest.json) | 12 | 11 | 1696 | 1416 |

All have zero egress MAU stages. The empty-egress harness nevertheless has
376 allocated PHV bits. Allocation footprint counts physical containers once;
the endpoint-span column conservatively covers parser/table/deparser endpoints.
Neither is a compiler-reported peak live-field pressure or complete-target
headroom. Full container type/width counts and report hashes are in resources.json.
These independent fits cannot be added together or ranked as complete architectures.

The builder's fresh verification finds all eleven current source inventories,
snapshots, compiler, logs, artifacts and derived resources consistent. The substantive live source hashes include:

- `work_record.p4`: `69164e6a6bba29f062f40d79dbbcfe76ca6a1e91a6435294d620b9c3d5f248c6`.
- `protected_recirc_probe.p4`: `9b03dc2e16b7cba16bf764e8b209471945e1bbad0eb3347000f02230fd557538`.
- `held_original_probe.p4`: `61fd5a19d192acb19cda9c8153bde5c0ac6f3784b86e6d6069b39f242b2eb215`.
- `timing_bound_probe.p4`: `c8d5caaf6d697981a37739b8d7f622c2c8dc01a44a7e7e8d21ea0e847181c3d7`.
- `expected_work_record.p4`: `26b2019ec6e549e22e98cf8361ee208952bd1cc94021d2ea56b9f8bc88571ef2`.
- `held_timing_expected_probe.p4`: `1af31bc97a4b331441ac0195f287483788b98c10af04441e224b5abeead2877e`.
- `original_credit_native.p4`: `51070caef5027474a1813ab41a8d9b3b776b6d25042d71133ed67a5d92114e52`.

[collect_resources.py](collect_resources.py) regenerates every resource row and
first verifies the actual source/compiler/snapshot/artifact inventories. It
retains no claim of combined whole-target fit.

## Interfaces and lifetime rules

[owner_cell.p4](p4/owner_cell.p4) implements atomic full32 expected-cell CAS,
read, and nonwrapping16 timing arm. It keeps the canonical interface cookie32
separate from phase. Its wrapper accepts external expected/desired solely for
placement diagnostics; that wrapper is not native lifecycle policy.

[work_record.p4](p4/work_record.p4) stores the pair `{generation32, phase32}`
atomically. Phase4 means free. A nonzero-generation claim changes4 to1; an exact
full-generation return changes1 to2, 2 to3, or3 to4 and returns the old phase.
Only those old phases authorize the corresponding producer operation. Zero
generation is refused before the SALU. There are four RegisterActions and one
textual dispatch/application. No early read of a separate generation bank grants
a later write. The globally nonwrapping allocator burns generations on busy
refusals and never reuses a completed identity.

The frozen first-generation helper assumes one unforked private producer
return. Its advance checks generation and phase range, not an emitted expected
phase. Its close action also lacks a generation comparison and accelerates
phase1/2 to3. Therefore duplicate/reordered returns or an unqualified stale
close cannot be considered safe under that helper; its original fixture tests
and fit are preserved as historical structural results.

[expected_work_record.p4](p4/expected_work_record.p4) replaces those assumptions
for the new true-recirculation holder/service experiment. Its API is
`ExpectedWorkRecord(op8, generation32, expectedPhase32, outOldPhase32)`.
Nonzero op1 claims free4 to1. Op2 admits only phase1/2/3 and compares full generation
and full emitted expected phase in the same SALU before incrementing. Op3
inspects that same full pair without writing state; stale references return0,
and duplicate qualified close inspection is idempotent. Op0 reads phase only
and cannot grant a protected writer. Actual raw current-epoch FIN/RST/off
quarantine remains a distinct lifecycle event; it never advances this work cell.

The normal lifetime is four passes: source claim, authorized payload return,
authorized publication return, actual terminal return. Every dirty bank write
must precede the real terminal that permits reuse. Neither heartbeat nor an
asserted completion bit frees this record. Independent epoch authority and
nonwrapping globally unique work generations remain required. Actual emitted
private stage bytes are parser-assigned once and feed the SALU comparison.
The [compiled stateful instruction evidence](validation/expected_work_compiled_semantics.json)
records both full32 equalities and the no-write inspection body from the actual
9.13.1 BFA. This static check is not a target packet/model execution.

[protected_recirc_probe.p4](p4/protected_recirc_probe.p4) derives its expected
owner word from an actual owner read and emits it in a real sixteen-byte prefix:
`epoch32, global workGeneration32, expectedCell32, event16, reserved16`.
The returning parser supplies that snapshot before the owner's fixed stage,
so later owner CAS avoids the impossible snapshot-bank read/write placement
cycle. Claim occurs before payload writes. Publication uses the actual current
owner word; terminal comes from the real third return. Invalid first snapshots
never enable owner CAS. The source producer event and epoch fixture remain
diagnostic, and the publisher/consumer lifetime must be composed with real cache
banks and native connection authority.

[owner_protected_cell.p4](p4/owner_protected_cell.p4) has a current-connection
quarantine operation preserving outstanding credits. Its caller must derive
that operation from a true valid FIN/RST or policy-off cancellation with exact
current epoch32. Old readiness/expiry/drain scans on the same connection must
use full expected-cell CAS; they cannot invoke unconditional quarantine.

[association_binding.p4](p4/association_binding.p4) atomically checks both full32
epoch and canonical cookie32. Installation is an interface, not wire authority.
The caller must hold the actual producer pin, verify connection identity and
prove all original credits terminal through final publication. Its separate
function classifier recognizes native READ 1, SELECT 3 and OPERATE 4 only after
full validation: READ opens without padding, SELECT opens control, and OPERATE
joins existing control. The classifier does not perform that validation.

## Actual packet holder

[held_original_probe.p4](p4/held_original_probe.p4) carries the original packet
bytes, rather than copying them into a circulating cache. It emits a real
twenty-byte prefix containing full epoch32, global workGeneration32, immutable
canonical cookie32, expectedCredit32, kind8, stage8 and reserved16. Returning
packets parse the original Ethernet header and keep original IP/TCP/application
bytes opaque; deparsing strips only the prefix on forwarding.

Port69 loads a real checksum-valid, unfragmented, option-free pure ACK fixture.
Ports70/71 are provisional private typed-producer/return roles; response and
unsent OPERATE require the native validated producer adapter at port70. The
program does not configure those ports. Native association install, flow/sequence
association admission and a supported fragment-to-holder publisher are absent.
No external proof flag makes this a final publisher.

The [OriginalCredit](p4/original_credit.p4) array has three 64-bit receipts, one
each for ACK/response/unsent OPERATE. Each stores full epoch32 plus credit32:
cookie16 above owned bit0 and issued-once bit8. Internally derived kind selects
the register index. Admit/debit compare both full epoch and full expected word
inside one SALU and apply constant state mutations. The issued bit remains after
debit, so a delayed terminal cannot consume a newer same-kind original in the
same timing cookie. There are four actions: read, admit, terminal and exact
current check. The source fixture is permanently epoch1/cookie1; no association
replacement setter exists in this probe.

The WorkRecord remains pinned through all actual producer returns. Only after
the actual producer terminal can policy-off settle an original. Each return
rereads the actual holding-policy register; clearing that flag does not skip
debit. A successful ACK/response receipt terminal forwards the exact original
bytes once; an unsent OPERATE terminal aborts. A stale expected receipt performs
an actual read on a further pass and retries. An already-terminal duplicate
receives an exact current check and produces no second packet or debit.

Closing before original admission forwards/aborts after the real work terminal
without inventing an original credit. Losing the producer leaves its WorkRecord
pinned. Losing an admitted original leaves its receipt owned after the producer
becomes free. Thus the independent original and producer barriers persist.
The software oracle checks that both must be quiescent before reassociation;
the target's native multi-receipt reassociation adapter is still required.
Busy-source fail-open behavior in this isolated fixture is not final native
fragment/retransmission association policy.

The [literal ACK fixture](fixtures/held_ack_off.json) includes independent valid
IPv4/TCP checksums, full32 wrapped sequences and exact expected twenty-byte
prefixes. Its policy write is administrative configuration, not a per-packet
CPU service. The fixture/reference tests are not a target model run.

## Timing and heartbeat

[timing_bound_probe.p4](p4/timing_bound_probe.p4) atomically guards diagnostic
producer events with full epoch32 and canonical cookie32. It uses a fixed 1/1
association, not a native minted association. Actual private pktgen app0
heartbeats ignore asserted wire events and service current pending state.
OP eligibility is independent of the ACK/response blockers. Normal ACK eligibility
requires both observations and D_A; readiness fallback is 30 ms. Atomic ACK phase1
to2 commits once, and readiness cannot retire a committed ACK. The response
pending flag commits once after its separately anchored gap.

The clock is low32 nanoseconds masked by `0xffffff00`. The four D_A offsets are
4,999,936 / 9,999,872 / 14,999,808 / 20,000,000 ns; readiness is 29,999,872 ns; the
response gap is 999,936 ns. The response anchor uses the heartbeat packet which
actually triggers the ACK state transition, rather than ideal `t0 + D_A`.
SDK `global_tstamp` is ingress-arrival time. This is the commit-service packet's
arrival timestamp, not a measured SALU-cycle time or physical departure time.
Precise internal/egress timing still needs actual service/queue measurement.

[heartbeat_spec.json](heartbeat_spec.json) records requested 100 us, app0,
source68 and the real SDK six-byte timer prefix. No pktgen configuration was
issued. Native READ/SELECT/OPERATE observation publication, safe rearm,
owner-qualified stale scans, policy-off holder/service composition and a
measured 40 ms upper bound remain required. A heartbeat cannot synthesize an
original or producer terminal after packet loss.

## Native receipt installation boundary

[original_credit_native.p4](p4/original_credit_native.p4) provides the new native
interface `NativeOriginalCredit(op8,index2,epoch32,expected32,outResult32)`.
The three receipts start at epoch0/word0. Op0 reads; op1 admits only a nonzero
cookie and unissued lower16==0 word; op2 debits only a nonzero cookie and exact
lower16==0x101 word. Both mutations atomically compare full epoch32 and full
expected word32. Op3 installs the actual native epoch and new cookie16<<16;
cookie0 is permitted only as neutral new-connection context.

Install itself is unconditional inside its selected action. Local9.13.1
rejected a sliced/masked owned-bit SALU predicate. The native caller therefore
must hold a genuine exclusive producer grant, establish zero actual debt and
all old writers terminal, and keep that pin through all three receipt installs
and final dirty-write publication. Arbitrary wire install opcodes, asserted
proof flags, or an early read of work-free cannot establish that contract.
The compile wrapper is diagnostic, not the native initializer.

[original_debt.p4](p4/original_debt.p4) tracks bounded aggregate0..3 debt.
Increment/decrement opcodes derive only from successful real receipt admit or
terminal result1. Duplicate/stale/refused events do not change debt; install
never clears it. An original lost in circulation leaves debt outstanding.
A late receipt/deadline/cache writer also requires a real lifetime pin even if
receipt debt already reached zero. Three indexed installs cannot release their
producer on the same early SALU stage as their last later bank write.

## Actual holder and independent heartbeat composition

[held_timing_expected_probe.p4](p4/held_timing_expected_probe.p4) composes actual
held originals, qualified producer returns, timing observations, independent
heartbeat service, eligibility, terminal receipts and final unchanged forwarding.
Readiness bits derive only from actual successful receipt admission carried to
the next real phase-qualified return. No externally asserted seen/proof field
or per-packet CPU callback drives the timing state.

Actual app0 pktgen on provisional port68 creates a separate protected service
generation. It reads real current epoch, receipt cookie, admission anchor,
readiness observations and response deadline into a genuine28-byte snapshot.
Private return73 supplies those actual bytes before fixed bank stages. Source,
phase1 service, phase2 relay and phase3 terminal are four real ingress passes;
full generation and emitted phase protect every service return. Losing an
original producer therefore does not prevent this independent heartbeat record
from servicing an already-armed deadline. Service emits a diagnostic16-byte
report only after its genuine terminal. No holding operation occurs in egress.

The structural fixture is forever epoch1/cookie1, fixed D_A=4,999,936 ns. Its
anchor is the first qualified original-admission relay, not native READ/SELECT
t0. Normal ACK requires actual ACK/response observations and the deadline;
readiness fallback is29,999,872 ns. OPERATE deadline eligibility remains independent
of those blockers. Response eligibility starts from the arrival timestamp of
the actual successful ACK receipt terminal plus999,936 ns. HB ACK eligibility
alone cannot create that response anchor. Policy-off still debits a real receipt,
forwards actual ACK/response bytes once, and aborts unsent OPERATE.

This improves actual role coexistence, not native timing completeness. Actual
validated READ/SELECT/OPERATE publication and native initializer remain missing
here. Safe native key replacement must atomically exclude producer AND service
grants and retain the ACK writer pin until its later deadline-bank write finishes.
This fixed namespace has no key setter, so it does not claim that dynamic barrier.
A lost HB service packet pins its separate service record; later HB grants are
refused. Arbitrary service-loss recovery, finite holding circulation, packet
spacing/queue latency, physical ACK-to-response wire gap and the40ms cap remain
unverified. No lost packet is replaced with a fabricated terminal/debit.

## Structural comparisons and transfer costs

The same-pipe owner has an actual three-stage full-cell transition fit, while
standalone full-key timing uses nine and the original holder uses eight. Their
coexistence with cache/validator/native lifecycle is not proved by those fits.

The exact-eight-byte resubmit alternative carries only epoch32/generation32
and references the protected record. It has four ingress passes and three
eight-byte transfers. Original-packet resubmit semantics preserve the original
input bytes and do not preserve transformation edits, so it is appropriate for
validation/ownership staging only. It does not yet compose the full owner or
cache publication operation.

The owner recirculation alternative has four ingress passes and three genuine
sixteen-byte-plus-inner-packet transfers. For inner lengthL, those transfers
carry `3 * (L + 16)` bytes, before physical/internal overhead. The holder prefix
is twenty bytes: source plus three producer returns establish an original;
each further held/refetch/terminal pass carries `L + 20`. Successful policy-off
needs a further terminal pass; stale snapshots add refresh/retry passes.
Independent heartbeat snapshot service adds three actual transfers carrying
`H + 28` each, where H is its preserved inner heartbeat-frame length, plus the
six-byte source SDK timer prefix and final diagnostic report on their own paths.
The original producer still needs three `L + 20` transfers before holding;
service traffic does not stand in for those original bytes.
Holding circulation has no proven finite pass-count or queue-service bound in
this primitive. Whole-architecture bandwidth must use the declared workload,
actual held residence and packet lengths, not a line-rate bypass assumption.

A concrete cross-pipe candidate assigns single owner/work/receipt/timing
authority to ingress pipeA and validator/assembly/image banks to pipeB. B sends
the actual packet to A ingress for a protected grant; A returns the emitted
WorkRef/expected-cell packet to B ingress; B writes under that pin and returns
the genuine publication/terminal to A. A applies current full-key publication
before releasing the pin. B cannot read/write A registers as shared state.
Every handoff must be an actual ingress packet transfer, with preserved bytes
and counted bandwidth. Egress routing alone does not expose another pipe's
ingress registers. Available internal/loop ports, pipe mapping, packet-loss
recovery, queue guarantees and a compiled composed handoff are unverified.
This is a concrete candidate, not a topology capability or fit claim.

## Retained failed experiments

- `owner_cas_01..03`: direct/nested gateways exceeded 4 bytes + 12 bits of PHV input;
  `owner_cas_04`: wide range key exceeded five PHV nibbles. Explicit ordered
  TCAM status predicates fit in05.
- `owner_events_01`: fifteen lifecycle RegisterActions exceed the register's
  four-action limit. The protected multi-pass full-cell alternative replaces
  that direct event explosion.
- `protected_work_01`: next-table propagation failed on repeated owner apply;
  a scalar snapshot bank also implies a fixed-stage read/write cycle.
- `protected_pair_01`: unsigned maximum compiled as illegal signed SALU constant;
  `02`: multiple per-register tables could not place. Signed exhaustion and
  one dispatch table fit in03, and zero-generation refusal fits in04.
- `protected_recirc_01`: multioperand bitwise action could not span stages;
  `02`:14-stage placement plus invalid masked SALU comparison; `03`: twelve
  stages but masked-compare assembler error. Current-connection quarantine
  with real caller authority fits in04; invalid-snapshot guard in05; the
  zero-generation helper in06. Old scans remain full-CAS only.
- `timing_service_01`: fourteen stages. Atomic one-shot outputs and early
  independent clock preparation fit in02; full-key atomic binding fits the
  new timing_bound01 in nine stages.
- `held_original_01`: held-policy gateway exceeded 4 bytes + 12 bits;
  `02`: epoch/expected/replacement needed three SALU PHV inputs, over two;
  `03`: dynamic-index register read could not be the default action because
  it needs the hash-distribution unit. Explicit dispatch and constant indexed
  receipt transitions fit in04. The failed aggregate-mask variant is retained
  in the source snapshots and is not claimed implemented.
- `original_credit_native_01`: sliced register condition unsupported; `02`:
  masked SALU condition reached assembler but failed syntax. Actual-caller
  zero-debt installation contract fits in03; strict opcodes and successful-
  receipt-driven aggregate debt coexist in04, four stages.
- `held_timing_bridge_01`:23 ingress stages. Genuine four-pass heartbeat bank
  snapshots reduce the dependency path to13 in `held_timing_snapshot_01`.
  Combining timing eligibility and its qualified terminal opcode yields
  snapshot02 at12. Actual emitted phase equality and no-write close inspection
  coexist at12 in `held_timing_expected_02`.

## Verification and outstanding gates

The fresh command `python3 -B -m unittest discover -s
defense4/timing/case4_architecture/ownership/tests -v` passes 36 tests.
[validation/unit_tests_02/result.json](validation/unit_tests_02/result.json)
binds that result and its log to reference/test/fixture hashes. Tests cover
stale scans, same-connection old readiness, reset/rearm work returns, independent
lost blockers/credits, cookie/work exhaustion, modular32 deadlines, late ACK
commit reanchoring, independent OPERATE, policy-off outcomes, exact8/16/20-byte
envelopes, actual three-return holder lifetime, full original conservation and
duplicate terminal rejection. The six new expected-phase tests reject duplicate
producer returns, reordered terminal, stale full-generation/same-epoch close,
wrong phase, and duplicate current close while retaining the real terminal
barrier. Red tests were observed before each new model. The byte/event models
and compiled SALU inspection do not validate target queue service or native
association publication.

Remaining full-target requirements are explicit:

1. Actual established connection epoch authority including supported coalesced
   final ACK+SELECT; transaction nonce is not connection epoch.
2. Fully validated native READ/SELECT/OPERATE mint/install/join, current-cookie
   event publication and nonwrapping16 timing allocation in the composed target.
3. Actual quiescence across all producer/fragment and original receipts before
   association/connection reuse, with current full-generation publication after
   every write. An early key check plus later writes is insufficient.
4. Native holder publishers, per-association retransmission/fragment semantics,
   raw FIN/RST/off quarantine and complete shared-cache consumer integration.
5. Native READ/SELECT t0 and all four D_A profiles in the real holder/HB
   composition; service-packet loss recovery without fabricated terminal debit,
   finite holding/declared-workload service, measured queue/latency and40ms cap.
6. Whole-architecture roles sharing actual authority/banks, complete byte/event
   behavior, actual worst-path passes and declared-workload bandwidth.
7. Verified topology/port roles for any functional pipe split.
8. Exact 9.13.2 complete-source fit, legitimate model validation, then separately
   authorized physical load/configuration/traffic and measured outcomes.

No incomplete probe is a qualified deployment package.

## Primary local SDK evidence

- [Tofino timestamp definition](/home/philip/bf-sde-9.13.1/install/share/p4c/p4include/tofino1_base.p4:190): ingress-arrival timestamp in nanoseconds.
- [Native pktgen timer header](/home/philip/bf-sde-9.13.1/install/share/p4c/p4include/tofino1_base.p4:343): six-byte SDK timer fields including pipe/app identifiers.
- [RegisterAction execution](/home/philip/bf-sde-9.13.1/install/share/p4c/p4include/tofino1_base.p4:683): the read/apply/write abstraction used by these single atomic stateful operations.
- [Resubmit limit and original packet reference](/home/philip/bf-sde-9.13.1/install/share/p4c/p4include/tofino1_base.p4:786):64-bit metadata returning to original ingress buffer.
- Exact compile logs retained beside each manifest are direct compiler evidence
  for observed PHV gateway, register-action, SALU-input and placement limits.

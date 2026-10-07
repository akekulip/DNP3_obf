# Independent root composition review

This review concerns the leader's `integration/egress_compose.py`, generated
`integration/egress_wire.p4`, and `integration/read/validator.p4`. It does not
certify the reviewer's shared-egress component or establish a complete candidate.

## Fixed concrete composition defect

The immutable `integration/evidence/egress_wire_02/source/egress_wire.p4` permitted
an ordinary carver unicast to enter egress without the cache's internal descriptor.
Its carver route omitted bypass_egress; missing split context left multicast0.
The root EgParser selected the cache parser for unicast RID0. A valid57 response
with ten unparsed Ethernet suffix bytes and source MAC bytes selecting op2/slot0
was then accepted as a descriptor-prefixed cache packet and wrote all14 banks.
`test_egress_admission.py` retains this executable source-fragment counterexample.
It is not target/model execution or evidence of physical traffic.

The leader's current generator fixes ordinary carver routing to bypass1, enables
bypass0 only in the split action, and requires actual non-dropped admission before
installing multicast metadata. A separate regression executes the current carver
body: unsplit unicast bypasses egress; valid admitted four-CRC split enters egress;
denied or bad-CRC traffic never installs PRE state. Valid split functionality remains.
Three review checks pass, including both immutable-source failure witnesses and the
current repair. The old denied-carver witness sets multicast metadata despite drop1;
it does not prove physical escape of a dropped packet.

## Remaining required integration gates

- Payload roles are mutually exclusive with the mapper in root `PATHS`: cache
  native35/tail1, carving57 and READ20/49 skip mapping. Second OPERATE still uses
  native sequence rather than adding the first20-byte growth; response payload ACK
  retains the server's wire ACK rather than the inverse native ACK. This is actual
  operation coexistence, not an end-to-end two-insertion transport implementation.
  The leader explicitly assigned a separate genuine payload-mapping pass to close
  this structural gap.
- No root wire source consumes autonomous connection epoch, selected objects,
  WorkRecord authority or real image-publication/retirement. Fulltuple CP tables
  and internal cache descriptors are prototype configuration seams. Frozen object,
  response-status, lifecycle, overlapping replay and assembly gates remain required.
- RID1/2 carving depends on actual PRE configuration and ordering; neither physical
  order nor queue service follows from source fit. Other multicast use must not
  collide with these RIDs or be routed into the cache parser.
- The current root ingress and egress parser_err guards run before role mutation.
  changed flags reset after subparser outputs, protecting inactive unconditional
  deparser calls. Conditional deparser calls were removed. Invalid inactive headers
  are emitted conditionally by validity in the target, not by an asserted role flag.

## READ review

The root READ profile binds request and response directions, exact wire-order link
addresses, frozen G10V2 range0..22, complete20/49 lengths and all request/response
DNP3 CRC blocks. The address fix compares both dl.dst and dl.src with the configured
wire fields before counting; CRC-valid changed addresses are refused by the existing
root tests. The suffix-safe source wrapper now executes the observation command
following the request/response else-if chain. Outer apply extraction deliberately
selects `\n apply{`, avoiding the counter RegisterAction's void apply.

READ forwards original bytes and observes validation. Its two32-bit counters are
not tuple/epoch/application-sequence owners, READ transaction associations, readiness
receipts or timing events. The earlier standalone parser_err gap is now repaired
in current `integration/read/validator.p4`, SHA
`2788c885b5645eb21b4285c19bab4827477c900eb9019bffe7910133d5626011`.
The new independent check runs an actual READ20 raw packet through its declared
parser, verifies the TCP residual, then executes its outer control with parser
error0/1. Only error0 updates the qualified counter; emitted bytes remain equal.
No additional READ semantic bug was established by this bounded review.

## Current unified cache and assembly review

`test_current_composition.py` adds nine passing independent review checks. They
execute current root source fragments, including the nested cache bank actions;
they do not certify the reviewer's frozen shared-egress component or execute a
target/model. Reviewed root wire SHA is
`ca7a76c4106aa75eed730a68575434276cc13df4d58b71086a441dde48a1ec94`;
selected-wire SHA is
`1cdf9ac6962e5eabdaba2fc185d61c2c9b18a24ab2ce0226e2c71b7857db2ac1`.
These are the leader's compiled wire06/selected04 10-ingress/7-egress sources,
not a complete candidate.

1. **Assembly hop limit repaired in the new source.** The old authority source's outer apply at
   `integration/assembly_passes/producer.p4:1762` checks `hops>16`, then increments
   and performs the selected processing action. A private return with hops16
   becomes17, reads all12 buckets and returns event3 without dropping. The
   stateless worker correctly requires hops<16. The immutable producer02 snapshot
   retains the exact counterexample; current reviewed authority SHA
   `22b79ec052c99a7fd3c344403d026a25025521597fd316303e5f0ce46b55c658`
   contained the same guard. The current generated authority, SHA
   `758da06ea3c3c125b2dadabe992a7f34438983714820b4c03d42b57e08585cd0`,
   checks hops>=16 before increment. New independent checks retain producer03's
   old hop16 witness, refuse current16 before origin or scratch, and allow15→16.
   This source remains a structural prototype, not a live pipeline claim.
2. **Actual shared cache requires the lifetime authority.** Root selected-wire
   lines81..204 use scalar banks with nonzero-descriptor admission but no stored
   generation check. The executable witness writes slot0 with generation2/imageA,
   then generation3/imageB, and replays the retained generation2 descriptor. Its
   output is exact imageB, with a valid current TCP checksum and no drop. This
   proves why current owner, committed-image identity and a no-reuse barrier are
   load-bearing. It does not assert reuse occurs under a future correctly pinned
   production WorkRecord. All14 bank actions are the actual root unified dispatch
   table actions; no per-packet publication assertion is supplied.
3. **Quantized30ms deadline repaired conservatively in the new source.** Old authority
   `clock_now` at line1699 clears the low8 timestamp bits. With origin0, actual
   arrival30,000,127ns becomes29,999,872ns and passes the30,000,000ns expiry guard.
   Current source retains256ns resolution and floors the expiry threshold to
   29,999,872ns. Independent checks execute actual clock/origin/elapsed actions
   and the extracted actual expiry condition for every256 origin residues,
   normal and wrap bases, and five true ages around30ms (2560 source cases).
   None accepts at/after true30ms; the earliest conservative expiry is383ns early.
   A representative full authority pass at30,000,127ns now faults before scratch;
   producer03's old acceptance remains an executable counterexample. No clock
   precision or physical timing improvement is claimed. First-generation origin
   remains immutable across duplicate fragments, including observation0.
4. **Earlier parser-error mutation is now repaired in source.** Immutable
   `assembly_passes/evidence/producer_02/source/producer.p4` (SHA
   `2f07448104cdde81cf8567a44846edf3eb0f5249f30c23b75dcd90ec73521206`)
   updates origin and reads all12 scratch buckets with supplied parser error1.
   Current authority gates the entire outer apply and drops error1 with origin
   unchanged and no bucket calls. The regression retains both behaviors. Network
   check results are explicit supplied fixture inputs here; this is not a raw
   malformed-packet reproduction or a fresh compiler qualification.

The actual unified cache parser rejects unsupported operation/slot combinations
before control. The root outer egress parser-error guard blocks every bank call;
the positive branch still invokes all14 real store actions. Zero generation is
separately covered in the leader's composed-cache tests. Each bank is applied once
through its actual scalar-key op1/load or op2/store dispatch, using the corrected
source wrapper rather than an artificial runtime action override. No additional
dispatch/admission defect was established in these reviewed root sources.

The assembly authority still installs connection/generation/native-start context
and selected bytes through external tables, carries expected_cell0, and has no
actual WorkRecord claim/pin/terminal integration (`producer.p4:1694..1709`,
`:1754..1759`). Its partial read/merge/CAS/publication stages therefore do not
prove whole-work lifetime or protect against an authorized stale work item after
reuse. The failed fixed-four-bank worker's PHV result is retained; supported
source-fragment tests do not replace a successful full source compile.

`test_fixed_worker.py` independently reviews the exact immutable fixed-worker04
source SHA `71f1bbf6d54318c4886c40793edcb4e6e15f9cd5a025e157decf2ed1b9daeb38`.
Its three checks cover all630 legal offset/length combinations, both fresh and
duplicate inputs; only the four active candidate banks change, while the eight
inactive candidate words retain their exact bytes. Actual declared8-bit mask,
data and difference fields and32-bit TCP/reference identities are checked.
Conflicting overlaps and illegal presence bits return a typed fault without
authoritative state writes. Parser errors, out-of-range pieces, hop16, zero
generation and malformed reserved fields refuse before candidate edits. Network
validation results are explicit supplied fixture inputs; these tests neither
revalidate raw frames nor model PHV allocation. The real container-annotated
fixed-worker04 compiler failure remains unchanged and cannot be replaced by
these functional checks. Whole-work pin/current phase and autonomous assembly
publication remain open.

`test_staged_worker.py` applies the same independent three-check byte suite to
the exact staged-worker01 compiler input, SHA
`c1b8f60af20c78de850f1525df29345343ff6f751bec5aea8e80838a2100db89`.
All1260 legal fresh/duplicate cases, inactive-word preservation, conflicts and
admission refusals pass after the patch and XOR actions are separated. The
source's126-byte private work format and full32 authority identity fields remain
unchanged. Its actual compiler result is still failed; functional source parity
does not establish target fit or a current WorkRecord pin.

`evidence/verification_01` is the fresh bounded review seal:18 unit checks,
current and retained historical source snapshots/hashes, and the raw unittest
log. It explicitly has no compiler qualification, full target or physical
measurement claim. Each source identity is checked again before completion.

No leader files, frozen sources, historical evidence or hardware were modified.

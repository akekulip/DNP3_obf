# Shared egress image banks

`shared_egress.p4` is a source-bound compiled wire/storage primitive, not a complete
Case 4 implementation. Actual raw native35 validation and padding occur in ingress;
egress reparses the emitted55 bytes and writes fourteen shared scalar32 image banks.
An independently configured, checksum-valid one-byte native tail replay reads those
same banks and emits the full55 image with the replay packet's current TCP headers.
No CPU image installation is used. This addresses the structural ingress cache
placement problem; it does not establish protected connection publication or reuse.

## Compiler evidence

All runs use bf-p4c9.13.1 (SHA e558d01), separate exclusive directories and complete
source snapshots. SDK outputs remain ignored. Earlier failures remain intact.

| Run | Actual outcome | Source SHA256 |
|---|---|---|
| `evidence/tagged_probe_01` | Failed: paired64 tag/data concatenation cannot be assigned to RegisterAction output | `f6ba9af2be0a1a13a5f074f3b102282319a097ab3501dc3a454960d84413b8fb` |
| `evidence/tagged_probe_02` | Failed: paired64 struct result has incompatible mem_lo/mem_hi outputs | `c792ad76147cb710ae161b0eacfc826313766021b3e7c3e24b1f165acf67faae` |
| `evidence/shared_01` | Failed:7 unallocated PHV slices around phase/1-bit slot packing | `9391102f280cbb552f497c38f7f2f61fc3392ba994c35e60e35537054aaee8f0` |
| `evidence/shared_02` | Failed: TCP urgent16 exceeds available1x16+2x8 parser match registers while later IP length remains live | `614e95e565cbc108003cf89f2288b58345f7d832e792436bda8af3b40528ffbb` |
| `evidence/shared_03` | Passed:9 ingress/4 egress occupied stages, compiler critical path9;14 egress stateful tables,2 entries each;7 warnings | `3f45f7c36390fe1de58435ee7261ede1250169db10d3f380aebcda24614dac4e` |

The successful source uses full-byte slot assignment and separate length75/41 IP
and TCP parser paths. All urgent/reserved/fragment checks remain present.
`evidence/verification_01/manifest.json` independently verifies current source,
snapshot, compiler identity, every required artifact and current resource reports.
No joint composition fit, switch-model execution or physical measurement is inferred.

## Interface and traffic cost

Ingress parses actual Ethernet/IPv4/TCP, without an external descriptor. The fixed
profile accepts IPv4 version4/IHL5, length75(native35) or41(native1), protocolTCP,
no fragmentation and flags0/DF, TCP offset5/reserved0/urgent0 with ACK or PSH+ACK.
IP and TCP checksums are checked. Complete35 parsing checks all three DNP3 CRCs,
G12V1 qualifier0x28/count1, SELECT or OPERATE, native zero status and distinct decoy
index. The real CROB/link/sequence bytes are retained by padding.

`forwarding` defaults deny. The forwarding admission guard encloses all validation
and descriptor creation; missing/disabled connection and replay contexts deny too.
`connection.configure` accepts inert decoy fields plus generation32.
`replay_context` keys the full IP/TCP tuple and exact native sequence; its parameters
are generation32, wire_start32, expected native last byte8 and slot8. SELECT uses
slot0 and OPERATE slot1. Those configuration tables are prototype interfaces, not
an autonomous connection or selected-object publisher.

Only actual admitted transformation/replay creates the12-byte internal prefix:
`{generation32, wire_start32, operation8, slot8, reserved16}`. Reserved bits are
zero. Operation2 stores; operation1 reads. EgParser rejects other operations/slots,
reparses Ethernet/IP/TCP and then image55 or native1. Image storage is thirteen32-bit
words plus a final24-bit word zero-padded to32 bits. Egress removes the descriptor
and regenerates IP/TCP checksums, preserving current ACK/window/flags/ports/IP id.

Each supported primitive uses one ingress plus one egress processing pass, without
resubmit or recirculation. A store crosses into egress with123 bytes
(12prefix+14Ethernet+40IPv4/TCP+55payload). A read crosses with69 bytes
(12+14+40+1) and renders109 bytes externally. These exclude FCS, internal hardware
metadata and wire overhead. Physical service/throughput remains unmeasured.
Holding originals and blooper paths are absent from this standalone primitive;
composition must preserve their bypass_egress behavior and enable egress only for
these qualified cache roles or the separate carver.

## Supporting exact-byte evidence

Eleven fresh tests pass in `evidence/verification_01/tests.log`. The evaluator
executes extracted source state selectors, field extraction, checksum commands,
outer control apply blocks, actual register bodies and deparser assignments. It
uses the leader's suffix-safe else-if wrapper; outer apply extraction avoids SALU
`void apply`. It is a restricted software evaluator, not a complete TNA simulator.

`exact_vectors.json` retains full input, internal transfer and output packets,
all cache words and independent expected packets. Expected application images come
from the previously verified Python codec; expected packet serialization/checksums
use the existing Scapy library, with no packet sends. Tests cover both phase slots,
wrapped native sequence/last-byte replay, current ACK/window/flags, zero window,
all native CRC blocks, malformed checksummed IP/TCP headers, truncation, denial,
missing replay context, generation0, wrong last byte and unsupported egress ops.
The replay emits the entire55-byte cached range at wire_start; the verified21-byte
software tail slice is a different rendering choice. Endpoint overlap acceptance
and full arbitrary overlap/resegmentation remain unproved here.

## Remaining integration gates

- Scalar image safety requires actual shared WorkRecord pin/no-reuse authority
  spanning every writer and reader pass, current epoch/work checks before publication,
  immutable committed images and verified connection retirement. No such lifetime
  gate exists in this standalone source. CP generation alone provides none.
- Actual selected-set/link/application-sequence/SELECT-response authorization is
  absent. A recorded regression deliberately shows that a CRC-valid OPERATE with a
  changed real CROB code can pass this shape primitive. It must be refused by the
  autonomous connection publisher in composition. The frozen decoy is configured,
  not retained autonomously across the pair here.
- Replay context publication must come after actual protected image production;
  the prototype can otherwise read uninitialized/stale scalar banks. An installed
  context is not evidence that publication or retirement happened.
- The frozen successful primitive does not explicitly gate ingress or egress
  `p.parser_err==0`. Software truncation rejection is not evidence of target error
  metadata behavior. Composition must deny parser errors before descriptors/banks.
- No all-overlap repair, segmented OPERATE assembly, transport ledger, disabled-policy
  recovery, FIN/RST lifecycle, heartbeat service or ordered response carve is in this
  primitive. Those require actual integrated producers and compiler verification.
- The failed tagged reader cannot return both full generation and data in one SALU
  output. A genuine two-pass tag/data read would still require a pinned work lifetime
  preventing intervening writes/reuse; a zero-data sentinel cannot represent validity.

Prior frozen protocol/assembly sources and evidence remain unchanged. No commits,
hardware loading, external traffic or physical measurements occurred in this lane.

# Protocol primitives: Task 2

Ten new executable TNA primitives compile with SDE 9.13.1. They include complete
fixed35 input validation and actual55-byte construction, exact cache-word writes,
actual replay, full32 TCP field completion, and complete57 validation/carving.
These are separate compiler probes. A complete Case4 target is **not implemented
or qualified by this lane**; the connection, fragment and protected-work lifecycle
must be composed by the lead. All compiled P4 snapshots below are frozen.

## Actual compiler results

The compiler is `p4c 9.13.1 (SHA: e558d01)`. Each directory contains an exclusive
source snapshot, exact source/compiler identities, retained compilation log,
artifact identities and independently derived resource reports in `manifest.json`.
SDK binaries remain ignored under `out/`. Stage counts are occupied stage spans,
not a claim that these rows coexist or that spans add to a combined design.

| Source | Evidence directory | Ingress / egress stages | Critical path | Register banks |
|---|---|---:|---:|---|
| `mapping_forward.p4` | `evidence/forward_02` | 7 / 0 | 7 | none |
| `mapping_reverse.p4` | `evidence/reverse_02` | 10 / 0 | 10 | none |
| `exact_replay.p4` | `evidence/exact_03` | 7 / 0 | 3 | 14 scalar32 × 2 slots |
| `canonical_replay.p4` | `evidence/canonical_02` | 8 / 0 | 5 | 12 scalar32 × 2 slots |
| `padding.p4` | `evidence/padding_02` | 11 / 0 | 6 | none |
| `padding_cache_writer.p4` | `evidence/writer_01` | 12 / 0 | 8 | 14 scalar32 × 2 slots |
| `carving.p4` | `evidence/carving_01` | 7 / 3 | 4 | none |
| `tagged_cache_writer.p4` | `evidence/tagged_05` | 10 / 0 | 10 | 14 paired64 × 2 slots |
| `selected_padding.p4` | `evidence/selected_01` | 12 / 0 | 6 | none |
| `selected_carving.p4` | `evidence/selected_carving_01` | 7 / 3 | 5 | none |

`evidence/compile_verification_01.json` rechecks current sources, snapshots,
compiler bytes, compiled artifacts, compilation logs and actual resource reports:
all ten pass. It explicitly retains `full_target: false`.

The combined bidirectional mapping probe remains unfitted: current `mapping.p4`
SHA `aa0c9aba72018d784293aa44eedec98e753ddca33a7ceb5e16d2c5a80a50b3a4`,
`evidence/mapping_09`, has 43 unallocated PHV slices. Direction-specific grouping
fits and completes forwarding rather than ending with a phase-limit drop. Earlier
mapping failures and exact/canonical/padding structural failures remain retained.
Tagged attempts 02–04 preserve concrete SALU failures: three comparisons where
only two are available, subtraction on paired-register output, and incompatible
nonexclusive outputs. Attempt05 uses two comparisons and mutually exclusive
register-field/zero outputs; status subtraction occurs in ordinary match-action
ALUs. No permission, tolerance or compiler-limit workaround was used.

## Byte construction and cache choice

The native validator parses actual Ethernet/IPv4/TCP/DNP3 fields. It admits the
fixed no-options IPv4/TCP profile, IPv4 v4/IHL5, no fragments, flags0/DF,
ACK or PSH+ACK, no urgent/reserved bits, exact IP length75. It checks IPv4 and TCP
checksums, all three DNP3 CRCs, one complete transport/application fragment,
SELECT/OPERATE, G12V1 qualifier28/count1, status0, and distinct real/decoy indices.
Only then does it append a separate G12V1 header and the configured decoy and
regenerate changed DNP3 CRCs and IPv4/TCP checksums. Native command bytes,
addresses, transport/application sequence bytes, TCP fields and real object
remain exact. The configured point's inertness remains an external prerequisite.

The exact writer packs the actual resulting55-byte frame into fourteen 32-bit
words (last byte of the 56-byte storage representation is zero). It writes all
words after actual CRC materialization in the validated pass. Each phase has its
own slot. It has no protected publisher or incarnation authority.

Exact replay stores55 bytes plus one pad byte. Canonical reconstruction stores
the original eight-byte link header and all39 user bytes, including each phase's
transport/application/function bytes and all object fields, then recomputes the
four CRCs. It uses48 stored bytes and one more occupied ingress stage. The
comparison does not substitute default command values, statuses or sequence
bytes. Exact storage is the simpler byte-preserving integration candidate.

The compiled replay primitives recognize one verified native byte at the frozen
last-byte TCP position. They emit the **entire cached55-byte image at wire_start**,
using the current retransmission's ACK, window, flags, ports and IP fields. This
includes a duplicated prefix; it differs from the existing software oracle's
21-byte missing-tail output. Safe use requires an authenticated committed cache
and the exact native byte/position/overlap checks. The target prototype itself
neither causes kernel retransmission nor proves endpoint overlap acceptance.
Arbitrary cached subranges/resegmentation are tested in the independent exact
record oracle, but not implemented by this target replay primitive.

The tagged alternative atomically protects each paired64 `{generation32,data32}`
word. Greater nonwrapping generation writes; equal generation/equal bytes is
idempotent; equal-generation conflict and stale generations do not overwrite.
The returned generation minus current generation must be zero for **all fourteen
full32 statuses** before forwarding. Zero work generation is excluded. A conflict
can leave other words updated: the retained test explicitly demonstrates this.
Therefore tags do not replace the whole-work no-reuse pin, overlap validation,
terminal credits or current-owner publication. Generation allocation is still an
external controller action in the standalone probe, not a trusted producer.

## Exact selected-object and response seams

`selected_padding.p4` adds an exact `selected_objects` table keyed by actual link
addresses, real index/code/repeat/on/off/status and phase function/application
byte. Its default prevents transformation. Tests change each field and recompute
valid CRCs; each changed object is refused. The connection table independently
keys the actual full IPv4/TCP tuple and configures immutable decoy fields.
These tables are an external immutable context seam; actual SELECT publication,
connection epoch, WorkRecord pin and expiry are not implemented here.

The base response carver validates the actual57-byte frame, all four CRCs and
the two separate G12V1 headers before multicast. A retained counterexample shows
that shape-only validation still accepts a valid wrong real index; it does not
prove association. `selected_carving.p4` adds exact link addresses,
transport/application bytes and the real and decoy object fields (including
fields crossing CRC block boundaries). Status bytes remain exact endpoint
results, independent of object identity. It defaults to no split when the frozen
selected set is absent/mismatched. Timing ownership/association publication is
an integration responsibility.

Real egress RID1/2 actions emit [28,29] exact payload slices, with second full32
TCP sequence +28, first PSH cleared, final flags preserved and network checksums
updated. PRE configuration and queue service determine physical order and are
unmeasured; the encoded sequence order and byte concatenation are verified.
Historical49/[28,21] remains a separate existing profile, not implemented by
these new57-only probes.

## Independent verification

`python3 -m unittest discover -s protocol/tests -v` from this directory's parent
passes **18 tests**. `verify_bytes.py NEW_EVIDENCE_DIR` reserves an exclusive
record, retains failures, never overwrites, reruns the suite and retains exact
bytes, logs and current source/test hashes. `evidence/bytes_01` passes18 tests;
`vectors.json` includes native SELECT/OPERATE35, independently expected55 images,
actual source-control fourteen-word writes, exact oracle21/replay55 tails,
response57 with statuses3/4 and actual source carves [28,29] crossing TCP wrap.

Tests execute actual source actions, constant tables, predicates, register
updates and field rendering through the bounded `source_eval.py` interpreter;
expected byte construction and modular mappings come from the existing read-only
software codecs/oracles. They cover both insertions and window edges, clamp
boundaries, wrap, zero window, corrupted CRCs in every block, default-disabled
profiles, phase-specific canonical bytes, current replay TCP fields, stale and
conflicting tags, high-bit status rejection, exact selected sets and order/status
counterexamples. The interpreter rejects unrecognized syntax. Parser eligibility
and network checksum outcomes are supplied in these control-fragment tests;
they are not target parser, compiled-model or physical packet execution. CRC
polynomial behavior is separately modeled. Compiler acceptance is a distinct
source-bound proof, not endpoint acceptance.

## Remaining integration obligations

- Producer authority must establish the verified handshake/MSS/full tuple and
  connection epoch, freeze actual SELECT object/decoy fields, enforce capacity,
  and retain committed translation/cache after policy disablement/quarantine.
- Supported fragmented OPERATE assembly (35-byte coverage, consistent overlap,
  first-fragment absolute deadline, CRC/profile/object validation) has no new
  compiled producer in this lane. No unfinished command may forward.
- The ledger's bounds, two insertion geometry and half-range admission must be
  protected actual state, rather than controller-seeded arithmetic hypotheses.
  Pure ACK direction probes do not implement payload-bearing READ mapping.
- The actual WorkRecord must pin all writes and returns until terminal credit;
  current-owner publication must follow every write before visible use. Raw
  FIN/RST, loss, reset, retirement and reuse need the complete connection contract.
- Arbitrary retransmission overlap/resegmentation, old tuple/epoch exclusion,
  READ, historical49 and physical queue/carve order remain full-target work.
- Complete composition must compile and run genuine model packets. No primitive
  total proves complete fit, no control-fragment result proves TCP kernel repair,
  and no compile proves queue service or physical bounds.

These prototypes each process one ingress pass without internal transfer;
carving creates two egress replicas. Normal padding is TCP35/IP75 → TCP55/IP95,
one-byte exact replay is TCP1/IP41 → TCP55/IP95, response57/IP97 becomes
TCP28/IP68 and TCP29/IP69. Add14 bytes for the Ethernet header; FCS/preamble/gap
and composed recirculation/heartbeat costs require the lead's actual topology and
measurement. No hardware was loaded/configured/contacted and no traffic was sent.

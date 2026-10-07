# Payload mapping private-pass primitives

Both direction-specific candidates compile to real Tofino-1 binaries with
P4 Studio 9.13.1, compiler SHA `e558d01`. These are separate primitive builds;
their coexistence with the current complete pipeline is unproved. No switch,
model, socket, physical endpoint, or network traffic was used in this slice.
`full_target` remains false.

| Candidate | Immutable build | Ingress / egress | Critical path | Source SHA256 |
|---|---|---:|---:|---|
| Forward SEQ | `evidence/forward_03` | 10 / 0 | 10 | `a64e27693cd7bb7138caa6b8654cc1b8adb67c363831bd56603a4eb26e826f9f` |
| Reverse ACK/window | `evidence/reverse_12` | 11 / 0 | 11 | `9d84793476f27395457b91f7799746f06880eccbc62f968544769949bd031552` |

`evidence/verification_01` seals nine passing source-driven tests, 204 exact
input/output/independent-expected packet vectors, current supporting-source
snapshots, and independently rechecked binaries, compiler, source snapshots,
and resource reports for both successful builds. The source-fragment evaluator
executes the actual parser selectors, table entries, actions, control branches,
and checksum expressions. It is supporting evidence rather than a switch model
or complete pipeline execution. The expected packets use independent serial
arithmetic plus Scapy's complete TCP checksum serialization.

## Integration interface

`generate.py` reads the frozen mapping primitives without modifying them.
`forward.p4` and `reverse.p4` expose `IgParser`, `Ingress`, and `IgDeparser`, with
the two configuration tables below. The reverse TCP header represents the real
control/window wire word as a single `bit<32> control_window`; its parser still
checks the exact offset/reserved/flags bytes and full urgent field. The forward
header uses the usual separate fields. Their serialized TCP layouts are equal.

The parser accepts only configured private ingress 68 and consumes a real 16-byte
prefix before inner Ethernet/IPv4/TCP:

```
epoch32 | generation32 | expected_cell32 | event16 | reserved16
```

The prefix is retained on completion. `reserved` must be zero, generation must
be nonzero, and the tuple plus epoch must match a configured connection. This
prefix carries identity references; it contains no validation assertion.

`Ingress.forwarding` is exact ingress-port → `route(output_port)`, default deny.
The route must lead to a genuine private publication/return processing path;
the primitive sets `bypass_egress=1`. No endpoint may receive this internal
prefix. There is no packet generator, CPU per-packet writer, resubmit, or
recirculation producer in these sources. One successful invocation consumes
one ingress processing pass and emits an actual updated packet on its configured
private route. A caller must produce that pass and consume its return.

`Ingress.connection` keys are full IPv4 source/destination, both TCP ports, and
prefix epoch32. `configure(first32,second32,valid8,direction8)` accepts valid
bits 0, 1, or 3 only; direction is 1 for forward or 2 for reverse. With valid3,
`second-first` must equal 35 modulo32. Each committed native35 request contributes
20 wire bytes. This is control-plane geometry for the isolated primitive, not
an autonomous ledger publisher. No configuration entry exists per packet.

Network admission checks actual IPv4 checksum, version4, IHL5, TCP protocol,
unfragmented flags0/DF, nonzero TTL, IP length at least40, TCP offset5/reserved0,
ACK or PSH+ACK flags, and urgent zero. Parser error, denied route, absent tuple,
zero generation, invalid bits, and invalid two-boundary geometry prevent header
edits. Reverse lookup scratch runs in parallel but the combined guard still
precedes all header changes; there is no persistent state to mutate on denial.

The payload is never extracted into PHV. The deparser emits the actual headers
and the target retains the unparsed packet suffix. SEQ changes forward; ACK and
advertised window change reverse. IPv4 and payload bytes remain unchanged.
The pass uses incremental TCP checksum repair from the old and new header
words, with no payload checksum placeholder. Forward uses the RFC1624 inverse
old-word sum directly. Reverse folds the old seq/ACK/control-window/checksum
words in the parser checksum engine and combines the resulting base with the
new words in the deparser. Unchanged TCP control bits cancel in that arithmetic.

## Behavior and independent checks

Forward shifts a native sequence at first+35 by20, and at second+35 by a total40.
Reverse maps first wire positions35..54 to native34, position55 to native35;
second positions90..109 to native69, position110 to native70. Thus an ACK inside
either inserted tail withholds the final native byte until the complete wire
image is acknowledged. The same inverse maps the full32 ACK+window right edge.
Subtraction produces the native advertised window; zero windows stay zero.
A positive inverse-window growth is refused before header edits, including the
retained half-range counterexample `first=0,second=35,ACK=35+0x7ffffff6,window=20`.

The 204 byte vectors cover native35, padded55, echoed response57, READ20,
READ response49, pure ACK, and native one-byte tail; normal and wrapped bases;
both insertion boundaries; zero/one/two insertions; windows0/1/20/65535; and TCP
checksum zero before or after mapping. Countertests cover wrong tuple/epoch,
missing route, parser errors, zero generation, malformed IP checksum, IPv4
version, fragmentation, FIN flags, urgent field, TTL, and invalid geometry.

Two passing tests deliberately expose required upstream seams: a corrupted
payload/TCP checksum is accepted by this header-only private pass, and a foreign
nonzero generation is accepted under an otherwise matching configured epoch.
These are explicit counterexamples to claiming full validation or current
WorkRecord ownership from this primitive.

## Compiler experiments retained

Forward01/02 retained input-expression target failures; forward03 splits the
network admission into a real table and fits10 stages. Reverse01..09 retained
PHV/field-group failures while checksum/header representation was repaired;
reverse07 is a retained reserved-identifier syntax failure repaired in08.
Reverse10 cleared PHV but failed real placement at15 ingress stages. Reverse11
grouped dead scratch masking with growth and prepared independent geometry and
window values in parallel, reducing the placement failure to13. Reverse12 runs
the independent read-only route/network/context lookups in parallel and fits11.
All failed source snapshots, logs, and manifests remain immutable. SDK binaries
and proprietary compiler output stay in ignored `out/` directories.

## Remaining required seams

The real upstream producer must validate complete actual IP/TCP length and
checksum, complete DNP3 CRC/profile/object set, supported handshake/features,
native stream bounds, and retransmission/fragment classification before creating
this private processing pass. These sources do not validate arbitrary payload,
Ethernet suffix length, or TCP payload checksum. Unsupported TCP options,
ECN/control flags, FIN/RST lifecycle, connection reuse, and half-range stream
admission require the connection authority's explicit profile/lifecycle handling.

Full current epoch/tuple/work-generation/expected-phase ownership must bind the
input and return. `expected_cell` and `event` are carried unchanged but are not
checked by these stateless primitives. An externally installed geometry entry
is insufficient: repeated or stale private work could map twice without an
actual pinned WorkRecord and a once-only phase transition. The real producer
must retain that pin, original observation time, slot lifetime, immutable image,
and terminal credit through the real return and publication. No internal
envelope loss recovery, assembly deadline, current image publication, selected
set association, autonomous ledger commit, or verified retirement is proved here.

The mapping pass preserves an existing payload; cached overlap reconstruction
and full control/response transformations remain separate producer/renderer
roles. The present builds do not compose them with ownership, assembly,
handshake, timing, or protected holding. Combined PHV/stage fit, finite service,
resource contention, and physical timing measurements remain open.

Reproduction (fresh evidence directories only):

```
python3 defense4/timing/case4_architecture/protocol/payload_mapping/generate.py
python3 defense4/timing/case4_architecture/build.py SOURCE NEW_BUILD_DIR
python3 defense4/timing/case4_architecture/protocol/payload_mapping/verify.py NEW_CHECK_DIR
```

No existing evidence directory is overwritten or resumed.

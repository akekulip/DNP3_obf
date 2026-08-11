# Size Probe 1 — equal-length DNP3 READ-range normalization (charter + starting state)

Branch `defense4-size-read-range-probe`, worktree of the accepted Defense 4 checkpoint (7c4a5a7).
This is the START of Priority-2 size obfuscation. The timing/header work is not allowed to consume
the project; this probe begins the size axis with a compileable, testable, bounded primitive.

## Mechanism (the first candidate)

Rewrite a supported fixed-width DNP3 READ **object range** to a public superset: keep the original
start point, expand only the stop/count field to a configured public range that still contains
every originally requested real point, and pad the superset with reserved **inert decoy**
measurement points. The request's TCP + DNP3 frame length is unchanged (only the value of a
same-width range byte changes), so the outstation naturally emits a larger, target-sized response.
**No byte is inserted into the request → no TCP sequence-number translation, no per-flow 32-bit
state.** Recompute the affected DNP3 CRC block and the TCP checksum. Fail open byte-identically on
unsupported layouts, fragmentation, malformed CRC, or an unsafe range. No SELECT/OPERATE/DIRECT.

## Corpus finding (bounds the claim — recorded 2026-08-11)

The real corpus READ request `dnp3_split_harness/captures/baseline/read_request.pcap` is a
**Class 1/2/3 integrity poll**: `05 64 11 c4 0a00 0100 <crc> c0 c0 <fn> 3c02 06 3c03 06 3c04 06 <crc>`
— object headers Group 60 (Class data) Var 2/3/4, **qualifier 0x06 (all-points, NO range field)**.
Qualifier 0x06 has no stop/count field to expand, so the range-expand mechanism does not apply to
it; on such a request the primitive must **fail open byte-identically**. The range-expand primitive
targets **start-stop qualifiers 0x00 (8-bit) / 0x01 (16-bit)** on a specific object group (e.g.
Group 30 analog inputs, Group 1 binary inputs). Since the corpus is Class-poll dominated, the probe
must (a) demonstrate correct fail-open on the real Class poll, and (b) demonstrate the expand on a
standards-valid **synthesized** range READ, and label the claim corpus-bounded accordingly.

## DNP3 CRC

Reuse `dnp3_split_harness/dnp3_crc.py` (`dnp3_crc16` / `append_crc` / `verify_crc`) for the offline
oracle. For the in-switch P4, the CRC over the affected 16-byte data block is the key compile
question; two candidates to implement and COMPILE before declaring infeasible:
1. **Tofino CRCPolynomial hash extern** with the DNP3 polynomial (0x3D65, reflected, init 0,
   xor-out 0xFFFF) computed in the deparser/MAU over the block.
2. A **fixed-layout CRC-delta / table patch**: since only the stop byte changes at a known offset,
   precompute the CRC delta for each (offset, old→new) via a table.

## Deliverables (this probe)

Offline transformer + oracle (Class-poll fail-open + synthesized-range expand, CRC + TCP checksum
+ length + real-points-included validation); standalone Tofino P4 compile probe (both CRC
candidates); model/PTF tests; isolated software DNP3 outstation with real + reserved decoy points;
unmodified software master; before/after PCAPs; size / segment-count / fragment-count measurements;
9.13.1 + 9.13.2 resource reports. Integration placement note: Defense 4 ingress is 12/12 stages with
its 32-bit PHV group full → evaluate **egress** placement or a bounded same-Tofino second pass.

## Status

STARTED — charter + corpus analysis recorded. Implementation not yet written. No push.

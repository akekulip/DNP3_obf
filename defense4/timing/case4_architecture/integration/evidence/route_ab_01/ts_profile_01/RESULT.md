# N admits the real stack's timestamped TCP profile (2026-10-11)

**Change.** `core/response_only/make_n.py` edit 9 (`admit_timestamped_profile`), parser only, at the
generator. It covers the profile Vision's kernel uses against the SEL-751
(`protocol/evidence/hw_range_read_01/native_ip_retest_20261010.pcap`):

- SYN: data offset 10, IP length 60.
- SYN-ACK: offset 11, length 64.
- Every later segment: offset 8 with the block NOP NOP Timestamp. ACK and FIN are 52, the READ request 72,
  the READ response 101.

Admission is by exact (IP length, data offset, flags) and an exact `01 01 08 0a` option prefix. Nothing is
wildcarded. The offset-8 states extract the 12 option bytes as an opaque header, then continue into the
clean profile's own `ack`, `close`, `read_dl` and `read_response_dl` states. So the DNP3 header and block CRC
checks, the connection key, sequence checks and length checks are the same code for both profiles.

The SYN's length (60) is the clean READ request's length. The two are told apart in `read_tcp` by data offset
(10 for the SYN, 5 for the clean READ). On the handshake, MSS is the first option in both directions and keeps
`mss_check` and `syn_shapes`. The remaining 16 or 20 option bytes are bounded by the exact offset and length
and carried opaque.

Every option byte is subtracted from the TCP checksum residual, so `network` still compares `m.tcp_sum` with
`16w0xffeb`. That constant does not depend on options: it is the folded difference between the subtracted
`hdr.ip.len` and the TCP length, about 20 for ihl 5. The real frames' checksums are verified through it. The
clean profile's states are unchanged. E (`make_e.py`, `e_response_only.p4`, `protocol/case4_response_path.p4`)
is not touched.

**The capture was taken on the sender.** Five master segments (frames 0, 2, 3, 6 and 7) were handed to the NIC
for checksum offload, so as captured they hold only the pseudo-header sum. `real_profile.wire()` restores the
checksum the NIC transmitted and asserts that only those five need it. With the raw bytes, N passes the five
untouched, as it must for a bad TCP checksum. `test_bad_tcp_checksum_is_passed_untouched` covers this case.

## Tests (source level, `core/response_only/tests/test_timestamp_profile.py`, 13)

**Positive cases.**
- The whole capture: handshake, READ request / ACK / response to T as kinds 9 / 10 / 11, the master ACK
  forwarded, FIN as a qualified close.
- Five READs in the same profile (`real_profile.session`: sequence numbers, timestamps, IP ids and the DNP3
  application sequence advanced; every checksum and CRC recomputed).
- Every synthesized frame verifies.

**Negatives.** Each is checked against the clean profile's existing contract
(`connection/binding/tests/test_native_read.py`), and each is followed by a check that the good frame is
still admitted.

| case | outcome (same as the clean profile) |
|---|---|
| DNP3 header CRC and request block CRC bad (the frame is parsed as a READ) | passed untouched, one pass, no register moves |
| response CRCs bad at the clean profile's four offsets | passed untouched |
| wrong TCP sequence number | dropped; owner, client, server, epoch and READ application unchanged; work pin released |
| IP length 71 or 73; offset 5 at length 72; NOP NOP SACK in place of the timestamp | not parsed as a READ, passed untouched |
| different source port | passed untouched |
| the capture's offloaded (bad-checksum) request | passed untouched |

**The two failures reported earlier were wrong expectations in the test, not program defects.**
1. "A bad-CRC READ is dropped": the clean profile's contract is *passed untouched*
   (`test_every_bad_crc_is_passed_untouched`, test_native_read.py:125). The frame is not a valid READ, so N
   forwards it natively and binds nothing.
2. "Wrong sequence leaves every register unchanged": the clean profile's contract (`untouched()`,
   test_native_read.py:97; `test_out_of_sequence_…`, :164) fixes owner, client, server and epoch and requires
   the work pin released. It does not fix the work allocator, and a dropped admission consumes one work
   generation on both profiles. `test_clean_profile_has_the_same_two_outcomes` asserts both outcomes on the
   clean profile, counter + 1 included.

Neither case was weakened: each now asserts the exact outcome, including a check that the CRC case was parsed
as a READ. Teeth check (scratch, in memory): without edit 9, 9 of 13 tests fail; with the option-prefix check
removed, `test_length_and_offset_must_agree` fails.

## Builds (exit 0 on all four)

| build | p0 ingress / egress | p1 ingress / egress | bfrt.json | p0/tofino.bin | p1/tofino.bin |
|---|---|---|---|---|---|
| `hw_compile_local` (9.13.1, hardware map) | 12 / 11, critical path 11 | 11 / 0, critical path 9 | `8459a74d1b10…` | `06a9826b1b4c…` | `ec58a0ebef7a…` |
| `hw_compile_switch_9132` (9.13.2, hardware map) | 12 / 11, critical path 11 | 11 / 0, critical path 9 | `2bd050b19523…` | `f20717da30de…` | `7627434ed89d…` |
| `default_compile_local` (default ports) | 12 / 11 | 11 / 0 | `f54f6f670a61…` | `5326b55e1707…` | `1c4ae47dfba2…` |
| `shared_default_compile_local` (`--relay-port=9`) | 12 / 11 | 11 / 0 | `8459a74d1b10…` | `de2b92a0a45c…` | `d9434a08e9ba…` |

Hardware map sources: sha256 `79a84450944e…`, default `27d731235a7c…`, shared `1bab99eb7bca…`.

**PHV on the hardware map, identical on both compilers.** Containers / bits, all classes counted from
`pa.results.log`:

| pipe and gress | before C (`loopback_ports_01`) | with C |
|---|---|---|
| p0 ingress | 121 / 2,669 | 127 / 2,832 |
| p0 egress | 118 / 2,535 | 118 / 2,535 (unchanged) |
| p1 ingress | 50 / 1,542 | 50 / 1,542 (unchanged) |
| p1 egress | 21 / 369 | 21 / 369 (unchanged) |

Pipe 0 normal containers: 8-bit 56/64 (was 55), 16-bit 74/96, 32-bit 64/64, still full. Stages and critical
path are unchanged. The cost of the edit is pipe 0 ingress PHV only (+6 containers, +163 bits), and it fits.
Pipe 0 32-bit PHV remains the binding resource.

## Model (functional only)

| run | result |
|---|---|
| `model_real_default` (default ports) | 35/35 |
| `model_real_hw_02` (hardware map, loop ports reflected) | 36/36 |
| `model_default_distinct` (existing scenario, default ports) | 70/70 |
| `model_default_shared` (existing scenario, `SHARED_PORT=1`) | 57/57 |
| `model_hw` (existing scenario, hardware map) | 58/58 |

The two real-profile runs replay the captured handshake, three READs and the captured close. Every frame
leaves byte for byte as sent, because E does not pad this profile. T releases each ACK and response once, in
order.

`model_real_hw_01` was 35/36. Its loop-port check expected all four ports to carry frames, but a READ-only
session never uses the OPERATE ladder, port 181. The driver now expects 48, 180 and 182 and requires 181 to
stay empty.

On the model, T's releases on this profile came through the fallback counters (`OUT_*_FALLBACK`) and not
commit. The model clock cannot rank the two; this is the known limitation from `response_only_17`.

**Recorded, not fixed (rearm item).** After the master's FIN, N is in phase 7 and refuses the master's last
ACK. This happens on both profiles and in the source replay; N has no rearm yet.

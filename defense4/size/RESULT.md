# Size Probe 1 — result

**Verdict: RANGE_READ_PRIMITIVE_PARTIAL** — the offline transformer + oracle PASS (7/7) and the
standalone Tofino-1 P4 (native DNP3 CRC) COMPILES; hardware packet and live-endpoint validation are
pending the injection harness (same blocker as Experiment 2B). This is a bounded primitive, **not**
normalization of the real all-points corpus.

## Offline transformer + oracle — 7/7 PASS (`offline/size_transform.py`)

Equal-length READ-range expansion: rewrite only the stop/count field to a configured public
superset, keep the request's DNP3 + TCP frame length unchanged, recompute the affected DNP3 block
CRC and the TCP/IP checksums, and fail open byte-identical otherwise. Verified:

- **Synthesized standards-valid range READs** (qualifier 0x00 8-bit, and 0x01 16-bit): stop expands
  (e.g. G30V1 0..5 → 0..15; G1V2 4..9 → 4..31; G30V1/16-bit 0..10 → 0..255), **every original real
  point stays included**, request length unchanged, all DNP3 CRCs valid, IPv4+TCP checksums valid,
  seq/ack preserved.
- **Fail-open byte-identical** on: the real corpus frame, an unsupported object (G30V2), a corrupted
  DNP3 CRC, and (by the range bound) any request already reading past the public range.
- **Response-size projection:** request bytes unchanged; response grows ~3 B per added analog point
  (G30V1 0..5→0..15 ≈ +30 B; G1V2 4..9→4..31 ≈ +66 B).

### Corpus finding (bounds the claim)

The real corpus request (`dnp3_split_harness/captures/baseline/read_request.pcap`) is **not a READ
at all — it is a DISABLE_UNSOLICITED request (application function `0x15` = 21)** for Class 1/2/3
(Group 60 Var 2/3/4, qualifier 0x06, all-points). The transformer correctly leaves it
**byte-identical** (`failopen_not_read`). The range-expand primitive therefore applies only to
start-stop **qualifier 0x00/0x01** READs on configured object groups, demonstrated on synthesized
standards-valid fixtures. **Qualifier 0x06 (all-points) has no range field and is out of scope of
this primitive** — it must fail open, which it does.

## Standalone Tofino-1 compile — PASS (`p4/size_read_range.p4`)

`bf-p4c 9.13.1`, `0 errors, 2 warnings`, `tofino.bin` 1,355,488 B, src SHA-256 `e28dd887…`.
Resources: **5 logical tables, 3 SRAM, 2 TCAM, 2 MapRAM** (`evidence/metrics_9131.json`).

- **DNP3 CRC candidate #1 (native `CRCPolynomial` hash extern) COMPILES** — no CRC-delta fallback
  needed. Two lowering constraints had to be respected: the `Hash`/`CRCPolynomial` extern runs in
  the **MAU**, not the deparser (only `Checksum` lives there); and "never shrink" is enforced by a
  **range match on the current stop** in the policy table (a variable-vs-variable gateway compare is
  not lowerable), which also keeps the bound in TCAM.
- **CRC parameters verified against the spec:** the offline reference `dnp3_crc16` produces the
  standard CRC-16/DNP check value `0xEA82` for `"123456789"`, and the P4 `CRCPolynomial(0x3D65,
  reversed=true, init=0x0000, xor=0xFFFF)` mirrors those exact parameters. The compiled hash uses
  the correct algorithm; **byte-exact output on silicon is pending the packet test.**
- **Length-preserving, no TCP sequence translation:** only the same-width stop byte changes, so the
  request length is unchanged and no per-flow 32-bit sequence-space translation is introduced.

## Pending (not done)

- **Packet test on the model/ASIC** — blocked by the same injection-harness gap as Experiment 2B.
- **Software outstation + unmodified master test** — the **physical ION7550** (Case-B, now connected
  for testing, READ-only, no control) is the natural real outstation for this once a path is up.
- **9.13.2 resource report** — trivial to add on the switch host (the handshake normalizer already
  compiled resource-identically across 9.13.1/9.13.2).

## Next (Phase 5): the corpus-relevant SBO size mechanism

The SBO mechanism (real + inert-decoy CROBs to a public target size `S`) genuinely inserts request
bytes, so — unlike this READ primitive — it **requires per-flow request-side TCP sequence-delta
tracking and outstation-ACK translation back to the master's sequence space**. That bidirectional
oracle is the next deliverable; it is a different, harder mechanism and is scoped in `CHARTER.md`.

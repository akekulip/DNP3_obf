# Full-project audit — findings and fixes

Adversarial audit of the joint timing-and-size obfuscation (both repos + the frozen Defense 4),
combining an automated sweep (all oracles, all compiles, git/evidence state, claim↔evidence
consistency) with a fresh-eyes P4 correctness review (p4-dataplane-engineer agent). Real bugs found
and **fixed**; documented limitations recorded honestly.

## Verification sweep (all green)
Handshake oracle 29/29 · indistinguishability YES · ACK-mode 10/10 · size 7/7 · SBO 10/10 ·
all 4 P4 compile clean (9.13.1) · both repos committed · frozen DNP3 intact at `7c4a5a7`.

## Doc-consistency fixes (stale claims)
- `VERDICT.md` / `HARDWARE_RESULT.md`: `ASIC_PACKET_PARTIAL`/`PENDING` → **`ASIC_PACKET_PASS`** (the
  byte-level capture supersedes the classification-only framing).
- `CROSS_AXIS_INDISTINGUISHABILITY.md`: predated Experiment 3; ACK-mode was still called "open" →
  marked **done (silicon 3/3)**.

## P4 correctness bugs — FIXED

### `size_read_range.p4` (was broken end-to-end)
- **H1 — missing TCP pseudo-header length.** The `tcp_csum` field list jumped from `protocol` to
  `sport`, omitting the 16-bit TCP length, so every rewritten request's TCP checksum was short by the
  segment length and the outstation would drop it. **Fixed:** assign `md.tcp_plen = 40` and insert it
  after `protocol` in the pseudo-header.
- **H2 — DNP3 block CRC emitted big-endian.** `dnp3_crc.get()` returns `V` in a `bit<16>` that
  serializes MSB-first, but DNP3 appends the block CRC low-octet-first — a byte-swap from the wire
  format (a regression from the lab-proven `p4_decoy` CRC pattern). **Fixed:** store
  `V[7:0] ++ V[15:8]` so the emitted bytes are `[V[7:0], V[15:8]]`, matching the oracle's
  `dnp3_crc16(...).to_bytes(2,'little')`.
- **H3 — unconditional TCP checksum over the parsed prefix.** `Checksum()` cannot cover unparsed
  residual, so recomputing for every packet corrupted multi-block responses and non-DNP3 traffic.
  **Fixed:** gate the TCP checksum recompute on `md.eligible == 1` (only the fully-parsed, rewritten
  single-block request); everything else passes through byte-identical with its original checksum.

### `handshake_normalizer.p4` + `combined_normalizer.p4`
- **M1 — SYN-ACK payload not guarded.** The SYN path bypassed payload-bearing SYNs; the SYN-ACK path
  did not, so a SYN-ACK carrying payload was normalized (truncated). **Fixed:** added
  `if (md.pl == 1) → fail open` as the first test in the synack branch. The **oracle had the same
  gap** — fixed there too, with a new regression case `09c` (SYN-ACK + payload → fail open).
- **M2 — stateless directional divergence (window-scale desync).** Corrected the over-strong safety
  comment: because each direction is decided statelessly, a corner case (master's SYN fails open with
  WScale while the SYN-ACK is normalized) can desync window scaling. A fully robust deployment needs
  per-flow SYN-seen state — the same Experiment-3 boundary. Recorded as a documented limit.

## Documented limitations (real, acknowledged — not silently shipped)
- **M3 — ACK-mode suppression is stateless.** Suppressing every outstation pure ACK is safe only for
  the DNP3 request→ACK→response pattern; TCP keepalives and application-CONFIRM ACKs not followed by
  data would be dropped. **Deployment precondition:** READ-only flows with no application CONFIRMs and
  short idle periods, until the per-flow "response pending" bit is added. Already noted in the
  ACK-mode safety envelope.
- **Fingerprint residuals (efficacy, not correctness):** MSS is clamped, not fully canonicalized;
  fail-open handshakes skip window canonicalization; ECN/NS TCP flag bits are not canonicalized.

## Positive findings (confirmed correct)
- `ig_dprsr.drop_ctl = 1` fully drops at the ingress deparser; the counter still tallies the drop.
- The payload/header-length logic (`t_exp` const table, `md.tlen == md.exp`) cannot false-positive.
- The `CRCPolynomial(0x3D65, reversed, init 0, xor 0xFFFF)` parameters are CRC-16/DNP; only the emit
  byte order was wrong (H2), now fixed.

## Post-fix verification
All oracles re-run green (handshake 29/29, indistinguishability YES, ACK-mode 10/10, size 7/7); all
three edited P4 recompile `0 errors` on bf-p4c 9.13.1.

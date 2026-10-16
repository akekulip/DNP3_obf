# m8_02: candidate with open gaps, not ready to freeze (2026-10-16)

## What m8_02 is

m8 is m7 plus one E exception (`generate.py` `transform_e_m8`). An outstation RST that is exactly 49 (READ) or 37
(control) octets ahead of E's frontier is placed at the master's RCV.NXT and counted as outcome 16. Before m8, E
dropped it as `OUT_DROP_AHEAD`.
- **Source:** `full_source('m8')` reproduces `response_only.p4` here byte for byte.
- **Compile:** N12/E12/T11 on SDK 9.13.1 (local) and 9.13.2 (switch); mirror guard PASS.
- **Model:** all eight drivers pass (`model_summary.json`). m8_01 failed placement and is retained.

## Gaps (code review, 2026-10-16). Each one blocks a freeze.

1. **The abort case can pass the flushed branch falsely.**
   - `model_contention.py` `outstation_abort_while_held_*` stops capturing after 1.5 s of quiet. T's response
     fallback comes later, and the next case's drain would discard it.
   - The case reads no counters: neither E cell 16 nor T's flush or release cells.
   - So "the +37 row fired" (SELECT: one RST at s+g, no response) is inferred, not measured.
   - READ took the released branch (RST at s+g+61, response delivered once), so **the +49 row has never been shown to
     fire.**
   - Needed: an extended capture, plus outcome deltas that require exactly one E-16 and one flush on the flushed
     branch, and no E-16 with exactly one `RESP_RELEASE` on the released branch.
2. **OPERATE abort is missing.** Directive section 2 names READ, SELECT and OPERATE. OPERATE (held for J) would
   exercise the 37-octet row deterministically.
3. **No negative cases.** Missing: RST at +48 or +50, RST at +49 with nothing held, bare RST, and a fresh handshake
   after the abort.
4. **RST checksum and ACK not asserted.** The model's veth does not validate checksums, while a Linux master drops an
   RST with a bad checksum. The RST bytes and checksum must be asserted.
5. **`request()`'s relayed flag is ignored in the case.**
6. **Bare RST (no ACK bit).**
   - `shape_t` gives it `r_SH_NOACK` = 5, and the frontier and image tables match shape 4 only. It is therefore
     **forwarded with its native, untranslated SEQ, not dropped**, and does not reset the master (behind RCV.NXT when
     g > 0, ahead when g = 0).
   - This predates m8.
   - Inference, not verified here: a Linux outstation aborting an established connection sends RST|ACK, while a bare
     RST is the reply to a segment for a connection the outstation no longer has.
7. **The rows are weaker than the docstring says.** They key on the distance (49/37) and the RST bit only, not on T
   holding anything.
   - Placement is always exactly the frontier.
   - An RST that follows 49 or 37 outstation bytes that E dropped for another reason (MERGED, OVERLAP, ODD) now resets
     the master.
   - Two held responses (distance 98) still drop as AHEAD.
   - Blind-injection exposure rises from one to three accepted SEQ values per frontier, which is negligible against
     2^32.

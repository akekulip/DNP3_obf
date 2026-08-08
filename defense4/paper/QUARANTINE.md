# Quarantine lifted for the bounded Introduction (2026-08-07)

The Introduction quarantine is lifted, and the Introduction was rewritten to match the accepted
verdict, TIMING EXPERIMENTS PARTIAL WITH CLOSED CLAIM BOUNDARY
(`../timing/evidence/EXPERIMENTAL_EVIDENCE_FREEZE.md`). The two claims that were held are now written
correctly:

- The result is stated as normalizing the measured response time to a fixed value with the whole
  distribution and its late tail reported in the evaluation, not as a perfect constant, and only for
  the D2/D4 modes on the corrected binary.
- Byte preservation is stated as a design property (the switch edits no packet) plus the paired
  comparator evidence, not as a live dual-capture result.

What the Introduction explicitly does NOT claim, because those parts are not complete: the controlled
negative-path tests run live, a live paired-byte dual capture, cross-device classification, size
concealment, and device indistinguishability across vendors. These are named as future work.

The story order was fixed per the review: it leads with why general traffic obfuscation cannot work
for ICS/SCADA (plaintext and CRC-protected traffic, unmodifiable endpoints, correctness bounds, and a
timing rather than size fingerprint), states the four constraints that follow, then the in-network
approach, then contributions bounded to the accepted evidence. The thesis is stated directly.

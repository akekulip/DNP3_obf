# Internal control token — threat & visibility model (Part 7)

The IBSPG construction (Part 6) uses an internal blocker token. This defines precise terminology and the
**evidentiary bar** that any internal token must clear: it must be provably invisible to the external
observer on the protected WAN link. There is no external-chaff requirement; there is a hard external-
visibility prohibition.

## Terminology (precise)

- **REAL packet** — an original DNP3 ACK or response from Vision/master or Hulk/outstation. Its bytes are
  never altered; it is what the external observer legitimately sees, at a normalized time.
- **INTERNAL CONTROL TOKEN** — a switch-generated packet that exists ONLY to coordinate scheduling/release.
  It must: (a) remain entirely inside the ASIC / on internal loopback ports; (b) be consumed (dropped) on
  an internal path; (c) NEVER egress a protected physical port (dp9→Vision, dp11→Hulk); (d) not replace a
  real packet; (e) not alter any real packet's bytes. The IBSPG blocker is an internal control token.
- **EXTERNAL CHAFF** — a synthetic packet that EGRESSES a protected WAN port as cover traffic. **Prohibited.**
  The distinguishing test is purely: *does it leave a protected physical egress?* If yes → external chaff
  (forbidden), regardless of intent. If no → internal control token (permitted, subject to the proof below).
- **CLONE** — a P4 `Clone`/`Mirror`-produced copy of a packet. Permitted ONLY as an internal control token
  (consumed internally); a clone that egresses a protected port is external chaff.
- **MIRROR COPY** — an egress/ingress mirror session copy; same rule as CLONE.
- **LOOPBACK PACKET** — any packet on an internal loopback / recirculation port. Permitted internally; must
  never be forwarded to a protected physical egress except as the RELEASE of a real packet (which restores
  the real packet's bytes and strips any internal header).

## The evidentiary bar (must be met before any IBSPG claim)

An internal token is only acceptable if PROVEN non-observable. For every microbenchmark that uses one:
1. **Capture on both protected physical egress ports** (Vision-facing dp9, Hulk-facing dp11), for the full
   run, and show **zero** internal-token frames — only the expected real DNP3 frames, byte-identical.
2. **Per-port TX counters** on dp9/dp11 must equal the real-packet count exactly (no surplus TX = no escape).
3. **The internal port's** counters may show the token traffic (that is expected and internal).
4. A distinguishing marker on the token (e.g. a private ethertype / a reserved internal MAC) so any escape
   is unambiguous in the capture.

A token that cannot be shown to satisfy (1)+(2) is treated as **external chaff and rejected**, not
relabeled. "Internal" is an evidence claim, not an assertion.

## Byte-identity & ordering still hold

The internal token never touches real-packet bytes: real ACK/response are held unmodified in Q_HOLD and
released byte-identical (any internal bridge header is stripped before a protected egress, as in the
GATE-1-validated deparser discipline). The token only changes *which internal queue is occupied*; it cannot
reorder or mutate a real packet beyond the intended ACK-before-response normalization.

## Failure modes that would violate this model (watch for in tests)

- A blocker token mis-forwarded to dp9/dp11 (escape) → external chaff → FAIL. (Capture proof catches this.)
- A release path that emits the internal bridge header on a protected egress → byte-identity FAIL.
- A token consuming a real packet's slot such that a real packet is dropped → correctness FAIL.

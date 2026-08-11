# Joint timing + size anti-fingerprinting defense — build spec

One Tofino-1 pipeline that makes an outstation's wire transcript **device-independent** so a
passive observer cannot tell an SEL-751 (Case A), ION7550 (Case B), or AB1400 (Case B) apart from
the master↔outstation DNP3-over-TCP flow. Timing is already built and silicon-validated; this spec
adds the **size** axis and composes the two into one program.

Grounded in two feasibility analyses (2026-08-11): the Tofino resource half (p4-dataplane-engineer)
and the DNP3-semantics half (power-systems-expert). Both read the real sources and corpus.

## Threat / observer model

A passive on-path observer records every packet of the flow and tries to identify the device from:
handshake (TCP options / data-offset / MSS / window / TTL), ACK mode (separate vs combined),
timing (CLRT = ACK→response latency), response **size** (TCP-visible `ip.len`/`tcp.len`), and the
DNP3 **object variation** byte. Indistinguishability = the observed tuple is the same public
canonical value for every device.

## Already closed on silicon (do not rebuild)

- **Timing** — ACK and RESPONSE held and released on public deadlines (T_A = t_A+D_A,
  T_RESP = T_A+D_R) → constant observed CLRT independent of native timing. Four-queue strict-priority
  ladder qid7>6>5>4 + K=64 blocker reservoir, internal loopback dp8, pktgen dp68. Validated
  2026-08-10 (D2/D4 240/240 held+deadline-released, RESP_BYPASS 0). Source:
  `DNP3/defense4/timing/p4/defense4_timing.p4`, `defense4_caseA.p4`.
- **Handshake + ACK-mode** — TCP handshake rewritten byte-identical; separate ACK suppressed so a
  Case-A device presents as Case-B. Silicon byte-identical. Source:
  `DNP3_fixed_transcript/experiments/.../combined_normalizer.p4`.

## The size leak (real numbers, quiescent corpus)

7 analog input points (start=1, stop=7) returned to the poll:

| Device | Static analog object | B/pt | Payload | Wire response |
|---|---|---|---|---|
| SEL-751 | G30 **V3** (32-bit, no flag) | 4 | 28 B | **54 B** |
| AB1400  | G30 **V3** (32-bit, no flag) | 4 | 28 B | **54 B** |
| ION7550 | G30 **V1** (32-bit, with flag) | 5 | 35 B | **61 B** |

- SEL-751 ≡ AB1400 already (54 B, V3). ION7550 differs by exactly 7 B (the per-point flag octet of
  V1 × 7 points).
- The **variation byte (V1 vs V3) is itself a fingerprint that survives length padding** — length
  equalization alone does not defeat a parsing observer.
- Corpus is **quiescent (0 event objects in 1,546 responses)** → 54/61 B is the **static floor**.
  Live Class-1/2/3 polls return the event backlog, so operational length tracks event count.

## Why size must be done response-side (no stateless request-side fix)

The real poll is a Group-60 **all-points Class read, qualifier 0x06** (func 0x01, packet 5 of the
capture). The request carries no size field; the **outstation** decides which events/points and which
encoding width. Every request-side rewrite either drops events (fills the event buffer, raises
IIN2.3 — breaks the SOE) or changes request length (forces the same per-flow seq translation).
The range-expand primitive (`size_read_range.p4`) is valid **only** for explicit start-stop range
READs (qual 0x00/0x01) and correctly fails open on the real poll. IEEE 1815-2012: Table 4-1 function
codes; Group-30 variations (V1 = 32-bit+flag, V3 = 32-bit no-flag); qual 0x06 = all-points; variation
0 = outstation default; CONFIRM retires events.

## Pipeline (one program, ingress core frozen)

Resource facts: ingress timing core is 12/12 stages, crit-path 10, PHV groups B0-15 and W0-15
**exhausted** — zero ingress headroom. Egress is **0/12, separate PHV** — this is where the size
layer lives. The bidirectional per-flow `flow_idx` the translator needs is **already built** by the
timing core (`tbl_fold`/`tbl_flow_idx`); the FIN/RST retire path (`tag_clear`) hosts the Δ-reset.

- **Layer 0 — ingress timing core: UNCHANGED, byte-preserving.** Holds/releases per the validated
  deadlines. Not touched.
- **Layer S — egress size-canonicalizer + seq/ack translator (NEW):**
  1. Re-hash the 5-tuple to `flow_idx` (Hash extern is free in egress).
  2. **Canonicalize the response** to one public form: rewrite the static analog block to the
     public **variation V3** (strip the ION7550 V1 flag octet, or insert to reach the public form),
     and pad to a single **public fixed length L** with DNP3-legal decoy analog objects — proper
     16-byte CRC blocks, link-header length octet bumped, each DNP3 block CRC recomputed. Padding
     is **valid DNP3 objects**, never trailing octets (an observer/parser must see a well-formed
     frame).
  3. **Per-flow seq/ack translation**: `reg_delta` (bit<32>, egress, keyed `flow_idx`) accumulates
     the byte delta; apply `seq += Δ` on outstation→master and `ack −= Δ` on master→outstation.
     `reg_last_resp_seq` (bit<32>) makes retransmit-of-the-last-response idempotent.
  4. **Deparser**: recompute DNP3 block CRC + IPv4/TCP checksums.
- **Pad to a single fixed public L** so Δ-per-response is a **compile-time constant** → the TCP
  checksum fixup is a guarded constant add, sidestepping the runtime-carry ICE risk. (Fixed-count
  DNP3-legal decoy is the same trick and equally Class-6-safe.)

## Seq-translation bounded contract (what makes the scalar Δ correct)

`{ lossless, in-order on the LAN, single response outstanding, SACK off/tolerated, Δ reset on
FIN/RST/SYN per flow_idx, retransmit-of-last handled via (reg_last_resp_seq, Δ_at_last), everything
else fails open forward (untranslated) }`. The DNP3 poll pattern (serialized READ→response→CONFIRM,
~400 ms apart, one response outstanding) sits inside this box by construction.

## Claim boundary (state exactly this in the paper)

**IN SCOPE:** observed (handshake, ACK-mode, timing, **static response size + object variation**) is
device-independent (a single public canonical value). **OUT OF SCOPE (principled):** live
event-backlog length variance — normalizing it would require withholding or fabricating events,
corrupting the SOE. **Device coverage:** silicon proof is one relay (SEL-751); observed tuple = the
public canonical value, i.e. device-independence *by construction* on one device. True two-device
byte-equality (SEL-751 vs ION7550/AB1400 identical on the wire) is the size line's device-matrix
work, named as deferred. The joint program **deliberately breaks** the timing core's
byte-preservation invariant, so application correctness (master SOE decodes, CRCs valid) must be
**re-established on silicon**, not inherited.

## Gates

1. **Compile gate (no hardware):** bf-p4c 9.13.2 build of the joint program — ingress timing core +
   egress canonicalizer + seq-translator — **0 errors**. The egress Δ + wholesale-checksum path is
   the new, unproven compile and the make-or-break step; the request-range primitive already clears.
2. **Wire gate (Vision-side capture = observer vantage, physical SEL-751, READ-only, 800 polls):**
   assert on the wire — (a) response `ip.len`/`tcp.len` (never `frame.len`) constant = public L
   regardless of point values; (b) object variation byte = public V3 for every response; (c) CLRT
   constant at the public deadline; (d) TCP health: 0 retransmits, 0 resets, DNP3 CONFIRM present,
   master SOE decodes byte-correct, including one **induced retransmit-of-last** to exercise
   Δ-idempotency; (e) master stack shows no dup-ACK gap.

## Corrections to fold in

- `CHARTER.md` / `RESULT.md`: the real poll is a **func-0x01 Group-60 all-points Class READ (packet
  5)**; the oracle's `break`-on-first-`05 64` frame lands on the **DISABLE_UNSOLICITED handshake
  (packet 2, func 0x15)**. Both fail open, so no result changes, but relabel the claim boundary to
  "qual-0x06 Class poll" and point the fixture at packet 5.

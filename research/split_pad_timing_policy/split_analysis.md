# Split Analysis — When, What, and How to Split (and When Not To)

_Synthesis of Agent A (DNP3 protocol), Agent B (TCP/packetization), and Agent C (traffic analysis),
2026-07-13. Research/design only. Evidence tags: [M] measured this rig · [S] standard · [V] vendor ·
[P] paper (abstract-level) · [I] inference · [H] hypothesis. Detailed source records:
`agent_reports/agent_A_dnp3_split_padding.md`, `agent_B_tcp_packetization.md`,
`agent_C_traffic_analysis.md`._

## 0. Bottom line
Splitting is **byte-preserving and safe on any traffic class**, and it reshapes Axis-1
{largest-packet, per-packet-size, packet-count, segment/frame count} — but it **never changes total
bytes**, so it does not hide message size. On the read plane (large multi-fragment responses) it is
the primary structural obfuscator; on small control responses it yields few chunks and does not hide
the CROB-count size leak. Aggressive splitting has two failure modes a naive design misses: at the
finest granularity the **chunk count itself scales with size** (re-leaking magnitude), and a
distinctively split flow is a **beacon**. Split therefore belongs *with* timing normalization and,
for size, a *future* padding phase — never alone.

## 1. What the master actually requires (the key correction) [S][I, source-grounded]
OpenDNP3's `LinkLayerParser` is **stream-oriented**: it accumulates the TCP byte stream in a
`ShiftableBuffer` and finds frames by content (sync `0x05 0x64` + LENGTH), ignoring where TCP segment
boundaries fall (`LinkLayerParser.cpp:88-138`). Because TCP delivers a reliable in-order byte stream,
**an on-path splitter can cut at *any* byte offset and the master reconstructs byte-identical
frames.** What the master rejects is byte **modification** — every 16-byte block carries a CRC and the
header a CRC over bytes 0–7; any mismatch drops the frame (`LinkFrame.cpp:51-69`). So:
- **CRC-block alignment is a defense/auditability choice, NOT a reassembly requirement.** The harness
  splits on CRC boundaries so every emitted chunk ends on a completed, already-valid CRC block — which
  keeps a mid-path DNP3-aware observer or Zeek `dnp3` analyzer from ever seeing a bisected CRC, and
  makes "no byte modified" self-evident. **Do not claim the master enforces CRC-block splitting** — it
  does not; it enforces *byte preservation*.

_Plain language: the receiver rebuilds the message no matter where you chop the byte stream — it only
cares that no byte changed. Cutting on the 18-byte checksum blocks is our choice so a watching IDS
still sees clean sub-units._

## 2. WHAT to split — the boundary menu [S][M]
| Boundary | Byte-preserving | Master reassembles | Use |
|---|---|---|---|
| **B0** arbitrary TCP byte offset | Yes | Yes | Maximum flexibility; needs pacing to survive the wire (§4) |
| **B1** DNP3 CRC 16-byte block boundary (the harness primitive) | Yes | Yes | **Preferred** — auditable, IDS-clean; measured 2407 B → 141/71/36/18 chunks (bpc 1/2/4/8), 0 retransmits, 800 measurements + CONFIRM [M] |
| **B2** link-frame boundary (≤292 B) | Yes | Yes | Coarsest CRC-aligned split |
| **B3** transport-segment boundary | Yes | Yes | ≡ B2 on this wire (1 TPDU ⇔ 1 link frame) |
| **B4** application-fragment boundary | Yes | With constraint | Re-split *within* a fragment freely; never merge/reorder across the CONFIRM handshake or touch the CONFIRM |
| **X1–X3** modify data byte / edit LENGTH-header / insert non-block bytes | **No** | **No** (CRC/framing fail) | Forbidden — needs CRC recompute |

## 3. HOW to split — surviving the wire (Agent B) [M][S]
Splitting only stays split on the wire because of **pacing, not `TCP_NODELAY`.** TCP preserves no
write boundaries; the measured 141 chunks → 145 segments held because the 10 ms inter-chunk gap drains
the send buffer and defeats TX autocorking (`tcp_autocorking=1`, verified [M]) and RX GRO. `NODELAY`
only removes Nagle. **A zero-delay "aggressive" split is NOT guaranteed to keep distinct wire
segments** — autocorking/GSO can re-merge them. **Capture vantage matters:** a sender-host trace
under-counts (GSO), a receiver-host trace over-merges (GRO); only a mid-path SPAN/tap is ground truth
— and that is exactly the passive attacker's vantage, so a real split is fully visible to the threat
model.

## 4. WHEN to split
Split when (all true): the natural packet/frame size is a distinguishing feature; the response is
large enough to repartition meaningfully (read plane, not a 37–256 B control response); a safe
boundary exists (always — B0–B4); packet-count increase is within budget; **and timing normalization
is applied so the new chunk schedule does not become a fingerprint.** The main value is on the read
plane, where a 12,204 B / 49-frame / 20-segment response can be reshaped.

## 5. WHEN NOT to split (the honest limits) [M][I]
- **Small control responses.** SELECT/OPERATE responses are ~1 frame (37–256 B, ≤16 blocks); splitting
  yields few chunks and does not hide the CROB-count size leak.
- **The re-leak trap (Agent C/I).** At the finest granularity, chunk count = CRC-block count ∝ size ∝
  N, so `I(chunks; N) ≈ I(size; N)`: aggressive splitting **relocates** the magnitude leak from
  byte-size to packet-count rather than removing it, at 3–7× wire-byte cost (headers).
- **The new-fingerprint trap (Agent B/C).** ~141 sub-64 B segments are a segmentation pattern no real
  DNP3 device emits; a fixed split pattern is itself distinctive, and a lone split device is a
  **beacon** (shaped-vs-unshaped is trivially separable — Wang, CCS 2015). Split fleet-wide with
  randomized/decoy-matched (not fixed) granularity, or not at all.
- **Total-volume is never hidden.** A sum-the-chunks attacker recovers the original size regardless
  (Agent C AT-1 / Agent I A9).

## 6. Recommended split policy
Read plane: split on **B1 (CRC-boundary)** for auditability, at a **decoy-/target-matched, not fixed**
granularity, *paced* (so it survives the wire) and *paired with timing normalization* (so chunk gaps
don't re-fingerprint). Control plane: generally **do not split** (few chunks, no size benefit, safety
gating dominates). Never split without pacing; never present split as hiding total size. The split
must be *created* upstream (software replay server or a DPU); Tofino can only *pace* already-split
chunks, not create the split (that needs TCP-sequence rewrite = out of phase) [Agent F].

_Plain language: split big reads into many small paced packets on the checksum seams, vary the pattern
so it isn't its own signature, and always delay-normalize the pieces. Don't bother splitting the tiny
control replies, and never pretend splitting hides how many bytes were sent._

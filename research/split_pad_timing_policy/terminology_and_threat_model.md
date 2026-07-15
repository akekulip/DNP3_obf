# Terminology and Threat Model

_Precise definitions so the study never conflates distinct mechanisms, and the threat model against
which every claim is scoped. 2026-07-13._

## Threat model
A **passive on-path observer** that does not inject or block, and sits at a **mid-path SPAN/tap** (the
ground-truth capture vantage — sender-host traces under-count via GSO, receiver-host over-merge via
GRO). It may exploit: packet and response **size**, response **volume**, **packet count**,
**segmentation** (TCP-segment / DNP3-link-frame / application-fragment counts),
**request→ACK-bearing-response delay**, **inter-packet/inter-frame gaps**, **TCP behavior**, and
**repeated polling** (the SCADA case — it observes the same class many times).

**The observer model must be stated in two tiers, because it decides whether the defense matters.**
- **Metadata-only observer (the one this defense targets).** A NetFlow/IPFIX-grade or
  volume/timing-only collector that records sizes, counts, and timings but does **not** perform deep
  packet inspection of DNP3 objects. Passive SCADA fingerprinting **without DPI** is a documented,
  practical threat (`jeon2016passive`, "Passive Fingerprinting of SCADA … without Deep Packet
  Inspection"; Formby's CLRT attack is itself metadata/timing-based). Against this observer the size and
  timing side channels are the *only* channels, and closing them is the whole game.
- **Full-DPI observer on cleartext DNP3.** A passive analyst that parses the SELECT/OPERATE objects
  reads the CROB count **directly off the payload** — for that observer the metadata side channels are
  redundant and this defense adds little in the current cleartext phase.

**The honest reconciliation (do not hide the mechanism discontinuity).** In the **current
byte-preserving, cleartext phase** the in-network mechanism (Tofino parses the function code at the
TCP-payload offset; the splitter cuts on visible DNP3 CRC blocks) is best understood as **defense in
depth against the metadata-only observer** — it removes the size/segmentation/timing side channels that
a no-DPI collector uses, and it degrades gracefully. It does **not** defeat a full-DPI observer on
cleartext; only **encryption** does that. Under a **future encrypted-tunnel phase** the payload is
hidden (so metadata *becomes* the dominant channel and the defense's value is maximal), but the
cleartext in-network primitives (FC parse, CRC-boundary split) no longer apply — **shaping relocates to
the cooperating tunnel endpoints** (`padding_analysis.md` §5). This is a real mechanism discontinuity:
the "buildable now" in-network line and the "future" size-hiding line are **partly different systems**,
and the study states so rather than implying one continuous mechanism. The single most important
open experiment (A0, `evaluation_plan.md` §14) is to **quantify how much CROB count a direct
cleartext payload read recovers**, which measures exactly how much the current-phase metadata defense
is worth.

Scope: one software OpenDNP3 outstation, one rig — an information-theoretic / regression setting on a
single device, **not** a device-identification (cross-device) claim.

## Definitions (keep these distinct)
- **Split** — divide an existing response into smaller wire units, preserving all original DNP3 bytes
  and order (`join(chunks) == original`). Changes segmentation/packet-count/per-packet-size; **not
  total bytes**.
- **Segmentation** — the *natural* division of a message into units by a protocol layer (DNP3 link
  frames ≤292 B; TCP segments ≤MSS). Distinct from split (a *deliberate* re-division).
- **Fragmentation** — DNP3 application-layer division into APDU fragments (≤`maxTxFragSize`=2048 B),
  serialized by the application CONFIRM. Distinct from TCP/IP fragmentation.
- **Padding** — adding bytes / packets / apparent volume to make a small transaction resemble a larger
  target. **Adds data by definition** (contrast: split and timing add none). Nine distinct categories
  (see `padding_analysis.md`); currently none is byte-preserving and safe.
- **Dummy traffic** — injected packets/objects with no operational meaning (a padding sub-type).
- **Cover traffic** — injected whole *transactions* (e.g. decoy reads) to hide which/when, not size.
- **Timing normalization** — releasing outputs on a **class-independent** schedule so timing is
  (approximately) independent of the secret. Un-averageable. Adds no bytes.
- **Timing randomization (jitter)** — adding i.i.d. noise to release time. **Averageable** by a
  repeated-poll observer (converges to the class mean).
- **Pacing** — controlling the *rate*/inter-packet gap of a burst (bounds rate, not first-packet
  latency). Required for a split to survive the wire.
- **Delay / hold** — releasing an existing packet later than ready (the timing lever; `max(ready,
  deadline)`).
- **ACK-bearing response** — a TCP segment with the ACK flag set that also carries a DNP3 response
  payload (piggyback). **The primary observable here** (9/9 measured).
- **Pure ACK** — a zero-payload TCP ACK. Largely absent on this wire.
- **DNP3 CONFIRM** — application function code 0x00; the master's acknowledgement that serializes
  multi-fragment responses and flushes the outstation event buffer. **Inviolable** (never suppress/
  synthesize/hold beyond the 5 s outstation timeout).
- **Criticality** — the physical consequence of a control. **Not encoded in any DNP3 field** — DNP3
  reveals operation *type* only. Criticality comes solely from an operator-supplied allowlist.
- **Anonymity profile** — a public, class-independent shaping *target* (size/packet-count/timing
  distribution) that multiple devices/transactions are shaped toward to form an anonymity set. Must
  not be selected using a secret variable.

## Evidence vocabulary (used throughout)
**[M]** measured this rig · **[S]** standard-defined · **[V]** vendor/kernel-documented · **[P]**
paper-reported (abstract/metadata-level unless noted) · **[I]** engineering inference · **[H]**
untested hypothesis.

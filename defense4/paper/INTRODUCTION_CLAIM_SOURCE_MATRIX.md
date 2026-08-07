# ►► UPDATED after the lifecycle fix (2026-08-07)
Two rows change because the D2/D4 lifecycle defect was fixed and the freeze reached TIMING EXPERIMENTS PASS:
- Claim 15 (modes): the response-only mode (D2) is NO LONGER a non-shaping boundary. After the fix D2
  normalizes CLRT to a fixed value (10 ms) with zero bypass, as do D3/D4. Allowed wording: "the
  response-deadline and dual-deadline modes normalize CLRT to a fixed value." A new sub-claim: the
  transaction state is preserved across the ACK release so a later response is held.
- Claim 16 (D4 normalization): now SUPPORTED as a TRUE normalization (Campaigns A+B, n=120: D4 CLRT
  p5 9.98, p50 10.00, p95 10.03; not the pre-fix bimodal mixture). Source: EXPERIMENTAL_EVIDENCE_FREEZE.md.
The barred claims and the single-relay / READ / CLRT-only limits are unchanged.

# Introduction claim-to-source matrix

Every substantive Introduction sentence maps to a primary source (a cited paper or a frozen
experimental artifact) with the allowed wording and the wording that would overclaim. Experimental
claims cite `EXPERIMENTAL_EVIDENCE_FREEZE.md` (the frozen result on the corrected binary `97175e7d`). Citation
keys are from `defense3/references.bib`.

| # | claim | source | direct or inference | allowed wording | would overclaim |
|---|---|---|---|---|---|
| 1 | Fingerprinting lets an attacker learn a target system's device type, role, vendor, or behavior during reconnaissance | kohno2005remote, radhakrishnan2014gtid, shu2006fingerprint | direct (these define device/protocol fingerprinting) | "fingerprinting reveals device type and behavior and supports reconnaissance" | "fingerprinting fully identifies any device" |
| 2 | Fingerprinting applies to ICS and power-grid systems | formby2016control, jeon2016passive | direct (both fingerprint ICS/SCADA devices) | "fingerprinting extends to industrial control and grid devices" | "all grid devices are fingerprintable" |
| 3 | Cross-layer response time (CLRT) is a fingerprinting observable for ICS devices | formby2016control | direct (Formby et al. introduce CLRT as a device-fingerprinting feature) | "prior work identifies device response timing (CLRT) as a fingerprinting feature" | "CLRT uniquely identifies every device" |
| 4 | Traffic obfuscation includes size, timing, rate, and pattern shaping | wright2009morphing, dyer2012peekaboo, cai2014csbuflo, juarez2016wtfpad, apthorpe2019stp | direct | "obfuscation defenses shape size, timing, rate, or communication pattern" | "obfuscation defeats all traffic analysis" |
| 5 | Many obfuscation defenses assume encrypted or payload-opaque traffic | dyer2012peekaboo, juarez2016wtfpad, sirinam2018df, wright2009morphing | inference from the website-fingerprinting setting (they shape encrypted flows) | "many Internet-oriented defenses assume encrypted or payload-opaque traffic" | "all prior defenses require encryption" (explicitly barred) |
| 6 | Padding-only or naive shaping defenses can be defeated | dyer2012peekaboo, sirinam2018df | direct (both show countermeasures fail) | "some shaping countermeasures have been shown to fail against stronger analysis" | "obfuscation is futile" |
| 7 | Visible legacy ICS content distinguishes real protocol traffic from dummy or transformed traffic | east2009taxonomy, fovino2010modbus, lin2013bro | inference (DNP3 is plaintext and CRC-protected, so injected/altered content is detectable) | "because legacy ICS traffic is plaintext, an observer can tell real protocol exchanges from dummy or altered ones" | "no obfuscation is possible on plaintext ICS" |
| 8 | Legacy field devices and deployed protocols are hard to modify | east2009taxonomy, cardenas2011attacks, sridhar2012cyber | direct (vendor firmware, deployed base) | "legacy outstation firmware and deployed protocols cannot be changed in practice" | "devices can never be updated" |
| 9 | An in-network defense on a programmable switch can shape traffic transparently | wang2020pinot, meier2022ditto, kfoury2021p4survey | direct (PINOT and ditto do in-network obfuscation on programmable data planes) | "programmable switches enable transparent in-network traffic shaping" | "programmable switches solve ICS privacy" |
| 10 | The defense must preserve endpoints, protocol exchanges, original packet contents, and correctness | EVIDENCE_FREEZE (byte-identity, 0 drops, 1200/1200 responded) | direct experimental | "the design preserves the endpoints, the DNP3 exchanges, the original bytes, and delivery" | "the design is provably correct in all cases" |
| 11 | Timing parameters must stay within DNP3, TCP, polling, and QoS limits | EVIDENCE_FREEZE (delays below poll interval, fail-open horizon, policy max) | direct experimental | "the added delay stays within the polling interval, the retransmission and QoS bounds" | "the delay has no effect on the protocol" |
| 12 | The defense assumes a trusted plaintext observation point | EVIDENCE_FREEZE threat framing; defense3 threat model | direct (the switch sees plaintext; the observer is passive on-path) | "the switch is a trusted observation and control point on the plaintext path" | "the defense needs no trust assumptions" |
| 13 | One programmable switch between master and device controls when the ACK and RESPONSE become externally visible | EVIDENCE_FREEZE (modes, silicon) | direct experimental | "a single switch controls when the original ACK and RESPONSE become visible" | "the switch controls all device behavior" |
| 14 | The original packets remain queue-resident; internal blocker tokens recirculate; TM scheduling provides the release | EVIDENCE_FREEZE + DEFENSE4_BOTTLENECKS + source | direct (queue residency, 0x88C1 tokens, strict-priority release) | "the original packets stay queue-resident while internal tokens recirculate and the traffic manager releases them on schedule" | "the switch can recall an arbitrary enqueued packet" (explicitly false; TM cannot) |
| 15 | Event-driven, ACK-deadline, response-deadline, and dual-deadline transformations are modes of one framework; the transaction state is preserved across ACK release so a later response is still held | EVIDENCE_FREEZE (fixed binary: D1/D2/D3/D4 all shape; D2 0 bypass) | direct experimental | "the four modes are configurations of one framework; the response obligation survives the acknowledgment release" | "eliminates the fingerprint" (barred) |
| 16 | The response-deadline and dual-deadline modes normalize the variable native CLRT to a fixed value on silicon | EVIDENCE_FREEZE (fixed binary, Campaigns A+B n=120: D2 10.00, D4 10.00 p5 9.98 p95 10.03; 0 bypass) | direct experimental | "the response-deadline and dual-deadline modes normalize the measured CLRT to a fixed value on hardware" | "eliminates the fingerprint / device-indistinguishable" (barred) |
| 17 | Implemented on Tofino-1 within resource limits | EVIDENCE_FREEZE + DEFENSE4_BOTTLENECKS (12/12 ingress) | direct experimental | "the framework fits a Tofino-1 pipeline at 12 of 12 ingress stages" | "the design scales to any pipeline or flow count" (barred) |
| 18 | Evaluated on one physical relay (SEL-751), CLRT only | EVIDENCE_FREEZE | direct experimental | "evaluated on one physical SEL-751 relay, transforming the CLRT observable" | "device-indistinguishable across vendors" (barred: single relay) |

## Barred claims (from the directive, enforced in the draft)

full anonymity; elimination of every fingerprint; size obfuscation; encrypted-packet processing
without plaintext visibility; general multi-flow scalability; complete combined-response protection;
SBO support; production readiness; optimal delays (say calibrated or selected); universal ICS
applicability; "first" without a systematic literature claim; cross-device indistinguishability from
a single relay. The draft distinguishes mechanism feasibility from fingerprint-classification
effectiveness and treats the individual defenses as configurations of one framework.

# SEL-751 vs ION7550 — native + SBO comparison (2026-08-14)

One physical Tofino, same testbed. Master Vision .1 -> switch -> SEL-751 .7 (link 0) / ION7550 .8 (link 10).
READ-only + non-actuating SELECT. NO OPERATE sent to the ION (unaudited controls — gated).

## Native comparison (pcap dev_cmp.pcap, 30 polls each, from the wire)
| Property | SEL-751 | ION7550 |
|---|---|---|
| DNP3 taxonomy | **Case A** (separate ACK) | **Case B** (combined ACK) |
| separate TCP ACK before response | 30/30 | 0/25 |
| CLRT (T_resp - T_ack) | exists (native ~1.2ms; 20ms under active RRC in this capture) | **none** (0.00 ms — no separate ACK) |
| G10V2 READ response (wire) | **49 B** (group 10 var 2, count 23) | **17 B** (no G10 points — null/error response) |
| 2-CROB SELECT echo (wire) | 49 B | **32 B** (status 0x00, IIN 0x9000 — accepts controls at pts 0/1) |
| CROB control points | yes (audited empty-fanout decoys RB02/RB04 = idx 1/3) | **yes at idx 0/1 — UNAUDITED** |

## Findings
1. **Natively distinguishable.** SEL vs ION differ in READ size (49 vs 17 B), SELECT echo size (49 vs 32 B), and ACK-mode (separate vs combined). A passive observer separates them trivially.
2. **The RRC/BOR/CLRT defense is Case-A specific.** It normalizes a separate-ACK CLRT and re-anchors ACK/echo to T0+A/T0+R — neither exists on the Case-B ION. The size carve normalizes segmentation of eligible 49-B responses (SEL); the ION's 17/32-B responses are not eligible and pass through unchanged.
3. **=> Multi-device indistinguishability is NOT achieved by this defense** (confirming the E-phase single-device limitation with real two-device evidence). The defense suppresses/normalizes the SEL's own signature; it does not make the SEL and ION look alike.

## SBO / OPERATE
- **SEL SBO + BOR: demonstrated** (Case A; guarded {1,3} audited empty-fanout decoys; ACK@T0+A, echo@T0+R, echo-ACK=R-A invariant).
- **ION SBO: NOT executed.** The ION has real CROB controls (SELECT at pts 0/1 returns SUCCESS), so an OPERATE would actuate physical ION points. There is NO ION isolation audit. Per the SEL safety protocol, an ION OPERATE requires (a) a read-only ION isolation audit proving the target points drive nothing, and (b) explicit authorization. Also, being Case B, the BOR ACK-anchoring mechanism does not apply to the ION regardless.

# Final claim matrix — Defense4 unified RRC+BOR (E0-E8, one physical Tofino + SEL-751)

| Claim | Evidence | Result | Limitation |
|---|---|---|---|
| Timing normalization | PCAP CLRT: native READ 1.27ms/SELECT 2.11ms (var) -> defended both 4.001ms std 0.02 | **PASS** | Classes READ/SELECT/OPERATE-echo |
| Size normalization | Segment vectors: native [49] 100/100 -> defended [28,21] 963 resp, byte-exact | **PASS** | Eligible 49-byte responses |
| Exactly-once BOR | Master-facing: 1 OPERATE/txn; relay-facing NOT captured | **PARTIAL** | Guarded {1,3}; relay-facing/T0+J evidence unavailable (dp68 internal) |
| Formby CLRT suppression | JS(nat vs def)=0.92-0.996; MI 0.223->0.018 bits; classifier BA 0.592->0.500 (chance); TCP-ts absent | **PASS** | Network CLRT threat; SINGLE SEL-751 -> signature REPLACEMENT, not multi-device |
| Testbed unchanged | E0 record: same relay/endpoints/links/switch/config across native & defended; dp8/dp10 internal loopbacks (switch impl, not inline devices) | **PASS** | Internal loopback addition documented |
| Safety | All 32 relay outputs OPEN before/during/after; zero actuation; index6 refused | **PASS** | No breaker actuation |

## Completion criteria (E7)
**Timing:** READ/SELECT CLRT follows policy (4.001ms) ✓; ACK/echo anchored T0+A~21/T0+R~25 ✓; varying J (2/6/12) does NOT reveal native interval (A/R/echo-ACK invariant, echo-ACK std 0.027) ✓; BOR exactly-once at T0+J = **PARTIAL** (master-facing exactly-once ✓, relay-facing T0+J inferred not captured); retransmission = offline-model + master-facing (hardware relay-facing PARTIAL). => **TIMING: PASS with T0+J relay-facing PARTIAL.**
**Sizing:** real-SEL READ/SELECT [28,21] ✓; guarded OPERATE echoes [28,21] ✓; source-copy escapes 0 ✓; reassembly byte-exact (28+21=49) ✓. => **SIZING: PASS.**
**Formby suppressed:** native CLRT distribution replaced by policy ✓; defended CLRT invariant to J ✓; attacker balanced-acc 0.592->0.500 chance ✓; size no longer exposes class ✓; TCP timestamps absent ✓. => **FORMBY (network CLRT, single-device signature replacement): SUPPRESSED.**

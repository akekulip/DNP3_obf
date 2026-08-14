# Final claim matrix (audit-corrected) — Defense4 unified RRC+BOR (E0-E8, one Tofino + SEL-751)

| Claim | Evidence | Result | Limitation |
|---|---|---|---|
| Timing (CLRT) normalization | size_verdict/clrt CSVs: native READ 1.27/SELECT 2.11ms (var) -> defended both 4.001ms std 0.02 | **PASS** | READ/SELECT; A/R include ~1ms master-facing offset |
| Size normalization | size_verdict.csv: 1280 defended responses ALL [28,21], seq-contiguous, DNP3-CRC-valid, IP/TCP-cksum-valid, 0x 49B escapes | **PASS** | Byte-identical-to-source NOT claimed (no source oracle); CRC/checksum-valid 49B reconstruction shown |
| Exactly-once BOR | Master issued 1 OPERATE/txn; relay-facing multiplicity NOT observable | **PARTIAL / not demonstrated** | dp68 internal (no relay-facing tap); guarded {1,3} |
| Formby feature suppression | MI(class;CLRT) 0.424 bits (>>null) -> 0.0018 bits (within null CI); classifier BA 0.592->0.500; JS_distance nat-vs-def 0.914-0.997; TCP-ts absent | **PASS (feature suppression)** | READ-vs-SELECT transaction class, NOT device identity; transaction-disjoint (not session-disjoint); single SEL -> signature REPLACEMENT |
| Testbed unchanged | E0 record: same relay/endpoints/links/switch/config across native & defended; dp8/dp10 internal loopbacks (switch impl) | **PASS** | Internal loopback documented |
| Safety | All 32 relay outputs OPEN before/during/after; zero actuation; index6 refused | **PASS** | No breaker actuation |

## Tightened claims (audit)
- **Size:** "Every defended response was two sequence-contiguous TCP payloads totaling 49 bytes; every reconstructed 49-byte DNP3 frame passed DNP3 block-CRC and IP/TCP checksum validation; zero 49-byte source-copy escapes." (NOT byte-identical-to-source.)
- **Timing:** "The master-visible echo-ACK interval remained ~4.00 ms (std ~0.027) across J=2,6,12 ms." A/R medians = configured 20/24 + ~1 ms master-facing path/capture offset; startup ACK maxima 23.48/25.61/27.57 ms at J=2/6/12 (documented, not hidden).
- **Exactly-once:** "The master issued one OPERATE per transaction. Relay-facing release multiplicity was not observable." (NOT duplicate-suppression evidence.)
- **Formby:** "A native-trained READ-vs-SELECT CLRT classifier fell from 0.592 to 0.500 balanced accuracy after normalization; MI(class;CLRT) fell from 0.424 bits to within the permutation null." This is transaction-class FEATURE suppression, not multi-device identification.
- **JS:** values are Jensen-Shannon DISTANCE (scipy); divergence = distance^2. Proves distribution REPLACEMENT, not suppression by itself.

## Completion criteria (E7)
Timing: CLRT->policy ✓; echo-ACK invariant to J ✓; A/R offset+outliers documented; exactly-once at T0+J = **not demonstrated** (relay-facing). Sizing: all defended [28,21], CRC/cksum-valid, seq-contiguous, 0 escapes => **PASS**. Formby: CLRT distribution replaced ✓, invariant to J ✓, transaction-class attacker -> chance ✓, size no longer exposes class ✓, TCP-ts absent ✓ => **feature suppression SUPPORTED for the network-CLRT threat, single-device signature replacement**.

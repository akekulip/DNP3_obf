# Read this first

Corrected package for the live-inline **Defense 2** result: the Tofino-1 holds the DNP3 RESPONSE
until an ACK-relative deadline, running inline with a physical SEL-751.

Every number in every document and figure here is generated from `authoritative_results.json`,
which is computed from the four shipped pcaps and nothing else. Rebuild it all with
`source/build_v2.sh`.

## Where to start

| I want to | open |
|:--|:--|
| read the result | `DNP3_INLINE_LIVE_REPORT_V2.pdf` (13 pp, single column) |
| read it in a browser | `index_v2.html` |
| explore the data | `interactive_v2.html` (switches campaign and variant; JSON embedded) |
| just the numbers | `RESULT_V2.md` |
| capture it myself | `WIRESHARK_GUIDE_V2.md` |
| read the code | `CODE_WALKTHROUGH_V2.md`, `source/dnp3_timing_normalizer_inline.p4` |
| what this does NOT show | `LIMITATIONS_V2.md` |

## The four shipped captures

| campaign | treatment | pcap | n (all-state) | n (steady-state) |
|:--|:--|:--|--:|--:|
| A | native | `campaignA_native_n10.pcap` | 10 | 9 |
| A | protected | `campaignA_protected_n11.pcap` | 11 | 10 |
| B | native | `campaignB_native_n13.pcap` | 13 | 12 |
| B | protected | `campaignB_protected_n13.pcap` | 13 | 12 |

Two live campaigns were run. Both are shipped and both are analysed. Neither corrects the other.

## Headline, reported two ways

| campaign | all-state sd ratio | steady-state sd ratio |
|:--|--:|--:|
| A | 224.4x | 34.5x |
| B | 328.1x | 80.3x |

The all-state variance is strongly influenced by the first transaction of each capture, which is
the connection-cold one (A: 22.660 ms, B: 37.215 ms). Excluding it, the steady-state distribution still
shows substantial normalization. Both are true; neither is "the" result.

## Three things to know

**CLRT is the Cross-Layer Response Time** (Formby et al., NDSS 2016), measured here as
t(DNP3 RESPONSE, function 129) minus t(the qualifying pure TCP ACK), at the master-side capture
point.

**The blocker reservoir is host-seeded.** It circulates internally afterwards and the release
decision is data-plane controlled, but the seed frames come from the host. This is not fully
internal blocker generation.

**Entropy is quoted only with its binning.** Bin origin 0.0 ms, half-open [lo, hi), and the sample
count stated. At 1 ms bins campaign B protected occupies one bin; campaign A protected occupies
two, because its minimum falls the other side of the edge.

## Verification

- Two independent analysis pipelines agree on every transaction to better than 1 microsecond.
- Every transaction in all four captures paired exactly: 0 ambiguous, 0 validation failures.
- The exact-pairing analyzer passes 10 adversarial tests (`source/test_analyzer_pairing.py`).
- 0 retransmissions, 0 duplicate ACKs, 0 reordering, all DNP3 CRCs valid.

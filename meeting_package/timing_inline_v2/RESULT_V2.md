# RESULT (corrected)

Generated from `authoritative_results.json`; every value below is recomputed from the four shipped
pcaps by two independent pipelines that agree to better than 1 µs.

## Shipped evidence

| campaign | treatment | pcap | sha256 (head) | n (all) | n (steady) |
|:--|:--|:--|:--|--:|--:|
| A | native | `campaignA_native_n10.pcap` | `c2ed9fc1d3f8f27f…` | 10 | 9 |
| A | protected | `campaignA_protected_n11.pcap` | `cba20f3872a3511b…` | 11 | 10 |
| B | native | `campaignB_native_n13.pcap` | `2065ff7ae308724a…` | 13 | 12 |
| B | protected | `campaignB_protected_n13.pcap` | `1a94024dc96d502b…` | 13 | 12 |

## All-state (every paired transaction)

**All-state**

| campaign | treatment | n | median | min | max | sd (pop) | sd (sample) | p95 | range |
|:--|:--|--:|--:|--:|--:|--:|--:|--:|--:|
| A | native | 10 | 2.126 | 1.061 | 22.660 | **6.261** | 6.600 | 22.660 | 21.599 |
| A | protected | 11 | 25.057 | 24.998 | 25.077 | **0.028** | 0.029 | 25.077 | 0.079 |
| B | native | 13 | 1.603 | 1.061 | 37.215 | **9.514** | 9.902 | 37.215 | 36.154 |
| B | protected | 13 | 25.070 | 25.003 | 25.083 | **0.029** | 0.030 | 25.083 | 0.080 |

## Steady-state (first, connection-cold transaction excluded)

**Steady-state**

| campaign | treatment | n | median | min | max | sd (pop) | sd (sample) | p95 | range |
|:--|:--|--:|--:|--:|--:|--:|--:|--:|--:|
| A | native | 9 | 2.090 | 1.061 | 4.018 | **1.008** | 1.069 | 4.018 | 2.956 |
| A | protected | 10 | 25.060 | 24.998 | 25.077 | **0.029** | 0.031 | 25.077 | 0.079 |
| B | native | 12 | 1.373 | 1.061 | 9.059 | **2.320** | 2.423 | 9.059 | 7.998 |
| B | protected | 12 | 25.069 | 25.003 | 25.083 | **0.029** | 0.030 | 25.083 | 0.080 |

## Compression, both variants

| campaign | all-state sd ratio | steady-state sd ratio |
|:--|--:|--:|
| A | 224.4x | 34.5x |
| B | 328.1x | 80.3x |

The all-state variance is strongly influenced by the first transaction of each capture. The
steady-state distribution also shows substantial normalization. Neither figure is "the" result.

## Release tail

Protected observations land near, not on, the 25 ms target: campaign A median +0.057 ms, campaign B
median +0.070 ms.

## Entropy

Reported only with binning. Bin origin 0.0 ms, half-open [lo, hi).

| campaign | treatment | bin width | occupied bins | entropy (bits) | n |
|:--|:--|--:|--:|--:|--:|
| A | native | 10 µs | 10 | 3.3219 | 10 |
| A | native | 50 µs | 9 | 3.1219 | 10 |
| A | native | 100 µs | 9 | 3.1219 | 10 |
| A | native | 500 µs | 5 | 2.0464 | 10 |
| A | native | 1 ms | 5 | 2.0464 | 10 |
| A | protected | 10 µs | 7 | 2.6635 | 11 |
| A | protected | 50 µs | 3 | 1.2407 | 11 |
| A | protected | 100 µs | 2 | 0.4395 | 11 |
| A | protected | 500 µs | 2 | 0.4395 | 11 |
| A | protected | 1 ms | 2 | 0.4395 | 11 |
| B | native | 10 µs | 11 | 3.3927 | 13 |
| B | native | 50 µs | 9 | 2.8074 | 13 |
| B | native | 100 µs | 8 | 2.6535 | 13 |
| B | native | 500 µs | 7 | 2.3535 | 13 |
| B | native | 1 ms | 6 | 2.0349 | 13 |
| B | protected | 10 µs | 7 | 2.6235 | 13 |
| B | protected | 50 µs | 2 | 0.8905 | 13 |
| B | protected | 100 µs | 1 | 0.0000 | 13 |
| B | protected | 500 µs | 1 | 0.0000 | 13 |
| B | protected | 1 ms | 1 | 0.0000 | 13 |

## Integrity in the shipped captures

0 retransmissions, 0 duplicate ACKs, 0 reordering, 0 malformed frames, all DNP3 CRCs valid,
response length constant at frame 120 B / IP 106 B / TCP payload 54 B, DNP3 link addresses
master 1 and outstation 0.

# ACK-Based Device Fingerprinting — Before vs After the ACK-Delay Defense

_Companion to `attacker_eval.md`, focused on the TCP-ACK channel. Data: device-specific transactions from the six real PCAPs (`ack_trace_characterization.csv`). Supervised = capture-level split (train base PCAP → test disjoint L PCAP); unsupervised = k-means / agglomerative on standardized features, scored against the true device. The defense transforms only per-transaction **timing**; response bytes and sizes are never touched._

Scenarios: **native** (before) · **timing_gap_norm** (the implemented defense: request→response pinned to 25 ms + SEL-751 ACK→response gap pinned to 20 ms) · **plus_ackmode** (what-if upper bound that also hides the ACK mode — not byte-preserving, shown only to expose the residual).

## 1. Supervised fingerprinting — accuracy (Random Forest, capture-level split)

Chance (majority class) ≈ 0.400. Higher = attacker identifies the device better.

| feature family | native | timing_gap_norm | plus_ackmode |
|---|---:|---:|---:|
| ack_only | 0.810 | 0.810 | 0.400 |
| timing | 0.511 | 0.797 | 0.400 |
| size | 0.500 | 0.500 | 0.500 |
| all | 0.888 | 0.888 | 0.500 |

Native all-features confusion (rows=true, cols=pred; AB1400, ION7550, SEL751):

```
  AB1400   1384    615      0
 ION7550    505   3493      1
  SEL751      2      0   3997
```

## 2. Unsupervised clustering — Adjusted Rand Index (no labels, k=3)

ARI = 1.0 means the clusters perfectly recover the devices; 0.0 means no better than random. NMI and purity in the JSON.

| feature family | native | timing_gap_norm | plus_ackmode |
|---|---:|---:|---:|
| ack_only | 0.654 | 0.658 | 0.000 |
| timing | -0.000 | 0.433 | 0.000 |
| size | 0.184 | 0.184 | 0.184 |
| all | 0.567 | 0.563 | 0.184 |

## 3. Reading

- **ACK alone is a strong fingerprint natively.** `ack_only` random-forest accuracy is **0.810** (chance 0.400): the SEL-751 is perfectly isolated by the mere presence of a pure TCP ACK before its response, and its request→ACK / gap values pin it further.

- **The implemented defense closes the ACK-*gap* magnitude but not the ACK *mode* — and does not even reduce timing separability.** Under `timing_gap_norm`, `ack_only` stays high (0.810 → 0.810) because a separate ACK still *exists* for the SEL-751 — pinning its gap to a constant does not make it look combined. Worse, `timing`-family accuracy **rises** (0.511 → 0.797) and clustering on timing **improves** (ARI −0.000 → 0.433): pinning SEL-751's ACK→response gap to a device-correlated 20 ms constant *re-encodes* the ACK mode into the timing features, so normalizing the gap magnitude moves the leak rather than removing it. (Earlier drafts described this as a "collapse," which contradicts the table above; the numbers show timing separability increasing, not falling.)

- **Only when ACK mode is also hidden does the ACK fingerprint fall.** The `plus_ackmode` what-if drops `ack_only` accuracy to 0.400 and its clustering ARI toward 0 — but that step is **not byte-preserving** and is not implemented; it is exactly what a Phase-2A socket-induced ACK-mode primitive would have to achieve. **Size still leaks** (ION7550's 61 B response) so `all`-features identity never reaches chance here.

- **Honest scope:** a distributional simulation on measured native timings, not a live capture of a defended device. It shows which channel each attacker relies on and precisely what the timing/ACK-delay defense removes versus leaves.


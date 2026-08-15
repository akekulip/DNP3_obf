# Gate S3 Offline Result

Status: **PASS — offline construction only**

Date: 2026-08-14

Policy: `S3-RNL-256-v1`

## Result

The deterministic prototype transforms complete captured or synthetic inner Ethernet frames into a fixed observer transcript and recovers every in-policy frame byte-for-byte after authenticated decoding.

Every successful epoch emits:

- 22 outer Ethernet cells;
- 256 captured bytes per cell, excluding physical FCS;
- 5,632 total captured outer bytes;
- the same ordered size, count, direction, slot, relative-timing, public-metadata, and direction-specific counter-stride vectors.

The one retained overflow case emits the configured cover transcript and releases no partial inner frames.

## Evidence

The reproducible package is in `evidence/s3_offline/`.

| Gate | Result | Evidence |
| --- | --- | --- |
| Corpus | 137 epochs: 100 balanced primary RN-L, 36 additional successful boundary/control/captured cases, 1 explicit overflow | `corpus_manifest.json`, `analysis_labels.csv` |
| Exact reconstruction | 136/136 successful epochs exact; 100/100 primary RN-L exact | `roundtrip_summary.json`, trusted-boundary PCAPs |
| Fixed public transcript | All 13 structural invariants pass | `observer_outer_cells.csv`, `observer_outer_cells.pcap`, `observer_stats.json` |
| Mutual information | 0.0 bits for total bytes, size vector, count vector, direction sequence, slot timing, and whole structural transcript | `observer_stats.json` |
| Statistical attacker | Logistic regression and random forest balanced accuracy 0.2 with 95% CI `[0.2, 0.2]`, equal to five-class chance | `observer_stats.json`, `observer_features.csv` |
| Active/fault behavior | 45/45 cases pass: loss, exact/conflicting duplication, reorder, replay, tag corruption, malformed public/private metadata, direction, overflow, and nonce restart | `fault_cases.csv` |
| Reproducibility | Same-path clean regeneration produced the same manifest hash `64a43ac1d814a428f10593d6810df68c997d5b49934390dc9924e22f3eb9810c`; every listed file passed `sha256sum -c` | `manifest.sha256`, `offline/reproduce.sh` |
| Unit/adversarial tests | 69 passed | `offline/test_s3_offline.py` |

The committed OpenDNP3 fragmented response bundle fits the response slot and is recovered exactly as a labeled response-only projection. The corresponding full extracted transaction is retained separately as `open-full-overflow-000` because its seven tail ACK frames exceed the provisional two-cell tail capacity. It is not silently treated as successful.

## Claim boundary

S3 supports this claim:

> For the declared offline RN-L corpus and policy, the construction hides the protected length from the evaluated outer size/count/direction/slot transcript while recovering every in-policy inner Ethernet frame exactly after authenticated decoding.

S3 does not establish:

- live or hardware-observed real size normalization;
- the Tofino `ens1`/`bf_kpkt` punt/reinject boundary;
- endpoint-transparent TCP behavior on a live network;
- RN-T or multi-device indistinguishability;
- production key storage, counter persistence, recovery, performance, latency, or cryptographic fitness;
- successful delivery of an overflowed transaction.

The old `[49] -> [28,21]` result remains a **SEGMENT SHAPE ONLY** negative control and is not promoted by this gate.

## Reproduce

From the repository root:

```bash
bash defense4/size/real_size_normalization/offline/reproduce.sh
python3 -m pytest -q defense4/size/real_size_normalization/offline/test_s3_offline.py
sha256sum -c defense4/size/real_size_normalization/evidence/s3_offline/manifest.sha256
```

No SSH, packet injection, package installation, P4/BFRT action, interface change, or relay operation is part of this result.

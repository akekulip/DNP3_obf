# TIMING_FINGERPRINTING_ANALYSIS.md (directive §6)

One reproducible pipeline (`scripts/fingerprint_eval.py`, deterministic, stdlib) over the committed
raw PCAPs. It separates the channel the defense acts on from the channels it does not, so the claim is
not overstated (security review O1).

## 1. The CLRT-magnitude channel — what the defense reduces

Observer entropy of the ACK→response interval, Miller-Madow bias-corrected, with bootstrap 95% CIs
(2000 resamples, fixed seed), at the resolutions in §6:

| resolution | native corpus SEL-751 (n=300) | native live relay (n=120) | protected G=25 ms (n=100) |
|---|---:|---:|---:|
| 1 ms | 2.73 bits, CI [2.52, 2.84] | 2.39, CI [2.02, 2.59] | **0.00, CI [0.00, 0.00]** |
| 500 µs | 3.73, CI [3.52, 3.80] | 2.94, CI [2.49, 3.15] | **0.00, CI [0.00, 0.00]** |
| 100 µs | 5.80 | 3.95 | 0.09, CI [0.00, 0.25] |
| 50 µs | 6.67 | 4.71 | 0.38, CI [0.15, 0.59] |
| 10 µs | 7.81* | 5.76* | 1.62 |

**Reliable result:** at the well-sampled resolutions (1 ms = 17 bins, 500 µs = 23 bins over 300
samples), the CLRT-magnitude channel drops from **2.73 bits to 0.00 bits** — the interval carries no
information at ms resolution after normalization, and the CI is [0,0]. At 50–100 µs it drops to
≤0.4 bits (what remains is the ~1.7 µs release-tail jitter, not device behaviour).

`*` **Caveat (review O5):** the 10 µs point estimates (194 bins over 300 samples ≈ 1.5 samples/bin)
are undersampling-biased and unreliable — the plug-in/MM estimator saturates toward log2(bins) when
bins ≈ N, and the point estimate even exceeds its own bootstrap CI. The defensible entropy figures are
the ≥500 µs rows; the finer rows are shown only for completeness and are marked unreliable.

Corroborating spread (from Stage A / the 100-rep campaign): native CLRT sd 10.33 ms → protected
0.010 ms; median 2.03 ms → 24.999 ms.

## 2. The channels the defense does NOT touch — the honest residual

Timing normalization acts only on the CLRT *value*. Device *identity* on this corpus is carried by
other channels, which the defense leaves unchanged:

| channel | per-device values | discriminates 3 devices? | device-ID balanced accuracy (chance 0.333) |
|---|---|:---:|---:|
| **ACK mode** | SEL-751 separate; AB1400, ION7550 combined | yes | 1.000 (SEL-751 is the unique separate-ACK device) |
| **TCP stack** (TTL, MSS, window) | AB1400 (128, 1478, 2048); ION7550 (64, 1460, 4380) | yes | 1.000 |
| **CLRT magnitude** | only SEL-751 has a CLRT at all | **no** | **N/A — anonymity set of 1** |

(The SEL-751 SYN is absent from its corpus capture, so its TTL/MSS/window are not extractable here;
its ACK-mode value alone already makes it uniquely identifiable, so the TCP-stack channel is not even
needed to separate it.)

**The decisive honesty point (review O1):** only one device in the corpus emits a separate ACK, so the
CLRT channel cannot discriminate devices — there is nothing for the SEL-751 to be confused with. And
the two channels that *do* discriminate (ACK mode, TCP stack) are at balanced accuracy 1.000 and are
untouched by the timing defense. **On this corpus, closing the CLRT-magnitude channel therefore
yields no reduction in a real passive device classifier's accuracy.**

## 3. What may be claimed (directive §10)

Supported: *the mechanism converts the ACK→response interval into a policy-controlled constant on
Tofino-1 — a data-plane-scheduled, chaff-free, byte-preserving timing state — reducing the
CLRT-magnitude channel from 2.73 bits to 0.00 bits at ms resolution on the physical SEL-751's real
traffic.* This is a **mechanism** result plus a **within-channel** entropy reduction.

NOT supported / explicitly disclaimed: device anonymity; size obfuscation; that closing CLRT reduces a
real multi-channel device classifier (it does not, on this corpus, because ACK mode and TCP stack
remain at 1.000); a live inline held session (this is replay of real frames, not a live relay session
held in real time); generality across devices/TCP configurations.

To turn the within-channel result into a demonstrated *security* result would require a fleet of
separate-ACK devices (or one device across operational states) all normalized to a **shared** G, with
a before/after classifier accuracy holding ACK-mode and TCP-stack constant — future work, noted in the
security review (O2).

## Reproduce

```
python3 scripts/fingerprint_eval.py --corpus "Traffic Trace" \
  --native-corpus "Traffic Trace/SEL751.pcap" \
  --native-live research/timing_final/evidence/native/native120.pcap \
  --protected research/timing_final/evidence/protected/final100_g25.pcap \
  --out research/timing_final/evidence/fingerprinting/fingerprint_eval.json
```

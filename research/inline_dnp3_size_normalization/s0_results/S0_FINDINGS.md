# S0 — Offline byte-transform smoke test: findings

*Run 2026-07-18, `s0_smoke_test.py`, system python3 3.8.10 (sklearn 1.3.2, numpy 1.24.4). Seed 20260718.
Unprivileged, no switch, no P4. Input: the Phase-01 characterization of the six replayed device
captures (`dnp3_split_harness/reports/ack_trace_characterization.csv`, n=22,988). Full numbers in
`s0_results.json`.*

## What the data is
Three devices, each emitting exactly two response sizes: a common **37 B** (all devices) and a
device-"large" response — **AB1400→54**, **ION7550→61**, **SEL751→54**. `req_size` is 22/35 for all
devices (request type, not device). So the entire size fingerprint on these READ traces is:
**61 ⟹ ION7550 (unique); 54 ⟹ AB1400 or SEL751 (ambiguous); 37 ⟹ any.** AB1400 and SEL751 are
size-indistinguishable. Native size-only balanced accuracy **0.493** (chance 0.333),
`I(size;label)` **0.487 bits** — a real but **modest, single-device-tail** fingerprint.

## Headline results (per bucket count B)

| B | idealized (exact-target) bal-acc | idealized MI (bits) | **constant-block** bal-acc | **constant-block** MI (bits) | mean/max added B |
|---|---|---|---|---|---|
| native | 0.493 | 0.487 | 0.493 | 0.487 | 0 / 0 |
| 1 | **0.333 (chance)** | **0.0002 (≈null)** | **0.493** | **0.487** | 14.1 / 24 |
| 2 | **0.333** | **0.0002** | **0.493** | **0.487** | 14.1 / 24 |
| 4 | 0.493 | 0.322 | 0.493 | 0.487 | 8.6 / 17 |
| 8 | 0.493 | 0.322 | 0.493 | 0.487 | 8.6 / 17 |

Gates: **G1 (up-only prefix) PASS**, **G9 (no MSS crossing) PASS** (max padded 73 B ≪ 1460) for every B.

## Three findings

**1. The mechanism works — with an *exact-target* (variable-length) filler.** Coarse bucketing
(B=1, and B=2 which degenerates to one bucket on this discrete data) drives size-only balanced accuracy
from 0.493 to **chance (0.333)** and MI from 0.487 bits to **≈0** — a full collapse of the size channel,
at ~14 B mean overhead. This is a Verdict-A signal for the *read* fingerprint.

**2. ★ The *constant-block* simplification does NOT collapse the fingerprint — the key refinement.**
A constant 18-byte filler block (16 data octets + 2-byte CRC, the "baked-in CRC" variant the research
design preferred) can only land padded sizes on a per-response grid: 37→**73**, 54→**72**, 61→**61**.
Because the native size gaps (17 between 37 and 54) are not multiples of the block, the three sizes map
to **three distinct padded sizes** → the device distinction is **fully preserved** (MI stays 0.487,
bal-acc 0.493). **Exact size collapse requires a *variable-length* filler** — choose the pad length per
response to hit a common target — which means a **runtime CRC** (different filler bytes ⇒ different CRC),
not a constant baked-in CRC. This is feasible: `p4_decoy` already computes CRC-16/DNP at runtime over a
field tuple on this chip. So the design refinement is concrete: **use a variable-length octet-string
filler with a runtime CRC, not a constant block.** The "constant block / baked CRC" optimization trades
away the exact-collapse the defense needs.

**3. Over-bucketing re-exposes the heavy-tail (the append-only k=1 residual, demonstrated).** At B≥4,
naive quantile boundaries separate 54 and 61 into different buckets, leaving ION7550's 61 B isolated
(k=1) → MI 0.322 bits, bal-acc back to native 0.493. This is exactly the append-only ceiling the eval
design predicted: **the bucket that captures a device's large response must also contain another
device's response, or that device stays identified.** Bucket boundaries must be chosen to mix devices
(here: group 54 and 61 together), not by naive size quantiles.

## Scope caveat (important, do not overclaim)
These are **READ-response** traces, whose size fingerprint is modest (native bal-acc 0.493, MI 0.49 bits)
and driven entirely by ION7550's one distinct size. The **strong ~0.99 size fingerprint (14.6 B/CROB)
lives on CONTROL responses** (the multi-CROB SBO data), which are **not** in this dataset. S0 therefore
validates the pipeline and the phenomena (collapse, block-granularity, heavy-tail residual) on the read
axis; **the strong control-response size axis is the natural next dataset** and would exercise a many-
valued size distribution where bucketing has real work to do.

## Verdict signal for the program
- **Pipeline validated**, real privacy/overhead numbers produced, gates pass. ✓
- **Mechanism collapses the size channel** — but **only with a variable-length / runtime-CRC filler**;
  the constant-baked-CRC block is refuted for exact collapse on non-congruent sizes. (Design refinement,
  not a blocker — runtime CRC is on-chip-proven.)
- **Heavy-tail k=1 residual is real and boundary-policy-dependent** — buckets must mix devices.
- **Next:** rerun S0 on the control-response (CROB) size distribution for the strong-fingerprint case;
  and carry the "variable-length filler + runtime CRC" refinement into the mechanism (Probe A/B) design.

---

# S0 (control-response) — the STRONG size fingerprint (CROB-count)

*Run 2026-07-18, `s0_control_smoke_test.py`. Input: `control_response_sizes.csv` — per-N SBO
operate-response sizes extracted from `dnp3_multicrob_harness/captures/sweep/multicrob_n{N}.pcapng`
(`tshark ... dnp3.al.func==129`). Secret = **CROB count N** (control-command complexity), not device
identity. n=1 per N (one SBO per N), N=1..16.*

## What the data is
Response size is a **near-perfect proxy for the CROB count**: 16 distinct sizes **37→256 B** for
N=1→16 (slope **14.6 B/CROB**, R²=0.9999). This is the strong, rich, 16-valued distribution where
bucketing has real work — and the secret is operationally sensitive: a passive observer reading the
response size learns **exactly how many control points the operator is operating**. Native
information leakage = full `H(N) = 4.0 bits`; best-guess N-recovery = **1.000** (a size↔N bijection).
(Metrics are information-theoretic + analytic N-recovery; with one sample per N a CV classifier is
degenerate.)

## Headline results (uniform prior over N=1..16; chance N-recovery = 1/16 = 0.0625)

| B | idealized N-recovery / MI (bits) | **constant-block** N-recovery / MI | mean/max added B | anonymity k, isolated |
|---|---|---|---|---|
| native (16) | 1.000 / 4.00 | 1.000 / 4.00 | 0 / 0 | k=1, 16 isolated |
| 8 | 0.500 / 3.00 | **1.000 / 4.00** | 7 / 15 | k=2, 0 isolated |
| 4 | 0.250 / 2.00 | **1.000 / 4.00** | 22 / 45 | k=4, 0 isolated |
| 2 | 0.125 / 1.00 | **1.000 / 4.00** | 52 / 103 | k=8, 0 isolated |
| **1** | **0.0625 (chance) / 0.00** | **1.000 / 4.00** | 110 / 219 | k=16, 0 isolated |

Gates G1/G9 PASS every B (max padded 265 B ≪ MSS 1460).

## Findings (decisive)

**1. A clean privacy-vs-overhead Pareto — the mechanism collapses the strong fingerprint.** Idealized
bucketed up-padding drives N-recovery 1.000 → **0.0625 (chance)** and MI 4.0 → **0 bits** as buckets
coarsen from 16 to 1, at mean overhead 0 → 110 B. Real, meaningful knee: e.g. B=4 hides N to a quartile
(N-recovery 0.25, MI 2 bits) at only +22 B mean; B=1 fully hides the CROB count at +110 B mean. Because
the N-distribution is uniform, equal-count buckets mix cleanly — **0 isolated buckets, no heavy-tail
residual** (unlike the mode-heavy read data, where naive quantiles isolated ION7550's tail — the
residual is *distribution-shape-dependent*, and the fix is device/level-mixing boundaries).

**2. ★★ The constant-block filler achieves ZERO privacy at EVERY bucket count.** With an 18-byte
constant block, padding each of the 16 sizes up to a common bucket ceiling lands them on 16 *distinct*
sizes (e.g. at B=1 the "collapsed" sizes are 256, 257, 258, 259, … — one per original N), so N stays
fully recoverable (N-recovery 1.000, MI 4.0 bits) no matter how few buckets. This is the read-data
finding made stark: **a constant baked-CRC block cannot normalize a size distribution whose values are
not congruent modulo the block; exact collapse *requires* a variable-length (runtime-CRC) filler.** The
constant-block optimization is refuted for the size axis.

## Combined S0 verdict
- **The size-normalization mechanism works** and cleanly collapses even the strong (perfect,
  16-valued, R²=0.9999) CROB-count size fingerprint to chance — a real privacy-vs-overhead Pareto.
- **Firm design refinement (now confirmed on both datasets):** the filler must be **variable-length
  with a runtime CRC** (feasible on-chip — `p4_decoy` proves runtime CRC-16/DNP); the constant baked-CRC
  block is refuted for exact size collapse.
- **Heavy-tail k=1 residual is distribution-shape-dependent** — absent for the uniform CROB-count
  distribution, present for the mode-heavy device-read distribution; bucket boundaries must be chosen to
  mix secret-levels.
- Two distinct privacy targets are now both demonstrated on real data: device identity (read traces,
  weak) and **operator-action / CROB-count (control responses, strong)** — the same primitive serves both.


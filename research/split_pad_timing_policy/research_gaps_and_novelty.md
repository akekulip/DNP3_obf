# Research Gaps and Novelty — Skeptical Assessment

_Hostile-review assessment of the combined split/pad/timing study, written to anticipate Agent J and a
TDSC/S&P/NDSS reviewer. Agent J reviews this and every deliverable; surviving caveats fold back here.
2026-07-13._

## 1. The contribution — stated so it survives review
> A **conditional, criticality-aware split/pad/timing decision policy** for byte-preserving in-network
> DNP3 obfuscation, grounded in a measurement that the same secret (CROB count / request complexity)
> leaks on **both** the size channel (14.6 B/CROB, R²=0.9999) and the timing channel (≈0.18 ms/CROB,
> R²≈0.99) — with the honest, load-bearing finding that **timing is closeable now by class-independent
> normalization, but size is NOT** (split preserves total bytes; no byte-preserving DNP3 padding
> exists at any layer; only a future encrypted-tunnel/endpoint phase closes it).

The strongest parts are two **negative results** plus a **decision framework**, not a "we hid
everything" claim:
1. **No byte-preserving DNP3 padding exists** (parser-level generalization of the measured
   invalid-index dead end). A genuine, publishable negative result for the ICS-privacy literature.
2. **Splitting cannot hide total size and relocates the magnitude leak to packet count** (`I(chunks;N)
   ≈ I(size;N)`); at the finest granularity it even re-leaks magnitude and creates a beacon.
3. **A criticality-aware conditional policy** that is dominant on *both* privacy and safety (shape the
   high-value/low-risk read plane; bypass the low-value/high-risk control plane), with the size
   residual recorded rather than papered over.

## 2. Reviewer attacks and honest answers
- **"Does splitting hide anything if total bytes remain visible?"** No — and we say so. Split reshapes
  segmentation (useful on the read plane, defeats per-packet-size and some segmentation classifiers)
  but never total volume; a sum-the-chunks attacker (A9) recovers size. Split's value is structural
  and as a carrier for timing normalization, not size hiding.
- **"Is padding protocol-safe?"** No safe byte-preserving padding exists this phase — a measured +
  source-grounded negative. Do not claim otherwise.
- **"Does timing normalization create a new fingerprint?"** Risk on two vectors: a degenerate constant
  target is itself distinctive (prefer a class-independent distribution), and a lone shaped device is a
  beacon (shape fleet-wide + decoy-match). Both are experiments (P3/P4/P7 + a detect-the-defense test),
  not assertions.
- **"Can the attacker average away randomization?"** Yes for i.i.d. jitter; not for class-independent
  normalization — attacker-model-dependent (repeated-poll observer), made measurable by the averaging
  attacker (A8).
- **"Is one outstation enough?"** For a configuration/complexity information-theoretic claim, yes; for
  device **classification**, no (needs ≥2 stacks). And the flagship leaks are **n=1 per N-level** — a
  clean 10-point line, not a replicated law; replication (E1/E1′, ≥30/N, bootstrap CI) is a
  precondition for every downstream claim.
- **"Is CROB count a legitimate database-size proxy?"** No — CROB count is control-command complexity;
  database size is a separate read-plane channel (size ∝ point count, ~5.7 B/pt, measured) whose
  *timing* dependence is unmeasured. Do not conflate.
- **"Is the Tofino implementation realistic?"** Stages 1–2 (classify + pace) are buildable in-phase;
  Tofino can only pace already-split chunks, not create the split; first-response absolute delay is an
  **unbuilt** recirc-hold (inference, not a result). BlueField/FPGA are the native homes.
- **"Does the contribution duplicate traffic shaping?"** The mechanisms are known; the novelty is the
  DNP3-specific constraint set + the measured dual-channel leak + the honest asymmetry + the
  criticality-aware conditional policy — not the primitives. NetWarden already does in-network
  timing-only shaping, so "byte-preserving" alone is not the wedge.
- **"Is the threat model internally consistent?"** Yes, but note: unencrypted DNP3 means the observer
  can read payload directly, so metadata fingerprinting matters most (a) when the observer ignores/
  can't rely on payload, and (b) in the future encrypted-tunnel phase. State this explicitly so the
  fingerprinting claim isn't trivially defeated by "just read the payload."

## 3. Known / borrowed / adapted / new
| Bucket | Content |
|---|---|
| Already known | CLRT is an ICS fingerprint; jitter is averageable; scheduled release bounds timing leakage; padding = adding bytes; split reshapes size distribution not total; in-network shaping feasible on Tofino |
| Borrowed | `release=max(ready,deadline)`; bucketing; WF attacker suite; DP/secret-independent shaping objectives; NSGA/ε-constraint optimization |
| Adapted to DNP3 | The distribution-matching objective on release timing (only byte-preserving axis); CRC-boundary split as auditable segmentation; the RTO/CONFIRM correctness bound; a criticality-allowlist-gated policy |
| Technically new | The **dual-channel measurement** (same secret on size R²=0.9999 AND timing R²≈0.99); the **parser-level padding negative result**; the **split-relocates-not-removes** result; the **criticality-aware conditional split/pad/timing decision policy** and target-profile architecture |
| Engineering (not research) | The policy engine in the replay server; the Tofino Stage-1/2 sketch |

## 4. What a strong paper needs (the evidence still owed)
0. **The A0 direct-payload-read baseline (the single most important missing experiment).** Because
   current-phase DNP3 is cleartext, a full-DPI observer reads CROB count off the payload directly, and
   the metadata (size/timing) defense only matters to a **no-DPI / NetFlow-grade** observer (documented:
   Jeon 2016 passive-SCADA-without-DPI; Formby CLRT) or under a **future encrypted tunnel**. Quantify
   how much the direct read recovers, so the current-phase defense's value is measured, not asserted;
   and state the **cleartext-now / tunnel-later mechanism discontinuity** explicitly (the in-network
   FC-parse/CRC-split primitives don't survive encryption — shaping then relocates to endpoints). This
   answers the reviewer's "unencrypted payload makes the fingerprinting claim trivial" attack head-on.
1. **Replicate** the n=1/N size and timing leaks (E1/E1′, ≥30/N, bootstrap CI) — precondition for all.
2. **The database-size (Class-0 read-plane) experiment** — the study is named for size; that channel's
   timing dependence is unmeasured, and it is the safe-to-shape one.
3. **One defended run** per axis (split-only, timing-only, split+timing) proving byte-preservation,
   0 retransmits/resets, DNP3 CONFIRM, 800-measurement count, and β/MI closure on the timing channel.
4. **The averaging attacker (A8)** and the **detect-the-defense attacker (A10)** made quantitative.
5. **Measure the effective RTO** on Vision (holds) and Hulk (splits) before any shaped run.
6. **≥2 stacks** before any device-classification wording.

## 5. Do-not-overclaim list
- Do NOT claim splitting hides total transaction size.
- Do NOT claim any current-phase padding is safe (none is).
- Do NOT claim timing normalization hides visible DNP3 payload content.
- Do NOT claim CROB-count size leak = database-size leak.
- Do NOT present the n=1/N sweeps as replicated laws.
- Do NOT label the Tofino recirc-hold as implemented; Tofino cannot create the split.
- Do NOT claim a device-fingerprinting result from one device.
- Do NOT recommend delaying protection/critical control; DNP3 fields never reveal criticality.
- Do NOT present a policy bypass as a shaped success.

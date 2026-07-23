# Morning Executive Summary — autonomous run 2026-07-22 → 2026-07-23

**Headline: the SIZE component of the joint size-and-time defense is PROVEN on Tofino-1
silicon.** A trace-driven Level-1 size normalizer padded every base-corpus frame to a single
128 B state, on real hardware, with **zero loss, zero reordering, zero queue growth, zero
external cover**, removing the packet-size signal entirely (mutual information 0.91 bits →
0.00 bits). The shared switch was restored to its queue-microbench baseline and verified clean.

## What I did overnight (all gated per `autunomous.md`)
1. **Gate A — builder v1.1 audit (blocking).** Two independent audits (DNP3/ICS + statistics).
   The DNP3 audit caught a **real, ground-truth-contradicting bug**: the earlier "SEL-751 ~50/50
   separate/combined" claim was an artifact of a second shared outstation (`10.0.0.2`)
   contaminating the corpus. **Fixed and retracted** — SEL-751 = 299/299 = 100 % separate,
   consistent with the locked terminology. Five statistical conditions applied. Gate A → PASS.
2. **Phase 2 — candidate selection.** `single128_corpus_baseline`: the only candidate that fits
   the existing P4 (1 state, 1 real queue, 128 ∈ pad set), has zero measured size-channel leak,
   covers the true base max (120 → 128), and has 0 unfit packets.
3. **Gate B / Phase 4 — compile.** Local bf-p4c 9.13.1 (3 ingress stages) + on-switch 9.13.2
   parity.
4. **Gate C (16/16) → Phase 5 — the single authorized hardware experiment.** Loaded
   `queue_microbench_trace_v1`, ran smoke + 4 × 150-frame campaigns, collected switch-side
   learning digests + Hulk-side wire pcaps.
5. **Rollback.** Restored the queue microbench; verified cover OFF, metronome OFF, telemetry OFF.

## The result in one table
| metric | native (input) | shaped (output on Tofino) |
|---|---|---|
| distinct packet sizes | 11 (60–120 B) | **1 (128 B)** |
| MI(size; device) | 0.909 bits | **0.000 bits** |
| MI(size; operation) | 1.892 bits | **0.000 bits** |
| loss / reorder | — | **0 / 0** (3 independent runs) |
| padding overhead | — | dir-1 54.8 B/frame, dir-2 30.8 B/frame (mean) |

- **Reproducibility:** three independent digest-complete ON runs, identical acceptance
  (150 released = 150 emitted = 150 recorded, 0 loss, 0 reorder, all 128 B).
- **A/B:** telemetry ON vs OFF changes nothing on the datapath (same 150 releases, same
  `{128:150}` wire output, `hold_ns = 0`); only digest emission differs (150 vs 0) — the learning
  digest is genuinely measurement-only.

## One correctness fix I made (and guarded)
The analyzer's reorder check sorted on a **32-bit** ingress timestamp that wraps ~14× per run,
producing a spurious "reorder" on clean data. Fixed to a wrap-robust send-order check; added a
regression test. **20/20 harness tests pass.** The unwrapped timestamps are strictly increasing
with sequence in every ON run → genuinely no reordering.

## What this does and does NOT claim (read before citing)
- **DOES:** demonstrate, on silicon, that a Tofino dataplane can normalize a trace's variable DNP3
  frame sizes to a single size with no loss/reorder — the **size axis** of the joint defense.
- **DOES NOT:** parse live DNP3/TCP (Level-1 uses a declared input-size class on synthetic replay
  frames); hide direction, timing/CLRT, ACK mode, packet count, or SBO structure; or generalize
  device/ACK-mode leakage beyond this 3-flow corpus. Those remain the timing defenses (Defense 1/2,
  frozen and untouched) and future cover work.

## State this morning
- **Switch:** queue microbench baseline restored and verified (co-resident work untouched).
- **Frozen Case-A defenses (`dcrn_defense1/2`) and their telemetry copies:** untouched.
- **Deliverables:** this summary, `HARDWARE_RESULT.md`, `FINAL_STATE.md`, `AGGREGATE_RESULT.json`,
  per-run evidence, updated harness (analyzer fix + test). Commits are staged per phase in
  Philip's name; tag `queue-trace-level1-hw-pass` applied (HW acceptance passed).

## Suggested next steps (your call — all gated)
1. Decide whether to promote Level-1 → **Level-2** (live DNP3/TCP classification instead of a
   declared class) — this is the step toward an actual inline defense and needs new dataplane work
   + a rig with the physical SEL-751.
2. Expand the corpus (more independent flows per device) so device/ACK-mode leakage becomes
   flow-cross-validatable — the Gate-A residual must-fix-before-paper.
3. Join the size axis with the timing defense on the same program (the real joint pattern), once
   you authorize touching the frozen timing path.

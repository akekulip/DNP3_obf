# Part 9 — controlled data-plane drain: result (IN PROGRESS)

Branch `research/ibspg-controlled-drain`. Tags: [DESIGN] [DOC] [COMPILED] [OBS] [REP] [FIX] [OPEN].
This document is being written as gates complete; it currently covers 9.1, 9.2, and the on-chip
mechanism (hold + negatives + matching drain + fail-open). Host-PCAP byte-identity (9.3–9.9 external)
is pending a working switch→host egress capture (see §Topology).

## Gate 9.1 — compile + resource fit [COMPILED] PASS
`ibspg_controlled_drain.p4` (SHA `3632264f79b640242620d9c5945423d04d170012f85ef01c6b6a967432f85e21`)
compiles 0-errors on local bf-p4c 9.13.1 AND on-switch 9.13.2, identical fit 11/12 ingress stages,
0 egress. Details: `p4/ibspg_controlled_drain/ibspg_controlled_drain_compile_note.md`.

## Gate 9.2 — TM readback [OBS] PASS
Q_BLOCK qid7 `max_priority=7 (HIGH)`, Q_HOLD qid1 `LOW`, both scheduling-enabled, `max_rate_enable=false`
(shaping disabled), same pg2/dp8 domain; dp8 MAC-near loopback; exactly one bf_switchd; fresh state.
Strict priority re-verified active throughout the mechanism runs.

## CORE FINDING — the hold needs a RESERVOIR (K≥64 here), not one token [OBS/REP]
Clean on-chip counters + fixed-slot timestamp registers (no trace-overflow confound) measured the hold
directly. **A single blocker token does NOT hold in this 11-stage program** — the first HELD is released
~540–860 ns after admission (essentially immediate), all 32 within ~177 µs, while the blocker loops
millions of times and strict priority is confirmed active. Sweeping blocker depth K (32 HELD, 0.6–0.8 s
window; `ctr_hold_release`):

| K | ctr_hold_release | first_release − first_hold_admit | verdict |
|---|---|---|---|
| 1  | 32 | 540 ns | LEAK |
| 8  | 32 | 562 ns | LEAK |
| 18 | 32 | 550 ns | LEAK |
| 32 | 32 | 860 ns | LEAK |
| **64** | **0** | — (no release) | **HELD** |
| **96** | **0** | — | **HELD** |

Sharp threshold between K=32 and K=64. Aggregate blocker loop rate saturates (~117 M loops/s) by K≈32 —
the dp8 loopback bandwidth is full — yet Q_BLOCK still empties enough to leak until K≥64.

### This CORRECTS the Part 8 claim (integrity) [FIX]
Part 8 (`IBSPG_HOLD_ON_SILICON_RESULT.md`) concluded "one recirculating token is sufficient, 0 leak,
empty-gap counting model overturned." **That is now refuted for the controlled-drain program.** The Part 8
evidence was a *short-duration* order test (budget≈400 loops ≈ 100 µs) on the *4-stage ring oracle*; over
a 0.6 s window with clean counters the same K=1 leaks all 32. Two compounding reasons: (a) the earlier
0-leak was measured over too short a window to see the empty-gap leak; (b) the 11-stage controlled-drain
pipeline gives each token a much lower Q_BLOCK duty cycle than the 4-stage oracle, so far more tokens are
needed to keep Q_BLOCK continuously non-empty. **The Part-5 empty-gap model (a reservoir is required) was
directionally RIGHT; the "K=1 universally sufficient / model overturned" statement was wrong.** The
required reservoir depth scales with the program's in-flight time (pipeline + loopback), not a universal
constant. Do not rely on K=1.

## Controlled-drain mechanism — on-chip validation (K=64) [OBS] PASS
ARM(slot0,gen7) → 64 blockers → 32 HELD, then a sequence of drains, one variable each:

| Event | ctr_hold_release | term_controlled | term_stale | drain_match | reject_unrel | reject_stale |
|---|---|---|---|---|---|---|
| held (0.8 s) | 0 | 0 | 0 | 0 | 0 | 0 |
| DRAIN_UNRELATED (slot 9) | 0 | 0 | 0 | 0 | **1** | 0 |
| DRAIN stale gen (slot0,gen3) | 0 | 0 | 0 | 0 | 1 | **1** |
| DRAIN_MATCH (slot0,gen7) | **32** | 1 | 63 | **1** | 1 | 1 |

- **Hold:** 32 HELD held (release=0) for 0.8 s (≫ the ~13 ms Case-A CLRT target).
- **Unrelated drain** (wrong slot): rejected, no release, blocker continues.
- **Stale-generation drain** (right slot, wrong gen): rejected (gen_mismatch blocks the drain_req write),
  no release, blocker continues.
- **Matching drain:** accepted (`drain_match=1`), all 64 tokens terminate (`timeout=0` — NOT budget
  expiry), all 32 HELD released.
- **Fail-open watchdog** (separately, K=1 large hold): budget expiry gives `ctr_block_term_timeout=1`,
  independent of the drain path.

### Counter-attribution nuance [OPEN, cosmetic]
With a reservoir, a matching drain yields `1 controlled + (K−1) stale`: the first token to loop after the
drain reads `drain_req=1` → terminates controlled + clears `active=0`; the rest read `active==0` → stale.
All K terminate *because of* the drain (root cause = drain; `timeout=0`), but per-cause attribution splits.
A clean "all controlled" attribution would need the terminate cause latched from drain_req before the
active-clear cascade — a cosmetic P4 refinement, not a correctness issue.

## Topology (CORRECTED) [OBS]
Locked pairing confirmed empirically: injecting from Hulk enp59s0f0np0 lands on **dp11** (+10 vs dp9 +2
background) → **Hulk↔dp11, Vision↔dp9**. The P4 releases to `PORT_VISION=dp9` → released frames egress to
**Vision**, not Hulk. Earlier "empty capture on Hulk" was capturing the wrong host, NOT a physical link
failure. Host-PCAP byte-identity requires capturing released frames on the host connected to dp9 (Vision)
or retargeting the release egress to dp11 (Hulk). Under evaluation.

## Host-PCAP byte-identity — VALIDATED on Vision (dp9) [OBS] PASS
The user's correction was decisive: the P4 releases to dp9=Vision, so released frames must be captured on
Vision, not Hulk. A per-hop bypass probe (neutral src MAC, real Vision NIC MAC as dst) confirmed the path:
Hulk TX +5 → dp11 RX +5 → P4 hold_enq/release 5/5 → dp9 TX +5 → **Vision enp59s0f0np0 RX +5**. Not a
physical failure — my earlier wrong-host capture. Injected frames are deterministic so they are
reconstructed in the verifier (`--held-spec`); released frames are captured on Vision.

- **Gate 9.3 (no blocker, 32 HELD):** ctr_hold_enq/release=32/32; Vision captured 32; verifier
  **PASS** — byte-identical, FIFO, 0 missing/dup/corrupt/unexpected.
- **Gate 9.7 (K=64 hold → matching drain, host-PCAP):**
  - during hold `ctr_hold_release=0` (held; nothing released before the drain);
  - after DRAIN_MATCH: `hold_release=32`, `term_controlled=1 + term_stale=63` (all 64 drain-terminated),
    `timeout=0`, `drain_match=1`;
  - Vision captured 32; verifier **PASS** — byte-identical, FIFO, 0 missing/dup/corrupt.

### Controlled-release latency (on-chip ns timestamps, single trial) [OBS]
| Quantity | ns |
|---|---|
| drain recognition (block_term − drain_match) | **12** |
| scheduler release (first_release − block_term) | **1719** (≈ one loopback RTT) |
| end-to-end (first_release − drain_match) | **1731** |
| release burst (last_release − first_release), 32 frames | **835** |
The blocker recognizes the drain within ~12 ns (its next loop); the first HELD then takes ~one loopback
RTT to surface and forward; all 32 clear within ~835 ns. (Distribution over the rep campaign: Gate 9.9.)

## Status
- [COMPILED] 9.1 · [OBS] 9.2 · [OBS] hold-needs-reservoir(K≥64) · [OBS] controlled drain on-chip ·
  [OBS] **9.3 host-PCAP byte-id PASS** · [OBS] **9.7 host-PCAP byte-id + latency PASS**.
- [OPEN] 9.4 budget-expiry regression (host-PCAP) · 9.5 negatives (host-PCAP) · 9.6 H=1 · 9.8 duration
  sweep · 9.9 30/30+100/100 reps · counter-attribution refinement · token-isolation (blocker never on
  dp9/dp11/hosts).

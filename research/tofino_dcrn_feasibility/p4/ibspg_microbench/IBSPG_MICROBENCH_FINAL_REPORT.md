# IBSPG microbench — final report (closeout)

**Classification: PARTIAL / STRICT-PRIORITY HOLD NOT ACHIEVABLE WITHIN SAFE BOUNDS.**

The Internal-Blocker Strict-Priority Gate (IBSPG) was evaluated on Tofino-1 silicon across two loopback
instantiations (recirc port dp68; physical port dp8, MAC-near loopback, rate-bounded). This report is
the authoritative closeout. It does **not** claim that strict priority provides a binary packet gate,
and it does **not** claim that the complete IBSPG mechanism works.

Physical dp8 result commit: **50d284f** (branch `research/queue-resident-transaction-release`). Recirc
result commit: `e9ba8e5`. Evidence docs: `EXPERIMENT_RESULT_recirc_L.md`,
`IBSPG_PHYSICAL_DP8_RATE_BOUNDED_REPORT.md`.

## What PASSED on Tofino-1 silicon
- **Physical dp8 loopback is reliable for the tested bursts** — preflight 10 and 100×3 tokens, each
  100-burst adding exactly +100 to dp8 tx *and* rx, zero loss, zero queue/egress drops.
- **Blocker-token pass budgeting works exactly** — N tokens × pass budget produces N×budget internal
  loops and then self-terminates (measured: 8 × 10 000 = 80 000 loops, then 8 expiries; ring died,
  no storm, switch healthy). This is a bounded, safe internal-token ring.
- **Wrong-generation drain does not release the held packet** — 4/4 reps: `reg_drain` stayed 0,
  `ctr_held_release` unchanged, HELD remained in Q_HOLD.
- **Matching-generation drain releases correctly** — 4/4 reps: `reg_drain`→1, HELD released.
- **Released real-packet count at dp9 is exact** — `dp9 tx` incremented one-for-one with releases (1→5).
- **Blocker tokens do not escape** toward dp11 or the protected hosts — `dp11 tx = 0` for the entire
  run; token traffic (ethertype 0x88C1) stayed on the internal dp8 loopback only.
- **Cleanup and restoration succeed** — see "Restoration state" below.

## What FAILED / the NEGATIVE result
- **Strict-priority blocker occupancy did not hold the lower-priority real packet within the approved
  safe rate envelope.** With the blocker ring rate-bounded for safety, the held packet was serviced
  while the high-priority queue was backlogged.
- **Shaping the high-priority queue creates scheduler-eligibility gaps in which the lower-priority
  queue receives service.** To keep the ring bounded/safe (≤50 000 pps), Q_BLOCK must be shaped. A
  shaped queue is *ineligible* between shaper credits (token-bucket refill), and strict priority
  correctly serves the next non-empty queue — Q_HOLD — during those windows. So the observed
  low-priority service in the safe envelope is at least partly a property of the shaping, not proof
  that strict priority "fails," but it means a **safely-bounded** blocker cannot hold the packet.
- **Prior unshaped saturation evidence also showed lower-priority service despite a nearly full
  high-priority path** — on the recirc port with no shaper, Q_BLOCK saturated at 126/127 cells (never
  sampled empty) and Q_HOLD was still serviced at 1.3–5.3 M/s.
- **Therefore strict-priority starvation is not accepted as a deterministic packet gate on this
  Tofino-1 configuration.** Unshaped it is not absolute; safely-shaped it is defeated by the shaping.

## Why increasing the blocker rate was NOT authorized
A >50 000 pps unshaped saturation ring was considered and **rejected by project decision**. It would at
best demonstrate empirical starvation at one saturation operating point — not a reliable architectural
gate — while imposing disproportionate switch risk (an unbounded/near-line-rate internal ring is what
previously hung the switch host) and internal bandwidth cost. The established safety ceiling stands;
IBSPG is not to be forced to "pass" by raising internal blocker rate.

## Why this result does NOT prove every queue-resident construction impossible
The refutation is specifically of **strict-priority starvation as a deterministic hold**. It says
nothing about constructions that hold a packet by other supported means — in particular internal
**backpressure** (a downstream internal path that cannot accept the packet, keeping it queue-resident)
or **two-stage park/release** topologies. Those are separate mechanisms with separate capability
questions and are the subject of the follow-on research (`research/queue-backpressure-release`).

## Primitives that REMAIN REUSABLE (proven on silicon)
- **Bounded internal token ring** — a self-looping internal control token with a hard pass budget.
- **Pass-budget termination** — N×budget bound on total internal passes; a runaway ring cannot storm.
- **Generation-safe data-plane drain** — a slot+generation-checked drain that ignores stale/unrelated
  events and releases only on an exact match, entirely in the data plane.
- **Internal-token isolation** — a private-marker token that provably never egresses a protected port
  (capture/counter-verified).
- **Matched release control** — drain-gated egress of the original packet, byte-preserving, to the
  correct protected port only.
These components carry forward into the backpressure / two-stage designs.

## Restoration state (verified after the physical dp8 run)
- Switch **10.10.54.81** (`ufispace`): 1 bf_switchd on `queue_microbench_abs.conf`, ASIC attached
  (`Operational mode set to ASIC`, 0 mmap errors; `bf_kdrv` loaded after the host reboot, with user
  authorization). No experimental processes; no circulating tokens; dp8 loopback reset by cold init.
- Vision **10.10.54.19** reachable (relay-side 192.168.10.1). Hulk **10.10.54.158** reachable.

## Novelty framing (preserved as scientific evidence)
The IBSPG negative is useful evidence, not a dead end. A paper contribution may include: the systematic
identification of the missing direct queue-release primitive; the **experimental refutation of
strict-priority occupancy as a deterministic gate** on Tofino-1 (two instantiations, bounded and
saturated); the bounded internal-token safety mechanism; the generation-safe data-plane drain; and a
successful queue-resident mechanism if one is later found. A carefully demonstrated hardware limitation
plus a safe successful alternative is a stronger contribution than an unsafe mechanism forced to pass.

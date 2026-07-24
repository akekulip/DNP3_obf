# IBSPG microbench — state & resume (as of 2026-07-24)

Single source of truth for resuming. Authority: `research/unified_queue_release/direction.md` (14-part
mandate: build the smallest Tofino-1 microbench deciding whether an **Internal-Blocker Strict-Priority
Gate** can hold a real packet queue-resident in a low-priority TM queue, starved by a continuously-
occupied high-priority internal blocker queue, drained by a data-plane event, with no blocker token on
dp9/dp11 and no continuous recirculation of the original). Branch `research/queue-resident-transaction-release`.

## ►► HEADLINE STATUS
- **Parts 1–3 DONE & committed.** Compile-only prototype fits (6/12 stages, local 9.13.1 + on-switch 9.13.2).
- **Silicon result #1 (recirc-port loopback) DONE & committed — DECISIVE NEGATIVE on the hold.**
  Zero-pass residency is REFUTED on the recirc port; release/teardown/gen-check/token-isolation all PASS.
- **Silicon result #2 (physical dp8 loopback) INCOMPLETE — switch host went unreachable mid-run.**
- **BLOCKER (current):** switch host `ufispace` 10.10.54.15 down/hung (ARP INCOMPLETE) since the dp8 run.
  Microbench NOT restored (cannot reach switch). Background watcher armed to restore on recovery.

## DONE (committed on branch research/queue-resident-transaction-release)

| Part | Deliverable | Commit |
|---|---|---|
| P1 | `IBSPG_TM_CONFIGURATION.md` — ports, Q_BLOCK/Q_HOLD qids+priorities, loopback L, marker, restore | 468e880 |
| P2 | `p4/ibspg_mb.p4` compile-only (local 9.13.1: 6 stages, SALU 2, Stats 9, SRAM 22) + `COMPILE_FIT_RESULT.md` | 468e880, 92f2f2f |
| P3 | `IBSPG_BLOCKER_OCCUPANCY_DESIGN.md` (variants A/B/C/D) | d4c0ea1 |
| harness | `control/ibspg_setup.py`, `harness/ibspg_gen.py`, `harness/ibspg_read.py` | 8434598 |
| P4–7 #1 | `EXPERIMENT_RESULT_recirc_L.md` — recirc-port silicon evidence | e9ba8e5 |
| P?  | `p4/ibspg_mb_physL.p4` (PORT_L=dp8 physical variant) + `--mac-loopback` in setup | fe8b3bd |

Supporting design docs (committed earlier on this branch): `QUEUE_RELEASE_RESEARCH_REOPENING.md`,
`INDIRECT_QUEUE_RELEASE_DESIGN_SPACE.md` (the IBSPG construction + 20 candidates),
`INTERNAL_TOKEN_THREAT_AND_VISIBILITY_MODEL.md`, `FIRST_EXPERIMENT_PAIRED_BUFFER.md`,
`docs/IBSPG_MECHANISM_AND_INSTRUMENTATION.md`.

## SILICON RESULT #1 — recirc-port loopback (L = dp68). REFUTED hold; PASS release/isolation.
Full evidence: `EXPERIMENT_RESULT_recirc_L.md`. Key numbers (host-injected from Hulk/dp11; ports
Vision=dp9, Hulk=dp11 confirmed by RX deltas):
- Strict priority VERIFIED (Q_BLOCK HIGH=7 > Q_HOLD LOW=0).
- HELD recirculated at **1.3–5.3 M passes/s** even at Q_BLOCK **use=126/127 (saturated, never sampled
  empty)** at N=256 → **no zero-pass residency**; strict priority does NOT absolutely starve Q_HOLD on
  the recirc port. IBSPG there = continuous original recirc (no gain over frozen recirc-hold).
- PASS: drain releases HELD (dp9 tx += 1 each), ring teardown exact (ctr_blk_drop += exactly N),
  gen-check rejects wrong gen, token (0x88C1) NEVER on dp9/dp11 (dp11 tx=0; dp9 tx==releases). 0 drops.
- The subagent's "move hold off-Tofino" recommendation is REJECTED (contradicts direction).

## WHAT'S LEFT (Parts 4–14 of the mandate)

Direction Part 10 forbids a family verdict from one failed variant. Gating next experiments, in order:

1. **[DECISIVE, was in progress] Physical MAC-near loopback port (L = dp8).** Tests whether a REAL
   egress port's strict priority absolutely starves Q_HOLD (the recirc port did not). If HELD stays
   resident (ctr_held_enq == injected) under a deep Q_BLOCK backlog → IBSPG viable on a physical
   loopback. If it still recirculates → Tofino-1 TM has no absolute strict-priority starvation on any
   port (anti-starvation floor) → the IBSPG family is REFUTED. **Staged & compiled; must RERUN with a
   RATE-BOUNDED ring (do NOT push to N=1024 line-rate saturation — that likely caused the switch hang).**
2. **Gap-free continuous feed** of Q_BLOCK (continuous pktgen tokens gated by a data-plane drop on
   drain) — removes the loopback empty-gap by construction; disambiguates empty-gap vs non-strict-sched.
3. **Variant C (Q_BLOCK shaping)** — with the caveat a shaped non-empty high queue may yield to the low
   queue during its shaped-off interval.
4. If 1–3 all fail → evaluate the **two-stage / backpressure** alternatives separately (Part 10 tail).
5. Then, only if a variant PASSES the hold: **P6 matched-drain full timing/jitter**, **P7 host-capture
   visibility proof**, **P8 blocker cost/bandwidth**, **P9 timeout/fail-open**, **P10 decision-gate
   classification**, **P11 paired ACK/response**, **P12 DNP3 integration** (synthetic/replayed, NO
   physical SEL), **P13 novelty analysis**, **P14 `IBSPG_MICROBENCH_FINAL_REPORT.md`**.

## STAGED ARTIFACTS ON THE SWITCH (decps@10.10.54.15, when it returns)
- `~/ibspg_mb/build_9132/` — recirc program `ibspg_mb`; `ibspg_mb_abs.conf`; launcher `~/ibspg_mb/launch_ibspg.sh`.
- `~/ibspg_mb/build_physL/` — physical program `ibspg_mb_physL`; `ibspg_mb_physL_abs.conf`; launcher
  `~/ibspg_mb/launch_ibspg_physL.sh`.
- `~/ibspg_mb/{ibspg_setup.py,ibspg_read.py}` (re-scp from repo if stale).
- RESTORE target (running before this work): `/home/decps/queue_microbench/out/queue_microbench_abs.conf`
  via `/home/decps/queue_microbench/launch_mb.sh`.

## RECOVERY / RESTORE PROCEDURE (when switch mgmt returns)
1. `sshpass -e ssh decps@10.10.54.15 'pgrep -xc bf_switchd; <conf-file check>'` — see what's running.
2. RESTORE microbench: `sudo pkill -x bf_switchd; sleep 2; sudo nohup bash /home/decps/queue_microbench/launch_mb.sh &; sleep 22`.
3. Verify: exactly 1 bf_switchd on `queue_microbench_abs.conf`; ping Vision 10.10.54.19 + Hulk 10.10.54.158;
   no residual ibspg/gen/setup processes. A cold restart resets dp8's loopback mode.

## KEY FACTS / CONSTRAINTS
- Testbed: Vision/master=dp9, Hulk/outstation=dp11 (MEASURED). Loopback L: recirc dp68 (pg17,nr0) OR
  physical dp8 MAC-near (pg2,nr0). Q_BLOCK qid7=HIGH, Q_HOLD qid1=LOW. Marker: token ethertype 0x88C1 +
  src 02:00:00:00:0B:0C.
- Access: `source ~/.lab_env` → `$SSHPASS` (ssh + `echo "$SSHPASS"|sudo -S` on hosts; sudo WORKS on both
  hosts). Host NICs enp59s0f0np0 (were UP: Vision dp9, Hulk dp11). Compile: local
  `/home/philip/bf-sde-9.13.1`, on-switch `/home/decps/Downloads/bf-sde-9.13.2`.
- bfrt idioms: strict priority `tf1.tm.queue.sched_cfg` min_priority HIGH('7')/LOW; occupancy
  `tf1.tm.counter.queue` (usage/watermark/drop); `$PORT_STAT` RX/TX; targets pipe0 (TM) / 0xffff (port/reg).
- Constraints (direction): Tofino-1 only; no external chaff; no controller in fast path; NO
  SmartNIC/DPU/host/eBPF/platform-split; no continuous thousands-of-pass recirc of the ORIGINAL; internal
  token recirc allowed; ACK-before-response; byte-preserving; bounded fail-open. Frozen dnp3_shadow.p4 /
  dcrn_defense1/2.p4 UNTOUCHED.

## LESSONS
- **Ring saturation on a loopback port is dangerous.** Pushing the blocker ring to N=1024 at line rate
  on dp8 MAC-near loopback coincided with the switch host hang. Future ring tests: bound N and/or shape
  the ring rate; never drive a loopback ring to line-rate saturation. Add a P4/pps cap.
- Coarse bfrt occupancy sampling can't see sub-µs queue states; "never sampled empty" ≠ "never empty."
- Off-Tofino (SmartNIC/host) solutions are OUT OF SCOPE per the current direction — do not recommend them.
- Never trust a stated host↔port mapping (GATE-1 inversion lesson); measure RX deltas (done: dp9/dp11 ok).

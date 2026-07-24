# IBSPG experiment forensic ledger (Part 2)

Reconstructed 2026-07-24 from committed reports, commit messages, and P4/control/harness sources.
Values verbatim from committed evidence; absent values marked **MISSING — not in committed evidence**;
nothing inferred. **Provenance caveat (all runs):** no raw per-read counter JSON is committed or on
disk — `runs/` is gitignored (`.gitignore` `**/runs/`); committed `evidence/` holds only compile
artifacts. Every silicon counter here exists only as prose inside committed `.md` reports.

## RUN 1 — recirc-port loopback (L=dp68), UNSHAPED, N∈{1,8,64,256}
- date 2026-07-24; commit `e9ba8e5`; program `ibspg_mb` sha `6baecac…`; SDE 9.13.2.
- internal port dp68 (pipe-0 **recirc**); pipe 0; **pg_id 17**; Q_BLOCK qid7 pgq7, Q_HOLD qid1 pgq1.
- Q_BLOCK `min_priority="HIGH"`(reads 7), Q_HOLD `min_priority="LOW"`(reads 0), `scheduling_enable=true`.
  **`max_priority` MISSING (never set). DWRR weight MISSING. min_rate MISSING. Unshaped.**
- pass-budget MISSING at run time (added later in `6484b17`, after this run); ring bounded only by DRAIN.
- N=1/8/64/256 (×3 at N=8). Q_BLOCK use/wm: 0/4, 1–3/3, 9–13/13, **126/127** (never sampled empty);
  Q_HOLD use ~0–1. Drops 0. dp11 tx=0; dp9 tx==releases.
- **Held outcome:** `ctr_held_enq` never == injected(1); climbed 1.3–5.3 M/s even at Q_BLOCK 126/127 →
  HELD continuously recirculated (reported "no zero-pass residency").
- Also passed: release gate, ring teardown (`ctr_blk_drop += exactly N`), generation check.
- **MISSING:** max_priority, DWRR, min_rate (never set); pass-budget (not yet implemented); total
  duration; raw JSON; sub-µs Q_BLOCK-empty invisible (polled occupancy).

## RUN 2 — physical dp8 loopback (MAC-near), SHAPED, preflight + N=8 crux + drain ×4
- date 2026-07-24; run commit `6484b17` (report `50d284f`); program `ibspg_mb_physL` sha `e630b43…`;
  on-switch 9.13.2, 7/12 stages.
- internal port dp8 (**physical**, BF_LPBK_MAC_NEAR); pipe 0; **pg_id 2, nr 0**; Q_BLOCK qid7 pgq7,
  Q_HOLD qid1 pgq1.
- Q_BLOCK `min_priority=7`, Q_HOLD `min_priority=LOW`, `scheduling_enable=true`; `strict_priority_verified:true`.
  **`max_priority` MISSING. DWRR MISSING. min_rate MISSING.**
- **Shaping ENABLED both queues: Q_BLOCK 20 000 pps, Q_HOLD 50 000 pps** (PPS/UPPER, burst 16384),
  `max_rate_enable=true`.
- N=8 crux, pass-budget=10 000 (preflight budget=1, bursts 10 + 100×3).
- Preflight exact (dp8 tx==rx, 0 loss); pass-budget exact (blk_loop 310→80310 = 8×10000 then 8 expiries,
  self-terminated); drain/gen/release 4/4 (wrong-gen no release; matched → dp9 tx 1→5); dp11 tx=0.
- **Held outcome:** HELD serviced (`held_enq` 0→64,546→165,166→265,786→287,286, ~100–130k/s) while
  Q_BLOCK backlogged (use 6–7). **Confound flagged in the report: Q_BLOCK shaped 20k ⇒ ineligible
  between shaper credits ⇒ strict priority serves Q_HOLD in those windows.**
- Pre-run: host reboot → `bf_kdrv` unloaded → Phase-1 BLOCKED (`2662227`); user authorized reload.
- **MISSING:** max_priority, DWRR, min_rate (never set); clean unshaped/saturated test not run (50k
  ceiling); host pcap not captured (switch-counter escape proof only); raw JSON; scheduler semantics
  unproven.

## RUN 3 — P-SCHED (scheduling-disable hold) on dp8
- date 2026-07-24; commit `38d02c8`; program `ibspg_mb_physL`; pg_id 2; Q_HOLD qid1 only (single HELD).
- `scheduling_enable` toggled false→true on Q_HOLD; **`min_priority`/`max_priority`/DWRR MISSING**
  (`psched_ctl.py` writes only `scheduling_enable`); Q_HOLD shaped 50k safety cap; N=1.
- Held outcome: `scheduling_enable=false` holds Q_HOLD usage=1, drop=0, dp8 tx=0 (2s); data-plane
  DRAIN_MATCH sets `reg_drain=[1,0]` but usage stays 1 (no release); CP enable → usage→0, dp9 tx=1.
  dp11 tx=0. Isolates the direct-TM-actuation limit only.
- **MISSING:** min/max_priority/DWRR (not set by psched_ctl); shaper burst; P4 sha (inherited); raw JSON.

## CROSS-RUN OBSERVATIONS
- **(a) priority fields:** SET = `scheduling_enable=true` + `min_priority` HIGH/LOW (Runs 1–2), via
  `ibspg_setup.py:112-128` `entry_mod(sched_cfg, [scheduling_enable, min_priority])` — **only** those
  two fields. **NEVER SET (all runs): `max_priority`, DWRR `weight`, `min_rate`** (0 repo-wide hits).
  Only `max_rate` (UPPER shaper) used, Run 2 both queues + Run 3 Q_HOLD cap.
- **(b) same priority config:** Runs 1 & 2 IDENTICAL priority config (min_priority HIGH/LOW, no
  max_priority, no DWRR); differ only in port (dp68/pg17 vs dp8/pg2) and shaping (unshaped vs 20k/50k).
- **(c) raw JSON:** none on disk or in git — all counters are hand-transcribed prose in the `.md` reports.
- **(d) single most suspicious gap:** **`max_priority` never set + strict-vs-min-bandwidth semantics
  never verified**, yet the whole negative rests on `min_priority` alone delivering absolute strict-
  priority starvation. If `max_priority` is the strict lever (min_priority being minimum-bandwidth
  priority, inert with `min_rate_enable=false`), Q_HOLD was serviced not because "strict priority isn't
  absolute" but because **the strict field was never configured** — reopening the hold hypothesis.
  Secondary: the two runs are in DIFFERENT scheduler domains (pg17 recirc vs pg2 physical) with L1-node
  attachment never read back; Run 2's Q_BLOCK shaping is a self-inflicted eligibility-gap confound.

## LIVE READBACK CORROBORATION (2026-07-24, this campaign, dp8 physL, base config)
`ibspg_tm_readback.py` full `sched_cfg` dump confirms the ledger: Q_BLOCK `{min_priority:"7",
max_priority:"LOW", dwrr_weight:1023, min_rate_enable:false, max_rate_enable:false}`; Q_HOLD
`{min_priority:"LOW", max_priority:"LOW", dwrr_weight:1023}`. Both queues on pg_id=2 dev_port=8
(same intended domain). **`max_priority` = LOW on BOTH (default), DWRR = 1023 on BOTH (default).** →
candidate root cause A1/A3/B2: strict-priority arbitration was never configured; the equal
max_priority + equal DWRR gave Q_HOLD fair service. Correction under test = set Q_BLOCK max_priority HIGH.

# WORKING NOTES

**Task (2026-08-05): Defense 4 directive §3 — reservoir-bootstrap feasibility probe.**

Goal: decide OFFLINE whether the two blocker reservoirs (ACK + RESPONSE) can be
**established and maintained with ONE-TIME control-plane config only** — no per-transaction
host/controller/ARM/blocker-injection/TM action — as an autonomous data-plane bootstrap.
This is the R11 kill-question. Outcome must be either **OFFLINE BOOTSTRAP FEASIBLE, SILICON
UNVERIFIED** or **DEFENSE 4 FEASIBILITY BLOCKED**.

**Construction under test (the feasibility hypothesis):**
one-shot pktgen **timer** app (configured ONCE) seeds each reservoir's K=64 tokens exactly
once (`trigger_timer_one_shot`, `batch_count_cfg=0`, `packets_per_batch_cfg=K-1` → K packets,
`packet_id` 0..K-1, `app_id`→reservoir). Tokens then **self-sustain by recirculation** on
loopback dp8; they PERSIST (adopt the current epoch each pass) so the reservoir never depletes
and needs NO re-seed → no per-transaction generation. Distinctness is **structural**: the
timer-parse path is first-appearance (counted once), the recirc-parse path is a subsequent
pass (never counted).

**Probe = ISOLATED file** `defense4/timing/bootstrap/bootstrap_probe.p4` (NOT a patch of
defense4_timing.p4). Demonstrates in code, each mapped to a site:
1 authenticated internal origin · 2 distinct id w/o double-counting recirc · 3 ACK+RESP
reservoir readiness · 4 data-plane gen/role/domain stamping · 5 ACK-before-ready fail-open
un-stranded · 6 stale-token termination not touching a newer gen · 7 inactive nonblocking ·
8 bounded cleanup + reservoir restoration.

**Plan:** write probe → code-reviewer → commit reviewed probe → compile offline w/ BF-SDE
9.13.1 → commit evidence separately (GATE `defense4/timing/bootstrap/evidence/`) → STOP.
Do NOT begin §4, Gate 3, size, switch load, TM config, or hardware.

**Status:** probe written + compiles clean (0 err, 3 benign warn; 6 ingress stages, CP 3,
5 stateful ALUs, TCAM 0; source sha256 73447b63…). First draft (one-shot + finite budget)
was adversarially reviewed by p4-dataplane-engineer and REFUTED-IN-CODE: budget self-drain
(pool empties ~0.17 s, no host traffic), sticky present (can't re-seed), gen_bump wrap to
0xFF drains both domains at 255th READ, pop never decremented (silent protection loss).
REWROTE to reconciled construction: PERIODIC one-time timer + residency-tracked reservoir
(present_admit/present_clear + pop_incr/decr), termination via CP-set reg_retire (not a gen
sentinel; gen wrap now benign), adopt makes hdr.token.gen live. Re-review IN FLIGHT
(agent a830c52786223532b) to confirm all 6 defects closed before commit.

**Next action:** on re-review PASS → code-review clean → commit reviewed probe → formal
compile of committed SHA → commit evidence doc separately → §3 verdict (FEASIBLE-silicon-
unverified vs BLOCKED) → STOP. If re-review still finds a drain/logic defect, judge BLOCKED.

**Safety (unchanged):** Tofino-1 data-plane only; no switch load / TM / port / relay /
SELECT-OPERATE; frozen D1/D2/D3/Part-11/Part-12/four-queue dirs untouched; no history rewrite.

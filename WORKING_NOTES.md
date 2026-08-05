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

**Status: §3 COMPLETE — verdict OFFLINE BOOTSTRAP FEASIBLE, SILICON UNVERIFIED (not blocked).**
Probe `defense4/timing/bootstrap/bootstrap_probe.p4` (sha256 73447b63…) committed `d991944`;
evidence `…/evidence/BOOTSTRAP_FEASIBILITY.md` + logs committed `6ce1438`; both pushed to
origin/main (HEAD 6ce1438). First draft (one-shot + finite budget) was REFUTED-IN-CODE by
adversarial P4/TNA review (self-drain ~0.17 s no-traffic; gen-wrap drain at 255th READ; pop
never decremented). Rewrote to PERIODIC one-time timer + residency-tracked reservoir
(present_admit/clear + pop_incr/decr; termination via read-only CP reg_retire; benign gen
wrap; adopt reads hdr.token.gen). Re-review confirmed all six defects CLOSED, not relocated.
Compiles clean (0 err, 6/12 ingress stages, 5 stateful ALUs, TCAM 0). defense4_timing.p4
untouched; frozen dirs untouched; nothing loaded/run.

Disclosed silicon-gated residuals (Gate 3 / hardware, R2/R11): pop is an admit/retire ledger
not a physical census; periodic top-up RATE keeping pop==K across a retire/refill gap; K≤64
index-slice guard before any resize.

**Next action: STOP (directive §3 boundary).** Do NOT begin §4 (rebuild the core), Gate 3,
size work, switch load, TM config, or hardware — all gated on Philip's explicit go-ahead.

**Safety (unchanged):** Tofino-1 data-plane only; no switch load / TM / port / relay /
SELECT-OPERATE; frozen D1/D2/D3/Part-11/Part-12/four-queue dirs untouched; no history rewrite.

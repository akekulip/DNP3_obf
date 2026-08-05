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

**►► CORRECTION (2026-08-05, Philip audit): §3 = PARTIAL/FAIL, R11 REMAINS OPEN (not blocked).**
My "OFFLINE FEASIBLE" verdict was OVER-REACHED. d991944 places 8 isolated mechanisms but does
NOT implement the R11 contract. Eight gaps (Philip): (1) one QID_BLOCK/one QID_HOLD, not the
four queues 7/6/5/4; (2) ACK reads only pop[ACK] — can hold ACK while RESP reservoir unready;
(3) fail-open forwards ACK but leaves active set → later RESPONSE still held (not txn-level);
(4) marker written, never validated; no scheduler_domain+role identity; domain/tokid bits alias
into valid cells; (5) gen mismatch calls adopt_epoch()+persists; termination only via CP
reg_retire, not generation-qualified, can kill current tokens; (6) pop increments before
to_block() and before first authenticated loopback return → proves ingress admission, not
establishment (early-ready window); (7) cleanup only on FIN/RST — persistent TCP never returns
domain to inactive; (8) no committed one-time pktgen setup code.

**Required v2 (Philip's spec = acceptance criteria):** keep d991944 as PARTIAL NEGATIVE probe;
forward-correct evidence verdict. Build bootstrap_probe_v2.p4: real 4 QIDs (7/6/5/4); token
{marker, scheduler_domain, role, generation, token_id} with EVERY field validated; identity
EMPTY→SEEDED→CONFIRMED, readiness++ only on first authenticated loopback return; both reservoir
counts packed in ONE stateful word (ACK tests both atomically); generation-qualified fail-open
LATCHED when either reservoir unready (all later pkts of the gen bypass); DATA-PLANE normal
cleanup+restoration (NOT reg_retire as correctness path); generation-qualified in-band stale
termination (only past-gen). Commit the exact one-time pktgen config code. Recompile, STOP at §3.

**Prior (WRONG) status line kept for the record:** "§3 COMPLETE — OFFLINE BOOTSTRAP FEASIBLE".
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

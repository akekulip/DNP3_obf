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

**v2 progress (2026-08-05):** verdict-correction committed `6770a9e` (d991944 = PARTIAL, R11
OPEN). Built `bootstrap_probe_v2.p4` (sha256 ab7728f0…) to the four-queue contract — compiles
clean (0 err, 7 ingress stages, CP 5, 5 stateful ALUs, 16 stats ALUs, TCAM 1). All eight gaps
addressed in code (grep G1..G8): four qids 7/6/5/4; packed reg_pop atomic dual-readiness
(BOTH_READY=0x00400040); tbl_token_valid validates marker/sdomain/role/token_id<64; identity
EMPTY→SEEDED→CONFIRMED with pop++ only on first authenticated loopback return; generation-
qualified in-band stale termination (no reg_retire); transaction-level latched fail-open;
data-plane normal cleanup via active_read_clear on the RESPONSE. Committed one-time setup
record `bootstrap_setup.py` (two trigger_timer_periodic apps, templates, K, period, value-set,
four queue priorities; refuses to run without DEFENSE4_HW_AUTHORIZED=1). Adversarial re-review
IN FLIGHT (agent a830c52786223532b).

**Known edge to fix (batch with review):** gen is bit<16>, gen_bump wraps 65535→0; gen 0 is
the "no-txn" value and reg_failopen resets to 0, so a txn whose generation wraps to 0 would see
failopen(0)==cur_gen(0) and wrongly bypass its RESPONSE (1 per 65536 READs). Fix: make gen_bump
skip 0 (65535→1) or guard the bypass with failopen!=0. Recompile after batching review findings.

**v2 COMPLETE (2026-08-05): §3 = PARTIAL, R11 STAYS OPEN.** v2 probe committed `d67184f`
(sha256 0c8770c1…); evidence `evidence_v2/BOOTSTRAP_FEASIBILITY_V2.md` + logs. Review:
G2/G4/G5/G6/G7/G8 close in code; TNA-legal; flagged G3 gen==0 wrap FIXED (gen_bump skips 0).
Formal compile of committed SHA clean (0 err, 7/12 ingress stages, CP 5, 5 SALUs, TCAM 1).
►► LOAD-BEARING OPEN (why not feasible): two continuously-recirculating strict-priority block
reservoirs on ONE loopback port likely STARVE the lower — qid7 ACK block starves qid5 RESP
block under strict priority → RESP never CONFIRMs → pop[RESP] never K → BOTH_READY (0x00400040)
structurally unreachable → every txn fails open (predicted reg_pop stalls 0x00400000). Never
concluded on silicon (four-queue oracle pilots failed). Needs CO-EQUAL/WRR block queues or
per-reservoir shapers = a TM decision proven on HARDWARE (gated). bootstrap_setup.py leaves the
scheduling policy an explicit NotImplementedError stub. Secondary silicon items: re-seed/confirm
within CLRT after pool turnover (R2 continuity); multi-fragment DNP3 response hold-granularity (§4).

**Next action: STOP at §3, R11 OPEN.** The pre-feasibility step is now HARDWARE (choose + prove
the block-queue scheduling policy), which is GATED — NOT §4, more offline P4, Gate 3, size, TM,
switch load, or any hardware action without Philip's explicit go-ahead.
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

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

**►► CORRECTION 2 (2026-08-05, second Philip audit): v2 (d67184f) is ALSO a PARTIAL NEGATIVE
probe; "G1-G8 closed" WITHDRAWN.** Six code-path defects: G2 reg_pop not reset/epoch-qualified on
gen_bump (stale K/K admits new ACK); G4 uninitialized metadata → undefined origin flags; G5
reg_ident lacks generation → unconditional ident_clear wipes newer-gen cells (ABA); wrap: 16-bit
gen repeats every 65535 txns (ABA unless widened/bounded lifetime); G7 active_read_clear on native
RESPONSE admission is premature (breaks RESP-before-ACK); G8 setup is a record not executable. My
TM remedies (co-equal/WRR/shaping) are ALSO unsuitable (co-equal starves Q_ACK_HOLD; shaping leaks
holds early). Evidence corrected (v1+v2 docs + R11); committed.

**►► v3 SPEC (Philip): STAGED RESPONSE-first establishment under the STATIC ladder 7>6>5>4.**
READ opens generation + atomically sets population 0/0; RESPONSE seeds accepted FIRST (ACK seeds
dropped) until 0/K; THEN ACK seeds → K/K; ONLY K/K admits native ACK else latch fail-open; release
naturally drains ACK-blocker→ACK→RESP-blocker→RESP. Solves starvation by ADMISSION ORDERING (no
co-equal/shaping/dynamic-TM/controller). Plus all fixes: (1) init EVERY metadata field in parser
start; (2) generation-qualified population (reg_pop reset 0/0 on READ, only current-gen confirms
count); (3) per-cell {generation, lifecycle} so a stale token only affects its OWN generation's
cell (no ABA clear); (4) full-wrap ABA via wider generation (32-bit) AND/OR bounded token lifetime
below reuse; (5) cleanup at generation-qualified loopback completion of the HELD RESPONSE (not at
native admission); (6) complete GUARDED setup implementing the fixed 7>6>5>4 ladder, shaping
disabled, main() wires the config behind DEFENSE4_HW_AUTHORIZED. Commit source before compile,
preserve exact BF-SDE 9.13.1 evidence separately, STOP at §3 again. Only after this offline
construction passes may a narrowly-scoped SILICON continuity test be authorized.

**Design notes for v3 (SALU-tractable plan):** cell reg_ident[128] 32-bit = generation (skip 0) with
lifecycle in a reserved encoding; seed overwrites iff cell not current-gen (stale/empty) → no
ident_clear/pop_decr needed (stale tokens just DROP; seed lazily invalidates stale cells);
confirm advances SEEDED→CONFIRMED only when token.gen==cur_gen (guaranteed cell.gen==cur_gen by the
no-intervening-READ invariant). ACK-seed gate: drop ACK pktgen tokens while pop.RESP != K (ternary
on pop_packed lo16). reg_resp_gen records the held RESPONSE's gen at admission; loopback completion
clears active iff reg_resp_gen==cur_gen. Verify EVERY claim by compile + adversarial review; do NOT
re-claim closure Philip can refute.

**v3 BUILT — NEGATIVE result (2026-08-05): staged design DOES NOT PLACE on Tofino-1
(register-ordering cycle).** bootstrap_probe_v3.p4 (sha256 31b51fce) implements the staged
RESPONSE-first design + all six v2 fixes; full metadata init WORKS (uninitialized warning gone).
But table placement FAILS on a register-stage ordering cycle (a Register lives in one MAU stage →
all accesses must share one global order). p4-dataplane-engineer diagnosed rigorously:
- Conflict 1 reg_ident↔reg_pop: staged ACK-seed gate reads pop BEFORE seed writes ident; loopback
  confirm writes ident BEFORE incrementing pop → pop<ident ∧ ident<pop. Breakable ONLY by splitting
  BOTH ident+pop by role → but that DROPS the atomic single-word dual-readiness. ►► ATOMIC-PACKED-POP
  and STAGED-ADMISSION are provably INCOMPATIBLE in one Tofino-1 ingress pass.
- Conflict 2 {resp_gen,active,failopen} SCC: RESOLVABLE semantics-preservingly by writing resp_gen
  unconditionally+early on native RESP (breaks active<resp_gen, failopen<resp_gen → resp_gen<active<
  failopen). [my analysis; specialist saw it as a wall under the strict "set when held" wording.]

Evidence evidence_v3/BOOTSTRAP_FEASIBILITY_V3.md; R11 note updated; committed. This IS the "Tofino
limitation to solve and evidence."

**DECISION SURFACED to Philip (explicit-instruction conflict — do NOT resolve unilaterally):**
Option A = single ingress pass, split reg_pop by role, DROP single-read atomicity (correct under
generation-qualification + staged stable-at-admission — a two-op read can't yield a false K/K).
Option B = multi-pass/recirculation, PRESERVE atomicity, but adds a recirc hop with §4-ish timing
implications. Asked via AskUserQuestion.

**►► Philip DECISION (2026-08-05): neither A nor B — a THIRD construction. v4 = single-pass SHADOW
STAGING with an AUTHORITATIVE packed population word.** My "provably incompatible" was too broad: v3
only proves the SAME packed register can't do both jobs. Fix: a SEPARATE shadow RESP count gates ACK
seeding; the authoritative packed pop (atomic single-read) is used ONLY by native admission.

**v4 acyclic state order:** reg_gen < reg_ident_resp[64] < reg_resp_stage < reg_ident_ack[64] <
reg_pop_packed  (then resp_gen < active < failopen for the cleanup/latch tail).
- reg_ident_resp[64]/reg_ident_ack[64]: per-role token lifecycle+generation (idx = token_id[5:0]).
- reg_resp_stage: RESP-only SHADOW count; opens ACK seeding ONLY (never authorizes a native pkt).
- reg_pop_packed: AUTHORITATIVE {ack,resp}; native ACK/RESP read it ONCE (atomic K/K). PRESERVED.
Transitions: 1st RESP confirm → confirm ident_resp, ++resp_stage, ++pop_packed.RESP. ACK seed → only
if resp_stage==K, then write ident_ack. 1st ACK confirm → confirm ident_ack, ++pop_packed.ACK.
Native ACK → read pop_packed once; hold iff ==K/K && active && fail-open NOT latched.
Safety: shadow ahead → pop.RESP still <K so native can't hold; shadow behind → conservative
fail-open. Neither yields a false packed K/K. Atomic safety PRESERVED.

**Two v3 semantic bugs to fix in v4:** (1) native ACK must CHECK the gen-qualified fail-open latch
(else a duplicate ACK is held after an earlier ACK failed open) → native-ACK failopen RMW, hold iff
!latched. (2) an UNREADY native RESPONSE must LATCH fail-open before forwarding (else later packets
don't bypass) → native-RESP failopen set on unready. Also: reg_resp_gen unconditional/early is
equivalent ONLY if an older held RESPONSE can't coexist with the current gen — enforce (DNP3 single-
outstanding-poll + READ-path overlap guard) OR carry gen in the loopback shim; resp_gen placed
gated-on-ready before active (breaks the resp_gen/active/failopen SCC).

**Evidence wording forward-correct (Philip):** v3 evidence "atomic-packed-pop and staged admission
are provably incompatible" → "directly REUSING the authoritative packed population register as the
staged ACK-seed predicate creates an unsatisfiable single-pass register-ordering cycle." Preserve
ead57b2 as the negative DIRECT-COUPLING probe.

**v4 IN PROGRESS (2026-08-05):** bootstrap_probe_v4.p4 written to the shadow-staging state order
(gen < ident_resp < resp_stage < ident_ack < pop_packed < resp_gen < active < failopen) with the
two semantic fixes (native-ACK failopen check; unready-native-RESP latch) + resp_gen<active
placement. ►► Shadow staging WORKS: the v3 register-ordering CYCLES are GONE (reg_ident/reg_pop/
reg_gen all resolved; hoisted gen_read to one top-of-apply site; merged native ACK/RESP branch;
merged the two active_clear sites via a do_clear flag). Full metadata init preserved (no uninit
warning). REMAINING obstacle is NOT a cycle — it's the STAGE BUDGET: compiler wants 16 stages
(critical path only 5) > Tofino-1's 12; 8-register acyclic chain + validation/index tables + 23
counters overflow. p4-dataplane-engineer (agent a366a0651aa049f2b) is fitting it ≤12 stages by
resource reduction (merge counters, pack active+failopen, merge idx tables), preserving the
shadow-staging semantics; instructed to REPORT any tradeoff/2-pass wall rather than take it silently.
v4 sha256 a081e67f (pre-fit). Do NOT edit bootstrap_probe_v4.p4 while the agent works on it.

**Next action:** on fit result → if ≤12 clean: complete guarded setup (7>6>5>4, shaping disabled,
main() wired), commit reviewed v4, formal compile, adversarial review, commit evidence_v4, STOP.
If genuine >12 wall: report the stage-budget finding + the 2-pass option to Philip. R11 OPEN either
way. No §4/Gate3/size/TM/switch/hardware.
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

---
## ►► LATEST STATE (2026-08-05, authoritative) — v4 shadow staging FITS 12/12
bootstrap_probe_v4.p4 (sha256 dcd704a6) — Philip's single-pass SHADOW STAGING. Fit to 12/12 ingress
stages by the p4-dataplane-engineer with NO semantic tradeoff; I independently verified the fit
changes bit-exact (counters 23→6+1 DirectCounter, all gated no control flow; seed-dedup two-comparator
= bit-exact to (v&GEN_MAX)==cur_gen, forced by a bf-asm masked-compare defect; tbl_native_decide 8
entries = FIX-ACK+FIX-RESP exactly; failopen_rmw fo_eq fold; ready includes active; @stage pins pure
placement). Register chain strictly increasing gen@0<ident_resp@2<resp_stage@3<ident_ack@4<pop_packed@6
<resp_gen@7<active@8<failopen@10. 0 err, CP 5, 8 stateful ALUs, tofino.bin. Guarded setup completed
(fixed 7>6>5>4 ladder — v4 staging makes strict ladder CORRECT, shaping disabled; 2 periodic apps;
main() wired behind DEFENSE4_HW_AUTHORIZED; template gen fixed to 4 bytes). evidence_v4 drafted.

HONEST VERDICT: the R11 contract PLACES in ONE 12-stage Tofino-1 ingress pass, NO semantic tradeoff
= positive OFFLINE result. Silicon CONTINUITY (reach+hold K/K within CLRT) UNVERIFIED → R11 STAYS
OPEN. Residuals: reg_resp_gen single-outstanding assumption (overlap→loopback-gen-shim §4);
release-at-first-loopback models the §4 deadline; K≤64. Nothing committed yet since ead57b2.

Final adversarial review DONE — CLEAN on substance (no false K/K; shadow==pop.RESP absolute lockstep
invariant; FIX-ACK/FIX-RESP exact; fit changes bit-exact; gen-qualification/TNA/init all PASS). Only
5 LOW/INFO comment-wording defects — all FIXED (seed-dedup comment; ctr_overlap "guard"→detector;
gated-on-ready wording; +increment_source_port=False in setup; failopen_old comment). Overlap
wrong-clear residual is FAIL-OPEN + needs single-outstanding violation + disclosed.

v4 COMMITTED `9effc43` (source dce08aa6 = reviewed dcd704a6 + comment/setup fixes, recompiled clean).
Formal compile of the COMMITTED blob DONE: 0 err, 12/12 stages, CP 5, 57 tables, 8 stateful ALUs,
tofino.bin; transcript sha matches HEAD. Forward-corrected the last "provably incompatible" overclaim
in RISK_REGISTER (v4 disproved it). R11 note updated with the v4 positive result.

**Next: commit evidence_v4 separately → verify EVERY Philip instruction complete → synthesize the
2-expert STAGE-OPTIMIZATION brainstorm (agents a304da36…/a8362d35… running) into a stage-saving menu
for Philip → STOP at §3.** R11 OPEN; silicon continuity gated. No §4/Gate3/size/TM/switch/hardware.

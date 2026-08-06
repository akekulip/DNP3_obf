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

v4 DONE + committed (9effc43/88b9473/e60a6d4); stage-opt brainstorm menu committed (7724174).

**►► Philip AUTHORIZED v5 (2026-08-06): implement the shim + close the residual + reclaim stages.**
v5 requirements (acceptance criteria):
1. SHIM: remove reg_resp_gen; stamp held-RESP generation before loopback; validate on return; strip
   before the master hop (byte-identical). Target 10/12 stages (TARGET, not established).
2. EARLY ATOMIC READ-ADMISSION GUARD: pack {active, generation} into ONE early stateful word (reg_txn,
   bit31=active, [30:0]=gen) — the STRONGEST construction to PROBE. On READ: if inactive → open (bump
   gen skip-0, set active); if active → NO-OP on ALL state (gen/counts/identities/shadow/failopen/
   active unchanged) = side-effect-free overlap. If the SALU/bf-asm can't test the active bit in the
   RMW (masked/slice-compare defect) → PROBE alternatives (e.g. `v < 0x80000000` magnitude), report
   the finding, use best fallback keeping the overlapping READ side-effect-free. The top reg_txn read
   gives every packet cur_gen AND active for free (slice in MAU, not SALU — legal).
3. RETIREMENT LIFECYCLE: early ACK/RESP latches gen-qualified fail-open; a fail-open RESPONSE forwards
   AND retires (clear active); a normally-held RESPONSE retires ONLY on authenticated loopback
   completion (gen-qualified via shim); duplicate/late packets cannot reactivate or hold (active==0 →
   fail open; only a READ re-opens).
4. INACTIVE-STATE: tokens STOP recirculating when inactive (loop drops if active==0, not re-enqueue);
   periodic seeds NOT admitted while inactive (seed drops if active==0); bounded drainage ≤2K tokens
   (no re-enqueue + no re-seed → drains in one loop period); stale tokens never alter current-gen
   identities/counts (keep gen-mismatch drop before cell/pop).
5. Preserve all v4 contract: shadow staging (resp_stage gates ACK seeding only; pop_packed authoritative
   atomic K/K); gen-qualified per-role cells; queues 7/6/5/4; identity validation; full metadata init.
6. SETUP: read back + ASSERT 7>6>5>4; assert shaping disabled; keep the HW-auth guard.
7. Source-first evidence flow; forward-correct v4 claims (v4 12-stage superseded by v5 target-10 +
   residual closed); commit reviewed v5 source+setup; compile the EXACT commit w/ BF-SDE 9.13.1;
   record sha + actual resources; commit evidence separately; STOP at §3.

Approach: specialist builds v5 (SALU-probing the packed guard is their strength) → I verify EVERY
criterion + adversarial review → commit. v4 file UNTOUCHED (v5 = new file bootstrap_probe_v5.p4).

**v5 BUILT (2026-08-06, sha256 5d51deba) — independently recompiled: 0 err, 11/12 stages (NOT 10 —
measured; early-active-merge for the atomic guard trades against the late co-location that gives 10,
mutually exclusive; specialist did B=strongest-construction as mandated), 6 registers (reg_txn +
ident_resp + resp_stage + ident_ack + pop_packed + failopen; reg_resp_gen/reg_gen/reg_active GONE),
tofino.bin, no uninit warning, v4 untouched.**
- ►► ATOMIC GUARD ASSEMBLES (no fallback): active test = magnitude `v < 0x80000000`; open = `v +
  0x80000001` (gen++ AND set active in one add), wrap GEN_MAX→0x80000001; gen-qual retire = full-word
  `v == shim_gen_active`. Overlap: txn_open returns pre-open word; resets gated on pre-open active==0.
  reg_txn ≤1 access/path (READ=open, loop-RESP=complete/retire, FIN/RST=clear, else=read).
- Shim: nd_hold_resp/nd_retire_resp stamp shim.gen=cur_gen_conf(=CONF|gen), etype 0x88C3; from_loop
  parses 0x88C3→shim / 0x88C1→token / 0x0800→held-ACK; completion strips shim → byte-identical.
- Inactive drops verified: loop token drops if active==0; seed drops if active==0; stale-gen drop
  before cell/pop. Setup readback+assert (7>6>5>4 + shaping off) done in bootstrap_setup.py (v5).
- Two ICE workarounds documented (parser `shim.gen|CONF` ICEs → stamp CONF form at admission;
  `txn_old & GEN_MASK` in MAU ICEs → use slice `[30:0]`).

**►► MY FLAGGED CONCERN (under adversarial review a4eccd0a9d656c8c3): the RETIRE LIFECYCLE.** Retire
= clear reg_txn active, ONLY via txn_complete on loopback ROLE_RESP&&is_loop (or FIN/RST). A HELD
RESP sits on qid4 (LOWEST) behind the always-full qid7/qid5 reservoirs → it only dequeues+loops+
completes+retires at the §4 DEADLINE. Without the deadline (§3, or a missing/never-released RESP),
active stays set → the NEXT READ hits the overlap guard (no-op) → subsequent polls fail open until
FIN/RST. Is this a §3-modeling artifact, or does the full system need a §4 bounded-transaction
watchdog for the retire lifecycle to be correct? Also: nd_retire_resp routes forwarded RESPs through
qid7 (ACK reservoir queue) — safe? Reviewer to construct the exact sequence. Fail-open (safe) either
way, but must be disclosed honestly. Held commit until the review returns.

**v5 REVIEW DONE — mechanisms all CORRECT, 11 stages real.** Review (a4eccd0a) verdict: atomic
guard, packed reg_txn, shim lifecycle, inactive drainage, contract preservation all CORRECT; guard
ASSEMBLES; no code bug in the core. Corrected MY misread: forwarded-RESP detour uses qid7 (highest,
prompt), NOT qid4 — safe. FIXED the one real code gap: ROLE_ARM now port-qualified (from_out==0) so
a relay-side READ can't spuriously open. DISCLOSED the load-bearing finding honestly in the header +
evidence + R11: a genuinely-HELD RESP retires ONLY at the §4 deadline (qid4 starved by design), so
§3-in-isolation WEDGES FAIL-CLOSED after the first hold; HARD §4 req = deadline release + deadline <
poll interval + a bounded-txn watchdog. v4's unconditional re-open masked this; v5's guard EXPOSED it.

v5 committed 8258401 (source 7724ca70 = reviewed 5d51deba + port-qualifier + disclosure; recompiled
0 err, 11 stages, tofino.bin). evidence_v5/BOOTSTRAP_FEASIBILITY_V5.md written; R11 forward-corrected
(v5 supersedes v4). Formal compile of committed blob IN FLIGHT (bg bj2c69la7).

v5 committed (8258401 source, c3f674f evidence). Stray files cleaned (38c9006).

**►► Philip TWO-PHASE directive (2026-08-06): Phase 1 = freeze v5, ONE corrective commit
(BF-RT setup + evidence claims); Phase 2 = offline §4 Gate-2 integration. Stop before Gate 3/hardware.**

**PHASE 1 DONE (this commit):** v5.p4 FROZEN (untouched). (1) bootstrap_setup.py REPAIRED to the
PROVEN BF-RT pattern from case_a_read_anchored_dual_release setup (a20aec7): gc.KeyTuple/DataTuple
(not plain tuples); entry_get consumed as (data,key) iterable; _resolve_pg reads tf1.tm.port.cfg for
pg_id/pg_port_nr; flattened pg_queue = pg_nr*8+qid; sched_cfg keyed on (pg_id,pg_queue); min/max_
rate_enable in sched_cfg (NOT a separate sched_shaping table — that was wrong); RMW preserving
dwrr_weight + minimal fallback; readback DERIVES the ordering from HW max_priority (pnorm) and asserts
strictly 7>6>5>4 + shaping off; DEFENSE4_HW_AUTHORIZED guard kept; NOT executed. (2) Evidence wording
made precise (v5 evidence + R11): shim closes STALE gen-association, NOT concurrent robustness (exact
txn matching still a §4 obligation); overlapping READ state-preserving but its later RESP must not
bind to active txn; periodic pktgen CANNOT replace a lost current-gen token once CONFIRMED (pop is a
LEDGER; token replacement/continuity = SILICON R2/R11); byte-identical → "byte identity preserved by
construction, pending packet-level verification"; v5 = offline placement + semantic-repair probe with
§4 dependency; no complete §3/R11/Defense 4 claim; negative findings + prior probes preserved.

**PHASE 1 DONE + reported: commit 3568816** (BF-RT setup ported to proven pattern; claims precise).

**PHASE 2 (offline §4 Gate-2 integration) — Gate 2 FAILS the ≤12-stage fit (dependency wall).**
Build agent hit a session limit mid-work; I took over. The full §4 integration (v5 bootstrap + full
matching/dual-deadline/watchdog state, 11 registers) does NOT place — register-ordering wall
(reg_exp_ack/reg_resp_stage can't co-allocate). I located the wall CLEANLY with a minimal probe:
- v5 bootstrap alone = 6 reg, 11/12 stages.
- v5 + ONE ACK-deadline (reg_deadline, frozen D3 idiom) = 7 reg, **12/12 stages, 0 err, tofino.bin**
  — fits with ZERO headroom.
- full §4 (adds reg_exp_ack, reg_exp_seq, reg_flow_fp exact-matching + reg_flags lifecycle) = 11 reg
  → does NOT place. So 4 matching/flag registers over budget.
Per directive: NO semantic tradeoff taken; failed result PRESERVED; wall characterized; smallest
behavior-preserving alternatives presented (1 ingress→egress redistribution [recommended, egress
empty=free], 2 state-packing, 3 two-pass); STOPPED for a decision.

Committed: probes defense4/timing/probes/{min_ack_deadline_probe.p4 [compiles 12/12],
full_integration_wall_probe.p4 [preserved non-compiling]} + evidence
defense4/timing/evidence/GATE2_INTEGRATION.md. Designated defense4_timing.p4 LEFT at b9ac9e8 WIP
(NOT committed as passing). Frozen v4/v5 untouched. deadline<poll-interval is documented NOT the
safety mechanism (watchdog is, and it's in the state that doesn't yet fit — retain in any alternative).

**Next: AWAIT Philip's decision on which alternative (1/2/3) to pursue for the integrated core.**
R11 OPEN. Complete Defense 4 NOT DEMONSTRATED. No Gate 3/hardware/TM/size; no qid7 stress test.

# Defense 4 timing core — risk register

| # | risk | impact | mitigation | kill criterion |
|---|---|---|---|---|
| R1 | **Combined ingress core exceeds 12 stages** | no single-pass timing core | identify exact dependency/PHV cause from the compile logs; test bounded ingress→egress redistribution or a same-Tofino two-pass; keep all safety properties | cannot fit ≤12 or via 2-pass on Tofino-1 without dropping a required property → report NO-GO for the single-binary goal (do not pivot platforms) |
| R2 | **Reservoir develops a pre-deadline empty gap** (a held packet escapes early) | broken timing guarantee | seed both reservoirs before the earliest ACK; use the validated depth; Gate-3 continuity test; hardware readiness/continuity check | a reservoir cannot be kept non-empty to the deadline at any usable rate → the mechanism is infeasible at that rate |
| R3 | **`ack_committed_to_master` misdefined** (ACK arrival / blocker expiry taken as commitment) | RESPONSE released before the ACK reaches the master (ordering inversion) | commitment = ACK returned from loopback AND assigned to the master FIFO; encode in the release predicate; Gate-3 ordering tests | ordering inverts in any synthetic/hardware test → redesign the commitment signal before proceeding |
| R4 | **Synthetic ACK/RESPONSE fabrication** creep | fabricated DNP3 reaches an endpoint (integrity) | only blocker TOKENS recirculate; the real ACK/RESPONSE stay queue-resident; no emit of an ACK/RESPONSE anywhere | any fabricated ACK/RESPONSE observed → halt |
| R5 | **Blocker-token escape to an endpoint** | token leaks onto the wire | tokens die on budget/deadline; deparser never emits a token toward a master/relay port; Gate-3 token-isolation test | a token frame observed on a master/relay port → the decoder/egress is unsafe |
| R6 | **Concurrent transaction overwrites active state** | corrupted protected transaction | one active txn per domain; concurrent eligible txn fails open without touching active state; collision fingerprint guard | concurrent txn corrupts the active generation in test → fix admission before any live use |
| R7 | **Combined model `T_RESP=T_A+D_R` not placeable** on Tofino | cannot compute the response deadline at ACK arrival | fall back to the bounded `T_RESP = t_ACK_commit + D_R` (arm at commitment); record in `TIMING_SPEC.md` | neither construction places without dropping a property → report the deadline-composition limit |
| R8 | **Overclaiming from compile/synthetic alone** | false "Defense 4 done" | claim boundary fixed in `TIMING_SPEC.md` §9; compile+synthetic ⇒ feasibility + logical correctness only | any doc/commit calls Defense 4 complete without silicon → correct immediately |
| R9 | **Unauthorized hardware action** | switch/relay disturbance | hardware phase gated on Philip's explicit authorization; no P4 load / TM / port / relay / SELECT-OPERATE without it; exact restore in every exit path | any hardware step attempted without authorization → stop |
| R10 | **Scope regression** (READ-relative grid, tunnel, filler, size work reappears) | re-fragmented Defense 4 | single authority `README.md`; size deferred to Priority 2 behind the timing PASS checkpoint | a competing authority doc or size code appears during Priority 1 → remove it |
| R11 | **Reservoir bootstrap not autonomous** — the frozen Part 11 / Part 12 evidence established the K=64 reservoir via an EXTERNAL harness (ARM + blockers injected from Hulk; established-before-admit is a harness obligation). Defense 4 must instead establish + maintain **both** reservoirs with only one-time control-plane config and data-plane admission/stamping/readiness — a NEW, unproven obligation (`EVIDENCE_BASELINE.md`). | without an autonomous bootstrap the timing core cannot enforce "both reservoirs ready before the earliest ACK" on its own, i.e. Defense 4 is not deployable as specified | design + compile a bounded bootstrap candidate FIRST (one-time config only; no per-transaction host/controller seeding; tokens accepted only from an authenticated internal origin carrying scheduler-domain + role + generation; inactive tokens non-blocking; both reservoirs ready before a protected ACK is admitted; ACK-before-ready fails open un-stranded; stale tokens terminate without touching a newer generation; cleanup returns the domain to inactive/non-blocking; the establishment rule counts the validated population WITHOUT counting repeated passes of one token as distinct). Investigate the repo's Tofino pktgen examples: a continuously-configured pktgen source is acceptable ONLY if configured once and the data plane controls admission/stamping/readiness. | **if no one-time pktgen or persistent-token construction can satisfy established-before-admit WITHOUT a per-transaction external action → report Defense 4 FEASIBILITY BLOCKED (do NOT hide it behind the later hardware phase)** |

**R11 status (2026-08-05) — OPEN. §3 = PARTIAL/FAIL, NOT resolved.** An isolated probe
(`timing/bootstrap/bootstrap_probe.p4`, commit `d991944`) **places** eight bootstrap mechanisms in
isolation on Tofino-1 (6/12 ingress stages, 0 errors), and a first draft (one-shot + finite budget)
was usefully **refuted in code** (self-drain ~0.17 s no-traffic; gen-wrap drain at the 255th READ;
stale-true readiness). BUT a Philip audit established `d991944` does **NOT** implement the R11
contract: single QID_BLOCK/QID_HOLD instead of the four queues 7/6/5/4; ACK reads only `pop[ACK]`
(non-atomic dual-readiness); fail-open leaves `active` set (not transaction-level); marker written
but unvalidated + domain/tokid alias into cells; generation mismatch persists via `adopt_epoch()`
with termination only through a non-generation-qualified CP `reg_retire`; `pop` counts ingress
admission not confirmed loopback establishment; cleanup only on FIN/RST; no committed one-time setup.
`d991944` is kept as a **PARTIAL NEGATIVE** probe; the verdict is forward-corrected in
`timing/bootstrap/evidence/BOOTSTRAP_FEASIBILITY.md`.

**v2 (2026-08-05, commit `d67184f`).** `bootstrap_probe_v2.p4` (+ one-time `bootstrap_setup.py`)
implements the four-queue contract and PLACES on Tofino-1 (7/12 ingress stages, 5 SALUs, TNA-legal,
0 errors). Adversarial review: G2/G4/G5/G6/G7/G8 close in code; the flagged G3 `gen==0` fail-open
wrap is FIXED (gen_bump skips 0). **But R11 STAYS OPEN on a load-bearing SILICON/TM item the P4
cannot resolve:** two continuously-recirculating strict-priority block reservoirs on one loopback
port likely STARVE the lower — qid7 (ACK block), essentially never empty, starves qid5 (RESP block)
under strict priority, so RESP tokens never CONFIRM, `pop[RESP]` never reaches K, and `BOTH_READY`
(0x00400040) is **structurally unreachable → every transaction fails open** (predicted `reg_pop`
stalls at 0x00400000). This "can two strict-priority reservoirs coexist on one port" question was
NEVER concluded on silicon (four-queue oracle pilots failed, `case-a-four-queue-oracle-resume`). It
needs CO-EQUAL/WRR block queues or per-reservoir shapers, a TM decision proven on hardware;
`bootstrap_setup.py` leaves the scheduling policy an explicit unresolved stub. Verdict + evidence:
`timing/bootstrap/evidence_v2/BOOTSTRAP_FEASIBILITY_V2.md`.

**v2 (d67184f) CORRECTED (2026-08-05, second audit) — also a PARTIAL NEGATIVE probe.** The
"G1–G8 closed" claim is withdrawn; six code-path defects: (G2) `reg_pop` not reset/epoch-qualified
on `gen_bump` → stale K/K admits a new ACK; (G4) uninitialized metadata → undefined origin flags on
a host `0x88C1`; (G5) `reg_ident` lacks generation → unconditional `ident_clear` can wipe a
newer-generation cell (ABA); (wrap) 16-bit gen repeats every 65 535 txns → ABA unless widened or
token lifetime bounded; (G7) `active_read_clear` on native RESPONSE admission is premature (breaks
RESPONSE-before-ACK) — cleanup belongs at the held RESPONSE's loopback completion; (G8) setup is a
record, not executable. The proposed TM remedies (co-equal/WRR/shaping) are unsuitable: co-equal
block queues starve `Q_ACK_HOLD` (ACK can't commit at T_A); shaping lets a hold queue leak early.

**v3 direction (Philip):** STAGED data-plane establishment under the STATIC ladder 7>6>5>4 — a READ
opens a generation + 0/0; RESPONSE seeds accepted first (ACK seeds dropped) until 0/K; then ACK
seeds → K/K; only K/K admits the native ACK; release drains ACK-blocker→ACK→RESP-blocker→RESP
naturally. Solves starvation by admission ordering, no TM changes/controller. Plus: init every
metadata field; generation-qualified population; `{generation, lifecycle}` per cell; full-wrap ABA
via wider generation and/or bounded token lifetime; cleanup at generation-qualified RESPONSE
loopback completion; complete guarded setup on the fixed ladder, shaping disabled. Only after that
offline construction passes should a narrowly-scoped silicon continuity test be authorized.

**v3 (2026-08-05, sha256 31b51fce) — NEGATIVE: staged design DOES NOT PLACE (register-ordering
cycle).** v3 implements the staged design + all six v2 fixes (full metadata init verified — the
uninitialized warning is gone), but the fully-coupled single-pass contract fails table placement on a
**register-stage ordering cycle** (a Register lives in one MAU stage → all its accesses must agree on
one global order): (Conflict 1) the staged ACK-seed gate reads `reg_pop` before the seed writes
`reg_ident`, while a loopback confirm writes `reg_ident` before incrementing `reg_pop`
(`pop<ident ∧ ident<pop`). CORRECTED (per Philip): this proves only that **directly REUSING the
authoritative packed population register as the staged ACK-seed predicate creates an unsatisfiable
single-pass register-ordering cycle** — NOT that atomic readiness and staged admission are inherently
incompatible. **v4 (below) RESOLVES it** with shadow staging (a separate RESP-only `reg_resp_stage`
gates ACK seeding; the authoritative packed `reg_pop_packed` is read only by native admission).
(Conflict 2) a `{resp_gen, active, failopen}` SCC, resolvable semantics-preservingly by writing
`reg_resp_gen` gated-on-ready before the active read. Design fork SURFACED for Philip — Option A: single-pass,
split pop, drop single-read atomicity (correct under generation-qualification+staging); Option B:
multi-pass/recirculation, preserve atomicity (§4-ish implications). Evidence:
`timing/bootstrap/evidence_v3/BOOTSTRAP_FEASIBILITY_V3.md`.

**v4 (2026-08-05, commit `9effc43`, sha256 `dce08aa6`) — the R11 contract PLACES in ONE 12-stage
Tofino-1 ingress pass (positive OFFLINE result). R11 STAYS OPEN on silicon continuity.** Philip's
neither-A-nor-B THIRD construction — single-pass SHADOW STAGING with an authoritative packed
population word — resolves the cycle without dropping atomicity: a separate RESP-only `reg_resp_stage`
gates ACK seeding while the authoritative packed `reg_pop_packed` is read once by native admission
(atomic K/K). Acyclic chain gen<ident_resp<resp_stage<ident_ack<pop_packed<resp_gen<active<failopen
places in 12/12 stages (0 errors, tofino.bin, 8 stateful ALUs). Both v3 semantic bugs fixed (native
ACK checks the fail-open latch; unready RESP latches). The 16→12 fit used only behaviour-preserving
reductions (adversarially reviewed clean; independently verified bit-exact); shadow==pop.RESP is an
absolute lockstep invariant so no false K/K. Two SDE-9.13.1 toolchain defects recorded (bf-asm can't
assemble a masked stateful compare; non-monotonic placer). Disclosed residual: the
overlapping-transaction wrong-clear is fail-open, requires a single-outstanding violation (DNP3
forbids), and `ctr_overlap` is a detector not a guard; robust handling = a §4 loopback-generation
shim. Evidence: `timing/bootstrap/evidence_v4/BOOTSTRAP_FEASIBILITY_V4.md`. **The offline construction
now passes — per Philip, this is what would justify authorizing a narrowly-scoped SILICON continuity
test (reach+hold K/K within the CLRT), which stays GATED. R11 OPEN; Complete Defense 4 NOT DEMONSTRATED.**

**Hard safety floor (always):** Tofino-1 data-plane only; no controller release fast-path; physical
SEL-751 READ-only; no SELECT/OPERATE to the physical relay; frozen D1/D2/D3/Part-11/Part-12/four-queue
evidence unmodified.

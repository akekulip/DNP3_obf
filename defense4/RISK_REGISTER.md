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
`timing/bootstrap/evidence_v2/BOOTSTRAP_FEASIBILITY_V2.md`. **The next pre-feasibility step is
HARDWARE (choose + prove the block-queue scheduling), which is GATED — not §4 or more offline P4.**
The concept (periodic pktgen + deduplicated identity + generation-qualified residency) is sound in
code; feasibility hinges on the queueing question. This is a Tofino/TM limitation to solve and
evidence, not an impossibility result.

**Hard safety floor (always):** Tofino-1 data-plane only; no controller release fast-path; physical
SEL-751 READ-only; no SELECT/OPERATE to the physical relay; frozen D1/D2/D3/Part-11/Part-12/four-queue
evidence unmodified.

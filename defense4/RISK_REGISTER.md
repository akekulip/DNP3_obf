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

**Hard safety floor (always):** Tofino-1 data-plane only; no controller release fast-path; physical
SEL-751 READ-only; no SELECT/OPERATE to the physical relay; frozen D1/D2/D3/Part-11/Part-12/four-queue
evidence unmodified.

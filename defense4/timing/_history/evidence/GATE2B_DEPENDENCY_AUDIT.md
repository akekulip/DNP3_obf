# Defense 4 §4 Gate-2B — contract + dependency-graph audit (Phase 1)

Grounded in the **compiler's placement output** for the clean minimal probe (`min_ack_deadline_probe.p4`
@ `bbb940d`, from its `.bfa`), not register count. The question Gate-2B tests: can the COMPLETE
contract fit ≤12 ingress stages via **state consolidation + dependency parallelization**, with NO
ingress→egress redistribution?

## Authoritative placement of the 7-register minimal probe (from the .bfa)

| register | MAU stage | role |
|---|---|---|
| `reg_txn` | 0 | atomic {active, generation} guard (early, per-packet) |
| `reg_ident_resp` | 4 | RESP identity cells (generation, confirmed bit) |
| `reg_resp_stage` | 5 | RESP-only shadow (gates ACK seeding) |
| `reg_ident_ack` | 6 | ACK identity cells |
| `reg_pop_packed` | 8 | authoritative packed K/K |
| `reg_deadline` | **8** | **co-located with pop_packed — already PARALLEL** |
| `reg_failopen` | 10 | fail-open latch |

Non-register stages: 1–3 (front validation / cur_gen derive / now-word+cand build), 7 (ident_ack→pop
span), 9 (pop→failopen span), 11 (native-decision table). **Key finding:** the chain is NOT
fully serial — `reg_deadline` already shares stage 8 with `reg_pop_packed`, and stages 1–3/7/9/11 hold
non-stateful work. So there is **parallelization headroom**, and 12 stages is not a hard 1-register-per-stage
wall. The measured critical path is 7 (not 12), confirming the stage count is placement/width-bound,
not depth-bound.

## Dependency table (semantic vs. code-artifact)

| state word | writers | readers | required predecessors | role-exclusive? | proposed stage | dep kind |
|---|---|---|---|---|---|---|
| `reg_txn` {active,gen} | READ opens (atomic); RESP-loop/ FIN clears | every packet (gives cur_gen+active) | none (packet-derived) | no (all packets read) | 0 | semantic (must be first — everything is gen-qualified) |
| flow ownership (NEW: static exact-match table, replaces `reg_flow_fp`) | control plane (startup) | classify | flow key from parser | n/a (table) | 1 (parallel, front) | semantic; the 16-bit runtime hash was a CODE ARTIFACT (collision-prone) |
| `reg_exp_ack` (32b) | ARM writes expectation | native ACK validates | cur_gen (txn@0) | ACK-only | **~7–8 (parallel w/ pop)** | semantic; independent of resp path |
| `reg_exp_seq` (32b) | ARM writes expectation | native RESP validates | cur_gen (txn@0) | RESP-only | **~7–8 (parallel w/ pop)** | semantic; independent of ack path |
| `reg_ident_resp` | RESP seed/confirm | RESP loop | cur_gen | RESP-only | 4 | semantic (shadow staging) |
| `reg_resp_stage` | RESP confirm | ACK seed gate | ident_resp confirm | mixed | 5 | semantic (staging: gates ACK seeding) |
| `reg_ident_ack` | ACK seed/confirm | ACK loop | resp_stage==K | ACK-only | 6 | semantic |
| `reg_pop_packed` | confirms ++ | native admit | ident confirms | mixed | 8 | semantic (authoritative K/K) |
| `reg_deadline` | native ACK arms T_A/T_RESP | ACK/RESP loop expiry | now_word, cur_gen | mixed | 8 (∥ pop) | semantic |
| `reg_lifecycle` (NEW consolidated: failopen+flags) | ACK-commit / resp-present / drain / retire — all gen-qualified, one-shot | native decide + completion | pop/deadline read | mixed | ~10 | semantic; the SEPARATE failopen+flags were a CODE ARTIFACT |

## Consolidation + parallelization decisions (Gate-2B)

1. **Consolidate `reg_failopen` + `reg_flags` → one `reg_lifecycle` word** (generation-qualified,
   one-shot): fail-open latched, ACK admitted, RESP admitted, ACK-committed/released, RESP present,
   drain initiated, retirement/barrier. −1 register. Overlapping/dup/stale/nonmatching packets must
   not mutate it.
2. **Remove `reg_flow_fp` (16-bit runtime hash) → static exact-match flow→domain ownership table**
   (startup-installed; no per-transaction controller action). −1 register, and removes a collision
   window. This is a code-artifact removal, not a semantic weakening.
3. **Keep `reg_exp_ack` and `reg_exp_seq` as SEPARATE 32-bit words** (two independent TCP sequence
   spaces — directive forbids packing them). Place them **in parallel** with `reg_pop_packed`/
   `reg_deadline` (stage ~7–8): their expectations are written at ARM (inputs available early) and
   they are role-exclusive (exp_ack read only on the native ACK, exp_seq only on the native RESP), so
   they need not extend the serial chain.
4. **Parallelize role-exclusive paths:** do not write shared metadata that couples ACK-only and
   RESP-only work; do not read lifecycle state earlier than the native decision; keep exact-match
   state off the token-bookkeeping chain.

**Resulting register budget: 9** (`reg_txn`, `reg_ident_resp`, `reg_resp_stage`, `reg_ident_ack`,
`reg_pop_packed`, `reg_deadline`, `reg_exp_ack`, `reg_exp_seq`, `reg_lifecycle`) + one static
flow-ownership table — vs the failed integration's 11 registers + a runtime fingerprint. Whether 9
registers place in ≤12 stages is exactly what the Gate-2B compile decides; parallelization of
`reg_deadline`@8 (already observed) and the two role-exclusive expected-value words is the mechanism.
**Stage pins are applied only AFTER the natural dependency graph is derived from the compiler** — not
to force a serial design into fewer stages.

## Guardrails carried into the build
No accidental serial dependencies (no unnecessary shared-metadata writes, no ACK/RESP serialization,
no early lifecycle reads). Match-before-mutation. deadline<poll-interval is an operating condition,
NOT the safety mechanism (the watchdog + qid4 retirement barrier is). No ingress→egress redistribution
(deferred, unauthorized). No two-pass (unauthorized).

# Adversarial injection — the forged 0x88C1 token, on silicon

**2026-07-30. `case_a_defense3_repair_candidate` synthetic builds with `-DD3_INJECT`,
11/12 stages, critical path 10.** Switch restored to `d3_abs.conf` and verified.

## What was built, and why this way

The three adversarial cases the relay will not produce on its own — a mis-sequenced
response (R1), a foreign token at budget zero (R2), and an injected `0x88C1` frame (R3) —
all reduce to one primitive: **put a chosen frame on a switch port.** The lab cannot do
that from a host: the master has no passwordless raw socket, and the relay-facing port has
no host on it, only the physical SEL-751.

So the injector is built where it can be — **inside the switch.** Under a new compile flag
`D3_INJECT`, a parser path (`parse_pktgen_inject`) treats a specially-tagged
packet-generator frame as a **fresh, host-injected `0x88C1` blocker token**: `is_pktgen = 0`
and `dequeued = 0`, so it takes the legacy / R3 branch and — unlike a real reservoir token —
**keeps the generation and budget the frame carries** instead of being re-stamped with the
current generation on admission. It is the in-switch stand-in for a frame a real attacker
would forge on the wire. The addition is a value-set, a parse state, and one `from_pgen`
route; it compiles at the same 11/12 and is a complete no-op when the flag is absent
(`pgen_inject` absent from the bfrt, resources bit-identical).

`harness/inject_probe.py` forges one such token with a chosen gen and seq, writes a "live"
generation directly into `reg_tag` (the property under test is only whether the injected
token's write reaches `reg_tag`; how `reg_tag` got there is irrelevant), fires the injector
once, and reads back `reg_tag`, `reg_failopen` and the counters.

## The matrix

Live `reg_tag = 0xC0`. Inject a token, seq = 0, at two generations — one matching the live
value, one value-foreign — across four builds. `note` is `reg_failopen` afterward;
`ENQ`/`TMO`/`STALE` are the counter deltas.

| build | inject gen | `reg_tag` after | note | fresh counter | reached dp8 | meaning |
|---|---|---|---|---|---|---|
| INJECT only (no repairs) | 0xC0 | **0xC0** | — | ENQ=1 | TMO=1 | |
| R1 | 0xC0 | 0xC0 | — | ENQ=1 | TMO=1 | |
| R1 | 0xC1 | 0xC0 | — | ENQ=1 | STALE=1 | value-foreign → stale-dropped |
| R1 + R2 | 0xC0 | 0xC0 | **0xC0** | ENQ=1 | TMO=1 | R2 note records the gen |
| R1 + R2 | 0xC1 | 0xC0 | **0xC1** | ENQ=1 | STALE=1 | accepted, then stale-dropped |
| **R1 + R2 + R3** | 0xC0 | 0xC0 | 0 | **REJECT=1** | **none** | **R3: dropped, never enters** |
| **R1 + R2 + R3** | 0xC1 | 0xC0 | 0 | **REJECT=1** | **none** | **R3: dropped, never enters** |

The `fresh counter` column reflects the **counter-fixed** build (below): an accepted `to_block()`
increments `BLOCK_ENQ`; the R3 drop increments the distinct `BLOCK_REJECT`. The R3 rows and the
R1+R2 accepted rows were re-run on silicon after the fix (`counterfix_20260730T232946Z/`): R1+R2
gave `{BLOCK_ENQ:1, BLOCK_TERM_STALE:1}` with `reg_failopen = 0xC1` (R2 noted the foreign gen);
R1+R2+R3 gave `{BLOCK_REJECT:1}` alone, no dequeue-side termination, `reg_failopen = 0`.

## What this demonstrates

**1. R3 closes the injection path — demonstrated on silicon, deterministically.** This was
completely unexercised before. In every non-R3 build the forged token is enqueued and
reaches the dp8 loopback (`BLOCK_TERM_TMO` or `_STALE` = 1). Under R3 the same frame is
dropped at the fresh stage — the distinct `BLOCK_REJECT` counter records it, and it
**never reaches dp8** (no dequeue-side termination, and `reg_failopen` stays 0 because the
note path is never entered). That is exactly R3's contract: a host-injected `0x88C1` frame
cannot enter the strict-priority queue.

**2. R2's note mechanism executes on silicon.** With R2, the injected token's generation is
recorded in `reg_failopen` (`note = 0xC0` and `0xC1` for the two injections), and `reg_tag`
is preserved. `fo_note` fires; the destructive write does not.

**3. A value-foreign token is stale-dropped** (`BLOCK_TERM_STALE = 1`), a value-matching one
reaches budget termination (`BLOCK_TERM_TMO = 1`) — the priority the design intends.

## An apparent negative that the K-sweep overturned

This matrix showed the *injected* token leaving `reg_tag` unchanged (`TMO = 1`,
`reg_tag = 0xC0`) on every build, which looked like evidence that the budget-zero write
never fires. **That reading was wrong**, and it should not have been generalized to the
mechanism. The fail-open **K-sweep** (`evidence/ksweep/RESULTS.md`) ran the *native*
reservoir at K = 1 on the pure-defect build and got `TMO = 1, STALE = 0, reg_tag → 0`: a
single native budget-zero token **does** clear `reg_tag`, exactly as the audit's static
reading predicted.

So the injected token was the **anomaly**, not the mechanism. A frame forged through the
legacy `is_pktgen = 0` path with `seq = 0` from the start does not traverse the same write
as a native token that was admitted (stamped) and looped its budget down to zero. The
injector faithfully reproduces the *admission* state R3 must reject — which is what it was
built for, and what the R3 rows here establish — but it is **not** a faithful stand-in for a
native token's budget-zero *termination*. Do not read the `reg_tag` column of this matrix as
evidence about the fail-open write; read `evidence/ksweep/RESULTS.md` for that.

The defect is therefore real and reproduces at K = 1 (not merely in aggregate, and not via
unspecified "reservoir dynamics"). It is a **within-transaction** effect — the token carries
the live generation, so clearing `reg_tag` is that transaction's own fail-open, and R2
corrects the accounting to K TMO / 0 STALE. The **cross-transaction** clobber (a token from
a *retired* transaction clearing a *different* live one) still needs the generation-wrap
coincidence and stays model-checked; but the write it depends on is now confirmed real and
single-token.

## Counter fix (2026-07-30) — verified on silicon

The first matrix was recorded before the `BLOCK_ENQ` counter fix. On that build the R3-drop
path incremented `CF_BLOCK_ENQ`, which reads elsewhere as *residence in Q_BLOCK* — so a
dropped frame wrongly incremented an "enqueued" counter. The P4 now counts a distinct
`CF_BLOCK_REJECT` (index 17) on the R3 drop, and `CF_BLOCK_ENQ` fires only on an accepted
`to_block()`.

This was **re-run on hardware** (`counterfix_20260730T232946Z/`, injecting foreign gen 0xC1,
seq 0, while 0xC0 live) to confirm the fix and that behaviour is otherwise unchanged:

| build | `reg_tag` | `reg_failopen` | counter deltas |
|---|---|---|---|
| R1 + R2 (accepted, stale-dropped) | 0xC0 → 0xC0 | **0xC1** (R2 noted the gen) | `{BLOCK_ENQ: 1, BLOCK_TERM_STALE: 1}` |
| R1 + R2 + R3 (dropped fresh) | 0xC0 → 0xC0 | 0 | `{BLOCK_REJECT: 1}` |

So the accepted token still increments `BLOCK_ENQ` and the R3 drop now increments only
`BLOCK_REJECT`, with no dequeue-side termination in either case for the dropped frame — the
frame is still dropped before dp8, exactly as before; only the counter is corrected. Both
synthetic builds compile at the same resources (`enq_r1r2r3` 11/12 stages, `enq_none` 9/12).
Switch restored to `d3_abs.conf`, one `bf_switchd`, verified (`counterfix_.../post_state.txt`).

## What R1's injection would need, and why it is not here

R1's rejecting arm fires on a **relay-facing** mis-sequenced RESPONSE. The injector produces
frames classified `DIR_OUT` (from the generator), not `DIR_RELAY`, so it cannot forge a
response on the relay leg — that needs a host on the relay-facing port, which the lab does
not have. R1's rejecting arm is instead exercised synthetically by Gate 4 case F (a response
carrying the previous transaction's sequence), which passes 6/6 with the stale copy
bypassed and `reg_tag` unmarked. A live relay-side injector remains genuinely blocked by the
topology.

## Files

| file | what |
|---|---|
| `p4/…p4` `D3_INJECT` | the injector parser path (value-set `pgen_inject`, `parse_pktgen_inject`) |
| `harness/inject_probe.py` | forge one token, fire it, read the outcome |
| `20260730T213411Z/inj_*_{match,foreign}.json` | the six-cell matrix + the pure-defect control |

Reproduce: load a `-DD3_INJECT` synthetic build, `python3 case_a_..._setup.py --config`,
then `inject_probe.py <prog> 0xC0 0xC0 0 out.json`.

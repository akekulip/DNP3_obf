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

| build | inject gen | `reg_tag` after | note | ENQ | reached dp8 | meaning |
|---|---|---|---|---|---|---|
| INJECT only (no repairs) | 0xC0 | **0xC0** | — | 1 | TMO=1 | |
| R1 | 0xC0 | 0xC0 | — | 1 | TMO=1 | |
| R1 | 0xC1 | 0xC0 | — | 1 | STALE=1 | value-foreign → stale-dropped |
| R1 + R2 | 0xC0 | 0xC0 | **0xC0** | 1 | TMO=1 | R2 note records the gen |
| R1 + R2 | 0xC1 | 0xC0 | **0xC1** | 1 | STALE=1 | |
| **R1 + R2 + R3** | 0xC0 | 0xC0 | 0 | 1 | **none** | **R3: dropped, never enters** |
| **R1 + R2 + R3** | 0xC1 | 0xC0 | 0 | 1 | **none** | **R3: dropped, never enters** |

## What this demonstrates

**1. R3 closes the injection path — demonstrated on silicon, deterministically.** This was
completely unexercised before. In every non-R3 build the forged token is enqueued and
reaches the dp8 loopback (`BLOCK_TERM_TMO` or `_STALE` = 1). Under R3 the same frame is
dropped at the fresh stage — `BLOCK_ENQ` counts it, but it **never reaches dp8** (no
dequeue-side termination, and `reg_failopen` stays 0 because the note path is never entered).
That is exactly R3's contract: a host-injected `0x88C1` frame cannot enter the
strict-priority queue.

**2. R2's note mechanism executes on silicon.** With R2, the injected token's generation is
recorded in `reg_failopen` (`note = 0xC0` and `0xC1` for the two injections), and `reg_tag`
is preserved. `fo_note` fires; the destructive write does not.

**3. A value-foreign token is stale-dropped** (`BLOCK_TERM_STALE = 1`), a value-matching one
reaches budget termination (`BLOCK_TERM_TMO = 1`) — the priority the design intends.

## What this does NOT demonstrate, and the finding that matters

**A single injected token does not clobber `reg_tag` — in any build, including the one with
no repairs at all.** Injecting a value-matching token (0xC0) while 0xC0 is live gives
`TMO = 1` and `reg_tag` unchanged, on the pure-defect build as much as on R2. So the
cross-transaction clobber that the audit's static reading predicted — "a budget-zero token's
write commits at level 2 before the stale check at level 3" — **does not manifest from a
lone injected token.**

The defect's real signature was only ever seen in *aggregate*, with the full 64-token
reservoir: `evidence/failopen/` shows the unrepaired build crediting 1 token to the budget
and 63 to *stale* (because the first token's write cleared `reg_tag`, so the rest read
foreign), which R2 corrects to 64 and 0. That is a real defect — the miscounting is real,
and it means the fail-open path was not doing what its counters claimed — but it is a
**within-transaction** effect on the transaction's own reservoir, not the
**cross-transaction** clobber of a *different* live transaction.

Reconciling the two: a token's generation IS its identity. A token that could clobber a
*different* live transaction must carry that transaction's value (temporal foreignness from
generation wrap), at which point the mechanism cannot distinguish it from the live
transaction's own token — and a single such token, as this matrix shows, does not write
`reg_tag` anyway. **So the dangerous cross-transaction clobber is narrower than the source
reading suggested: it requires the wrap coincidence AND the reservoir dynamics that produce
the aggregate write, not merely one stray token.** R2 is defense-in-depth against a window
that is even smaller than §7.6 feared.

## Counter fix (2026-07-30, after this matrix)

The matrix above was recorded before the `BLOCK_ENQ` counter fix. On that build the R3-drop
path incremented `CF_BLOCK_ENQ`, which reads elsewhere as *residence in Q_BLOCK* — so a
dropped frame wrongly incremented an "enqueued" counter. The P4 now counts a distinct
`CF_BLOCK_REJECT` on the R3 drop, and `CF_BLOCK_ENQ` fires only on an accepted `to_block()`.
The *behaviour* is unchanged (the frame is still dropped before dp8, shown by the absence of
any dequeue-side termination); only the counter name is corrected, so "ENQ=1" in the matrix
above should be read as "a fresh blocker candidate was seen," which is now `BLOCK_REJECT=1`.

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

# Defense 3 — repair history (why `case_a_defense3_repair_candidate.p4` is named that)

This file holds the historical build-and-provenance notes that used to sit in the header of
`p4/case_a_defense3_repair_candidate.p4`, moved here on 2026-07-30 once the three repairs
were loaded and validated on silicon and the header's "candidate / not loaded" framing
became false. The P4 file is now the **final repaired R1+R2+R3 build**; this is its history.

## Why a separate file, not `#ifdef`s in the frozen source

The repairs were authored in a **copy** of `p4/case_a_defense3_fixed_ack_delay.p4` rather than
edited into it, because the archived resource logs and assembly name tables by **source line
number** (e.g. `tbl_case_a_defense3_fixed_ack_delay1871`). Editing the original would break
the correspondence between the source, the archived assembly in `artifacts/`, and the binaries
that were run. The frozen `case_a_defense3_fixed_ack_delay.p4` is the original (unrepaired)
Defense 3 program and remains the switch's restore baseline; it is **not** modified by the
repair work. The repaired program kept the `..._repair_candidate.p4` filename after validation
because the harness (`harness/inject_probe.py`, the setup module), the swap `.conf` files, and
the archived evidence all reference it by that exact name; renaming would orphan that evidence.

## The candidate phase (now superseded)

Originally the file was **authored and locally compiled only** — nothing loaded, the switch
untouched, and the (then) loaded program was the frozen baseline. That phase is over:

- **R1** (authorise a RESPONSE's marker before writing it, `D3_REPAIR_R1`) — validated on
  silicon in the synthetic build (Gate 2/3/4) and run against the physical relay for 960
  transactions (REPORT §7.6, §10.5).
- **R2** (generation-qualify the fail-open via a second register `reg_failopen`,
  `D3_REPAIR_R2`) — validated on silicon at two budgets; fail-open terminations went from the
  defective 1 TMO / K−1 STALE to the correct K TMO / 0 STALE with `reg_tag` preserved
  (REPORT §7.7). The three refuted merge attempts (single arm → input-crossbar error; fifth
  RegisterAction → too-many-RegisterActions error; packed 16-bit pair → "requires more than 2
  PHV inputs") are recorded in `p4/probe_failopen_qualification.p4` and REPORT §7.6.
- **R3** (drop a fresh, non-generator `0x88C1` frame instead of enqueuing it, `D3_REPAIR_R3`)
  — demonstrated on silicon with the in-switch injector; the dropped frame increments the
  distinct `BLOCK_REJECT` counter and never reaches the loopback (REPORT §7.8).

## The fail-open clobber: what the injector did and did not show

The `D3_INJECT` in-switch injector faithfully reproduces the **admission** state R3 must
reject (a fresh `0x88C1` token on a host-facing port). It is **not** a faithful stand-in for a
native token's budget-zero *termination*: a frame forged through the legacy `is_pktgen = 0`
path with `seq = 0` from the start does not traverse the same write as a native token that was
admitted, stamped, and looped its budget to zero. The injected token therefore left `reg_tag`
unchanged, which briefly looked like evidence the destructive write never fires — an
**injection-harness artifact**. The fail-open **K-sweep** on the *native* reservoir settled it:
a single native budget-zero token clears `reg_tag` at K = 1 (1 TMO / 0 STALE / `reg_tag → 0`),
so the write the audit predicted is real and single-token. The cross-transaction *reach* of
that write (a retired transaction's token clearing a different live one) still needs the
generation-wrap coincidence and stays model-checked, not reproduced (REPORT §7.8, limit 10).

## Resource footprint across the two generations

See REPORT §9.9 for the two-generation table. In short: the original campaign build was 9/12
(core) at critical path 8; the final R1+R2+R3 build is 10/12 (core) / 11/12 (telemetry and
synthetic/injector) at critical path 10, the extra table and dependency level being R1's cost.
R2 and R3 add zero on top of R1.


---

# Moved out of REPORT (2026-08-04)

The report was restructured to explain the system **as built** and to interpret its
results, rather than to narrate how it was debugged. The defect-and-repair material
below was removed from `REPORT.md`/`REPORT.tex` and is preserved here verbatim. The
behaviours these sections introduced are still in the shipped program
(`p4/case_a_defense3.p4`) and are described there and in the report as ordinary design,
without the R1/R2/R3 labels.

### 8.5 Three defects — all three repaired and validated on silicon

An external audit found three defects — two state-ordering (defects 1 and 2) and a
host-injected-token admission path (defect 3) — and reading the source confirmed all three.
Since then **all three have been repaired and each validated on silicon**; defect 2's obvious
one-operation repair was shown *not* to fit and a second-register repair was built instead
(§8.6–§8.7). Current status, before the explanation:

| defect | repair | status |
|---|---|---|
| **1 — a RESPONSE marks before its identity is checked** | **R1** | **REPAIRED.** Compiles at 10/12 (live core), 11/12 (live + telemetry, and synthetic), critical path 10. **Validated on silicon in the synthetic build** (Gate 2 PASS, Gate 3 PASS 10/10, Gate 4 PASS on all six cases) **and run against the physical relay** for 960 transactions with the hold, the CLRT compression and the ordering invariant all unchanged (§11.5). |
| **2 — fail-open retirement is not generation-qualified** | **R2** | **REPAIRED, VALIDATED ON SILICON, AND RUN ON THE LIVE BUILD** (§8.7, §11.5). Fail-open now credits all 64 tokens instead of 1, `reg_tag` survives, the next transaction still arms — 28/28 trials at two budgets — and 960 live transactions against the relay show no harm. ⚠ Single-generation only; the *foreign*-token case is model-checked, not produced on hardware. |
| **3 — a host-injected `0x88C1` frame enters the priority queue** | **R3** | **REPAIRED and DEMONSTRATED ON SILICON** (§8.8). A forged `0x88C1` token injected in-switch is dropped at the fresh stage and never reaches the loopback; without R3 the same frame enters. Zero resource cost. |

**The original physical campaign — §§11.1–10.4 and the §12 D-sweep, every number in those
results — was collected on the UNREPAIRED build**, with all three defects present. The
**repaired** builds appear only in **§11.5** (the two R1+R3 and R1+R2+R3 live campaigns
totalling 1 920 transactions). The repairs do not retroactively change any earlier
measurement; they change what the mechanism does next time.

The repair work, the compile evidence and the refutation of R2 are in
`design/REPAIR_R1_R2_R3.md`; the silicon rerun is in `evidence/repaired/RESULTS.md`.

**The rule the two state-ordering defects break: state is written before it is validated.**
The switch resolves a packet's conditions across pipeline levels, and in both cases the
register write happens at level 2 while the test that authorises it resolves at level 3.

**Defect 1 — a RESPONSE marks the transaction before its identity is checked.**

```
level 1 class driver sets meta.tag_val = TAG_PENDING_DELTA for a RESPONSE (p4 1924–1932)
level 2 meta.cur_gen = tag_read_or_mark.execute(0) <-- THE WRITE HAPPENS HERE (1973–1978)
level 3 tbl_state_decode.apply() <-- seq / ack / learned-port resolve HERE (1990)
```

`CLASS_RESP` is assigned on direction, session and DNP3 framing alone. The stateful ALU's
own guard is `(int<8>)v < 8s0` — a test on the *stored* state, not on *this packet's*
validity. So a correctly framed response on the tracked session with a **wrong TCP
sequence** still marks the live transaction. The legitimate response then reads the pending
marker, is treated as a duplicate and is **dropped**, and the acknowledgement's release
declines to retire — leaving the transaction stuck until fail-open.

**Defect 2 — a foreign zero-budget token can retire the current transaction.**

```
p4 1938 if (meta.budget_zero == 8w1) { meta.tag_val = TAG_INACTIVE; }
p4 1985 meta.tag_diff = tag_rmw.execute(0); <-- writes it, guarded only by tag_val
p4 1990 tbl_state_decode.apply(); <-- the generation check is HERE
```

The documented `stale > deadline > budget` priority is evaluated in the action block, one
level *after* the write has already committed. A later table cannot undo a stateful-ALU
write. And the parser forces EtherType `0x88C1` to `ROLE_BLOCK` from **any** topology port,
with a legacy branch that enqueues such a frame into the strict-priority queue — so an
injected token with a zero budget reaches this path. The threat model is passive, so that
injection is outside the modelled adversary, but a production build should not carry it.

**Neither defect was observed firing.** Across 400 defended physical transactions,
duplicate suppressions were 0, stale terminations were 0 and fail-open fired 0 times. They
were latent, not manifested — but "not observed" is not "cannot happen", and defect 1
invalidated a test this report previously reported as passing (§10.8).


### 8.6 What the repairs cost, and why one of them is refuted

**R1 — authorise the marker before writing it. It fits.** The RESPONSE rows of
`tbl_state_decode` mask `tag_diff` out entirely, so the RESPONSE verdict never depended on
`reg_tag` at all: it depends only on the three session-tracker differences, and all three
are produced *before* the tag access. The same conjuncts therefore resolve one level earlier
in a small table and choose the marker delta. An unauthorised RESPONSE now carries delta 0,
which makes the identical stateful operation a pure read. `reg_tag` keeps its placement and
its four operations. Cost: one table and one dependency level — 9 → 10 ingress stages,
critical path 8 → 10. Since stage count now equals critical path the program is
dependency-bound at 10, and with the telemetry registers it would sit at 11/12.

**R2 — generation-qualify the fail-open retire. Three refuted attempts, then a repair.**
The two operations look mergeable into one stateful arm (`if idle, arm` and `if it is mine,
retire` are the same shape). They are not.
`p4/probe_failopen_qualification.p4` reduces the first two walls to a minimal program:

| build | result |
|---|---|
| four operations, unmerged | **compiles** — the control |
| merged into one arm | `error: The input meta.tag_alt to stateful alu reg_tag is not allocated in a valid region on the input xbar to be a source of an ALU operation` |
| kept separate, i.e. a fifth operation | `error: too many RegisterActions attached to the Register` |

A third attempt, packing both operands into one 16-bit field, named the real constraint
outright: `error: Ingress.reg_tag requires more than 2 PHV inputs`. **`reg_tag`'s stateful
ALU has a budget of two PHV inputs shared across all four of its operations, and it was
already full** (`gen_in` and `tag_val`). No third source can be added, however packaged.

**The repair works by not needing one.** Two observations. The fail-open write never
released anything — the held ACK leaves because the budget-zero token *drops itself* and
`Q_BLOCK` empties — so its only job was to let the **next** READ arm. And on the ARM path
`meta.tag_val` is dead. So the note rides on `tag_val`, an operand `reg_tag` already has,
and **the generation qualification moves from the producer to the consumer**:

```
producer a budget-zero token records the generation IT carries, in reg_failopen.
 Unconditional, and harmless: a note naming a generation is not a
 destructive write.
consumer the next READ arms if reg_tag is idle OR equals the noted generation.
 A foreign token's note names a generation that is not the live one,
 so it can never authorise anything.
```

The note is cleared as it is read, so it authorises at most one arm. Cost: **none** on top
of R1 and R3 — 11/12 stages, critical path 10, identical without it.

**The note is an *observation*, not proof of ownership.** A stale or foreign budget-zero
token also writes `reg_failopen` (the injection matrix shows a foreign 0xC1 token recording
`note = 0xC1`), because the producer is unconditional. Safety comes entirely from the
*consumer*: the next READ arms over the note only if `reg_tag == reg_failopen`, so a
mismatching note can never authorise a takeover. Three invariants must stay tested — every
READ consumes or clears the note; a mismatching note cannot authorise; and an old matching
note cannot survive until the generation value is reused. R3 closes the external
forged-token route, but *internal* stale tokens can still write mismatching notes, so R2
must remain safe independently of R3 — which the consumer equality check ensures.

Verified offline three ways. The compiled assembly is *asserted* to contain both
comparisons and a write predicated on their OR (`alu_a (cmplo | cmphi)`), because a
predicate that compiles and is never true is exactly the trap of §8.1 and §8.2. The state
model gained 321 assertions over all sixteen generations and all ordered foreign pairs. And
the suite is mutation-checked: dropping the note comparison gives 16 failures, arming
unconditionally 224, making the note reusable 16. **R2 was subsequently loaded and validated
on silicon at two budgets; see §8.7.**

**R3 — refuse host-injected blocker frames. Free.** 9 ingress stages, critical path 8,
resources bit-identical to baseline. It matters more than its size: it removes the only
*practical* route to defect 2. Without an injectable token, reaching defect 2 requires a
blocker to outlive its own generation's deadline, which was never observed in 25 600 tokens.

**A repair that broke the mechanism, caught by Gate 2 on the first transaction.** R1's first
version gave its authorisation table a catch-all default action setting `tag_val = 0`. That
reaches every packet class, and for every class other than the RESPONSE the tag arm is
`tag_rmw`, whose write is guarded by `tag_val != TAG_NO_WRITE` — so it became an
unconditional write of `TAG_INACTIVE`. The READ armed the generation and the mirrored
trigger clone, returning ~700 ns later, wiped it: `PKTGEN_ADMIT=0`, `PKTGEN_DROP=64`,
`ACK_REJECT=1`. Fixed by making "not authorised" a CLASS_RESP *entry* rather than the table
default. It is worth recording that this defect passed 2 354 offline assertions and a
compile-fit check first: **the offline model covers the state machine, not which table
default reaches which packet class.**


### 8.7 R2 on silicon, and a defect fingerprint that was already in the evidence

**A correction first.** I wrote that fail-open "has fired 0 times in every campaign, so the
path has never executed on silicon". That is true of the gates and both D-sweeps, where the
deadline always beat the budget — but `--check2` is READ-only by construction, so no ACK
arrives, no deadline is armed, and the tokens can *only* terminate on the budget. The path
had been executing all along. What had not been done was reading what it recorded.

**The defect was visible in evidence collected a day earlier.** Unrepaired build, 60
trials, every single one:

```
BLOCK_TERM_TMO = 1 BLOCK_TERM_STALE = 63 reg_tag afterwards = 0
```

One token terminates on the budget and sixty-three are credited as *stale*. That 1/63 split
**is** the defect: the first token to reach budget zero writes `TAG_INACTIVE` with no
generation test, and the other 63 then compute `gen_in − 0 ≠ 0`, read as a foreign
generation and are dropped. Both outcomes are "token terminated", so nothing looked wrong.

**R2 predicts 64 and 0, and that is what the hardware gives.** Two arms, 28 trials each:

| | unrepaired | R2, B = 18 000 | R2, B = 500 |
|---|---|---|---|
| `BLOCK_TERM_TMO` | 1 | **64** | **64** |
| `BLOCK_TERM_STALE` | 63 | **0** | **0** |
| `BLOCK_LOOP` | 1 152 000 | 1 152 000 | **32 000** |
| `reg_tag` afterwards | 0 (cleared) | **0xC0 (preserved)** | **0xC0 (preserved)** |
| next trial `ARM_FRESH` / `PKTGEN_ADMIT` | 1 / 64 | **1 / 64** | **1 / 64** |

The recovery property survives, which was the risk in not clearing `reg_tag`: the next READ
arms through the note and its reservoir is admitted in full, `ARM_BUSY = 0` throughout. And
the budget arithmetic is confirmed exactly — `BLOCK_LOOP = K × B` on the nose at both
budgets, which is the model `H = B·K/rate` rests on.

**One guard had to be scoped.** The shrunk budget was first *refused*: `H = 0.856 ms ≤
a_worst + D = 24 ms`, i.e. the budget would fire during a legitimate hold. Correct in
general — that is the §7.3 failure mode — but the wrong test for a READ-only trial, where no
ACK arrives and there is no hold to cut short. It is now gated behind an explicit
`--read-only-trial`; the general case is untouched. **A safety check that fires on the one
scenario a mechanism exists for is usually mis-scoped, not too strict, and the fix is to
narrow its precondition rather than remove it.**

**The single-token case is now pinned down (§8.8's K-sweep).** On the unrepaired build a
reservoir of *one* native token gives TMO = 1, STALE = 0, `reg_tag` cleared — so a single
budget-zero token does write the tag, and `1 / K−1` is the mechanical cascade at larger K.
R2 turns every K into K budget terminations, 0 stale, tag preserved.

⚠ **These trials are single-generation.** The token reaching budget zero always carries the
live generation, so they exercise note-and-recover and the within-transaction accounting,
**not** the *cross-transaction* case — a token from a retired transaction clearing a
*different* live one. That needs the generation-wrap coincidence and remains model-checked
(321 assertions over all ordered foreign pairs), not reproduced on hardware. Detail:
`evidence/failopen/RESULTS.md`, `evidence/ksweep/RESULTS.md`.


### 8.8 Injecting the adversarial frames, and a defect narrower than it read

The three cases the relay will not produce — a mis-sequenced response (R1), a foreign token
at budget zero (R2), an injected `0x88C1` frame (R3) — all reduce to putting a chosen frame
on a switch port. The lab cannot do that from a host (no raw socket on the master, no host
on the relay leg), so the injector is built **inside the switch**, under a flag
`D3_INJECT`: a parser path that treats a tagged generator frame as a fresh, host-injected
`0x88C1` token carrying an attacker-chosen generation and budget. It compiles at the same
11/12 and is a no-op when the flag is absent.

**R3 is now demonstrated on silicon** — it had been completely unexercised. Injecting the
forged token across builds:

| | `reg_tag` after | note (`reg_failopen`) | reached the loopback? |
|---|---|---|---|
| no repairs, inject 0xC0 | 0xC0 | — | yes (TMO) |
| R1+R2, inject 0xC0 | 0xC0 | **0xC0** | yes (TMO) |
| **R1+R2+R3**, inject 0xC0 | 0xC0 | 0 | **no — dropped fresh** |

Under R3 the frame is dropped at the fresh stage and never reaches the strict-priority
queue; without R3 it enters. And **R2's note mechanism is shown executing** — with R2 the
injected token's generation is recorded in `reg_failopen` and `reg_tag` is preserved.

**A counter that misreported the drop, corrected and re-verified.** The first
injector build counted the R3 drop with `BLOCK_ENQ`, the same counter that elsewhere means
*residence in* `Q_BLOCK` — so a dropped frame wrongly incremented an "enqueued" tally. The
P4 now increments a distinct `BLOCK_REJECT` on the R3 drop, and `BLOCK_ENQ` fires only on an
accepted `to_block()`. Re-run on silicon (foreign gen 0xC1, seq 0, 0xC0 live): the R1+R2
build gives `{BLOCK_ENQ:1, BLOCK_TERM_STALE:1}` with `reg_failopen = 0xC1` (the accepted
token is enqueued, then stale-dropped at dequeue, and R2 noted its generation), while
R1+R2+R3 gives `{BLOCK_REJECT:1}` alone — no enqueue, no dequeue-side termination,
`reg_failopen = 0`. The drop behaviour is unchanged; only the accounting is now correct.

**A puzzle the injector raised, and a microbenchmark that resolved it.** The *injected*
token above did **not** clobber `reg_tag` on any build — including the pure-defect one — which
seemed to say the write never fires. That was an **injection-harness artifact**, not a fact
about the mechanism, and a fail-open *K*-sweep on the **native** reservoir settled it.

The sweep runs a READ-only fail-open (no ACK, so the budget is the only terminator) at
reservoir sizes `K = 1, 2, 4, … , 64` on the pure-defect build, and reads the terminations
and `reg_tag`:

| K | 1 | 2 | 4 | 8 | 16 | 32 | 64 |
|---|---|---|---|---|---|---|---|
| budget-expiry (TMO) | **1** | 1 | 1 | 1 | 1 | 1 | 1 |
| stale | **0** | 1 | 3 | 7 | 15 | 31 | 63 |
| `reg_tag` after | **0** | 0 | 0 | 0 | 0 | 0 | 0 |

**TMO = 1 and STALE = K − 1 at every K, and `reg_tag` is cleared even at K = 1.** So the
write the audit predicted *does* fire — from a single **native** token — and the
`1 / K−1` cascade is its mechanical consequence: the first budget-zero token clears the tag,
and every later token then reads foreign and terminates stale. The injected token was the
anomaly, because a frame forged through the legacy path with `seq = 0` from the start does
not traverse the same write as a token that was admitted and looped its budget down. **The
defect is real and reproduces at K = 1**; my earlier "a single token does not clobber" was
wrong about the native path.

**What this does and does not settle.** It is a *within-transaction* effect — every token
carries the live generation, so clearing `reg_tag` is that transaction's own fail-open, and
the harm is the corrupted accounting (1 TMO / K−1 STALE instead of K / 0) and the lost
reservoir ownership. R2 fixes it to K TMO / 0 STALE with `reg_tag` preserved (§8.7). The
*cross-transaction* clobber — a token from a *retired* transaction clearing a *different*
live one — is a separate claim that still needs the generation-wrap coincidence and remains
model-checked, not reproduced; but the write it depends on is now confirmed real and
single-token on silicon. Detail: `evidence/ksweep/RESULTS.md`,
`evidence/inject/RESULTS.md`.

![The fail-open K-sweep and R2's correction](figures/out/fig9_ksweep.png)

**Figure 9.** *(a)* On the unrepaired build the budget-zero terminations are 1 (budget) and
K−1 (stale) at every reservoir size, including K = 1 — one native token clears `reg_tag` and
the rest read foreign, so the defect is not an emergent effect of size. *(b)* R2 turns the
same event into K budget terminations and 0 stale, and preserves `reg_tag`. Source:
`figures/src/fig9_ksweep.py`.


### 9.2 The bug: a missing exit from the state machine

Gate 4 case C tested the obvious failure: the relay acknowledges but never answers. The
result was clean on every count except one — **the transaction never ended**. `reg_tag` was
left holding a live identity forever, and the *next* poll was consequently refused as a
concurrent transaction: no reservoir, no hold, an unprotected transaction.

The cause is a two-line proof. There were exactly two ways to end a transaction:

1. the released response ends it, and
2. the fail-open budget ends it.

With no response, (1) cannot fire. And the tokens die on the *deadline*, so they never reach
their budget — the deadline **pre-empts** (2). Neither exit fires. The measured cost was
exactly **one** subsequent unprotected transaction, after which the system self-heals,
because the *next* transaction's own response clears the stale identity on its way out.


### 9.3 The repair that could not be built

The natural fix is to record "a response is pending for transaction *g*" in a second
register, and on the acknowledgement's release check whether it matches the current
transaction. It **does not compile**:

```
error: Table placement cannot make any more progress. Though some tables have not yet
been placed, dependency analysis has found that no more tables are placeable.
```

The reason is structural, not incidental. The response path needs to read the identity
register *before* writing the pending register. The acknowledgement-release path needs the
opposite order. Register placement in this hardware is **static** — each register lives in
exactly one pipeline stage — so two registers with opposite orderings on two paths are a
dependency cycle, even though the two paths are mutually exclusive at run time. The
condition that separates them is invisible to placement.

`p4/probe_retire_dependency.p4` reduces this to the smallest possible reproduction: two
byte-sized registers, two paths, opposite orders, nothing else. `-DPROBE_CYCLE` reproduces
the error verbatim. Keeping the state **inside the existing register** (`-DPROBE_ONE_REG`)
compiles in two stages. That is why the design is as it is.


### 9.4 The repair that was built

- when the first response of a transaction is admitted, add `0x50` (one-shot by
 construction);
- on the acknowledgement's release, **if the top bit is still set** — meaning nothing is
 pending — end the transaction immediately;
- if the top bit is clear, a response is queued, so leave the transaction live and let that
 response end it, exactly as before.

One extra table entry was required. When the marker changes, the circulating tokens are
comparing themselves against a value that just moved. The difference a token computes is
`carried_identity − stored_value`, which for a marked tag is `0xC*n* − (0xC*n* − 0xB0)` =
**`0xB0` for every one of the sixteen identities**. So it is a single exact entry, not
sixteen, and if it were wrong the failure would be immediate and loud: the tokens would read
as foreign, the reservoir would collapse before the deadline, and the counters would show it.
`BLOCK_TERM_STALE` was **0** in every subsequent test.

**A free bonus fell out of the encoding.** The "response pending" state is a *distinct
value*, not a flag, so every pre-existing test of the form "is this transaction live and
nothing pending yet" keeps its exact meaning — and a duplicate response therefore misses the
hold branch by itself, with no new code. That is how §10's duplicate case is handled.


### 9.5 A defect that the repair itself introduced

Moving "idle" to `0x00` collided it with a **different** constant already meaning "leave this
register alone" — also `0x00`. Both transaction-ending paths write "idle" through the
operation guarded by that constant, so **both silently became no-ops**. Nothing had run yet;
it was caught by an audit, not by a failure.

This is worth stating as a general lesson: **a fix that moves a sentinel value must enumerate
every other sentinel in the same field.** The distinct-value constant was moved to `0x01`,
which is safe because the field only ever holds that constant, idle, or an identity in
`0xC0`–`0xCF`.


## 15. Lessons: what went wrong along the way, and what it cost

Recorded because the pattern is more useful than the individual bugs: **in this project,
tests and criteria were wrong about as often as the code was.**

| # | mistake | how it was found | cost |
|---|---|---|---|
| 1 | Graded the design against a broader objective than the threat model sets, and concluded "do not build" | corrected by the project lead | one wrong verdict, reversed |
| 2 | Quoted D = 12 ms as reaching a 99th percentile of 12.607 ms | caught in review | corrected to 13 |
| 3 | Pooled a connection-cold poll into a "steady-state" sample | found by a review pass | D for a full clamp was 13 ms, not 22 |
| 4 | Large constant in stateful hardware; the write silently never committed | reading the compiled assembly, after two wrong theories | the whole of §8.1 |
| 5 | Then claimed the *cause* was proven from the assembly | a 13-constant probe showed identical output for all K | claim narrowed to an inference |
| 6 | Moving the idle marker collided it with a different sentinel; both transaction exits became no-ops | an audit, before it ever ran | would have broken every second transaction |
| 7 | Counted the defense's own mirrored copy as an off-topology packet | the same audit | made a gate requirement unsatisfiable whenever the defense worked |
| 8 | Left a stale `0xFF` in the scoring code | the same audit | a gate could never pass again |
| 9 | Put all synthetic events in one generator run | measured 1 000 012 ns, reproduced to the nanosecond | discovered the generator run-span law |
| 10 | Assumed a pattern-triggered generator can label its packets | three roles collapsed into one | forced the two-timer design |
| 11 | Set the token increment in the wrong branch of the classifier | 16 admitted then 48 dropped — `0xC0 + 16 = 0xD0` leaves the valid range exactly at token 17 | one silicon run |
| 12 | Clean-state criterion demanded zeros the architecture never promised | Gate 3 stopped at transaction 2 | replaced with a **stricter** rule |
| 13 | Sign test written unsigned; always false | the assembly assertion, which now blocks it | §8.2 |
| 14 | Duplicate-response rubric never tested ordering | added a timestamp and looked | the duplicate was overtaking the held ACK by 1.0014 ms |
| 15 | That new timestamp also fired on the *dropped* copy | the gate failed against a packet that departed nowhere | one analysis pass |
| 16 | Scored a boundary case with the normal-transaction rubric, which forbids the bypass the case exists to produce | the gate failed on its own purpose | one analysis pass |
| 17 | No live arming step, so the first physical run had an empty hold queue | the registers said `app_enable = false` | one physical run, stopped and preserved |
| 18 | Per-block counter zeroing failed silently; cumulative snapshots were summed | the totals were absurd (307 arms for 80 polls) | one arm's counters unusable; recovered by differencing |
| 19 | Reported concealment on one feature | asked what an eavesdropper actually gets | §12.4 — the headline result changed |
| 20 | **Wrote state before validating it, twice** — the response marker and the fail-open retire both commit at pipeline level 2 while their authorising test resolves at level 3 | an external audit read the source | §8.5; two confirmed unfixed defects, and it invalidates §10.8 |
| 21 | **Called a stale-response case PASS on an inference that could not distinguish the two responses**, and the run's own timestamps put the single bypass 200 µs from where the stale copy was scheduled | the same audit, then re-reading my own evidence file | §10.8 withdrawn |
| 22 | **Sized the fail-open horizon against D alone**, quoting 8.8× from a stale design point and omitting the relay's own ACK latency | the same audit | the true worst case was 1.49×, and the advertised 40 ms clamp is infeasible |
| 23 | **Said "480 of 480 transactions, exactly 64 tokens each"** when only 400 were defended | the same audit; my own §12.3 table already totalled 400 | an internal contradiction that survived every read |
| 24 | **Said 80 transactions "land on the same 32 µs constant"** when the sample has 18 distinct values and a 47 µs maximum | the same audit, contradicted by my own table on the same page | compression restated as compression |
| 25 | **Used "release tail" for two quantities three orders of magnitude apart** | the same audit | §7.2 now names them separately |
| 26 | **Said the compiler "accepted all four traps without complaint"** in a section whose third trap is a hard compiler error | the same audit | §8 reclassified; the unsigned comparison is a type error, not a miscompile |
| 27 | **Treated 80 transactions as 80 independent observations** when they came from 4 connections | the same audit | §12.4 now block-bootstraps by connection; the conclusion strengthened |
| 28 | **Called D = 1 ms a null control** when it produces the predicted 1 ms shift | the same audit | relabelled a sub-threshold arm; the native arm is the null |
| 29 | **The repair for defect 1 broke the mechanism**: its authorisation table used a catch-all default that set `tag_val = 0`, which for every non-RESPONSE class turned the tag write into an unconditional `TAG_INACTIVE` | Gate 2, on the first transaction, on silicon | the trigger clone wiped the generation ~700 ns after the READ armed it. The defect had already passed 2 354 offline assertions and a compile-fit check |
| 30 | **Asserted the stale injector arrives where it is configured.** It does not — 600 µs and 800 µs both realise at ~1 000 µs | the master-side capture, after the check failed 6/6 and the mechanism turned out to be right | the check was scoring harness fidelity, not switch behaviour; rewritten, and the timer defect recorded rather than absorbed |
| 31 | **Said the capture could not label which frame is the ACK.** The synthetic ethertypes are deliberate labels, not corruption | re-reading `synth_ack()` / `synth_resp()` | understated what the external evidence proves |
| 32 | **Called defect 2 "refuted" when only three *implementations* were.** All three tried to qualify the write at the producer, inside a stateful ALU that had no room; the constraint was real but the conclusion was too broad | asked what the write was actually for, and found it only had to let the next READ arm | the qualification moved to the consumer and cost nothing |

The two that generalise:

> **A test that cannot fail proves nothing.** Every checker in this directory has negative
> controls, and the state-machine model is mutation-checked four ways. Three of the bugs above
> were found *by* those controls; four were bugs *in* the checkers.

> **When a correction term and the residual it explains are the same measurement, the term is
> unfalsifiable.** The `K/rate` release bias was exactly that until instrumentation was added
> to measure the drain independently. It then agreed to 1.1 % — but it could have disagreed,
> and that is the whole point.

---


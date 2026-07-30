# Repairs for the three audit defects — all three now designed and compiled

**2026-07-30. R1 and R3 have since been validated on silicon and against the physical
relay; R2 is compile-verified, assembly-asserted and model-checked but NOT yet loaded.**

The 2026-07-30 audit confirmed three problems in `case_a_defense3_fixed_ack_delay.p4`
(see [`../AUDIT_RESPONSE.md`](../AUDIT_RESPONSE.md) and `REPORT.md` §7.5). This note
records what a repair for each actually costs, measured with `bf-p4c` 9.13.1 rather than
estimated.

The candidate lives in **`../p4/case_a_defense3_repair_candidate.p4`**, a *copy* of the
frozen program. It is a separate file, not `#ifdef`s in the original, because the archived
resource logs name tables by source line number
(`tbl_case_a_defense3_fixed_ack_delay1871`) — editing the original would break the
correspondence between the source, the archived assembly and the binary now on the switch.

## Result

| repair | what it fixes | ingress stages | critical path | verdict |
|---|---|---|---|---|
| *(none — baseline copy)* | — | 9 / 12 | 8 | reproduces the frozen artifact exactly, so the copy is faithful |
| **R1** | a RESPONSE marks the transaction before its identity is checked | **10 / 12** | **10** | **fits. Ready for a hardware gate.** |
| **R2** | fail-open retirement is not generation-qualified | **9 / 12** | **9** | **REPAIRED** by the second-register design below, after three refuted attempts. Free on top of R1+R3. |
| **R3** | a host-injected `0x88C1` frame enters the strict-priority queue | **9 / 12** | **8** | **fits at zero cost.** Identical resources to baseline. |
| R1 + R3 | both | 10 / 12 | 10 | fits |

Evidence: `../artifacts/resources_repair/`.

---

## R1 — authorise the marker before writing it

**The defect.** The class driver sets `meta.tag_val = TAG_PENDING_DELTA` on direction,
session and DNP3 framing alone. `tag_read_or_mark` then commits at pipeline level 2, while
`tbl_state_decode` resolves the sequence, acknowledgement and learned-port conjuncts at
level 3. A response with a wrong TCP sequence therefore marks a live transaction it does
not belong to.

**Why it can be repaired cheaply, and why this is not just moving the defect.** The
RESPONSE rows of `tbl_state_decode` mask `meta.tag_diff` out entirely
(`8w0x00 &&& 8w0x00`) — the RESPONSE verdict has **never** depended on `reg_tag`. It
depends only on `seq_diff`, `ack_diff` and `sport_diff`, and all three are produced by the
session trackers *before* the tag access. So the identical conjuncts can be resolved one
level earlier, in a small table, and used to choose the delta:

```
tbl_resp_authorise   key = (pkt_class, seq_diff, ack_diff, sport_diff)
                     the one entry has the same full-width masks as dec_resp
   hit  -> meta.tag_val = TAG_PENDING_DELTA     (mark)
   miss -> meta.tag_val = 0                     (pure read — the same arm a token uses)
```

`reg_tag` keeps its placement, its four RegisterActions and every other class's ordering.
The one-shot property is unchanged: it is still enforced by the MSB test inside the
stateful ALU, so a *valid* duplicate still cannot mark twice. What changes is only that an
**invalid** response now carries delta 0, making the same operation a pure read.

**Cost.** One extra table and one extra level of dependency on the RESPONSE path:
9 → 10 ingress stages, critical path 8 → 10. Stage count equals critical path, so the
program is dependency-bound at 10 — with the `D3_LIVE_FULL_TELEMETRY` registers it would be
11 / 12. That is inside budget but no longer comfortable, and it is the reason to decide
whether the telemetry build is still needed before loading this.

**Offline verification.** `analysis/test_tag_domain.py` gained two tests and now runs
**2 354 assertions, 0 failures**:

- `t_r1_unauthorised_response_is_inert` — over every live generation, both live domains and
  the idle state, an unauthorised response must leave `reg_tag` bit-identical and must not
  change what `tbl_txn_active` reports (81 assertions).
- `t_r1_defect_is_real` — the negative control. With the *shipped* 0x50 delta, every one of
  the sixteen live generations is corrupted and then reads as pending, which is exactly the
  chain that gets a legitimate response suppressed (17 assertions). If this ever stops
  failing to mark, the first test has become vacuous.

`analysis/assert_salu_asm.py` passes against the repaired build.

---

## R2 — generation-qualified fail-open: three refuted attempts, then a repair

**The three attempts below are all genuinely dead**, and they are kept because together
they pin down the exact constraint — which is what made the working design findable.
The repair follows them.

**The defect.** A dequeued blocker with `hdr.ib.seq == 0` sets
`meta.tag_val = TAG_INACTIVE`, and `tag_rmw` commits it guarded only by
`tag_val != TAG_NO_WRITE`. The generation test lives in `tbl_state_decode`, one level
later, so a token of a *foreign* generation retires whatever transaction is live. The
documented `stale > deadline > budget` priority is evaluated in the action block, after the
write — and a later table cannot undo a stateful-ALU write.

**The obvious repair does not fit, for two independent reasons.** The two operations are
the same shape — compare the stored byte against an operand and, on a hit, write a second
operand — so they *look* mergeable into one arm:

```
CLASS_ARM          tag_val = TAG_INACTIVE, tag_alt = gen_in    "if idle, arm"
budget-zero token  tag_val = gen_in,       tag_alt = INACTIVE  "if it is MINE, retire"
```

`p4/probe_failopen_qualification.p4` reduces both walls to a minimal program:

| build | result |
|---|---|
| four RegisterActions, unmerged | **compiles, 0 errors** — the control |
| `-DPROBE_THREE_OPERANDS` (merged arm) | `error: The input ingress::meta.tag_alt to stateful alu Ingress.reg_tag is not allocated in a valid region on the input xbar to be a source of an ALU operation` |
| `-DPROBE_FIFTH_ACTION` (keep them separate) | `error: Ingress.reg_tag: too many RegisterActions attached to the Register` |

So the merged arm exceeds what the stateful ALU can source from the input crossbar — it
needs three PHV bytes (`gen_in` for the returned difference, `tag_val` to compare,
`tag_alt` to write) — and keeping the arms separate exceeds the four-action limit. Both are
hard target errors, not warnings. **This is the same class of wall as `REPORT.md` §8.3's
"repair that could not be built", and it is documented the same way.**

### The third wall, which is the one that matters

Feeding the note in as a *separate byte* and as a *packed 16-bit pair* both failed, and the
second failure named the real constraint outright:

```
error: Ingress.reg_tag requires more than 2 PHV inputs
```

**`reg_tag`'s stateful ALU has a budget of TWO PHV inputs shared across all four of its
RegisterActions, and it was already full** — `meta.gen_in` and `meta.tag_val`. The source
had said so all along, in the comment at the register's own declaration. Every attempt to
add a *third* source was doomed regardless of how it was packaged.

### The repair: the note rides on an operand `reg_tag` already has

Two observations make it work.

**First, the fail-open write never released anything.** The held ACK leaves because the
budget-zero token *drops itself*, `Q_BLOCK` empties and `Q_HOLD` becomes eligible — which
the action block shows plainly (`D3_DROP()` then `CD_BLOCK_TERM_TMO`). The write to
`reg_tag` had exactly one job: let the **next** READ arm. So the *write* does not have to be
generation-qualified. The **decision** does.

**Second, on the ARM path `meta.tag_val` is dead.** `tag_arm` never referenced it,
`CLASS_ARM` never executes `tag_rmw` or `tag_read_or_mark`, and nothing downstream reads it
for that class. So it can carry the note at zero cost — and it is already one of the two
inputs the SALU is allowed.

```
producer   a budget-zero token records the generation IT carries, in reg_failopen.
           Unconditional, and harmless whoever writes it: a note naming a generation
           is not a destructive write.
consumer   the next READ arms if reg_tag is idle OR equals the noted generation:
               if (v == TAG_INACTIVE || v == meta.tag_val) { v = meta.gen_in; }
           A FOREIGN token's note names a generation that is not the live one, so it
           can never authorise anything.
```

**The qualification moved from the producer to the consumer**, which is what got it out of
the SALU's operand budget. `reg_failopen` has its own four-action budget, so nothing is
displaced; `tag_arm` gains a comparison rather than `reg_tag` gaining an operation; and the
note is cleared as it is read, so it authorises at most one arm.

**Cost: none on top of R1 and R3.** R2 alone is 9/12 stages with critical path 9; R1+R2+R3
with full telemetry is 11/12 and critical path 10 — identical to R1+R3 without it.

### Verified, and how

**The compiled assembly is asserted, not assumed.** `analysis/assert_salu_asm.py` now
requires `tag_arm_0` to contain both comparisons and a write predicated on their OR:

```
tag_arm_0:
- sub hi, phv_lo, lo                    ; rv = gen_in - v
- equ lo, lo                            ; v == 0        (compare-against-zero)
- equ hi, lo, -phv_hi                   ; v == the note
- alu_a (cmplo | cmphi), lo, phv_lo     ; write gen_in if EITHER hit
```

The assertion fires only on builds that carry R2, and it exists because a predicate that
compiles, reads plausibly and is never true is the specific failure this project has
already been bitten by twice (§7.1, §7.2).

**The state model covers it exhaustively.** `analysis/test_tag_domain.py` gained 321
assertions over all sixteen generations and all ordered foreign pairs — a note authorises
the generation that failed open, a foreign note changes nothing, and with no note the
behaviour is bit-identical to the old `tag_arm`. Total 2 675 assertions, 0 failures,
mutation-checked three ways:

| mutation | failures |
|---|---|
| drop the note comparison (arm only when idle) | 16 |
| arm unconditionally | 224 |
| make the note non-single-use | 16 |

**The residual window, stated rather than hidden.** Generations wrap every 16 polls, so a
note naming `G` could in principle authorise arming over a *live* `G` that armed later. For
that, the old token must reach budget zero (H = 30.8 ms) while a generation 16 polls newer
is live — 3.2 s at the 200 ms poll rate. Two orders of magnitude apart, and the note is
cleared by the first READ after it is written.

**Not yet run on hardware.** R2 is compile-verified, assembly-asserted and
model-checked; it has not been loaded. That is the next gate.

**How reachable is the defect in the meantime?** Fail-open exists for one scenario: a READ
armed a transaction and the acknowledgement never came, so nothing ever releases. In that
scenario the stored generation *is* the token's own, and the unqualified write is therefore
harmless — it retires exactly the transaction it should. The defect bites only when a
**foreign** token reaches budget zero while a *later* transaction is live, which requires
the deadline path to have failed first (a token that survives its own deadline), or an
externally injected token. The measured evidence is consistent with this: across 400
defended physical transactions, `BLOCK_TERM_TMO` and `BLOCK_TERM_STALE` were both 0 and
every one of the 25 600 tokens terminated on its deadline.

**Which is why R3 matters more than it looks.**

---

## R3 — close the injection path

**The defect.** The parser forces EtherType `0x88C1` to `ROLE_BLOCK` from *any* topology
port, every topology port sets `port_ok = 1`, and a fresh non-generator `ROLE_BLOCK` frame
falls to a legacy branch that calls `to_block()` — enqueuing an externally supplied frame,
with an attacker-chosen generation and budget, into the **strict-priority** queue.

**The repair is one action:** drop it and count it. A fresh `0x88C1` frame that did not come
from the packet generator can only have arrived on a host-facing port, and the in-switch
generator has made the host-injection path unnecessary for A/B rollback.

**Cost: none.** 9 ingress stages, critical path 8 — bit-identical resources to baseline.

**Why it is the highest-value item here.** R3 removes the only *practical* route to R2's
defect. With R3 applied, exercising R2 requires a blocker token to outlive its own
generation's deadline, which was never observed in 25 600 tokens. R2 still needs repairing
before the mechanism can be called correct, but R3 turns it from *reachable by an adjacent
host* into *reachable only via a second, unobserved failure*.

---

## Recommended order

1. **R3** — free, closes the injection path, no behavioural change to any tested case.
2. **R1** — fits at 10/12, verified offline over the whole state domain with a negative
   control. Costs 2 on the critical path, so decide the telemetry-build question first.
3. **R2** — repaired and verified offline; needs a hardware gate. Do not attempt a fifth
   RegisterAction, a three-operand arm or a packed operand pair; all three are refuted
   above, and the third names the real constraint (two PHV inputs, shared).

All three need a hardware gate before loading. R1 in particular changes which packets reach
the marking arm, so the rerun of the withdrawn stale-response case (`REPORT.md` §9.8) should
happen **on the repaired build** — that test and this repair are about the same defect.

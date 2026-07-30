# Repairs for the three audit defects — designed, compiled, and one of them refuted

**2026-07-30. Compile-only. Nothing here has been loaded on the switch.**

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
| **R2** | fail-open retirement is not generation-qualified | — | — | **BLOCKED by two independent target limits.** Refuted, with a probe. |
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

## R2 — generation-qualified fail-open: REFUTED

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

### What remains open, and how bad it is meanwhile

Two structural options survive, neither trivial:

1. **A second register for the fail-open request.** The budget-zero token records its
   generation in a new register and a later packet acts on it. This does *not* recreate
   §8.3's placement cycle (only one path writes it, and nothing reads it in the same pass),
   but it defers retirement to the next packet on the session, which changes the watchdog's
   timing guarantee and needs its own gate.
2. **Remove the data-plane write.** Let fail-open drop tokens and count, and retire from the
   control plane or from the next READ. Simpler, slower, and it re-opens the Gate 4C
   question the E1 repair closed.

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
3. **R2** — needs a design decision between the two structural options above. Do not
   attempt a fifth RegisterAction or a three-operand arm; both are refuted above.

All three need a hardware gate before loading. R1 in particular changes which packets reach
the marking arm, so the rerun of the withdrawn stale-response case (`REPORT.md` §9.8) should
happen **on the repaired build** — that test and this repair are about the same defect.

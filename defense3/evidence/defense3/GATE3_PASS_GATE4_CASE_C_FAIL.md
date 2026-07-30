# §13 GATE 3 — PASS · GATE 4 — CASE C FAILS

Artifact rebuilt from `c82afcd` on the switch's own bf-p4c 9.13.2. Every previously
staged binary was deleted first; source `sha256 = c1ae0fde…3442d`, identical to the
committed file. 9 ingress / 0 egress / critical path 8 / 0 errors, and the `reg_tag`
SALU reads `tag_arm_0: equ lo, lo` with no `initial_value: 255`.

| | verdict | evidence |
|---|---|---|
| **GATE 3** — 5 consecutive normal transactions | **PASS** | `evidence/gate2/gate3_20260729T233512Z/` |
| **GATE 4 case A** — RESPONSE just before the deadline | **PASS 3/3** | `evidence/gate2/gate4_20260729T233709Z/` |
| **GATE 4 case B** — RESPONSE after the ACK release | **PASS 3/3** | same |
| **GATE 4 case C** — missing RESPONSE | **FAIL 0/3** | same |
| **GATE 4 recovery** — one normal transaction after C | **FAIL** | same |

**Physical SEL-751 validation stays blocked.** The direction gates it on Gate 3 *and all
three* Gate 4 cases passing.

---

## 1. GATE 3 — five consecutive transactions, no reload, no state reset

Each transaction scored against 16 per-transaction requirements **and** the full 17-item
Gate-2 rubric. **All five: 16/16 and Gate-2 PASS.** The generation advanced 0xC0 → 0xC4
(the DNP3 application sequence), so a transaction that failed to retire could not be
mistaken for one that did — it would decode `ARM_BUSY`, and case C below shows exactly
that signature.

| txn | gen | READ ingress | reservoir standing | ACK ingress | configured deadline | first term | final term | ACK commit | RESP commit | **hold** | detect err | drain | tail | ACK→RESP |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 0xC0 | 4 084 320 246 | 1 194 | 4 084 820 255 | 4 086 820 097 | 4 086 820 120 | 4 086 821 813 | 4 086 821 841 | 4 086 821 870 | **2 001 586** | 24 | 1 693 | 28 | 29 |
| 2 | 0xC1 | 1 007 796 540 | 1 196 | 1 008 296 551 | 1 010 296 321 | 1 010 296 330 | 1 010 298 026 | 1 010 298 051 | 1 010 298 080 | **2 001 500** | 10 | 1 696 | 25 | 29 |
| 3 | 0xC2 | 2 224 202 276 | 1 195 | 2 224 702 286 | 2 226 702 081 | 2 226 702 096 | 2 226 703 790 | 2 226 703 819 | 2 226 703 844 | **2 001 533** | 16 | 1 694 | 29 | 25 |
| 4 | 0xC3 | 3 450 340 338 | 1 195 | 3 450 840 348 | 3 452 840 193 | 3 452 840 211 | 3 452 841 905 | 3 452 841 933 | 3 452 841 959 | **2 001 585** | 19 | 1 694 | 28 | 26 |
| 5 | 0xC4 | 386 217 000 | 1 194 | 386 717 009 | 388 716 801 | 388 716 821 | 388 718 516 | 388 718 541 | 388 718 570 | **2 001 532** | 21 | 1 695 | 25 | 29 |

All values in nanoseconds; the absolute instants are `ingress_mac_tstamp[31:0]`, which
wraps every ~4.295 s (visible between txn 1 and txn 2 — every interval is a signed
32-bit difference).

**Stability over five transactions:**

| quantity | min | max | spread |
|---|---|---|---|
| hold | 2 001 500 | 2 001 586 | **86 ns** |
| drain | 1 693 | 1 696 | **3 ns** |
| release tail | 25 | 29 | **4 ns** |
| reservoir standing | 1 194 | 1 196 | **2 ns** |
| READ→ACK | 500 009 | 500 011 | **2 ns** |

The 86 ns of hold spread is dominated by the **detection error** (10–24 ns) and the 256 ns
deadline tick quantization, not by the drain (3 ns) or the tail (4 ns). Corrected against
`D + K/rate`, every transaction is inside ±100 ns of a ±1 000 ns bound.

### A criterion of mine failed first, and it was wrong

The **first** Gate 3 attempt stopped at transaction 2 on my own clean-state rule, not on
the defense. That rule demanded `reg_tag == reg_ack_rel == 0` **and** `reg_deadline == 0`.
What transaction 2 actually inherited was `reg_deadline = 652 185 089` (txn 1's armed
word) and `reg_ack_rel = 0xC0` (txn 1's released-ACK generation) — and it was materially
correct on every other count: `ARM_FRESH=1`, `ACK_HOLD=1`, `RESP_HOLD_EARLY=1`, 64
admitted, retired to `0x00`.

Both of those registers are **self-clearing by construction**, which is a documented
design decision:

- `reg_deadline` — the fresh ARM writes `UNARMED_WORD` unconditionally, and
  `deadline_arm_once` only writes when the stored word *is* `UNARMED_WORD`. A stale armed
  word cannot let a duplicate ACK re-arm, and cannot survive its own transaction's READ.
- `reg_ack_rel` — the RESPONSE's early/late test is the *difference*
  `cur_gen − reg_ack_rel`, so a new generation reads non-zero with no reset.

The rule was replaced with the architecture's actual contract, which is **stricter, not
looser** — it adds a failure mode the old rule could not see at all:

1. `reg_tag == TAG_INACTIVE` — the generation retired. Required.
2. `reg_ack_rel != this generation` — otherwise the difference reads 0 at the RESPONSE and
   an **early** response is misclassified as **late**, silently inverting the one ordering
   property Defense 3 claims.
3. This transaction's ARM **superseded** any inherited deadline (new word ≠ inherited, and
   armed).

The harmlessness of a stale deadline is not asserted anywhere — it is *measured*, by the
same transaction's "exactly one ACK_HOLD, zero ACK_DUP_HOLD" and "hold ≥ D". The analyzer
self-test carries controls for all three, and for the benign case that must still pass:
17 controls, 0 bad.

## 2. GATE 4 case A — RESPONSE just before the deadline · PASS 3/3

`ipg = 1 995 000 ns`, so the RESPONSE arrives **4 872 ns before** the deadline. All three
repetitions: `RESP_HOLD_EARLY=1`, `LATE=0`, `BYPASS=0`, `BLOCK_TERM_DL=64`, ACK committed
before the RESPONSE, no fail-open, retired to `0x00`. Shrinking the margin from 1.5 ms to
under 5 µs changed nothing — which is the point of the case.

## 3. GATE 4 case B — RESPONSE after the ACK release · PASS 3/3

`ipg = 2 500 000 ns`, so the RESPONSE arrives **500 128 ns after** the deadline, i.e. after
the held ACK has committed. All three: `RESP_HOLD_EARLY=0`, **`RESP_HOLD_LATE=1`**,
`BYPASS=0`, forwarded exactly once, `ACK_DUP_HOLD=0` (no re-hold), ACK released at the
deadline within tolerance, **retired to `0x00`**.

Note what B establishes for the case-C analysis: **a late RESPONSE must find the generation
still live**, and it is what retires it. Any fix for C that retires the generation when the
reservoir drains would break B.

## 4. GATE 4 case C — missing RESPONSE · FAIL 0/3

READ and ACK only. What passes: the ACK still releases at the configured deadline, all 64
blockers terminate on the deadline (`BLOCK_TERM_DL=64`, `TMO=0`, `STALE=0`), so there is
**no indefinite blocker circulation**, and no RESPONSE is generated or forwarded.

What fails, in all three repetitions:

| rep | gen | `reg_tag` before | `reg_tag` after |
|---|---|---|---|
| 1 | 0xC8 | 0x00 | **0xC8** |
| 2 | 0xC9 | 0xC8 | **0xC9** |
| 3 | 0xCA | 0xC9 | **0xCA** |

**The generation is never retired.** No watchdog or bounded cleanup exists on the data
path for this case, and the mechanism is exact: there are only two retire paths, and this
case fires neither.

```
retire path 1   the RELEASED RESPONSE   (dequeued ROLE_RESP -> tag_val = TAG_INACTIVE)
                -> never fires: there is no RESPONSE
retire path 2   the FAIL-OPEN BUDGET    (budget_zero -> tag_val = TAG_INACTIVE)
                -> never fires: the blockers terminate on the DEADLINE first
                   (BLOCK_TERM_DL = 64, BLOCK_TERM_TMO = 0)
```

The deadline **pre-empts** the only bounded cleanup the program has. With no ACK at all the
budget path *would* fire and bound the state at `H = B·K/rate = 30.8 ms`; it is precisely
the ACK-arrives-but-RESPONSE-does-not case that has no bound.

## 5. The cost, measured rather than argued

The direction asks for one normal transaction after case C to prove recovery. It **fails** —
and a second one was added to measure the actual cost, because "recovery fails" and
"recovery takes two transactions" are very different findings.

| | generation | inherited `reg_tag` | result |
|---|---|---|---|
| **recovery 1** | 0xCF | 0xCA | **FAIL** — `ARM_BUSY=1`, **zero blockers admitted**, `ACK_DUP_HOLD=1`, no hold. Completely unprotected. Its own late RESPONSE then wrote `reg_tag = 0x00`. |
| **recovery 2** | 0xC0 | 0x00 | **PASS** — 16/16 and Gate-2 PASS. Protection has resumed. |

So the blast radius is bounded and exactly one transaction wide:

> **A lost RESPONSE costs exactly ONE subsequent unprotected transaction, after which the
> defense self-heals.** The stuck generation is cleared by the next transaction's own
> RESPONSE, arriving on the dequeued `ROLE_RESP` path — but that transaction escapes as
> `ARM_BUSY` with no reservoir and no hold, so its ACK is forwarded with its native CLRT
> intact.

That is materially smaller than "permanently disabled", and materially worse than the
direction's requirement, which is why both sentences are here.

## 6. Smallest fixes, priced but NOT implemented

No architecture change has been made. The direction authorizes none, and physical
validation is blocked until case C passes, so this is a decision to be taken rather than
assumed.

**Option 1 — retire a STALE generation on the next READ.** Add one decode entry: a
`CLASS_ARM` whose `tag_diff` says "busy" **and** whose stored deadline has already expired
arms fresh instead of escaping. The expiry bit is already computed (`tbl_deadline_expiry`)
and already read by the blocker path, so the cost is one const entry in an existing table
and no new state. It reduces the cost from one unprotected transaction to **zero**, and it
does not touch case B (a late RESPONSE still finds its own generation live, because that
generation's own deadline expiry only matters to the *next* READ). It does change the
§7 `CONCURRENT_TRANSACTION_ESCAPE` semantics: a concurrent READ whose predecessor has
expired now takes over rather than escaping — which is arguably the correct behaviour, but
it is a semantic change and needs sign-off.

**Option 2 — a bounded grace after the deadline.** Let the blockers, on deadline
termination, run a short second phase and retire the generation at the end of it if no
RESPONSE has been seen. Bounds the stuck state in time rather than in transactions, but it
changes the blocker lifecycle — the most invasive of the three and the only one that
touches the drain, which every timing number in this report depends on.

**Option 3 — accept and document.** One unprotected transaction per lost RESPONSE, stated
as a limitation. Defensible only if lost RESPONSEs are rare on the real link; the physical
campaign would measure that. It does not satisfy the direction's case-C requirement.

**Recommendation: Option 1.** Smallest diff, no new state, no effect on the measured
timing, and it turns a bounded-but-real gap into no gap. It needs an explicit decision
because it redefines what a concurrent READ does.

## 7. The SALU finding, stated as the direction requires

> **A large-constant SALU comparison was behaviourally incorrect on silicon in this
> construction.** The exact immediate-width cause is **not** claimed to have been formally
> proven from the BFA.

The evidence is behavioural: with `TAG_INACTIVE = 0xFF` the conditional state write never
committed (`reg_tag` stayed `0xFF`, 64 tokens dropped, ACK rejected) while the SALU's
return value worked; with `TAG_INACTIVE = 0x00` it commits (64/64 admitted). The `.bfa`
showed `equ lo, lo, -255` in the broken build and `equ lo, lo` in the working one — but a
probe over 13 constants (`p4/probe_salu_immediate.p4`) shows bf-p4c emits `equ lo, lo, -K`
for **every** K, identically and without warning, so the BFA cannot distinguish a safe
constant from an unsafe one and no width conclusion follows from it. The durable rule is
structural and enforced by `analysis/test_tag_domain.py`: **never compare SALU state
against a large constant — compare against zero or a PHV field.**

## 8. Restoration

All five facts verified after the tests: `p4_name = dnp3_timing_normalizer_pktgen`,
`strict_priority_verified = true`, `app_enable = false`, exactly one `bf_switchd`,
dp8 shaping restored.

# F02 + F01-b ROOT CAUSE — an out-of-range SALU immediate silently killed the arm write

Found by reading the compiled `.bfa`. **One fault, both symptoms.** Fixed; the hold now runs.

## The compiled instruction

```
tag_arm_0:
- sub hi, phv_lo, lo        ; rv = gen_in - v            <- RETURN path: correct
- equ lo, lo, -255          ; predicate: v == 0xFF ???   <- BROKEN
- alu_a cmplo, lo, phv_lo   ; conditional write of gen_in
- output alu_hi             ; returns rv                 <- correct
```

`TAG_INACTIVE = 0xFF` (255) **does not fit the stateful ALU's signed immediate field**, so the
compare emitted `-255` — a predicate that can never be true for `v = 0xFF`. The **return** path was
unaffected.

## Why this fooled the diagnosis twice

`ARM_FRESH` is driven by `tag_diff`, the SALU's *return* value, which is computed regardless of
whether the predicated write commits. So the counter said the arm fired while the register said it
never happened. That single asymmetry produced two wrong theories before this one:

1. "the arm write did not land" — right symptom, no mechanism, and abandoned for the wrong reason;
2. "the template carries no DNP3 so `gen_in` is invalid" — refuted by the installed `role_map`
   (`gen: 192`) and by `.p4:192-197`, which says the generation is control-plane action data.

`tag_rmw` was **immune** because its predicate compares against a **PHV** value
(`neq lo, phv_hi`), not an out-of-range constant. That is why only the arm path failed.

## The causal chain, now closed

`reg_tag` stays `0xFF` → every blocker token reads `cur_gen = 0xFF` → `tbl_txn_active` does not
match `0xC0 &&& 0xF0` → **`PKTGEN_DROP = 64`** — and simultaneously no live generation →
the ACK's generation conjunct fails → **`ACK_REJECT = 1`**. F02 and F01-b were never independent.

## The decisive isolation

A READ-only run (`--n-events 1`) — nothing that could retire anything — still gave `ARM_FRESH = 1`
with `reg_tag = 255`. That killed the RESP_BYPASS-retirement explanation and forced the `.bfa` read.
Earlier probes at `D=20 ms / ipg=5 ms` also showed the drop persisting across a 10 ms live window,
proving it was never a timing race.

## Fix (PI decision)

**`TAG_INACTIVE: 0xFF → 0x00`**, and `reg_tag`'s init with it. Recompiled: the predicate is now
`equ lo, lo` — compare against zero, no immediate — still 9 ingress / 0 egress / 0 errors.

The three decode sets stay disjoint: fresh → `rv = gen_in − 0 = 0xCn` (matches `0xC0 &&& 0xF0`);
duplicate → `0x00`; concurrent → small non-zero. `0x00` is also the register's natural init, so the
reset path simplifies. The control plane's `TAG_INACTIVE` and its clean-start assertion were moved
in step.

## Result on silicon — the hold RUNS

| quantity | before | after |
|---|---|---|
| `blockers_admitted` | 0 | **64** |
| `blockers_terminated` | 0 | **64** |
| G-02 one K=64 burst | FAIL | **PASS** |
| G-03 ACK admitted to Q_HOLD | FAIL | **PASS** |
| G-06 no RESPONSE before the ACK | FAIL | **PASS** |
| G-07 ACK released FIRST | FAIL | **PASS** |
| G-08 RESPONSE released SECOND | FAIL | **PASS** |
| G-09 all blockers terminate | FAIL | **PASS** |

First execution of Defense 3's hold, with the ordering invariant holding on hardware.

## Remaining — F03, a HARNESS schedule fault, not a mechanism fault

`reservoir_standing_ns = 1000012` ≈ the 1 ms one-shot `timer_ns`, against the R2 bound of 100 µs.
The reservoir stands ~1 ms after the READ, so the ACK is admitted before `Q_BLOCK` is occupied and
leaves in `hold_ns = 480`, which also trips `ACK_RELEASE_FAILOPEN` and the corrected-deadline check.

Cause: the READ/ACK/RESPONSE come from one 3-packet batch spaced by `ipg`, while the blocker burst
is triggered *by* the READ and inherits the generator's own start latency. The fix is the event
schedule — give the reservoir its standing window before the ACK event — **not** the P4.

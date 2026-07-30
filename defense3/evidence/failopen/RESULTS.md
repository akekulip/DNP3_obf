# The fail-open path, exercised — and R2 validated on silicon

**2026-07-30. `case_a_defense3_repair_candidate`, synthetic build with R1 + R2 + R3,
11/12 ingress stages, critical path 10.** Switch restored and verified afterwards.

## First, a correction

I said fail-open "has fired 0 times in every campaign, so the path has never executed on
silicon." **That was wrong.** It is true of the gates and both D-sweep campaigns, where the
deadline always beat the budget — but `--check2` is READ-only by construction, so no ACK
ever arrives, no deadline is ever armed, and the tokens can only terminate on the budget.
The existing unrepaired evidence shows the fail-open path executing in every one of its
trials. What nobody had done is *read what it recorded*.

## The defect's fingerprint was already in the evidence

`evidence/gate2/check2_20260729T225751Z`, unrepaired build, 60 recorded trials:

| counter | value | in how many trials |
|---|---|---|
| `BLOCK_TERM_TMO` | **1** | 60 / 60 |
| `BLOCK_TERM_STALE` | **63** | 60 / 60 |
| `BLOCK_LOOP` | ~1 152 000 | 60 / 60 |
| `reg_tag` afterwards | **0** (cleared) | every trial |

**One token terminates on the budget and the other sixty-three are credited as stale.**
That 1/63 split *is* the defect, sitting in evidence that had been collected, scored and
filed. The first token to reach budget zero writes `TAG_INACTIVE` into `reg_tag` with no
generation test; the remaining 63 then compute `gen_in − stored = gen − 0 ≠ 0`, read as a
foreign generation, and are dropped as stale. Both outcomes are "token terminated", so
nothing looked wrong.

## R2's prediction, and the result

If the fail-open write becomes a *note* in a second register instead of a destructive write
to `reg_tag`, then nothing invalidates the other tokens and **all 64 should reach budget
zero**. Two arms were run, 28 recorded trials each:

| | unrepaired (existing) | **R2, B = 18 000** | **R2, B = 500** |
|---|---|---|---|
| `BLOCK_TERM_TMO` | 1 | **64** | **64** |
| `BLOCK_TERM_STALE` | 63 | **0** | **0** |
| `BLOCK_LOOP` | 1 152 000 | 1 152 000 | **32 000** |
| `reg_tag` afterwards | 0 (cleared) | **0xC0 (preserved)** | **0xC0 (preserved)** |
| `ARM_FRESH` next trial | 1 | **1** | **1** |
| `PKTGEN_ADMIT` next trial | 64 | **64** | **64** |
| verdict | — | COMPLETE, 0 fail | COMPLETE, 0 fail |

Every prediction holds, in 28/28 trials on both arms.

**The recovery property is preserved, which is the part that had to be checked.** R2 stops
clearing `reg_tag`, so the obvious risk is that the next transaction can no longer arm.
`ARM_FRESH = 1` and `PKTGEN_ADMIT = 64` in every trial say otherwise: the next READ arms
through the note, and its reservoir is admitted in full. `ARM_BUSY = 0` throughout.

**The budget arithmetic is confirmed exactly, not approximately.** `BLOCK_LOOP` is
`K × B` on the nose: 64 × 500 = **32 000** at the shrunk budget, and 64 × 18 000 =
**1 152 000** at the standard one. Each token consumes exactly `B` passes before giving up,
which is the model `H = B·K/rate` rests on.

## A guard that refused the shrunk budget, and why it was scoped rather than weakened

The first attempt at the shrunk arm was **refused by the control plane**:

```
[FAIL] fail-open horizon exceeds the worst-case hold
       H=0.856 ms <= a_worst+D=24.000 ms: the budget would fire DURING a legitimate hold
       and the trial would measure B, not D.
```

The guard is correct in general — a budget that expires mid-hold silently converts a
D-governed delay into a B-governed one, which is the failure mode §6.3 exists to prevent.
But it is the wrong test for *this* trial: `--check2` sends a READ and nothing else, so no
ACK arrives, no deadline is armed, and **there is no hold to cut short**. The budget is the
only thing that can terminate the reservoir, which is the entire point of the trial.

So the check is now scoped by an explicit `--read-only-trial`, which `--check2` sets for
itself, and the requirement becomes the one that actually applies. The general case is
untouched: any trial that holds still has to satisfy `H > a_worst + D`.

This is worth recording as a pattern rather than a footnote: **a safety check that fires on
the one scenario a mechanism exists for is usually mis-scoped, not too strict** — and the
fix is to narrow its precondition, never to remove it.

## What this establishes, and what it does not

**Established.** R2 behaves on silicon exactly as designed: the fail-open note replaces the
unqualified write, all 64 tokens now terminate on the budget instead of 63 being invalidated
by the first, `reg_tag` survives, and the next transaction still arms. Confirmed at two
budgets three orders of magnitude apart in horizon (0.856 ms and 30.802 ms), 28 trials each.

**Not established.** These trials are all *single-generation*: the token that reaches budget
zero always carries the generation that is live. So they exercise the note-and-recover path,
**not** the case the defect was actually dangerous in — a *foreign* token reaching budget
zero while a later transaction is live. That case is covered exhaustively in the offline
model (321 assertions over all ordered foreign pairs, mutation-checked) but has not been
produced on hardware, and producing it needs a token to outlive its own generation, which
the current harness cannot arrange.

**R2 has still not been run on the live build against the relay.**

## Files

| file | what |
|---|---|
| `20260730T202339Z/` | both arms of the first run; `evidence_standard/` carries the B = 18 000 trials |
| `20260730T202339Z/check2_shrunk.log` | the refusal, kept as the record of the mis-scoped guard |
| `shrunk_20260730T202747Z/` | the B = 500 arm after the guard was scoped |
| `*/post_state.txt` | the switch conf after restore |

Reproduce: load the synthetic R1+R2+R3 build, then
`C2_TRIALS=20 BUDGET=500 C2_WAIT_S=0.05 PROG=case_a_defense3_repair_candidate
run/run_defense3.sh --check2`.

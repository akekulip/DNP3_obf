# F01-a diagnosis — progress, and the next concrete step

The resolution agent was **terminated mid-run by a server-side API error**, not by a technical
dead end. Its findings are preserved here. **Switch restored to Defense 2 and verified on all five
facts.**

## What it established

### ★ The chip has TWO pipes, not four — read from the device, not assumed

```
tf1.dev.device_configuration : num_pipes = 2, sku = BFN-T10-032D, num_stages = 12
pipe probe                   : pipe 0 ok, pipe 1 ok, pipe 2 INVALID_ARGUMENT, pipe 3 INVALID_ARGUMENT
```

Every conf in this project — Defense 2's included — declares `pipe_scope: [0,1,2,3]`. That is
tolerated (it is a P4 pipeline scope, not a probe), but **any control-plane loop that iterates
pipes 0–3 will error on 2 and 3**, and the microbench's per-pipe pktgen readback did exactly that.
This is a live-fact correction worth carrying into every future setup script.

### The blocker-admission check still failed, with a different error than Gate 2

```
FAIL  F01-a FIX: blockers ADMITTED   got "err: INVALID_ARGUMENT, 'Entry not found'", want 64
```

Note this is an `entry_get` **error**, not `got 0` — so at that point the harness was failing to
*read* the counter, which is a different fault from Gate 2's clean `trigger_counter=0`. The
per-pipe iteration above is the likely cause of the read error.

### The lead it was following when it died

> *"Let me inspect the compiled SALU for `reg_tag` — the arm write did not land."*

That is the right thread and it is **not yet resolved**. It matters because Gate 2 reported
`ARM_FRESH=1` (the arm *path* ran) while `reg_tag` readback was `255` = `TAG_INACTIVE` — i.e. the
counter says the branch executed but the register says no generation was ever installed. If the
arm write genuinely does not land, then:

- no generation is active, so the ACK predicate's `generation active` conjunct fails → **explains
  F01-b's `ACK_REJECT=1`**;
- the pktgen trigger clone is gated on `tag_diff != 0` in the inherited design, so a failed arm
  write → **no clone → no trigger → explains F01-a's `trigger_counter=0`**.

**One fault would explain both F01-a and F01-b.** That is the hypothesis to test first, and it is
cheaper than either of the two constructions (C1 direct-pattern-trigger, C2 timer-armed reservoir)
that were queued as fixes — both of those presuppose the arm succeeded.

## Next concrete step

1. Read the compiled `reg_tag` SALU and its driver table in `build_synth_9.13.1/pipe/*.bfa` and
   confirm whether the arm write is placed and reachable on the synthetic READ path.
2. Microbench: one synthetic READ, then read `reg_tag`. Expect a generation in `0xC0..0xCF`;
   `255` means the arm write did not land.
3. Fix the arm path, then re-test whether the trigger fires **before** choosing between C1 and C2 —
   if the arm was the fault, neither construction is needed.
4. Fix the per-pipe iteration to use `num_pipes` from `tf1.dev.device_configuration` rather than a
   hardcoded 0–3.
5. F01-c (event app fired twice) remains open and is independent.

## Artifacts

`evidence/defense3/f01_resolution/` (snapshots, load logs),
`evidence/gate2/microbench_2026072919{3741,4516}Z/` (two microbench runs),
`evidence/gate2/switch_state_snapshot_*.json`, `restore_*.log`.

Modified but uncommitted at the time of the failure: `analysis/analyze_defense3.py`,
`run/poll_defense3.py`, `run/run_defense3.sh`.

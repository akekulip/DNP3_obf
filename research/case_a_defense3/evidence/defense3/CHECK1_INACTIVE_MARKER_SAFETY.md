# CHECK 1 — INACTIVE MARKER SAFETY

Required by `meeting_direction.md` (2026-07-29) before another Gate 2 transaction.
**Status: COMPLETE. It found a live bug that the repair itself had introduced, plus a
second one that made a Gate 2 requirement unsatisfiable.** Neither had run yet.

Reproduce: `python3 analysis/test_tag_domain.py` → **790 assertions, 0 failures.**

---

## 1. What the audit found

| # | Finding | Severity | State |
|---|---|---|---|
| **C1-1** | `TAG_NO_WRITE = 0` **collided** with the new `TAG_INACTIVE = 0`. Both transaction-retire paths write `TAG_INACTIVE` through `tag_rmw`, whose write predicate is `tag_val != TAG_NO_WRITE` — so **both retires became silent no-ops**. | **critical, introduced by the F02 repair** | FIXED: `TAG_NO_WRITE = 0x01` |
| **C1-2** | The trigger clone was charged to `CF_BAD_PORT`, so `BAD_PORT` read **1 on every armed transaction** — making G-10's "no off-topology packets" clause **unsatisfiable whenever the defense worked**, and a real off-topology packet indistinguishable from correct operation. | **high** | FIXED: `CF_CLONE_SEEN` + `ROLE_CLONE` |
| **C1-3** | The analyzer's G-10 hard-coded `reg_tag == 0xFF`. After the repair a retired transaction leaves `0x00`, so **G-10 could never pass again**. | **high** | FIXED, plus `TAG_INACTIVE` is now a named constant in the analyzer |
| **C1-4** | A `tag_diff == 0xD0 → dec_arm_fresh` decode entry, left from the 0xFF era. Under 0x00 it is unreachable in normal operation, and the only way to reach it is `reg_tag` out of domain — in which case `v == 0` is false and **it would declare ARM_FRESH on a generation that never committed: the F02 signature, reproducible silently**. | medium | REMOVED |
| **C1-5** | Three stale comments asserting the tag domain is `{0xC0..0xCF, 0xFF}` and that `0x00` is "the SALU no-write sentinel". | low | corrected |

**C1-1 is the one that matters.** Had Gate 2 been re-run without this audit, the ACK
hold would have looked right while `reg_tag` kept a live generation for ever: G-10
would have failed, and — worse — the next transaction would have decoded `ARM_BUSY`
instead of `ARM_FRESH`, so a *second* poll would never arm. Chasing that from the
symptom would have looked exactly like a new, unrelated fault.

## 2. Proof that no active transaction generation can equal zero

**Live build.** `meta.gen_in = hdr.dnp3_app.app_control` is assigned in
`parse_dnp3_app`, and the select immediately after admits `ROLE_ARM` only under
`(app_control & 0xF0) == 0xC0`. `ROLE_ARM` is the **only** role that reaches
`tag_arm`, the only RegisterAction that writes a generation. Therefore every
generation that can be written lies in `0xC0..0xCF`.

**There is no generation arithmetic anywhere in the data plane.** Nothing increments
and nothing can wrap: the 4-bit DNP3 application sequence advances inside the **low**
nibble (`0xCF → 0xC0`) while the mask pins the high nibble to `0xC`. So the direction's
conditional — "if generation arithmetic can wrap to zero, reserve zero explicitly" —
**does not arise**: there is no arithmetic to guard. Reserving zero would be dead code,
and the invariant is instead enforced where it is actually decided, in the parser gate.

`gen_in` is also assigned on the two non-ARM branches (unsupported response, default
accept) where it may be any byte; neither reaches `tag_arm`.

**Synthetic build.** The generation is control-plane action data (`synth_read(gen)`),
which the P4 cannot check. Range-checked in the control plane instead, with the
zero test asserted **separately** from the `0xC0..0xCF` test so a future change to
either constant cannot quietly remove the guarantee.

Tested exhaustively over all 16 generations and both markers (`t_no_generation_is_zero`,
`t_initialization`, `t_normal_increment`, `t_wrap`, `t_blocker_generation`).

## 3. Initialization / increment / wrap tests

`analysis/test_tag_domain.py` models the three `reg_tag` RegisterActions and the
`const entries` of `tbl_state_decode` / `tbl_txn_active` **byte for byte**, and reads
the constants **out of the P4** rather than restating them — a test that restates them
cannot catch the drift it exists to catch.

| group | assertions | what it establishes |
|---|---|---|
| initialization | 34 | `reg_tag`'s declared init **is** `TAG_INACTIVE`; every one of the 16 generations arms from it and decodes ARM_FRESH |
| normal increment | 60 | arm → duplicate-READ-is-DUP → retire → next generation arms, across the whole cycle |
| wrap `0xCF → 0xC0` | 20 | the wrap is indistinguishable from any other increment; idle+generation can never yield `tag_diff == 0` (which would read as DUP and never arm) |
| concurrent | 480 | every ordered pair of distinct generations decodes ARM_BUSY and does **not** overwrite live state |
| decode disjointness | 20 | the three ARM sets partition every reachable `tag_diff`; `0xD0` is unreachable; **ARM_FRESH implies the write committed** — the direct F02 guard |
| pure-ACK liveness | 35 | idle reads "no live transaction", every generation reads live, a **stale `0xFF` still reads rejected**, and an ACK never moves the tag |
| SALU constants | 16 | no RegisterAction predicate compares against a constant above the proven-safe 2 |
| mirrors | 8 | the Python mirrors in setup and analysis agree with the P4 |

**The tests were mutation-checked** — a test that cannot fail proves nothing:

| mutation | result |
|---|---|
| revert `TAG_INACTIVE`/init to `0xFF` (**the exact F02 state**) | **8 failures** in 5 independent groups, including "ARM_FRESH implies committed" |
| re-collide `TAG_NO_WRITE` back to `0x00` (**the C1-1 state**) | **50 failures** in 4 groups |

So both bugs in this report would have been caught **before** any switch load.

## 4. SALU constant audit — and a correction to the F02 mechanism

Every SALU comparison in the **loaded** build, read out of the switch's own
`/home/decps/d3/build_synth_9.13.2/pipe/*.bfa`:

| RegisterAction | P4 predicate | compiled | constant |
|---|---|---|---|
| `tag_arm` | `v == TAG_INACTIVE` | `equ lo, lo` | **0** |
| `tag_rmw` | `tag_val != TAG_NO_WRITE` | `neq lo, phv_hi, -1` | 1 |
| `tag_read` | none | `output mem_lo` | — |
| `ack_rel_rmw` | `tag_val != TAG_NO_WRITE` | `neq lo, phv_hi, -1` | 1 |
| `deadline_arm_once` | `v == UNARMED_WORD` | `equ lo, lo, -2` | **2** |
| `deadline_rmw` | `dl_val != DL_NO_WRITE` | `neq lo, phv_lo` | 0 |
| `exp_seq_rmw`, `sess_port_rmw` | `!= 0` | `neq lo, phv_hi` | 0 |
| 7 × `ts_*_w` | `v == 0` | `equ lo, lo` | 0 |
| `exp_ack_w/r`, `ts_last_block_w` | none | — | — |

**Nothing anywhere compares against a constant in `0x80..0xFF`.** The largest
constant in the program is 2, in `deadline_arm_once`, and that one is *proven working
on silicon* — the deadline arms at `t_ACK + D` and reads back correctly.

The lowering convention, established from this assembly:

```
equ lo, lo          <=>  v == 0                  (no immediate)
equ lo, lo, -K      <=>  v == K                  (the immediate holds MINUS K)
neq lo, phv_hi      <=>  <that PHV field> != 0   (no immediate)
neq lo, phv_hi, -1  <=>  <that PHV field> != 1
```

### ⚠ CORRECTION — the mechanism, not the fix

The accepted root-cause wording says 255 "did not fit the SALU signed immediate". The
**repair is confirmed on silicon** (`reg_tag` 0xFF→0xC0, admitted 0→64) and the `.bfa`
evidence (`equ lo, lo, -255`) is real. But the direction also asked to audit *other*
constants in `0x80..0xFF`, and doing that produced a result I have to report against
myself:

`p4/probe_salu_immediate.p4` compares 13 registers against
K ∈ {1, 2, 7, 8, 15, 16, 63, 64, 127, 128, 192, 254, 255}. **bf-p4c emits
`equ lo, lo, -K` for every one of them — identically, with no error and no warning.**
`-2` and `-255` are printed by the same code path.

So the `.bfa` **cannot** distinguish a safe constant from an unsafe one, and the
"field is too narrow" step is an **inference** consistent with all the evidence, not
something this audit proved. (The mechanism that fits is truncation of the immediate
followed by sign-extension into a wider compare datapath, which turns `v == 255` into
`v == 0xFFFFFFFF` for a zero-extended 8-bit register — but the encoding happens below
the `.bfa`, in the assembler, and I have not decoded the binary.)

**This changes the audit rule, which is the point of reporting it.** The direction asked
to "inspect compiler assembly and preserve any suspicious signed-immediate lowering"
— but *no* lowering looks suspicious; they all look the same. The only durable rule is
therefore structural, and it is now enforced by a test rather than by inspection:

> **Never compare SALU state against a large constant. Compare against zero, or
> against a PHV field.** Where a constant is unavoidable, keep it small and prove it
> on silicon. `t_no_large_constant_compares` fails the build for any RegisterAction
> predicate above the proven-safe value of 2, and fails — rather than skips — on any
> named constant it cannot resolve.

Deliberately **not** done: finding the exact K boundary on silicon. It would cost a
switch load to measure a number the rule above says never to rely on.

## 5. Compile result after every CHECK 1 change

| build | stages | egress | critical path | errors |
|---|---|---|---|---|
| synthetic (`-DD3_SYNTH_EVENTS`) | **9 / 12 ingress** | 0 | 8 | 0 |
| live (no flag) | **9 / 12 ingress** | 0 | 8 | 0 |

Unchanged from before the repair — the new `ROLE_CLONE` arm, the `CF_CLONE_SEEN`
slot, the `parse_clone` state and the two CHECK 2 registers cost **zero stages**
(`reg_ts_last_block` shares `ev_first_block`'s guard and therefore its stage;
`ts_clone_w`'s predicate is parser-derived and floats, like `ts_ack_release_w`).

## 6. Files

- `p4/case_a_defense3_fixed_ack_delay.p4` — `TAG_NO_WRITE` 0→1; `ROLE_CLONE`,
  `CLONE_TAG_BYTE`, `CF_CLONE_SEEN`, `parse_clone`, the clone ACT arm; the `0xD0`
  decode entry removed; `reg_ts_clone` + `reg_ts_last_block`; comments corrected.
- `setup/case_a_defense3_fixed_ack_delay_setup.py` — mirrors `TAG_NO_WRITE`.
- `run/poll_defense3.py` — the three CHECK 1 assertions (generation in range,
  generation ≠ marker, sentinels distinct); `CLONE_SEEN`; the two new registers.
- `analysis/analyze_defense3.py` — `TAG_INACTIVE` constant; G-10 repaired; a new
  negative control for a genuinely off-topology packet. Self-test: 17 controls, 0 bad.
- `analysis/test_tag_domain.py` — new; 790 assertions; mutation-checked.
- `p4/probe_salu_immediate.p4` — new; compile-only, never loaded.

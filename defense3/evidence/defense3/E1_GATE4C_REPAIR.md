# E1 — the Gate 4C repair: conditional retirement on ACK release

Base `5e33ab2`. **All targeted suites and the full regression PASS.** Defense 3 with E1 is
**still loaded** on the switch.

| | verdict |
|---|---|
| Gate 3 — five consecutive normal transactions | **PASS 5/5**, 17/17 requirements each |
| Gate 4A — RESPONSE just before the deadline | **PASS 3/3** |
| Gate 4B — RESPONSE after the ACK release | **PASS 3/3** |
| **Gate 4C — missing RESPONSE** | **PASS 3/3** |
| **Immediate recovery, after every 4C repetition** | **PASS 3/3, the FIRST one every time** |
| Suite 6 — duplicate early RESPONSE | **PASS 3/3** |
| Suite 7 — stale RESPONSE | **PASS 3/3** |

---

## 1. reg_tag domains

```
0x00                 INACTIVE
0xC0 .. 0xCF         LIVE, no early RESPONSE pending      (MSB SET   -> signed < 0)
0x10 .. 0x1F         LIVE, early RESPONSE pending         (MSB CLEAR, never 0x00)
```

Transition `reg_tag += 0x50` maps `0xCn -> 0x1n`. **One-shot by construction**, not by a
flag: the add is predicated on the MSB, and applying it clears the MSB, so a duplicate,
retransmitted or stale RESPONSE cannot apply it again. The marker is generation-bound —
`0x1n` still carries `n` — so it cannot leak across generations, and the difference a
blocker sees is the constant `0xB0` for *every* generation.

## 2. Final state-transition table

| event | pre `reg_tag` | action | post | disposition |
|---|---|---|---|---|
| READ, idle | `0x00` | `tag_arm` writes the generation | `0xCn` | ARM_FRESH |
| READ, live | `0xCn`/`0x1n` | no write (predicate false) | unchanged | ARM_BUSY |
| blocker token, fresh | `0xCn` | `tag_read_or_mark` delta **0** → no-op | unchanged | admitted |
| blocker, dequeued, `tag_diff` `0x00` | `0xCn` | read-only | unchanged | live, recirculates |
| blocker, dequeued, `tag_diff` `0xB0` | `0x1n` | read-only | unchanged | **live**, recirculates |
| blocker, foreign generation | any | read-only | unchanged | STALE, terminates |
| **1st early RESPONSE** | `0xCn` | `+0x50` | **`0x1n`** | held in Q_HOLD, `RESP_HOLD_EARLY` |
| **duplicate RESPONSE** | `0x1n` | predicate false → no 2nd mark | `0x1n` | `RESP_BYPASS`, forwarded once |
| **ACK release, pending** | `0x1n` | no retire | `0x1n` | `CD_ACK_RELEASE`, forwarded |
| **ACK release, none pending** | `0xCn` | **retire** | **`0x00`** | `CD_ACK_REL_RETIRE`, forwarded |
| queued RESPONSE release | `0x1n` | `tag_rmw` → `TAG_INACTIVE` | `0x00` | forwarded, **retires** |
| late RESPONSE | `0x00` | none | `0x00` | `RESP_BYPASS`, forwarded once, never held |
| stale RESPONSE, idle | `0x00` | none | `0x00` | `RESP_BYPASS`, nothing altered |
| fail-open blocker | `0xCn` | `tag_rmw` → `TAG_INACTIVE` | `0x00` | unchanged from before |

## 3. Generated SALU instructions

Identical on **both** SDEs (9.13.1 local, 9.13.2 on the switch) — no drift:

```
tag_read_or_mark_0:                      tag_retire_if_unmarked_0:
- lss.s lo, lo                           - lss.s lo, lo
- add cmplo, lo, lo, phv_hi              - alu_a cmplo, lo, 0
- output mem_lo                          - output mem_lo

tag_arm_0:                               tag_rmw_0:
- sub hi, phv_lo, lo                     - sub hi, phv_lo, lo
- equ lo, lo                             - neq lo, phv_hi, -1
- alu_a cmplo, lo, phv_lo                - alu_a cmplo, lo, phv_hi
- output alu_hi                          - output alu_hi
```

`lss.s` — signed, compared against zero, no immediate. `add cmplo, lo, lo, phv_hi` is the
predicated marker add. `alu_a cmplo, lo, 0` is the predicated inactive write.

### The automated assembly assertion — `analysis/assert_salu_asm.py`

Required by the direction and **mutation-checked**: reverting the cast to `if (v < 8w0)`
makes **bf-p4c exit 0** while the assertion exits 1 and prints

```
FAIL  tag_retire_if_unmarked_0   CONTAINS FORBIDDEN /\blss\.u\b/
      emitted: lss.u lo, lo ; alu_a cmplo, lo, 0 ; output mem_lo
```

So a compile that emits unsigned less-than-zero fails validation even though the compiler
reports success. It also asserts the marker add and the `0xB0` blocker-live entry survive
into the assembly.

## 4. Compiler resource reports

| | ingress | egress | critical path | errors |
|---|---|---|---|---|
| BF-SDE 9.13.1, synthetic | **9 / 12** | 0 | **8** | 0 |
| BF-SDE 9.13.1, live | **9 / 12** | 0 | **8** | 0 |
| BF-SDE 9.13.2, synthetic (loaded) | **9 / 12** | 0 | **8** | 0 |

**E1 is stage-neutral and critical-path-neutral.** Deltas: **no new persistent register**
(reg_tag absorbed the phase; `tag_read` was folded into the marker because the target
allows only **4** RegisterActions per Register — five is a hard error); **+1 RegisterAction**
net on reg_tag; **+1** `tbl_state_decode` entry (`tag_diff 0xB0`); **+2**
`tbl_txn_active` entries and one action; **+1** `ctr_deq` slot; **no** new deadline, **no**
blocker-lifecycle change.

★ An intermediate version cost 10 ingress / critical path 9. The cause was a
**write-after-write on `meta.tag_val`** in one class-driver arm; collapsing it to a single
write recovered both the stage and the critical path.

## 5. Targeted validation traces

All nanoseconds. `ACK_REL` = `CD_ACK_RELEASE` (pending, no retire); `RETIRE` =
`CD_ACK_REL_RETIRE` (nothing pending, the ACK retired).

### Suite 1 + 2 — missing RESPONSE, each with immediate recovery

| | gen | pre tag | post tag | EARLY | BYPASS | ACK_REL | RETIRE | DL | STALE | TMO | hold | drain | tail |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| C rep 1 | 0xCA | 0x00 | **0x00** | 0 | 0 | 0 | **1** | 64 | 0 | 0 | 2 001 533 | 1 694 | 26 |
| **recovery 1** | 0xCB | 0x00 | 0x00 | 1 | 0 | 1 | 0 | 64 | 0 | 0 | 2 001 423 | 1 693 | 27 |
| C rep 2 | 0xCC | 0x00 | **0x00** | 0 | 0 | 0 | **1** | 64 | 0 | 0 | 2 001 370 | 1 692 | 28 |
| **recovery 2** | 0xCD | 0x00 | 0x00 | 1 | 0 | 1 | 0 | 64 | 0 | 0 | 2 001 584 | 1 693 | 27 |
| C rep 3 | 0xCE | 0x00 | **0x00** | 0 | 0 | 0 | **1** | 64 | 0 | 0 | 2 001 562 | 1 694 | 28 |
| **recovery 3** | 0xCF | 0x00 | 0x00 | 1 | 0 | 1 | 0 | 64 | 0 | 0 | 2 001 454 | 1 695 | 28 |

Every missing-response transaction: ACK held to D, all 64 blockers terminate through the
**deadline** path, `ACK_RELEASE_FAILOPEN = 0`, `CD_ACK_REL_RETIRE = 1`, `reg_tag = 0x00`,
no pending marker left. Every recovery transaction is the **first** one after the failure
and every one passes 16/16 plus the Gate-2 rubric — the pre-E1 behaviour was `ARM_BUSY`
with zero blockers admitted.

### Suites 3, 4 — early RESPONSE, and just before the deadline

| | gen | post tag | EARLY | ACK_REL | RETIRE | DL | STALE | hold | drain | tail |
|---|---|---|---|---|---|---|---|---|---|---|
| A rep 1 | 0xC0 | 0x00 | 1 | **1** | **0** | 64 | **0** | 2 001 424 | 1 693 | 25 |
| A rep 2 | 0xC2 | 0x00 | 1 | **1** | **0** | 64 | **0** | 2 001 535 | 1 693 | 26 |
| A rep 3 | 0xC4 | 0x00 | 1 | **1** | **0** | 64 | **0** | 2 001 346 | 1 694 | 25 |

`ACK_RELEASE = 1` with `ACK_REL_RETIRE = 0` is the **direct readout of the retirement
SALU's own pre-state**: the ACK saw the tag in `0x10..0x1F`, so the marker had committed
and the ACK did **not** retire. `BLOCK_TERM_STALE = 0` with `BLOCK_TERM_DL = 64` proves the
`0xB0` decode kept every circulating token live across the marking. `reg_tag = 0x00`
afterwards proves the queued RESPONSE's release performed the retirement. Gate 3's five
normal transactions are the same shape at the 1.5 ms margin.

### Suite 5 — late RESPONSE

| | gen | post tag | EARLY | LATE | BYPASS | ACK_REL | RETIRE |
|---|---|---|---|---|---|---|---|
| B rep 1–3 | 0xC5 / 0xC7 / 0xC9 | 0x00 | 0 | 0 | **1** | 0 | **1** |

The ACK release retires because nothing is pending; the RESPONSE, arriving 500 128 ns
later, finds the transaction retired and takes the **normal forwarding path** — forwarded
exactly once, never held, never re-held, and it cannot alter a subsequent generation.
**This is a deliberate behaviour change from pre-E1**, where it was `RESP_HOLD_LATE = 1`
and cost one loopback traversal. It is what the direction asked for.

### Suite 6 — duplicate early RESPONSE

| | gen | post tag | EARLY | BYPASS | ACK_REL | RETIRE | DL | STALE |
|---|---|---|---|---|---|---|---|---|
| D rep 1–3 | 0xCF / 0xC1 / 0xC3 | 0x00 | **1** | **1** | **1** | **0** | 64 | 0 |

`EARLY = 1` and `BYPASS = 1` in the same transaction: the first RESPONSE was held and
marked, the second read `txn_active == 2`, missed the hold branch and was forwarded once.
`ACK_REL = 1 / RETIRE = 0` proves the marker was applied **exactly once** — a second
application would have pushed the tag out of `0x10..0x1F` and the ACK would have retired
instead. No value outside the three domains was produced.

### Suite 7 — stale RESPONSE

| | pre tag | post tag | BYPASS | deadline before → after | PKTGEN_ADMIT | ARM_FRESH | ACK_HOLD |
|---|---|---|---|---|---|---|---|
| E rep 1–3 | 0x00 | **0x00** | **1** | 0 → 0 | **0** | 0 | 0 |

A RESPONSE with no READ and no ACK, against an idle transaction: bypassed, and `reg_tag`,
the deadline and the blockers are all untouched.

## 6. Full regression — Gate 3

Five consecutive transactions, no reload, no transaction-state reset, generations
0xC0→0xC4. **17/17 requirements each** (the new T-17 included) plus the Gate-2 rubric.

| quantity | E1 | pre-E1 (`0e24012`) |
|---|---|---|
| **drain** | 1 692 – 1 695 (spread **3**) | 1 693 – 1 696 (spread 3) |
| **release tail** | 26 – 28 (spread 2) | 25 – 29 (spread 4) |
| reservoir standing | 1 193 – 1 195 | 1 194 – 1 196 |
| READ→ACK | 500 009 – 500 011 | 500 009 – 500 011 |
| hold | 2 001 371 – 2 001 504 | 2 001 500 – 2 001 586 |

**The measured drain behaviour is unchanged**, which is the direction's own constraint on
this repair. K=64, the deadline calculation, queue priorities, blocker recirculation and
termination, and the synthetic schedule are all untouched.

## 7. Negative evidence

- **The preferred two-register construction does not compile** (dependency cycle), reduced
  to `p4/probe_retire_dependency.p4 -DPROBE_CYCLE`. E1 exists because of that, not instead
  of trying it.
- **5 RegisterActions on one Register is a hard target error**, which is why `tag_read` was
  folded into the marker: `error: Ingress.reg_tag: too many RegisterActions … limits … to 4`.
- **`if (v < 8w0)` silently emits `lss.u`** — never true. bf-p4c exits 0. Caught by
  `assert_salu_asm.py`, which was mutation-checked against exactly that build.
- **A first silicon run of E1 failed** with `PKTGEN_ADMIT=16 / PKTGEN_DROP=48 /
  BLOCK_TERM_STALE=16`. Cause: the token's marker delta was set in the class driver's
  **dequeued** arm, which a fresh token never reaches, so `tag_val` stayed `TAG_NO_WRITE`
  (0x01) and every token added **1** to the generation — `0xC0 + 16 = 0xD0` leaves the
  active domain at token 17 exactly. Moved to the fresh branch, tested first so there is
  one write per path.
- `analysis/test_tag_domain.py`: **2 255 assertions, 0 failures** (790 pre-existing + 1 465
  for E1), mutation-checked four ways — marker reverted to 0xFF → 10 failures; sentinels
  re-collided → 66; delta 0x50→0x40 → 317; delta → 0x00 → 195.
- `analyze_gate34.py` self-test: **20 controls, 0 bad**, including "case C PASSES when the
  ACK retires", "case C FAILS when a pending marker is left behind", and "case B REJECTS
  the pre-E1 held-late classification".
- Two criteria of **mine** had to be corrected, and neither was a relaxation: B-06 asserted
  a queued-response release timestamp that E1 correctly never produces (replaced with the
  bypass + retire evidence), and the Gate-3 clean-state rule demanded a zero
  `reg_deadline`/`reg_ack_rel` the architecture never promised (replaced with a stricter
  rule).

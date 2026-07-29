# Gate 4C repair — state-machine review, and why the preferred construction cannot compile

Required by `meeting_direction.md` (2026-07-29) before editing. Branch
`research/case-a-defense3-fixed-ack-delay`, base `0e24012`.

**Result: the preferred two-register construction is a genuine placement cycle and does
not compile. Reduced to a minimal probe. Two alternative encodings compared with real
compiler output; one of them realises the preferred lifecycle exactly.**

---

## 1. The current state machine, traced

State access order inside one `apply`, with the MAU level each register lands at. Level is
forced by data dependencies, not chosen:

| level | register / table | who writes it | write operand |
|---|---|---|---|
| 1 | `reg_exp_relay_seq`, `reg_session_port` | the READ, via `tbl_session` | `meta.seq_w` / `meta.sport_w` |
| **2** | **`reg_tag`** | ARM via `tag_arm` (conditional on idle); anything with `tag_val != TAG_NO_WRITE` via `tag_rmw`. **`CLASS_RESP`, `CLASS_ACK_REL` and pktgen tokens take `tag_read`, which is READ-ONLY** | `meta.tag_val` |
| 2 | `reg_exp_ack` | the READ installs, others test | — |
| 3 | `tbl_state_decode`, `tbl_txn_active` | — (consume `tag_diff`, `cur_gen`) | — |
| **4** | `reg_deadline`, **`reg_ack_rel`** | deadline: ACK arms once, others rmw. `reg_ack_rel`: `CLASS_RESP` and `CLASS_ACK_REL` only | `meta.dl_val` / `meta.tag_val` |

### 1.1 Where is an early RESPONSE marked?

**Nowhere in state.** The mark is *packet-local and derivative*: the fresh RESPONSE
executes `ack_rel_rmw`, which returns `rel_diff = cur_gen − reg_ack_rel`. `rel_diff != 0`
means the ACK of this generation has not yet been released, and that is counted as
`RESP_HOLD_EARLY`. `dec_resp()` sets only `dl_val = DL_NO_WRITE` and leaves `tag_val` at
`TAG_NO_WRITE`, so **the fresh RESPONSE writes nothing at all**. There is currently no
response-pending state in the program.

### 1.2 What generation information survives in the queued RESPONSE?

**None.** On its release pass it is identified purely by `dequeued == 1 && role ==
ROLE_RESP` — from `ETYPE_SYNTH_RESP` in the synthetic build, and from the DNP3 parse chain
in the live build. The packet carries no generation, and the live build cannot be given one
without breaking byte preservation.

### 1.3 What state does the RESPONSE release path require?

Only `expired`, to attribute `RELEASE_DEADLINE` vs `RELEASE_FAILOPEN`. Its retirement
(`meta.tag_val = TAG_INACTIVE` in the dequeued `ROLE_RESP` branch of the class driver) is a
**write**, not a read. It never consults the generation to decide anything.

### 1.4 Can that state remain packet-local after ACK release?

**Yes** — the release-pass classification is entirely parser-derived. This matters: it means
retiring at ACK release would not break the queued RESPONSE's release *mechanically*. The
only hazard is that the RESPONSE's **unconditional** `tag_val = TAG_INACTIVE` would clobber
a *new* generation if one armed in the interval between the two releases (29 ns, measured).
That hazard is precisely what CASE 1 of the direction protects against.

### 1.5 Can an existing register represent `response_pending_gen`?

`reg_ack_rel` is the right shape — 8-bit, generation-valued, an SALU difference, and already
written from `meta.tag_val` on the `CLASS_RESP` path (which currently writes nothing). One
line, `dec_resp() { … meta.tag_val = meta.cur_gen; }`, turns it into `response_pending_gen`
with **zero new registers**. That is the construction the direction prefers, and it is the
one that fails to place — see §3.

## 2. State-transition table

`g` = the active generation. `P` = a current-generation RESPONSE is pending.

| # | event | precondition | current behaviour | required behaviour |
|---|---|---|---|---|
| 1 | **normal early RESPONSE** | `reg_tag = g`, blockers circulating | admitted to `Q_HOLD` behind the ACK, `RESP_HOLD_EARLY`, `rel_diff != 0`. Nothing recorded. | additionally record `response_pending_gen := g` |
| 2 | ACK release, `P` set | early RESPONSE queued | forwards; `reg_ack_rel := g`; **does not** retire | must **not** retire (CASE 1) |
| 3 | queued RESPONSE release | after the ACK | forwards; retires `reg_tag := TAG_INACTIVE` | remains the retirement event (CASE 1) |
| 4 | **late RESPONSE** | ACK already released, `reg_tag = g` still live | `rel_diff == 0` → `RESP_HOLD_LATE`, held one traversal, released, retires | after the repair the tag is already retired, so it takes the **normal forwarding path** (`RESP_BYPASS`), forwarded once, not held |
| 5 | ACK release, `P` clear | **no** RESPONSE ever queued | forwards; **nothing retires** ⇒ `reg_tag` keeps `g` for ever | **retire immediately** (CASE 2) |
| 6 | **missing RESPONSE** | as #5 | next READ decodes `ARM_BUSY`, escapes, zero blockers, no hold — **measured** | next READ must decode `ARM_FRESH` |
| 7 | **duplicate RESPONSE** | second RESPONSE, tag live | admitted again; `rel_diff` now 0 ⇒ classified LATE; forwarded | forwarded once, never re-held |
| 8 | **stale-generation RESPONSE** | arrives after a NEW transaction armed | §8.2 seq/ack tested against the **new** trackers ⇒ mismatch ⇒ `RESP_BYPASS` | unchanged: cannot clear, hold or alter the new generation |

Rows 5 and 6 are the defect. Rows 1–4, 7 and 8 are regressions to protect.

## 3. The preferred construction does not compile

Implemented minimally: `dec_resp()` records `response_pending_gen` in `reg_ack_rel`, and a
new `reg_tag` action retires on the ACK-release pass when `rel_diff != 0`.

```
bf-p4c --target tofino --arch tna -DD3_SYNTH_EVENTS
error: Table placement cannot make any more progress.  Though some tables have not yet
been placed, dependency analysis has found that no more tables are placeable.
1 error, 3 warnings generated.
```

**Why, structurally.** The two paths need the two registers in opposite orders:

```
path CLASS_RESP     reg_tag  (read g)          ->  reg_ack_rel (write g)
path CLASS_ACK_REL  reg_ack_rel (read pending) ->  reg_tag     (conditional retire)
```

Register placement is **static** — each register lives in exactly one stage, and a register
may be accessed at most once per packet. The two orderings are therefore contradictory even
though the two paths are mutually exclusive at run time: `pkt_class` is invisible to
placement. Moving `reg_tag` later does not help, because the ARM path's `tag_arm` feeds
`tbl_state_decode`, which feeds `dl_val`, which feeds `reg_deadline` and `reg_ack_rel` — so
`reg_tag` late pushes `reg_ack_rel` later still and the cycle simply moves.

### Minimal probe — `p4/probe_retire_dependency.p4`

Two 8-bit registers, two paths, opposite orders, nothing else:

| build | result | stages |
|---|---|---|
| `-DPROBE_CYCLE` — the structure above | **FAILS**, same error verbatim | — |
| `-DPROBE_ONE_REG` — encoding E1 (pending marker inside the tag register) | **compiles** | 2 |
| `-DPROBE_ACK_ONLY` — encoding E2, as first written | FAILS | — |

The `PROBE_ACK_ONLY` failure is a **probe bug, not a result**: that variant still let the
retire action read the pending PHV, so the dependency survived. E2's real form takes no
pending input at all and is trivially placeable — it is the `tag_rmw` path the program
already uses elsewhere. Recorded because a probe that fails for the wrong reason is worse
than no probe.

### ⚠ A silent miscompile found inside the probe

E1's natural predicate is "is the marker bit set", written as a sign test. As
`if (v < 8w0)` on a `bit<8>` register bf-p4c emitted

```
tag_retire_if_unmarked_0:
- lss.u lo, lo          <-- UNSIGNED less-than-zero: NEVER TRUE
```

with no error and no warning — a vacuous predicate, and the same class of trap as the
large-constant SALU comparison. With an explicit signed cast, `if ((int<8>)v < 8s0)`, it
emits the correct instruction:

```
- lss.s lo, lo          <-- signed, compares against zero, no immediate
```

**Any sign or magnitude test in an SALU must be read back out of the assembly.** Neither
form is rejected by the compiler.

## 4. Two encodings, compared

### E1 — the pending marker lives inside `reg_tag`

```
idle                          0x00
live, no RESPONSE pending     0xC0..0xCF          (MSB set)
live, RESPONSE pending        gen - 0xB0 = 0x10..0x1F   (MSB clear, never 0x00)
```

- **RESPONSE admission**: `reg_tag := reg_tag - 0xB0` (emits `add lo, lo, 80`, verified).
- **ACK release**: `if ((int<8>)v < 0) { v = TAG_INACTIVE; }` — retires **only** when
  nothing is pending. Compare against zero, no immediate, no large constant.
- **RESPONSE release**: retires as it does today.

Realises the direction's CASE 1 and CASE 2 **exactly**, uses an existing register, adds no
duplicate register, and is generation-bound rather than a boolean (the marked value *is* the
generation, offset by a constant).

Costs: two extra `tbl_txn_active` entries (`0xC0 &&& 0xF0` and `0x10 &&& 0xF0`, so a marked
tag still reads active), and **one** extra `tbl_state_decode` entry — because a marked tag
changes what circulating blockers compare against. That entry is a single exact value:
`tag_diff = carried_gen − (gen − 0xB0) = 0xB0` for *every* generation, so
`(CLASS_BLOCK_DEQ, 0xB0 &&& 0xFF) : dec_block_live()`.

**This is the one item that brushes the "do not alter" list.** It does not change the
blocker *lifecycle* — same admission, same loop, same deadline termination — only the
encoding of "this token's generation is still live". It is directly falsifiable: if it were
wrong, `BLOCK_TERM_STALE` would go non-zero and the reservoir would collapse before `D`,
which every existing gate already measures. Without the entry the failure is severe and
obvious (the reservoir dies the instant the RESPONSE is admitted), not subtle.

### E2 — retire at ACK commitment, unconditionally

- **ACK release**: `tag_val = TAG_INACTIVE` via the existing `tag_rmw`. One line.
- **RESPONSE release**: stops writing `reg_tag`.

Simplest possible change, no new state, no blocker involvement, nothing on the "do not
alter" list. The corruption vector CASE 1 guards against **disappears by construction**: a
stale queued RESPONSE can no longer write `reg_tag` at all. Late and stale RESPONSEs take
the normal forwarding path (`RESP_BYPASS`), forwarded once, never re-held.

Its deviation: the retirement event becomes the ACK release in **all** cases, so validation
requirement 3's "RESPONSE release retires the transaction" would not hold as worded. It also
leaves a 29 ns window in which a new READ could arm while the previous RESPONSE is still
queued; that RESPONSE would then be released behind the new transaction's hold — forwarded
once and in order, but delayed by up to `D`.

### Recommendation

**E1.** It is the direction's lifecycle implemented as specified, and its one cost is a
single decode entry whose correctness is measurable by gates that already exist. E2 is the
smaller diff but silently relocates the retirement event, which is the thing the direction
was most explicit about.

## 5. What has NOT been done

No repair is implemented. `p4/case_a_defense3_fixed_ack_delay.p4` is unchanged from
`0e24012` apart from the SALU wording correction already committed; the failed preferred
construction was compiled from a scratch copy and discarded. The only new files are the two
compile-only probes. **Defense 2 is currently loaded** — the rebuilt Defense 3 artifact has
not been reloaded, because there is no repair to validate yet.

E1 touches an item on the "do not alter" list (the blocker generation decode), and E2
relocates the retirement event. Both deviate from an explicit instruction in different
ways, which is why this stops here rather than choosing for you.

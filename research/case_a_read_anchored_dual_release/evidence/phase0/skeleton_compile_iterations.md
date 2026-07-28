# Phase 0 final gate — dual-release skeleton compile iterations

Local `bf-p4c 9.13.1` (`p4c 9.13.1 (SHA: e558d01)`,
`/home/philip/bf-sde-9.13.1/install/bin/bf-p4c`) on this host.
**No switch was touched, no ssh, no `bf_switchd` restart, nothing was loaded or run.**

Deliverable: `research/case_a_read_anchored_dual_release/p4/case_a_dual_release_skeleton.p4`
Canonical build: `.../p4/build_skeleton_9.13.1/`, log `.../p4/build_skeleton_9.13.1_compile.log`

Every number below is read out of the compiler's own `pipe/logs/table_summary.log` and
`pipe/logs/mau.resources.log`. Nothing is estimated except where explicitly labelled an
estimate, and each estimate is backed by a probe compile.

---

## Iteration 1 — the whole skeleton, first attempt

All six gate items added in one pass on top of `case_a_stripped_baseline.p4`: two
READ-anchored deadline registers, two expiry ternary tables, two blocker roles from a
full-width `packet_id` ternary, four queue assignments, `ack_committed_to_master`, and
per-class blocker termination with per-class per-token budgets.

**Result: 0 errors, 3 warnings, on the first attempt. No fix was required.**

```
Table allocation done 1 time(s), state = INITIAL
Number of stages in table allocation: 9
  Number of stages for ingress table allocation: 9
  Number of stages for egress table allocation: 0
Critical path length through the table dependency graph: 8
Number of tables allocated: 81
```

The three warnings are byte-for-byte the stripped baseline's three benign ones: the
struct-wide `uninitialized_out_param` notice on `IgParser`'s `meta`, and two
`min_parse_depth_accept_loop` unroll notices. **No new warning.**

### Why there was nothing to iterate on — the failure classes that were designed around

A clean first compile is not luck, and recording *what was avoided* is the negative
evidence this file exists for. Each of the following is a known bf-p4c 9.13.1 failure
this design deliberately did not walk into. Any future edit that reintroduces one of
them will fail, so they are recorded as constraints, not as history.

| # | Failure class that was avoided | The construction used instead |
|---|---|---|
| 1 | A bit-slice inside a gateway -> `condition expression too complex`; a slice of a 32-bit arithmetic field -> `N field slices remain unallocated` (design §5.2) | Both deadline tests and the blocker-role split are **full-container ternary matches**: `age_a`/`age_r` under `0x00000000 &&& 0x800000FF`, and `hdr.pgen_id.packet_id` under `0xFFC0`. Branching on `packet_id[6]` would have been the natural expression and is exactly the trap. |
| 2 | More than 2 PHV inputs to one register's SALU | `reg_d_ack` takes `(now_word, dl_val_a)`; `reg_d_resp` takes `(now_word, dl_val_r)`; `reg_ackc` takes `(ackc_w)`; `reg_tag` still takes `(gen_in, tag_val)`. Exactly 2 or fewer each. |
| 3 | Two RegisterActions per register that are not mutually exclusive per packet | Each of the four state registers is accessed by **one** RegisterAction executed once per packet, except `reg_tag`, which keeps the baseline's proven mutually-exclusive `tag_rmw` / `tag_read` split. The baseline's `deadline_arm_once` was **retired**, not duplicated (see below). |
| 4 | A three-way conditional write inside a SALU | `reg_ackc` is a single `if (ackc_w != 0) v = ackc_w;`. Clear/commit/leave-alone are encoded in the *written value*, which is why "committed" is `1` and "not committed" is `2`: `0` is reserved as the no-write sentinel. |
| 5 | `count()` sites on one Counter object that are not mutually exclusive -> hard error (`cannot share Counter ... not mutually exclusive`) | Every new counter slot is a leaf of an `if/else` chain. `ctr_fresh` is touched at most once and `ctr_deq` at most once per packet on every path. Both arrays were widened to 16 slots so no total-plus-subset counter had to be reintroduced. |
| 6 | `action spanning multiple stages` from bf-p4c merging consecutive unconditional statements with an intra-action dependency | `tbl_build_now` stays a separate table, and `tbl_build_cand`'s two adds are **independent** (`now_word + a_word`, `now_word + r_word`), so they legitimately co-locate in one action. |
| 7 | Parser write-once violation (Tofino has no clear-on-write) | `is_pktgen`, `role`, `dir`, `fwd_port`, `port_ok`, `gen_in`, `dequeued` are still left out of `start` and assigned exactly once per path. Every new metadata field is assigned in `start` **or** on the parser path, never both. |

### One design substitution that had to be made, and why it is not a weakening

The baseline armed its single deadline with an in-SALU compare-and-arm-once
(`deadline_arm_once`: write only while the stored word is `UNARMED_WORD`), which made
the *first qualifying ACK* the arming event. That cannot be carried over literally: in
the READ-anchored design the arming event is the READ, and the READ would have to
disarm and re-arm the same register in one pass.

The idempotency is therefore taken from the register that already decides freshness.
`tbl_state_decode` splits `CLASS_ARM` by `tag_diff`:

```
(CLASS_ARM, 8w0x00 &&& 8w0xFF) : dec_arm_dup();    /* retransmit: writes DL_NO_WRITE */
(CLASS_ARM, 8w0x00 &&& 8w0x00) : dec_arm_fresh();  /* fresh: anchors d_ACK and d_RESP */
```

Entry order is priority, so the exact-zero reject pattern wins. This is the same
`reg_tag` idempotency the baseline already used to suppress a duplicate READ's pktgen
burst, so a retransmitted READ now suppresses the second burst **and** cannot move
either deadline, from one test. `UNARMED_WORD` disappears with it; a never-written
deadline register reads `0`, whose age has low byte `0x01`, so it can never satisfy the
expiry mask — the same fail-safe the baseline relied on.

---

## Where the ninth stage comes from — measured, not inferred

Critical path is **8 in both** the stripped baseline and the skeleton. **The second
deadline did not extend the dependency chain.** `reg_d_ack`, `reg_d_resp`, `reg_ackc`
and `reg_t_read` all land in **stage 4, in parallel** (Meter ALU 4/4 = 100%), and the
two expiry tables land together in stage 5.

Placement went 8 -> 9 because the program stopped being purely dependency-bound. The
binding resource is **logical table IDs, 16 per stage on Tofino-1**:

| Stage | 5 | 6 | 7 | 8 |
|---|---|---|---|---|
| stripped baseline, logical table IDs | **16/16** | **16/16** | 6/16 | — |
| skeleton, logical table IDs | **16/16** | **16/16** | **16/16** | 10/16 |

The baseline's ACT block saturated two stages of logical table IDs; the skeleton's
saturates three. The growth is the ACT block's *breadth*, not its depth: four queue
actions instead of two, a per-class blocker loop/terminate structure instead of one, and
four more counter sites. Total logical tables 57 -> 81.

---

## Attribution probes (scratchpad only; not part of the deliverable)

Three probe compiles, each a mechanical transform of the skeleton, compiled with the same
`bf-p4c 9.13.1`. Sources and builds live in the session scratchpad and are **not** added
to the repository; the numbers are reproduced here because they are the evidence behind
the Phase-4 estimate.

| Probe | Change from the skeleton | Ingress stages | Critical path | Tables |
|---|---|---|---|---|
| — | the skeleton itself | **9** | 8 | 81 |
| A | delete `reg_t_read` (the optional `t_READ` telemetry register) | **9** | 8 | 80 |
| B | add 6 escape-counter branches, modelling design §11 terminal states B–H | **10** | 8 | 88 |
| C | add the exact-predicate sketch: `reg_exp_ack`, `reg_exp_seq`, `reg_txn_state`, and three extra ternary key fields on `tbl_state_decode` | **10** | 8 | 85 |
| D | B + C together, plus a reverse-5-tuple exact `tbl_session` | **11** | 8 | 93 |

Readings:

- **A: the `t_READ` telemetry register is free in stages.** It costs one Meter ALU in
  stage 4 (4/4 -> 3/4 without it) and one logical table, and zero stages. It is kept.
- **B: ACT-block breadth is the live cost.** Six more `if/else` counter leaves — 7 more
  logical tables — is exactly one more saturated stage. The marginal rate in this region
  of the program is about **16 logical tables per stage**, and every §11 terminal state
  lands in that region.
- **C: the predicate half costs one stage and no depth.** The expected-value registers
  sit in parallel with `reg_tag` and their differences join `tbl_state_decode`'s key, so
  the critical path stays 8; the extra stage is again placement, not dependency.
- **D: the two costs are additive here, 9 -> 11.** The compiler tried three placements
  (`INITIAL` 11, `NOCC_TRY1` 10, `REDO_PHV1` 11) and kept 11.

**Probe D is a sketch, not Phase 4.** The expected-ack / expected-seq arithmetic is a
placeholder, the one-shot latch is a stub, and segmentation handling is absent. It
bounds the estimate from below, not from above.

---

## Tooling note (a real dead end worth recording)

`bf-p4c` **without `-g`** produces no `pipe/logs/` directory at all, so
`table_summary.log`, `mau.resources.log` and `phv_allocation_summary_0.log` do not exist
and there is no stage count to read. The first probe compile was run without `-g` and
produced only `bfrt.json`, `manifest.json` and the `.bfa`. Every compile in this campaign
must carry `-g`.

`bf-p4c` also **wipes its `-o` directory** on each run, which is why the compile log is
written outside it.

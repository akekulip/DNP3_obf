# Defense 3 — resource ledger

One row per compile, from the first one onward, as `meeting_direction.md` §11 requires
("Do not wait until the full implementation to discover stage pressure").

**Compiler:** local `bf-p4c 9.13.1` (`p4c 9.13.1`, SHA `e558d01`,
`/home/philip/bf-sde-9.13.1/install/bin/bf-p4c`), invoked as

```
bf-p4c --target tofino --arch tna -g [-D<variant>] -o <outdir> \
       research/case_a_defense3/p4/case_a_defense3_fixed_ack_delay.p4
```

**No switch was touched by any row below.** Every number is read out of the compiler's
own `pipe/logs/table_summary.log`, `pipe/logs/mau.resources.log` and
`pipe/logs/phv_allocation_summary_0.log`. Nothing is estimated.

The 9.13.2 compile (§13 Gate 1) has **not** been run — it requires the switch, and this
task is author-and-local-compile only.

---

## 1. Reference points

| | stripped baseline (start point) | Defense 2 (frozen, silicon) |
|---|---|---|
| source | `case_a_read_anchored_dual_release/p4/case_a_stripped_baseline.p4` | `defense2_pktgen/p4/dnp3_timing_normalizer_pktgen.p4` |
| ingress / egress stages | **8 / 0** | 10 / 0 |
| critical path | **8** | 8 |
| logical tables | **57** | 70 |
| LTID by stage (of 16) | 9,3,3,2,2,**16**,**16**,6 | — |
| PHV: MAU group B0-15 | **16/16 containers (100 %), 116/128 bits** | — |

The baseline sits **exactly at its dependency floor** (stages == critical path == 8).
No lever can take Defense 3 below 8; width is the only thing that can push it above.

---

## 2. The ledger

| # | Build | Change under test | Ing | Egr | Crit path | Tables | Verdict |
|---|---|---|---|---|---|---|---|
| 0 | — | *(reference)* stripped baseline | 8 | 0 | 8 | 57 | reference |
| 1 | `build_v1_9.13.1` (superseded) | Full Defense 3, Variant A, all §8 predicates, no inline lever | **10** | 0 | **8** | 80 | compiles, 0 errors — but **placement-bound** |
| 2 | `build_v2_9.13.1` **(SELECTED)** | Row 1 + the inline lever on `to_fwd` / `drop_pkt` | **9** | **0** | **8** | 70 | **PASS** — inside the ≤10 / ≤1 target |
| 3 | scratch probe (not kept) | Row 2 + inline `to_hold` / `to_block` as well | 9 | 0 | 8 | 65 | **no stage bought** — reserve NOT spent |
| 4 | `build_variantB_9.13.1` | §10 Variant B: bridged role marker + egress release counter | 8 | **1** | 8 | 71 | compiles; see §5 |
| 5 | `build_variantC_9.13.1` | §10 Variant C: B + egress release timestamp register | 8 | **1** | 8 | 72 | compiles; see §5 |

All six rows: **0 errors**, 3 warnings, and the 3 warnings are byte-identical to the
baseline's (one `uninitialized_out_param` on the parser's `meta`, two
`min_parse_depth_accept_loop` unroll notices). No new warning class was introduced.

### Row 1 → row 2: the diagnosis, and why the lever was the right first move

Row 1 landed at **10 ingress stages with a critical path of 8**. Panel A's rule applies
literally: *if stages > critical path, read the Logical TableID column first, and it is
LTIDs, full stop.* It was:

| stage | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 |
|---|---|---|---|---|---|---|---|---|---|---|
| LTID (of 16) | 10 | 9 | 6 | 1 | 2 | 2 | **16** | **16** | **16** | 2 |

Three consecutive stages at 16/16, exactly the shape `dual_min` had. `table_summary.log`
showed **19 bare-action tables** (`tbl_to_fwd`×7, `tbl_drop_pkt`×5, `tbl_to_block`×3,
`tbl_to_hold`×2, `tbl_arm_clone`), ~12 of them inside the saturated ACT region. A bare
action *call* becomes its own logical table and will not merge with the statement beside
it, so `to_fwd(); ctr.count(x);` costs two LTIDs where the inlined form costs one.

Inlining `to_fwd` (7 sites) and `drop_pkt` (6 sites) through single-definition macros:
**10 → 9 stages, 80 → 70 tables, zero behavioural change.**

### Row 3: the measurement that stopped the optimisation

`to_hold()` and `to_block()` were deliberately **not** inlined. Their single-site
property is the evidence that nothing else in the program can enqueue to Q_HOLD or
Q_BLOCK — checkable in `pipe/context.json` action immediates rather than by reading the
source — and that is a safety claim, not a style preference.

Row 3 tested the tradeoff rather than assuming it: inlining them too drops the table
count 70 → 65 but leaves the stage count at **9**. **The reserve buys no stage**, so it
was not spent. Recorded here so nobody re-tries it.

---

## 3. Selected build — Variant A, `build_v2_9.13.1`

```
ingress stages 9 / 12      egress stages 0 / 12      critical path 8      tables 70
```

### LTIDs and per-stage resources (ingress)

| stage | LTID/16 | SRAM | Map RAM | TCAM | Meter ALU (SALU) /4 | Stats ALU /4 | Gateway |
|---|---|---|---|---|---|---|---|
| 0 | 9 | 4 | 2 | 3 | 0 | 1 | 7 |
| 1 | 9 | 6 | 6 | 0 | 3 | 0 | 5 |
| 2 | 6 | 4 | 4 | 0 | 2 | 0 | 3 |
| 3 | 1 | 1 | 0 | 3 | 0 | 0 | 0 |
| 4 | 2 | 2 | 2 | 0 | 1 | 0 | 2 |
| 5 | 2 | 2 | 2 | 0 | 1 | 0 | 1 |
| 6 | **16** | 2 | 2 | 0 | 0 | 1 | 12 |
| 7 | **16** | 4 | 4 | 0 | 0 | 2 | 7 |
| 8 | 9 | 10 | 10 | 0 | 3 | 2 | 6 |
| **totals** | **70** | 35 | 32 | 6 | 10 | 6 | 43 |

Egress: **0 stages, 0 tables, 0 of everything.**

- **The binding resource is still LTIDs in the ACT region** (stages 6 and 7 at 16/16,
  12 and 7 gateways). Stage 8 has 7 free and stages 0–5 have 47 free between them, but
  ACT-block work has `min stage` 5–6 and cannot reach them.
- **No resource is close to its ceiling except LTIDs.** Meter ALU peaks at 3/4, Stats ALU
  at 2/4, TCAM at 3, SRAM at 10.
- **Critical path is unchanged at 8**, i.e. the whole of Defense 3 — the new register,
  the three session trackers, the widened decode, the ACK/RESPONSE hold branches — added
  **zero depth**. That was the design bet and it held.

### PHV

| | Variant A | baseline |
|---|---|---|
| Overall containers | 48 / 224 (21.4 %) | ~16.5 % |
| **MAU group B0-15 (8-bit ingress)** | **16/16 containers (100 %), 116/128 bits** | **16/16 containers (100 %), 116/128 bits** |
| MAU group W0-15 (32-bit) | **16/16 containers (100 %), 512/512 bits** | not saturated |
| H0-15 (16-bit) | 10/16 (62.5 %) | — |
| Tagalong collections occupied | 4 of 8 (I:0,2 · E:1,3) | 4 of 8 |

Two things worth carrying forward:

1. **B0-15 came out at exactly 116/128 bits — identical to the baseline.** That was the
   plan, not luck: `meta.tag_ok` and `meta.ack_ok` were merged into one `meta.verdict`
   code, `reg_ack_rel`'s two SALU operands reuse the provably-dead `meta.tag_val` /
   `meta.tag_diff` (CONSENSUS §4's pre-identified fix, applied up front), and the
   ACK-release timestamp uses a parser-derived predicate so it needs no `ev_*` flag.
   Net 8-bit growth for the whole of Defense 3: **zero**.
2. **W0-15 is the NEW pressure point** — 16/16 containers, 512/512 bits, because the
   three session trackers and their difference results are all 32-bit. W16-31 and W48-63
   are completely empty, so there is raw space, but *a further 32-bit SALU operand pair
   is the next thing likely to hit a MAU-group binding failure*. Anyone adding 32-bit
   state to this program should read the group table before writing the code.

---

## 4. Where the §8 predicates cost their resources

Panel A flagged the full §8 predicate set as "the largest un-costed item in the design".
Measured cost, relative to the stripped baseline: **+1 ingress stage, +13 tables, +3 SALU
accesses, +3 TCAM blocks, 0 depth.** Specifically:

| construct | carries which conjunct | cost |
|---|---|---|
| `tbl_session` (2-entry ternary, control-plane installed) | protected 5-tuple, both directions; also seeds both trackers at level 0 | 1 LTID + 3 TCAM, stage 0 |
| `reg_exp_relay_seq` | `tcp.seq == EXP_RELAY_SEQ` — **rejects 61/61 keepalives** | 1 SALU, stage 1 |
| `reg_session_port` | learned master ephemeral port | 1 SALU, stage 1 |
| `reg_exp_ack` + `tbl_build_exp_ack` | `tcp.ack == EXP_ACK` (the program's only arithmetic) | 1 SALU + 1 LTID, stages 1–2 |
| widened `tbl_state_decode` (5 key fields, 96 bits ternary, 11 const entries) | everything else in §8.1/§8.2 | **0 additional LTIDs** — the table already existed |
| parser gates (flags `0x3F`/`0x27`, `flags_frag` mask, `tp_ctrl & 0xC0`, `app_control & 0xF0`) | IPv4 structure, fragmentation, ACK-only flags, single segment/fragment, solicited | 0 MAU cost |

Folding every remaining conjunct into the **existing** decode table, rather than adding
per-conjunct tables, is what kept this at one stage instead of four.

---

## 5. §10 ingress-versus-egress variants

| | **A (selected)** | B | C |
|---|---|---|---|
| what it adds | nothing — all logic in ingress | 1-byte bridged role marker + egress release counter | B + 32-bit egress release timestamp register |
| **ingress stages** | **9** | 8 | 8 |
| **egress stages** | **0** | 1 | 1 |
| **critical path** | 8 | 8 | 8 |
| **logical tables** | 70 | 71 | 72 |
| ingress LTID by stage | 9,9,6,1,2,2,**16**,**16**,9 | 7,12,6,2,3,**16**,**16**,9 | 8,12,6,2,3,**16**,**16**,9 |
| egress LTID by stage | — | 1 (stage 0) | 1 (stage 0) |
| PHV overall containers | 48 (21.4 %) | 49 (21.9 %) | 50 (22.3 %) |
| PHV B0-15 | 16/16, 116 bits | 16/16, 116 bits | 16/16, 116 bits |
| SRAM (ing total) | 35 | 38 | 41 |
| Map RAM (ing total) | 32 | 30 | 30 |
| TCAM (ing total) | 6 | 6 | 6 |
| Meter ALU (SALU, ing total) | 10 | 10 | 11 |
| Stats ALU (ing total) | 6 | 7 | 7 |
| egress resources | none | 1 table, 1 SRAM, 1 Map RAM, 1 Stats ALU | same + 1 Meter ALU |

### The prediction that was wrong, stated plainly

Panel A predicted **A at 8 ingress / 0 egress** and **B at 8 ingress / 1 egress**, i.e.
that B would *cost* a stage. Measured, the opposite happened on the ingress axis: A
landed at 9 and B/C at 8. **Total** silicon stages are identical (A = 9+0, B = 8+1), so
nothing was actually saved; the ingress allocator simply repacked when `to_fwd`'s body
grew the two `setValid`/assignment statements. This is exactly the greedy-packing
sensitivity Panel A warned about ("placement is recomputed from scratch each compile and
greedy packing has surprised this program family before"), and it is recorded here rather
than smoothed over.

### Selection: **A**, and the reason is correctness, not stages

CONSENSUS §3 pre-registered A, and the measurement does not disturb the reason:

- B and C do not reduce total stages (9 either way) and do not relieve any binding
  resource — the ACT-region LTID saturation at 16/16 is present in **all three**.
- B and C put a bridged header on the **byte-preserving path**. Today byte identity is
  provable in one sentence: *egress extracts only ethernet and re-emits everything else
  as residual, so no field can be modified.* Under B/C it becomes *the egress parser
  consumes exactly the byte the ingress deparser added* — a weaker property, on the
  program's single most load-bearing invariant, in exchange for a counter.
- C's egress timestamp is **strictly worse as an instrument**: the true dequeue instant
  is the loopback pass's `ingress_mac_tstamp`, and an egress timestamp is taken after
  the forward hop, contaminating the release-tail measurement with a hop A excludes.

A also leaves the wider ingress margin where it matters least (9/12 vs 8/12, both
comfortable) and zero egress commitment.

---

## 6. Fail-open horizon — the model, not the constant

`INITIAL_BUDGET` 100 000 → **`budget` 18 000**, and it is now a **runtime** parameter of
`tbl_params` rather than a compiled-in constant.

```
H = B x tau        tau = K / rate_dp8        <- THE MODEL
tau = 64 / 37.4e6 = 1.711 us   (measured 1.715 us, Defense 2 gate f)
```

Computed by `setup/…_setup.py::failopen_horizon()` and printed at config time:

| B | tau | H | vs worst legitimate hold (a=22 ms, D=3 ms) | vs 200 ms RTO floor |
|---|---|---|---|---|
| 100 000 (inherited) | 1.711 µs | 171.12 ms | 6.8× | **0.86×** — too close |
| **18 000 (adopted)** | 1.711 µs | **30.80 ms** | **1.23×**… see note | **6.5× clear** |

Note on the middle column: 30.80 ms clears the *worst observed* transaction
(a = 22 ms + D = 3 ms = 25 ms) by 1.23× and the *typical* one (a = 0.505 ms) by 10.3×.
The setup script gates on both bounds and FAILS the run if `H ≤ a_worst + D` or
`H ≥ 200 ms`, so a mis-set B cannot silently produce a trial that measures B instead of D.

**H scales with port speed** (`tau = K / rate_dp8`), which is why
`assert_dp8_speed()` aborts the run — at 10G the same B gives H ≈ 99 ms. The inherited
comment's "~10 µs/pass" model was ~5.8× wrong; the value survived the error, the model
did not.

---

## 7. Reproduce

```bash
export PATH=/home/philip/bf-sde-9.13.1/install/bin:$PATH
cd research/case_a_defense3/p4

# Variant A — the selection
bf-p4c --target tofino --arch tna -g -o build_v2_9.13.1 \
       case_a_defense3_fixed_ack_delay.p4

# Variant B / C probes
bf-p4c --target tofino --arch tna -g -DD3_EGRESS_MARKER \
       -o build_variantB_9.13.1 case_a_defense3_fixed_ack_delay.p4
bf-p4c --target tofino --arch tna -g -DD3_EGRESS_MARKER -DD3_EGRESS_TS \
       -o build_variantC_9.13.1 case_a_defense3_fixed_ack_delay.p4
```

There is a third compile-time flag, `-DD3_REPLAY_ON_HULK`, which adds dp11 to the
relay-facing parser state so a Hulk-side injector can stand in for the SEL-751 during the
synthetic gates. **The live campaign build must not define it**, because CONSENSUS §8.1's
first conjunct is `ingress_port == PORT_RELAY`. **It is also unusable in practice: dp11 is
not configured and its link is dark**, which is why §13 Gate 2 generates its events in-chip
instead (§8 below).

```bash
# §13 Gate 2 — the SYNTHETIC-EVENT build
bf-p4c --target tofino --arch tna -g -DD3_SYNTH_EVENTS \
       -o build_synth_9.13.1 case_a_defense3_fixed_ack_delay.p4
```

---

## 8. §13 Gate 2 — the synthetic-event build

Gate 2 needs a synthetic READ, ACK and RESPONSE. dp11 is dark, so the events are emitted
by a SECOND in-chip packet-generator application (`trigger_timer_one_shot`, ONE batch of
three copies of one template, spaced by the hardware `ipg`) — the construction proven in
the frozen `case_a_read_anchored_dual_release/p4/case_a_dual_min.p4`. Everything it needs
is behind `-DD3_SYNTH_EVENTS`.

### The ledger rows

| # | Build | Change under test | Ing | Egr | Crit path | Tables | Verdict |
|---|---|---|---|---|---|---|---|
| 6 | `build_live_9.13.1` | row 2 **re-compiled after the ifdef was added**, macro UNDEFINED | **9** | **0** | **8** | **70** | **PASS — identical to row 2** |
| 7 | `build_synth_9.13.1` | row 6 + `-DD3_SYNTH_EVENTS` | **9** | **0** | **8** | **73** | **PASS** |

Both: 0 errors, the same 3 warnings as every earlier row, no new warning class.

### Row 6 — the live build is unchanged, and that is checked rather than asserted

The whole point of the ifdef is that the campaign build is still the Gate-1 program. Three
comparisons against the stored `build_v2_9.13.1` artifacts:

| comparison | result |
|---|---|
| preprocessed source (`.p4pp`), blank lines removed | **byte-identical** |
| `pipe/*.bfa`, with compiler-generated anonymous names and `run_id` normalized | **byte-identical, 0 differing lines** |
| `pipe/context.json`, same normalization | **differs only in `build_date` and `run_id`** |

**One consequence must not be glossed over:** bf-p4c derives the names of anonymous action
tables from SOURCE LINE NUMBERS (`tbl_case_a_defense3_fixed_ack_delay1252` became
`…1536`). Inserting the ifdef blocks above them renamed every one. The behaviour is
identical and no control-plane script names those tables — but **the binary currently
loaded on the switch was produced by the pre-edit source, so the live build must be
re-compiled and re-loaded before it is used again.** That is a reload, not a redesign.

### Row 7 — where the +3 tables landed

| stage | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | total |
|---|---|---|---|---|---|---|---|---|---|---|
| LTID live | 9 | 9 | 6 | 1 | 2 | 2 | **16** | **16** | 9 | 70 |
| LTID synth | 7 | **13** | 6 | 1 | 3 | 2 | **16** | **16** | 9 | 73 |

**The ACT region is untouched.** Stages 6, 7 and 8 are identical between the two builds in
*every* column — LTID 16/16/9, gateways 12/7/6, SRAM 2/4/10, Meter ALU 0/0/3, Stats ALU
1/2/2. The three new tables (`tbl_synth_role` and the two timestamp-register call sites)
all placed in stages 0/1/4, which is exactly the region §3 identified as having free LTIDs
that ACT-block work cannot reach. The stage count therefore did not move.

`tbl_synth_role` and `tbl_session` are **mutually exclusive by construction** and the
compiler placed them in the same stage under one gateway
(`true: tbl_synth_role_0 / false: tbl_session_0`, stage 0), so the synthetic session
lookup costs no depth.

Other resources, synth vs live: SRAM 43 vs 35, Meter ALU (SALU) **12 vs 10**, Stats ALU 6
vs 6, TCAM 6 vs 6, PHV 49 vs 48 containers (21.9 % vs 21.4 %), B0-15 unchanged at 16/16.

**The one thing to watch: stage 1's Meter ALU is now 4/4 in the synthetic build** (it was
3/4). The next 32-bit SALU added to this program will not fit at level 1. This is the same
warning §3 gave about the W0-15 PHV group, now with a second symptom.

### The ordering invariant survives the new build

CONSENSUS §8.3 requires that exactly one action write `QID_HOLD` and exactly one write the
master-facing qid — checkable in the compiled artifacts rather than by reading the source.
Read out of both `.bfa` files:

| | live | synth |
|---|---|---|
| writers of `qid 1` (Q_HOLD) | `Ingress.to_hold` only | `Ingress.to_hold` only |
| writers of `qid 7` (Q_BLOCK) | `Ingress.to_block` only | `Ingress.to_block` only |
| writers of `qid 0` | the 7 inlined `D3_TO_FWD()` sites | the same 7 sites |

### What the synthetic build costs in fidelity, not in resources

`tbl_synth_role`'s compiled action bodies are the honest statement of what is synthesized:

```
Ingress.synth_read(gen): set meta.sess,2 (MASTER); set meta.mport; set meta.role,6 (ARM); set meta.gen_in,gen
Ingress.synth_ack     : set meta.sess,1 (RELAY); set meta.mport; set hdr.eth.etype,35014 (0x88C6)
Ingress.synth_resp    : set meta.sess,1 (RELAY); set meta.mport; set meta.role,2 (RESP); set hdr.eth.etype,35015 (0x88C7)
Ingress.synth_none    : set meta.sess,0
```

The ethertype writes are the role stamp that lets a released frame be re-identified after
the dp8 loopback (the generator header, the only thing distinguishing the three identical
copies, is stripped at the ingress deparser). **A held frame in this build is therefore
NOT byte-preserved** — two bytes of ethertype are rewritten. Byte preservation is a
property of the live build, where no MAU action writes any byte of any host frame, and
Gate 2 makes no byte-identity claim.

0x88C6 / 0x88C7 are fresh values in this tree: 0x88C1 is the blocker token, 0x88C5 is
`case_a_dual_min`.

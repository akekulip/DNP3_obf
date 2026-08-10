# Resource and stage optimization audit — Defense 4 Case-A timing core

**Workstream:** resource and stage optimization for size/timing co-residency
**Date:** 2026-08-10 · **Compiler:** `/home/philip/bf-sde-9.13.1/install/bin/bf-p4c`, `p4c 9.13.1 (SHA: e558d01)`
**Silicon contact:** none. Every number below comes from a compile run in this session, in
`/home/philip/Projects/DNP3/research/size_timing_coresidency/evidence/scratch/`.
Nothing under `defense4/`, `defense3/` or `research/stage_reclamation/` was modified.

---

## 0. Headline

Three findings, in order of how much they change the plan.

1. **The binding constraint named in the brief is not this program's binding constraint.**
   The "tagalong at 7 of 8 collections, 16-bit 83.3 %, 32-bit 84.4 %" figure belongs to
   `p12_combined.p4`, a **different program** from the one that is live. I recompiled both. The
   live core, `defense4/timing/p4/defense4_caseA.p4`, sits at **4 of 8 tagalong collections,
   16-bit 50 %, 32-bit 40.6 %** — four collections completely free. Tagalong is not the wall here.

2. **A size axis fits on the live timing core at zero ingress cost — measured, not projected.**
   Grafting the full 14-class egress size normalizer onto the live core compiles with 0 errors at
   **12 ingress / 2 egress stages**, and the ingress table placement is **identical to the
   baseline, stage for stage** (`[9,11,5,3,1,6,2,6,16,16,16,16]`, 107 tables). The ingress
   assembly differs from the baseline only in physical RAM row/bus assignment — 4 non-physical
   diff lines, all of them filenames and one TCAM row index.

3. **12 ingress stages is not a hard floor.** Two independent probes reached **11**: deleting the
   telemetry bank and all counters (an upper-bound forensic probe, not shippable), and — more
   surprisingly — *adding* one ingress table keyed on `hdr.ipv4.total_len`. The best combined
   result measured is **C1: 11 ingress / 2 egress, 0 errors**, carrying the complete timing core,
   an ingress size-plan hook, and the complete egress size normalizer.

**Verdict on the question I was asked (deliverable 5): a size axis that fires on
`data_offset = 8` traffic fits.** It fits at zero ingress stage cost, and the premise that it
needs "+13 length classes per `data_offset` value" is itself false — `data_offset` does not
belong in the key at all, which the prior campaign already measured and which I re-verified.

---

## 1. Measured baseline of the current timing core

### 1.1 Which program is live, and the p12 discrepancy — stated plainly

The brief asked me to say plainly if the p12 numbers came from a different program. **They did.**

| | live timing core | prior-campaign reference |
|---|---|---|
| file | `defense4/timing/p4/defense4_caseA.p4` | `research/stage_reclamation/variants/p12_combined/p12_combined.p4` |
| sha256 | `1242ca4d68e78430587b01c15f69befa9d7bd33c57a11445579773389ba33127` | `c43409c82e932b6be19ddbee03a90f80ae9a564ee3870c38490c30bb1598112b` |
| lines | 2 994 | 926 |

The live sha matches the one recorded in
`defense4/timing/evidence/EXPERIMENTAL_EVIDENCE_FREEZE.md:13` ("P4 source
`defense4/timing/p4/defense4_caseA.p4`, sha256 `1242ca4d…`"), so the file on disk is the source
of the deployed binary. Note that `defense4/timing/evidence/caseA_placement_facts.txt:1` records
an **older** commit (`65a4ced`, sha `711303656099…`, 94 tables, SRAM 47 / mapRAM 42 / TCAM 10 /
SALU 13 / Stats 8) — those numbers are stale relative to the current file and should not be
quoted.

Both programs were recompiled by me in this session under the same compiler. My p12 recompile
reproduces the prior campaign's numbers exactly (8/2 stages, 48 tables, 7 of 8 tagalong
collections, 16-bit 83.3 %, 32-bit 84.4 %), which validates the method before I use it on the
live core.

### 1.2 The baseline numbers

Source: `evidence/scratch/baseline_caseA/`, `bf-p4c --target tofino --arch tna -g`, exit 0,
0 errors, 2 warnings (`compile.log:1-6`).

| quantity | value | source |
|---|---:|---|
| ingress MAU stages | **12** of 12 | `baseline_caseA/build/pipe/logs/table_summary.log:3` |
| egress MAU stages | **0** of 12 | `table_summary.log:4` |
| critical path (table dependency graph) | **10** | `table_summary.log:5` |
| logical tables | **107** | `table_summary.log:6` |
| SRAM | 47 | `mau.resources.log:25` |
| map RAM | 42 | `mau.resources.log:25` |
| TCAM | 10 | `mau.resources.log:25` |
| stateful ALUs (Meter-ALU column) | 12 | `mau.resources.log:25` |
| Stats ALUs | 9 | `mau.resources.log:25` |
| gateways | 67 | `mau.resources.log:25` |
| VLIW instructions | 69 | `mau.resources.log:25` |
| action-data bus bytes | 50 | `mau.resources.log:25` |
| ingress parser states / TCAM rows | 19 / **103** of 256 | `.bfa` parser section; `metrics.json` |
| egress parser states / TCAM rows | 5 / 8 of 256 | same |
| ingress / egress deparser FDE entries | 26 / 12 | `metrics.json` |
| ingress MAU latency | 248 cycles | `metrics.json` |

**Normal PHV** (`phv_allocation_summary_0.log:465ff`) — containers occupied 8 b 18, 16 b 14,
32 b 19; overall 51 of 224 containers (22.8 %), 913 of 4096 bits (22.3 %). That aggregate is
misleading. The real picture is per MAU group:

| MAU group | containers | bits used | bits allocated |
|---|---|---|---|
| **B0-15** (ingress 8 b) | **16 of 16 (100 %)** | 116 of 128 (90.6 %) | 124 (96.9 %) |
| B16-31 | 2 (12.5 %) | 4 | 4 |
| H0-15 (ingress 16 b) | 13 of 16 (81.2 %) | 176 of 256 | 184 |
| **W0-15** (ingress 32 b) | **16 of 16 (100 %)** | **512 of 512 (100 %)** | 736 (144 %, i.e. overlaid) |
| W32-47 | 3 (18.8 %) | 96 | 104 |

**Tagalong PHV** (`phv_allocation_summary_0.log:494ff`) — 8 b 8 of 32 (25 %), 16 b 24 of 48
(50 %), 32 b 13 of 32 (40.6 %), 864 of 2048 bits (42.2 %), **4 of 8 collections occupied**
(0 and 2 ingress, 1 and 3 egress; 4, 5, 6, 7 empty).

---

## 2. Stage and resource map: what is pinned and why

### 2.1 The shape of the pipeline

Ingress tables per stage (from `table_dependency_summary.log`, gress-labelled):

```
stage:   0   1   2   3   4   5   6   7   8   9  10  11
tables:  9  11   5   3   1   6   2   6  16  16  16  16
LTID%:  56  69  31  19   6  38  12  38 100 100 100 100
gates:   7   7   2   2   0   5   0   4  16   9   4  11
```

Two regimes, and they are qualitatively different:

- **Stages 0–7 — the dependency chain.** 43 tables in 8 stages (average 5.4, peak 11) against a
  capacity of 16 per stage. Nothing is capacity-limited here; the depth is serialization.
- **Stages 8–11 — the tail.** 64 tables in 4 stages, **every one of those stages at 16 of 16
  logical table IDs**. This is capacity, not dependency: not one table in the tail is pinned
  (`min == max`); their placement ranges are `[7,10]`, `[7,11]`, `[8,11]`. The compiler needed
  4 stages because 64 tables cannot fit in fewer at 16 LTIDs per stage.

Exactly one table in the whole program is pinned, and it is pinned trivially: `Ingress.tbl_params`
with range `[-,-]` (no key). **Every other table has placement freedom.**

### 2.2 The chain, named

The compiler's own longest chain (`table_dependency_summary.log`, "Table dependency chains") is
10 deep, and maps onto the source like this:

| depth | table (source line) | what it is | safety property |
|---|---|---|---|
| 0 | `tbl_params`, `tbl_session` | runtime D / read_len / budget; 5-tuple session lookup | session isolation |
| 1 | `…2315/2318/2321` | `meta.pkt_class` decode | classification |
| 2 | `…2382/2384` — `exp_ack_w` / `exp_ack_r` | the EXP_ACK tracker SALU | ACK identity |
| 3 | `tbl_resp_authorise` | RESPONSE authorization | response authenticity |
| 4 | `…2401/2405/2411/2422/2424/2427` — `reg_tag` | **the generation register** | **generation safety** |
| 5 | `tbl_state_decode`, `tbl_txn_active` | the single verdict decode | — |
| 6 | `…2446/2448` `reg_deadline`, `…2455/2457` `reg_tresp`, `…2467/2473` `reg_ack_rel` | the two deadlines + ACK-release generation | the deadline |
| 7 | `tbl_deadline_expiry`, `tbl_tresp_expiry` | release decision | release correctness |
| 8 | ACT block (queue assign / forward / drop / budget) | TM decisions | — |
| 9 | `…2845/2846/2847` — `ts_*_w` | **telemetry timestamps** | none |

Note the last link: **the deepest node on the critical path is a telemetry register, not a safety
mechanism.** Deleting the timestamp bank drops the critical path from 10 to 9
(`L1_no_ts/build/pipe/logs/table_summary.log:5`). The safety chain proper is 9 deep.

### 2.3 Genuine dependency vs packing outcome — verified for the current program

The prior campaign's conclusion ("tail is packing, head is a real dependency chain that IS the
generation-safety property") **still holds in shape but has changed in kind**, and the change
matters:

- **Head (0–7): still a genuine dependency chain.** Each state register's write driver is
  computed from the previous register's read. Confirmed by the compiler's chain listing above and
  by the fact that the head runs at 19–69 % LTID occupancy — it is not competing for capacity.
- **Tail (8–11): still a packing outcome, but now a *capacity-bound* one, not a spread.** In
  Part 12 the tail was slack (the allocator "simply spread out"). Here the tail is at 16/16 LTIDs
  in all four stages. That is a different failure mode and it changes which levers work.
- **The head is one stage looser than the compiler chose.** Measured, §4.3: a packing exists that
  puts the head in 7 stages instead of 8.

---

## 3. Reclamation levers, ranked by measured saving per unit of risk

All rows are real compiles in `evidence/scratch/`. `Δ ig` is against the 12-stage baseline.

| # | lever | Δ ig | Δ crit | Δ tables | shippable? | safety property touched | evidence |
|---|---|---:|---:|---:|---|---|---|
| **A** | **egress-side size axis** (add the whole normalizer) | **0** | 0 | 0 ingress (+3 egress) | yes | none — ingress assembly semantically identical | `S1_egress_size/` |
| **B** | **allocator perturbation** — one extra ingress table keyed on a parser-produced header field | **−1** | 0 | +1 | yes but fragile | none | `I1_one_ingress_table/` |
| **C** | delete telemetry bank (10 ts registers, 10 call sites) | **0** | −1 | −4 | no (deletes release-time evidence) | none, but destroys the instrument | `L1_no_ts/` |
| **D** | delete all 36 `ctr_fresh`/`ctr_deq` call sites | **0** | 0 | −13 | no (destroys the counter evidence base) | none, but destroys the instrument | `L2_no_counters/` |
| **E** | **C + D together** | **−1** | −1 | −19 | no | as above | `L3_no_ts_no_counters/` |

### 3.1 The overlap question, re-tested rather than inherited

The brief said to budget levers as `max(lever)`, not `sum(lever)`, and to test that rather than
assume it. **Tested. For this program the relationship is neither `max` nor `sum` — it is a
threshold.**

- C alone: 12 → **12**. Zero.
- D alone: 12 → **12**. Zero.
- C + D: 12 → **11**. One stage.

Neither lever is individually sufficient; together they cross a capacity threshold. This is what
"overlap" looks like when the binding resource is a per-stage *capacity* rather than a dependency
edge: you need to free enough logical table IDs to collapse one whole tail stage, and partial
credit buys nothing. **The measured exchange rate is ≈19 logical tables per ingress stage** at
this point in the packing (107 → 88 tables bought exactly one stage).

That is the practical budgeting rule for this program: **do not budget in stages, budget in
logical table IDs, and only count a stage when the tail drops below a multiple of 16.**

### 3.2 Lever B, and an honest warning about it

Adding a single ingress table — 32 exact entries keyed on `hdr.ipv4.total_len`, two trivial
actions, applied at the end of the ACT block — moved the program from **12 to 11 ingress
stages** (`I1_one_ingress_table/build/pipe/logs/table_summary.log:3`), with 108 tables (one more
than baseline) and the critical path unchanged at 10.

The head collapsed from 8 stages to 7: the `reg_failopen` block, which the baseline allocator put
alone in stage 3, co-resides with `tbl_build_cand` in stage 2, and everything downstream shifts
up one.

**This is an allocator outcome, not a structural improvement, and it is key-sensitive.** Control
experiment `I2_key_variant/`: the *same* table with the *same* size and actions, keyed on
`meta.pkt_class` (a level-1 metadata byte) instead of `hdr.ipv4.total_len` (a parser-produced
header field available from stage 0), compiles back at **12** stages
(`I2_key_variant/build/pipe/logs/table_summary.log:3`).

So: the 11-stage packing is real and reachable, and it proves 12 is not a hard floor. It is not a
design guarantee. Any future edit can flip it back, and it must be re-measured after every change
rather than assumed. Placement on this target is not monotonic in program size.

### 3.3 Levers that were checked and do not exist here

- **Parser offload of head metadata** — already fully exploited. The live parser computes
  `role`, `dir`, `dequeued`, `fwd_port`, `port_ok`, `gen_in` (`defense4_caseA.p4:851-853`
  states this explicitly). There is no stage-0 metadata producer left to move, and with a
  critical path of 10 against 12 stages the head is not the binding constraint anyway.
- **Egress telemetry offload as a stage lever** — deletion bounds it at zero (lever C), which is
  the same conclusion the prior campaign reached, now re-measured on the current program. It
  remains worth doing for ingress SRAM/Stats-ALU headroom: lever C alone takes SRAM 47 → 31,
  map RAM 42 → 26, stateful ALUs 12 → 8, Stats ALUs 9 → 5.
- **Packed transaction state** — the P1 lever that bought Part 12 four stages is not available in
  the same form: this program's head is already only 8 stages against a 10-deep critical path,
  and its 32-bit ingress group (W0-15) is at 16/16 containers and 512/512 bits, which is exactly
  the condition the prior campaign's three SALU rejections came from
  (`SIZE_CORESIDENCY_VARIANT_MATRIX.md:127-134`). I did not build it; I am flagging it as
  high-cost, not as refuted.

---

## 4. The tagalong budget

### 4.1 How much the timing core actually holds

Attributed from `phv_allocation_summary_0.log` by container:

| | containers | bits | share of the 2048-bit tagalong file |
|---|---:|---:|---|
| **ingress** (`eth`, `ib`, `ipv4`, `tcp`, `tcp_opt4/8/12`, `dnp3_dl/tp/app`, 2 `ig_intr_md` slices) | 25 | **488** | 23.8 % |
| **egress** — `eth` only, plus compiler-inserted `min_parse_depth_padding_0[0..2]` | 20 | 376 | 18.4 % |
| of which the auto-inserted min-parse-depth padding | 15 | **264** | 12.9 % |
| **total** | 45 | 864 | 42.2 % — **4 of 8 collections** |

Two things are worth naming:

1. **The timing core's own tagalong footprint is 488 bits, in 2 collections.** That is the whole
   cost of carrying Ethernet + IPv4 + TCP + TCP options + the DNP3 headers + the internal blocker
   token through ingress.
2. **264 bits of the egress tagalong are compiler padding for an egress that does nothing.** The
   live egress parser extracts only Ethernet (`defense4_caseA.p4:2940-2943`), which is below
   Tofino-1's minimum parse depth, so bf-p4c inserts three padding header-stack entries.
   I checked whether a deeper egress parser makes that padding disappear: **it does not.** In the
   size-graft build the padding still occupies 264 bits (12 containers instead of 15). So this is
   a fixed egress overhead, not something the size axis can recover.

### 4.2 What the size axis costs in tagalong — measured

| variant | tagalong 8 b | 16 b | 32 b | bits | collections |
|---|---:|---:|---:|---:|---:|
| baseline (timing only) | 8 (25 %) | 24 (50 %) | 13 (40.6 %) | 864 (42.2 %) | **4** |
| + egress reconstruction parser only, no table, no pads (`S0`) | 15 | 35 | 24 | 1448 (70.7 %) | **6** |
| + full 14-class normalizer (`S1`) | 16 (50 %) | 34 (70.8 %) | 24 (75 %) | 1440 (70.3 %) | **6** |
| + 33 contiguous classes (`SW_33`) | 20 | 38 (79.2 %) | 24 | 1536 (75 %) | **7** |
| + 62 contiguous classes, split table (`SP63_split2`) | 20 | 38 | 24 | 1536 (75 %) | **7** |
| *(reference)* p12_combined | 15 | 40 (83.3 %) | 27 (84.4 %) | 1608 (78.5 %) | 7 |

Three measured facts:

- **The ingress tagalong footprint is invariant.** 25 containers / 488 bits, collections 0 and 2,
  in every single variant including the widest. The size axis touches only egress.
- **The cost is the reconstruction parser, not the pads.** `S0` (parser and deparser only, no
  table, no pad headers) already costs +2 collections and +584 bits; adding the whole table and
  all 14 pad actions on top costs *less than nothing* in 16-bit containers (35 → 34). The
  `pad*` headers are all constant zero, so bf-p4c overlays every one of them into a single 8-bit
  container (`B16`, holding `pad8`, `pad16`, `pad32`, `pad64` slices) — they are effectively free.
- **Headroom after a shipped 14-class size axis: 2 of 8 collections.** After a 33-class version:
  1 collection.

### 4.3 Can tagalong pressure be relieved by restructuring?

The brief asked specifically about re-parsing rather than carrying, egress-side reconstruction,
and narrower containers. Measured answers:

- **Egress-side reconstruction is what the size axis already is**, and it is the thing that costs
  the tagalong. Moving *more* work to egress increases tagalong; it does not relieve it.
- **Narrower containers do not apply.** The occupied ingress collections (0 and 2) are at 100 %
  on their 16-bit and 32-bit containers because they hold whole header fields at their natural
  widths. There is no sub-word packing available: tagalong containers are never written by the
  MAU, so no packing trick from the state-packing playbook transfers.
- **The genuine relief, if it is ever needed, is deleting carried headers.** `tcp_opt4/8/12`
  cost 7 containers and are declared "NEVER read in the MAU" (`defense4_caseA.p4:696-700`); they
  exist only so the deparser can re-emit them. `dnp3_dl/tp/app` cost 10 containers and are used
  for classification. Neither is currently under pressure, so I did not price their removal.

**Bottom line on tagalong: it is not the wall for this program, and the brief's premise that it
would be is inherited from a different program.** With a full size axis in place there are still
two free collections.

---

## 5. Feasibility verdict for a size axis on `data_offset = 8` traffic

### 5.1 The premise in the brief is wrong, and the prior campaign already proved it

The brief states the fix direction is "extending chunk classes across `data_offset` values,
roughly +13 length classes per value". `research/stage_reclamation/variants/p13_size_do8/compile_note.md`
records the actual measured fix, and it is the opposite of an enumeration:

> the egress parser select was keyed on `(tcp.data_offset, ipv4.total_len)` … **drop
> `data_offset` from the select key**

The chunk states consume `total_len − 40` bytes — every byte of the IP datagram after the fixed
20-byte TCP base header, an arbitrary mixture of TCP option bytes and payload. That count is a
function of `total_len` alone. **One class set covers every `data_offset` value with no new state,
no new header, no new action and no new tagalong byte.** So the cost the brief anticipated does
not exist.

### 5.2 The decisive compile

`S1_egress_size` = the live `defense4_caseA.p4` with the p13-shape egress normalizer grafted on
(14 `total_len` classes covering 2 104 / 2 104 packets of the measured corpus, all at
`data_offset = 8` and 10). **0 errors, 3 warnings, exit 0.**

| | baseline | S1 (+ size axis) | Δ |
|---|---:|---:|---:|
| ingress stages | 12 | **12** | **0** |
| egress stages | 0 | **2** of 12 | +2 |
| critical path | 10 | **10** | 0 |
| **ingress tables per stage** | `9 11 5 3 1 6 2 6 16 16 16 16` | **identical** | **0** |
| ingress logical tables | 107 | **107** | **0** |
| egress logical tables | 0 | 3 (stages 0–1) | +3 |
| ingress B0-15 / W0-15 | 16/16, 16/16 | **16/16, 16/16 — unchanged** | 0 |
| ingress tagalong | 25 containers / 488 b | **25 / 488 — unchanged** | 0 |
| tagalong collections | 4 | 6 | +2 |
| egress parser TCAM rows | 8 | 60 of 256 | +52 |
| SRAM | 47 | 57 | +10 |
| Stats ALU | 9 | 11 | +2 |

**Machine-checked equivalence of the ingress.** Extracting the `phv ingress`, `parser ingress`,
`deparser ingress` and all twelve `stage N ingress` blocks from both `.bfa` files and
canonicalising only the compiler-generated names (which embed the program name and source line
numbers), the diff is **98 lines, of which 94 are `row` / `bus` / `unit` / `home_row` / `column`
physical assignments** and the remaining 4 are the two sidecar filenames and one TCAM row index
(`ternary_match tbl_PROG2259 8` → `9`). Every table, action, VLIW instruction, gateway
expression and next-table pointer is identical. The same check against the 33-class build gives
the same result.

One caveat worth stating: Tofino-1's 16 logical table IDs per stage are a **shared** pool across
gresses — the egress size tables land in stages 0 and 1, where ingress occupies 9 and 11 of 16.
That is the reason this is free. It would not be free if the size axis needed to place tables in
stages 8–11, which are at 16/16.

### 5.3 Coverage headroom, and where the next wall is

Bisected with contiguous `total_len` classes (every class distinct, so class count = action
count), all on the live core:

| contiguous classes | `total_len` range | result |
|---:|---|---|
| 14 (the ship set) | scattered | **fits** — 12 / 2 |
| 32 | 83–114 | **fits** — 12 / 2 |
| **33** | **82–114** | **fits** — 12 / 2, tagalong 7 of 8, egress parser 161/256 rows |
| **34** | **81–114** | **FAILS** |
| 35, 36, 40, 63, 75 | wider | FAILS, same error |

The wall, verbatim from `SW_34/compile.log:9`:

```
error: SW_34.p4(3088): Could not place table Egress.size_norm:
       The table size_norm_0 could not fit within the instruction memory
```

**It is instruction memory, and it is soft.** Splitting `size_norm` into two tables applied in
series clears it: `SP63_split2` carries **62 contiguous classes** (`total_len` 52–113, i.e. every
IPv4/TCP/`ihl=5` frame in that range at any `data_offset`) and compiles at **12 ingress / 3
egress, 0 errors**, ingress placement still `[9 11 5 3 1 6 2 6 16 16 16 16]`.

At that width the next wall becomes visible: **egress parser TCAM rows, 243 of 256 (95 %)** and
176 egress parser states. Roughly 65 contiguous classes is the practical ceiling for this
parser shape before the egress parser TCAM runs out.

### 5.4 The best combined result

`C1_combined` = live timing core + one ingress size-plan hook table + the full 14-class egress
normalizer: **11 ingress / 12, 2 egress / 12, critical path 10, 111 logical tables, 6 of 8
tagalong collections, 0 errors** (`C1_combined/build/pipe/logs/table_summary.log:3-6`).

So the co-residency budget, measured end to end, is: **one free ingress stage, ten free egress
stages, two free tagalong collections.**

### 5.5 What this does and does not establish — the honest boundary

- It establishes the **resource shape** of an *append/emit*-style size axis: an egress
  reconstruction parser, power-of-2 chunk headers, and one class table with a `setValid`-subset
  action per class. That shape co-resides with the timing core at zero ingress cost.
- It does **not** revive the mechanism. The trailer-padding mechanism this graft transplants was
  falsified on silicon 2026-07-25 — it pads below IP, so `ip.len` is untouched and an observer
  simply reads `ip.len`. I used it as a resource probe only.
- The charter's two live candidates have **different** resource shapes, and one of them lands in
  the wrong place:
  - **CROB-based padding** — inert volume added *inside* the DNP3 application layer. Resource
    shape is close to what I measured (egress emit of extra bytes) but requires TCP sequence
    translation, which is per-flow ingress state, i.e. it lands on the saturated ingress tail
    and on the exhausted W0-15 group. **Not priced here.**
  - **CRC-boundary splitting** — requires producing *several* frames from one, which on Tofino-1
    means ingress mirroring or multicast replication plus per-copy truncation. That is ingress
    work, in stages 8–11, which are at 16 of 16 logical table IDs. **This is the one place where
    the "zero ingress cost" result does not transfer**, and it should be priced with its own
    compile before any design commits to it. The `I1` probe shows one extra ingress table can be
    absorbed (and here even helps), but a replication path is more than one table.

---

## 6. Reproduction

```bash
cd /home/philip/Projects/DNP3/research/size_timing_coresidency/evidence/scratch
python3 mkvariants.py S1          # and S0 / SW <lo> / L1 / L2
cd <variant> && /home/philip/bf-sde-9.13.1/install/bin/bf-p4c \
      --target tofino --arch tna -g -o build <variant>.p4
python3 ../summarize.py build <variant>
```

`summarize.py` reads only compiler-produced logs (`table_summary.log`, `mau.resources.log`,
`metrics.json`, `phv_allocation_summary_0.log`, `table_dependency_summary.log`).

### Source hashes

| variant | sha256 |
|---|---|
| `defense4_caseA.p4` (live, unmodified) | `1242ca4d68e78430587b01c15f69befa9d7bd33c57a11445579773389ba33127` |
| `p12_combined.p4` (reference recompile) | `c43409c82e932b6be19ddbee03a90f80ae9a564ee3870c38490c30bb1598112b` |
| `S0_egress_parse_only.p4` | `25b0095a3b9d28fdfb0f04a3cad6670f1de35250f3e017a1df48cfa95cbd3e7d` |
| `S1_egress_size.p4` | `39ed3665a6189da9c6db9d137840251587d9804cc52a24a1060a42928f2c24a4` |
| `SW_33.p4` (fits) | `1f4b2353b827c1fc2b0c65e0fc53ea3d45e74161d2cc07099e6655f2f532c7a2` |
| `SW_34.p4` (fails) | `04bb2ce7a2020c589d0b49661b601d4fa3ed58f56c70847125dc079fc933880f` |
| `SP63_split2.p4` | `5d6f4d13233eac843af38b0b002fd533f35f271433813a3e077f53b1861d7d13` |
| `L1_no_ts.p4` | `fd1f9f8dc57750ace78bdabfa06870a0335f594f0907c706f1aa9cc7aa539d34` |
| `L2_no_counters.p4` | `49ce59bf506b4b775fae6f7d5942d4d0bc86d0ed71123c9814ed70e69af78926` |
| `L3_no_ts_no_counters.p4` | `26427f964b257d595e5f659273a801e3e09049b236adc418fc8402619eb1917d` |
| `I1_one_ingress_table.p4` | `e7180c7bd8d08e61c7ba0da77ba98d98393727af0dad121b1e2d46caa604e62b` |
| `I2_key_variant.p4` (control) | `56ed1518127622865ab0d6b4780120b317d878c01f8d66bef546c89cce859289` |
| `C1_combined.p4` | `347544479dac87f18cfd8a0adb65d4a05d7b81599ceb6945b77671697cddcc77` |

### Scope

Compile-only. Nothing was loaded, no switch was contacted, and no functional or defensive claim
is made about any variant. `L1`/`L2`/`L3` are forensic deletion probes that destroy the
telemetry and counter evidence the gates depend on; they are upper bounds, not candidates.
`I1`/`I2`/`C1` contain a semantically inert probe table. `S0`/`S1`/`SW_*`/`SP63` transplant a
mechanism that is falsified as a defense and are resource measurements only.

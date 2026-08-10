# Resource budget — fixed-transcript defense on the Tofino-1 live timing core

**Baseline:** the measured live Defense-4 Case-A timing core (`defense4/timing/p4/defense4_caseA.p4`
at commit `7c4a5a7`), as reported in `research/size_timing_coresidency/reports/p4-resource-audit.md`
(bf-p4c 9.13.1, compile-only, no silicon). All baseline numbers below are that report's measured
values; all deltas are either that report's measured grafts or, where a graft was not compiled,
reasoned from it and **labelled projected**.

**This budget is deliberately not reduced to an ingress-stage count.** The two binding resources on
this program are (1) the **ingress tail stages 8-11, all at 16/16 logical table IDs**, and (2) the
**32-bit ingress PHV group W0-15 at 16/16 containers and 512/512 bits** (and the 8-bit group B0-15
at 16/16 containers). A change that adds zero ingress stages can still be infeasible if it needs a
logical-table ID in the tail or a 32-bit ingress field. Conversely, egress is almost empty and
absorbs a large amount of work for free. The budget is expressed in the compiler's own categories.

---

## 1. Measured baseline (what is already spent)

| Category | Baseline (live core) | Headroom fact |
|---|---:|---|
| Ingress MAU stages | 12 / 12 | full, but critical path is only 10 |
| Egress MAU stages | 0 / 12 | **12 free** |
| Critical path (table dep graph) | 10 | 2 slack vs stage count |
| Ingress logical tables | 107 | tail stages 8-11 at **16/16 LTIDs each** |
| Egress logical tables | 0 | 16 LTIDs/stage free across egress |
| SRAM (of 480) | 47 | ample |
| map RAM | 42 | ample |
| TCAM | 10 | ample |
| Stateful (Meter) ALUs | 12 | of ~ per-stage limit; head is looser than tail |
| Stats ALUs | 9 | a few free (size-axis graft reached 11) |
| Gateways / VLIW / action-data-bus B | 67 / 69 / 50 | not binding |
| Ingress parser states / TCAM rows | 19 / **103 of 256** | ~150 rows free |
| Egress parser states / TCAM rows | 5 / **8 of 256** | **~248 rows free** |
| Ingress / egress deparser FDE | 26 / 12 | not binding |
| Ingress MAU latency | 248 cycles | not binding for a ms-scale defense |
| **PHV B0-15 (8-bit ingress)** | **16/16 containers (100%)**, 116/128 b | **exhausted (container-bound)** |
| PHV H0-15 (16-bit ingress) | 13/16 containers | 3 containers free |
| **PHV W0-15 (32-bit ingress)** | **16/16 containers (100%), 512/512 bits (100%)** | **exhausted** |
| PHV W32-47 (upper 32-bit) | 3/16 | free but not MAU-addressable the same way |
| Tagalong PHV collections | **4 of 8** (ingress 0&2, egress 1&3) | 4 collections free |

**Two grafts already measured on this exact core, reused below as evidence:**

- **Egress size axis (`S1`)** — a 14-class egress reconstruction/emit: **+0 ingress stages, +2
  egress stages, +3 egress tables (stages 0-1), +52 egress parser TCAM rows (8->60), SRAM +10,
  Stats ALU +2, tagalong 4->6 collections; ingress placement byte-for-byte identical, B0-15 and
  W0-15 unchanged at 16/16.** This is the template for the transcript's per-cell outer-header
  stamping: egress emit work is free of ingress cost.
- **One extra ingress table (`I1`/`I2`)** — a single 32-entry table with two trivial actions:
  keyed on a **parser-produced header field** it went 12->**11** ingress (an allocator win, fragile,
  non-monotonic); keyed on an **early metadata byte** (`meta.pkt_class`) it stayed at **12**
  (absorbed, no new stage). This brackets the cost of the transcript's ingress cell-class ->
  {qid, egress_port} table: **expected absorbed at 12/12, possibly 11, must be re-measured.**

---

## 2. TM / PRE / pktgen inventory (non-MAU resources)

These are the resources the fixed transcript actually spends most heavily. None is scarce except
pktgen apps (shared with D4) and the cadence quality of the shaper (a behavior, not a count).

| Resource | Hardware ceiling (TF1) | Spent by D4 today | Transcript needs (one-size lane A) | Verdict |
|---|---|---|---|---|
| **Queues per port** | 32 addressable (5-bit qid); carving-dependent | qid4-7 **on dp8 (loopback)** | +2 **on the WAN port** (real=HIGH, chaff=LOW) | free; keep OFF dp8's flat scheduler |
| **Physical / loopback ports** | pktgen ports pipe-local 68-71; loopback via `$LOOPBACK_MODE` | dp8 loopback + dp68 pktgen/recirc | +0 (reuse WAN egress + dp8 + dp68); +1 internal port only for multi-size Ditto | free for one size |
| **Mirror sessions** | 1024 (`MirrorId_t` = 10 bits) | session 7 | +0-1 | ample |
| **Multicast groups** | 64K (`mgid` 16-bit); large node table | 0 (D4 uses mirror+recirc) | +0 (lane A); +1 group + K nodes only if a K-cell fan-out burst is used | ample |
| **pktgen apps** | **8 per pipe** (`app_id` 3-bit) | recirc-pattern app(s) for the 128-cell reservoir seed | **+1** (periodic-timer chaff clock) or reuse a recirc ring | **budget carefully — shared 8-app pool** |
| **pktgen packet buffer** | ~16 KB/pipe, shared | reservoir template | +1 cell template (tiny) | ample |
| **Input buffer 17** | shared by pktgen + recirc | D4 recirc ring | high-rate chaff contends here | **priced coupling** |
| **Packet buffer** | ~20 MB in ~80-B cells (exact cell size & per-queue admission thresholds are TM-carving/SDE-dependent — verify) | D4 hold + reservoir cells | see Section 4 | ample |

---

## 3. Incremental MAU cost per scheduler family

Deltas are **against the 12/12 baseline**. "Lands in" names the binding-resource zone each item hits.

### Family A — continuous constant-rate, one size (RECOMMENDED)

| Category | Δ | Lands in | Note |
|---|---:|---|---|
| Ingress stages | **+0 expected** (possibly -1 or +1) | head stages 0-7 (loose) if class byte is early | I2 evidence: early-keyed classify absorbed at 12; re-measure |
| Ingress logical tables | +1 to +2 (cell-class -> {qid, egress_port}) | head LTIDs (19-69% used) if placeable there | if forced into tail (16/16) it costs a stage — the real risk |
| **New 32-bit ingress field / register** | **0 (design constraint)** | would hit **W0-15 (exhausted)** | **Family A adds NO 32-bit ingress state — this is why it fits** |
| New 8-bit ingress field (cell-class) | +1 byte | **B0-15 (exhausted, 16/16)** | **reuse/fold into an existing 8-bit field** (D4's -2/+2 trick) or widen to 16-bit (H0-15 has 3 free) |
| Egress stages | +1 to +2 | egress (0/12 free) | per-cell outer-header stamp = the S1 template, ingress-free |
| Egress tables | +1 to +3 | egress stages 0-1 | RID- or class-keyed outer-header/format |
| Egress parser TCAM | +0 to ~+52 | egress parser (8/256, ~248 free) | only if the cell is reconstructed like S1 |
| Stateful ALUs | +0 | — | scheduling is qid + shaper (control-plane), no register |
| Stats ALUs | +1 to +2 (chaff-emit / real-preempt counters, one indexed array) | 9 -> ~10-11 | within headroom |
| pktgen apps | +1 (periodic clock) or reuse recirc ring | 8-app pool | shared with D4 |
| Queues / buffer | +2 queues on WAN port; negligible cells | — | free |

**Family A verdict: fits the current core with no ingress-stage cost expected, provided the
cell-class byte reuses an existing 8-bit field (B0-15 is full) and no 32-bit ingress state is
added.** The one item to re-measure is whether the cell-class classify table places in the head or
is forced into the 16/16 tail. Everything cadence-related is a TM behavior, not an MAU cost.

### Family B — request-synchronized epochs (D4 timing + fixed-epoch size normalization)

| Category | Δ | Lands in | Note |
|---|---:|---|---|
| Timing engine | +0 | already the live core | it *is* D4 |
| Egress emit of the fixed epoch shape | free of ingress (S1 template) | egress | measured |
| **Per-flow TCP seq/ack translation** | **+>=1 ingress stage (projected)** | **ingress tail 8-11 (16/16 LTIDs)** and **W0-15 (exhausted)** | the expensive part; per-flow **32-bit** ingress state |
| Stateful ALUs / 32-bit PHV | + (projected) | **W0-15 exhausted** | likely needs reclamation first |
| Reclamation available | lever C: delete telemetry -> SRAM 47->31, SALU 12->8, Stats 9->5, crit path 10->9 | frees head capacity | destroys the instrument; forensic only |

**Family B verdict: MUST-BE-PRICED with its own graft compile.** The timing half is free (it exists);
the size-normalization half lands squarely on the two exhausted ingress resources and is the part
the audit explicitly flags as *not* transferring the "zero ingress cost" result. Do not assume it
fits — compile it.

### Family C — Ditto two-pass (multi-size)

| Category | Δ | Lands in | Note |
|---|---:|---|---|
| Loopback port | +1 internal port | ports | required (no L1 layer on TF1) |
| Queues | +2N (one real+chaff pair per size) | per-port queues | N = number of cell sizes |
| pktgen inventory | +N templates / apps | 8-app pool (**hard ceiling**) | N distinct chaff sizes |
| MAU (two passes) | ACT-block breadth + possibly +1 stage per new dependency level | ingress (crit-path == stage count) | loopback itself is 0 stages; new dep levels are not |
| Interaction with D4 timing | **substitutes, not adds** | — | a coarse grid makes D4's 10-stage deadline apparatus dead weight; a fine grid needs ~580 kpps chaff |

**Family C verdict: NEEDS-LOOPBACK, justified only by genuine multi-size, and it competes with D4
timing rather than composing with it.** For one size it collapses to Family A and should not be built.

### Family D — slot-token / calendar

| Category | Δ | Lands in | Note |
|---|---:|---|---|
| Native primitive | none | — | TF1 has no calendar/timing-wheel scheduler |
| Emulation via pktgen periodic apps | +up to 8 apps (one per distinct period) | 8-app pool | coarse; exhausts the app budget fast |
| Emulation via recirc + per-slot deadline register | + SALU + **32-bit** field per slot | **W0-15 (exhausted)** | the D4 deadline idiom, one slot at a time |

**Family D verdict: NOT-SUPPORTED natively; MUST-BE-PRICED as a coarse emulation that spends the
scarce pktgen-app / W0-15 budgets.**

---

## 4. Packet buffer — can it absorb the max protected burst, including the 12,204-byte READ?

**Yes, comfortably.** At ~80-byte cells, the 12,204-byte READ is `ceil(12204/80) = 153 cells
≈ 12 KB` — about 0.06% of a ~20 MB packet buffer (~256k cells). Even holding many transactions
concurrently, or replicating the burst into K chaff cells, stays orders of magnitude under
capacity.

The real limit is **not total capacity but the per-queue / per-PPG admission (tail-drop) threshold**
set in the TM carving, plus the pktgen packet buffer (~16 KB/pipe) which is far too small to *stage*
a large payload — so a large real object must be **split into cells on the fly**, not buffered whole
in pktgen. In the fixed-transcript design the large READ is master->outstation; it is re-celled as
it passes, never resident as a 12 KB blob. Two things to set and verify on silicon, not assume:

1. the WAN-port real-queue and chaff-queue admission thresholds are high enough that a 153-cell
   real burst is never tail-dropped while the chaff queue is also backlogged;
2. `watermark_cells` on the chaff queue reads ~`K - N_f` (Little's-law backlog) confirming the
   chaff ring stays saturated — an under-reading means the chaff queue emptied and the fixed grid
   broke.

**Packet buffer verdict: not a constraint for capacity; the constraint is admission-threshold
configuration and the on-the-fly re-celling of large objects, both of which are config/transport
concerns, not buffer-size concerns.**

---

## 5. Landing-zone summary — where each addition hits

| Addition | Lands in | Free or binding |
|---|---|---|
| Per-cell outer-header stamp, cell formatting, RID-keyed per-copy header | **egress** (0/12 stages, parser 8/256, tagalong 4/8) | **FREE** — the whole reason one-size transcript is cheap |
| Chaff cell parse path | ingress parser (103/256 rows) + already exists for dp68 | free |
| Cell-class -> {qid, egress_port} classify | ingress head LTIDs (0-7, 19-69% used) **if early-keyed**; else the **16/16 tail** | **absorbed if it places in the head; +1 stage if forced to the tail — re-measure** |
| A new 8-bit ingress metadata byte | **B0-15 (16/16, exhausted)** | **binding — must fold into an existing byte or widen to H0-15 (3 free)** |
| Any new 32-bit ingress field/register (Families B, D) | **W0-15 (16/16, 512/512 bits, exhausted)** | **binding — needs reclamation (lever C) or a different design** |
| Stats-ALU validation counters | 9 -> ~11 | free (small headroom) |
| pktgen chaff app | 8-app pool (shared with D4) | budget it |
| Transcript queues | +2 on the WAN port (off dp8's scheduler) | free |

---

## 6. Bottom line

- **Family A (one-size constant-rate lane)** is the only family that fits the current 12/12 core
  without touching the two exhausted ingress resources: its scheduling lives in the TM (qid +
  shaper, control-plane), its per-cell headers live in the free egress, and its only ingress
  addition is a classify table that must reuse an existing 8-bit field and should place in the loose
  head. **Expected +0 ingress stages; re-measure the classify-table placement.**
- **Family B (D4 + fixed-epoch size normalization)** is feasible only after pricing the per-flow TCP
  sequence translation, which lands on the saturated ingress tail and the exhausted W0-15 group and
  is the part the audit says does not inherit the free-egress result. **Compile it before
  committing.**
- **Family C (Ditto multi-size)** needs a loopback and 2N queues and substitutes for D4 timing;
  build it only for genuine multi-size.
- **Family D (calendar)** has no native primitive; emulation spends the scarce pktgen-app / W0-15
  budgets.
- **Packet buffer is never the limit;** the 12,204-byte READ is ~153 cells. The limits are the
  8-app pktgen pool, the B0-15/W0-15 ingress PHV exhaustion, the 16/16 ingress tail, and — the one
  that is not a count at all — the shaper's low-rate cadence quality (see TOFINO_TM_FEASIBILITY.md
  §11).

**Feasibility is not the ingress-stage count.** The stage count barely moves for Family A. What
decides feasibility is whether a change needs a logical-table ID in the 16/16 tail, a 32-bit field
in the exhausted W0-15 group, or an 8-bit field in the exhausted B0-15 group — and, above all,
whether TF1's shaper/pktgen can hold a fixed cadence at the chosen cell rate.

# Tofino-1 TM Strict-Priority Scheduler Semantics — SDE Audit

**Scope:** READ-ONLY audit of BF-SDE 9.13.2 TM scheduler semantics on the switch at
`decps@10.10.54.81`, SDE at `/home/decps/Downloads/bf-sde-9.13.2` (SDE_INSTALL = `.../install`).
**Purpose:** Determine whether a prior IBSPG experiment's failure to starve a low queue via
`min_priority=HIGH` on a blocker queue was a **configuration/semantics error** (wrong field / wrong
scheduler model) before drawing any architecture conclusion.
**Nothing was changed on the switch.** All switch commands were `find` / `grep` / `scp` / `cat` on
SDE headers and JSON. The running `bf_switchd` (microbench `ibspg_mb_physL_abs.conf`, PID 12665) was
NOT restarted, no program was bound, no bfrt/bfshell write was issued (confirmed at audit end).

## Primary SDE sources cited (all under SDE_INSTALL)

- **H1** `include/traffic_mgr/traffic_mgr_sch_intf.h` — C scheduler API + doxygen (authoritative).
- **H2** `include/traffic_mgr/traffic_mgr_types.h` — enums (`bf_tm_sched_prio_t`).
- **H3** `include/tofino/pdfixed/pd_tm.h` — lower-level PD API, independent corroboration.
- **H4** `include/traffic_mgr/traffic_mgr_mcast.h` — the ONLY API in the SDE that exposes an explicit
  boolean "strict priority" (PRE multicast input FIFOs — a *different* mechanism, not egress queues).
- **J1** `share/bf_rt_shared/bf_rt_tm_tf1.json` — the fixed (non-P4) bfrt schema that defines the
  runtime tables the prior experiment used (`tf1.tm.queue.sched_cfg`, etc.), with per-field
  descriptions. This is the direct bfrt-name → semantics binding.

A note on citation confidence: **DIRECT** = quoted verbatim from an SDE file; **INFERENCE** =
a conclusion chained from two or more direct citations, flagged as such; **MEASURED** = from the
prior on-silicon microbench (see project memory `tofino1-strict-priority-not-absolute-recirc`), not
from SDE text. I do not fabricate any field name or signature; where the SDE is silent I say so.

---

## Q1 — All schedulable fields of `tf1.tm.queue.sched_cfg` and their documented meaning

**Source J1, table `tf1.tm.queue.sched_cfg` (table_type `TmQueueSchedCfg`), key = `pg_id` (0..17),
`pg_queue` (0..31).** The complete data-field set and verbatim descriptions:

| bfrt field | type | Verbatim description (J1) |
|---|---|---|
| `min_rate_enable` | bool | "Enable token bucket that assures guaranteed (min) rate for the Queue with tm.queue.sched_shaping parameters." |
| `min_priority` | enum string {LOW,0..7,HIGH} | "The queue scheduling priority when serving **guaranteed (min) bandwidth**." |
| `max_rate_enable` | bool | "Enable token bucket that assures max shaping rate for the Queue with tm.queue.sched_shaping parameters." |
| `max_priority` | enum string {LOW,0..7,HIGH} | "The queue scheduling priority when serving **max shaping bandwidth**." |
| `dwrr_weight` | uint16 | "The queue DWRR weight." |
| `scheduling_enable` | bool | "Enable the Queue for scheduling. If disabled, queue will not participate in scheduling." |

**Note `pfc_cos` is NOT in `sched_cfg`.** It lives in `tf1.tm.queue.cfg` (J1): "Non-zero CoS value
set when the egress queue needs to honor received PFC from downstream. The queue will not participate
in scheduling until PFC gets cleared." So PFC is a *hold* input, not a priority selector.

Related rate parameters live in `tf1.tm.queue.sched_shaping` (J1): `min_rate` = "**Guaranteed**
shaping rate", `max_rate` = "**Remaining** shaping rate", plus `min_burst_size` / `max_burst_size`
(see Q9).

**Finding:** there is no single "strict priority" boolean for egress queues. Scheduling behaviour is
the composite of two enable bits (`min_rate_enable`, `max_rate_enable`), two priority enums
(`min_priority`, `max_priority`), one `dwrr_weight`, and `scheduling_enable`. Crucially the two
priority enums are tied to **two different bandwidth-service passes** (Q3).

---

## Q2 — Which field/mechanism produces strict priority among a port's queues

**There is no boolean "strict priority" for egress queues in the SDE.** Strict priority is *implicit*
in the priority-level enums: within a given service pass the scheduler always selects the
highest-priority eligible queue first.

**DIRECT — H1 `bf_tm_sched_q_priority_set` (traffic_mgr_sch_intf.h:40-61):**
> "Set queue scheduling priority. Scheduling priority level used when serving **guaranteed
> bandwidth**. Higher the number, higher the priority to select the queue for scheduling. Default:
> Queue scheduling priority set to BF_TM_SCH_PRIO_7. Related APIs:
> bf_tm_sched_q_remaining_bw_priority_set()."

**DIRECT — H1 `bf_tm_sched_q_remaining_bw_priority_set` (traffic_mgr_sch_intf.h:203-224):**
> "Set scheduling priority when serving **remaining bandwidth**. Higher the number, higher the
> priority to select the queue for scheduling. Default: Queue scheduling priority set to
> BF_TM_SCH_PRIO_7."

**DIRECT — H3 corroboration:** `p4_pd_tm_set_q_sched_priority` (pd_tm.h:1420-1425) = "priority level
used when serving **guaranteed bandwidth**"; `p4_pd_tm_set_q_remaining_bw_sched_priority`
(pd_tm.h:1552-1556) = "scheduling priority when serving **remaining bandwidth**".

**DIRECT — H2 enum `bf_tm_sched_prio_t` (traffic_mgr_types.h:217-228):** 8 levels; `BF_TM_SCH_PRIO_LOW
= BF_TM_SCH_PRIO_0`, `BF_TM_SCH_PRIO_HIGH = BF_TM_SCH_PRIO_7`.

The bfrt equivalents are `min_priority` (→ `bf_tm_sched_q_priority_set`) and `max_priority`
(→ `bf_tm_sched_q_remaining_bw_priority_set`), bound by the identical J1 wording in Q1.

The C API named in the task, `bf_tm_sched_q_max_rate_sched_prio_set`, **does not exist** in this SDE
(grep of `include/traffic_mgr/` returns no such symbol). The real pair is
`bf_tm_sched_q_priority_set` + `bf_tm_sched_q_remaining_bw_priority_set`.

**Finding:** strict-priority arbitration between a port's queues is produced by the priority ENUM
that governs the pass in which those queues are actually competing. When queues are simply backlogged
without a configured guaranteed (min) rate, that pass is the **remaining-bandwidth** pass, governed by
**`max_priority`** (`bf_tm_sched_q_remaining_bw_priority_set`) — *not* `min_priority`. This is the
crux (Q3, Verdict).

---

## Q3 — `min_priority` vs `max_priority`: separate arbitration stages? (THE CRUX)

**Yes — two distinct passes, DIRECTLY documented.**

- `min_priority` (`bf_tm_sched_q_priority_set`) governs selection **"when serving guaranteed
  bandwidth"** (H1:42, H3:1421). "Guaranteed bandwidth" is the min-rate quantum assured by the min
  token bucket, which is enabled by `min_rate_enable` + `min_rate` (J1: `min_rate_enable` = "assures
  guaranteed (min) rate"; `min_rate` = "Guaranteed shaping rate").
- `max_priority` (`bf_tm_sched_q_remaining_bw_priority_set`) governs selection **"when serving
  remaining bandwidth"** (H1:204) / **"max shaping bandwidth"** (J1) — i.e. the excess/unshaped pass,
  bounded above by the max token bucket (`max_rate_enable` + `max_rate` = "Remaining shaping rate").
- `dwrr_weight` breaks ties **"used by queues at same priority level ... share excess or remaining
  bandwidth"** (H1:64-77 `bf_tm_sched_q_dwrr_weight_set`; H3:1444-1447). Default weight 1023
  (H1:69).

**INFERENCE (chained from the above direct citations):** the per-port egress scheduler runs a
two-level work-conserving selection each round:
1. **Guaranteed pass** — among queues that have a configured+enabled min rate and are still within
   that guaranteed rate, pick by `min_priority` (strict), DWRR among equals. Assures each queue its
   min.
2. **Remaining/excess pass** — for bandwidth beyond the guaranteed quanta and up to each queue's max
   shaping rate, among eligible queues pick by `max_priority` (strict), DWRR among equals.

Because both priority enums default to `PRIO_7` (H1:46, H1:208) and DWRR defaults to 1023 (H1:69),
an out-of-the-box queue competes only in the remaining pass at equal priority and equal weight.

**Finding:** `min_priority` and `max_priority` belong to **separate** arbitration stages tied to
**separate** bandwidth quanta (guaranteed vs remaining). They are not two views of one selector.
Setting only `min_priority` changes only the guaranteed-pass ordering — which is inert unless a
guaranteed min rate is enabled.

---

## Q4 — Is strict priority absolute (full starvation), or is there a documented fairness floor?

**SDE text:** documents only strict *preference* — "Higher the number, higher the priority to select
the queue for scheduling" (H1:44, H1:205). **The SDE contains no statement of an anti-starvation /
minimum-service floor for egress queues, and no statement that strict priority is absolute.** (grep
of the whole `include/traffic_mgr/` and `share/` for "anti-star|starv|min-service" finds nothing for
egress queues; the only "strict priority" prose is the PRE multicast FIFO in H4/J1, unrelated.) So on
documented text alone, absoluteness is **unverified — the SDE neither asserts nor denies it.**

What the SDE *does* document is the **eligibility gate** that bounds starvation (Q6): a queue is only
selectable in a pass while it is backlogged AND has token-bucket credit for that pass. A high queue
that exhausts its max shaping credit becomes ineligible, at which point a lower queue is served
(H1:88-176). Absent any max shaping rate, a continuously-backlogged high queue would monopolize the
remaining pass — but only *while continuously backlogged and eligible*.

**MEASURED (project memory, not SDE):** on this silicon, on the **recirculation** port with a
self-looping blocker ring, the low queue was **never** fully starved — it drained at ~1.3–5.3 M
passes/s even with the high queue's cell occupancy saturated (use=126/wm=127, "never observed
empty"). Root cause is sub-microsecond empty-gaps: the blocker ring is fed by its own delayed recirc
dequeues, so the high queue transiently empties and the low queue becomes momentarily
highest-eligible. This is consistent with — not contradicted by — the SDE eligibility model.

**Finding:** strict priority is **not documented as absolute**, and it is **measured non-absolute on
the recirc port** because eligibility (backlog + credit), not a fairness floor, is what a lower queue
exploits. Zero-pass residency of a low queue behind a high queue is therefore not achievable this way
even with correct priority config. (This is the separate, real limitation; it does not excuse the
config error in the Verdict.)

---

## Q5 — Scheduler hierarchy queue → L1 node → port; do qid 1 and qid 7 share a parent by default?

**DIRECT — H2 (traffic_mgr_types.h:55-63):** hierarchy is Port → up to 32 **L1 nodes** per port
group → up to 128 **queues** per port group.

**DIRECT — H1 `bf_tm_sched_q_l1_set` (traffic_mgr_sch_intf.h:366-385):** "Associate queue with l1
node ... **Default: By default, queue is set to schedule with the default l1 node for a port.**"
**H1 `bf_tm_sched_l1_enable` (653-655):** "each port receives an l1 one when a queue is first
allocated to it." Reset via `bf_tm_sched_q_l1_reset` (400-402).

**DIRECT — J1:** the fixed TF1 bfrt schema (33 tables) contains **no `tf1.tm.l1_node.*` table**
(`has l1_node table: False`). L1-node remap and L1 priority are exposed only through the C/PD APIs
(`bf_tm_sched_q_l1_set`, `bf_tm_sched_l1_priority_set`, `bf_tm_sched_l1_remaining_bw_priority_set`),
**not** through bfrt on TF1.

**Finding:** by default, all queues of one dev_port (including qid 1 and qid 7) attach to the **same
single default L1 node**, so they are **siblings in one arbitration domain** — strict priority
between them is meaningful and operates at that L1 node. A bfrt-only control plane (what the prior
experiment used) **cannot** move queues to separate L1 nodes on TF1; they necessarily share the
parent. So the L1 mapping was not the problem — the two queues were correctly in one domain. (The
`bf_tm_sched_q_l1_set` API exists for finer hierarchies but requires the C/PD path, not bfrt.)

---

## Q6 — Does shaping change eligibility *before* strict-priority arbitration?

**DIRECT — H1 max shaping enable/disable (156-176):** `bf_tm_sched_q_max_shaping_rate_enable` /
`_disable` control "token bucket that assures queue shaping rate"; default max shaping is **enabled**
and set to match port bandwidth (H1:91-92, 145). **J1:** `max_rate_enable` = "Enable token bucket
that assures **max shaping rate**"; `max_rate` = "**Remaining** shaping rate".

**DIRECT — H1 guaranteed enable (227-260):** `bf_tm_sched_q_guaranteed_rate_enable` / `_disable`;
**"Default: Queue guaranteed shaping rate is disabled"** (H1:229, 247). So min-rate is OFF by default.

**INFERENCE (from the token-bucket semantics above + the two-pass model in Q3):** a queue is
selectable in a pass only while it holds credit in that pass's bucket. A nonempty, high-`max_priority`
queue that has exhausted its **max** shaping credit becomes **ineligible** for the remaining pass, and
a lower-priority eligible queue is served instead. Thus shaping gates eligibility *upstream of*
priority arbitration — a shaped high queue does **not** starve a lower one once it is over-rate.

**Finding:** yes. To make a high queue actually starve a lower one, you must leave its max shaping
rate effectively unbounded (do not enable a restrictive `max_rate`), so it never drops out of the
eligible set. Conversely, if the prior blocker had a max shaping rate enabled (default = port speed),
it could still transiently exhaust credit and yield the port — reinforcing Q4.

---

## Q7 — DWRR interaction with strict priority

**DIRECT — H1 `bf_tm_sched_q_dwrr_weight_set` (63-86):** "These weights are used by queues at **same
priority level**. Across priority these weights serve as ratio to share excess or remaining
bandwidth. Default: 1023. Weight 0 is used to disable the DWRR especially when Max Rate Leakybucket is
used." (Corroborated H3:1444-1447.)

**INFERENCE:** DWRR is the *tie-breaker within one priority level*, not a competitor to strict
priority across levels. Queues at a **higher** priority are selected before any DWRR sharing occurs
among **lower** ones. But if two queues sit at the **same** priority (e.g. both at the default
`PRIO_7` in the remaining pass), strict priority does nothing and DWRR splits the bandwidth by weight
— default 1023:1023 = **50/50**.

**Finding:** DWRR remains "unintentionally active" exactly when you *think* you set strict priority
but left the two queues at equal priority in the operative pass. That is precisely what the prior
IBSPG config did in the remaining pass (both `max_priority` = default HIGH, both `dwrr_weight` = 1023)
→ the two queues shared the port 50/50, which is the observed low-queue drain.

---

## Q8 — Recirculation port (dp68): documented scheduling difference vs a physical/MAC port?

**SDE:** the scheduler C API (H1) and bfrt schema (J1) are expressed purely in terms of
`(dev_port, queue)` / `(pg_id, pg_queue)`; **no separate scheduler model, table, or priority
semantics is documented for the recirculation port.** The recirc port is a normal TM egress port with
queues, one default L1 node, and the same `sched_cfg`/`sched_shaping` tables. The only port-level
scheduler table is `tf1.tm.port.sched_cfg` (fields `max_rate_enable`, `scheduling_speed`) — same for
all ports. So on documented semantics, **dp68 uses the same L1/port scheduler model**; there is no
"recirc is special" clause in the scheduler API. (Marked **DIRECT for the absence** — I searched the
TM headers and J1 and found no recirc-specific scheduler path.)

**MEASURED caveat:** although the *model* is identical, the recirc port's *behaviour* differs in
practice because its queue is fed by the pipe's own delayed recirc dequeues, which manufactures the
empty-gaps that defeat starvation (Q4). That is a traffic-pattern property, not a documented
scheduler difference.

**Finding:** no documented scheduler difference for dp68; same model. The observed difference is
emergent from recirc traffic dynamics, not from a different arbitration rule.

---

## Q9 — Burst credit (`max_burst_size` / `min_burst_size`) effect on eligibility timing

**DIRECT — H1 shaping setters (88-201):** every shaping/guaranteed-rate setter takes a `burst_size`
("Burst size in packets or bytes"). **J1 `tf1.tm.queue.sched_shaping`:** `min_burst_size` =
"Guaranteed shaping burst size", `max_burst_size` = "Remaining shaping burst size"; units per `unit`
(PPS → packets, BPS → bytes).

**INFERENCE (standard token-bucket semantics, grounded in the above):** burst size is the token
bucket depth — the maximum credit that can accumulate while a queue is idle. A larger `max_burst_size`
lets a queue stay eligible (keep dequeuing above its steady rate) for a longer burst before the bucket
empties; a small burst forces it to drop out of the eligible set sooner. So burst size tunes *how
long* a queue remains selectable between credit refills, i.e. the granularity of the eligibility
gating in Q6. **The SDE documents burst size as a parameter but does not give a numeric HW quantum**
(mantissa/exponent representation is noted via `provisioning`); exact timing is **unverified —
reasoning only** beyond "bigger burst = longer eligible window."

**Finding:** burst size sets token-bucket depth and therefore the duration of eligibility windows; it
does not change the priority ordering, only when a shaped queue becomes (in)eligible.

---

## Was the prior IBSPG config correct?

**Prior config:** `sched_cfg{scheduling_enable:true, min_priority:HIGH}` on Q_BLOCK and
`sched_cfg{scheduling_enable:true, min_priority:LOW}` on Q_HOLD, both on the same dev_port; min/max
rate left at defaults (min-rate **disabled**, max-rate default = port speed), `max_priority` and
`dwrr_weight` left at defaults.

**Verdict: NO — the config was wrong/insufficient. It never engaged strict-priority arbitration in
the pass where the two queues actually competed.** Concretely:

1. **Wrong field.** `min_priority` governs only the **guaranteed-bandwidth** pass
   (H1:42 / J1 "when serving guaranteed (min) bandwidth"). With `min_rate_enable = false` (default,
   H1:229), there is **no guaranteed quantum to order**, so `min_priority` is inert. This is the
   core error: the readback that "confirmed strict priority (7 vs 0)" only confirmed the *field* was
   written — it confirmed nothing about the operative arbitration, because that field governs a pass
   that was switched off.
2. **The operative pass was left undifferentiated.** With no min-rate, both queues competed entirely
   in the **remaining-bandwidth** pass, ordered by **`max_priority`** — which was **default `HIGH`
   for BOTH** (H1:208) — with DWRR tie-break at **default weight 1023 for BOTH** (H1:69). Equal
   priority + equal weight ⇒ **50/50 DWRR split** (Q7). That is exactly the measured low-queue drain.
3. Therefore the prior experiment's failure to starve Q_HOLD does **not** demonstrate anything about
   strict priority — it demonstrates that strict priority was **never actually configured** in the
   competing pass. The architecture conclusion must not be drawn from this run.

**Corrected config — set the priority of the pass the queues actually compete in (remaining/excess),
and keep the blocker perpetually eligible.**

bfrt_python (keys are port-group-relative: `pg_id` 0..17, `pg_queue` 0..31 — translate the
experiment's `(dev_port, qid1/qid7)` via `tf1.tm.queue.map` first):

```python
sched = bfrt.tf1.tm.queue.sched_cfg
# Q_BLOCK: highest priority in BOTH passes, never shaping-limited -> stays eligible & preferred
sched.mod(pg_id=PG, pg_queue=Q_BLOCK,
          min_priority='HIGH', max_priority='HIGH',      # <-- max_priority was the missing knob
          min_rate_enable=False, max_rate_enable=False,  # no max shaper -> never becomes ineligible
          dwrr_weight=1023, scheduling_enable=True)
# Q_HOLD: lowest priority in BOTH passes
sched.mod(pg_id=PG, pg_queue=Q_HOLD,
          min_priority='LOW', max_priority='LOW',
          min_rate_enable=False, max_rate_enable=False,
          dwrr_weight=1, scheduling_enable=True)
```

Equivalent C/PD calls (the one that was missing is the *remaining_bw* priority):

```c
bf_tm_sched_q_priority_set(dev, port, Q_BLOCK, BF_TM_SCH_PRIO_7);              // guaranteed pass
bf_tm_sched_q_remaining_bw_priority_set(dev, port, Q_BLOCK, BF_TM_SCH_PRIO_7); // REMAINING pass  <-- MISSING BEFORE
bf_tm_sched_q_priority_set(dev, port, Q_HOLD,  BF_TM_SCH_PRIO_0);
bf_tm_sched_q_remaining_bw_priority_set(dev, port, Q_HOLD,  BF_TM_SCH_PRIO_0); // REMAINING pass  <-- MISSING BEFORE
bf_tm_sched_q_max_shaping_rate_disable(dev, port, Q_BLOCK); // keep blocker continuously eligible
```

Notes on the fix:
- The single decisive change is differentiating **`max_priority`** (remaining_bw priority). Setting
  `min_priority` too is harmless and belt-and-suspenders, but only `max_priority` bites while
  `min_rate_enable=false`.
- Disable/omit a restrictive max shaping rate on Q_BLOCK so it never drops out of the eligible set
  (Q6); otherwise even correct priority yields the port when the blocker exhausts credit.
- `dwrr_weight` becomes irrelevant between the two once their `max_priority` differs (it only matters
  among equal-priority queues), but skewing it (1023 vs 1) is a safe extra margin.

**Important honesty caveat — the fix makes the experiment *valid*, not necessarily *successful*.**
Even with `max_priority` differentiated correctly, the SDE does **not** document strict priority as
absolute (Q4), and this silicon **measured** the low queue draining at MHz rate on the recirc port
regardless, because eligibility empty-gaps — not priority — let it through (project memory
`tofino1-strict-priority-not-absolute-recirc`). So the corrected config is **necessary to cleanly
separate two things the prior run conflated**: (a) the config error (wrong priority field — now
fixed), and (b) the genuine non-absoluteness of strict priority on recirc. The re-run with the
corrected `max_priority` should be done before concluding, but the prior architecture conclusion
should be treated as **not yet established** either way, because the prior run never tested strict
priority at all.

---

## Confirmation

Nothing was changed on the switch. This audit used only read operations
(`find`/`grep`/`scp`/`cat`/`python -c` over copied JSON) against SDE headers and the fixed bfrt
schema. No P4 program was compiled or bound, no bfrt/bfshell/`bf_tm_*` write was issued, and the
running `bf_switchd` (microbench PID 12665) was left untouched.

### Citation index
- H1 `SDE_INSTALL/include/traffic_mgr/traffic_mgr_sch_intf.h`: q_priority_set 40-61; dwrr 63-86;
  shaping enable/disable 145-176; guaranteed enable/disable "default disabled" 227-260;
  remaining_bw_priority_set 203-224; q_enable/disable 326-364; q_l1_set 366-385; l1_priority_set
  405-425; l1_enable 636-655; adv_fc/PFC 773-847.
- H2 `.../traffic_mgr_types.h`: L1/queue counts 55-63; `bf_tm_sched_prio_t` 217-228.
- H3 `.../include/tofino/pdfixed/pd_tm.h`: q_sched_priority "guaranteed bandwidth" 1420-1425;
  q_remaining_bw_sched_priority "remaining bandwidth" 1552-1556; dwrr 1444-1447.
- H4 `.../traffic_mgr_mcast.h`: PRE input-FIFO strict priority 38-56 (separate mechanism).
- J1 `SDE_INSTALL/share/bf_rt_shared/bf_rt_tm_tf1.json`: `tf1.tm.queue.sched_cfg` fields+descriptions;
  `tf1.tm.queue.sched_shaping` min_rate/max_rate; `tf1.tm.queue.cfg` pfc_cos; `tf1.tm.port.sched_cfg`;
  no `tf1.tm.l1_node.*` table (L1 not bfrt-exposed on TF1); 33 TM tables total.

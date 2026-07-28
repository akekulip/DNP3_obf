# Request-Triggered Pktgen — Implementation Report

Defense 2 blocker generation moved from Vision-seeded raw sockets to a request-triggered,
fully in-switch Tofino-1 packet generator. This report is the running record of every gate,
with hardware evidence. **No claim here is from memory; every hardware fact was read off the
switch's own SDE 9.13.2 install this session.**

Branch: `research/defense2-request-triggered-pktgen`
Baseline (frozen, rollback): `dnp3_timing_normalizer_inline` on the switch, bf_switchd
**PID 228141**, conf `/home/decps/timing_inline/tn_inline_abs.conf`, launcher
`/home/decps/timing_inline/launch_tn_inline.sh`.

> **Restore-target note.** The task text says restore `queue_microbench_abs.conf`. The switch is
> NOT running that — it is running `dnp3_timing_normalizer_inline` (Philip's standing instruction
> not to restore the microbench). The correct rollback for THIS work is therefore the inline
> launcher above. Recorded so the two do not get confused.

---

## Gate tracker

| Gate | State | Evidence |
|---|---|---|
| A. Design discovery (HW trigger feasibility) | **PASS** | this doc, §A |
| B/C/D/E. P4 implementation | **PASS** | `p4/dnp3_timing_normalizer_pktgen.p4` (grep `PKTGEN:`) |
| Compile 9.13.1 (local) | **PASS** | 0 errors; ingress 10/12, egress 0; `evidence/compile_iterations.md` |
| Compile 9.13.2 (switch) | **PASS** | 0 errors; ingress 10/12, egress 0 — identical to 9.13.1, no drift; `evidence/compile_logs_9.13.2/` |
| Control-plane bring-up (silicon) | **PASS** | all 6 TODO(silicon) resolved; §B below |
| Pktgen trigger (silicon) | **PASS** | gate (b): 1 READ -> trigger_counter=1, pkt_counter=64; §C |
| Queue integration (silicon) | **PASS** | gate (b/g): 64 admit -> Q_BLOCK -> 64 term on deadline; response held+released; §C |
| Live validation (SEL-751) | **PASS** | CLRT 2.17->25.05 ms median, sd 8.38->0.40 ms (21x), entropy 2.265->0.549 bits; §D |

---

## §B. Control-plane bring-up — the six TODO(silicon) items, RESOLVED on the switch

bf_switchd PID 441314 (never restarted), program `dnp3_timing_normalizer_pktgen`, bfruntime :50052.
Run env: `PYTHONPATH=$SP:$SP/tofino python3.8 …` with
`SP=/home/decps/Downloads/bf-sde-9.13.2/install/lib/python3.8/site-packages`.

| # | TODO(silicon) | Resolved to (read off the switch) |
|---|---|---|
| 1 | value_set table name | `pipe.IgParser.pgen_recirc`; key `f1` ternary `{value:1, mask:255}` (EXACT 0xFF, not the SDE's 0x1F — 0xE1 clone would alias to app_id 1 under 0x1F); scope set once at `prsr_id=17`, `pipe_id=0`. |
| 2 | `$mirror.cfg` session 7 -> dp68 | `$mirror.cfg` is ACTION-based: `make_data([...], '$normal')` is REQUIRED (omitting the action -> INVALID_ARGUMENT). Readback: sid 7, `$direction=INGRESS`, `$ucast_egress_port=68`, valid+enable True, `$max_pkt_len=128`. |
| 3 | `tf1.pktgen.*` vs `pktgen.*` | `tf1.pktgen.port_cfg` / `.pkt_buffer` / `.app_cfg` all resolve. |
| 4 | pkt_buffer excludes 6 B pktgen header | Confirmed functionally: buffer = 60 B `[eth 0x88C1][ibspg]`; HW prepends the 6 B `pktgen_recirc_header`; the P4 `advance(48)` skips it and admits the token (gate b, admit=64). |
| 5 | dp68 recirc-mode + generated-token source port | TWO parts. (a) `tf1.pktgen.port_cfg` needs ALL THREE flags: `pktgen_enable`+`recirculation_enable`+`pattern_matching_enable` (missing `recirculation_enable` = clone never loops back). (b) **`app_cfg.pipe_local_source_port=68` is REQUIRED** on this switch (the SDE's "implicit on TF1" note is FALSE here): without it the 64 generated tokens arrive with the wrong ingress_port, miss `from_pgen`, and are dropped as `port_ok=0` (seen as 64 in `ctr_bypass[1]`, `ctr_pktgen_admit=0`). No `$PORT` entry for dp68 is needed (it stays up=False; that is expected for the internal recirc port). |
| 6 | tbl_guard default-entry API | `pipe.Ingress.tbl_guard`.`default_entry_set(tgt, make_data([DataTuple('g_ticks', v)], 'Ingress.set_guard'))`; readback g_ticks=24999936 (25 ms). |

Setup-script edits made on the switch during bring-up (local file updated, NOT committed):
mirror `'$normal'` action; value_set idempotent del+add with scope-set wrapped separately;
`recirculation_enable` added to port_cfg; `pipe_local_source_port=68` + `increment_source_port=False`
added to app_cfg.

## §C. Functional gates (switch counters) — all PASS

Reader `run/read_pktgen.py` (SyncCounters for Stats-ALU counters; registers read live).

| Gate | Result | Evidence (per single controlled READ unless noted) |
|---|---|---|
| (a) no READ -> 0 tokens | **PASS** | app enabled, no traffic 3 s: trigger_counter=0, pkt_counter=0, arm_clone=0, admit=0 |
| (b) 1 fresh READ -> 1 trigger, 64 tokens | **PASS** | trigger=1, pkt=64, ctr_arm=1, ctr_arm_clone=1, **ctr_pktgen_admit=64**, block_term_deadline=64, release_deadline=1; only the clone (1) hits ctr_bypass[1] |
| (c) duplicate READ -> no 2nd burst | **PASS** | gen 0xC9 x2 on one conn: ctr_arm=2 but ctr_arm_clone=1, trigger=1, pkt=64 (idempotent via baseline reg_tag) |
| (d) token isolation | **PASS** | Vision capture (enp59s0f0np0): `eth.type==0x88c1` count = **0** in both native and protected runs. dp64 leg is untappable (unmanaged switch, no SPAN) — argued by construction (tokens forced ROLE_BLOCK -> only to_block()/drop_pkt(), never to_fwd()) AND accounting: over 21 protected polls **admit 1344 == term 1344** (every admitted token terminated on the dp8 loopback; zero forwarded) |
| (e) hold near t_ack+G | **PASS** | protected CLRT median 25.05 ms, min 24.997 ms (never < G -> no premature release), sd 0.40 ms; ACK forwarded immediately (ROLE_ACK -> to_fwd) |
| (f) fail-open | **PASS** | with G set to 2 s, response released at **171.5 ms** via budget exhaustion: ctr_release_fail_open=1, ctr_block_term_timeout=1, release_deadline=0 — a stuck deadline cannot hold the response indefinitely |
| (g) cleanup + re-burst | **PASS** | poll1: admit=64, term=64, release=1; poll2 (fresh gen): admit=128, term=128, release=2 — each fresh READ re-bursts, Q_BLOCK empties between |

## §D. Live validation (physical SEL-751, 20 measured polls each) — PASS

`run/run_pktgen.sh native|protected` on Vision (192.168.10.1 -> relay 192.168.10.7:20000), READ-only.
Client identical in both modes; native/protected differ ONLY by the in-switch app_enable toggle.

| Metric (clrt.py, ACK->response) | native | protected |
|---|---|---|
| n answered | 21/21 | 21/21 |
| median CLRT | 2.165 ms | 25.052 ms |
| sd (spread) | 8.383 ms | **0.401 ms  (21x tighter)** |
| range width | 40.207 ms | 1.931 ms |
| min / max | 1.06 / 41.27 ms | 24.997 / 26.93 ms |
| observer bins @1 ms | 6 | 3 |
| entropy | 2.265 bits | **0.549 bits** |
| 0x88C1 on Vision | 0 | 0 |
| escapes (native CLRT >= G) | 1 of 21 (the 41.27 ms connection-cold warmup poll) | n/a |

Protected traffic clusters onto G=25 ms with the spread collapsing 21x and observer entropy dropping
from 2.265 to 0.549 bits. Honest limitation: the ONE native poll with CLRT >= G (connection-cold,
41 ms) escapes — the defense normalizes only responses whose native CLRT < G; it cannot pull a
slower-than-G response down. Byte-identity is NOT re-claimed here (relay leg untappable); the frozen
inline baseline established it.

Final state left for the owner: switch on `dnp3_timing_normalizer_pktgen`, bf_switchd PID 441314
untouched, pktgen app DISABLED (quiescent), all control-plane config in place, G=25 ms.

---

## §A. Hardware trigger verification (Gate A) — PASS

**Question (task A.3): can Tofino-1 trigger the packet generator from a data-plane / packet
event, without a controller and without a periodic timer?**

**Answer: YES — via `trigger_recirc_pattern`.** A packet recirculated onto the packet
generator's port whose leading bytes match a configured value/mask fires the generator. This is a
genuine packet-driven trigger. It is the mechanism the whole design rests on.

### Evidence, read off `/home/decps/Downloads/bf-sde-9.13.2` this session

**1. The four trigger modes actually supported (bf-rt schema
`install/share/bf_rt_shared/bf_rt_pktgen_tf1.json`), as data-action names on
`tf1.pktgen.app_cfg` (table_type `PktgenAppCfg`):**

- `trigger_timer_one_shot`
- `trigger_timer_periodic`
- `trigger_port_down`
- **`trigger_recirc_pattern`** — with data fields **`pattern_value`** and **`pattern_mask`**  ← the one we use

Port-config table `tf1.pktgen.port_cfg` (`PktgenPortCfg`) additionally exposes
`recirculation_enable` and `pattern_matching_enable`.

**2. `tf1.pktgen.app_cfg` data fields (exact names):**
`app_enable`, `pkt_len`, `pkt_buffer_offset`, `pipe_local_source_port`,
`increment_source_port`, `batch_count_cfg`, `packets_per_batch_cfg`, `ibg`, `ibg_jitter`,
`ipg`, `ipg_jitter`, `timer_nanosec`, `trigger_counter`, `batch_counter`, `pkt_counter`.
Key: `app_id` (Tofino-1 = 3 bits, 0–7).

**3. Generated-packet header (`tofino1_base.p4`, auto-included by `tna.p4`):**

```p4
header pktgen_recirc_header_t {
    @padding bit<3> _pad1;
    bit<2>  pipe_id;     // pipe of the generator
    bit<3>  app_id;      // application id
    bit<24> key;         // 24-bit context COPIED FROM the triggering recirculated packet
    bit<16> packet_id;   // 0..(packets_per_batch_cfg) within the single batch
}
```

The **24-bit `key`** is decisive: it carries context lifted from the READ-derived trigger packet,
so the transaction generation can ride into every generated blocker with no controller and no
extra register read.

**4. Zero-basing (task C.4) — CONFIRMED, in the SDE example's own comment
(`pkgsrc/p4-examples/p4_16_programs/tna_pktgen/test.py`):**

> "these values are zero based, so a value of zero makes one packet and a value of ten makes
> eleven packets."

```python
gc.DataTuple('batch_count_cfg',       batch_cnt - 1)      # 1 batch  -> 0
gc.DataTuple('packets_per_batch_cfg', pkt_per_batch - 1)  # 64 pkts  -> 63
```

So **K=64 blockers = one batch, `batch_count_cfg = 0`, `packets_per_batch_cfg = 63`.** Tofino-1
recirc triggers are **single-batch only** (the recirc header carries `key` in place of a
`batch_id`); 64 packets in one batch is exactly within that limit.

**5. Generator/source port (task C.5–C.6):** Tofino-1 uses **pipe-local port 68** as the packet
generator port (`pgen_port = 68`; global dp68 in pipe 0). Enabled via `tf1.pktgen.port_cfg`
`pktgen_enable=true`. This is **distinct from the dp8 blocker loopback** — no conflict, and the
baseline P4 does not reference dp68 at all (verified by grep of
`dnp3_timing_normalizer_pktgen.p4`).

**6. Config sequence (verbatim shape from `test.py`):** `port_cfg.pktgen_enable` →
`pkt_buffer` (load the 0x88C1 token template, 16 B-aligned, keyed `pkt_buffer_offset` +
`pkt_buffer_size`) → `app_cfg` (pkt_len, pkt_buffer_offset, batch/packet counts, ipg/ibg,
`make_data(..., 'trigger_recirc_pattern')` carrying `pattern_value`/`pattern_mask`) →
`app_cfg.app_enable=true`.

### Verdict
No hardware limitation blocks the exact construction. The design does **not** fall back to a
controller trigger or a periodic timer. Proceed to implementation.

### Baseline structure the implementation must preserve (read from the copied P4)
- Ports: `PORT_L=dp8` (loopback), `PORT_VISION=dp9` (master), `PORT_HULK=dp11` (replay),
  `PORT_RELAY=dp64` (live relay). Queues on dp8: `QID_BLOCK=7` (high), `QID_RESP=1` (low).
- Roles: `ROLE_BLOCK=1` (0x88C1 → Q_BLOCK), `ROLE_RESP=2` (DNP3 response → Q_RESP),
  `ROLE_ARM=6` (READ), `ROLE_ACK=7` (ACK). Token carries `seq`=pass budget, `gen`=generation.
- All deadline/generation/transaction/expiry state is in ingress registers
  (`reg_tag`, `reg_deadline`, `reg_t_ack`, …). Egress is empty (byte-preserving deparser only).

---

## §B. Compile gates — PASS on both compilers

**Local bf-p4c 9.13.1** (`p4c 9.13.1`, SHA e558d01) and **on-switch bf-p4c 9.13.2**
(`p4c 9.13.2`, SHA 1baf055) both compiled the identical committed source
(`sha256 812a56fa…`) to **0 errors, 3 warnings**, with **identical allocation: 10/12 ingress
stages, 0 egress stages** — no 9.13.1→9.13.2 drift.

The 3 warnings are benign and identical on both: (1) the struct-wide
`out parameter 'meta' may be uninitialized` TNA notice — the field that gates pktgen admission,
`meta.is_pktgen`, is provably zero-init (PHV container H12 ∈ the ingress parser `init_zero` set,
verified in the `.bfa`), so ordinary traffic cannot enter the admission branch; (2–3) the
baseline's pre-existing `min_parse_depth_accept_loop` unroll notices.

**The on-switch compile was non-destructive.** It ran `bf-p4c` only; `bf_switchd` stayed on the
inline baseline (**PID 228141**, `tn_inline_abs.conf`) before and after — verified. No load, no
restart, no config change. Work dir on the switch: `/home/decps/defense2_pktgen_compile/`
(inert, staged for the later gated load). Authoritative logs kept under
`evidence/compile_logs_9.13.1/` and `evidence/compile_logs_9.13.2/`.

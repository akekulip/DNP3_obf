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
| Compile 9.13.2 (switch) | pending | — |
| Pktgen trigger (silicon) | pending (gated load) | — |
| Queue integration (silicon) | pending (gated load) | — |
| Live validation (SEL-751) | pending (gated load) | — |

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

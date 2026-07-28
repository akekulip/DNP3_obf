# Phase 1 (local half) — pktgen batch and packet_id semantics, read from the installed SDE

Date 2026-07-28. **Source-of-truth reads from `~/bf-sde-9.13.1` on this host. No switch, no
hardware. A live BFRT readback is still required before the reservoir-readiness measurement** —
this establishes what the hardware and driver *permit*, not what the running switch is configured
to do.

## Q1. Is 128 packets in one batch legal on Tofino-1? **YES.**

The hardware field is 16 bits. `install/include/tofino_regs/tofino.h:123714`,
register `pgr_app_event_number`, field `packet_num`:

```c
static inline uint32_t getp_pgr_app_event_number_packet_num (uint32_t* csr)
{ return ((*csr >> 16) & 0xfffful); }
```

`batch_num` is the companion 16-bit field at bits 15:0. So `packets_per_batch` spans 0..65535,
and **zero-based** per `install/include/pipe_mgr/pktgen_intf.h:258`:

```c
uint16_t batch_count;       /**< The number of batches to send when the application
                                 is triggered.  Zero based. */
uint16_t packets_per_batch; /**< The number of packets within each batch. Zero based. */
```

`packets_per_batch_cfg = 127` → 128 tokens is comfortably inside the field. Confirms the
zero-basing the Defense 2 bring-up derived from the SDE example.

## Q2. ★ The only driver bound on batch size is conditional — and it is load-bearing

`pkgsrc/bf-drivers/src/pipe_mgr/pipe_mgr_tof_pktgen.c:1361-1375`:

```c
/* Cannot increment the source port to an illegal value. */
if (cfg->increment_source_port &&
    cfg->packets_per_batch >
        (PIPE_MGR_PKTGEN_SRC_PRT_MAX - cfg->pipe_local_source_port)) {
  ...
  return BF_INVALID_ARG;
}
```

with `PIPE_MGR_PKTGEN_SRC_PRT_MAX = 127` (`pipe_mgr_pktgen_comm.h:26`).

There is **no unconditional limit**. But if `increment_source_port` were ever set true, the bound
with the required `pipe_local_source_port = 68` becomes `packets_per_batch <= 127 - 68 = 59`,
i.e. **60 tokens — which would reject even the existing K = 64 reservoir**, let alone 128.

**`increment_source_port = False` is therefore a load-bearing configuration invariant, not an
incidental setting.** It is already False in the Defense 2 setup script. Anyone flipping it
would break the proven baseline as well as this design. Assert it in the setup script and
read it back.

## Q3. ★ Correction: recirculation triggers are NOT restricted to one batch — but the batch is not identifiable

The Defense 2 report states that "Tofino-1 recirc triggers are single-batch only." The driver
does **not** enforce that. The only `batch_count` restriction is for a different trigger type
(`pipe_mgr_tof_pktgen.c:1376-1384`):

```c
/* If the trigger type is port down, then only one batch is usable as
 * the batch id in the pkt-gen header carrys the port number. */
if (cfg->batch_count != 0 &&
    cfg->trigger_type == BF_PKTGEN_TRIGGER_PORT_DOWN) { ... return BF_INVALID_ARG; }
```

So multi-batch generation from a recirculation-pattern trigger is *permitted*. **The reason the
original two-batch design still fails is different, and stronger:**

1. The generated header carries the 24-bit `key` in the position a `batch_id` would occupy, so a
   token cannot report which batch produced it; and
2. `packet_id` is *per batch* — it restarts at 0 for each batch.

Two batches of 64 would therefore both emit `packet_id` 0..63 with no way to tell them apart.
**One batch of 128 emits `packet_id` 0..127, which is uniquely partitionable.**

The conclusion in the design document is unchanged — classify on `packet_id`, not `batch_id` —
but the reason is now precise: *the batch is unidentifiable and `packet_id` is not batch-unique*,
rather than *multi-batch is forbidden*.

## Consequences for the design

- **Preferred construction is confirmed viable:** one recirculation-triggered application,
  `batch_count_cfg = 0`, `packets_per_batch_cfg = 127`, `increment_source_port = False`,
  `pipe_local_source_port = 68`.
- Classification by full-width ternary on `packet_id` (`0x0000/0xFFC0` → ACK blocker,
  `0x0040/0xFFC0` → response blocker, default drop) is well-founded: the values are unique across
  the whole 128-token burst.
- The two-application fallback is **not needed on capability grounds**. Retain it only as a
  contingency if the live readback contradicts any of the above.

## Still to verify on hardware (reservoir-readiness gate, switch-gated)

- Live BFRT readback that `packets_per_batch_cfg = 127` is accepted and reports back as 127.
- Actual emitted `packet_id` range and ordering — whether the 128 tokens arrive 0..127 in order,
  or interleaved. Classification is by value so interleaving is tolerable, but the readiness
  measurement must then be taken per class.
- That exactly 64 tokens land in each class.
- Admission timing: all 64 ACK blockers within 100 µs of READ detection, against the 0.400 ms
  minimum measured READ→ACK.

# BOR two-pipe control plane — `defense4_bor_twopipe_setup.py`

The ONE authoritative control-plane setup for the **faithful two-pipe BOR + RRC** deployment
(`BOR_TWO_PIPE_FAITHFUL_RESULT.md`). It drives BOTH programs of the two-program device from one
process: pipe 0 (frozen RRC + T0-admission + cross-pipe route + SELECT-prepares-a-BOR-epoch) and
pipe 1 (faithful BOR hold/release). It reuses the proven `defense4_rrc_setup.py` (PRE + shape) and
`defense4_caseA_setup.py`/`d3` (timing, queues, pktgen, registers) helpers **without modifying
them**, and adds all of pipe 1 plus the BOR deadline admissibility gate.

> **Status: OFFLINE / COMPILE-ONLY.** Nothing here was run against silicon. `dry-run` is fully
> offline; every write refuses unless `DEFENSE4_HW_AUTHORIZED=1`. The hardware calls are designed
> and gated; they run only under an authorized session on the switch.

---

## 1. Ops

| op | what it does | touches hardware? |
|---|---|:--:|
| `dry-run` | validate the BOR deadline matrix + the pipe-0 timing mode + the TCP-timestamp preflight vectors + a unit self-check of the matrix + the faithful two-pipe emulator + the RRC carve math; print the plan and the exact bring-up sequence. **Never connects.** Exit 0 iff admissible, 2 otherwise. | no |
| `configure` | SAFE ORDER: validate → pipe-0 timing (subprocess) → connect one client → pipe-0 PRE install+verify → pipe-1 tables + qid3 reservoir install+verify → **enable BOR + shape only after every readback passes** → final readback-or-abort. | yes |
| `verify` | read both pipes back read-only; PASS/FAIL per element (no writes). | yes (read) |
| `evidence-dump` | read-only dump of both pipes (pipe-0 `tbl_params` + PRE; pipe-1 queues/codebook/pktgen/registers) for the bring-up scorer. | yes (read) |
| `disable-bor` | pipe-1 pktgen app OFF → no qid3 reservoir → the OPERATE **fails open** (forwarded once, unshaped); retire the epoch registers. Timing + size intact. | yes |
| `disable-rrc` | size layer OFF: `shape_enable=0` (unicast restored), **confirm 0**, then delete the PRE group. Timing + BOR intact. | yes |
| `rollback` | full teardown to benign forwarding, in **verify-disabled-then-delete** order: shape off (verify) → BOR off (verify) → delete PRE → pipe-0 timing OFF (subprocess) → pipe-1 pktgen off. | yes |
| `recover` | after a **partial** failure, read the live state and force it to the benign state (shape off, BOR off, PRE absent, epoch clean), tolerating anything already gone (idempotent). | yes |

---

## 2. Pipe / port / pipe_scope map

`dev_port = (pipe << 7) | local`, so pipe 0 = dp 0–127, pipe 1 = dp 128–255.

| role | dev_port | pipe | who owns bring-up | how realized |
|---|---:|---:|---|---|
| master (Vision) | dp9 | 0 | caseA subprocess | physical 25G |
| relay (SEL-751) | dp64 | 0 | caseA subprocess | physical 1G |
| pipe-0 hold ring `PORT_L` | dp8 | 0 | caseA subprocess | MAC-near loopback |
| pipe-0 pktgen `PORT_PGEN` | dp68 | 0 | caseA subprocess | pktgen/recirc |
| **cross-pipe entry `PORT_X1`** | **dp144** | **1** | **this script** | **MAC-near loopback** |
| **pipe-1 hold ring `PORT_L1`** | **dp136** | **1** | **this script** | **MAC-near loopback** |
| **pipe-1 pktgen `PORT_PGEN1`** | **dp196** | **1** | **this script** | **pktgen/recirc (local port 68 of pipe 1)** |

**Per-program bfrt targets (`pipe_scope` discipline).** The two programs are deployed as one
device with `pipe_scope [0]` and `pipe_scope [1]`:

- pipe-0 P4 tables (`tbl_params`, registers) → `Target(pipe_id=0)`, bfrt_info of `--program-pipe0`.
- pipe-1 P4 tables (`tbl_bor_codebook`, `tbl_params`, registers) → `Target(pipe_id=1)`, bfrt_info of `--program-pipe1`.
- PRE / multicast (device-global) → `Target(pipe_id=0xffff)`.
- TM queue `sched_cfg`, `$PORT`, pktgen, `$mirror.cfg` are fixed tables addressed by the pipe that
  owns the port (pipe 1 for dp136/dp196), never by a shared-register assumption.

**No cross-pipe register is ever read.** T0 crosses to pipe 1 in the packet (`xpipe.t0`); pipe 0's
`reg_epoch` allocator and pipe 1's `reg_epoch/reg_ready/reg_gen/reg_topj` are independent per-pipe
state, each cleared on its own pipe.

**Queue ladder split across the two pipes** (`BOR_RRC_DESIGN.md` §3's full qid7..qid2 ladder):
pipe 0 carries qid7 > qid6 > qid5 > qid4 (ACK/RESP reservoirs, set by caseA); pipe 1 carries
**qid3 (OPERATE blocker reservoir) > qid2 (OPERATE hold)** strict-priority, set here; qid0 is the
default forward FIFO.

---

## 3. Deadline-validation rules (all milliseconds; a bad set is REJECTED, never defaulted)

`A` = the OPERATE ACK release total-from-T0 (default `D_A`); `R` = the OPERATE echo release
total-from-T0 (default `D_A + D_R`); `J_max` = max of the admissible J codebook (`--j-set`).

```
  A  > J_max + native_ACK_bound
  R  > J_max + native_response_bound
  R >= A
  A, R, J_max  all <  min( operational_command_to_actuation_limit,
                           master_SBO_timeout - guard,
                           TCP_retransmit_bound - guard,
                           BOR_fail_open_horizon,          # = budget*K/rate_dp8 (d3.failopen_horizon)
                           operational_latency_budget )
  operating J (--op-j-ms) in the admissible set AND <= J_max
```

Additional rules:

- **BOR needs both holds.** `A>0` and `R>0` are required, so a mode with `D_A==0` (D2) or `D_R==0`
  (D3) is rejected — BOR runs under **D1/D4**. The old `D_A = 2 ms` ACK target does **not** survive
  (`BOR_RRC_DESIGN.md` §1): with `J_max ≈ 12 ms`, `A` must exceed `J_max + native_ACK`.
- **Real millisecond deadlines only.** D-modes require an explicit ms deadline; the sub-millisecond
  `0x8000 ns` (0.033 ms) placeholder is rejected (reused from the RRC/caseA resolver).
- **REJECT is hard.** An invalid set exits non-zero **before any connection attempt** and never
  substitutes a default value.

The default set is admissible: `mode D4, D_A=16, D_R=6 → A=16, R=22`; `J-set {0,2,4,6,8,10,12} →
J_max=12`; `native=1.9`; `budget=18000 → horizon≈30.8 ms` (the binding ceiling). Verified by the
matrix truth table in `selfcheck_deadline_matrix()` (8 valid/invalid rows, run by `dry-run`).

**TCP-timestamp preflight (anti-subtraction, `BOR_RRC_DESIGN.md` §2).** The protected flow must
negotiate **without** TCP timestamps, else a passive observer recovers `J` from the relay's stale
`TSval`. `tcp_options_has_timestamp()` walks the actual TCP option **kinds** (0=EOL, 1=NOP, else
`[kind,len,…]`), so `data_offset==8` (a 20-byte options field) is **not** taken as proof of option
kind 8. Timestamp-safe iff BOTH the SYN and SYN-ACK parse cleanly AND neither carries kind 8
(**fail closed** on a malformed/truncated blob). Offline, supply the captured option bytes with
`--syn-options`/`--synack-options` (hex); on hardware, feed them from the protected flow's
handshake. `configure` **rejects** before connecting when the preflight fails.

---

## 4. Readback-or-abort and the dead `read_len`

- No step reports PASS from a command's exit code — only from a **readback**. An empty
  `tbl_params` read aborts (`rrc._verify_all_params`), never trusting substituted timing values.
- The RRC kernel **retired `read_len`** (it reads back 0, dead PHV). `run_timing_pipe0` always
  forwards `--read-len 0` to the caseA subprocess so its readback matches, and the final verify
  tolerates `read_len == 0` explicitly — there is no lenient tolerance that could mask a real
  pktgen-not-enabled failure.

---

## 5. Exact hardware bring-up sequence (later, authorized phase)

```bash
# 0. Load the TWO-program device (one .conf, two p4_programs, pipe_scope [0] and [1]):
#      p4_programs: { twopipe_pipe0, pipe_scope [0], bin/context/bfrt from pipe0/ }
#                   { twopipe_pipe1, pipe_scope [1], bin/context/bfrt from pipe1/ }
#    Program names must match --program-pipe0 / --program-pipe1.

# 1. Dry-run FIRST (offline) — prove the deadline set + preflight + models:
python3 defense4_bor_twopipe_setup.py dry-run \
  --mode D4 --d-a-ms 16 --d-r-ms 6 --op-j-ms 10 --j-set '0,2,4,6,8,10,12' \
  --syn-options <syn_hex> --synack-options <synack_hex>

# 2. Configure in ONE shot (SAFE ORDER; BOR + shape enabled only after every readback passes):
DEFENSE4_HW_AUTHORIZED=1 python3 defense4_bor_twopipe_setup.py configure \
  --mode D4 --d-a-ms 16 --d-r-ms 6 --op-j-ms 10 --j-set '0,2,4,6,8,10,12' \
  --syn-options <syn_hex> --synack-options <synack_hex>
#   -> validate -> pipe-0 caseA subprocess (ports/queues/pktgen/session/mirror/value_set/params,
#      --read-len 0) -> connect one client -> pipe-0 shape OFF -> PRE install+verify -> clear
#      pipe-0 reg_epoch -> pipe-1 ports/queues/codebook/params/mirror/value_set/pktgen(off) ->
#      clear pipe-1 epoch registers -> enable pipe-1 reservoir -> enable pipe-0 shape ->
#      final tbl_params readback (shape=1, timing present, read_len=0 tolerated).

# 3. Read both pipes back:
DEFENSE4_HW_AUTHORIZED=1 python3 defense4_bor_twopipe_setup.py verify
DEFENSE4_HW_AUTHORIZED=1 python3 defense4_bor_twopipe_setup.py evidence-dump

# 4. Selective disable / full teardown / recover:
DEFENSE4_HW_AUTHORIZED=1 python3 defense4_bor_twopipe_setup.py disable-bor    # OPERATE fails open
DEFENSE4_HW_AUTHORIZED=1 python3 defense4_bor_twopipe_setup.py disable-rrc    # size off + PRE del
DEFENSE4_HW_AUTHORIZED=1 python3 defense4_bor_twopipe_setup.py rollback       # benign forwarding
DEFENSE4_HW_AUTHORIZED=1 python3 defense4_bor_twopipe_setup.py recover        # after partial failure
```

PRE group: `mgid 0x2849 → node 0x2851 (RID 1, prefix) + node 0x2852 (RID 2, suffix), both → dp9`.

---

## 6. Assumptions that need HARDWARE confirmation (not verifiable offline)

1. **Mirror session collision (highest-risk).** Both frozen probes hardcode mirror session **7**:
   pipe 0 → dp68, pipe 1 → dp196. TF1 mirror sessions are device-global. If the SDE does **not**
   scope a session per pipe under `pipe_scope`, these collide. Resolution before hardware: confirm
   per-pipe session scoping, **or** re-spin the pipe-1 probe with a distinct session id.
2. **`J_DEFAULT_TICKS` is wrong in the probe.** `topj_cand = (t0 & 0xFFFFFF00 | 1) + j_ticks`, so
   `j_ticks` is a **delay in nanoseconds** (low byte 0). The probe's `J_DEFAULT_TICKS = 0x2800`
   is 10 240 ns = **0.010 ms**, not the ~2.7 ms its comment claims. The control plane therefore
   installs an explicit `set_j` entry (encoded via `d3.quantize_d`, same as the deadline words)
   and never relies on the default.
3. **Leak-safety is partial in this probe.** `tbl_bor_codebook` matches `hdr.tcp.dst_port`
   exactly → **one deterministic J per flow**. A fixed J is a known constant an observer can
   subtract. Only the T0-anchoring (response-timing channel) is closed here; per-OPERATE
   randomization (`Random<>`/salt) is a P4 follow-up not present in this build.
4. **A / R mapping to pipe-0's OPERATE deadlines.** `A` and `R` are validated as first-class
   inputs (default `A=D_A`, `R=D_A+D_R`, consistent with what caseA writes to `tbl_params`).
   Which register fields the frozen pipe-0 program arms for the OPERATE (vs the READ/SELECT path)
   should be confirmed on silicon; override with `--op-a-ms`/`--op-r-ms` if they differ.
5. **Multi-program bfrt binding.** One `ClientInterface` fetching a second program's `bfrt_info`
   without a second `bind_pipeline_config`, and the fixed TM/pktgen/mirror tables being reachable
   from either program's `bfrt_info`, are assumed; confirm on the two-program device.
6. **Pipe-1 pktgen addressing.** The pktgen app/port/buffer tables are addressed with
   `Target(pipe_id=1)` and `pipe_local_source_port = dp196 & 0x7F = 68`. Confirm on hardware.
7. **The SELECT-prepare has no runtime enable** — it is compile-active on pipe 0
   (`-DPIPE0_SELECT_PREP`). The runtime BOR on/off lever is the pipe-1 qid3 reservoir
   (`pktgen app_enable`): with it off, `arm_clone` still mirrors but no burst is generated, so
   the OPERATE fails open. `disable-bor` uses exactly this.
8. **qid3 residency continuity** (budget/rate vs J) and the physical operation-time divergence
   floor are hardware/security-campaign questions, out of scope here.

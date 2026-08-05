# MB-1 v3 — offline bf-p4c compile evidence

Raw compiler artifacts for `defense4/p4/mb1_v3_unified_core.p4`, the defect-repaired
successor to `mb1_v2_unified_core.p4`. **Offline compile only** — nothing was loaded on the
switch; the physical Tofino stays on Defense 3.

## Exact compile command

```bash
cd /home/philip/Projects/DNP3/defense4/p4
source /home/philip/bf-sde-9.13.1/set_sde.bash
/home/philip/bf-sde-9.13.1/install/bin/bf-p4c --target tofino --arch tna -g \
    -o build_mb1v3 mb1_v3_unified_core.p4
```

- **Compiler:** `p4c 9.13.1 (SHA: e558d01)` at `/home/philip/bf-sde-9.13.1/install/bin/bf-p4c`
- **Result:** `0 errors, 2 warnings generated.` (exit 0)
- **Warnings (both benign, both from the TNA pktgen include, NOT from this source):**
  `Parser state min_parse_depth_accept_loop will be unrolled up to 3 times due to
  @pragma max_loop_depth.` (x2). The v2 `uninitialized_out_param` warning is **eliminated**
  (FIX 10).

## Hashes

| Artifact | sha256 |
|---|---|
| `mb1_v3_unified_core.p4` (source) | `4b0d1951926caaeab43e902c8b1ce087e7087d1aa6bea0892e530544d59fc48a` |
| `build_mb1v3/pipe/context.json` | `4733cb09c53e30f7c8b2456aff85cec5db7813dd63ad01011151f61af7ff2bbc` |
| `build_mb1v3/pipe/mb1_v3_unified_core.bfa` | `dc936fee6988bdc3e9814c9cc99233ec1314ea0e6bb972ffc847ec67d37b8d00` |

The build directory `build_mb1v3/` is gitignored (per `.gitignore`); `context.json` and the
`.bfa` are the compiler's binary/config outputs and are NOT committed — only their hashes are
recorded here for reproducibility, alongside the three human-readable resource logs.

## Committed raw logs (copied verbatim from `build_mb1v3/pipe/logs/`)

- `table_summary.log` — stage count, critical path, per-stage table/Min-Max placement.
- `mau.resources.log` — per-stage SRAM / MapRAM / TCAM / Gateway / Meter-ALU(SALU) /
  Stats-ALU / Logical-TableID.
- `phv_allocation_summary_0.log` — PHV MAU groups + tagalong collections.
- `compile_transcript.log` — full stdout/stderr of the bf-p4c run above.

## Resource summary (read straight from the logs)

- **Stages: 12 ingress / 0 egress. Critical path: 11. Tables: 122.**
  `table_summary.log` lines 2-6.
- **Fit verdict: FITS ≤12 ingress, exactly at the ceiling (0 empty ingress stages, egress
  entirely unused).** v2 was 10 ing / CP 8 / 96 tbl with 2 stages of margin; the ten fixes
  cost **+2 stages (10→12)** and **+3 critical path (8→11)**, landing on the 12-stage wall.
  No required fix was dropped to fit.
- **Per-stage Logical TableID:** `[14, 6, 8, 9, 6, 14, 14, 6, 1, 16, 16, 12]`.
  **st9 and st10 are 16/16 SATURATED** (the dominant tail); st11 is 12/16. This is the same
  LTID-bound ACT-block cluster tail seen in v2 and shipped Defense 3 — the forwarding actions
  (`to_fwd`/`to_ack_hold`/`to_resp_hold`/`to_ack_block`/`to_resp_block`/`drop_pkt`/`arm_clone`)
  plus the 7 counters spill into the last stages.
- **Meter ALU (stateful SALU): 10 total**, per stage `[0,0,1,2,0,3,3,1,0,0,0,0]`, max 3/stage
  (< the 4/stage cap). One per Register: reg_tag, reg_fp, reg_valid, reg_phase, reg_event,
  reg_ack_gone, reg_deadline, reg_slot_clock, reg_slot_bitmap, reg_active_flow.
- **Stats ALU: 11 total** (the 7 counters; some counters consume 2 ALUs), in st0/st9/st10/st11.
- **Gateways: 77 total**; busiest st5 = 13/16, st6 = 12/16.
- **SRAM 59, Map RAM 42, TCAM 9** (totals row of `mau.resources.log`).
- **PHV:** all three low groups now container-saturated — **B0-15 16/16, H0-15 16/16,
  W0-15 16/16** — with overflow absorbed by B32-47 (3 new 8-bit containers, 24 b) and by
  live-range overlay onto W0-15 (696 b allocated / 512 available = 136% via non-overlapping
  ranges). Upper groups B48-63, H16-95, W16-63 are essentially free. Tagalong 43.8%
  (collections 0/2 ingress full, collections 5-7 empty). PHV placed with 0 errors.

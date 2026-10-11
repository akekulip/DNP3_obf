# Composite on silicon with the OPERATE + generator fixes: paired T on / T off (2026-10-11)

Follow-up to `combined_silicon_01`, now on the complete build (C timestamp profile `0c5e3673c`, OPERATE
Ethernet header `421d78ac1`, generator buffer ethertype `f4272787a`): build
`route_ab_01/operate_header_01/hw_compile_switch_9132`, bfrt.json `8459a74d…880f64`, p0/tofino.bin
`634e14ed…`, p1/tofino.bin `314680f3…`. Each block is a fresh cold restart of bf_switchd, a bring-up
(`--t-enabled` 0 or 1, `--enable-pktgen`), one connection of 20 READs (8-bit range, 20 ms gap) then a
SELECT/OPERATE, then teardown. A cold restart per block is required: N does not re-arm, and the T registers
move once a connection runs, so the installer refuses a second apply. Endpoints and NIC as in
`combined_silicon_01` (software master/outstation on dev 9, clean profile, source pruning on, separate-ACK
emulation on).

| block | T | READs padded 49->58 | SELECT | OPERATE | commit vs fallback | queues |
|---|---|---|---|---|---|---|
| `block_on_1` (port 54420) | enabled | 20/20, CRCs valid | accepted (1 real, 0 decoy) | **lost** (`operate_real` 0) | 20 ACK + 20 RESP all **fallback**, 0 commit; `HELD_REWAIT` 298,352; generator 136 triggers / 544 pkts; ACK_HOLD and RESP_HOLD held cells | yes |
| `block_off_1` (port 54421) | disabled | 20/20, CRCs valid | accepted (1 real, 0 decoy) | **lost** (`operate_real` 0) | no T outcome moved (T off); E pads | n/a |

Both blocks: master `success` false only because the SBO did not complete; all 20 READs completed and matched
the seeded points in both.

## Two findings

1. **OPERATE is lost with T off as well as on.** So the loss is not the T timing path. In the earlier
   pure-padding runs on `case4_response_path` (`protocol/evidence/hw_vepa_padding_01`, same VEPA endpoints and
   port) OPERATE completed. The difference is the composite: N admission and the master-side lap on the
   front-panel loopback port 48. SELECT (35 bytes) completes and its response returns, but the OPERATE request
   never reaches the outstation (`select_real` 1, `operate_real` 0; ~5 master->outstation frames unaccounted
   for on the wire in both blocks). This is a model-invisible drop — the composite's `model_hw_operate`
   scenario is 60/60, because the model's reflectors do not filter a MAC loopback. It needs investigation of
   the OPERATE request's path through N and the port-48 lap on the hardware map, not more T work.

2. **The clean commit path does not fire on silicon; every READ releases by fallback.** The generator
   ethertype fix (`f4272787a`) did not change this: `block_on_1` still shows `ACK_FALLBACK` and `RESP_FALLBACK`
   = 20 with zero commits, exactly as `combined_silicon_01` did before the fix. The agents had already noted
   that T releases through its fallback path, not its commit path, on the model too ("known model-clock
   limitation"), so the commit path has never been exercised anywhere. Whether it can work across front-panel
   MAC loopback at all, or needs the pipe-local recirculation that this 2-pipe chip does not spare, is open.

## What the combined run does establish on silicon

The composite loads, installs (35 writes, 4 ports in MAC loopback) and tears down cleanly per block; the
pipe-1 packet generator runs; blockers lap the front-panel loopback (`HELD_REWAIT` hundreds of thousands);
the hold queues hold real cells; and **every READ response is padded 49->58 with a valid CRC while being held
and released by T** (via fallback). Padding and the READ hold/release work together through the ASIC. The
clean commit path and the SBO OPERATE do not, and both are now scoped as the next problems.

## Files

`block_on_1/` and `block_off_1/`, each with master/outstation JSON, result, state, `out.pcap`/`in.pcap`, and
`snb_*`/`sna_*` switch counter snapshots. Rig restored to baseline after the run (loopback cleared on 48/180/
181/182, relay slot read back, ping .1 -> .7).

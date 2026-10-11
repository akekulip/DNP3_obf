# First hardware milestone passed: READ + SBO through the composite with normal timing (2026-10-11)

After the three audit fixes — A (IIN admission, `8efae4002`), B (READ generator app 0, `818b4da0e`), and the
5 ms response fixture inside the 12 ms readiness deadline (audit defect D) — the composite does successful READ
and SELECT→OPERATE on the physical Tofino-1, pads every eligible response to 58 bytes, and **commits and
releases through the clean path with zero fallback**. This is the milestone Philip's execution prompt defined.

Build `route_ab_01/sbo_admission_01/hw_compile_switch_9132`: bfrt.json `ee998605…`, p0/tofino.bin `741fee7e…`,
p1/tofino.bin `084e4963…`. Ports: relay 9, N_ACK_RETURN 48, T_IN 180, HB_RETURN 181, HELD_RETURN 182 (front-panel
MAC loopback), RETURN_PORT 68, PKTGEN_RETURN 196. Software OpenDNP3 endpoints (master 192.168.10.61, outstation
192.168.10.62:20000) on dev 9 (VEPA, source pruning on), clean TCP profile, READ in the 20-byte 8-bit-range form.
Each arm is a fresh cold bring-up (N does not re-arm; T registers move once a connection runs).

| gate test | arm | result |
|---|---|---|
| 1. READ + SBO | T off (`toff/`, port 54430) | master success; 10/10 READs match seed; 1 real SELECT + 1 real OPERATE, 0 decoy; outstation sent 10×49 + 3×37, switch returned **12×58** with valid DNP3 CRCs; no T outcomes, all queues idle |
| 2. normal timing | T on, 5 ms fixture (`ton5/`, port 54431) | **`OUT_ACK_COMMIT` 10, `OUT_RESP_RELEASE` 10, zero fallback**; blocker queues active (ACK_BLOCK wm 335, RESP_BLOCK 334, OP_BLOCK 5), pktgen READ 24 trig/96 pkt, OPERATE 1/4 |
| 3. SBO under T | same run | **`OUT_OP_RELEASE` 1**; master success; 1 real SELECT + 1 real OPERATE, 0 decoy; all 12 responses returned 58 B, valid CRCs |

## What this establishes

- The OPERATE loss was defect A (the response IIN1 `0x90` never matching the exact `0x8100` key), not a MAC
  loopback drop — confirmed: OPERATE completes on silicon once the key is the ternary `0x8100 &&& 0xff6f`.
- The fallback-only releases were defect B (READ on app 2, which the parser dropped) — confirmed: with READ on
  app 0 the ACK/RESP blocker queues go from zero to hundreds of cells, and every READ now takes the genuine
  `OUT_ACK_COMMIT`/`OUT_RESP_RELEASE` path with zero fallback.
- The earlier "25 ms response vs 12 ms readiness forces fallback" (defect D) is confirmed by contrast: the same
  build with a 5 ms fixture commits cleanly.

## The remaining defect this run also shows

`OUT_HELD_REWAIT` = 71,310 for 10 READs + 1 SBO: originals are re-circulating thousands of times while held,
even though commit/release is now correct. This is the residency/overhead work (plan step 3) — measure original
vs blocker passes separately and size the reservoir/K from the measured loop — and is separate from the
correctness just demonstrated. It does not block the milestone but must be reduced before the campaign.

## Files

`toff/` and `ton5/`, each with `out.pcap`/`in.pcap`, master/outstation/result JSON, `state.txt`, and switch
counter snapshots (`snap_toff.json`; `snb_ton5.json`/`sna_ton5.json`). Rig restored to baseline after the run.

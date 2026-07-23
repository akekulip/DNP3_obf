# SWITCH_COMPILE_PARITY.md — Phase 4 (queue_microbench_trace_v1.p4)

Non-destructive on-switch compile; the loaded queue microbench was NOT touched.

| | Local (bf-p4c 9.13.1) | On-switch (bf-p4c 9.13.2) |
|---|---|---|
| Errors | 0 (2 benign parser-unroll warnings) | 0 (2 benign) |
| Ingress stages | 3 | 3 |
| tofino.bin + context.json | produced | produced |
| SRAM / Map RAM / TCAM | 13 / 12 / 0 | 13 / 12 / 0 |
| Meter(SALU) / Stats ALU | 2 / 4 | 2 / 4 |
| Gateways / xbar / hash / VLIW / logical | 6 / — / — / 21 / 15 | 6 / 8 / 10 / 21 / 15 |

**Full resource parity; no 9.13.2 drift.** Staged at `/home/decps/queue_microbench_trace/build_9132`
(compile-only, NOT loaded). `bf_switchd` remained on `/home/decps/queue_microbench/out/queue_microbench_abs.conf`.

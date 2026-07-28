# Preserved baseline — do not modify

Recorded per the direction's §PRESERVE EXISTING RESULTS, before any new file was written.

## The proven Defense 2 implementation (frozen)

| Item | Value |
|---|---|
| Tree | `research/defense2_pktgen/` |
| P4 source | `p4/dnp3_timing_normalizer_pktgen.p4` |
| P4 sha256 | `812a56facd842dc7e96d631faffead9d88ca9753ac4d19f11f0b9bd809ffc7db` |
| Commit introducing that P4 | `d95f731` (compile gate 2, bf-p4c 9.13.1) |
| Commit recording silicon PASS | `a163e81` (gates 4–6, Tofino-1 + physical SEL-751) |
| Setup script | `setup/dnp3_timing_normalizer_pktgen_setup.py` |
| Runners | `run/run_pktgen.sh`, `run/poll_pktgen.py`, `run/read_pktgen.py`, `run/clrt.py`, `run/fgate_inject.py` |
| SDE (local compile) | bf-p4c 9.13.1, SHA `e558d01` |
| SDE (switch compile + load) | bf-p4c 9.13.2, SHA `1baf055` |
| Resource fit | **10 / 12 ingress stages, 0 egress**, identical on both compilers (no drift) |
| Detail | 70 logical tables, 61 SRAM, 60 map RAM, 1 TCAM, 9 Meter ALU, 21 Stats ALU, 36 gateways, 41 PHV containers / 580 ingress PHV bits, critical path 8 |
| Queues (dp8 loopback) | `QID_BLOCK = 7` (HIGH), `QID_RESP = 1` (LOW), strict priority via `max_priority` |
| Pktgen | one app, `trigger_recirc_pattern`, `pattern_value = 0xE1000000 / mask = 0xFF000000`, `batch_count_cfg = 0`, `packets_per_batch_cfg = 63` → **one batch of 64**, `pipe_local_source_port = 68` |
| Live result | native CLRT median 2.165 ms / sd 8.383 ms → protected median 25.052 ms / sd 0.401 ms; `0x88C1` on Vision = 0 both modes |
| Switch restore target | `dnp3_timing_normalizer_inline`, `/home/decps/timing_inline/launch_tn_inline.sh` |

**These files are not modified by this branch.** All new work lands under
`research/case_a_read_anchored_dual_release/`.

## The fixed-D analysis (preserved as a negative analytical baseline)

Kept at `research/case_a_fixed_ack_delay/` on `main` — study, three reproducible gate scripts,
and their raw outputs. It is referenced from `evidence/fixed_d_negative_result/README.md` rather
than duplicated, so there is a single authoritative copy and the `main`-side references
(including the `CLAUDE.md` header) stay valid.

**Its conclusion is not an implementation impossibility.** Fixed-D is implementable and, at
`D ≥ max(CLRT)`, does conceal the CLRT. What it fails is robustness under a multi-interval
adaptive observer — see `evidence/fixed_d_negative_result/README.md` for the precise scope.

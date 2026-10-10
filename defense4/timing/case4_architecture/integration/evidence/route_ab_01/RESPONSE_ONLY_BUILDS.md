# Response-only composite: build and model-run index (2026-10-09 / 10)

Program: N (pipe 0 ingress, `core/response_only/make_n.py`) + E, the B' response path (pipe 0 egress,
`make_e.py` from the unmodified `protocol/case4_response_path.p4`) + T (pipe 2, `read/read_queue_timing.p4`),
composed by `core/response_only/compose.py`. Every directory has:
- `manifest.json`, with the exact command, compiler and version, exit code and the hashes of every source and
  include;
- `compile.log`;
- `source/`, the exact inputs;
- `out/*/logs/table_summary.log` and `pa.results.log`.

The raw compiler trees (`out/`) and raw model logs stay on disk, gitignored. Local builds used SDE 9.13.1
(`build.py`); `compile_switch_9132` used the switch's installed 9.13.2, compile-only (`installed_sdk_build.py`).
Stages are ingress/egress per pipe. Model runs are the local Tofino-1 model, functional only: not hardware,
not timing.

| build | exit (9.13.1 / 9.13.2) | p0 stages | what it showed |
|---|---|---|---|
| response_only_01 | 6 / 6 | 13/11 | First pipe-0 N+E compile: PHV allocation failure, 4 fields short (N still carried its decoy state). |
| response_only_02 | 6 / - | 13/11 | With the N_ACK_RETURN loop: PHV 5 fields short. Led to the generator `response_only` profile. |
| response_only_03 | 2 / - | 13/11 | PHV fits; ingress 13 at critical path 11. Placement: N fills stage 1, which ingress shares with E's egress (table IDs, crossbar, hash). N alone (`compile_n_alone`): 12. |
| response_only_04 | 2 / - | 13/11 | ACK test folded into `ports`: still 13 (`input_head_t could not fit within the input crossbar`). |
| response_only_05 | 0 / 0 | 12/11 | Five duplicate CRC tables merged into `crc_t`: fits. |
| response_only_06 | 0 / 0 | 12/11 | Review fixes C1-C3, W1-W2. |
| response_only_07 | 0 / 0 | 12/11 | Model: `model_01`/`_02` front ports looped (`MODEL_INT_PORT_LOOP`); `model_03` exposed the E checksum defect (every mapped ACK short by its ACK value, `c111` vs `c496`). |
| response_only_08 | 0 / - | 12/11 | Metadata-side `@pa_no_overlay` pins: allocation unchanged. `pin_probe/q` (pipe-qualified) and `pin_probe/s` (`@pa_solitary`): unchanged; pins are not honored. |
| response_only_09 | 2 / - | 13/13 | Zeroing absent padding headers late: a 13th stage on both gresses. Rejected. |
| response_only_10 | 0 / 0 | 12/11 | Checksum split into three single-term deparser updates (make_e edit 3). Model `model_02`: 29/29. `teeth_c3_no_egress_port`: without E's `egress_port` binding exactly the two forged-tuple checks fail. |
| response_only_11 | 2 / - | 13/14 | Tail loop guard: critical path 12. Rejected. |
| response_only_12 | 2 / - | 13/11 | Guard as a separate `if` after `connection`: next-table order pulls later tables one stage on. Rejected. |
| response_only_13 | 2 / - | 13/11 | Guard as first arm of the `m.go` chain (`m.output_port`): 13. Rejected. |
| response_only_14 | 2 / - | 13/11 | Same, reading `tm.ucast_egress_port`: 13. Rejected. |
| response_only_15 | 0 / - | 12/11 | Guard as a `guard` table entry (make_n edit 8): fits. Model `model_01`: driver error, E `odd_ip_t` host-pair conflict for slot 1. `model_02`: 62/66 (READ timing artifact; T dropped closes). |
| response_only_16 | 0 / 0 | 12/11 | T forwards qualified closes. Model `model_01`: device add failed, `tin_verdict` 15 entries vs `size = 14`, which bf-p4c accepted silently. |
| response_only_17 | 0 / 0 | 12/11 | `size = 15`. Model `model_01` 61/70 (replies 50 ms after injection overlapped N's busy record; late response outside capture). `model_02` 67/70 (commit vs fallback swapped: model clock cannot rank them). **`model_03`: 70/70.** |
| response_only_18 | 0 / 0 | 12/11 | `_17` plus a corrected comment in E (pins not honored). Normalized assembly identical to `_17` on all three pipes. **Committed program.** |
| t_close_fix_01 / _02 | 0 / 0 | T 11/0 | T standalone after the close fix (`_02` with `size = 15`); critical path 9. |
| compose_t_response_01 | 0 / 0 | 1/12 | Earlier T + response-path join (stub ingress). `model_join_02` 6/6, `model_padded_01` 14/14. |

The narrative, numbers and open items are in `read/TIMING_QUEUE_MIGRATION_STATUS.md`.

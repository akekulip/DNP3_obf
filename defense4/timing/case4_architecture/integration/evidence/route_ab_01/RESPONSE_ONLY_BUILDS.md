# Response-only composite: build and model-run index (2026-10-09 / 10)

Note: `response_only_19` and `response_only_2*` are another workstream's builds, not this index's.

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
| response_only_18 | 0 / 0 | 12/11 | `_17` plus a corrected comment in E (pins not honored). Normalized assembly identical to `_17` on all three pipes. Committed in 2cb6ecf9d; superseded by two_pipe_01 (3-pipe placement cannot load on the 2-pipe chip). |
| response_only_19 | 0 / 0 | 12/11 | `_18` plus make_e edit group 4 (E only, source diff = those lines): outgoing link CRC by XOR in the pad action, tail CRCs hashed early from native fields; 4 E tables and 1 hash unit fewer, PHV 196 -> 193 (8b 59 -> 55, 16b 73 -> 74, 32b 64), same on 9.13.2. Model `model_01`: 70/70, every emitted frame byte-identical to `_17/model_03`; `efficiency_01/verify_wire.py` valid in all three deparser cases. |
| two_pipe_01 | 0 / 0 | 12/11 (T: p1 11/0) | `Switch(p0, p1)`: T moved to pipe 1 (the switch has 2 pipes; `_18` placed T in pipe 2 and cannot load). conf pipe_scope p0 [0,2], p1 [1,3] (bf-p4c/SDE 2-pipe form; acceptance on the chip unverified). Model `model_01`: 70/70. |
| clone_marker_composite_01 | 0 / 0 | 12/11 (T: p1 11/0) | T tells clone from generator token by content (CLONE_MARKER 0xE1, exact lookahead; branches on `hdr.clone/timer.isValid()`). Model `model_01` 70/70; `model_tok196` 2/2 (tokens injected on 196 reach the token verdict). Teeth: same driver on two_pipe_01 fails (`two_pipe_01/model_tok196_teeth`). |
| clone_marker_t_01 | 0 / 0 | T 11/0 | T standalone after the clone marker; critical path 9. |
| op_tag_composite_02 / op_tag_t_02 | 0 / 0 | 12/11 (T 11/0) | OPERATE clone tag `0xE101 ++ op_gen[15:0]`. Model 70/70. |
| token_admission_composite_01 / _t_01 | 3 / 3 (T: 0 / 0) | - | Composite: `t_reject: declaration not found`; compose's role prefixer read the comment "parser reject" as a declaration. |
| token_admission_composite_02 / _t_02 | 0 / 0 | 12/11 (T 11/0) | Tokens only from 196 (or model port 0) in generator format; clones only by 0xE1; other pipe-1 ingress dropped uncounted. Model `model_01` 70/70; `model_tok196_front164` 6/6. |
| shared_port_01 (shared, distinct) | 0 / 0 each | 12/11 (T 11/0) | `ports` keyed on `hdr.ip.src`; `shared_*` composed with `--relay-port=9` (both endpoints on dev_port 9), `distinct_*` default. Model `model_shared_01` 57/57 (`SHARED_PORT=1`), `model_distinct_01` 70/70. |
| t_close_fix_01 / _02 | 0 / 0 | T 11/0 | T standalone after the close fix (`_02` with `size = 15`); critical path 9. |
| compose_t_response_01 | 0 / 0 | 1/12 | Earlier T + response-path join (stub ingress). `model_join_02` 6/6, `model_padded_01` 14/14. |

**Provenance of the CRC edits (corrects an earlier note here and in 979b38fd1's message).** 979b38fd1's
message and an earlier version of this paragraph said 2cb6ecf9d already contained the efficiency
workstream's edit group 4. That is wrong, checked against git: 2cb6ecf9d's `make_e.py` and
`e_response_only.p4` contain no `0x3b2f`, and 2cb6ecf9d's own `make_e.generate()`, run from a clean
`git archive` of that commit, reproduces its committed `e_response_only.p4` byte for byte (sha256
`0a32f97a8d5310ab...`). Edit group 4 first appears in 17161e70b (make_e.py +49/-2), built and verified as
`_19` (70/70, all three checksum cases valid from emitted bytes). The likely source of the error: at
relocation time HEAD was already 17161e70b, so HEAD's generators did differ from `_17`/`_18` — but because of
17161e70b, not 2cb6ecf9d. `two_pipe_01` is the first two-pipe build of that same `make_e.py`.

**`_19` evidence restored.** The relocation build briefly composed into `response_only_19/` and overwrote
three of its files (`compile_local.stdout`, `compile_switch_9132.stdout`, `source/response_only.inputs.json`).
All three were already committed in 17161e70b and have been restored from git; nothing was lost.

The narrative, numbers and open items are in `read/TIMING_QUEUE_MIGRATION_STATUS.md`.

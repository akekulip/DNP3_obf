# E window fold classify experiment

Isolated attempt to fold the final reverse `window_t` exact/clamp decision into `classify_rev` while preserving outcome counters, lifecycle, CRC, inverse arithmetic, and checksums.

Result: blocked. The arithmetic row split is equivalent, but the required direct endpoint precompute makes `reverse_window_base` add the widened TCP window and `m.r` to `m.s_end` in one action. Local bf-p4c 9.13.1 rejects that as an action spanning multiple stages.

Artifacts:

- `evidence/full_01/response_only.p4` transformed source.
- `evidence/full_01/compile_local/compile.log` failed compiler log.
- `evidence/full_01/baseline_stage11_allocations.json` current stage-11 allocation extract.
- `evidence/full_01/result_summary.json` result and diagnostics.

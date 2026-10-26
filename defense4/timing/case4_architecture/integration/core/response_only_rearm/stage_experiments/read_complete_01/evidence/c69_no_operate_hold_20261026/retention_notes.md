The c69 compiler bundle is bounded by `compiler_retention.json`. Its `files` map
lists every repository-relative file to retain, with size, SHA-256 and reason.
The inventory includes all successful compile-manifest artifacts, every supported
profile artifact (including `response_only.p4pp`), all resource report pins,
source and compile log. Failed `compile_attempt_01` retains its source snapshot,
manifest and compile log. Other local compiler diagnostics and partial IR remain
unchanged and are excluded from the retained bundle.

The compiler inventory was checked with the existing local
`build.py::verify_evidence`; source, snapshots, compiler identity and compiled
artifacts all verified. The compiler binary remains an external prerequisite
with its original SHA-256 pin.

After the last model gate, run from the repository root:

```sh
python3 defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/read_complete_01/evidence/c69_dependency_retention_20261026/archive_completed.py
```

This c69-only command requires a completed `launch_command.json` with final exit
code and matching dependency-closure SHA before archiving. It includes failed
fixtures, preserves raw logs, checks existing archives instead of replacing them,
and uses single-thread xz preset 6 at niceness +10. It writes per-run
`RAW_SHA256SUMS` and the existing restoration helper's `logs` manifest format.
`runs` additionally pins the original launch, final closure and result summaries.
Missing completion records are skipped and must be captured by a later rerun.

The existing `restore_retained_logs.py` is unchanged. Its targeted suite passed
25 tests. Additional synthetic checks for the c69 archiver confirmed running-run
skipping, retention of a failed fixture, repeatability without overwrites, and
rejection of raw-log or closure tampering.

For the final explicit staging inventory, combine the compiler inventory's
`files` keys, the model retention manifest's `logs[*].archive` values and each
`runs` key followed by `/RAW_SHA256SUMS`, plus these metadata files and
`c69_dependency_retention_20261026/archive_completed.py`. Raw model logs remain
local; their byte-exact xz files are retained. Retention does not qualify failed
attempts or assert hardware or physical timing validation.

Final verification:46 logs from23 attempts (six failed),7,579,676,262 raw bytes and348,680,764 archive bytes. Fresh checkout restored the shared374-log inventory with zero failures, then independently verified all c69 raw/archive and attempt-record pins. All38 compiler-retention files matched. See `clean_checkout_verification.json`.

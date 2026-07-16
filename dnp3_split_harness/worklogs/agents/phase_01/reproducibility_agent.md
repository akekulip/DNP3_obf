# Phase 01 — Reproducibility Agent worklog

Date (session): 2026-07-15 UTC
Working dir: `/home/philip/Projects/DNP3/dnp3_split_harness` (Python 3.8.10)
Existing run under audit: `runs/20260716T024101Z_phase_01_real_trace_characterization/`
Driver: `phase01_characterize.py` (route: `phase01_reconstruct` extractor → `phase01_stats` → `run_manifest`)

Read-only audit except: this worklog + one fresh reproduction dir `runs/repro_check_phase01/`
(minted, verified, then removed — `runs/` is gitignored).

---

## 1. Manifest completeness — PASS (no missing fields)

Source: `runs/20260716T024101Z_phase_01_real_trace_characterization/manifest.json`

| Required field | Present? | Value / note |
|---|---|---|
| run_id | yes | `20260716T024101Z_phase_01_real_trace_characterization` |
| git commit (full) | yes | `c69e07e569183f2d21846c1c909aef28fdb2aa25` (len 40, confirmed full) |
| branch | yes | `research/ack-timing-phased` |
| dirty_tree | yes | `true` + `dirty_files` list (5 files) |
| python_version | yes | `3.8.10` |
| tool_versions.tshark | yes | `TShark (Wireshark) 4.4.9.` |
| tool_versions.scapy | yes | `2.4.3` |
| host / os / kernel | yes | host.hostname=`gambit`, host.os=`Linux-5.15.0-139-generic-x86_64-with-glibc2.29`, host.kernel=`5.15.0-139-generic` |
| command (argv) | yes | `["phase01_characterize.py"]` |
| six input paths + SHA-256 | yes | all 6 under `inputs{}`, each with `path` + `sha256` + `size_bytes` |
| start / end UTC | yes | start_utc=`2026-07-16T02:41:01Z`, end_utc=`2026-07-16T02:41:10Z` (also created_utc + duration_ms=9626.709) |
| exit_status | yes | `0` |

No field from the required checklist is missing.
Observation (not a checklist failure): `DATA_PROVENANCE.md §2.1` also lists `random_seed`,
`dependency_versions`, `nic_info`, `tcp_offload_settings`. This is a pure PCAP-analysis run, so
NIC/offload are legitimately N/A. `random_seed` is not a top-level manifest field, but the
bootstrap CIs use a hardcoded `seed=12345` in `phase01_characterize._metric_block` (deterministic).
Not required by this task's checklist; flagged for completeness only.

## 2. Input hashes — PASS (match manifest AND Phase 00 provenance)

Recomputed `sha256sum` of the six raw PCAPs in `Traffic Trace/` this session and compared to
BOTH the manifest `inputs{}` and the `DATA_PROVENANCE.md` §1.1 table. All six match exactly:

| File | SHA-256 | manifest | DATA_PROVENANCE |
|---|---|---|---|
| AB1400.pcap   | `01dceb19965f42fec16fad2b6bf2a563849d3a052c53831fe6c49d47f2dc86b5` | match | match |
| AB1400L.pcap  | `7c631744fe5d1f7748e517a05d1571164201a0ee63e216ac91dc3257a60f6e76` | match | match |
| SEL751.pcap   | `519cae47ea3863ea5c08783ee435935aca7a570a31e15e86e72b17681b0e981c` | match | match |
| SEL751L.pcap  | `be6159026c1b4ffff62b698eb9939cd675fd6ae8ff9f11d42029c6b084ddc2bb` | match | match |
| ION7550.pcap  | `f41681a631ed08ef6458d47d181f46222fd48c3b885e5e7c061cbe1a9ce12d6f` | match | match |
| ION7550L.pcap | `69c9dcf9c2ccf012ae5d09817bb860361acb122938892417c09c7825a06dc2b9` | match | match |

Zero mismatches.

## 3. No fixed report overwritten — PASS

- `reports/ack_trace_characterization.csv` — tracked (`git ls-files` confirms), timestamp
  Jul 14 16:13 (predates the run at Jul 15 22:41). `git status --porcelain reports/` is empty
  → unmodified.
- `profiles/*` — three tracked files (`ab1400_combined_ack.json`, `ion7550_combined_ack.json`,
  `sel751_separate_ack.json`), all timestamp Jul 14 16:13. `git status --porcelain profiles/`
  empty → unmodified.
- The run wrote its own copies INTO `runs/.../reports/` and `runs/.../profiles/`
  (e.g. `runs/.../profiles/sel751_observed_profile.json`, `runs/.../reports/ack_trace_summary.md`)
  — different paths, not the fixed ones.
- After BOTH of my repro invocations, `git status --porcelain` shows **no tracked-file
  modifications** (only untracked `??` phase01_*.py / acj_delay2.md that pre-existed).

## 4. One-command reproduction — PASS (deterministic, byte-identical)

Command run: `python3 phase01_characterize.py --run-dir runs/repro_check_phase01`
Result: exit 0, "reconstructed 22988 transactions".

Compared `runs/repro_check_phase01/tables/ack_trace_characterization.csv` to the existing run's:

- Total data rows: **22988 == 22988** (both files 22989 lines incl. header).
- Whole-file `diff -q`: **IDENTICAL**.
- SHA-256 of both CSVs: `09fa133be1b8ab65e6dfff56987e3a6bb47a9c051ff004239fa7e8a377959199` (equal).
- Per-(device,capture) COMBINED / SEPARATE / OTHER counts — identical across both runs:

| capture | total | COMBINED | SEPARATE | OTHER |
|---|---:|---:|---:|---:|
| AB1400.pcap   | 798  | 797  | 1    | 0 |
| AB1400L.pcap  | 3998 | 3997 | 1    | 0 |
| ION7550.pcap  | 1598 | 1597 | 1    | 0 |
| ION7550L.pcap | 7998 | 7996 | 2    | 0 |
| SEL751.pcap   | 598  | 298  | 300  | 0 |
| SEL751L.pcap  | 7998 | 3998 | 4000 | 0 |
| **GRAND**     | **22988** | | | |

Because the CSVs are byte-identical (same SHA-256), the classification for every single row —
not just a sample — matches. Only the two manifests differ (timestamps/run_id), which is
expected and fine. **Reconstruction is deterministic and reproducible.**

## 5. Populated-dir refusal — PASS

Re-ran the same command against the now-populated `runs/repro_check_phase01`:
- Exit status: **2**.
- Message: `ERROR refusing to write into a populated run directory: .../runs/repro_check_phase01`.
- CSV SHA-256 unchanged after the refused run (`09fa133...`) → nothing overwritten.
- No new auto-minted run dir was created (`ls -dt runs/*/` unchanged).

Code path confirmed by reading source: `run_manifest._is_populated()` (dir exists AND non-empty)
→ `RunContext.start` raises `RunDirectoryError` → `phase01_characterize.main()` catches it and
`return 2`.

## Cleanup

`runs/repro_check_phase01/` removed with `rm -rf` at end of audit (`runs/` is gitignored;
nothing tracked was touched).

## Verdict

Manifest complete: Y · Hashes match Phase 00: Y · Reconstruction reproducible (identical
transaction data): Y · Fixed reports untouched: Y · Refusal works: Y.

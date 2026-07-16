# Phase 01 — Closeout

Phase 01 received a **CONDITIONAL PASS**. This closeout executes the required actions
(items 1–7) without beginning Phase 02. It resolves everything that can be done
programmatically and leaves exactly one open item — **genuine human packet inspection** —
which an automated agent cannot perform and which the reviewer explicitly required a person
to complete.

- **Phase 01 code commit:** `7b2701b9989f6a7bba6cfff25705e4d02fc13413` (feat: full Phase 01
  implementation) + `8ed594881c28ad76d4ea6aa2478d0a1ab8c21c07` (adds `--isolated`/`--run-name`
  to the driver so the documented command runs verbatim).
- **Closeout / results commit:** `__RESULTS_COMMIT__`.
- **Fresh run ID:** `20260716T103940Z_phase_01_real_trace_characterization_committed`.
- **Branch:** `research/ack-timing-phased`.

## 1. Committed implementation

All Phase 01 source, tests, reports, and configuration are committed:
`phase01_reconstruct.py`, `phase01_stats.py`, `phase01_characterize.py`,
`phase01_extractor_agreement.py`, `phase01_manual_validation.py`, `phase01_figures.py`,
`phase01_human_validation_prep.py`, `tests/test_phase01_stats.py`, and the deliverable under
`reports/phases/phase_01/`. `acj_delay2.md` (the governing plan) was committed separately so
the working tree is clean — consistent with the repo's other tracked planning docs. No
personal notes were committed.

## 2. Fresh rerun from the committed state (manifest status)

The documented command was run from the clean committed state:
```
python3 phase01_characterize.py --isolated --run-name real_trace_characterization_committed
```
Manifest of the fresh run: **`dirty_tree = false`**, **git commit
`8ed5948…` = the committed implementation**, tool_versions `{tshark 4.4.9, scapy 2.4.3}`,
all six raw-PCAP paths + SHA-256 present and matching Phase 00, exact `command` recorded,
`exit_status = 0`. The populated-directory refusal was re-checked (exit 2, no overwrite).

## 3. Old-versus-new comparison (every difference explained)

| item | old run `…4101Z` | new run `…3940Z_committed` | match |
|---|---|---|---|
| transaction count | 22,988 | 22,988 | ✓ |
| transaction CSV SHA-256 | `09fa133b…` | `09fa133b…` | ✓ identical |
| device counts (per device/capture) | — | — | ✓ identical |
| ACK-mode counts | SEL-751 100% sep; AB1400/ION7550 combined | same | ✓ |
| anomaly counts | 93 retrans / 93 dup / 4 reset / 0 ooo / 0 missing | same | ✓ (`transaction_anomalies.csv` identical) |
| summary statistics | `device_summary.json` | identical file | ✓ |
| profile values | 3 profiles | identical files | ✓ |
| capture comparison | `capture_comparison.csv` | identical file | ✓ |

**Only difference:** the embedded `run_id`/timestamp strings in the manifest and the report
headers (e.g. `ack_trace_summary.md` line 3). All scientific results are byte-identical — the
expected outcome for a reproducible pipeline.

## 4. Human packet validation (findings)

The automated 60/60 check is now labeled **AUTOMATED FRAME-TARGETED RE-EXTRACTION
VALIDATION** (it is a second tshark read, not human inspection). Genuine human validation
was **prepared, not completed**:

- `phase01_human_validation_prep.py` wrote `validation/human_packet_validation.csv` — a
  **75-transaction** worksheet (60 deterministic 20/device @ seed 20250716 + the lone ION7550
  separate + all 4 reset + 10 retransmission/duplicate-ACK across affected captures) with the
  packet fields (frames, sizes, seq, expected & observed ACK, software ACK mode) pre-read and
  the **reviewer verdict columns intentionally blank**.
- `validation/human_packet_validation.md` is the review protocol.
- **Status: INCOMPLETE.** No human verdict was auto-generated (the reviewer required a person;
  this agent cannot perform genuine Wireshark inspection). Phase 01 human validation is
  complete only when a human fills every `reviewer_ack_mode` / `agreement` row.

## 5. ION7550 separate-ACK exception

Documented in `phase_01_trace_characterization.md` (§ION7550 Separate-ACK Exception) and not
generalized (n=1): `ION7550L` req_frame 8135 / pure-ACK 8136 / resp 8137; request→response
**72.058 ms** vs the surrounding ±5 combined transactions (~15.6–16.1 ms) and the ION7550
combined median 15.983 ms. No retransmission/duplicate-ACK/reset; the pure ACK acknowledges
the request (68584 = 68549 + 35). Reading: a single delayed-response event where a slow
(~72 ms) response let the host emit a standalone ACK first — an anecdote consistent with the
Phase 03 mechanism, not evidence of a rate.

## 6. Tests

| Check | Result |
|---|---|
| `python3 -m pytest tests/ -q` | **39 passed** (22 timing_policy + 8 run_manifest + 9 phase01_stats), Python 3.8.10 |
| Fresh isolated run | PASS (`dirty_tree=false`, manifest commit = code) |
| Populated-dir refusal | PASS (exit 2, no overwrite) |
| Manifest validation | PASS (all §3 fields; tshark+scapy; six hashes; exit 0) |
| Output-hash comparison (old vs new) | PASS (transaction CSV byte-identical; only run_id differs) |
| Human validation review | **INCOMPLETE** (worksheet prepared; verdicts blank) |
| Rig / pydnp3 integration tests | **SKIPPED** (environment unavailable) — reported skipped, not passed |

## 7. Remaining limitations

- **Genuine human packet validation is not done** — the single blocker to full PASS.
- Deferred (non-blocking, not required by §4): persist the response packet's `tcp.ack` in the
  main transaction table (the COMBINED ACK relationship is already verified by the PCAP agent
  and the automated re-extraction re-read).
- The 22,988 / device behavior describes only the captured traces of these specific devices,
  not product families; the pure-ACK→response gap is a wire-visible interval, not exact
  device processing time; host-side timestamps are not wire timestamps.

## Final verdict

Per the gate, Phase 01 may be marked full PASS only when the generating code is committed
(✓), the fresh manifest records `dirty_tree=false` (✓), results are reproduced (✓), the
ION7550 exception is documented (✓), **genuine human packet inspection is complete (✗)**, and
no Phase 02 work has begun (✓). Because human inspection is the one item an agent cannot
perform, the phase closes as:

**Status: CONDITIONAL PASS.** `next_phase_allowed = false`.

```
STOP: Awaiting genuine human packet validation and human authorization before Phase 02.
```

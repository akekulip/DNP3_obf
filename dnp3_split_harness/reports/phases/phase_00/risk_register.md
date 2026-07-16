# Risk register (Phase 00)

Integrated risks from all four audit agents (repository architect, CLI inventory,
result provenance, research reviewer) plus lead-agent verification. Ranked by impact
on scientific correctness / reproducibility. Each row names a concrete mitigation and
the phase that owns it. IDs are stable references for later phases.

| ID | Risk | Evidence (path:line) | Severity | Mitigation | Owner phase |
|---|---|---|---|---|---|
| R1 | **Phase-2 ACK-delay before/after is presented as achieved but is a projection.** `plan_ack_response_release` has no enforcement mechanism and no PCAP; ACK-advancing modes aren't user-space-realizable (kernel owns the pure ACK). | `timing_policy.py:331-387`; `reports/trace_before_after.md:~33`; tutorial/briefing | **CRITICAL** (integrity/overclaim) | Relabel all before/after as PROJECTED / not wire-validated; do not reuse until a real mechanism + PCAP exist. Build the §H mechanism-feasibility table before Phase 04. | 03/04 |
| R2 | **Defense math triplicated.** The two attacker evals re-implement `max(native,target)` instead of importing the shipped scheduler, so "measured defense" can diverge from what `split_server.py` runs. | `timing_policy.py:12-14`; `attacker_eval.py:127,155`; `ack_fingerprint_eval.py:92` | HIGH | Consolidate onto `timing_policy`; add a regression test proving eval-path ≡ `ReleaseScheduler` on a fixture before removing copies (migration M3). | 05 (prep now) |
| R3 | **`run_master` SOE CSV appends without truncate.** Re-running a `--phase` accumulates rows and silently inflates the 800-measurement success bar. | `run_master.py:344-352,385` (lead-verified) | HIGH | Truncate or write to a run-scoped path per run; adopt the run-directory contract. | 02 (fix), all |
| R4 | **Undeclared heavy deps + unguarded imports.** numpy/pandas/sklearn/matplotlib + the tshark binary are absent from `requirements.txt`; `ack_fingerprint_eval.py` imports sklearn unguarded → clean-env crash for 3 scripts. | `requirements.txt`; `ack_fingerprint_eval.py:51-55`; `attacker_eval.py:45-50` | HIGH (repro-blocking) | Declare deps in `pyproject.toml`; guard the sklearn import; document tshark prerequisite (migration M1). | 00→01 |
| R5 | **Two parallel ACK feature extractors** (scapy `analyze_ack.py` vs tshark `characterize_ack_traces.py`) compute the same observables differently; only tshark feeds downstream → inconsistent "native" baselines possible. | `analyze_ack.py:100`; `characterize_ack_traces.py:141` | MED-HIGH | Pick the canonical extractor; prove observables match on a fixture; retire/wrap the other (migration M4). | 01 |
| R6 | **All analysis outputs use fixed, un-scoped filenames**; re-runs clobber prior artifacts; `extract_payloads` orphans stale `.bin`; timing `.jsonl` sinks accumulate. | CLI worklog; `split_server.py:630` | MED-HIGH | Run-directory contract (`runs/<id>/` + manifest); never append, never reuse a path (migration M9). | 01→02 |
| R7 | **16 of 24 reports have provenance gaps** — hand-authored aggregates with no producer, broken reproduce commands (renamed/missing pre-split scripts), missing `logs/master/soe.csv` & `logs/replay/`, out-of-repo rig SSH driver. | `result_provenance_map.md` | MED-HIGH | Do not carry gap-report numbers into new results; regenerate from raw in Phase 01+; commit the rig orchestration driver. | 01,06 |
| R8 | **Rig-only claims not yet wire-reproduced.** ~40 ms ACK threshold rests on manual tshark (`pure_ack_emitted=undetermined` in the CSV); ~211 ms RTO is loopback-only, not a wire RTO. | `reports/ack_separation_rig_results.md`; `rto_probe_notes.md` | MED | Reproduce both from fresh captures with packet-field ACK detection on the rig; never state ~40 ms as universal. | 03 |
| R9 | **Device capture IPs hard-coded and duplicated across 4 files** (no central table). | `characterize_ack_traces.py:54-58`; `ack_fingerprint_eval.py:62`; `attacker_eval.py:75`; `trace_before_after.py:53-57` | MED | Centralize into one shared device-IP table (the repo already uses `lab_config` for rig IPs). | 01 |
| R10 | **Data-collection mixed with plotting** in two evaluators couples results to matplotlib. | `ack_fingerprint_eval.py:191-193`; `trace_before_after.py:353-355` | MED | Separate analysis from figure rendering (proposed `evaluation/` vs `reporting/figures`). | 05 |
| R11 | **Near-duplicate socket-probe scaffold** (~10 helpers copied). | `rto_probe.py:201-232` vs `ack_separation_probe.py:268-321` | MED | Factor shared tshark capture harness into one module (migration M5). | 03 |
| R12 | **pcap overwrite** via delete-then-`tshark -w` at fixed paths each run. | `rto_probe.py:223-226`; `ack_separation_probe.py:312-315` | LOW-MED | Write captures under `runs/<id>/pcaps/`. | 03 |
| R13 | **Naming-rule leak.** The internal codename string is present in `docs/implementation_guide.md` (verified via grep; string withheld) — inside the rule's own example — and in two root-level note files. All `.py` source is codename-clean. Lead note: the architect's additional `README.md:13` citation could **not** be reproduced (no codename in any README). | `docs/implementation_guide.md` (in-scope); root `Claude Code Prompt- …md`, `docs/project-memory/lab-hosts-dnp3.md` | LOW-MED | Replace the literal example with a generic placeholder so the codename is absent from the tree. Flag only in Phase 00 (no edit to the governing spec during an audit). | 00 follow-up |
| R14 | **Stale root snapshots** `dnp3_experiment_harness*.zip` (pre-split duplicates) clutter the tree; both py38 and py312 bytecode caches present though 3.8 is canonical. | root zips; `__pycache__/` | LOW | Move to `legacy/` or remove (history retains); gitignore caches (migration M10). | 00 follow-up |

## Cross-cutting

- The single most important integrity item is **R1** — it is the difference between
  "we can normalize the visible request→response time of a piggybacked response"
  (supported, C5) and "we manipulate the separate ACK" (projected, not enforced). The
  §H mechanism-feasibility table (application write / tc / eBPF / bridge / DPDK /
  P4 / raw proxy / kernel) must precede any Phase-04 implementation.
- R3, R6, R9 are all resolved by the same move: the run-directory + manifest contract
  in `DATA_PROVENANCE.md`. Adopting it early retires three risks at once.

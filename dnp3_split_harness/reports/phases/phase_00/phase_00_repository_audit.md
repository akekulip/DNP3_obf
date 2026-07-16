# Phase 00 — Repository Audit and Reorganization Plan

DNP3 traffic-obfuscation research line (`dnp3_split_harness/`). This is the Phase 00
deliverable required by `acj_delay2.md` §I. It integrates four independent audit
agents plus lead-agent verification. **No scientific behavior was changed, no active
file moved or deleted, and no new timing distribution or ACK behavior was introduced.**

---

## 1. Phase objective

Understand the complete repository before changing any scientific behavior: inventory
and classify every file, identify entry points and duplicate implementations, run the
existing tests, map every result claim to its evidence, and produce a migration plan
that preserves current commands. Do not begin Phase 01.

## 2. Research questions

- RQ0.1 Which files are active source/CLI vs test vs data vs legacy?
- RQ0.2 Where is logic duplicated (timing math, feature extraction, replay servers)?
- RQ0.3 Do the existing tests pass on the supported interpreter, unmodified?
- RQ0.4 Which reported results are reproducible from a command + raw data, and which
  are hand-authored or depend on missing/renamed producers?
- RQ0.5 Which scientific claims are measured vs replayed vs simulated vs projected, and
  which exceed their evidence?
- RQ0.6 What reorganization reduces fingerprint-research risk while preserving
  byte-preservation, entry points, and provenance?

## 3. Scope

In scope: `dnp3_split_harness/` (the obfuscation line) and root-level context. Out of
scope: `dnp3_multicrob_harness/` (separate non-obfuscation line), `PyDNP3/` (reference),
and any behavior change. Read-only audit; the only writes are the Phase 00 deliverables
and agent worklogs.

## 4. Inputs and SHA-256 hashes

The six real-device PCAPs (Phase 01 input set), hashed this session — full table with
packet counts and durations in `../../../DATA_PROVENANCE.md`:

| File | Bytes | Packets | SHA-256 (short) |
|---|---:|---:|---|
| AB1400.pcap | 242,066 | 2,407 | `01dceb19…dc86b5` |
| AB1400L.pcap | 1,208,466 | 12,007 | `7c631744…f6e76` |
| SEL751.pcap | 216,416 | 2,104 | `519cae47…0e981c` |
| SEL751L.pcap | 2,888,482 | 28,007 | `be615902…ddc2bb` |
| ION7550.pcap | 498,327 | 4,904 | `f41681a6…12d6f` |
| ION7550L.pcap | 2,452,655 | 24,097 | `69c9dcf9…6dc2b9` |

Total 73,526 packets. Full 64-hex digests in `DATA_PROVENANCE.md`.

## 5. Repository commit

- Audited state: `dea8f8bde69cb524d92e7c55d84f6ce88f0d0c8a` (was `main` HEAD at start).
- Work branch created: `research/ack-timing-phased` (off the audited commit; the
  untracked `acj_delay2.md` was preserved). No tracked source changed.
- Remote: `github.com/akekulip/DNP3_obf`.

## 6. Environment

- Host `gambit` · Ubuntu 20.04.6 LTS · kernel 5.15.0-139-generic · x86_64.
- **Supported interpreter: CPython 3.8.10** (system `python3`) — the only place
  `pydnp3` builds; where the timing tests run. Packages present: scapy 2.4.3, numpy
  1.24.4, pandas 2.0.3, scikit-learn 1.3.2, matplotlib 3.7.5, pytest 8.3.5.
- Research venv `~/.venvs/research/bin/python` = 3.12.13 (scapy 2.7.0, **no pytest**) —
  usable for pure PCAP analysis only; committed code must remain 3.8-valid.
- External binary: tshark (Wireshark) 4.4.9 — a hard runtime dependency of the pcap
  tools, undeclared in `requirements.txt`.

## 7. Agents used and their findings

Four parallel agents, each read-only, each writing `worklogs/agents/phase_00/<name>.md`;
the lead independently verified the load-bearing findings.

- **Repository Architect** (`repository_architect.md`): classified all files; found the
  defense math triplicated (R2), two parallel ACK extractors (R5), undeclared deps (R4),
  the `run_master` CSV-append bug (R3), duplicated device IPs (R9), mixed analysis/plot
  (R10), duplicated probe scaffold (R11), and the codename leak (R13). Verified no active
  file imports from the archives; no import cycles.
- **CLI/Entry-point Inspector** (`cli_inventory.md`): mapped all 16 entry points
  (pydnp3/root/rig needs, outputs, overwrite/append behavior); surfaced three fresh-run
  isolation problems (R3, R6).
- **Reproducibility & Provenance** (`result_provenance.md`): 24 reports → 8 solid / 16
  gaps (R7); traced the 22,988-transaction claim to `characterize_ack_traces.py`.
- **Research Reviewer** (`research_reviewer.md`): classified 8 headline claims by
  evidence class and flagged the Phase-2 ACK-delay overclaim (R1) as the top integrity
  item.

Consolidated deliverables: `cli_inventory.md`, `result_provenance_map.md`,
`../../../RESEARCH_CLAIMS.md`, `migration_plan.md`, `risk_register.md`,
`proposed_repository_tree.md`, `file_inventory.csv`.

## 8. Files added, changed, moved, or deprecated

- **Added (Phase 00 only):** `PROJECT_CONVENTIONS.md`, `RESEARCH_CLAIMS.md`,
  `DATA_PROVENANCE.md` (at `dnp3_split_harness/`); `reports/phases/phase_00/*`
  (this report, `phase_status.json`, `repository_tree_before.txt`,
  `dependency_inventory.txt`, `file_inventory.csv`, `cli_inventory.md`,
  `result_provenance_map.md`, `proposed_repository_tree.md`, `migration_plan.md`,
  `risk_register.md`); `worklogs/agents/phase_00/*` (4 worklogs).
- **Changed:** none of the tracked source. (One self-inflicted fix: the codename string
  the architect agent echoed into its own worklog was redacted — no repo source touched.)
- **Moved / deleted:** none.
- **Deprecated:** nothing yet — the migration plan proposes consolidating the already-inert
  `archive_experiments/`, `archive_original/`, `future_work/` under `legacy/`, deferred to
  post-approval.

## 9. Exact commands

Reproduce the audit's mechanical parts:
```bash
# tests (supported interpreter)
cd dnp3_split_harness && python3 -m pytest tests/ -v
# hashes + capture metadata of the six inputs
sha256sum "Traffic Trace/"{AB1400,AB1400L,SEL751,SEL751L,ION7550,ION7550L}.pcap
capinfos -c -u "Traffic Trace/AB1400.pcap"   # (repeat per file)
# tree + inventory
find dnp3_split_harness -not -path '*/.git/*' -not -path '*/__pycache__/*' | sort
python3 <scratch>/gen_inventory.py           # -> reports/phases/phase_00/file_inventory.csv
# the 22,988-transaction result (raw, not from a report)
cd dnp3_split_harness && python3 characterize_ack_traces.py
```

## 10. Tests executed

`python3 -m pytest tests/ -v` on Python 3.8.10 → **22 passed in 0.03 s** (unit tests for
`timing_policy`: fixed/bounded targets, deterministic seed, deadline miss, fail-open,
queue limit, critical/unknown bypass, per-flow FIFO, ACK-before-response invariant,
byte-carry check, etc.). This is the current, live, unmodified baseline.

## 11. Tests skipped and why

- **Integration / rig tests** (`tests/native_master_loopback.sh`, `tests/loopback_smoke.py`,
  and any two-host Vision↔Hulk run): **skipped** — require `pydnp3` runtime, `fuser`/root,
  and/or the two-host rig not available in this audit session. Per the plan, a skipped
  privileged test is reported as skipped, never as passed.
- No test was modified, weakened, or deleted.

## 12. Raw result locations

- Inputs: `Traffic Trace/*.pcap` (hashes in `DATA_PROVENANCE.md`).
- Existing raw results (audited, not regenerated): `reports/*.{csv,json,jsonl,png,pcap}`,
  `profiles/*.json`, `payloads/`, `captures/`.
- Phase 00 artifacts: `reports/phases/phase_00/`.

## 13. Figures and tables generated

Phase 00 generates **no figures** (it is an audit). Tables produced:
`file_inventory.csv`, the CLI map, the provenance map, the claim ledger, the risk
register (all markdown/CSV under `reports/phases/phase_00/` and the root convention docs).

## 14. Main findings

1. `dnp3_split_harness/` **is** the active obfuscation root; the code that matters is
   3 library modules + 13 CLIs + 3 tests; 14 legacy modules are inert (no active import).
2. `timing_policy.py` is a clean, 3.8-valid, unit-tested pure-decision scheduler with the
   correct normalization semantics (`max(response_ready, desired_release)`).
3. **The most important gap is integrity, not code:** the Phase-2 separate-ACK before/after
   is a **projection** of an unwired, non-enforceable planner (R1/C8), yet is written up as
   an achieved manipulation.
4. Reproducibility is uneven: 8/24 reports are solidly regenerable; 16 have gaps (hand
   numbers, renamed/missing producers, out-of-repo rig driver).
5. Three concrete correctness/isolation bugs: `run_master` CSV append (R3), un-scoped
   clobbering outputs (R6), undeclared/unguarded deps that crash a clean env (R4).
6. Duplication risk: defense math triplicated (R2), two ACK extractors (R5), duplicated
   probe scaffold (R11) — all consolidate onto `timing_policy` / shared modules.

## 15. Failed or ambiguous cases

- The architect's `README.md:13` codename citation **could not be reproduced** by the
  lead's grep (no codename in any README); the verified location is
  `docs/implementation_guide.md` plus two root-level note files (R13). Recorded as
  corrected.
- `ack_separation_client_matrix.csv` carries `pure_ack_emitted=undetermined`, so the
  ~40 ms threshold is currently ambiguous at the data level (R8) — flagged for Phase 03.

## 16. Threats to validity

- Files were classified from headers/imports/call-sites, **not executed** — "active"
  means "on the current import/invoke path", not "verified to run end-to-end".
- Only unit tests ran; rig/integration behavior is unverified this session.
- One capture per device model ≠ product family; host-side capture ≠ exact wire timing.
- Prior reports' numbers were audited for provenance, not re-derived — Phase 01 re-derives
  from raw.

## 17. Measured vs simulated vs projected results

This phase produced **no** measured/simulated/projected experimental results — it is an
audit. It *classified existing* results: measured (C1–C4, rig/loopback), replayed (C5),
simulated (C7), projected (C8 + pad-rig drop). See `RESEARCH_CLAIMS.md`.

## 18. Claims supported by the phase

- The repository is fully inventoried and classified (480 files; 0 unknown).
- The 22 timing-policy unit tests pass, unmodified, on the supported interpreter.
- `dnp3_split_harness/` is the active root; archives are inert; entry points are mapped.
- The six input PCAPs are present and hashed.
- A migration plan exists that preserves every current command via wrappers.
- Every headline scientific claim is mapped to an evidence class and verdict.

## 19. Claims NOT supported (by this phase)

- Phase 00 does **not** validate any experimental result, does not run the rig, does not
  confirm reproducibility of the 16 gap-reports (only that they have gaps), and does not
  fix R1–R14 (it records them). It does **not** endorse the Phase-2 ACK-delay before/after,
  which remains a projection.

## 20. Remaining risks

See `risk_register.md` (R1–R14). Highest: R1 (ACK-delay overclaim), R2 (triplicated
defense math), R3 (CSV append), R4 (deps). R1 is the one that changes what may be
claimed in a paper; R3/R6/R9 are all retired by adopting the run-directory contract.

## 21. Status

**CONDITIONAL PASS.**

All six Phase 00 gate criteria are met: code and results are inventoried; existing tests
were executed (22/22 pass); no user file was lost (only additions; no move/delete); active
vs legacy is identified; the migration plan preserves current commands; and scientific
claims are mapped to evidence or marked unsupported. The status is *conditional* because
two integrity items remain unresolved in the tree and require a human decision before the
reorg proceeds:
- **Condition A (integrity):** relabel the Phase-2 ACK-delay before/after and briefing as
  PROJECTED / not wire-validated (R1), or explicitly accept the flag.
- **Condition B (naming rule):** decide on removing the internal codename from
  `docs/implementation_guide.md` (R13) — not edited here because Phase 00 does not modify
  the governing spec.
- Recommended (not blocking the gate): declare the missing deps + guard the sklearn import
  (R4, migration M1); approve `proposed_repository_tree.md` + `migration_plan.md` before
  any move.

## 22. Prerequisites for the next phase (Phase 01)

1. Human approval of this audit and of the target tree / migration plan.
2. A decision on Conditions A and B above.
3. Dependency declaration (M1) so a clean 3.8 env runs the analysis scripts.
4. Agreement that Phase 01 re-derives all trace-characterization numbers **from the raw
   PCAPs**, not from any existing report, and adopts the run-directory + manifest contract.

## 23. Gate line

```
STOP: Awaiting human review before Phase 01.
```

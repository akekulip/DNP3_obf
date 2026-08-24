# Phase 1 independent adversarial audit at 4f1df31 (Phase 1 completion REJECTED)

Date 2026-08-07. Branch `defense4-caseA-hw-integration`. Boundary commit `4f1df31`.

The earlier Phase 1 "25/25 pass" claim is rejected. The 25 tests passed but never touched the paths
below. Independent adversarial testing supplied bad evidence and the pipeline still exited zero. Every
failure here was reproduced against the committed `4f1df31` tools before any repair. Expected exit is
what a fail-closed tool must return; actual exit is what `4f1df31` returned.

## 1. score_campaign.py accepts bad blocks (all reproduced, exit 0, must be 1)

| case | expected | actual @4f1df31 |
|---|---|---|
| duplicate ACK in a normal block (`rows[i].dup_ack=1`) | 1 | 0 |
| retransmission in a normal block (`rows[i].retransmit=1`) | 1 | 0 |
| inconclusive ordering (`rows[i].order_inconclusive=true`) | 1 | 0 |
| missing `regs.reg_tag` field in the post snapshot | 1 | 0 |
| missing `queues` + `port_tm_drops` snapshots | 1 | 0 |
| `missing_ack` scenario where no ACK is actually missing | 1 | 0 |
| `missing_resp` scenario where no RESPONSE is actually missing | 1 | 0 |
| nonempty text file supplied as the PCAP | 1 | 0 |

Root causes: `dup_ack`/`retransmit`/`order_inconclusive` were recorded but never added to `hard`.
`reg_tag` was read with `(post.get("regs") or {}).get("reg_tag")` and checked `not in (0, None)`, so a
MISSING field read as clean (missing was treated as zero). `queues`/`port_tm_drops` were only inspected
when present, so their absence raised nothing. The scenario schema used permissive `allow_*` booleans,
so a declared negative that was never exercised passed. `--pcap` was checked with
`os.path.getsize(path) == 0` only, so any nonempty file passed.

Commands (representative):
```
python3 score_campaign.py dupack/block.json clean/ev_pre.json clean/ev_post.json \
  --scenario normal --mode D2 --n-expected 60 --expected-protected 60 ; echo $?   # -> 0
python3 score_campaign.py clean/block.json clean/ev_pre.json clean/ev_post.json \
  --scenario missing_ack --mode D2 --n-expected 60 ; echo $?                       # -> 0
python3 score_campaign.py clean/block.json clean/ev_pre.json clean/ev_post.json \
  --scenario normal --mode D2 --n-expected 60 --expected-protected 60 --pcap fake_text.pcap ; echo $?  # -> 0
```

## 2. pair_bytes.py returns BYTE-IDENTICAL for tampered/empty captures (reproduced, exit 0, must be 1)

| case | expected | actual @4f1df31 | verdict returned |
|---|---|---|---|
| two captures with zero relay->master frames | 1 | 0 | BYTE-IDENTICAL |
| ACK-only captures, zero protected payloads | 1 | 0 | BYTE-IDENTICAL |
| ACK present at ingress, dropped at egress | 1 | 0 | BYTE-IDENTICAL |
| Ethernet MAC changed at egress | 1 | 0 | BYTE-IDENTICAL |
| nonzero TCP checksum changed at egress | 1 | 0 | BYTE-IDENTICAL |
| both captures are relay->10.0.0.5, `--master-ip 192.168.10.1` | 1 | 0 | BYTE-IDENTICAL |
| wrong `--intended` file (parsed, never used) | 1 | 0 | BYTE-IDENTICAL |

Root causes: an empty match set produced no anomalies, so zero relevant frames "passed". Only frames
with `plen > 0` were considered for unmatched detection, so a dropped/changed pure ACK was invisible.
MAC addresses were assumed to be rewritten by an L2 switch and were never compared; the current P4 does
NOT rewrite source or destination MAC, so a MAC change must fail. TCP checksums were only noted when the
egress checksum was zero; a changed nonzero checksum was never compared. `extract()` filtered on
`ip.src == relay and sport == port` only, never on the master IP, so an entirely unrelated relay flow
compared clean. `--intended` was declared in argparse but never read. The match key omitted the DNP3
application sequence.

## 3. run_campaign.sh cannot fail on finalization, accepts stale dirs, no -e (reproduced)

- Extra PCAP at finalization: a stale `OUT/pcaps/` pre-seeded with `blk_STALE_EXTRA.pcap`, then a clean
  DRY run into the same dir. `finalize()` logged `PCAP count mismatch: got 4 expected 3` and set
  `RUN_FAILED=1`, but the run still exited **0**. `on_exit()` computed `rc` at its top (before calling
  `finalize()`), so any finalize/manifest failure could not change the exit status. Reproduced exit: 0.
- Stale/nonempty OUT directory accepted: the run above proceeded into a pre-populated OUT dir. Stale
  evidence can satisfy a failed copy.
- `set -Euo pipefail` without `-e`: several required staging and watchdog commands were unchecked.
- DRY PCAP stubs contained the text `DNP3-DRY-PCAP-STUB`, not valid captures, so the claimed
  PCAP-validation test never proved malformed/truncated captures are rejected.
- The orchestrator never invoked `analyze_campaign.py`, `pair_bytes.py`, or any offload check, and never
  copied the governing specification into the evidence directory.

## 4. analyze_campaign.py passes with no scores; one-session CI is zero-width (reproduced)

- `blocks.jsonl` absent: the analyzer exited **0** (no scores loaded, nothing flagged).
- One session per condition: `session_ci95_median = [10.000000000005116, 10.000000000005116]`, a
  zero-width interval that measures nothing about session-level uncertainty (`n_sessions = 1`).
- It did not require one PASS per block label, reject unknown modes, or detect missing/extra/unmatched
  scores. Its bootstrap depended on NumPy.

## 5. make_manifest.sh extension allowlist omits substantive artifacts (reproduced)

A dir with `driver.err`, `results.csv`, `environment.record`, `keep.json`. After `make_manifest.sh`:
`driver.err` in manifest: 0, `results.csv`: 0, `environment.record`: 0, `keep.json`: 1. The allowlist
(`*.pcap *.json *.jsonl *.txt *.log *.p4 *.py *.md *.conf`) silently drops driver error files, CSV
results, environment records, and figures. `make_manifest.sh` also lacked `set -e`/`pipefail`.

## 6. Offload control (Prompt 1) not implemented

There was no `ethtool` capture-and-enforcement of GRO/GSO/TSO/LRO at either observation point, and no
offload record in the evidence.

## 7. Canonical documents not consistently reopened (verified by reading them)

- `WORKING_NOTES.md` said Phase 1 acceptance was met, the commit line was unchecked, and Phase 1 was
  still in progress, at the same time.
- `EXPERIMENT_MATRIX.md` and `PARAMETER_CALIBRATION.md` still called the lifecycle defect open and kept
  pre-fix interpretations.
- `SPEC_IMPLEMENTATION_EVIDENCE_MATRIX.md` and `DEFENSE4_BOTTLENECKS.md` still named the pre-fix source
  and binary as current.
- The canonical freeze still contained a full PASS verdict below its withdrawn banner.

## Disposition

Every item above is repaired in this corrected Phase 1. The repaired tools live in
`../../control/deploy/`; their fail-closed behavior is proven by the extended suite
`../../control/deploy/fixtures/run_tests.sh` (REAL deterministic pcaps, no text stubs), which reports
every test name with its expected and actual exit code. **Result: 77 passed, 0 failed** — every
adversarial fixture above exits nonzero, the clean fixtures exit zero, invalid/truncated pcaps are
rejected, a declared negative not exercised is rejected, missing scorer output fails the analyzer, an
extra pcap fails the orchestrator, and a clean synthetic run produces paired pcaps, intended-byte
records, scorer records, analysis, a copied spec, offload records, provenance, and a complete manifest
that passes `sha256sum -c`.

Documentation reconciled: the withdrawn ae2a802 PASS freeze is archived verbatim in
`EXPERIMENTAL_EVIDENCE_FREEZE_ae2a802_ARCHIVED.md`; the canonical freeze carries only REOPENED;
`EXPERIMENT_MATRIX.md`, `PARAMETER_CALIBRATION.md`, `SPEC_IMPLEMENTATION_EVIDENCE_MATRIX.md`,
`DEFENSE4_BOTTLENECKS.md`, and `WORKING_NOTES.md` now agree (code repaired vs not re-accepted; pre-fix
hashes historical). The Introduction stays quarantined.

The repair makes the pipeline trustworthy; it does not re-accept any experimental result. Acceptance
stays with the Phase 6 gate. The live switch was not touched.

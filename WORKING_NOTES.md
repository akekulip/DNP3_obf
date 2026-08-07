# WORKING NOTES — Defense 4 gated closeout (2026-08-07)

**Governing plan:** `defense4/Defense4_Completion_Experiment_Prompts.md` (Prompts 0-8, one gate at a
time). No accepted verdict exists for Defense 4. Branch `defense4-caseA-hw-integration`, do NOT merge
to main. Not ADTA/ADTD. Timing Defense 4 only, no size obfuscation. Physical SEL-751 READ-only;
negatives run ONLY on an isolated software outstation (Phase 2). Plain storyline prose, no em dashes,
never "optimal" (say selected/tested), never describe a distribution by median or as an exact fixed
value when a late tail exists.

## Honest state (reconciled)
- The P4 lifecycle CODE was repaired (fix commit `e47bcaa`, source `1242ca4d…`, binary `97175e7d…`,
  BF-SDE 9.13.2, 12/12 ingress). This is a code/compile fact.
- The repaired implementation has NOT been re-accepted experimentally. No timing/byte/disposition/
  fail-open/negative/classification claim is accepted. Canonical freeze verdict = REOPENED.
- Pre-fix source `1272679…` / binary `0ec4e452…` are historical, not current.

## Phase 1 (fail-closed evidence pipeline) — reopened by independent audit, then repaired
The first Phase 1 pass (commit `4f1df31`, "25/25") was REJECTED: independent adversarial testing found
bad evidence that still exited zero. Every failure is reproduced at `4f1df31` in
`defense4/timing/evidence/PHASE1_INDEPENDENT_AUDIT.md`. The pipeline was then rebuilt to close them.

### What the corrected Phase 1 delivers
- `score_campaign.py`: mandatory scenario expectations (a declared negative must be exercised), every
  register/counter/queue/port field required present in both snapshots (missing != zero), reg_tag
  present+idle, exact counter reconciliation where the scenario permits, negative/noninteger deltas
  rejected, spec/label/mode/param reconciliation, PCAP validated by magic not size.
- `pair_bytes.py`: fails on zero relevant/zero protected frames, validates relay+master flow, matches
  ACKs too, MAC/IP/TCP preserved-field compare (MAC change fails; P4 does not rewrite MAC), nonzero
  checksum compare under offloads-off, real `--intended` (intended vs ingress then ingress vs egress),
  rejects malformed/truncated/wrong-flow/wrong-dest, handles VLAN explicitly, emits frame numbers.
- `run_campaign.sh`: `set -Eeuo pipefail`; refuses a stale/nonempty OUT; temp-copy + structural pcap
  validation + rename; runs the analyzer and the paired comparator before declaring success; records +
  enforces offload at both capture points; copies the spec + full provenance (commit, source/binary
  hash, env, tool versions, ifaces); `finalize()` runs BEFORE the exit code is chosen so an
  extra/missing pcap or a manifest/verify failure forces nonzero; dual-capture + pairing path for Phase 2.
- `analyze_campaign.py`: requires `blocks.jsonl` + spec; exactly one PASS score per expected label (no
  missing/extra/duplicate/unmatched, no unknown mode, no nonzero embedded exit); condition-aware
  grouping (mode,D_A,D_R,budget,scenario,device); pure-Python session bootstrap; one-session CI marked
  unavailable, not zero-width.
- `make_manifest.sh`: `set -euo pipefail`, hashes ALL files (no extension allowlist), excludes only the
  post-manifest verify outputs.
- `fixtures/build_fixtures.py` + `fixtures/run_tests.sh`: REAL deterministic pcaps (no text stubs),
  every audited failure covered; the runner prints every test name with expected+actual exit.
- Docs reconciled: withdrawn PASS freeze archived to `EXPERIMENTAL_EVIDENCE_FREEZE_ae2a802_ARCHIVED.md`;
  canonical freeze = REOPENED only; EXPERIMENT_MATRIX / PARAMETER_CALIBRATION / SPEC_IMPLEMENTATION /
  DEFENSE4_BOTTLENECKS reconciled (code-fixed vs not-re-accepted; pre-fix hashes historical).
  Introduction stays quarantined.

### Phase 1 acceptance (corrected)
- every listed adversarial fixture exits nonzero; clean fixtures exit zero;
- invalid pcaps rejected; a declared negative not exercised rejected;
- missing scorer output fails the analyzer; an extra pcap fails the orchestrator;
- a clean synthetic run produces paired pcaps + intended records + scorer records + analysis + copied
  spec + offload records + provenance + a complete manifest; `sha256sum -c` passes; no hashed artifact
  changes afterward; canonical docs agree; Introduction quarantined; committed + pushed; main untouched.

## STATUS: corrected Phase 1 rebuilt + retested offline. Full suite result recorded at commit time.
Live switch NOT touched. Do not request Phase 2 authorization until this corrected Phase 1 is
independently audited and accepted.

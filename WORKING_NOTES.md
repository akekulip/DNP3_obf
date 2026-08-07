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

## Full-plan run (authorized 2026-08-07, lead-PI autonomy)
Testbed reachable (switch ufispace, Vision, SEL-751 all up). Two lines held: SEL-751 READ-only
(SELECT/OPERATE only to the software outstation), and every switch write behind snapshot + watchdog +
D3 rollback. "Results in line with timing obfuscation" = run honestly, report what the data shows.

### ►► CRITICAL FINDING (read-only probe): the corrected binary was NEVER deployed
- Running pipeline loads `d4_build/build9132/pipe/tofino.bin` sha `0ec4e452` = the PRE-fix defective
  binary (D2 240/240 bypass, D4 80/240 bypass), from old source `1272679c`.
- The corrected binary `97175e7d` (from corrected source `1242ca4d`, identical to the repo) was
  compiled to `d4_fix_build/out/.../tofino.bin` on Aug 7 but the switch was never reloaded to it.
- So the current silicon is DEFECTIVE. The prior "switch runs the corrected binary" claim is wrong.
- `run_campaign.sh` preflight fixed to verify the LOADED pipeline sha, not a disk file. Recorded in
  `defense4/timing/evidence/PHASE2_3_SILICON_STATE_FINDING.md`.

### Progress this run (committed)
- Phase 1 corrected pipeline: 77/77 fail-closed suite green (bb0aedc); preflight fix (f93d87d).
- Phase 2 controlled software outstation scenario engine + offline validation 58/58 (1904e19):
  `defense4/timing/control/outstation/software_outstation.py` (21 cases) + `test_outstation_offline.py`.
  The live scapy wire realizer `serve()` is a documented stub, wired up in the live Phase 2 step.

### IMMEDIATE NEXT (high-stakes live step): Phase 3 deploy
Reload bf_switchd onto the corrected binary `97175e7d` and verify the LOADED sha == 97175e7d, ports,
queues, pktgen, policy, relay reachability, one READ. Do it under: read-only snapshot -> arm watchdog
(D3 rollback) -> reload -> verify -> rollback on any failed check. Needs the project's tested load
mechanism (rollback_defense3.sh / bringup_runner.sh / swap script) understood first. This reload
briefly interrupts testbed forwarding; do it carefully, not rushed.

## STATUS: mid-run. Phase 1 done (77/77). Phase 2 offline done (58/58). Phase 3 deploy of the
corrected binary is the next live action. Current silicon runs the DEFECTIVE pre-fix binary.

# Framework / Case 4 handover — 2026-10-06

Read [STATUS.md](STATUS.md), then [STATUS_MATRIX.md](STATUS_MATRIX.md) and [CLAIMS_RECONCILIATION.md](CLAIMS_RECONCILIATION.md). Repository `/home/philip/Projects/DNP3` is on `main`; protected execution base is `235e7f01…`. Recovery/association/admission is committed as `130aac45baef277fa40cbd2164ee79972ec22be5`; size and packet evidence is committed as `0131fbe903256f75511855d456c958d301c6a3a3`. The final artifact commit is identified by `git rev-parse HEAD`. All commits must use `akekulip <akekulip@gmail.com>` as author and committer, without co-author or co-contributor trailers. Preserve other working-tree edits and the 2,210 protected files in `PROTECTED_EXECUTION_BASE.json`.

## Current stopping point

Local recovery04 passes exact-source resource verification: source `3f759d06…`, SDE 9.13.1 `e558d01`, 10/0 stages, 104 tables. It implements actual app association, busy tracker/BOR admission guards, fixed 30 ms independent expiry, owner commitment phase and explicit native boundary fallback. It is not a deployable SDK 9.13.2 complete joint program.

The archived complete-ledger attempt 18 failed its PHV ACK-clamp expression. Current joint26 (10/10), source `bada4652…`, proves limited compiler coexistence with exact recovery04/current wire input hashes and corrected IPv4-version/TCP eligibility guards. Standalone wire24 (9/12) is an older source snapshot. Component source omits complete ledger, ingress CRC/shape and phase-specific association integration.

The current software artifact is `framework/results/case4_bmv2_transport_repair_20261006/`, source `0fba5225…`, with a verified 231-file manifest. `final_captures/sbo_12` retains two successful 55-byte SELECT/OPERATE requests and 57-byte echoes carved to `[28,29]`, statuses, both PCAPs and build identity. Tail traces cover actual P4 ACK transformation and manually injected last-native-byte cache replay with explicit receiver duplicate trimming. The older `framework/results/case4_bmv2_20261006/` and its verified 138-file manifest remain immutable. OpenDNP3's separate production-stack gate has 46 assertions / 4 passing cases; it is distinct from the Python codec emulator.

The aggregate regression ran 503 tests in 319.06 s: 501 passes, one failure, one error, zero skips. The generated-ACK evidence-file error and historical/current constants mismatch have targeted passing corrections; original log/results remain retained. The separately retained 22-test BMv2 run has 21 passes and one legacy gap tolerance failure. The repaired current source `0fba5225…` completed 23 BMv2 tests in 247.077 s: all 14 Case 4 pass, 22 total pass, one legacy failure, zero skips. Native-ACK forwarding measured 1,242,183 ns against the unchanged 1,000,000 ns limit; no rerun or tolerance widening. Current evidence is `framework/results/case4_bmv2_transport_repair_20261006/`. Inserted-tail ACK withholding, actual ACK/cache packet loss replay, both boundaries, wrap and zero windows pass. Autonomous kernel repair is unproved; the inactive full target prototype retains its unsafe clamp. Do not replace these states with a global all-tests-pass claim.

## Offline checks from repository root

```bash
python3 defense4/timing/framework/runner/cli.py plan --campaign defense4/timing/framework/declarations/case4_campaign.json
python3 defense4/timing/response_ready/verify_build.py defense4/timing/response_ready/src/defense4_response_ready.p4 defense4/timing/response_ready/evidence/case4_recovery_build_04 --profile case4
python3 defense4/timing/framework/analysis/admission_record.py /tmp/case4-admission.json --da-ms 10
python3 defense4/timing/framework/paper/working_gate.py
```

The retained recovery04 command above requires its ignored local SDK output, assembler and binary files. They are absent from a clean checkout; missing inputs must still fail the verifier. For a fresh checkout, first compile with an installed licensed SDE into an unused directory and verify that new manifest:

```bash
python3 defense4/timing/stage_reduction/build.py defense4/timing/response_ready/src/defense4_response_ready.p4 /tmp/case4_recovery_rebuild --compiler /home/philip/bf-sde-9.13.1/install/bin/bf-p4c --max-ingress 12
python3 defense4/timing/response_ready/verify_build.py defense4/timing/response_ready/src/defense4_response_ready.p4 /tmp/case4_recovery_rebuild --profile case4
```

Use the actual installed compiler path and a directory that does not exist. New compiler run IDs and artifact hashes need not equal historical outputs. See [compiler evidence packaging](../../response_ready/evidence/README_CASE4.md). The compile is offline and supplies no deployment authority.

The current offline mode values are in `framework/control/consts_case4.json`; `consts.json` and the default historical bring-up remain bound to retained df599 source. The new constants file supplies no live initialization or deployment authority. The verifier requires exact current source identity; an older snapshot can only be verified against its own source. Its `passed` result does not change `joint_mechanism_verified=false`, `deployment_authorized=false` or the SDK9.13.1 deployment blocker. The planning and admission commands do not connect to a device.

For focused regression, use `unittest discover` in `framework/tests` for `test_case4_packet_parity.py`, `test_model_vs_p4.py` and `test_admission*.py`; use `active_control/tests` for `*admission.py` and `response_ready/tests` for source/build fragments. The full test runner includes software network labs; its retained failure must be resolved or explicitly carried. Original codec BMv2 failure tolerance is unchanged.

## Remaining work and gates

1. Preserve both final BMv2 runs, their unchanged legacy timing failures and all failure manifests. The software tail repair is tested; autonomous kernel recovery and the full target ledger remain unresolved. Current corrected component build26 is retained. Retain all failed build manifests and logs. Successful component coexistence does not complete the hardware translation ledger.
2. Complete the bounded TCP stream/overlap/retransmission ledger, source CRC/eligibility and size/timing/phase integration; verify actual target semantics. Generic negotiated TCP options, old-epoch same-tuple FIN/RST quarantine and full BOR pipeline behavior remain outside demonstrated scope.
3. Produce an exact-source SDE 9.13.2 deployable joint artifact and genuine schema/write mapping. Case 4 controller currently has empty writes and refuses before device connection; keep that refusal until these exist.
4. Measure current-build switch tA/tR, feedback, detection, release, completion, heartbeat service and physical drain. Admission is provisional with twelve unavailable inputs and null ACK/response/recovery bounds. A nominal loop budget or TCP_INFO estimator cannot close them. Normal full gap requires successful ACK commitment; near readiness expiry the source explicitly permits native fallback.
5. Only then enforce the prepared matrix/runbook. Declared total 16,168 <= 18,360; maximum 14,571,200 ms; warmups/state READs retained, additional prechecks/retries consume the same ceiling. No campaign has been acquired. Physical OPERATE remains separate and attended; its declaration supplies no live authorization.
6. Keep the manuscript in `framework/paper` until implementation/evidence claims and author text are ready. The exact newer Dr. Lin paragraph is absent. Frozen paper, writing checker and Introduction stay unchanged; a local PDF build is not promotion or submission approval.

## Historical evidence to preserve

Earlier source `df599101…` was configured in Timing OFF, with main 30 READs and one separate precheck (31 capture exchanges). Its master RTO 201 ms and first repeat 204.4 ms are historical baseline observations. Current source admission correctly marks that timer inherited. Current hardware state was not re-read during this implementation; retained restoration/snapshot reports are historical, not a live-state assertion. Use `CASE4_HARDWARE_RUNBOOK_20261006.md` as a prepared, unexecuted procedure; its earlier candidate identity is historical and must be replaced by the actual deployable build before collection.

New cohort and admission artifacts are in `framework/results/case4_analysis_20261006/`; software population reanalysis is under `framework/results/bmv2_clrt_20261006/analysis_case4/`. Campaign-v2 reproduction path verification preserves the original reproduction and frozen publication checker. No current device labels or classifier results exist.

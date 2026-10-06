# Framework / Case 4 handover — 2026-10-06

Read [STATUS.md](STATUS.md), [STATUS_MATRIX.md](STATUS_MATRIX.md) and [CLAIMS_RECONCILIATION.md](CLAIMS_RECONCILIATION.md). Work directly on `main`; no branch, push or history rewrite. Author and committer must both be `akekulip <akekulip@gmail.com>` without contributor trailers. Preserve pre-existing local changes and all 2,210 files in `PROTECTED_EXECUTION_BASE.json`. Continuation base is 5a816ab26…; final revision is `git rev-parse HEAD`.

## Exact current stopping point

Recovery source `cac84a26aea5233ae01cb0f7ac220bded92a7a74c5005133dd8eeca2e53ca87a` has exact core22 compiler failure (PHV, 31 slices). Instrument05 source 8dcf04c3… separately fails (PHV, 35 slices). The mask bank uses 16 bits, with a zero-extended 16-bit cookie stored in 32 bits. Scalar SALU constraints now pass; owner/cookie/header PHV alignment remains unresolved after packed/pair/scalar and container attempts. All core01–22 and instrument01–05 failures are retained. The model, source control-fragment simulator and mutation regressions do not prove the full parser, BOR/interleaving, queue or wire path. Deferred modeled originals cover ACK/response; OPERATE deadline/reset checks are scalar/table tests, without an actual queued OPERATE packet-service proof.

`framework/p4/case4_ingress_mapping.p4` current 31bb3303… matches build33: six ingress / zero egress, local SDK 9.13.1 e558d01, 27 warnings. It checks per-pass cookie/phase and rejects window growth, but tests execute arithmetic phases 1–14 only. CP geometry, epoch/service/producer authentication and completed processing remain unproved. Its phase 15 drops. `case4_joint_processing_probe.p4` current 413e8c5b… matches composite34 and exact current inputs, but fails PHV; it is an incomplete resource probe, never a deployable program. Full inactive size build27 repairs clamps but remains failed/unqualified.

Policy-off drain is also unfinished: native phase-2 repair forwarding can continue after `read_release` is disabled, while original-bank terminal debit is gated by `read_release == 1`. This conservatively retains quarantine; it does not prove stop/drain liveness. Do not disable/reconfigure an active lifecycle without verified drain/cleanup. Generic configuration restoration supplies no such proof.

The actual validation/replacement-image/replay-cache/handshake/assembly/lifecycle producer is missing. Its timing seam must preserve the observed wire ACK before inverse translation: current timing tracker compares the packet ACK against stored wire_end. Preserve original observation timestamps and operation-specific request end. Port 69 cannot be activated until independent queue/return availability is established; no blind port/group substitution. Full target remains required; no reduced/software substitute completes it.

Production context_evidence_03 passes four cases / 46 assertions. Isolated Linux socket_evidence_03 passes actual sender-owned repair of both truncated commands and separately sealed raw-capture reconstruction. Both phases have 1-byte native repeats / 21-byte cached replay and complete 57-byte SUCCESS echoes. SELECT-to-OP acceptance 440.139 ms under configured 500 ms is one software observation. This is not target P4 or physical inertness. Context02/socket01 and independent analysis01/02 failures are retained; socket02 application-only PASS did not establish full transport parity.

Fresh Case 4 BMv2: 14/14 PASS, zero skips, 152.566 s. Its source 0fba5225… is unchanged, launcher/evidence reservation are corrected. Original combined 22/23 and older 21/22 network results and tolerances remain unchanged. These are Python codec endpoints, not the production socket gate.

Controller whole-plan/schema/source/policy/operation guards, backup/readback/restore/cancellation and SBO/observation import are implemented. The full-target qualified registry stays empty. `consts_case4.json` binds the current source only; it is not initialization/deployment authority. Generic configuration restore never claims switching back to a different saved program or physical drain.

## Reproduce offline checks

```bash
python3 -B defense4/timing/framework/runner/cli.py plan --campaign defense4/timing/framework/declarations/case4_campaign.json
python3 -B defense4/timing/framework/paper/working_gate.py
python3 -B defense4/timing/framework/paper/build.py
python3 -B -m unittest discover -s defense4/timing/framework/tests -p test_case4_preprocess.py -v
python3 -B -m unittest discover -s defense4/timing/framework/tests -p test_case4_binding.py -v
python3 -B -m unittest discover -s defense4/timing/framework/tests -p test_case4_drain_parity.py -v
```

The full framework runner includes legacy software network suites. Do not widen tolerances or erase retained failures. Current aggregate/post-review source identities, counts and deliberate exclusions are in `CONTINUATION_VERIFICATION.json` and its referenced logs; original `EXECUTION_VERIFICATION.json` remains unchanged. Final verification_03 passes 69 model/packet and 26 source-parity tests with zero skips. Its reused 100-test recovery log has explicit provenance; the root aggregate independently passed the same 100 frozen-P4 tests. Overlapping counts are not added as unique coverage. Mutation regressions execute actual cookie/mask/duplicate control predicates rather than merely recognizing a source literal. Their interpreter remains a subset.

A new local compiler run must use a fresh path and the actual installed licensed SDK. Current source is expected to remain blocked until the PHV architecture is corrected. Do not verify current source against historical recovery04 or joint26. Example fresh run:

```bash
python3 -B defense4/timing/stage_reduction/build.py defense4/timing/response_ready/src/defense4_response_ready.p4 /tmp/new-case4-recovery-build --compiler /home/philip/bf-sde-9.13.1/install/bin/bf-p4c --max-ingress 12
python3 -B defense4/timing/response_ready/compile_instrument.py /tmp/new-case4-instrument-build
```

Exact own-source/log/manifest/resource metadata is packaged; ignored SDK outputs/binaries/assembly stay local. Missing licensed artifacts must fail verification in a clean checkout. Local 9.13.1 is not deployed 9.13.2. No source/log/binary from a failed or older snapshot can qualify new source.

Endpoint production commands require explicit fresh evidence/build paths, as documented in `framework/size/endpoint_gate/README.md`. Evidence wrappers reserve before compile/namespaces/capture and reject existing files/directories/symlinks. No overwrite/resume/force or implicit rerun; explain a failure first and retain it. All nine sealed inventories hash-check.

## Required next dependencies

1. Correct the full recovery/header PHV architecture without weakening cookie/original/quarantine semantics; compile both core and instrument. Complete the actual target validation/images/cache/assembly/lifecycle and wire-ACK seam. Produce a genuine complete joint source and exact SDK 9.13.2 proof.
2. Source-review and qualify the actual full mutation inventory, queues/pktgen/PRE/loopback/ledger seeding and loaded artifacts. Preserve default refusal and physical saved-program restoration guards.
3. Obtain applicable build/connection/operation/profile timer, feedback, detection, release, heartbeat, completion, physical drain and SBO retention inputs. The READ record still has 12 missing inputs; control adds retention/profile/origin requirements. Internal learns supply no physical endpoints or future maxima.
4. Only then apply actual recorded live authorization/admission/restoration to the prepared runbook. Its older candidate identity is historical and must be replaced. Declared 44 blocks / 16,168 attempts include 600 warmups / 88 state READs; preserve 500 ms setup / 1 s block budgets, failed-attempt accounting and no implicit retry. Requested D_A grid 5/10/15/20, 1 ms gap, 100 us pulse, 30 ms readiness, 40 ms cap and existing 10 us / 99.9%-within-50 us criteria stay fixed. Physical OP remains attended verified inert only. No hardware traffic/contact or restoration occurred in this continuation; live state remains unknown here.
5. Keep the four-page working paper and editable full-width mechanism figure separate from frozen sources. Exact newer Dr. Lin text/acceptance and Philip's promotion instruction are missing. All 2,210 protected hashes pass; XML/export hashes pass; 13 strict figure policy warnings remain explicit and packaged. No new classifier/device-label or physical campaign claim is supported.

Historical OFF source df599101… had 30 main READs plus separate precheck and historical RTO 201 ms / first repeat 204.4 ms. Its load/restore/timer records remain historical. Campaign_v2 and its path-only 27-relocation reproduction stay unchanged. Do not promote older measured endpoints to current admission.

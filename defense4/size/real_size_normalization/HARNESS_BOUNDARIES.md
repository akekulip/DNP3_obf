# Real Size Normalization Harness Boundaries

Status: active for Gate S3 after author approval

Branch: `defense4-real-size-normalization`
Scope root: `defense4/size/real_size_normalization/`

## S0-S2 target result

Select a defensible two-boundary design whose observer-visible size transcript is independent of protected inner DNP3 length, using only Vision, the installed UFISpace Tofino-1 (including its onboard control CPU if verified suitable), and the existing relay leg.

## Locked surfaces

The following are evidence or authority inputs and must not be edited during S3:

- `defense4/README.md`
- `defense4/CLAIMS.md`
- `defense4/CODEX_NEXT_PHASE_REAL_SIZE_NORMALIZATION.md`
- `defense4/defense4_release/evidence/E_FINAL/`
- `defense4/size/native_parity/`
- the committed S0-S2 security, observer, impossibility, capability, design-selection, threat-model, and architecture artifacts, except append-only coordination logs
- the currently deployed P4 kernel, BFRT state, port state, TM/PRE state, mirror state, and pktgen state

## Editable surfaces

S3 edits are limited to:

- `defense4/size/real_size_normalization/offline/` for the deterministic codec, corpus driver, observer analysis, and tests;
- `defense4/size/real_size_normalization/evidence/s3_offline/` for reproducible generated PCAP/CSV/JSON evidence and its manifest;
- new S3 result, claim-matrix, runbook, and agent-review artifacts under `defense4/size/real_size_normalization/`;
- append-only coordination surfaces listed below.

S3 may read but not rewrite prior captures and frozen evidence. It has no hardware dependency.

## Append-only surfaces

- `THREAD.md`
- `MECHANISM_REGISTRY.jsonl`
- `REJECTED_OPTIONS.md`

Corrections to these logs are new entries; earlier entries remain intact.

## Human-controlled surfaces

The following require a later explicit authorization and are not part of S3:

- loading or stopping a P4 program;
- changing ports, forwarding, TM, PRE, mirrors, pktgen, routes, or interfaces;
- injecting traffic or starting packet capture on the live path;
- issuing DNP3 SELECT or OPERATE;
- changing relay state;
- installing packages on Vision or Tofino;
- pushing, merging, or deleting branches.

## S3 validation and stop condition

The author approved the conditional S2 selection on 2026-08-14. S3 stops after it has:

1. a deterministic offline fixed-cell encoder and decoder using a standard AEAD library;
2. exact inner-byte recovery across multiple captured and synthetic inner lengths;
3. fixed outer wire size, count, direction, and slot vectors under one declared policy;
4. deterministic loss, duplicate, reorder, replay, authentication-failure, and overflow tests;
5. reproducible PCAP/CSV/JSON evidence, an observer analysis, and an offline claim matrix;
6. independent security/code/evidence review and a dedicated S3 commit.

S3 can prove only an offline construction. It cannot upgrade the claim to hardware-observed real size normalization or prove the conditional Tofino CPU path.

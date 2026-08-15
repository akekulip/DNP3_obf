# Real Size Normalization Harness Boundaries

Status: active for Gate S4 software prototype after S3 PASS

Branch: `defense4-real-size-normalization`
Scope root: `defense4/size/real_size_normalization/`

## S0-S2 target result

Select a defensible two-boundary design whose observer-visible size transcript is independent of protected inner DNP3 length, using only Vision, the installed UFISpace Tofino-1 (including its onboard control CPU if verified suitable), and the existing relay leg.

## Locked surfaces

The following are evidence or authority inputs and must not be edited during S4:

- `defense4/README.md`
- `defense4/CLAIMS.md`
- `defense4/CODEX_NEXT_PHASE_REAL_SIZE_NORMALIZATION.md`
- `defense4/defense4_release/evidence/E_FINAL/`
- `defense4/size/native_parity/`
- the committed S0-S3 security, observer, impossibility, capability, design-selection, threat-model, architecture, offline specification, offline implementation, and offline evidence artifacts, except append-only coordination logs
- the currently deployed P4 kernel, BFRT state, port state, TM/PRE state, mirror state, and pktgen state

## Editable surfaces

S4 edits are limited to:

- `defense4/size/real_size_normalization/software/` for the isolated software shim prototype, driver, and tests;
- `defense4/size/real_size_normalization/evidence/s4_netns/` for packet-preserving namespace/veth PCAP/CSV/JSON evidence and its manifest;
- `defense4/size/real_size_normalization/evidence/s4_software/` for ancillary localhost TCP-record smoke evidence that must not be labeled a full S4 pass;
- new S4 result, specification, claim-matrix, runbook, and agent-review artifacts under `defense4/size/real_size_normalization/`;
- append-only coordination surfaces listed below.

S4 may read but not rewrite prior captures and frozen evidence. It has no hardware dependency.

## Append-only surfaces

- `THREAD.md`
- `MECHANISM_REGISTRY.jsonl`
- `REJECTED_OPTIONS.md`

Corrections to these logs are new entries; earlier entries remain intact.

## Human-controlled surfaces

The following require a later explicit authorization and are not part of S4:

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

## S4 validation and stop condition

S4 stops after it has:

1. two packet-preserving software shims connected through a rootless namespace/veth fixed-cell link;
2. native bidirectional DNP3/TCP correctness across at least 100 synthetic transactions spanning five protected response lengths;
3. exact trusted-boundary byte recovery and checksum-valid restored Ethernet/IPv4/TCP frames;
4. fixed outer wire size, count, direction, and slot vectors under the unchanged S3 cell policy;
5. deterministic loss, duplicate, reorder, replay, wrong-key-epoch, overflow, timeout/deadlock, and bounded-buffer tests;
6. reproducible PCAP/CSV/JSON evidence, observer statistics, overhead/latency/resource metrics, and a software claim matrix;
7. independent review and a dedicated S4 commit.

S4 can prove only isolated software-shim behavior on rootless Linux network namespaces and veths. It cannot upgrade the claim to hardware-observed real size normalization, live Tofino CPU punt/reinject behavior, RRC/BOR integration, or physical relay integration.

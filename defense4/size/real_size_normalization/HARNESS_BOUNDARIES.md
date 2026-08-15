# Real Size Normalization Harness Boundaries

Status: active for Gates S0-S2

Branch: `defense4-real-size-normalization`
Scope root: `defense4/size/real_size_normalization/`

## Target result

Select a defensible two-boundary design whose observer-visible size transcript is independent of protected inner DNP3 length, using only Vision, the installed UFISpace Tofino-1 (including its onboard control CPU if verified suitable), and the existing relay leg.

## Locked surfaces

The following are evidence or authority inputs and must not be edited during S0-S2:

- `defense4/README.md`
- `defense4/CLAIMS.md`
- `defense4/CODEX_NEXT_PHASE_REAL_SIZE_NORMALIZATION.md`
- `defense4/defense4_release/evidence/E_FINAL/`
- `defense4/size/native_parity/`
- the currently deployed P4 kernel, BFRT state, port state, TM/PRE state, mirror state, and pktgen state

## Editable surfaces

Only new design artifacts under `defense4/size/real_size_normalization/` are editable in S0-S2.

## Append-only surfaces

- `THREAD.md`
- `MECHANISM_REGISTRY.jsonl`
- `REJECTED_OPTIONS.md`

Corrections to these logs are new entries; earlier entries remain intact.

## Human-controlled surfaces

The following require a later explicit authorization and are not part of S0-S2:

- loading or stopping a P4 program;
- changing ports, forwarding, TM, PRE, mirrors, pktgen, routes, or interfaces;
- injecting traffic or starting packet capture on the live path;
- issuing DNP3 SELECT or OPERATE;
- changing relay state;
- installing packages on Vision or Tofino;
- pushing, merging, or deleting branches.

## Validation and stop condition

Each gate is reviewed and committed separately. This tranche stops after S2 with:

1. an explicit size-security definition and impossibility boundary;
2. an evidence-backed capability audit of the current testbed;
3. compared architectures, a conditionally selected design, a threat model, and a reader-first diagram;
4. unresolved prerequisites labeled as blockers rather than assumptions.

No implementation begins before design approval.

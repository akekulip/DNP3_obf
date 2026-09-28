# DNP3 timing evidence and implementation map

This directory contains the paper's timing evidence plus separate implementation and experiment
work. Keep their claims and source hashes distinct.

## Paper evidence

`evidence/campaign_v2/` is the dataset reported by `paper/rewrite/main.tex`: 22 grouped runs,
132 captures, and 63,360 DNP3 exchanges. Both arms disabled the size carve, so the comparison
measures timing. Start with `evidence/campaign_v2/README.md` and `FINDINGS.md`; use
`CLAIMS_AND_LIMITATIONS.md` for supported claims. `campaign_v1/` is the earlier anchoring record;
`final_read_sbo/` is retired. Neither should be substituted for campaign_v2.

Reproduce the paper dataset from this directory with:

```sh
./reproduce.sh
```

The active path verifies provenance before producing derived tables and figures. Historical data
requires the explicit `--historical` option. The notation authority is `NOTATION_MAPPING.md`.

## Separate engineering evidence

- `stage_reduction/` contains the seven-stage timing-only candidate and the bounded 2026-09-25
  master–SEL-751 smoke evidence. It does not establish complete packet-sequence equivalence,
  exactly-once delivery, or the paper's long-run results.
- `latency_search/` contains later delay-policy experiments and attacker evaluations. Each run's
  preregistration, completion status, manifests, and analysis define what its data supports.
- `anchor_fix/` documents the anchoring correction. `implementation/` preserves the exact older
  source used for historical captures and is not a working copy.
- `audit_current/` contains focused evidence and claim audits.

The seven-stage smoke-test source is tied to the commit and hash recorded in
`stage_reduction/hardware/20260925/README.md`. Its analyzer reads that source from Git history so
later comment cleanup does not rewrite the hardware record.

## Figures

Paper figures are generated from their documented source data and scripts. Consult `CLAUDE.md`
and `paper/rewrite/README.md` for the current figure-to-generator map. Do not hand-edit generated
plots or treat a later engineering figure as part of the paper without updating its provenance and
claim review.

## Hardware boundary

Before hardware work, read the current Tooling connectivity map and inspect the live process,
program, ports, and run status. Dated reports are evidence of past state, not live-state authority.
Use the guarded runner, capture the required observations, and follow the run-specific rollback
procedure.

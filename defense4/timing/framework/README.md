# Case 4 working implementation

The canonical capability matrix, evidence identities and remaining acceptance
checks are in [STATUS_MATRIX.md](../audit_current/framework_20261005/STATUS_MATRIX.md).
[HANDOVER.md](../audit_current/framework_20261005/HANDOVER.md) has the reproducible
commands and live-operation boundaries. These working files preserve the frozen
timing implementation, raw campaigns and manuscript.

Case 4 combines response-ready scheduling, supported control-command padding,
response carving and bounded TCP translation. The independent event model,
source-driven packet simulator, Python transport oracle, isolated BMv2 packet
artifact and production OpenDNP3 semantic gate establish different evidence
levels. Compiler coexistence of timing and size components does not establish
a complete joint target implementation. The controller refuses activation while
the complete ledger, target mappings or measured admission inputs are missing.

Run `bash defense4/timing/framework/run_tests.sh` from the repository root for
the five suites. BMv2 tests use private network namespaces when their tools are
available; skips must be counted. Retained verification records include actual
timing failures and corrected evidence regressions. The software queue emulator
is not the Tofino queue server, and its tolerances are not hardware acceptance
criteria. Cases 1–3 remain explanation-only engineering history.

The separate [working paper](paper/README.md), editable mechanism diagram under
`figures/`, and generators under `analysis/` link claims to the retained sources.
No new hardware campaign or physical OPERATE was run in this implementation.

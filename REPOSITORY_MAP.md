# Repository map

Use this map to distinguish paper evidence, later experiments, and implementation candidates.
A dated evidence bundle and its manifest are authoritative for what ran; current live switch state
must be checked on the hardware.

## Publication authority and frozen manuscript

| Path | Authority |
|---|---|
| `defense4/timing/evidence/campaign_v2/` | Approved publication dataset and reproducibility inputs. |
| `defense4/timing/CLAIMS_AND_LIMITATIONS.md` | Claim boundaries and evidence qualifications. |
| `defense4/timing/NOTATION_MAPPING.md` | Timing notation. |
| `paper/rewrite/main.tex` and `sections/` | The single active manuscript. |
| `paper/rewrite/figures/` | Current figures and their data, methods, limitations, and provenance. |

`campaign_v1/` is retained as the earlier acknowledgment-anchored record. `final_read_sbo/` and
other dated audits are historical. Do not combine their measurements with `campaign_v2`.

The manuscript and paper figures are frozen pending Dr. Lin's acceptance. Existing later-study
text is an open authority conflict, not evidence approval. See the
[September 29 verification ledger](defense4/timing/audit_current/verification_20260929/README.md).

## Separate engineering work

| Path | Purpose and boundary |
|---|---|
| `defense4/timing/stage_reduction/` | Seven-ingress-stage timing candidate, offline checks, and the bounded 2026-09-25 hardware smoke evidence. It is not the source of the paper's campaign results. |
| `defense4/timing/latency_search/` | Later matched-delay experiments and attacker analyses. Treat each run directory's protocol, manifests, and completion status as its authority; these results are not paper evidence by default. |
| `defense4/timing/anchor_fix/` | Corrected request-anchoring source and findings. |
| `defense4/timing/audit_current/` | Current claim, timing, retransmission, and measurement audits. |
| `defense4/timing/response_ready/` | READ response-ready P4 candidate, its offline tests, compiler-report evidence and build gate. Engineering candidate; no hardware results yet. |
| `defense4/timing/framework/` | Framework track (2026-10-06): policy contract, independent reference model, experiment-declaration validator, offline tests (`run_tests.sh`). Nothing here is paper evidence. `build/` is untracked output. |

## Frozen records and derived outputs

- `defense4/timing/implementation/` and raw capture directories preserve the exact historical sources and inputs. Do not edit them to match later candidates.
- `defense4/timing/figures/` contains analysis and historical figure families; `paper/rewrite/figures/` holds the paper-facing generated artifacts. Follow each figure family's documented generator.
- `paper/rewrite/corpus/` holds local reference material and style notes. Reference PDFs are excluded from Git.
- `paper/rewrite/archive/` holds superseded drafts and figures that remain useful for provenance.

## Reproduction

- Paper data: `defense4/timing/reproduce.sh` dispatches to the active `campaign_v2` reproduction path.
- Paper build: `paper/rewrite/pipeline/build.sh`, followed by the manuscript publisher when a new PDF is intended.
- Seven-stage candidate: follow `defense4/timing/stage_reduction/README.md`; offline compilation and tests do not establish live hardware behavior.

For Tofino work, read the current Tooling connectivity map, inspect the live daemon/configuration, and follow the active run's guarded setup and rollback procedure. A loaded pipeline is not identified by a repository manifest alone.

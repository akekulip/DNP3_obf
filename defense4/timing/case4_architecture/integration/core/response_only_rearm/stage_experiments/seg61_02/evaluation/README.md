# Gambit hardware campaign

This campaign measures READ/SELECT/OPERATE fingerprints on the supported OpenDNP3 endpoints through physical Tofino-1. It uses the exact m11_09 image. Compiler and model qualification are prerequisites; they are separately typed and do not supply the main observations. Supervision and analysis fixtures never count as hardware results. The implementation contract is [HARDWARE_EVALUATION_PLAN.md](HARDWARE_EVALUATION_PLAN.md).

The fixed hardware cohort has 154 blocks: five recovery, one reference, four pilot, sixteen feasibility, and 128 main. Main collection has eight training rounds across all eight conditions before eight testing rounds. It contains 98,816 attempted exchanges. Every block remains in the status report after failure or expiry; partial coverage is INCOMPLETE.

## Preparation and launch

Run these from the repository on Gambit, using fresh campaign and evidence identities. The preparation command writes configurations and the complete immutable order; it does not touch hardware.

```bash
python3 defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/seg61_02/hw/evaluation_prepare.py prepare /absolute/persistent/campaign_root --campaign-id CAMPAIGN_ID
```

Before launch, require the current normal model gate, focused/legacy/clean-checkout tests, harmless real-systemd supervision checks, fresh non-agent SSH preflight, and initial normal freeze:

```bash
python3 defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/seg61_02/hw/evaluation_prepare.py freeze-initial /absolute/persistent/campaign_root
python3 defense4/timing/case4_architecture/integration/evidence/rearm_01/hw/evaluation_campaign.py init /absolute/persistent/campaign_root/controller_manifest.json
python3 defense4/timing/case4_architecture/integration/evidence/rearm_01/hw/evaluation_campaign.py start /absolute/persistent/campaign_root/CAMPAIGN_ID
```

Hardware changes remain behind run_block_frozen.sh, with a cold bring-up per arm, the existing source bindings/headroom checks, and independent restoration verification after every block. No physical relay OPERATE is part of this campaign.

The detached controller and detached block services live on Gambit. Closing a laptop SSH session, monitor, or Codex session does not own their lifetime. Gambit's user manager must have Linger=yes; start refuses otherwise. Credentials must work without a forwarded agent or SSH multiplex connection. All commands, paths, configurations, captures, counters, state and logs must reside on Gambit's persistent local storage.

## Deadline and failure behavior

The controller persists start and deadline immediately before its first hardware block dispatch. The deadline is start plus 86,400 seconds and never resets on resume. Scheduling and actual command entry both check it. No campaign-level runtime kill interrupts an admitted block: the active block finishes and independently verifies restoration.

An unverified restoration stops the campaign and leaves a persistent testbed refusal under ~/.local/state/dnp3-evaluation/tofino1-testbed. Lost ownership also refuses new entry. Different campaign IDs and checkouts share that guard. Failed blocks are never replaced, rerun, reordered or used to shrink the cohort. Ambiguous service state refuses replay. Offline analysis may finish after hardware collection stops.

These are read-only status and explicit control commands:

```bash
python3 defense4/timing/case4_architecture/integration/evidence/rearm_01/hw/evaluation_campaign.py status /absolute/persistent/campaign_root/CAMPAIGN_ID
python3 defense4/timing/case4_architecture/integration/evidence/rearm_01/hw/evaluation_campaign.py resume /absolute/persistent/campaign_root/CAMPAIGN_ID
python3 defense4/timing/case4_architecture/integration/evidence/rearm_01/hw/evaluation_campaign.py stop-after-current /absolute/persistent/campaign_root/CAMPAIGN_ID
```

Status never starts another service. Resume is only for controller loss with a live independent step or verified terminal record; it cannot reopen a failed/expired campaign. campaign_report.json explicitly lists completed, failed and unexecuted blocks. Per-block artifact_manifest.json hashes the retained evidence, including failures and partial logs.

## Pilot and collection gates

The four pilots use provisional da/pb/readiness/cap=30/55/70/80ms at D10/J2.4. One envelope is derived from the maximum native response-availability proxy over all pilot classes/blocks, with the declared J/D maxima, 1ms grid and 5ms experimental guards. Both endpoints' observed TCP RTO and the 500ms endpoint constraints must leave headroom. The guards are not proven worst-case bounds; cap is not a demonstrated hard deadline.

Envelope creation precedes pilot native-baseline competence scoring. Every condition then requires both feasibility workloads to pass actual timing, J, counter/fallback, capture and completion checks. All sixteen feasibility blocks must qualify before any main block. The envelope never changes per condition or after attacker results. The controller runs these deterministic hooks without Codex intervention.

After round8, the training hook locks RF/NB models, training membership and bin edges before test9. Test data never fits edges/models. K8/32/64 windows remain within connection/session/split, preserve order and do not overlap; operation grouping is oracle-assisted. Primary inference is fixed joint-feature native-minus-combined balanced accuracy at D10/J2.4, with 10,000 paired test-block bootstrap resamples, seed20260828. Secondary intervals are pointwise; no near-chance guarantee is claimed.

## Offline reproduction

A complete release contains observed rows, raw main and preliminary captures/counters, attempted-exchange ledgers, split/window membership, predictions, settings/seeds, model lock, normal freezes, controller records, hashes, scripts and environment pins. Missing metrics remain explicit. Original timestamp precision does not assert capture-clock accuracy. Plaintext, identities, configurations and collection indices are audit/label fields and excluded from attacker feature whitelists.

With the release's requirements-analysis.txt installed in a compatible Python environment, one command regenerates tables and all six figure families without a switch or commercial SDK:

```bash
python3 RELEASE_DIR/scripts/reproduce_evaluation.py RELEASE_DIR --output OUTPUT_DIR
```

Main replay rejects incomplete cohorts, nonhardware observations, changed artifacts, changed training membership, unsupported cost values, and missing source/restoration/ledger linkage. Validation prerequisites are separate from statistical inputs. Exact underlying CSVs accompany the figures; legacy descriptive estimation remains separately labelled and uses the unchanged pinned estimator.

This is a private experiment archive. No new redistribution rights are granted for repository code, experiment data, third-party endpoint code, or SDK materials. Code and data licensing require their respective owners' terms; commercial SDK binaries/manuals are not included by the release packager.

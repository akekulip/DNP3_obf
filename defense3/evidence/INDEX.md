# Defense 3 evidence — index

What each evidence directory holds, and which claim it backs. Empty aborted-run stubs were
pruned; every directory below has real content. Section numbers refer to
[`../REPORT.md`](../REPORT.md); the development history behind the safety paths is in
[`../REPAIR_HISTORY.md`](../REPAIR_HISTORY.md).

| directory | what it establishes |
|---|---|
| `final_silicon/` | **the canonical `case_a_defense3` build on Tofino-1 9.13.2**: compile (10/11 stages, 0 warnings), assembly `--require-r2` PASS, `setup --config` 43/43, Gate 2 PASS. The release-hardening validation. |
| `gate2/` | Gate 2 synthetic-transaction runs (§10.2): one READ → K=64 burst → ACK-then-RESPONSE → clean retire. Latest `gate2_*` = the canonical build, 1 PASS / 0 FAIL. |
| `ksweep_hold/` | **the hold-continuity sweep (§7.5)**: 96 in-chip transactions, K = 1…64 against D = 2/8/16 ms, 3 reps per point, per-block pcaps. Establishes the measured floor **K = 44 at every D**. Analyzer `analysis/analyze_ksweep_hold.py`. |
| `failopen/` | the fail-open budget/horizon behaviour, including the before/after termination accounting (1 TMO / 63 stale → 64 / 0) and the K-sweep inputs. |
| `ksweep/` | the fail-open K-sweep that reconciles the single-token and aggregate results: a native budget-zero token clears `reg_tag` at K = 1, giving the 1 / K−1 cascade. |
| `repaired/` | the canonical build's compile + silicon rerun, including the stale-response isolation case scored from a master-side capture (§10.8). |
| `inject/` | the adversarial in-switch injector matrix for the safety paths, incl. the `BLOCK_ENQ`→`BLOCK_REJECT` counter re-verification. |
| `physical/` | the **first** physical SEL-751 campaign — the 480-transaction D-sweep and its analyses. |
| `physical_repaired/` | the **second and third** live campaigns against the same relay, 960 transactions each (§11.5). |
| `defense3/` | CHECK 2 production-blocker-start-latency measurements and per-gate supporting evidence. |
| `negative_results/` | runs kept **because they failed**, with the reason recorded — notably reduced-K Gate 2 configurations refused by the K = 64 safety pin before any transaction ran. Not to be read as measurements. |

Campaign totals (all valid, different questions): first session 480 transactions / 400
defended; second and third 960 / 800 each; cumulative 2 400 / 2 000. See REPORT.md §11–§12.

The final artifacts (assembly + resource logs, semantic names) are under `../artifacts/final/`;
earlier build artifacts under `../artifacts/resources/`, `../artifacts/assembly/` and
`../artifacts/resources_repair/`. The binding of claims to artifacts and analyzers is
[`../MANIFEST.yaml`](../MANIFEST.yaml).

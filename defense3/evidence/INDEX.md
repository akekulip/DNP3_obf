# Defense 3 evidence — index (CORRECTIONS.md §9)

What each evidence directory holds, and which claim it backs. Empty aborted-run stubs were
pruned (CORRECTIONS.md §8); every directory below has real content.

| directory | what it establishes |
|---|---|
| `final_silicon/` | **the canonical `case_a_defense3` build on Tofino-1 9.13.2**: compile (10/11 stages, 0 warnings), assembly `--require-r2` PASS, `setup --config` 43/43, Gate 2 PASS. The release-hardening validation. |
| `gate2/` | §13 Gate 2 synthetic-transaction runs (one READ → K=64 burst → ACK-then-RESPONSE → clean retire). Latest `gate2_*` = the canonical build, 1 PASS / 0 FAIL. |
| `repaired/` | the R1+R2+R3 repaired-build compile + silicon rerun (§7.7). |
| `failopen/` | the fail-open budget/horizon behaviour, including the R2 before/after (1 TMO/63 STALE → 64/0) and the K-sweep inputs. |
| `ksweep/` | the fail-open K-sweep reconciling the single-token/aggregate result (a native budget-zero token clears `reg_tag` at K=1). |
| `inject/` | the adversarial in-switch injector matrix (R1/R2/R3), incl. the `BLOCK_ENQ`→`BLOCK_REJECT` counter-fix re-verification. |
| `physical/` | the **original** physical SEL-751 campaign — the 480-transaction D-sweep (unrepaired build) and its analyses. |
| `physical_repaired/` | the two **repaired** live campaigns (R1+R3 and R1+R2+R3), 960 transactions each. |
| `defense3/` | CHECK 2 production-blocker-start-latency measurements and per-gate supporting evidence. |

Campaign totals (both valid, different questions): original 480/400 defended; repaired
960/800 ×2; cumulative 2 400/2 000; repaired-only 1 920/1 600. See REPORT.md §10–§11.

The final artifacts (assembly + resource logs, semantic names) are under `../artifacts/final/`;
the pre-repair originals under `../artifacts/resources/` and `../artifacts/assembly/`; the
repaired intermediates under `../artifacts/resources_repair/`. The binding of claims to
artifacts/analyzers is `../MANIFEST.yaml`.

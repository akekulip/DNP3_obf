# c68 repair execution — 2026-10-26

Baseline: 789092c2d. Current user instruction: “do it”, following the accepted correction plan.

- [ ] Restore software J and piggyback fixture identity; keep CLRT/extra piggyback latency ungated.
- [ ] Repair event-clear fragmentation and final-response matching.
- [ ] Integrate c68 archives/artifacts and pin c67 reproduction.
- [ ] Verify offline, review changes, then freeze the exact recovery configs.
- [ ] Run D20 mixed/full recovery with new IDs and independent restoration.
- [ ] Record actual results and provenance; preserve historical evidence and unrelated deletions.

Ownership: root=reproduction/schema/hardware/docs; repair_shared_checks=checks/standards; repair_retention=restore/manifests; repair_event_clear=event helper/tests.

Ruling: preserve c68 dataplane and model helper hashes; no P4 rebuild or model rerun unless an executed dependency changes.

Verification: active_harness/event_clear 22 tests; active_harness full126; retention helper25 tests and348 logs validated; analysis/reproduction62 tests; c68 v3 gate stillpasses. Focusedmodel_summary standalone needs SDK helper PYTHONPATH; verifying with existingmodulepaths.

Read-only hardware preflight: Vision .19 identity/MAC verified; switch .81 production case4_response_path confirmed; two native READs (mixed91/integrity134) OK, IIN 0x0080 (wire8000), no event clear or SBO performed.

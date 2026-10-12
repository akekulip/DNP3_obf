# Paused for lab resumption

The user requested a checkpoint commit and pause. All implementation agents and compile sessions have stopped. No candidate pipeline was loaded. The switch remains on `case4_response_path`, PID273372, rechecked read-only before pausing; the last hardware run's restoration is retained in `baseline_restored_after_native_rst03.txt`.

The original same-tuple failure was captured first and independently verified. Independent frozen-baseline timing, four-arm and native reference experiments are complete; strict failures remain preserved. `baseline_independent_results_02.json` indexes their records and hashes. Exact native49 FIN and genuine kernel-RST replay archives are available for the next lab tests.

Latest immutable candidate: `integration/core/response_only_rearm/evidence/incremental_47/response_only.p4`, SHA256 `a741682a0759227cc600b8dbbef1adc1d788f1b163803931969359f694d559e5`. Current generators match checkpoint47. Local SDK9.13.1 compile failed: N12 / E13 / T12 stages, no binary. Installed SDK9.13.2 checkpoint46 independently failed with the same N12 / E13 / T12 placement; its manifest, compiler log and resource_stage_summary.json are retained. The remaining blocker is E's lifecycle/CRC preparation dependency, which delays the reverse window/checksum stage to index12. N's independent bad_links suggestion was investigated but not implemented; N already fits.

Source/interpreter tests36 and installer tests3 passed; independent semantic review approved. Fresh checks passed401 campaign tests,109 hardware-helper tests and36 source tests. Independent isolation review approved. These are source/tooling evidence. Full compile, mirror/resource qualification, compiled-model execution and candidate silicon rearm remain unproven.

Resume in this order:

1. Read PLAN.md/CHECKPOINT.md here and the candidate README. Shorten E by one stage while preserving read-only normalization, full wireACK/epoch qualification, FIRST latch and authoritative bank ordering. Freeze a new checkpoint; never modify numbered evidence.
2. Obtain a full installedSDK9.13.2 compile, both mirror guards and at-most12stages per direction. Run the private compiled-model driver before any candidate activation.
3. Bind copied campaign configs to actual successful artifact hashes. Use one physical hardware owner and the ordinary guarded baseline rollback. Qualify three successive same-tuple graceful and RST connections, fresh mapping/padding, 800/950us READ precision and software SBO integrity without reset/reseed.
4. Run separately the real delayed app0-token diagnostic (`candidate_isolation.py`) and exact native old-frame replay diagnostic (`candidate_external.py`). The barrier endpoint is separately pinned/deployed but unused on hardware. Both diagnostics require full bank isolation and successful current connection traffic afterward.
5. Complete candidate four-arm smoke and seven deterministic single-loss classes, restoring baseline after every block. Update evidence before claiming completion.

Preserve frozen sources/artifacts, paper and historical untracked files. The preexisting diagnostic/ranged-READ edits in make_diag_t.py/dnp3_read_client.py are included unchanged as relevant checkpoint dependencies; their original diff is retained in preexisting_edits.patch. No push was requested. Regenerable compiler output trees remain local under the existing ignore rules; manifests, frozen sources and compiler logs provide the committed checkpoint.

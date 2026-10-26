# c68 repair execution — 2026-10-26

Current direct instruction: “do it”, following the reviewed plan and three explicit choices. Main code commits: f12458308 (repairs/artifact retention), a4aa1f330 (missing-freeze refusal).

- [x] Restore software J and piggyback fixture identity; preserve original recovery/runner exemptions. CLRT/extra piggyback latency remain ungated.
- [x] Fix event-clear fragmentation, sequence matching and final-response completion; no event-clear operation performed in this task.
- [x] Integrate 83 c68 archives and 30 existing compiler artifacts/reports; keep old bytes, closures and freezes unchanged.
- [x] Fresh-checkout c68 and pinned c67 reproduction pass. Source 825b7e6d… unchanged; model 17/17 passes; current freeze04 seven configs + historical freeze03 four checks + c67 ten historical checks all pass.
- [x] New05 mixed-loss D20: seven trials PASS, including t3 exact SELECT-response drop; independent restoration PASS.
- [x] New06 full-loss D20 completed all seven trials: six PASS, t3 OPERATE TIMEOUT on points 1 and 3. Block rc1; independent restoration PASS.
- [x] Independent replay/raw-application/manifest/restoration audits completed for both blocks. Records updated; all requested execution/verification complete. Final evidence commit records this state.

Last campaign: read_complete_01/evidence/hw_campaigns/rc01_hw_c68_20261026_06 (step rc01_hw_c68_20261026_06_loss_full_950). The campaign is stopped after its recorded application failure; final ownership is inactive, unsafe_restoration=false. Any unverified restoration stops hardware.

New05 SELECT-drop t3: exactly one packet dropped, SELECT OK after 1021.67 ms, OPERATE OK. This observation does not prove a cause or establish that the older c67 failure is fixed.

Clean verification retained under this folder; full runs at f12458308, isolated failure-only guard tests at a4aa1f330. Main local inventory: 348 logs; clean published inventory: 328 logs, including all 83 c68; pinned historical c67 inventory: 245. Two obsolete-v1 test failures remain baseline debt; no new unsupported timing criteria added.

Full loss t3: SELECT OK after 1015.238 ms, then OPERATE TIMEOUT on both guarded points. All targets were exact single drops; all 154 reports/raw responses reproduced, including the genuine failure. No causal window or switch-hold conclusion is established.

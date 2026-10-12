Candidate 56 diagnostic attribution passed 45 actual-source tests and 519 compiled-model checks. The local SDK 9.13.1 full assembler build passed in 86.174 seconds at N11/E12/T11 stages; the physical mirror BFA guard passed.

The generator reads immutable combined source `cad16b85f79d0609ad07e547a9551def720fdfa668c14000b7503a570cae7357`. N, E, and surrounding source remain byte-identical. Seven exactly reversible T edits enlarge the existing outcomes register from 16 cells/index width 4 to 25 cells/index width 5 and select raw OP rejects at 23 and raw READ rejects at 24. Stale blockers retain index 6. Other original indices 0–15 retain their meaning, including old epoch 14 and generation exhaustion 15; 16–22 remain unused. The compiled allocation still contains 37 stateful banks and one outcomes SALU instance at T stage 10.

The actual-source parity oracle compares emitted and enqueued bytes/times, every non-outcome authority bank, and original counters after each input. Original counter 6 equals new counters 6+23+24. It covers four old tokens from each app before and after OPEN, live and sealed sentinel tokens, all six old OFF held roles, and exact current OFF originals.

The copied private model retains all 507 prior check names in their original order, including 289 ACK/window observations and eight explicit CRC/link negatives. Twelve added assertions prove independent attribution: sealed raw batches increment 23 and 24 by four each; reopened batches increment them by another four each; exhausted/sentinel batches increment each by two; three stale blockers increment only 6. Final raw counts are 6=3, 23=10, 24=10. All raw-token drops preserve the selected 34 N/E/T authority banks and produce no wire output.

The model ran through the supported private namespace launcher with `MODEL_INT_PORT_LOOP` and `MODEL_EXTRA` unset, ports 9/48/68/180/181/182/196, and the candidate's exact input map. Driver/namespace exit code was 0, and 196 hugepages were free after cleanup. The model's configured binary/context/schema paths and artifact hashes are recorded in `model_qualification.json`.

Pins:

- Source: `13b21e3c34072b9a113acaf5bda5a1210d9a70cbe787d30fb722ad3c3dcbf5bd`.
- Inputs: `5cfdd8af36a983d20d68951c88c93ad8976fa067aa998d5c76e475f12800afe7`.
- p0 binary: `9159894b0b4ec6b5baaaf5a006ac11e127cb469dc1fa88b62616fc29572fde0e`.
- p1 binary: `9c96c1d590e7d836fff19bfaccf48654f6da58da810df6589fc5fc89c8fef54a`.
- BFRT schema: `4c1bfc92eb746d5df80cb6464e777c3b244fb7f792b17c76eb31bb461e1170da`.
- Full compile qualification: `4095352c65a9ae79dbd72cada1f2dabaea8f214a79cca6c2bccffe8a2200e1d1`.
- Driver: `b8296fc2321e1e75c3dac378da7c8b109910d5e09b037636308d84bec68edcb3`.
- Model results: `d215f8705d38a1502d9bb44ba5e2c2394e5418281b678544c39528f99c7ae8e9`.
- Model qualification: `808e17c2ed02445aa07968fa8350b94c0a52184a741a04786a4cc063f0a9be4f`.
- Counter attribution: `c49b69650b0f40557f4fea0c3f2b92b0b53e9d95c3323a7e02b34484189989bd`.

This is offline qualification. Installed SDK 9.13.2 compilation and hardware qualification are separate, root-owned work. Selected-bank equality covers cell 0, not all E slots. Compiled tests cover sealed old raw tokens and live sentinel tokens separately; the combined sealed/sentinel case is covered by actual-source tests. Hardware attribution must pair raw indices 23/24 with both apps' packet deltas; quiet raw OP is not assumed zero because scheduling can delay that batch. Host precision and physical scheduling are outside this model claim.

Canonical candidate55, CP, and hardware files remain untouched. A candidate56 counter reader must use the explicit 25-cell layout, retain the virtual stale aggregate 6+23+24, and avoid legacy diagnostic indices 19–24/`diag.present` auto-selection.

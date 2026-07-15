> **STATUS: IMPLEMENTED 2026-07-06.** All required changes (1–8) and acceptance
> criteria are done and rig-validated. Result: **Nmax=16** for the default config
> (OpenDNP3 `maxControlsPerRequest`). See `reports/sweep_results.md`,
> `reports/sweep_manifest.csv`, `reports/sweep/analyze_n<N>.json`, and
> `captures/sweep/multicrob_n<N>.pcapng`.

Review and simplify the multi-CROB SBO harness. Preserve the existing N=1 and N=2 PCAPs as historical evidence, but do not modify the replay, CRC-splitting, Class 0 READ, or P4-related code.

Goal: convert the current fixed two-CROB validation into a reproducible highest-N experiment for one controlled OpenDNP3 master/outstation configuration.

Current validated result:

* N=2 works.
* One G12V1 object header uses qualifier 0x28 and Count=2.
* SELECT and OPERATE each contain the same two indexed CROBs.
* Both responses return success status.
* Current PCAP files are PCAPNG despite their .pcap extension.

Required changes:

1. Replace fixed simulated control indexes `(0, 1)` with a configurable count.

   * Add `--control-point-count N` to the outstation.
   * Supported indexes must be `0..N-1`.
   * Initial simulated state must alternate:
     even index = False
     odd index = True.
   * Reject N less than 1.

2. Replace static Test A/B/C as the primary control path.

   * Keep them only as regression aliases if easy.
   * Add `--crob-count N` to the master.
   * Generate one command set:
     even index -> LATCH_ON
     odd index -> LATCH_OFF.
   * Expected final state:
     every even index = True
     every odd index = False.
   * Reject duplicate indexes in generated or user-supplied plans.

3. Fix stale SELECT handling.

   * Add a monotonic selection timeout, default 5 seconds.
   * A matching OPERATE after expiry must return NO_SELECT.
   * A partially failed SELECT batch must not leave valid controls armed indefinitely.
   * Instrument ICommandHandler Start/End first and confirm through logs whether they bracket one control request batch.
   * Use Start/End to discard a pending SELECT batch when any object in that SELECT batch fails.

4. Add structured evidence.

   * Add `--run-id`.
   * Outstation writes one JSON result file after the OPERATE batch:
     requested_n, select_seen, select_success, operate_seen, operate_success,
     rejected_indexes, pending_selection_count, final_state_matches_expected,
     and final_state.
   * Master writes a JSON summary with requested_n, task completion, timeout flag,
     and a precise timestamp immediately before SelectAndOperate.
   * Do not label task-level SUCCESS as proof that every output changed.

5. Correct exit behavior.

   * A master timeout or non-success task completion must return non-zero.
   * Do not report the current approximately two-second startup delay as SBO latency.
   * Keep the pybind11 workaround isolated and explicitly labelled temporary.
   * Use the existing hard-exit helper so logs are flushed; do not call os._exit(0)
     directly without flushing.
   * Do not attempt to turn the blocked DNP3-thread workaround into a persistent
     production architecture.

6. Add `analyze_multicrob_pcap.py`.

   * Input: PCAPNG file and expected N.
   * Reassemble TCP payloads into DNP3 link frames.
   * Validate DNP3 header CRC and every data-block CRC.
   * Reassemble DNP3 transport fragments into logical application fragments.
   * Find G12V1 SELECT, SELECT response, OPERATE, and OPERATE response.
   * Verify:
     Group=12, Variation=1, qualifier=0x28, Count=N,
     N distinct CROB indexes,
     identical SELECT and OPERATE CROB lists,
     N success statuses in both responses.
   * Emit one JSON pass/fail report including logical fragment count and data-link
     frame count per SELECT and OPERATE.
   * Do not use TCP packet count as a correctness metric.

7. Add a highest-N procedure.

   * Fresh outstation process for every N.
   * Save PCAPs as .pcapng.
   * Mandatory sweep points: 1, 2, 4, 8, 16, 18, 19, 32, 64, 128.
   * Continue exponentially until first failure, then binary-search the boundary.
   * Re-run the final passing N three times.
   * Produce reports/sweep_manifest.csv.

8. Keep scope narrow.

   * No physical outputs.
   * No DirectOperate.
   * No fake control objects.
   * No padding, chaff, replay-server changes, P4, or obfuscation claims.
   * Do not claim a universal DNP3 maximum. Report Nmax only for the exact
     OpenDNP3 version, host configuration, point count, and fragment settings tested.

Acceptance criteria:

* N=1, N=2, till N=19 all have separate PCAPNG files and JSON reports.
* N=19 is correctly recognized as one logical SBO transaction even if it spans
  multiple DNP3 data-link frames.
* The final reported Nmax has a passing PCAP report, passing outstation JSON report,
  and three successful repeat runs.
* The first failing N also has a PCAPNG and report explaining whether the failure is
  caused by command count, fragment size, timeout, parser rejection, or another
  explicit observable condition.

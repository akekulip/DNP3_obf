# READ response-ready candidate

Status: implementation in progress; not compiled or deployed.

## Approved contract

- READ first; DA = 5, 10, 15, 20 ms from request arrival (anchor_req=1).
- Fixed 1 ms configured CLRT, quantized on the existing 256 ns clock grid.
- Normal ACK-blocker expiry requires deadline elapsed and matching response pending.
- Response deadline stays disarmed until the first qualified held-ACK loopback return.
- Retain existing finite per-token watchdog; report timeout escapes separately.
- Preserve seven ingress / zero egress target, existing queue ladder, and U_BOR build.
- No BMv2, sizing, classifier experiments, paper edits, or changes to measured inputs.
- All commits belong to Philip; no push.

## Execution plan

1. Checkpoint and preserve baseline hashes; create separate candidate.
2. Add source-bound sequence regressions and implement ACK gating and one-shot response anchoring.
3. Verify pending-state timeout recovery, stale returns, and busy-request matching ownership.
4. Add candidate-specific enable/gap BFRT control with strict readback; random overrides disabled.
5. Compile offline SDE 9.13.1, then SDE 9.13.2; check final allocation against context.
6. Only after all offline/recovery/stage gates pass, snapshot live state and test on Tofino.
7. Run controlled early/late/fault traces, then 100 READ smoke trials per DA.
8. If smoke passes, collect 6000 candidate READs per DA, 1000 current-mechanism READs
   per DA, and 1000 Timing OFF READs, using 400 ms spacing / 500 ms app budget.
9. Restore pre-test program and configuration, retain exact evidence, write engineering report.

## Acceptance

- Median absolute configured-gap error <= 10 us; >=99.9% normal completions within +/-50 us.
- Apply thresholds separately to verified early/late arrivals; report insufficient coverage.
- No unexplained loss, corruption, stale completion, or stuck next transaction.
- No exclusion of timeout/failure records from accounting; they are not CLRT successes.
- A seven-stage compile alone does not authorize deployment while recovery tests fail.

## Progress

- Checkpoint and source hash recorded in baseline.json.
- Existing feature branch retained; all candidate changes isolated in this directory.
- The user's approval covers the bounded hardware phase after the prerequisite gates.

## Offline checks

Run the candidate tests without contacting hardware:

```bash
python3 -m unittest discover -s defense4/timing/response_ready/tests -v
python3 defense4/timing/response_ready/control.py --da-ms 5
```

`verify_build.py SOURCE BUILD_DIRECTORY` checks source identity, retained compiler
artifacts, final allocation, and the seven-stage limit. It rejects a successful
older build if the source has since changed. Passing it does not authorize
deployment or establish packet behavior.

`analyze.py` accepts an exchange CSV and an expected-ID JSON array. Missing
transactions, missing measurements and ordering failures remain visible. Full
acceptance cannot be weakened below 6000 normal exchanges per DA and 200 per
verified arrival group. Smoke acceptance is separate. Latency statistics describe
observed request-to-ACK and request-to-response intervals; they are not estimates
of added delay without a corresponding reference measurement.

See [HARDWARE_TEST.md](HARDWARE_TEST.md) for the deployment, observation and
restoration prerequisites. No hardware results exist for this candidate yet.

We are working in the current DNP3 multi-CROB Select-Before-Operate harness.

Goal:
Extend the existing boundary-index CROB experiment to test invalid-index placement, multiple invalid CROBs, decoy-only invalid CROBs, and the interaction between invalid indexes and the OpenDNP3 operation-count limit.

This is still a software-only OpenDNP3 experiment. Stay with Group 12 Variation 1 CROBs only.

Do NOT:
- modify replay/split server code
- modify Class 0 READ code
- modify P4 code
- implement padding
- rewrite DNP3 responses
- raise maxControlsPerRequest
- add mixed groups or variations
- add analog output commands
- use physical-device assumptions
- treat TCP packet count as a correctness metric
- claim this proves padding works

Main scientific question:
Can nonexistent G12V1 CROB indexes act as harmless padding candidates, and what response evidence do they produce?

We already know:
- K=5, N=5 all valid works.
- K=5, N=6 with invalid index 5 at the end returns OUT_OF_RANGE for index 5.
- Because SELECT is not fully successful, the master does not send OPERATE.
- N=17 with all configured indexes previously returned TOO_MANY_OPS.

Now implement and run a broader boundary-index test suite.

Required new capability:
Add support for a custom CROB plan in run_master.py.

Current --crob-count N only generates indexes 0..N-1.
Add a new option:

  --crob-plan "5:LATCH_ON,0:LATCH_ON,1:LATCH_OFF,..."

Rules:
- --crob-plan applies only with --action multi-crob-sbo.
- If --crob-plan is provided, it overrides --crob-count and --crob-test.
- Each entry is index:CONTROL_CODE.
- Supported control codes for now: LATCH_ON, LATCH_OFF.
- Reject duplicate indexes.
- Reject malformed entries.
- Keep the existing --crob-count path unchanged.
- The plan should still create ONE CommandSet and issue ONE SelectAndOperate task.
- The master JSON should record the exact crob_plan in transmitted order.

Required analyzer improvement:
Update analyze_multicrob_pcap.py so it can analyze invalid-index cases cleanly.

Add or confirm these options:

  --mode all-success|boundary-index
  --configured-points K
  --expect-operate absent|present|either

For boundary-index mode:
- SELECT must be found.
- SELECT must be Group 12 Variation 1.
- qualifier must be 0x28.
- Count must equal expected_n.
- SELECT response must be found.
- Report statuses per index.
- Report status names.
- Report first rejected index.
- Report first rejected status.
- Report whether OPERATE was sent.
- Report whether an OPERATE response was seen.
- Do not fail just because OPERATE is absent if --expect-operate is absent or either.
- Classify the behavior.

Status name mapping:
- 0 = SUCCESS
- 2 = NO_SELECT
- 4 = NOT_SUPPORTED
- 8 = TOO_MANY_OPS
- 12 = OUT_OF_RANGE
Unknown nonzero statuses should be reported as UNKNOWN_0xNN.

Classification values:
- all_success
- invalid_index_rejected_during_select_no_operate
- invalid_index_rejected_during_select_operate_still_sent
- too_many_ops_during_select
- multiple_invalid_indexes_rejected
- decoy_only_invalid_rejected
- parser_or_crc_failure
- unexpected_behavior

Do not invent results. Classify only from the PCAP.

Add a new runner script:

  run_crob_padding_candidate_tests.py

Purpose:
Run a fixed set of CROB invalid-index tests on the rig and produce PCAPNG + JSON + manifest evidence.

Use the same SSH/deploy/pull/dumpcap pattern from run_multicrob_sweep.py.

Default lab roles:
- Master host from lab_config.MASTER_IP
- Outstation host from lab_config.OUTSTATION_IP
- TCP port 20000
- default SSH user from RIG_USER or decps
- default interface eno1
- remote dir same as run_multicrob_sweep.py

CLI options:
- --user
- --iface
- --remote-dir
- --no-deploy
- --only CASE_NAME, optional
- --valid-points, default 5

Before each case:
- stop old outstation
- stop dumpcap
- delete stale local and remote artifacts
- start fresh dumpcap on outstation host
- start fresh outstation with --control-test --control-point-count K --run-id CASE
- run master with --action multi-crob-sbo and either --crob-count or --crob-plan
- stop dumpcap
- pull PCAPNG, master JSON, outstation JSON, and logs if available
- run analyze_multicrob_pcap.py
- write one row to manifest

Output directories:
- captures/padding_candidates/
- reports/padding_candidates/
- logs/outstation/
- logs/master/

Required cases:

Case 1: valid_k5_n5
- K = 5
- Master plan: indexes 0,1,2,3,4
- Use --crob-count 5 or explicit plan.
- Analyzer mode: all-success
- Expected: OPERATE present, all success.

Case 2: invalid_end_k5_n6
- K = 5
- Plan: 0,1,2,3,4,5
- index 5 invalid at end.
- Analyzer mode: boundary-index
- expect-operate: absent or either
- Expected observation: first rejected index likely 5, status likely OUT_OF_RANGE, OPERATE likely absent.

Case 3: invalid_begin_k5_n6
- K = 5
- Plan: 5,0,1,2,3,4
- invalid index first.
- Analyzer mode: boundary-index
- Goal: determine whether OpenDNP3 reports status for all objects or stops early.

Case 4: invalid_middle_k5_n6
- K = 5
- Plan: 0,1,5,2,3,4
- invalid index in middle.
- Analyzer mode: boundary-index
- Goal: determine whether invalid position changes the response pattern.

Case 5: multiple_invalid_k5_n8
- K = 5
- Plan: 0,1,2,3,4,5,6,7
- invalid indexes 5,6,7.
- Analyzer mode: boundary-index
- Goal: determine whether multiple invalid padding CROBs produce multiple visible rejection statuses.

Case 6: decoy_only_invalid_k5_n3
- K = 5
- Plan: 5,6,7
- all requested CROBs invalid.
- Analyzer mode: boundary-index
- Goal: determine whether a harmless decoy control-looking transaction is possible and what response it produces.

Case 7: count_limit_vs_invalid_k5_n17
- K = 5
- Plan: indexes 0..16
- valid indexes 0..4, invalid 5..16
- Analyzer mode: boundary-index
- Goal: determine whether OpenDNP3 reports OUT_OF_RANGE for invalid indexes or TOO_MANY_OPS because the command count reaches 17.

Case 8: count_limit_valid_k16_n17
- K = 16
- Plan: indexes 0..16
- valid indexes 0..15, invalid index 16.
- Analyzer mode: boundary-index
- Goal: compare against the previous N=17 behavior and determine whether the rejection is still TOO_MANY_OPS or invalid-index related.

For each case, collect:
- PCAPNG path
- analyzer JSON path
- master JSON path
- outstation JSON path
- configured_points K
- sent CROB count N
- transmitted index order
- SELECT count
- SELECT statuses by index
- first rejected index
- first rejected status name
- OPERATE sent true/false
- OPERATE response seen true/false
- outstation select_seen
- outstation select_success
- outstation operate_seen
- outstation operate_success
- outstation rejected_indexes
- final_state_matches_expected
- SELECT request byte length if available
- SELECT response byte length if available
- number of DNP3 data-link frames for SELECT and SELECT response
- classification
- notes

Write:
- reports/padding_candidates/padding_candidate_manifest.csv
- reports/padding_candidates/padding_candidate_results.md
- reports/padding_candidates/analyze_<case>.json
- captures/padding_candidates/<case>.pcapng

The markdown results file should include:
1. Purpose
2. Method
3. Case table
4. Interpretation
5. What this means for padding
6. What it does NOT prove

Important interpretation language:
Use this wording if supported by the results:

“Invalid-index CROBs do not execute physical or simulated configured outputs, but they are visible in the SELECT response through non-success command statuses. In the current OpenDNP3 SBO behavior, a partial SELECT failure prevents OPERATE, so invalid-index padding cannot be inserted into a real control transaction without additional response-side handling or a different cover-traffic design.”

Do not say:
- padding works
- this is safe for real relays
- this is a universal DNP3 behavior
- invalid CROBs are invisible
- accepted SELECT means executed

Validation:
Run static checks:

  python3 -m py_compile run_master.py
  python3 -m py_compile run_outstation.py
  python3 -m py_compile analyze_multicrob_pcap.py
  python3 -m py_compile run_crob_padding_candidate_tests.py

Then run:

  python3 run_crob_padding_candidate_tests.py --user decps

Final response should report:
- files changed
- cases run
- pass/classification per case
- first rejected index/status per invalid case
- whether OPERATE was sent per case
- paths to PCAPNG, analyzer JSON, manifest, and markdown report
- any uncertainty or failed case
# Invalid-Index CROB Padding-Candidate Tests

## Purpose

Determine whether nonexistent G12V1 CROB indexes can act as harmless padding candidates in a Select-Before-Operate command set, and what response-side evidence they produce. This is protocol characterisation only -- it does NOT implement padding and does NOT prove padding is safe.

## Method

- Object type fixed: Group 12 Variation 1 CROB; one SBO command set; qualifier `0x28`, Count=N.
- Outstation configured with K valid software-only points (indexes `0..K-1`).
- Master sends N CROBs via an explicit ordered `--crob-plan` (baseline uses `--crob-count`), placing invalid (index >= K) CROBs at chosen positions.
- `maxControlsPerRequest` is unchanged; no response is rewritten; no physical output exists.
- Correctness = per-index `CommandStatus` in the SELECT response (PCAP) + outstation JSON, never TCP packet count. Task-level master SUCCESS is not proof any output changed.

## Case table

| case | K | N | transmitted order | classification | first rejected | OPERATE sent | valid output changed | analyzer pass |
|------|---|---|-------------------|----------------|----------------|--------------|----------------------|---------------|
| valid_k5_n5 | 5 | 5 | [0, 1, 2, 3, 4] | `all_success` | - | True | yes | True |
| invalid_end_k5_n6 | 5 | 6 | [0, 1, 2, 3, 4, 5] | `invalid_index_rejected_during_select_no_operate` | 5 / OUT_OF_RANGE | False | no | True |
| invalid_begin_k5_n6 | 5 | 6 | [5, 0, 1, 2, 3, 4] | `invalid_index_rejected_during_select_no_operate` | 5 / OUT_OF_RANGE | False | no | True |
| invalid_middle_k5_n6 | 5 | 6 | [0, 1, 5, 2, 3, 4] | `invalid_index_rejected_during_select_no_operate` | 5 / OUT_OF_RANGE | False | no | True |
| multiple_invalid_k5_n8 | 5 | 8 | [0, 1, 2, 3, 4, 5, 6, 7] | `multiple_invalid_indexes_rejected` | 5 / OUT_OF_RANGE | False | no | True |
| decoy_only_invalid_k5_n3 | 5 | 3 | [5, 6, 7] | `decoy_only_invalid_rejected` | 5 / OUT_OF_RANGE | False | no | True |
| count_limit_vs_invalid_k5_n17 | 5 | 17 | [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16] | `multiple_invalid_indexes_rejected` | 5 / OUT_OF_RANGE | False | no | True |
| count_limit_valid_k16_n17 | 16 | 17 | [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16] | `too_many_ops_during_select` | 16 / TOO_MANY_OPS | False | no | True |

## Interpretation (observed, not assumed)

Per-case status maps, byte lengths, and DNP3 frame counts are in `padding_candidate_manifest.csv` and `analyze_<case>.json`. The per-index CommandStatus is read verbatim from the SELECT response on the wire and reported as observed; the harness does not assume it. In these runs the observed status for a nonexistent index was `OUT_OF_RANGE` (status 12), and the per-request operation-count limit produced `TOO_MANY_OPS` (status 8) once the command count exceeded `maxControlsPerRequest`; the two are distinct and both visible per-index on the wire. The returned status originates in the outstation application control-point backend (OpenDNP3 does not validate a control index natively), not in this test runner.

## What this means for padding

Invalid-index CROBs do not execute physical or simulated configured outputs, but they are visible in the SELECT response through non-success command statuses. In the current OpenDNP3 SBO behavior, a partial SELECT failure prevents OPERATE, so invalid-index padding cannot be inserted into a real control transaction without additional response-side handling or a different cover-traffic design.

## What it does NOT prove

- It does NOT show padding works, or that invalid CROBs are invisible.
- An accepted SELECT does not mean a control executed; task-level SUCCESS is not execution.
- It is not safe for real relays and maps no index to a physical output.
- It is not a universal DNP3 behavior -- only this OpenDNP3 build/host/config.


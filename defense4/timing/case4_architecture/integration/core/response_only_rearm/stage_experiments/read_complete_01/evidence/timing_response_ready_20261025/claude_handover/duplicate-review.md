# Independent review of the pending duplicate-driver change

Spec compliance verdict: **PASS** for the scoped change.

Code quality verdict: **PASS** for the scoped change. No blocking or non-blocking defects found in the added assertions or repaired expectation. This is the assigned independent review slice, not an aggregate merge authorization.

## Scope and findings

Reviewed the current diff in `defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/seg61_02/model_dup.py`, specifically lines 514 and 518–531, against generated c67 N/E/T source and retained duplicate runs 01/02. No source edits, model launches, hardware access, network activity, or child agents were used.

Severity-ranked findings: **CRITICAL 0; HIGH 0; MEDIUM 0; LOW 0**.

## Why the expectation repair is justified

The generated source is `stage_experiments/ctl_timing_01/evidence/m12p_c67_sdk9132/response_only.p4` (paths in this report are relative to `defense4/timing/case4_architecture/integration/core/response_only_rearm/` unless otherwise stated).

- E's `acct_rev` computes `hi = lo - m.ina` at source line 1018. Its table selects that write for qualified reverse ACK provenance (`0xe4`, `0xe5`, or reset kind 13), at line 1029. A forwarded request duplicate does not satisfy those rows. `acct.hi` is pending wire distance; it is not an unconditional replay marker.
- N creates a validated request-duplicate event through `first_request_dup` at line 391 and the profile-specific rows at line 404. T's verdict rows at lines 2178–2180 forward a completed response generation, suppress a duplicate while the response child is retained, and otherwise forward. These duplicate paths do not admit another request or allocate a generation.
- Retained `model_dup_m12p_c67_sdk9132_01/dup_results.json` fails only the old marker expectation: expected `hi=141`, observed `hi=0`, with `lo=26142`. Its other 112 cases pass. The repaired profile-specific expectation agrees with the actual c67 write conditions. The `else READ_IMAGE` branch preserves the previous expectation for historical contracts.
- In retained run 02's `model.out`, N takes `first_request_dup` at line 933558 and T drops the held duplicate at line 939280. The later retry takes N `first_request_dup` at line 949459 and T `passthrough_request_dup` at line 952698. The corresponding E pass (`0x44e`) executes no `do_acct_*` action. It emits one normalized READ to port 64; the retained frame has sequence 23001 and the expected adjusted window. The snapshot keeps `hi=0`, `lo=26142`, `front=img_end=26092`, `img_start=26001`, and `img_wend=26142`.

## Replay coverage and evidence

The new block sends the original native response again only for `response_ready_ack_d_v2`. The existing `step` helper at `model_dup.py:133` requires exactly one frame and checks it with `same_frame`; the new call therefore checks the padded replay bytes rather than accepting arbitrary traffic.

The added checks cover both generation allocators, all sampled timing outcome counters (1–5), and the native/image frontiers. The late retry already checks the entire account register and all remaining sampled E mapping registers. Together they establish no extra allocation, image commit/frontier growth, or counted timing release for this scenario.

I checked the actual replay processing as well as the report assertions:

- Run 02's model log takes N `first_response_dup` at line 954401 and E `out_replay` at line 958973. The E pass has `front_ret=-91`, `grant=0`, native length 91, `p=0`, `q=-91`, and `y=0`, matching the exact cached-image replay classification at generated source line 1103.
- It uses `do_start_fwd`, `do_end_fwd`, and `do_wend_fwd`, and executes no `do_acct_*` action. These are the noncommitting replay paths.
- The raw `Tx Pkt to port 9` record at model-log line 959162 contains the same complete Ethernet/IP/TCP/DNP3 bytes as the originally released response after trimming bytes beyond the IPv4 total length. The meaningful frame is 207 bytes with a 141-byte TCP payload. This independently corroborates the driver's exact-frame success.
- Retained run 02 records **117/117 passing cases**, including all four added replay assertions. READ and OPERATE generation values remain 21 and 20; sampled timing outcome counters remain `{1:292, 2:6, 3:6, 4:0, 5:5}`; all four frontier snapshots remain unchanged.

## Validation performed

Read-only commands included:

```sh
git diff -- defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/seg61_02/model_dup.py
nl -ba defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/seg61_02/model_dup.py
rg -n 'do_acct_rev|out_replay|first_request_dup|passthrough_request_dup|drop_request_duplicate|first_response_dup' defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/ctl_timing_01/evidence/model_dup_m12p_c67_sdk9132_02/model.out
```

A read-only Python audit also parsed the current driver with `ast.parse`, asserted that every retained run-02 case passes, checked current driver/retained driver/report/launch/closure SHA-256 identity, checked generated-source/compiled-source/launch SHA-256 identity, verified all 37 retained dependency-closure hashes against the current working tree, extracted and compared the raw replay Tx bytes with the original wire response, and checked the relevant E actions for account writes. All checks passed. The current driver hash is `04fe7dbfff03715689b58cabfd640a308e4c1c57cf9ac99c93f238ec9237a09c`; the generated source hash is `e8565de7c317124b2c3377ce02fc2a932d4f86e1625ed224ec9fed550d6d2ec1`.

Limit: this review verifies the retained compiled-model run and its current source/dependency identity. It does not claim a new model execution or hardware validation. The added ready-profile block was not executed for historical profiles in this review; inspection confirms its guard retains their prior execution path and account expectation.

# c67 v2 review record — 2026-10-25

Selected source: e8565de7c317124b2c3377ce02fc2a932d4f86e1625ed224ec9fed550d6d2ec1.

Independent reviewer `/root/review_source` approved the four-field API, exact source/profile bindings,
obsolete-parameter rejection, readable duplicate counters, zero normal bypass, 1,930 reference denominator,
100 µs criterion and explicit unproven physical J. Fresh targeted review tests: 49 passed.

Source review reproduced and required repair of disabled OPERATE retries and two request-identity aliases:
READ25 versus READ27 with a shifted start but equal end, and SELECT versus OPERATE with equal application byte.
c67 binds shape/function in existing 32-bit banks and invalidates opposite-class identity on admission.
Fresh frozen-source tests and positive SELECT→OPERATE / both READ response checks passed. Final c67 differs
from the reviewed c66 only by a PHV isolation annotation. Independent artifact audit: no problems; N/E0..10,
T0..9, pipe1egress0..3, all 11 T state objects have one physical allocation.

`/root/source_impl` independently reviewed root's model_dup/model_contention adapters: genuine ACK before
OPERATE response, actual T-clock J/ACK/D proofs, no v2 host DA/gap floor or removed t0 snapshot, actual request
counter names, and retained duplicate, contention, abort and restart cases. Root corrected the reviewer's
remaining 180 ms host-gap floor finding. Associated offline tests: 215 passed.

Actual pipe1 resource totals c52→c67: SRAM61→52, TCAM63→52, stateful ALU13→11, crossbar403→325;
T allocated PHV capacity1344→1040 bits, occupied T stages11→10. Pipe0 TCAM102→105 and crossbar866→882;
SRAM182→179, stateful ALU24 unchanged, N/E stages unchanged. Full reports: c52_to_c67_resources.json.

Reviews do not claim a completed runtime gate or physical qualification. Those require their own recorded runs.

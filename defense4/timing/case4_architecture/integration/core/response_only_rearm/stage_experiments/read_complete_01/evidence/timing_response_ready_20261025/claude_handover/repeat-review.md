# Read-only repeat-driver review

Reviewed the current uncommitted repeat/lifecycle/abandon changes on 2026-10-25. No source, tests, profiles, model evidence, hardware, or model processes changed by this reviewer. This report is the only authored file. The implementation assignment was superseded by the parent's read-only review request because another session owns those edits.

Reviewed SHA-256 identities, freshly checked before finalizing:

```text
model_repeat.py            7f9a301f1cec9c03b6aab792a910f44af89787553b05e0298244549859bca7ae
model_select_lifecycle.py  f411f334ca420ec38de69b997d5b2bfda19ed19d0b88d02cea3f3f879783f33d
model_abandon.py           8022a36b23e74a08ab7e234e109316b1ab8c2ec4ac92c6802766a96e4e3146a5
```

## Findings requiring correction

1. **HIGH — `response_ready_pair` accepts delivery to the wrong physical endpoint.** `stage_experiments/seg61_02/model_repeat.py:122-123` flattens all output-port lists before checking two exact frame bytes. A capture `{9: [], 64: [ACK, RESPONSE]}` returns `good=True`, although the master received nothing. The helper is consumed by repeat at lines 264-268 and `ctl_timing_01/model_select_lifecycle.py:144-148`, so both can label this exact pair successful. This is reproduced offline against the actual helper below. Require exactly `[ACK, RESPONSE]` on the explicit master port and zero frames on other observed ports; preserve the lifecycle caller contract deliberately if adding an argument.

2. **HIGH — failed requests still cause simulated relay replies, and dependent timed cases continue.** `model_repeat.py:247-249` records a failed request but advances the client frontier; lines 257-276 then submit ACK/response and increment the exchange count. `sbo` at lines 287-291 unconditionally issues OPERATE after a failed SELECT. Phase B at lines 326-333 ignores the READ/SBO return values and continues later cycles/probes. The offline actual-`exchange` probe below returns `ok=False` while still invoking the relay-pair boundary and incrementing SELECT. Thus a request never observed at the relay can elicit fabricated relay stimulus, with later coordinates/counts derived from failed delivery. This continuation existed in legacy control flow; the approved correction explicitly required stopping dependent cases and retaining planned/unexecuted diagnosis. Stop immediately at the first failed prerequisite, retain its capture and planned/completed counts, and mark remaining dependent cases unexecuted. Lifecycle has the same prerequisite issue: `model_select_lifecycle.py:125-128` ignores `step` and advances its frontier before `respond` sends the pair.

## Acceptance gap and proof limitation

- **Missing requested per-repeat temporal J evidence; not a legacy regression.** Legacy repeat promised one OPERATE release per timed cycle and counted outcome 5; it did not measure J. The current patch still provides only those counts (`model_repeat.py:329-333`). Its observer offset is taken after the request has already been captured at the relay (`:247-248`, `:263`), excluding that OPERATE's anchor/release passes. `repeat_clock_proof` does not accept J or read OPERATE actions. A zero-duration synthetic OPERATE hold leaves its proof passing. This fails the explicit repeat-brief requirement for T-clock J evidence, but does **not** establish a dataplane regression or absence of J coverage overall: `ctl_timing_01/model_response_ready.py:637-642` independently checks J against the written units. To close the repeat-specific requirement, take an additional offset before sending OPERATE and compare its measured anchor/release delta with the recorded `written['op_j']`, while retaining one-release assertions.

- **Tied-stamp causality is weaker than the helper docstring suggests.** `model_repeat.py:132-137` accepts commit and response-arrival in the same quantized T tick, regardless of record order. A synthetic list containing `hold_ack(1000), release_ack_commit(1000), admit_response(1000), release_response_counted(20534)` passes for D=19534. This demonstrates the clock check's permissiveness, **not** an observed early ACK or dataplane bug: equal 512 ns-grid stamps cannot order sub-grid events. The helper does not retain action ordinals. If the model log/parser provides a trustworthy total order for these actions, preserve and validate it for ties; otherwise state the sub-grid ordering limitation and use additional causal evidence. Do not infer early release merely from equal stamps. The established observer also permits equal commit/arrival stamps, so this concern should not be described as a newly introduced regression.

## What the patch does correctly

Timed v2 READ/SELECT/OPERATE all receive a real simulated relay ACK and complete response. ACK and response are sent without BFRT/log work between the two sends. The response-ready branch is selected through the source-validating profile resolver, and legacy/Phase A packet branches remain in place. D is checked against `t_params_written.json`'s converted T units, rather than comparing model ticks to nanoseconds. Existing sequence-wrap, growth, selection-cancel, unpaired-OPERATE and reset probes remain present. Neither the source nor profile is silently switched by these changes.

## Fresh verification

Executed successfully:

```text
python3 -m pytest -q \
  defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/ctl_timing_01/tests/test_rearm_response_ready.py \
  defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/ctl_timing_01/tests/test_response_ready_stimulus.py \
  defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/ctl_timing_01/tests/test_response_ready_profile.py
53 passed in 0.18s
```

These 53 tests cover existing rearm, observer, and profile behavior. A dedicated repeat test file **does exist** at `stage_experiments/seg61_02/tests/test_repeat_response_ready.py`; my initial review searched only the CTL tests directory and incorrectly stated it was absent. It was subsequently read and executed:

```text
python3 -m pytest -q defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/seg61_02/tests/test_repeat_response_ready.py
3 passed in 0.04s
```

The dedicated tests execute the actual helpers/closure through AST extraction. They cover ACK/response send-before-capture ordering; rejection of reversed, extra, missing and empty output frames on port 9; D threshold, required arrival/action stamps, duplicate commit/release actions and clock wrap; and the READ/SELECT/OPERATE adapter branch across v2/non-v2 and enabled/disabled conditions, including successful coordinate/count updates. They do **not** test delivery on a wrong port, failed-request/dependent-case behavior, temporal OPERATE J, tied-stamp causality, or source-bound profile resolution. The two concrete findings therefore remain, as do the explicitly qualified J acceptance gap and tied-clock limitation. Source hashes were rechecked after this correction and remain identical to the identities above.

The following minimal offline reproducer executes the actual helper and actual nested exchange with fake packet/model I/O. Extracting the nested function replaces only its closure declaration with equivalent test-namespace globals; its control flow is unchanged. No SDK, model, hardware, or network is involved.

```python
import ast
from pathlib import Path
from types import SimpleNamespace as NS
p = Path('defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/seg61_02/model_repeat.py')
tree = ast.parse(p.read_text())
ns = {}
def install(node):
    exec(compile(ast.fix_missing_locations(ast.Module(body=[node], type_ignores=[])), str(p), 'exec'), ns)
pair = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'response_ready_pair')
install(pair)
model = NS(drain=lambda ports: None, send=lambda port, raw: None,
           capture=lambda *a, **k: {9: [], 64: [b'ACK', b'RESPONSE']})
assert ns['response_ready_pair'](model, [9, 64], 64, b'ACK', b'RESPONSE',
                               b'ACK', b'RESPONSE', lambda a,b,c: a == b)[1]
print('Wrong-port capture accepted with empty master capture')

main = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'main')
body = next(n for n in main.body if isinstance(n, ast.Try)).body
exchange = next(n for n in body if isinstance(n, ast.FunctionDef) and n.name == 'exchange')
exchange.body = [n for n in exchange.body if not isinstance(n, ast.Nonlocal)]
exchange.body.insert(0, ast.Global(names=['c', 's', 'growth']))
calls = []
ns.update(c=101, s=901, growth=0,
    seqs=NS(request=lambda *a: (b'REQ', 0), next_app=lambda: None, response=lambda *a: b'NATIVE'),
    step=lambda *a, **k: False, vectors=NS(packet=lambda *a, **k: b'FRAME'),
    ready=True, params={'enabled': 1}, IMAGE_LEN=5,
    encode61=NS(read61=lambda n: b'IMAGE', ctl61=lambda n: b'IMAGE'),
    rp=NS(image_len_of=lambda *a: 5, preserve_options=lambda a,b: b,
          advance_timestamp=lambda: None, growth=lambda *a: -1),
    view=NS(size=lambda p: 0), log_path=None, RELAY=NS(dev_port=64),
    m=object(), ports=[9,64], same_frame=lambda a,b,c: a == b,
    report=NS(add=lambda *a, **k: None), counts={'READ': 0, 'SELECT': 0, 'OPERATE': 0},
    timing_proof=lambda *a: True,
    response_ready_pair=lambda *a: (calls.append('relay pair') or ({9:[b'ACK', b'IMAGE']}, True)))
install(exchange)
assert ns['exchange']('t00', 'SELECT', 3, b'objects', b'body', False)[0] is False
assert calls == ['relay pair'] and ns['counts']['SELECT'] == 1
print('Failed request still stimulates relay pair and increments SELECT count')
```

The exact embedded reproducer was re-executed from this report and printed both reproduction messages, exit 0. Additional offline probes reproduced the zero-J acceptance and tied-stamp permissiveness described above. Compiled runs launched by the other session were not rerun, stopped, or altered by this reviewer; a passing run does not remove these verifier false-acceptance and coverage issues.

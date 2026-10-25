"""v2 abort negatives: after the rejected RST, the genuine ACK must release the already-held original response once."""
import ast
from pathlib import Path

DRIVER = Path(__file__).resolve().parents[1] / 'model_contention.py'


def verdict():
    tree = ast.parse(DRIVER.read_text())
    node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'abort_survivor_verdict')
    ns = {}
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(DRIVER), 'exec'), ns)
    return ns[node.name]


def frame(tag, rst=False):
    raw = bytearray(64)
    raw[47] = 0x14 if rst else 0x10
    raw[48:48 + len(tag)] = tag
    return bytes(raw)


ACK, RSP = frame(b'ack'), frame(b'rsp')
GOOD = dict(ACK_COMMIT=1, RESP_RELEASE=1, HELD_REWAIT=900)
PROOF = dict(passed=True)


def same(got, want, _sent):
    return got == want


BEFORE = dict(responses=0, frames_to_master=0)


def judge(frames=(ACK, RSP), deltas=GOOD, e_delta=0, proof=PROOF, held=True, before=BEFORE):
    return verdict()(held, dict(before), list(frames), b'native-ack', ACK, RSP, dict(deltas), e_delta, dict(proof),
                     same)


def test_exact_ack_then_original_response_with_one_commit_release_and_clock_proof_passes():
    assert judge()


def test_wrong_order_missing_extra_or_reset_frames_fail():
    for frames in ([RSP, ACK], [ACK], [RSP], [], [ACK, RSP, RSP], [ACK, RSP, frame(b'x', rst=True)],
                   [ACK, frame(b'rsp', rst=True)], [ACK, frame(b'other')]):
        assert not judge(frames=frames)


def test_lane_counts_fallbacks_e_reset_and_clock_proof_are_each_required():
    for change in (dict(ACK_COMMIT=0), dict(ACK_COMMIT=2), dict(RESP_RELEASE=0), dict(RESP_RELEASE=2),
                   dict(RESP_FALLBACK=1), dict(ACK_FALLBACK=1)):
        assert not judge(deltas=dict(GOOD, **change))
    assert not judge(e_delta=1)
    assert not judge(proof=dict(passed=False))
    assert not judge(proof={})


def _abort_case():
    tree = ast.parse(DRIVER.read_text())
    main = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'main')
    return next(n for n in ast.walk(main) if isinstance(n, ast.FunctionDef) and n.name == 'abort_case')


def _ready_negative_block():
    """The `if ready:` block that follows the `<tag>_no_master_reset` verdict in abort_case."""
    for node in ast.walk(_abort_case()):
        if isinstance(node, ast.If) and isinstance(node.test, ast.Compare) and \
                isinstance(node.test.left, ast.Name) and node.test.left.id == 'offset' and \
                isinstance(node.test.ops[0], ast.In):
            body = node.body
            first = ast.unparse(body[0]) if hasattr(ast, 'unparse') else ast.dump(body[0])
            assert 'no_master_reset' in first
            ready = [n for n in body if isinstance(n, ast.If) and isinstance(n.test, ast.Name)
                     and n.test.id == 'ready']
            assert len(ready) == 1 and body.index(ready[0]) == 1
            return ready[0]
    raise AssertionError('negative-control branch not found')


def _sends(nodes):
    return [n for block in nodes for n in ast.walk(block) if isinstance(n, ast.Call)
            and isinstance(n.func, ast.Attribute) and n.func.attr == 'send']


def test_v2_negative_sends_only_the_genuine_ack_to_the_relay_after_the_rst_verdict():
    block = _ready_negative_block()
    sends = _sends(block.body)
    assert len(sends) == 1
    port, payload = sends[0].args
    assert ast.dump(port) == ast.dump(ast.parse('RELAY.dev_port', mode='eval').body)
    assert isinstance(payload, ast.Name) and payload.id == 'ack'
    ack = next(n for n in block.body if isinstance(n, ast.Assign) and
               any(isinstance(t, ast.Name) and t.id == 'ack' for t in n.targets))
    # the same standalone ACK the released branch sends: packet(16, s, c, reverse=True)
    call = ack.value
    assert [a.value if isinstance(a, ast.Constant) else a.id for a in call.args] == [16, 's', 'c']
    assert block.orelse == []                         # legacy (non-v2) negatives are unchanged


def test_v2_negative_verdict_uses_survivor_rule_and_records_post_completion_row():
    block = _ready_negative_block()
    calls = [n for n in ast.walk(block) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
             and n.func.id == 'abort_survivor_verdict']
    assert len(calls) == 1
    updated = [n for n in ast.walk(block) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
               and n.func.attr == 'update' and isinstance(n.func.value, ast.Name) and n.func.value.id == 'row']
    assert len(updated) == 1
    keys = {k.arg for k in updated[0].keywords}
    assert {'responses', 't_deltas', 'resets_seq', 'e_reset_front_delta', 'response_ready_clock_proof'} <= keys


def test_response_must_be_held_across_the_rst_and_nothing_delivered_before_the_ack():
    for held in (False, None):
        assert not judge(held=held)
    for before in (dict(responses=1, frames_to_master=1), dict(responses=0, frames_to_master=1), {}):
        assert not judge(before=before)

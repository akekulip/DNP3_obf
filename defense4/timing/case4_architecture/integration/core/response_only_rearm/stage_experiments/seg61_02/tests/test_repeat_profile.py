"""Exercise the repeat driver's production expectation branch without importing SDK/model clients."""
import ast
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

SEG = Path(__file__).resolve().parents[1]
RR = SEG.parents[1]
CT = SEG.parent / 'ctl_timing_01'
DRIVER = SEG / 'model_repeat.py'


def driver_logic():
    tree = ast.parse(DRIVER.read_text(), filename=str(DRIVER))
    stdlib = {'copy', 'hashlib', 'importlib', 'json', 'os', 'sys', 'traceback'}
    pure = [node for node in tree.body if
            isinstance(node, ast.Import) and all(alias.name.split('.')[0] in stdlib for alias in node.names) or
            isinstance(node, ast.ImportFrom) and node.module == 'pathlib' or
            isinstance(node, ast.FunctionDef) and node.name in ('load', 'repeat_milestone')]
    namespace = {'__file__': str(DRIVER), 'HERE': RR}
    exec(compile(ast.Module(body=pure, type_ignores=[]), str(DRIVER), 'exec'), namespace)
    branch = next(node for node in ast.walk(tree) if isinstance(node, ast.If) and
                  any(isinstance(child, ast.Constant) and child.value == 'probe3_READ_after_SELECT_cancels_selection'
                      for child in ast.walk(node)))
    return namespace, branch


def probe3_decision(monkeypatch, inputs, milestone):
    if inputs is None:
        monkeypatch.delenv('PORT_MAP', raising=False)
    else:
        monkeypatch.setenv('PORT_MAP', str(inputs))
    if milestone is None:
        monkeypatch.delenv('MILESTONE', raising=False)
    else:
        monkeypatch.setenv('MILESTONE', milestone)
    namespace, branch = driver_logic()
    resolved = namespace['repeat_milestone']()
    calls, cases = [], []
    namespace.update(milestone=resolved,
                     report=SimpleNamespace(add=lambda *args, **kwargs: cases.append(args)),
                     read=lambda tag: calls.append(tag) or True,
                     seqs=SimpleNamespace(request=lambda *args: (b'read', 0), next_app=lambda: None),
                     vectors=SimpleNamespace(packet=lambda *args, **kwargs: b'read'),
                     m=SimpleNamespace(exchange=lambda *args, **kwargs: {9: [b'read']}),
                     MASTER=SimpleNamespace(dev_port=9), ports=[9], c=40036, s=50038, growth=24,
                     READ_OBJECTS=b'objects')
    exec(compile(ast.Module(body=[branch], type_ignores=[]), str(DRIVER), 'exec'), namespace)
    return resolved, calls, cases


def test_m11_successor_runs_the_cancellation_exchange(monkeypatch):
    resolved, calls, cases = probe3_decision(monkeypatch, CT / 'evidence/m11_09/response_only.inputs.json', 'm11')
    assert calls == ['probe3_cancel']
    assert cases == [('probe3_READ_after_SELECT_cancels_selection', True, True)]
    assert resolved == 'm10'


@pytest.mark.parametrize('milestone,build,cancels',
                         [('m1', 'm1_01', False), ('m2', 'm2_01', False),
                          ('m3', 'm3_01', False), ('m10', 'm10_03', True)])
def test_historical_source_bound_expectations_stay_unchanged(monkeypatch, milestone, build, cancels):
    resolved, calls, cases = probe3_decision(monkeypatch, CT / ('evidence/' + build + '/response_only.inputs.json'), milestone)
    assert resolved == milestone
    assert bool(calls) is cancels
    assert cases[0][0] == ('probe3_READ_after_SELECT_cancels_selection' if cancels else
                           'probe3_READ_after_SELECT_dropped_unsupported_shape')


def test_non_ct_driver_without_a_milestone_keeps_legacy_drop(monkeypatch):
    resolved, calls, cases = probe3_decision(monkeypatch, SEG / 'evidence/full_04/response_only.inputs.json', None)
    assert resolved is None and calls == []
    assert cases[0][0] == 'probe3_READ_after_SELECT_dropped_unsupported_shape'


def test_recorded_successor_profile_applies_when_env_label_is_absent(monkeypatch):
    resolved, calls, _ = probe3_decision(monkeypatch, CT / 'evidence/m11_09/response_only.inputs.json', None)
    assert resolved == 'm10' and calls == ['probe3_cancel']


@pytest.mark.parametrize('mutation', ('source', 'candidate_hash', 'unknown_source', 'milestone'))
def test_mismatched_or_unknown_identity_is_rejected_before_the_probe(monkeypatch, tmp_path, mutation):
    source = (CT / 'evidence/m11_09/response_only.p4').read_bytes()
    inputs = json.loads((CT / 'evidence/m11_09/response_only.inputs.json').read_text())
    label = 'm11'
    if mutation == 'source':
        source += b'\n// changed source\n'
    elif mutation == 'candidate_hash':
        inputs['supported_profile']['candidate']['source_sha256'] = '0' * 64
    elif mutation == 'unknown_source':
        inputs.pop('supported_profile')
    else:
        label = 'm10'
    (tmp_path / 'response_only.p4').write_bytes(source)
    path = tmp_path / 'response_only.inputs.json'
    path.write_text(json.dumps(inputs))
    with pytest.raises(ValueError):
        probe3_decision(monkeypatch, path, label)


def test_profile_resolution_precedes_connecting_to_the_model():
    tree = ast.parse(DRIVER.read_text())
    main = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'main')
    calls = [n for n in ast.walk(main) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)]
    profile = next(n for n in calls if n.func.id == 'repeat_milestone')
    model = next(n for n in calls if n.func.id == 'Model')
    assert profile.lineno < model.lineno


def test_legacy_default_port_map_without_ct_milestone_remains_supported(monkeypatch):
    resolved, calls, cases = probe3_decision(monkeypatch, None, None)
    assert resolved is None and calls == []
    assert cases[0][0] == 'probe3_READ_after_SELECT_dropped_unsupported_shape'


def test_claimed_ct_semantics_without_a_source_bound_map_are_rejected(monkeypatch):
    with pytest.raises(ValueError, match='source-bound PORT_MAP'):
        probe3_decision(monkeypatch, None, 'm11')


def test_empty_port_map_without_ct_milestone_keeps_legacy_default(monkeypatch):
    resolved, calls, cases = probe3_decision(monkeypatch, '', None)
    assert resolved is None and calls == []
    assert cases[0][0] == 'probe3_READ_after_SELECT_dropped_unsupported_shape'


def test_claimed_ct_semantics_with_empty_port_map_are_rejected(monkeypatch):
    with pytest.raises(ValueError, match='source-bound PORT_MAP'):
        probe3_decision(monkeypatch, '', 'm11')

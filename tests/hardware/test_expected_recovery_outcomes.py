"""Expected recovery outcomes in loss blocks (Philip, 2026-10-30): a declared outcome is recorded and counted; any
other correctness failure stops the campaign; a block without the declaration keeps the historical rule."""
import copy
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/hardware'))
import campaign_base as cb  # noqa: E402

BLOCK = next(iter(sorted((ROOT / 'results/hardware/blocks').glob('rc01_hw_c74_recovery_r1_20261030_02_*'))), None)
needs = pytest.mark.skipif(BLOCK is None, reason='retained c74 recovery block absent')
DECLARED = {'operate_crob_status': ['SUCCESS', 'TIMEOUT'], 'points': [1, 3]}


def load(t):
    path = next((BLOCK / 'physical_relay').glob('*/*_%s' % t))
    return tuple(json.loads((path / n).read_text()) for n in ('trial.json', 'relay_wire.json', 'standards_verdict.json'))


def decide(t, declared=DECLARED, vision_rc=None, loss_failures=(), change=None):
    trial, wire, standards = load(t)
    if change:
        change(trial, wire, standards)
    rc = vision_rc if vision_rc is not None else (0 if trial['ok'] else 1)
    return cb.loss_trial_decision(trial, wire, standards, declared, rc, list(loss_failures))


@needs
def test_a_success_passes_and_a_declared_timeout_is_an_expected_outcome():
    assert decide('t0') == 'pass'
    assert decide('t3') == 'expected_outcome'


@needs
def test_without_a_declaration_the_historical_soft_failure_rule_holds():
    assert decide('t3', declared=None) == 'soft_failure'
    assert decide('t0', declared=None) == 'pass'


def operate(wire):
    return next(e for e in wire['exchanges'] if e['operation'] == 'OPERATE')


def read(wire):
    return next(e for e in wire['exchanges'] if e['operation'] == 'READ')


@needs
@pytest.mark.parametrize('name,change', [
    ('undeclared status', lambda t, w, s: operate(w)['application'].update(points=[[1, 'NO_SELECT'], [3, 'NO_SELECT']])),
    ('other points', lambda t, w, s: operate(w)['application'].update(points=[[1, 'TIMEOUT'], [6, 'TIMEOUT']])),
    ('a failed READ', lambda t, w, s: read(w)['application'].update(ok=False)),
    ('an incomplete response', lambda t, w, s: read(w)['response'].update(complete=False)),
    ('two OPERATEs', lambda t, w, s: w['exchanges'].append(copy.deepcopy(operate(w)))),
    ('wrong OPERATE size', lambda t, w, s: operate(w)['response'].update(end_offset=operate(w)['response']['end_offset'] + 3)),
    ('switch failure', lambda t, w, s: t['dimension_verdicts'].update(switch=False)),
    ('standards transport failure', lambda t, w, s: s['verdicts'].update(transport=False)),
    ('standards size failure', lambda t, w, s: s['verdicts'].update(size=False))])
def test_any_other_correctness_failure_stops(name, change):
    assert decide('t3', change=change) == 'stop', name


@needs
def test_a_loss_target_failure_or_an_infrastructure_rc_stops():
    assert decide('t3', loss_failures=['target not dropped']) == 'stop'
    assert decide('t0', loss_failures=['target not dropped']) == 'stop'
    assert decide('t3', vision_rc=2) == 'stop'


def config(entries):
    return {'loss': {'presets': {'p': entries}}, 'trials': {'reads_per_trial': 20}, 'arms': [], 'scenarios': {}}


def test_the_declaration_is_validated():
    entry = {'class': 'select_resp_padded', 'n': 1, 'target': 'identity'}
    cb.validate_loss_and_scenarios(config([dict(entry, expected_outcomes=DECLARED)]))
    cb.validate_loss_and_scenarios(config([entry]))
    for bad in ({'operate_crob_status': ['SUCCESS', 'NO_SELECT'], 'points': [1, 3]},
                {'operate_crob_status': [], 'points': [1, 3]},
                {'operate_crob_status': ['TIMEOUT'], 'points': [1, 6]},
                {'operate_crob_status': ['TIMEOUT'], 'points': []},
                {'operate_crob_status': ['TIMEOUT'], 'points': [1, 3], 'extra': 1}):
        with pytest.raises(ValueError):
            cb.validate_loss_and_scenarios(config([dict(entry, expected_outcomes=bad)]))

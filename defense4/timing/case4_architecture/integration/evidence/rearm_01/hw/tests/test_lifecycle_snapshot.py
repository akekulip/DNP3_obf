import importlib.util
import json
from pathlib import Path

import pytest

path = Path(__file__).resolve().parents[1] / 'snapshot_lifecycle.py'
spec = importlib.util.spec_from_file_location('lifecycle_snapshot', path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

PAIR = {'data': [{'singleton': {'name': 'work.lo'}}, {'singleton': {'name': 'work.hi'}}]}


def test_both_paired_register_lanes_are_retained():
    values = {'work.lo': [0], 'work.hi': [65537]}
    assert module.validate_register_fields(PAIR, values) == values


@pytest.mark.parametrize('values', [
    {'work.lo': [0]}, {'work.lo': [0], 'work.hi': None},
    {'work.lo': [], 'work.hi': [1]}, {'work.lo': [False], 'work.hi': [1]},
])
def test_incomplete_registers_cannot_be_valid_evidence(values):
    with pytest.raises(ValueError, match='missing or unreadable'):
        module.validate_register_fields(PAIR, values)


def test_context_allocation_separates_absent_declarations(tmp_path):
    for pipe in ('p0', 'p1'):
        (tmp_path / pipe).mkdir()
        (tmp_path / pipe / 'context.json').write_text(json.dumps({'tables': [
            {'name': 'control.owner', 'table_type': 'stateful', 'stage_tables': [{'stage_number': 1}]},
            {'name': 'control.unused', 'table_type': 'stateful', 'stage_tables': []},
            {'name': 'control.match', 'table_type': 'match', 'stage_tables': [{'stage_number': 1}]},
        ]}))
    names, hashes = module.allocated_registers(tmp_path)
    assert names == {'p0.control.owner', 'p1.control.owner'}
    assert all(len(value) == 64 for value in hashes.values())


def test_missing_context_cannot_silently_omit_hardware_registers(tmp_path):
    with pytest.raises(FileNotFoundError):
        module.allocated_registers(tmp_path)

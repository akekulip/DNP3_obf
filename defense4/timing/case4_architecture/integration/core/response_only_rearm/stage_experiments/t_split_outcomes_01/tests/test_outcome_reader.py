import importlib.util
from pathlib import Path

import pytest

path = Path(__file__).resolve().parents[1] / 'outcome_reader.py'
spec = importlib.util.spec_from_file_location('split_outcome_reader', path)
reader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reader)


def schema():
    return {'tables': [dict(name=name, table_type='Register', size=25,
                           data=[{'singleton': {'name': 'arbitrary_' + bank,
                                                 'type': {'width': 32}}}])
                       for name, bank in zip(reader.REGISTER_NAMES, reader.BANKS)]}


class Fake:
    def __init__(self):
        self.values = {bank: [0] * 25 for bank in reader.BANKS}

    def register_read(self, name, index, pipe):
        assert pipe == 1
        bank = name.rsplit('_', 1)[1]
        return {'arbitrary_' + bank: [self.values[bank][index]],
                'action_name': None, 'is_default_entry': False}


def test_dynamic_fields_sum_all_banks_and_preserve_modular_count():
    model = Fake()
    outcomes = reader.Outcomes(model, schema())
    model.values['tin'][6] = 0xffffffff
    model.values['held'][6] = 2
    model.values['hb'][6] = 1
    assert outcomes.value(6) == 2
    assert outcomes.snapshot() == model.values


def test_single_event_oracle_checks_all_one_hundred_cells():
    model = Fake()
    outcomes = reader.Outcomes(model, schema())
    before = outcomes.snapshot()
    model.values['token'][23] = 1
    assert outcomes.snapshot() == reader.incremented(before, 'token', 23)
    model.values['hb'][23] = 1
    assert outcomes.snapshot() != reader.incremented(before, 'token', 23)


@pytest.mark.parametrize('value', [[], [1, 2], [-1], [1 << 32], [True]])
def test_malformed_or_multiplane_read_fails_closed(value):
    model = Fake()
    model.register_read = lambda *args, **kw: {'arbitrary_token': value}
    with pytest.raises(ValueError):
        reader.Outcomes(model, schema()).read('token', 23)


def test_schema_and_field_mismatch_fail_closed():
    broken = schema()
    broken['tables'][0]['size'] = 16
    with pytest.raises(ValueError):
        reader.Outcomes(Fake(), broken)
    model = Fake()
    model.register_read = lambda *args, **kw: {'old_outcomes.f1': [1]}
    with pytest.raises(ValueError):
        reader.Outcomes(model, schema()).value(6)

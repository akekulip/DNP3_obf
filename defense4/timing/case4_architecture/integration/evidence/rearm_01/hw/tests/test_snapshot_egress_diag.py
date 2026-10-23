"""snapshot_counters.read_egress_diag and its place in the after-snapshot (round-2 review: field names, no-op)."""
import importlib.util
import json
from pathlib import Path

import pytest

SC = Path(__file__).resolve().parents[4] / 'core/response_only_rearm/hw/snapshot_counters.py'
# Loading snapshot_counters imports the installer stack, which registers generic module names ('cp', 'build_ports',
# ...) in sys.modules. Later tests in the same process import their own modules under those names, so every module
# this import adds is removed again; the loaded module keeps its own references.
import sys as _sys  # noqa: E402
_before = set(_sys.modules)
spec = importlib.util.spec_from_file_location('snapshot_counters_under_test', SC)
sc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sc)
for _name in set(_sys.modules) - _before:
    del _sys.modules[_name]


class Data:
    def __init__(self, d):
        self.d = d

    def to_dict(self):
        return self.d


class Table:
    """Field names exactly as BF Runtime reports them: from bfrt.json, without the pipe prefix."""
    def __init__(self, rows):
        self.rows = rows

    def entry_get(self, target, keys, flags):
        assert keys is None and flags == {'from_hw': True}
        for i, (lo, hi) in self.rows.items():
            yield (Data({'r_Egress.diag_egress_ts.lo': [lo], 'r_Egress.diag_egress_ts.hi': [hi]}),
                   Data({'$REGISTER_INDEX': {'value': i}}))


class Switch:
    def __init__(self, rows=None, fail=None):
        self.rows, self.fail = rows, fail

    def table(self, name):
        if self.rows is None:
            raise KeyError(name)                         # BF Runtime: table_dict[name] on a build without it
        if self.fail:
            raise self.fail
        return Table(self.rows)

    def target(self, pipe):
        return pipe


def test_unprefixed_field_names_are_read_and_zero_entries_skipped():
    assert sc.read_egress_diag(Switch({5: (100, 950_100), 6: (0, 0), 7: (200, 0)})) == {5: [100, 950_100], 7: [200, 0]}


def test_a_build_without_the_register_reads_none():
    assert sc.read_egress_diag(Switch(None)) is None


@pytest.mark.parametrize('name, rows, fail, key', (
    ('t0_after.json', None, None, None),                      # m9_01: snapshot unchanged
    ('t0_after.json', {3: (1, 2)}, None, 'egress_diag'),      # m9d after a trial
    ('t0_before.json', {3: (1, 2)}, None, None),             # never in a before-snapshot
    ('t0_after.json', {3: (1, 2)}, TimeoutError('grpc'), 'egress_diag_error')))
def test_after_snapshot_adds_the_register_only_where_it_belongs(tmp_path, monkeypatch, name, rows, fail, key):
    out = tmp_path / name
    out.write_text(json.dumps({'outcomes': {}}))
    monkeypatch.setattr(sc, 'read_n_counters', lambda sw, pipes: {'count_busy': [0] * 8, 'count_term': [0] * 4})
    import types
    import sys
    monkeypatch.setitem(sys.modules, 'switch', types.SimpleNamespace(
        Switch=lambda program, client_id: types.SimpleNamespace(close=lambda: None, **{
            'table': Switch(rows, fail).table, 'target': lambda pipe: pipe})))
    assert sc.add_n_counters(['-o', str(out)]) == 0
    data = json.loads(out.read_text())
    assert data['n_counters']['count_busy'] == [0] * 8
    assert {k for k in ('egress_diag', 'egress_diag_error') if k in data} == ({key} if key else set())


class StateSwitch:
    """register()/must_get() as switch.Switch provides them; 'missing' names raise like an absent BF Runtime table."""
    def __init__(self, cells, missing=()):
        self.cells, self.missing = cells, set(missing)

    def register(self, name, pipes, index=0):
        if name in self.missing:
            raise KeyError(name)
        return self.cells[(name, index)]

    def must_get(self, name, pipes, key):
        if name in self.missing:
            raise KeyError(name)
        return {'n_Ingress.work.work.generation': [7, 0], 'n_Ingress.work.work.phase': [4, 4]}


def test_n_state_reads_work_cell_owner_and_counts_per_pipe():
    cells = {('p0.n_Ingress.%s' % n, 0): [i, 0] for i, n in enumerate(sc.N_STATE)}
    cells.update({('p0.n_Ingress.count_first', i): [10 + i, 0] for i in range(4)})
    state = sc.read_n_state(StateSwitch(cells), [0, 1])
    assert state['work'] == {'generation': [7, 0], 'phase': [4, 4]}
    assert state['owner'] == [0, 0] and state['client'] == [sc.N_STATE.index('client'), 0]   # per pipe, not summed
    assert state['count_first'] == [[10, 0], [11, 0], [12, 0], [13, 0]]


def test_n_state_records_an_unreadable_register_instead_of_failing():
    cells = {('p0.n_Ingress.%s' % n, 0): [0, 0] for n in sc.N_STATE}
    cells.update({('p0.n_Ingress.count_first', i): [0, 0] for i in range(4)})
    state = sc.read_n_state(StateSwitch(cells, missing={'p0.n_Ingress.owner', 'p0.n_Ingress.work.work'}), [0, 1])
    assert state['owner'] == 'unreadable: KeyError' and state['work'] == 'unreadable: KeyError'
    assert state['epoch'] == [0, 0]

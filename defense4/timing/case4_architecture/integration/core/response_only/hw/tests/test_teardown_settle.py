"""bringup_teardown.settle on a build without T outcomes (c68): settles on the T loop ports' sent frames."""
import importlib.util
import sys
from pathlib import Path

HW = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HW))
spec = importlib.util.spec_from_file_location('bringup_teardown', HW / 'bringup_teardown.py')
teardown = importlib.util.module_from_spec(spec)
spec.loader.exec_module(teardown)


class NoOutcomes:
    """A switch whose program has no outcomes register; each port's TX counter follows a script."""
    def __init__(self, scripts):
        self.scripts, self.calls = {port: list(values) for port, values in scripts.items()}, 0

    def register(self, name, pipe, index=0):
        raise KeyError(name)

    def get(self, table, pipe, key):
        port = key[0][1]
        values = self.scripts[port]
        value = values.pop(0) if len(values) > 1 else values[0]
        return None if value is None else {'$FramesTransmittedAll': value}


class WithOutcomes:
    def __init__(self):
        self.reads = []

    def register(self, name, pipe, index=0):
        self.reads.append((name, index))
        return [7]


def test_settles_once_every_loop_port_stops():
    sw = NoOutcomes({180: [1, 2, 3, 3], 181: [5, 9, 9], 182: [10, 10]})
    assert teardown.settle(sw, quiet=0.3, timeout=5) is True


def test_never_settles_on_an_unreadable_port():
    sw = NoOutcomes({180: [1], 181: [None], 182: [2]})
    assert teardown.settle(sw, quiet=0.3, timeout=1.0) is False


def test_does_not_settle_while_a_port_keeps_moving():
    sw = NoOutcomes({180: [1], 181: list(range(100)), 182: [2]})
    assert teardown.settle(sw, quiet=0.5, timeout=1.5) is False


def test_outcome_counters_used_when_present():
    sw = WithOutcomes()
    assert teardown.off_counts(sw) == (7, 7)
    assert sw.reads == [('p1.t_Ingress.outcomes', teardown.OFF_FLUSH), ('p1.t_Ingress.outcomes', teardown.TOKEN_OFF)]


def test_no_j_settle_ports_come_from_owned_manifest_loopbacks():
    manifest = dict(timing_contract='response_ready_ack_d_no_j_v3', installed=[
        dict(kind='loopback', label=role + ' dev ' + str(port), key=[('$DEV_PORT', port, None)])
        for role, port in [('n_ack_return', 48), ('t_in', 180), ('held_return', 182)]])
    assert teardown.settle_ports(manifest) == (180, 182)
    manifest['timing_contract'] = 'response_ready_ack_d_v2'
    assert teardown.settle_ports(manifest) == (180, 181, 182)
    manifest.pop('timing_contract')
    assert teardown.settle_ports(manifest) == (180, 181, 182)


def test_no_j_settles_without_absent_outcomes_or_unowned_hb():
    class NoJ(NoOutcomes):
        def register(self, *args):
            raise AssertionError('no-J has no outcomes register')
    sw = NoJ({180: [1, 2, 2], 182: [3, 3]})
    assert teardown.settle(sw, quiet=0.2, timeout=2.0, ports=(180, 182),
                           timing_contract='response_ready_ack_d_no_j_v3') is True


def test_partial_no_j_install_settles_only_ports_it_installed():
    manifest = dict(timing_contract='response_ready_ack_d_no_j_v3', installed=[
        dict(kind='loopback', label='t_in dev 180', key=[('$DEV_PORT', 180, None)])])
    assert teardown.settle_ports(manifest) == (180,)

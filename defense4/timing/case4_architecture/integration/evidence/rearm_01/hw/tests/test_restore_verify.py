"""restore_verify.py comparison and record logic, offline (no host contact)."""
import copy
import importlib.util
import json
from pathlib import Path

HW = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('restore_verify_test', HW / 'restore_verify.py')
rv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rv)


def snap():
    return {'program': 'case4_response_path', 'errors': {},
            'tables': {'$PORT': {'entries': [{'key': {'$DEV_PORT': {'value': 164}}, 'data': {'$PORT_UP': True}}]},
                       '$PORT_STAT': {'entries': [{'data': {'rx': 1}}]},
                       'pipe.fwd': {'entries': [{'key': {'k': 1}, 'action': 'route'}]}}}


def test_identical_except_volatile_counters_passes():
    pre, post = snap(), snap()
    post['tables']['$PORT_STAT']['entries'][0]['data']['rx'] = 999
    errors, compared = rv.compare_snapshots(pre, post)
    assert errors == [] and compared == 2


def test_any_changed_port_or_table_or_program_fails():
    for mutate in (lambda s: s['tables']['$PORT']['entries'][0]['data'].update({'$PORT_UP': False}),
                   lambda s: s['tables']['pipe.fwd']['entries'].append({'key': {'k': 2}}),
                   lambda s: s['tables'].pop('pipe.fwd'),
                   lambda s: s.update(program='response_only'),
                   lambda s: s.update(errors={'pipe.fwd': 'read failed'})):
        post = snap()
        mutate(post)
        assert rv.compare_snapshots(snap(), post)[0]


def counter_snap():
    s = snap()
    s['tables']['pipe.Egress.outcome'] = {'entries': [
        {'key': {'$COUNTER_INDEX': {'value': 0}}, 'data': {'$COUNTER_SPEC_PKTS': 0, 'action_name': None}}]}
    s['tables']['tm.counter.ig_port'] = {'entries': [
        {'key': {'dev_port': {'value': 9}}, 'data': {'drop_count_packets': 0, 'usage_cells': 0, 'watermark_cells': 0,
                                                      'action_name': None, 'is_default_entry': False}}]}
    return s


def test_counter_statistics_reset_by_the_cold_swap_do_not_fail():
    """A cold swap zeroes packet, drop and occupancy statistics; a pre-run snapshot taken after hours of
    background traffic holds nonzero ones (dev_m11_09_20261019_01 pilot, 2026-10-19)."""
    pre, post = counter_snap(), counter_snap()
    pre['tables']['pipe.Egress.outcome']['entries'][0]['data']['$COUNTER_SPEC_PKTS'] = 4416
    pre['tables']['tm.counter.ig_port']['entries'][0]['data'].update(drop_count_packets=3, watermark_cells=7)
    errors, compared = rv.compare_snapshots(pre, post)
    assert errors == [] and compared == 4


def test_counter_tables_still_fail_on_any_non_statistic_difference():
    for mutate in (lambda s: s['tables']['tm.counter.ig_port']['entries'][0]['key']['dev_port'].update(value=10),
                   lambda s: s['tables']['pipe.Egress.outcome']['entries'].append(
                       {'key': {'$COUNTER_INDEX': {'value': 1}}, 'data': {'$COUNTER_SPEC_PKTS': 0}}),
                   lambda s: s['tables']['tm.counter.ig_port']['entries'][0]['data'].update(is_default_entry=True),
                   lambda s: s['tables']['pipe.Egress.outcome']['entries'][0]['data'].update(action_name='x')):
        post = counter_snap()
        mutate(post)
        assert rv.compare_snapshots(counter_snap(), post)[0]


def test_statistic_names_are_not_stripped_from_configuration_fields():
    pre, post = snap(), snap()
    post['tables']['pipe.fwd']['entries'][0]['data'] = {'usage_limit': 5}
    assert rv.compare_snapshots(pre, post)[0]


def test_runner_record_is_found_and_failed_or_missing_steps_are_reported(tmp_path):
    steps = [{'step': s, 'rc': 0, 'ok': True} for s in rv.REQUIRED_STEPS]
    (tmp_path / 'series_run.json').write_text(json.dumps({'restore': steps}))
    path, record = rv.run_record(tmp_path)
    assert path.name == 'series_run.json' and len(record['restore']) == 4
    assert rv.run_record(tmp_path / 'absent') == (None, None)


def test_rx_coalescing_must_equal_the_recorded_baseline():
    base = {'adaptive_rx': 'on', 'rx_usecs': 50}
    text = 'Coalesce parameters for x:\nAdaptive RX: %s  TX: on\n\nrx-usecs:\t%d\n'
    assert rv.rx_coalesce_failures(text % ('on', 50), base) == []
    assert rv.rx_coalesce_failures(text % ('off', 0), base)
    assert rv.rx_coalesce_failures(text % ('on', 0), base)
    assert rv.rx_coalesce_failures('', base)
    recorded = __import__('json').loads(rv.RX_COALESCE_BASELINE.read_text())
    assert (recorded['adaptive_rx'], recorded['rx_usecs']) == ('on', 50)


def test_cpu_latency_must_equal_the_baseline_with_no_helper():
    base = {'value': 2000000000}
    assert rv.cpu_latency_failures('value 2000000000 helpers 0\n', base) == []
    assert rv.cpu_latency_failures('value 0 helpers 1\n', base)
    assert rv.cpu_latency_failures('value 2000000000 helpers 1\n', base)
    assert rv.cpu_latency_failures('value 0 helpers 0\n', base)
    assert rv.cpu_latency_failures('', base)
    assert __import__('json').loads(rv.CPU_LATENCY_BASELINE.read_text())['value'] == 2000000000


def test_cpu_latency_probe_counts_holders_not_its_own_parents(tmp_path):
    """The probe under a parent shell whose command line carries the probe text: no false helper; a process holding
    the device open is a helper (a regular file stands in for /dev/cpu_dma_latency)."""
    import shlex
    import struct
    import subprocess
    import sys
    import time
    device = tmp_path / 'cpu_dma_latency'
    device.write_bytes(struct.pack('i', 2000000000))
    probe = rv.cpu_latency_probe(str(device))
    run = lambda: subprocess.run(['sh', '-c', '%s -c %s; true' % (sys.executable, shlex.quote(probe))],
                                 stdout=subprocess.PIPE, text=True).stdout
    assert rv.cpu_latency_failures(run(), {'value': 2000000000}) == []
    holder = subprocess.Popen([sys.executable, '-c', 'import time; f = open(%r, "rb"); time.sleep(30)' % str(device)])
    try:
        time.sleep(0.5)
        assert rv.cpu_latency_failures(run(), {'value': 2000000000}) == ['Vision /dev/cpu_dma_latency is still held open by a process']
    finally:
        holder.kill()

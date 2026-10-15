"""m5_summary contention gate: zero busy drops, exhaustion and stale retries; missing counters fail."""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE / 'analysis'))
import m5_summary as ms  # noqa: E402


def snaps(tmp_path, before, after, label='t'):
    d = tmp_path / 'snapshots'
    d.mkdir()
    for side, value in (('before', before), ('after', after)):
        (d / ('%s_%s.json' % (label, side))).write_text(json.dumps({'n_counters': value}))
    return d


def test_clean_trial_passes_and_reports_retries(tmp_path):
    b = {'count_busy': [0] * 8, 'count_term': [0] * 4}
    a = {'count_busy': [0, 3, 5, 0, 0, 0, 0, 0], 'count_term': [1, 0, 0, 0]}
    g = ms.contention_gate(ms.counter_delta(snaps(tmp_path, b, a), 't'))
    assert g['ok'] and g['retry_laps'] == 5 and g['retried_duplicates_aborted'] == 1


def test_busy_drop_exhaustion_or_stale_fail(tmp_path):
    for index in (0, 3, 4):
        busy = [0] * 8
        busy[index] = 1
        d = tmp_path / str(index)
        d.mkdir()
        g = ms.contention_gate(ms.counter_delta(snaps(d, {'count_busy': [0] * 8, 'count_term': [0] * 4},
                                                      {'count_busy': busy, 'count_term': [0] * 4}), 't'))
        assert not g['ok'] and g['failures'] == ['%s 1' % ms.GATED[index]]


def test_missing_counters_fail_and_absent_cells_fail(tmp_path):
    assert not ms.contention_gate(None)['ok']
    b = {'count_busy': [0, 0, 0, 0, None, None, None, None], 'count_term': [0] * 4}
    g = ms.contention_gate(ms.counter_delta(snaps(tmp_path, b, b), 't'))
    assert not g['ok'] and g['failures'] == ['stale_retry None']

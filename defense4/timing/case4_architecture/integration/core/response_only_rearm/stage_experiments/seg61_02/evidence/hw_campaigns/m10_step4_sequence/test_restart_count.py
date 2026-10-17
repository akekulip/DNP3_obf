"""restart_count.py: exercised only on a positive delta; missing evidence is unknown, never not exercised."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import restart_count as rc  # noqa: E402


def trial(root, name, before, after):
    d = root / name / 'snapshots'
    d.mkdir(parents=True)
    for tag, value in (('before', before), ('after', after)):
        if value is not None:
            (d / ('%s_%s.json' % (name, tag))).write_text(json.dumps({'n_counters': {'count_busy': value}}))


def test_positive_delta_is_exercised(tmp_path):
    trial(tmp_path, 't0', [0] * 8, [0, 0, 0, 0, 0, 2, 0, 0])
    assert rc.coverage(tmp_path)['restart_path'] == 'exercised'


def test_zero_delta_everywhere_is_not_exercised(tmp_path):
    trial(tmp_path, 't0', [0] * 8, [1, 0, 3, 0, 0, 0, 0, 0])
    assert rc.coverage(tmp_path)['restart_path'] == 'not exercised'


def test_missing_after_snapshot_or_cell_is_unknown(tmp_path):
    trial(tmp_path, 't0', [0] * 8, None)
    assert rc.coverage(tmp_path)['restart_path'] == 'unknown'
    trial(tmp_path, 't1', [0] * 4, [0] * 4)
    assert rc.coverage(tmp_path)['restart_path'] == 'unknown'


def test_no_trials_is_unknown(tmp_path):
    assert rc.coverage(tmp_path)['restart_path'] == 'unknown'

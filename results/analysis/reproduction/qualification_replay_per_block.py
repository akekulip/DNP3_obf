"""Diagnostic only: replay each qualification block with the frozen replay code, unmodified."""
import json
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from scripts.checks import replay  # noqa: E402
INDEX = ROOT / 'results/hardware/rc01_hw_c72_20261027_02_index.json'   # records the run's checkout root
steps = replay.matrix(ROOT / 'results/hardware/campaigns/rc01_hw_c72_20261027_02/manifest.json',
                      Path(replay.read(INDEX)['repository_root']))['steps']
out = {}
for step in steps:
    engine = replay.owner(step)
    count, error = 0, None
    try:
        for unit in engine.units():
            source = Path(step['run_root']) / unit['fixture'] / unit['arm']['name'] / engine.label(unit)
            count += replay.replay_trial(engine, unit, source)
    except Exception as exc:
        error = '%s: %s' % (type(exc).__name__, str(exc)[-160:])
    out[step['id']] = dict(expected=step['expected_exchanges'], replayed=count if error is None else None, error=error)
print(json.dumps(out, indent=1))

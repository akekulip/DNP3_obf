"""Diagnostic only: would blocks 06-08 reproduce if the endpoint came from scenario.json?"""
import json
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from scripts.checks import replay  # noqa: E402
INDEX = ROOT / 'results/hardware/rc01_hw_c72_20261027_02_index.json'   # records the run's checkout root
frozen_read = replay.read
def read(path):
    path = Path(path)
    if path.name == 'result.json' and not path.exists() and (path.parent / 'scenario.json').exists():
        return frozen_read(path.parent / 'scenario.json')
    return frozen_read(path)
replay.read = read
out = {}
steps = replay.matrix(ROOT / 'results/hardware/campaigns/rc01_hw_c72_20261027_02/manifest.json',
                      Path(replay.read(INDEX)['repository_root']))['steps']
for step in steps:
    if not step['id'].startswith(('06', '07', '08')):
        continue
    engine = replay.owner(step)
    try:
        count = sum(replay.replay_trial(engine, unit, Path(step['run_root']) / unit['fixture'] / unit['arm']['name'] /
                                        engine.label(unit)) for unit in engine.units())
        out[step['id']] = dict(expected=step['expected_exchanges'], replayed=count)
    except Exception as exc:
        out[step['id']] = dict(error='%s: %s' % (type(exc).__name__, str(exc)[-200:]))
print(json.dumps(out, indent=1))

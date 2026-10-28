"""Run a model driver and record every repository Python file it executed, with sha256 (review of af7bd434).

  CTL_CLOSURE_TARGET=driver.py CTL_CLOSURE_OUT=out/dependency_closure.json python3 record_closure.py [args]

The drivers load local modules dynamically (sys.path inserts, spec_from_file_location), so a static import list
misses some. An audit hook on 'exec' sees each module's code object as it runs; its co_filename names the source
file even when Python loaded a cached .pyc. Each file is hashed when first executed. On exit the record is written:
  {closure_version, target, target_sha256, repo, files: {repo-relative path: sha256}, outside_repo: [...]}
The record is written however the driver exits, and the driver's exit status is preserved.
"""
import atexit
import hashlib
import json
import os
import runpy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

CLOSURE_VERSION = 'dependency-closure-v1-20261017'
REPO = Path(os.environ.get('CTL_CLOSURE_REPO') or ROOT)


def _sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    target = Path(os.environ['CTL_CLOSURE_TARGET']).resolve()
    out = Path(os.environ['CTL_CLOSURE_OUT'])
    files, outside = {}, set()

    def note(filename):
        if not filename or filename.startswith('<'):
            return
        path = Path(filename).resolve()
        if not path.is_file():
            return
        try:
            rel = str(path.relative_to(REPO))
        except ValueError:
            outside.add(str(path))
            return
        if rel not in files:
            files[rel] = _sha(path)

    def hook(event, args):
        if event == 'exec' and args and hasattr(args[0], 'co_filename'):
            note(args[0].co_filename)

    def write():
        for module in list(sys.modules.values()):
            note(getattr(module, '__file__', None))
        # These small data inputs define the independent packet expectations and
        # action-observation semantics. Python's exec audit cannot see JSON reads.
        for directory in (ROOT / 'scripts/model', ROOT / 'tests/fixtures/vectors'):
            for path in directory.glob('*.json'):
                note(str(path))
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(dict(
            closure_version=CLOSURE_VERSION, target=str(target.relative_to(REPO)), target_sha256=_sha(target),
            repo=str(REPO), files=dict(sorted(files.items())),
            outside_repo=sorted(x for x in outside if '/site-packages/' not in x and '/lib/python' not in x)),
            indent=1) + '\n')

    note(str(target))
    sys.addaudithook(hook)
    atexit.register(write)
    sys.argv = [str(target)] + sys.argv[1:]
    sys.path[0] = str(target.parent)          # as 'python3 target' would set it
    runpy.run_path(str(target), run_name='__main__')


if __name__ == '__main__':
    main()

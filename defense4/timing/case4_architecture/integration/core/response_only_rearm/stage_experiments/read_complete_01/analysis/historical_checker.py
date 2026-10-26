"""Load a recorded relay checker for offline evidence reproduction only.

The live checker deliberately has a different output contract. Historical helpers
and fields remain here through pinned Git source, never through the live import.
"""
import builtins
from pathlib import Path
import subprocess
import types

ARCH = Path(__file__).resolve().parents[6]
CHECKER_DIR = ARCH / 'protocol/hw_vepa'
REPO = ARCH.parents[2]
CHECKER_REL = 'defense4/timing/case4_architecture/protocol/hw_vepa'
REVISIONS = ('a4ebbecbe', '789092c2d')


def _source(revision, name):
    result = subprocess.run(['git', '-C', str(REPO), 'show', '%s:%s/%s.py' %
                             (revision, CHECKER_REL, name)], capture_output=True, check=False)
    if result.returncode:
        raise ValueError('historical checker source unavailable at %s; use a pinned worktree: %s' %
                         (revision, result.stderr.decode().strip()))
    return result.stdout


def load_checker(revision):
    """Return a private module after checking both local imports against pinned bytes."""
    if revision not in REVISIONS:
        raise ValueError('unsupported historical checker revision: ' + str(revision))
    dependencies = {}
    for name in ('wire_check', 'endpoint_profiles'):
        source = _source(revision, name)
        path = CHECKER_DIR / (name + '.py')
        if not path.is_file() or path.read_bytes() != source:
            raise ValueError('%s differs from %s; use a pinned worktree for historical replay' % (path, revision))
        module = types.ModuleType('_historical_%s_%s' % (revision, name))
        module.__file__ = str(path)
        exec(compile(source, str(path), 'exec'), module.__dict__)
        dependencies[name] = module

    def historical_import(name, globals=None, locals=None, fromlist=(), level=0):
        if not level and name in dependencies:
            return dependencies[name]
        return builtins.__import__(name, globals, locals, fromlist, level)

    module = types.ModuleType('_historical_%s_relay_check' % revision)
    module.__file__ = '%s:%s/relay_check.py' % (revision, CHECKER_REL)
    module.__dict__['__builtins__'] = dict(vars(builtins), __import__=historical_import)
    exec(compile(_source(revision, 'relay_check'), module.__file__, 'exec'), module.__dict__)
    module.source_revision = revision
    return module

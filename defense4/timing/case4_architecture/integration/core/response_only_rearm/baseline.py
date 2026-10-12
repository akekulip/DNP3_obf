"""Load frozen response-only generators under private module names."""
import importlib.util
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
BASE = HERE.parent / 'response_only'
INTEG = HERE.parent.parent
sys.path.insert(0, str(BASE))


def load(name):
    spec = importlib.util.spec_from_file_location('rearm_base_' + name, BASE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


n = load('make_n')
e = load('make_e')
composition = load('compose')
cp = load('cp')
ports = load('port_map')
# The baseline composition imports its siblings using public names. Keep those
# aliases out of the candidate namespace; candidate imports must resolve here.
for _name in ('make_n', 'make_e'):
    _module = sys.modules.get(_name)
    if _module and Path(_module.__file__).resolve().parent == BASE:
        sys.modules.pop(_name)
sys.path.remove(str(BASE))
sys.path.insert(0, str(HERE))

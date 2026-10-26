"""Software expected_identity / build_standards_artifact unchanged by the SEL-751 split (e1c16ecbc vs working tree)."""
import importlib.util, json, sys, copy, glob
from pathlib import Path
NEW = Path('/home/philip/Projects/DNP3/defense4/timing/case4_architecture/protocol/hw_vepa')
OLD = Path(sys.argv[1]) / 'defense4/timing/case4_architecture/protocol/hw_vepa'
def load(d, name):
    sys.path.insert(0, str(d))
    for m in ('capture_boundary', 'read_classes', 'standards', 'hold_check', 'wire_check'):
        sys.modules.pop(m, None)
    spec = importlib.util.spec_from_file_location(name, d / 'standards.py')
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    sys.path.remove(str(d))
    return mod
old, new = load(OLD, 'std_old'), load(NEW, 'std_new')
sys.path.insert(0, str(NEW / 'tests')); sys.path.insert(0, str(NEW))
import test_standards_validator as tsv
import tempfile
results = []
def compare(ctx, label):
    def run(mod):
        try:
            return json.dumps(mod.expected_identity(copy.deepcopy(ctx)), default=str)
        except Exception as e:
            return 'EXC %s: %s' % (type(e).__name__, e)
    a, b = run(old), run(new)
    results.append((label, a == b, a[:80]))
for padding in (0, 1):
    for image_len in (58, 61, 49):
        for unbound in (False, True):
            tmp = Path(tempfile.mkdtemp())
            ctx = tsv.base_context(tmp, padding=padding, image_len=image_len)[0] if isinstance(tsv.base_context(tmp, padding=padding, image_len=image_len), tuple) else tsv.base_context(tmp, padding=padding, image_len=image_len)
            ctx['unbound_native'] = unbound
            compare(ctx, 'base p%d L%d u%d' % (padding, image_len, unbound))
RC = Path('/home/philip/Projects/DNP3/defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/read_complete_01/hw/config')
for cfgp in sorted(RC.glob('*.json')):
    cfg = json.loads(cfgp.read_text())
    if cfg.get('endpoint_profile', 'software') != 'software':
        continue
    for arm in cfg.get('arms', []):
        ctx = {'config': cfg, 'arm': arm, 'trial': {'label': 't', 'reads': 4}, 'run_record': {'run_id': 'r'},
               'checker_files': [], 'connection_id': 'primary', 'candidate_source_sha256': 'a'*64}
        compare(ctx, cfgp.name + ':' + arm['name'])
bad = [r for r in results if not r[1]]
print('compared', len(results), 'contexts; differing', len(bad))
for r in bad[:10]: print(r)
print('exceptions (identical in both):', sum(r[2].startswith('EXC') for r in results))

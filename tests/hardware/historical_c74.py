"""The freeze gate as it stood while c74 was canonical, for tests of the retained c74 confirmation definitions.

Since c75 became canonical, c74 and c74_diag_mirror are no longer admitted: c74_diag_mirror's identity binds the c74
canonical source and the generator at C74_GENERATOR_COMMIT. use_c74_context() points the gate's canonical source at
results/builds/c74 and its generator at that exact generator (sha256-checked against the identity), so a test can still
prepare and freeze the c74 definitions exactly as before. Nothing in the repository is written."""
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
C74_DIAG = ROOT / 'results/builds/c74_diag_mirror'
C74_SOURCE = 'results/builds/c74/response_only.p4'
C74_GENERATOR_COMMIT = 'bffcf6339'      # "Make c74 the canonical candidate and add its diagnostic mirror build"


def use_c74_context(monkeypatch, tmp_dir):
    import freeze_gate
    generator = subprocess.run(['git', '-C', str(ROOT), 'show', C74_GENERATOR_COMMIT + ':scripts/build_diag_mirror.py'],
                               capture_output=True, check=True).stdout
    recorded = json.loads((C74_DIAG / 'diag_mirror.json').read_text())['generator_sha256']
    if hashlib.sha256(generator).hexdigest() != recorded:
        raise AssertionError('the c74 generator at %s is not the one c74_diag_mirror records' % C74_GENERATOR_COMMIT)
    path = Path(tmp_dir) / 'build_diag_mirror_c74.py'
    path.write_bytes(generator)
    monkeypatch.setattr(freeze_gate, 'CANONICAL_P4', C74_SOURCE)
    monkeypatch.setattr(freeze_gate, 'DIAG_GENERATOR', str(path))
    return path

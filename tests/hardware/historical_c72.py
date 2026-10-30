"""The freeze gate as it stood while c72 was canonical, for tests of the retained c72 diagnostic definitions.

Since c74 became canonical, c72_diag_mirror is no longer admitted: its identity binds the c72 canonical source and the
generator at C72_GENERATOR_COMMIT. use_c72_context() points the gate's canonical source at results/builds/c72 and its
generator at that exact generator (sha256-checked against the identity), so a test can still prepare and freeze the
c72 diagnostic definitions exactly as before. Nothing in the repository is written."""
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
C72_DIAG = ROOT / 'results/builds/c72_diag_mirror'
C72_SOURCE = 'results/builds/c72/response_only.p4'
C72_GENERATOR_COMMIT = 'c78363905'      # "Add the c72_diag_mirror diagnostic build and its model evidence"


def use_c72_context(monkeypatch, tmp_dir):
    import freeze_gate
    generator = subprocess.run(['git', '-C', str(ROOT), 'show', C72_GENERATOR_COMMIT + ':scripts/build_diag_mirror.py'],
                               capture_output=True, check=True).stdout
    recorded = json.loads((C72_DIAG / 'diag_mirror.json').read_text())['generator_sha256']
    if hashlib.sha256(generator).hexdigest() != recorded:
        raise AssertionError('the c72 generator at %s is not the one c72_diag_mirror records' % C72_GENERATOR_COMMIT)
    path = Path(tmp_dir) / 'build_diag_mirror_c72.py'
    path.write_bytes(generator)
    monkeypatch.setattr(freeze_gate, 'CANONICAL_P4', C72_SOURCE)
    monkeypatch.setattr(freeze_gate, 'DIAG_GENERATOR', str(path))
    return path

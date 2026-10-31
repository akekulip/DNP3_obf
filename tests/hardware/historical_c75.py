"""The freeze gate as it stood while c75 was the source selected for testing, for tests of the retained c75 definitions.

Since c72 was restored as the build, c75 and c75_diag_mirror are no longer admitted: c75_diag_mirror's identity binds
the c75 canonical source and the generator at C75_GENERATOR_COMMIT. use_c75_context() points the gate's canonical
source at results/builds/c75 and its generator at that exact generator (sha256-checked against the identity), so a test
can still prepare and freeze the c75 definitions exactly as before. Nothing in the repository is written."""
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
C75_DIAG = ROOT / 'results/builds/c75_diag_mirror'
C75_SOURCE = 'results/builds/c75/response_only.p4'
C75_GENERATOR_COMMIT = '434c7cf72'      # "Select c75 for hardware testing and add its diagnostic mirror build ..."


def use_c75_context(monkeypatch, tmp_dir):
    import freeze_gate
    generator = subprocess.run(['git', '-C', str(ROOT), 'show', C75_GENERATOR_COMMIT + ':scripts/build_diag_mirror.py'],
                               capture_output=True, check=True).stdout
    recorded = json.loads((C75_DIAG / 'diag_mirror.json').read_text())['generator_sha256']
    if hashlib.sha256(generator).hexdigest() != recorded:
        raise AssertionError('the c75 generator at %s is not the one c75_diag_mirror records' % C75_GENERATOR_COMMIT)
    path = Path(tmp_dir) / 'build_diag_mirror_c75.py'
    path.write_bytes(generator)
    monkeypatch.setattr(freeze_gate, 'CANONICAL_P4', C75_SOURCE)
    monkeypatch.setattr(freeze_gate, 'DIAG_GENERATOR', str(path))
    return path

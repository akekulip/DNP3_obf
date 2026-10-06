import importlib.util
from pathlib import Path
import pytest

SCRIPT = Path(__file__).parents[1] / 'recovery.py'

def module():
    spec = importlib.util.spec_from_file_location('recovery', SCRIPT)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_archive_restores_identical_bytes_and_checks_conflicting_target(tmp_path):
    m = module()
    src = tmp_path / 'source'; src.mkdir()
    payload = src / 'model.pkl'; payload.write_bytes(bytes(range(256)) * 100)
    archive = tmp_path / 'archive'; archive.mkdir()
    entry = m.pack(src, Path('model.pkl'), archive)
    target = tmp_path / 'restored'
    m.restore_entry(entry, archive, target)
    assert (target / 'model.pkl').read_bytes() == payload.read_bytes()
    (target / 'model.pkl').write_bytes(b'different')
    with pytest.raises(ValueError, match='conflict'):
        m.restore_entry(entry, archive, target)
    assert (target / 'model.pkl').read_bytes() == b'different'


def test_corrupt_archive_never_writes_target(tmp_path):
    m = module(); src = tmp_path / 'source'; src.mkdir()
    (src / 'input').write_bytes(b'evidence' * 100)
    archive = tmp_path / 'archive'; archive.mkdir()
    entry = m.pack(src, Path('input'), archive)
    (archive / entry['archive']).write_bytes(b'corrupt')
    with pytest.raises(ValueError, match='archive'):
        m.restore_entry(entry, archive, tmp_path / 'restored')
    assert not (tmp_path / 'restored/input').exists()


def test_manifest_path_escape_rejected(tmp_path):
    m = module()
    with pytest.raises(ValueError, match='path'):
        m.restore_entry({'path': '../outside', 'archive': '../outside'}, tmp_path, tmp_path/'dest')

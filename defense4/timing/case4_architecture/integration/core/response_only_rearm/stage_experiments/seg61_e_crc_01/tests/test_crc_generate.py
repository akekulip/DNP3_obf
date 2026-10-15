"""seg61_e_crc_01: the generator reproduces the retained experiment source, preserves N/T, and its table constants
agree with the independent CRC probe."""
import hashlib
import importlib.util
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_generator_reproduces_the_retained_source_and_preserves_n_and_t(tmp_path):
    gen = load('crc_generate', HERE / 'generate.py')
    gen.write(tmp_path / 'out')
    text = (tmp_path / 'out/response_only.p4').read_text()
    assert hashlib.sha256(text.encode()).hexdigest() == \
        hashlib.sha256((HERE / 'evidence/full_01/response_only.p4').read_bytes()).hexdigest()
    base = gen.frozen()
    for role in ('N', 'T'):
        assert gen.combined.segment(text, role) == gen.combined.segment(base, role)


def test_table_constants_match_the_probe():
    gen = load('crc_generate2', HERE / 'generate.py')
    probe = gen.probe
    text = (HERE / 'evidence/full_01/response_only.p4').read_text()
    rows = re.findall(r'8w(\d+):ctl_sequences\(8w(\d+),8w(\d+),16w0x([0-9a-f]{4}),16w0x([0-9a-f]{4})\)', text)
    assert len(rows) == 64
    zero7 = probe.crc(bytes(7))
    for key, th2, th3, delta, crc3 in rows:
        th2, th3 = int(th2), int(th3)
        assert int(delta, 16) == gen.le(probe.crc(bytes([th2]) + bytes(6)) ^ zero7)
        assert int(crc3, 16) == gen.le(probe.crc(bytes([th3, 0])))

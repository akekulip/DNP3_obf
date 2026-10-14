import hashlib
import importlib.util
import json
import random
import re
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent


def load_generator():
    spec = importlib.util.spec_from_file_location('seg61_02_generate', HERE / 'generate.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gen = load_generator()


HEADER_BYTES = {
    'dl': 10,
    'rh': 5,
    'robj': 5,
    'ra': 5,
    'p03': 4,
    'p45': 2,
    'c0': 2,
    'ca': 2,
    'rbh': 5,
    'p69': 4,
    'p1012': 3,
    'rc': 7,
    'cb': 2,
    'p1321': 9,
    'c1': 2,
    'p22': 1,
    'c2': 2,
    'cb0': 18,
    'ctn': 9,
    'cd2': 10,
    'cs2': 9,
    'cd3': 10,
    'cs3': 4,
}

EMIT_RE = re.compile(r'pkt\.emit\(hdr\.([a-z0-9_]+)\)')
FIELD_RE = re.compile(r'(?:hdr|m)\.([A-Za-z0-9_.]+)|\b(\d+)w0x[0-9a-fA-F]+|\b(8w0)\b')


def emitted_headers(egress_source):
    start = egress_source.index('pkt.emit(hdr.prov);')
    end = egress_source.index('\n    }\n}\n', start)
    return [name for name in EMIT_RE.findall(egress_source[start:end])
            if name not in {'prov', 'eth', 'ip', 'tcp', 'mss'}]


def emitted_len(valid_headers):
    return sum(HEADER_BYTES[name] for name in valid_headers)


def update_fields(egress_source, extern):
    start = egress_source.index(extern + '.update({')
    start = egress_source.index('{', start) + 1
    end = egress_source.index('});', start)
    return [match.group(1) or match.group(2) or match.group(3)
            for match in FIELD_RE.finditer(egress_source[start:end])]


def field_header(field):
    return field.split('.', 1)[0]


def payload_fields(fields):
    return [f for f in fields if f.startswith(('dl.', 'rh.', 'robj.', 'ra.', 'p03.', 'p45.', 'c0.',
                                                'ca.', 'rbh.', 'p69.', 'p1012.', 'rc.', 'cb.',
                                                'p1321.', 'c1.', 'p22.', 'c2.', 'cb0.', 'ctn.',
                                                'cd2.', 'cs2.', 'cd3.', 'cs3.')) or f == '8w0']


def projected_headers(fields, valid_headers):
    seen = []
    for field in payload_fields(fields):
        if field == '8w0':
            seen.append(field)
            continue
        header = field_header(field)
        if header in valid_headers and header not in seen:
            seen.append(header)
    return seen


def headers_between_pads(fields, valid_headers, start_header=None):
    chunks = []
    current = []
    for field in payload_fields(fields):
        if field == '8w0':
            chunks.append(current)
            current = []
            continue
        header = field_header(field)
        if header in valid_headers and header not in current:
            current.append(header)
    if current:
        chunks.append(current)
    if start_header is None:
        return chunks[0]
    for chunk in chunks:
        if chunk and chunk[0] == start_header:
            return chunk
    return []


NATIVE_READ_HEADERS = ['dl', 'rh', 'robj', 'p03', 'p45', 'c0', 'p69', 'p1012', 'p1321', 'c1', 'p22', 'c2']
NATIVE_CTL_HEADERS = ['dl', 'cb0', 'ctn']
PADDED_READ_HEADERS = ['dl', 'rh', 'ra', 'p03', 'p45', 'ca', 'rbh', 'p69', 'rc', 'cb',
                       'p1012', 'p1321', 'p22', 'c2']
PADDED_CTL_HEADERS = ['dl', 'cb0', 'cd2', 'cs2', 'cd3', 'cs3']


class Seg61Source(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = gen.frozen()
        cls.source = gen.full_source()
        cls.base_e = gen.combined.segment(cls.base, 'E')
        cls.new_e = gen.combined.segment(cls.source, 'E')

    def test_strict_input_is_pinned_and_only_e_changes(self):
        self.assertEqual(hashlib.sha256(gen.SOURCE.read_bytes()).hexdigest(), gen.SOURCE_SHA256)
        self.assertEqual(gen.combined.segment(self.source, 'N'), gen.combined.segment(self.base, 'N'))
        self.assertEqual(gen.combined.segment(self.source, 'T'), gen.combined.segment(self.base, 'T'))
        self.assertNotEqual(self.new_e, self.base_e)
        self.assertEqual(self.source.replace(self.new_e, self.base_e, 1), self.base)

    def test_mapper_uses_61_byte_image_and_growths(self):
        e = self.new_e
        self.assertIn('const bit<32> r_IMAGE_LEN = 61;', e)
        self.assertIn('virtual image: ISN+1-61', e)
        self.assertIn('v = hdr.tcp.seq + 32w0xFFFFFFC4;', e)
        self.assertIn('m.pm = m.p + 32w0xFFFFFFC3;', e)
        self.assertIn('hdr.ip.len=hdr.ip.len+16w12;m.len_delta=16w12;', e)
        self.assertIn('hdr.ip.len=hdr.ip.len+16w24;m.len_delta=16w24;', e)
        self.assertIn('hdr.dl.len=8w0x32', e)
        self.assertIn('hdr.dl.len=8w0x15', e)
        self.assertIn('size = 124; const default_action = rev_drop();', e)
        self.assertIn('(32w0xffffffc3, 16w61 .. 16w65535) : rev_withhold_open();', e)

    def test_emitted_header_orders_have_native_and_padded_lengths(self):
        e = self.new_e
        order = emitted_headers(e)
        self.assertEqual([h for h in order if h in NATIVE_READ_HEADERS], NATIVE_READ_HEADERS)
        self.assertEqual([h for h in order if h in NATIVE_CTL_HEADERS], NATIVE_CTL_HEADERS)
        self.assertEqual([h for h in order if h in PADDED_READ_HEADERS], PADDED_READ_HEADERS)
        self.assertEqual([h for h in order if h in PADDED_CTL_HEADERS], PADDED_CTL_HEADERS)
        self.assertEqual(emitted_len(NATIVE_READ_HEADERS), 49)
        self.assertEqual(emitted_len(NATIVE_CTL_HEADERS), 37)
        self.assertEqual(emitted_len(PADDED_READ_HEADERS), 61)
        self.assertEqual(emitted_len(PADDED_CTL_HEADERS), 61)

    def test_read_crc_inputs_match_independent_61_byte_blocks(self):
        e = self.new_e
        self.assertIn('header r_read_hdr40_h{bit<40> v;}', e)
        self.assertIn('hdr.ra.v=40w0x0a02000005;', e)
        self.assertIn('hdr.rbh.v=40w0x0a02000609;', e)
        self.assertIn('hdr.rc.v=56w0x0a02010a001600;', e)
        self.assertIn('hdr.ca.crc=hdr.c0.crc^16w0x6222;', e)
        expected_crc_inputs = {
            'hash_read_b.get': ['40w0x0a02000609', 'p69.d', '56w0x0a02010a001600'],
            'hash_read_tail.get': ['p1012.d', 'p1321.d', 'p22.d'],
        }
        for anchor, expected in expected_crc_inputs.items():
            start = e.index(anchor + '({') + len(anchor) + 2
            end = e.index('})', start)
            actual = [f'hdr.{x}' if '.' in x and not x.startswith(('hdr.', '40w', '56w')) else x
                      for x in e[start:end].split(',')]
            actual = [x.replace('hdr.', '') for x in actual]
            self.assertEqual(actual, expected)

    def test_read_first_crc_delta_preserves_randomized_native_bytes(self):
        spec = importlib.util.spec_from_file_location(
            'independent_crc', HERE.parent / 'read_reencode_01/dnp3_std.py')
        std = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(std)
        rng = random.Random(1815)
        for _ in range(1024):
            native = bytearray(rng.randrange(256) for _ in range(16))
            native[9] = 0x16
            changed = bytearray(native)
            changed[9] = 0x05
            # The P4 field stores the two wire CRC octets as a big-endian bitstring.
            old = int.from_bytes(std.crc(native).to_bytes(2, 'little'), 'big')
            new = int.from_bytes(std.crc(changed).to_bytes(2, 'little'), 'big')
            self.assertEqual(old ^ 0x6222, new)

    def test_tcp_checksum_field_order_matches_native_and_padded_payloads(self):
        e = self.new_e
        plain = update_fields(e, 'tcp_plain')
        read = update_fields(e, 'tcp_read')
        ctl = update_fields(e, 'tcp_ctl')
        self.assertEqual(headers_between_pads(plain, set(NATIVE_READ_HEADERS)), NATIVE_READ_HEADERS)
        self.assertEqual(['dl'] + headers_between_pads(plain, set(NATIVE_CTL_HEADERS), 'cb0'), NATIVE_CTL_HEADERS)
        self.assertEqual(headers_between_pads(read, set(PADDED_READ_HEADERS)), PADDED_READ_HEADERS)
        self.assertEqual(['dl'] + headers_between_pads(read, set(NATIVE_CTL_HEADERS), 'cb0'), NATIVE_CTL_HEADERS)
        self.assertEqual(headers_between_pads(ctl, set(NATIVE_READ_HEADERS)), NATIVE_READ_HEADERS)
        self.assertEqual(['dl'] + headers_between_pads(ctl, set(PADDED_CTL_HEADERS), 'cb0'), PADDED_CTL_HEADERS)
        self.assertNotIn('p612.d', '\n'.join(payload_fields(plain + read + ctl)))

    def test_control_sequence_table_covers_all_mod64_starts(self):
        e = self.new_e
        entries = dict((int(src), (int(second), int(third)))
                       for src, second, third in re.findall(
                           r'8w(\d+):ctl_sequences\(8w(\d+),8w(\d+)\);', e))
        self.assertEqual(len(entries), 64)
        self.assertEqual(sorted(entries), list(range(192, 256)))
        for seq in range(64):
            self.assertEqual(entries[192 + seq], ((seq + 1) % 64, 0x80 | ((seq + 2) % 64)))
        self.assertEqual(entries[254], (63, 128))
        self.assertEqual(entries[255], (0, 129))

    def test_write_outputs_manifest_and_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            outdir = Path(tmp) / 'full_01'
            gen.write(outdir)
            source = (outdir / 'response_only.p4').read_text()
            manifest = json.loads((outdir / 'response_only.inputs.json').read_text())
        self.assertEqual(source, self.source)
        self.assertEqual(manifest['strict_source']['sha256'], gen.SOURCE_SHA256)
        self.assertEqual(manifest['changed_role'], 'E')
        self.assertEqual(manifest['image_len'], 61)
        self.assertEqual(manifest['read_growth'], 12)
        self.assertEqual(manifest['control_growth'], 24)
        self.assertEqual(manifest['segment_sha256']['N'], hashlib.sha256(gen.combined.segment(self.base, 'N').encode()).hexdigest())
        self.assertEqual(manifest['segment_sha256']['T'], hashlib.sha256(gen.combined.segment(self.base, 'T').encode()).hexdigest())


if __name__ == '__main__':
    unittest.main()

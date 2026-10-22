"""N (pipe-0 ingress) classification of the two segments of the 377 READ response (make_m12.py
--segmented-full), on the repository P4 source interpreter. Adapts the admit() driver of
test_n_read_shapes to the two-frame segmented native produced by derive.segmented_sample.

What this validates (source-interpreter tier):
 - seg0 (ip.len 332, dl.len 0xff): parsed as a READ response (kind 11), first block CRC valid, the ordinary
   response profile marks it eligible, the network table accepts it, next_seq_t advances by 292.
 - seg1 (ip.len 125, dl.len 0x46): parsed as a READ response (kind 11), first block CRC valid, the
   continuation table (seg1_admit_t) marks it eligible, next_seq_t advances by 85.
 - child_tag_t rewrites the handoff event to 0x0b01 (tev.stage 1) for seg1 and leaves 0x0b00 for seg0.

Explicit BOUND: seg1 carries no application header (its block 0 is mid-stream object data), so N's
per-response application-sequence match (read_app_t) cannot validate it as an independent response -- seg1 is
a continuation of seg0's already-validated transaction. Whether the two frames commit as ONE transaction and
release in order is a property of T's two-child hold/release, which is NOT modelled at this tier. This test
therefore asserts PARSE + PROFILE/ELIGIBLE + block-0 CRC + network admission + sequence accounting + child
tag, and records (does not assert) the guard's go bit for seg1.

Run with the research venv (derive.py needs Python >= 3.10):
  ~/.venvs/research/bin/python -m pytest -q m12_fullsize/tests/test_segmented_classifier.py
"""
import importlib.util
import json
import re
import struct
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
STAGE = HERE.parents[1]
BASE = STAGE.parent
INTEG = BASE.parent.parent
VEC = STAGE / 'read_complete_01/vectors'

shim = types.ModuleType('baseline')
shim.INTEG = INTEG
sys.modules.setdefault('baseline', shim)


def _module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


interp = _module('segcls_interp', BASE / 'interpreter.py')
combined = _module('segcls_segments', STAGE / 'combined_nt_01/generate.py')
derive = _module('segcls_derive', VEC / 'derive.py')
gp, std = derive.gp, derive.std
GOOD = 0x993a


def generate():
    out = Path(tempfile.mkdtemp(prefix='segcls_'))
    subprocess.run([sys.executable, str(STAGE / 'm12_fullsize/make_m12.py'), str(out),
                    '--policy', '--c3', 'cimg', '--shapes', 'passthrough', '--segmented-full'],
                   check=True, capture_output=True)
    return (out / 'response_only.p4').read_text()


def role(text, name):
    prefix = {'N': 'n', 'E': 'r', 'T': 't'}[name]
    return re.sub(r'\b' + prefix + r'_(\w+)', r'\1', combined.segment(text, name))


def n_source(text):
    return interp.ExtSource(interp.source_text(role(text, 'N')).replace('p.global_tstamp', 'ig.global_tstamp'), INTEG)


def _branch(text):
    body = role(text, 'N')
    start = body.index('connection.apply();retry_epoch_t.apply();crc_t.apply();')
    return body[start:body.index('  ports.apply();', start)]


def _sum(data):
    data += bytes(len(data) & 1)
    total = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def frame(src, dst, sport, dport, seq, ack, flags, payload):
    tcp = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 0x50, flags, 4096, 0, 0)
    tcp = tcp[:16] + struct.pack('!H', _sum(src + dst + struct.pack('!BBH', 0, 6, 20 + len(payload)) + tcp + payload)) + tcp[18:]
    ip = struct.pack('!BBHHHBB', 0x45, 0, 40 + len(payload), 0, 0x4000, 64, 6) + b'\0\0' + src + dst
    ip = ip[:10] + struct.pack('!H', _sum(ip)) + ip[12:]
    return bytes.fromhex('001122334455aabbccddeeff0800') + ip + tcp + payload


class SegmentedClassifier(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = generate()
        cls.n = n_source(cls.text)

    def admit_segment(self, payload, seq):
        """Run N on one response segment; return the observable admission state."""
        n = self.n
        m_ip = int.from_bytes(bytes([192, 168, 10, 1]), 'big')      # master
        s_ip = int.from_bytes(bytes([192, 168, 10, 7]), 'big')      # outstation
        m_port, s_port = 56857, 20000
        n.begin_pass(9)
        n.controls['Ingress'].tables['connection']['runtime'].clear()
        n.controls['Ingress'].tables['read_connection']['runtime'].clear()
        n.install('connection', [m_ip, s_ip, m_port, s_port, 9], 'forward_flow', [64])
        n.install('connection', [s_ip, m_ip, s_port, m_port, 9], 'reverse_flow', [9])
        n.install('read_connection', [m_ip, s_ip, m_port, s_port], 'read_configure', [0, 0])
        n.install('read_connection', [s_ip, m_ip, s_port, m_port], 'read_configure', [0, 0])
        accepted, cursor = n.packet_parser(frame(bytes([192, 168, 10, 7]), bytes([192, 168, 10, 1]),
                                                 s_port, m_port, seq, 0x1000, 0x18, payload))
        out = {'accepted': accepted, 'kind': n.env.get('m.packet_kind'), 'parsed': n.env.get('m.parsed', 0),
               'states': list(n.parser_states)}
        if not accepted or out['parsed'] != 1:
            return out
        n.run(_branch(self.text))
        n.table('network')
        out.update({'profile': n.env.get('m.profile'), 'bcrc': n.env.get('m.bcrc'),
                    'crc1': n.env.get('m.crc1'), 'tcrc': n.env.get('m.tcrc'),
                    'network': n.env.get('m.network_valid', 0)})
        n.env['m.port_valid'] = 1
        n.table('guard')
        out['go'] = n.env.get('m.go', 0)
        n.table('next_seq_t')
        out['new_seq'] = n.env.get('m.new_seq')
        return out

    def test_both_segments_parse_and_profile(self):
        import random
        for t in range(16):
            req, native = derive.segmented_sample(random.Random(2000 + t))()
            n0, n1 = gp.split_frames(native)
            seq0 = 0x44440000 + t * 500
            g0 = self.admit_segment(n0, seq0)
            g1 = self.admit_segment(n1, (seq0 + len(n0)) & 0xffffffff)
            # seg0: ordinary response profile, block-0 CRC valid, admitted, +292
            self.assertEqual((g0['parsed'], g0['kind']), (1, 11), ('seg0 parse', t, g0))
            self.assertEqual(g0['profile'], 1, ('seg0 eligible', t, g0))
            self.assertEqual(g0['bcrc'], GOOD, ('seg0 block0 crc', t, g0))
            self.assertEqual(g0['network'], 1, ('seg0 network', t, g0))
            self.assertEqual(g0['new_seq'], (seq0 + 292) & 0xffffffff, ('seg0 seq +292', t, g0))
            # seg1: continuation admit, block-0 CRC valid, +85
            self.assertEqual((g1['parsed'], g1['kind']), (1, 11), ('seg1 parse', t, g1))
            self.assertEqual(g1['profile'], 1, ('seg1 eligible via seg1_admit_t', t, g1))
            self.assertEqual(g1['bcrc'], GOOD, ('seg1 block0 crc', t, g1))
            self.assertEqual(g1['network'], 1, ('seg1 network', t, g1))
            self.assertEqual(g1['new_seq'], ((seq0 + len(n0)) + 85) & 0xffffffff, ('seg1 seq +85', t, g1))

    def test_child_tag_table(self):
        """child_tag_t rewrites the handoff event to 0x0b01 for the seg1 continuation (dl.len 0x46) and leaves
        the seg0 / single-frame event at 0x0b00."""
        n = self.n
        for dl_len, expect in ((0xff, 0x0b00), (0x46, 0x0b01), (0x26, 0x0b00)):
            n.begin_pass(9)
            n.env['m.kind'] = 11
            n.env['hdr.event.event'] = 0x0b00
            n.valid['event'] = True
            n.env['hdr.dl.len'] = dl_len
            n.valid['dl'] = True
            n.table('child_tag_t')
            self.assertEqual(n.env.get('hdr.event.event'), expect, ('dl.len 0x%02x' % dl_len))


if __name__ == '__main__':
    unittest.main(verbosity=2)

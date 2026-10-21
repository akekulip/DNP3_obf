"""Pass-through READ classes in N (make_m12.py --policy --c3 cimg --shapes passthrough), on the repository's P4
source interpreter.

Frames: the DNP3 bytes of one real exchange per READ class, taken from the fixture endpoint's loopback capture
evidence/rearm_01/repeat_sbo_endpoint/loopback_evidence_20261021/b_rotate4_base/capture.pcap (sha256 pinned below),
with their real TCP sequence/acknowledgement numbers, ports and addresses. Loopback TCP carries the timestamp option;
the hardware workload does not (ip.len 58/60/62/67 requests, 89/181/287 responses), so each payload is re-wrapped in
an option-free IPv4/TCP header with correct checksums. That envelope is the only synthetic part.

Per class: N's parser recognises the frame (packet kind, exact header), the profile marks it eligible, the real
block-0 CRC verifies, the network row accepts it, the guard admits it (go_new), next_seq_t advances by the native
length and the application-sequence input is read from the right header. A corrupted block-0 octet (TCP checksum
recomputed so only the DNP3 CRC is wrong) is refused. The range READ path gives the same result as m12p_c04.
E (pipe-0 egress) and pipe-1 egress segments are byte-identical to m12p_c04; E is also run on the pass-through
responses (native length, no read_shape). Source-interpreter tier only: not the compiled model or hardware.
"""
import hashlib
import importlib.util
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
C04 = STAGE / 'ctl_timing_01/evidence/m12p_c04/response_only.p4'
C04_SHA = '8976816787a326512ffb6e921c5eb41011436ca94a3b52336778e3031335ece5'
CAPTURE = INTEG / 'evidence/rearm_01/repeat_sbo_endpoint/loopback_evidence_20261021/b_rotate4_base/capture.pcap'
DECODER = STAGE / 'read_complete_01/software/source/read_reencode_01'

shim = types.ModuleType('baseline')
shim.INTEG = INTEG
sys.modules.setdefault('baseline', shim)


def _module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


interp = _module('shapes_interpreter', BASE / 'interpreter.py')
combined = _module('shapes_segments', STAGE / 'combined_nt_01/generate.py')
capture = _module('shapes_capture', DECODER / 'capture.py')
std = _module('shapes_dnp3_std', DECODER / 'dnp3_std.py')

# class -> (request octets, response octets, request dl.len, response dl.len)
CLASSES = {'range': (20, 49, 0x0d, 0x26), 'analog': (22, 141, 0x0f, 0x78),
           'class0': (18, 247, 0x0b, 0xd6), 'integrity': (27, 247, 0x14, 0xd6)}
GOOD = 0x993a   # CRC residual over block||CRC that the guard requires


def generate(*flags):
    out = Path(tempfile.mkdtemp(prefix='shapes_'))
    subprocess.run([sys.executable, str(STAGE / 'm12_fullsize/make_m12.py'), str(out)] + list(flags),
                   check=True, capture_output=True)
    return (out / 'response_only.p4').read_text()


def role(text, name):
    prefix = {'N': 'n', 'E': 'r', 'T': 't'}[name]
    result = re.sub(r'\b' + prefix + r'_(\w+)', r'\1', combined.segment(text, name))
    return result + ('\nPipeline() source_adapter_marker;\n' if name == 'E' else '')


def exchanges():
    """First request/response pair of each class from the capture: (request record, response record)."""
    want = {(v[0], v[1]): k for k, v in CLASSES.items()}
    found, prev = {}, None
    for r in capture.tcp_records(CAPTURE):
        if not r['payload']:
            continue
        if r['dst'][1] == 20000:
            prev = r
            continue
        if prev is not None:
            k = want.get((len(prev['payload']), len(r['payload'])))
            if k and k not in found:
                found[k] = (prev, r)
    return found


def _sum(data):
    data += bytes(len(data) & 1)
    total = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def frame(rec, payload=None):
    """Option-free Ethernet/IPv4/TCP frame around the record's DNP3 payload, real seq/ack/ports/addresses."""
    payload = rec['payload'] if payload is None else payload
    src, sport = rec['src']
    dst, dport = rec['dst']
    tcp = struct.pack('!HHIIBBHHH', sport, dport, rec['seq'], rec['ack'], 0x50, rec['flags'], 4096, 0, 0)
    tcp = tcp[:16] + struct.pack('!H', _sum(src + dst + struct.pack('!BBH', 0, 6, 20 + len(payload)) + tcp + payload)) + tcp[18:]
    ip = struct.pack('!BBHHHBB', 0x45, 0, 40 + len(payload), 0, 0x4000, 64, 6) + b'\0\0' + src + dst
    ip = ip[:10] + struct.pack('!H', _sum(ip)) + ip[12:]
    return bytes.fromhex('001122334455aabbccddeeff0800') + ip + tcp + payload


def corrupt_block0(payload):
    b = bytearray(payload)
    b[12] ^= 0x01            # an object-header octet inside block 0 (after tp/app/func)
    return bytes(b)


def corrupt_crc0(payload):
    """Flip the first CRC octet of block 0 (the profile still matches; only the CRC check can refuse it)."""
    b = bytearray(payload)
    b[10 + min(16, payload[2] - 5)] ^= 0x01
    return bytes(b)


def corrupt_block1(payload):
    b = bytearray(payload)
    b[28] ^= 0x01            # first octet of block 1 (10 link header + 16 block 0 + 2 CRC)
    return bytes(b)


def n_source(text):
    return interp.ExtSource(interp.source_text(role(text, 'N')).replace('p.global_tstamp', 'ig.global_tstamp'), INTEG)


def _branch(text):
    """N's actual read-lane admission statements: from connection.apply() up to ports.apply()."""
    body = role(text, 'N')
    start = body.index('connection.apply();retry_epoch_t.apply();crc_t.apply();')
    return body[start:body.index('  ports.apply();', start)]


def admit(n, text, req, rsp, payload_of, which):
    """Run N on one frame (which = 'req' | 'rsp'); return the observable admission state."""
    rec = req if which == 'req' else rsp
    n.begin_pass(9)
    n.controls['Ingress'].tables['connection']['runtime'].clear()
    n.controls['Ingress'].tables['read_connection']['runtime'].clear()
    m_ip, s_ip = (int.from_bytes(req['src'][0], 'big'), int.from_bytes(req['dst'][0], 'big'))
    m_port, s_port = req['src'][1], req['dst'][1]
    n.install('connection', [m_ip, s_ip, m_port, s_port, 9], 'forward_flow', [64])
    n.install('connection', [s_ip, m_ip, s_port, m_port, 9], 'reverse_flow', [9])
    q = req['payload']
    n.install('read_connection', [m_ip, s_ip, m_port, s_port], 'read_configure',
              [int.from_bytes(q[4:6], 'big'), int.from_bytes(q[6:8], 'big')])
    n.install('read_connection', [s_ip, m_ip, s_port, m_port], 'read_configure',
              [int.from_bytes(q[6:8], 'big'), int.from_bytes(q[4:6], 'big')])
    accepted, cursor = n.packet_parser(frame(rec, payload_of(rec['payload'])))
    out = {'accepted': accepted, 'states': list(n.parser_states), 'kind': n.env.get('m.packet_kind'),
           'parsed': n.env.get('m.parsed', 0)}
    if not accepted or out['parsed'] != 1:
        return out
    n.run(_branch(text))
    n.table('network')
    out.update({'profile': n.env.get('m.profile'), 'hcrc': n.env.get('m.hcrc'), 'bcrc': n.env.get('m.bcrc'),
                'crc1': n.env.get('m.crc1'), 'tcrc': n.env.get('m.tcrc'), 'badh': n.env.get('m.badh', 0),
                'tcp_sum': n.env.get('m.tcp_sum'), 'network': n.env.get('m.network_valid', 0),
                'valid': sorted(h for h in ('rd_req', 'rd_req_an', 'rd_req_c0', 'rd_req_full', 'first', 'second', 'rd_tail')
                                if n.valid.get(h))})
    n.env['m.port_valid'] = 1
    n.table('guard')
    out.update({'go': n.env.get('m.go', 0), 'go_kind': n.env.get('m.kind')})
    n.table('read_input_t')
    n.table('next_seq_t')
    out.update({'new_seq': n.env.get('m.new_seq'), 'read_app': n.env.get('m.compare_read_app')})
    return out


class PassthroughReadShapes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = generate('--policy', '--c3', 'cimg', '--shapes', 'passthrough')
        cls.c04 = C04.read_text()
        assert hashlib.sha256(cls.c04.encode()).hexdigest() == C04_SHA
        cls.n = n_source(cls.text)
        cls.n04 = n_source(cls.c04)
        cls.ex = exchanges()

    def run_class(self, name, which, payload_of=lambda p: p, n=None, text=None):
        req, rsp = self.ex[name]
        return admit(n or self.n, text or self.text, req, rsp, payload_of, which)

    def test_capture_has_every_class(self):
        import json
        pinned = json.loads((CAPTURE.parent / 'decode.json').read_text())['capture_sha256']
        self.assertEqual(hashlib.sha256(CAPTURE.read_bytes()).hexdigest(), pinned)
        self.assertEqual(sorted(self.ex), sorted(CLASSES))
        for name, (q, r, qdl, rdl) in CLASSES.items():
            req, rsp = self.ex[name]
            self.assertEqual((len(req['payload']), req['payload'][2]), (q, qdl), name)
            self.assertEqual((len(rsp['payload']), rsp['payload'][2]), (r, rdl), name)
            std.deframe(req['payload'])
            std.deframe(rsp['payload'])      # every link CRC of the real frame is valid

    def check_admitted(self, name, which, got):
        req, rsp = self.ex[name]
        rec = req if which == 'req' else rsp
        native = CLASSES[name][0 if which == 'req' else 1]
        self.assertTrue(got['accepted'] and got['parsed'] == 1, got)
        self.assertEqual(got['kind'], 9 if which == 'req' else 11, got)
        self.assertEqual(got['profile'], 1, got)
        self.assertEqual((got['hcrc'], got['bcrc'], got['badh']), (GOOD, GOOD, 0), got)
        self.assertEqual(got['network'], 1, got)
        self.assertEqual((got['go'], got['go_kind']), (1, got['kind']), got)
        self.assertEqual(got['new_seq'], (rec['seq'] + native) & 0xFFFFFFFF, got)
        self.assertEqual(got['read_app'], rec['payload'][11] & 0x0F, got)

    def test_requests_admitted(self):
        header = {'range': 'rd_req', 'analog': 'rd_req_an', 'class0': 'rd_req_c0', 'integrity': 'rd_req_full'}
        for name in CLASSES:
            with self.subTest(name):
                got = self.run_class(name, 'req')
                self.check_admitted(name, 'req', got)
                self.assertEqual(got['valid'], [header[name]], got)

    def test_responses_admitted(self):
        for name in CLASSES:
            with self.subTest(name):
                got = self.run_class(name, 'rsp')
                self.check_admitted(name, 'rsp', got)
                self.assertEqual((got['crc1'], got['tcrc']), (GOOD, GOOD), got)
                if name == 'range':
                    self.assertEqual(got['valid'], ['first', 'rd_tail', 'second'], got)
                else:   # first block only; block-1+ CRCs derived from block 0, TCP checksum waived (documented)
                    self.assertEqual(got['valid'], ['first'], got)

    def test_corrupt_block0_refused(self):
        for name in CLASSES:
            for which in ('req', 'rsp'):
                for corrupt in (corrupt_block0, corrupt_crc0):
                    with self.subTest((name, which, corrupt.__name__)):
                        got = self.run_class(name, which, corrupt)
                        self.assertTrue(got['parsed'] == 1 and got['network'] == 1, got)   # only the DNP3 CRC is wrong
                        self.assertNotEqual(got['bcrc'], GOOD, got)
                        self.assertEqual(got['go'], 0, got)
                        if corrupt is corrupt_crc0:
                            self.assertEqual(got['profile'], 1, got)   # refused by the CRC alone

    def test_shallow_limitation_block1_not_checked(self):
        """Recorded limitation, not a desired property: a corrupted block-1 octet of a 141/247 response is
        admitted by N (only block 0 is parsed); the range response's full parse still refuses it."""
        for name in ('analog', 'class0', 'integrity'):
            self.assertEqual(self.run_class(name, 'rsp', corrupt_block1)['go'], 1, name)
        self.assertEqual(self.run_class('range', 'rsp', corrupt_block1)['go'], 0)

    def test_range_path_unchanged_vs_c04(self):
        for which in ('req', 'rsp'):
            for payload_of in (lambda p: p, corrupt_block0, corrupt_crc0) + ((corrupt_block1,) if which == 'rsp' else ()):
                ours = self.run_class('range', which, payload_of)
                theirs = self.run_class('range', which, payload_of, n=self.n04, text=self.c04)
                ours.pop('valid', None), theirs.pop('valid', None)
                self.assertEqual(ours, theirs, which)

    def test_c04_does_not_recognise_new_classes(self):
        for name in ('analog', 'class0', 'integrity'):
            for which in ('req', 'rsp'):
                got = self.run_class(name, which, n=self.n04, text=self.c04)
                self.assertNotEqual(got['parsed'], 1, (name, which, got))

    def test_length_dispatch_is_exact(self):
        """A frame at a new ip.len whose dl.len belongs to another class is left unparsed (never mis-sized)."""
        req, rsp = self.ex['analog']
        swapped = bytearray(req['payload'])
        swapped[2] = 0x0b
        got = admit(self.n, self.text, dict(req, payload=bytes(swapped)), rsp, lambda p: p, 'req')
        self.assertNotEqual(got['parsed'], 1, got)

    def test_e_and_pipe1_unchanged(self):
        for r in ('E', 'T'):
            self.assertEqual(combined.segment(self.text, r), combined.segment(self.c04, r), r)
        x = self.text[self.text.index('parser x_EgParser('):self.text.index('control x_Egress(')]
        self.assertEqual(re.findall(r'select\(hdr\.ip\.len\) \{([^}]*)\}', x), [' 16w89: ip_frag; default: accept; '])
        self.assertEqual(re.findall(r'select\(hdr\.dl\.len\) \{([^}]*)\}', x), [' 8w0x26: dl_start; default: accept; '])

    def test_e_maps_passthrough_at_native_length(self):
        e = interp.ESource(role(self.text, 'E'))
        for name in ('analog', 'class0', 'integrity'):
            rsp = self.ex[name][1]
            prov = struct.pack('!IIIBBH', 1, 0, 0, 0x0b, 0, 0)
            e.begin_pass(0)
            e.env['eg.egress_port'] = 9
            accepted, _ = e.packet_parser(prov + frame(rsp))
            self.assertTrue(accepted, name)
            e.table('leff_t')
            e.table('read_profile')
            self.assertEqual((e.env.get('m.leff'), e.env.get('m.read_shape', 0), bool(e.valid.get('robj'))),
                             (CLASSES[name][1], 0, False), name)


if __name__ == '__main__':
    unittest.main(verbosity=2)

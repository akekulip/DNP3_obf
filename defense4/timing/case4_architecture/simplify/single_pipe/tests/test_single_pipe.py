"""Source-level checks of the single-pipe candidate (no compiler, no model, no switch).

Run from case4_architecture/:  python3 -m pytest -q simplify/single_pipe/tests
"""
import re
import struct
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SP = HERE.parent
TIMING = SP.parent.parent.parent
sys.path.insert(0, str(SP))
import make_single_pipe as msp  # noqa: E402
import cp_single_pipe as cps  # noqa: E402
sys.path.insert(0, str(SP.parent.parent / 'protocol'))
import response_path_cp as rp  # noqa: E402

CAPTURE = TIMING / 'evidence' / 'campaign_v2' / 's01' / 'raw_pcaps' / 's01_b1_obfuscated.pcap'


def strip_comments(text):
    return msp.COMMENTS.sub(' ', text)


class Generation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.src, cls.meta = msp.generate()
        cls.code = strip_comments(cls.src)

    def test_committed_file_is_the_generator_output(self):
        committed = SP / 'single_pipe.p4'
        self.assertTrue(committed.exists(), 'run make_single_pipe.py single_pipe.p4')
        self.assertEqual(committed.read_text(), self.src)

    def test_one_pipeline_timing_ingress_padder_egress(self):
        self.assertEqual(self.code.count('Pipeline('), 1)
        self.assertIn('Pipeline(d_IgParser(), d_Ingress(), d_IgDeparser(), r_EgParser(), r_Egress(), r_EgDeparser()) pipe;', self.src)
        self.assertIn('Switch(pipe) main;', self.src)
        self.assertEqual(self.src.count('#include <tna.p4>'), 1)
        self.assertTrue(self.src.splitlines()[4].startswith('#define U_BOR'), 'U_BOR must precede the timing source')

    def test_prefixing_touches_no_comment_word(self):
        # the shared prefixer turned comment words into d_is / d_so; this one must not
        for word in ('is', 'so', 'that', 'the', 'channel', 'reject'):
            self.assertNotRegex(self.src, r'\b[dr]_%s\b' % word)

    def test_no_unprefixed_type_left(self):
        for name in ('headers_t', 'tcp_h', 'Ingress', 'Egress'):
            self.assertNotRegex(self.code, r'(?<![\w.])%s\b' % name)

    def test_egress_parses_only_final_departures(self):
        gates = re.findall(r'transition select\(eg\.egress_port\) \{([^}]*)\}', self.code)
        self.assertEqual(len(gates), 1)
        self.assertEqual(re.findall(r'9w(\d+): eth', gates[0]), ['9', '64'])
        self.assertIn('default: accept', gates[0])

    def test_conn_keys_on_egress_port(self):
        conn = re.search(r'table conn \{\s*key = \{([^}]*)\}', self.code)
        self.assertIn('eg.egress_port : exact', conn[1])

    def test_syn_scrub_wiring(self):
        self.assertIn('(4w10, 8w0x02 &&& 8w0x12): syn_opts', self.code)
        self.assertIn('state syn_opts { pkt.extract(hdr.sopt); transition accept; }', self.code)
        self.assertIn('(2, r_SH_SYN, true, 16w0x0204) : scrub_syn();', self.code)
        self.assertEqual(self.code.count('syn_scrub_t.apply();'), 1)
        # its own single-term deparser case, summing only fields valid on a SYN
        case = re.search(r'if \(m\.scrub == 1w1\) \{(.*?)\}', self.code, re.S)[1]
        self.assertNotRegex(case, r'hdr\.(dl|rb0|rb1|rtn|rtp|cb0|ctn|ctp1|ctp2|mss)\.')
        self.assertIn('m.residual', case)
        self.assertIn('pkt.emit(hdr.sopt);', self.code)

    def test_scrub_is_exclusive_with_every_other_checksum_case(self):
        # m.changed is set only by forward classify (dir 1) and reverse classify (dir 2, SH_ACK); padding by
        # dir 1 commit/replay. The scrub row requires dir 2 and SH_SYN, so no packet reaches two cases.
        self.assertIn('if (m.dir == 1 && (m.shape == r_SH_ACK || m.shape == r_SH_NOACK))', self.code)
        self.assertIn('else if (m.dir == 2 && m.shape == r_SH_ACK && m.mode == 1)', self.code)


class TimingIngressBypass(unittest.TestCase):
    """The padder must see each frame once: loopback holds bypass egress, final departures do not."""

    @classmethod
    def setUpClass(cls):
        cls.lines = strip_comments(msp.TIMING_SRC.read_text()).splitlines()

    def window(self, i, n=4):
        return ' '.join(self.lines[i:i + n])

    def test_every_loopback_send_bypasses_egress(self):
        sends = [i for i, l in enumerate(self.lines) if re.search(r'ucast_egress_port\s*=\s*PORT_(L|BOR_L)\b', l)]
        self.assertEqual(len(sends), 6)
        for i in sends:
            self.assertRegex(self.window(i), r'bypass_egress\s*=\s*1w1', self.lines[i])

    def test_every_final_departure_runs_egress(self):
        finals = [i for i, l in enumerate(self.lines)
                  if re.search(r'ucast_egress_port\s*=\s*(meta\.fwd_port|PORT_RELAY|PORT_VISION)\b', l)]
        self.assertGreaterEqual(len(finals), 3)
        for i in finals:
            self.assertRegex(self.window(i, 3), r'bypass_egress\s*=\s*1w0', self.lines[i])

    def test_no_other_egress_port_writer_and_no_multicast(self):
        writers = [l for l in self.lines if re.search(r'ucast_egress_port\s*=', l)]
        self.assertEqual(len(writers), 9)
        self.assertFalse(any(re.search(r'mcast_grp_[ab]\s*=', l) for l in self.lines))


def ones_sum(data):
    if len(data) % 2:
        data += b'\0'
    s = 0
    for (w,) in struct.iter_unpack('!H', data):
        s += w
        s = (s & 0xFFFF) + (s >> 16)
    return s


def oc_add(a, b):
    s = a + b
    return (s & 0xFFFF) + (s >> 16)


def words(b):
    return [w for (w,) in struct.iter_unpack('!H', b)]


class SynScrubArithmetic(unittest.TestCase):
    """The deparser formula on a real master SYN from the relay rig: residual = ~(seq + window + csum + options)
    as the parser deposits it (E's convention), new csum = ~(seq + window + new options + residual)."""

    @classmethod
    def setUpClass(cls):
        from scapy.all import PcapReader, TCP, IP
        cls.TCP, cls.IP = TCP, IP
        with PcapReader(str(CAPTURE)) as r:
            captured = next(p for p in r if TCP in p and p[TCP].flags == 'S')
        # The master's frames were captured on the master host before transmit offload filled the TCP
        # checksum (its field holds the partial pseudo-header sum); restore the value the wire carries.
        wire = captured[IP].copy()
        del wire[TCP].chksum
        cls.syn = IP(bytes(wire))

    def test_captured_syn_has_the_layout_the_parser_selects(self):
        t = self.syn[self.TCP]
        self.assertEqual(t.dataofs, 10)
        raw = bytes(t)[20:40]
        self.assertEqual(raw[:2], b'\x02\x04')            # MSS first: syn_scrub_t's key
        self.assertEqual(int(t.flags) & 0x12, 0x02)        # SYN without ACK: the parser's select

    def scrub(self, pkt):
        ip, t = pkt[self.IP], pkt[self.TCP]
        seg = bytearray(bytes(t))
        old_opts = bytes(seg[20:40])
        new_opts = old_opts[:4] + b'\x01' * 16
        seq, win, csum = bytes(seg[4:8]), bytes(seg[14:16]), t.chksum
        sub = ones_sum(seq + win + struct.pack('!H', csum) + old_opts)
        residual = (~sub) & 0xFFFF
        total = residual
        for w in words(seq + win + new_opts):
            total = oc_add(total, w)
        new_csum = (~total) & 0xFFFF
        seg[20:40] = new_opts
        seg[16:18] = struct.pack('!H', new_csum)
        return bytes(seg), ip

    def test_incremental_checksum_equals_full_recompute(self):
        seg, ip = self.scrub(self.syn)
        pseudo = struct.pack('!4s4sBBH', bytes(map(int, ip.src.split('.'))), bytes(map(int, ip.dst.split('.'))),
                             0, 6, len(seg))
        self.assertEqual(ones_sum(pseudo + seg), 0xFFFF, 'scrubbed SYN must verify')
        zeroed = seg[:16] + b'\0\0' + seg[18:]
        self.assertEqual(struct.unpack('!H', seg[16:18])[0], (~ones_sum(pseudo + zeroed)) & 0xFFFF)

    def test_scrubbed_syn_offers_mss_only(self):
        seg, ip = self.scrub(self.syn)
        t = self.TCP(seg)
        names = [o[0] for o in t.options if o[0] != 'NOP']
        self.assertEqual(names, ['MSS'])
        self.assertEqual(t.options[0][1], self.syn[self.TCP].options[0][1])   # MSS value kept


class ControlPlaneRows(unittest.TestCase):
    def setUp(self):
        self.o = rp.Endpoint('192.168.10.7', 20000, 64)
        self.m = rp.Endpoint('192.168.10.1', 54321, 9)

    def test_forward_at_master_reverse_at_relay(self):
        rows = cps.e_conn_rows(0, self.o, self.m)
        conn = {r[2]: dict(r[1]) for r in rows if r[0] == 'Egress.conn'}
        self.assertEqual(conn['Egress.fwd_conn']['eg.egress_port'], 9)
        self.assertEqual(conn['Egress.fwd_conn']['hdr.ip.src'], self.o.ip_int)
        self.assertEqual(conn['Egress.rev_conn']['eg.egress_port'], 64)
        self.assertEqual(conn['Egress.rev_conn']['hdr.ip.src'], self.m.ip_int)
        self.assertFalse([r for r in rows if r[0] == 'Ingress.forwarding'])
        self.assertEqual(len([r for r in rows if r[0] == 'Egress.odd_ip_t']), 2)

    def test_ports_match_the_generated_gate(self):
        self.assertEqual((cps.MASTER_PORT, cps.RELAY_PORT), (msp.MASTER_PORT, msp.RELAY_PORT))

    def test_shared_port_refused(self):
        with self.assertRaises(ValueError):
            cps.e_conn_rows(0, self.o, self.m, master_port=9, relay_port=9)


if __name__ == '__main__':
    unittest.main()

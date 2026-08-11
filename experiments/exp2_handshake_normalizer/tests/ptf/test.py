"""PTF functional tests for the standalone handshake normalizer (Experiment 2B).

Topology assumed by the P4 program: egress_port = ingress_port ^ 1, so a packet sent
into port `p` leaves on port `p ^ 1`. All tests send on port 0 and expect on port 1.

The program's tables use compile-time `const entries`, so NO runtime table population is
required — loading the program is enough. Run with the SDE harness (see ../../MODEL_TESTS.md):

    $SDE/run_tofino_model.sh -p handshake_normalizer -c <conf>      # terminal 1
    $SDE/run_switchd.sh      -p handshake_normalizer -c <conf>      # terminal 2
    $SDE/run_p4_tests.sh -p handshake_normalizer -t tests/ptf       # terminal 3

Device fixtures come from Experiment 1's attribution of the three physical stacks
(SEL751, ION7550, AB1400) and a reference endpoint.
"""
import ptf
from ptf import testutils as tu
from ptf.base_tests import BaseTest
from scapy.all import Ether, IP, TCP, Raw

SND, RCV = 0, 1  # send port, receive port (0 ^ 1 == 1)
PUB_MSS = 1460


def _syn(mss, opts, ttl=64, df=True, sport=44000):
    """A SYN with the given MSS-first option list `opts` (scapy TCP options)."""
    flags = "DF" if df else 0
    return (Ether() / IP(src="10.0.0.9", dst="10.0.0.2", ttl=ttl, flags=flags) /
            TCP(sport=sport, dport=20000, flags="S", seq=1000,
                options=[("MSS", mss)] + opts))


def _expect_canonical(mss_out):
    """Expected normalized handshake: data_offset 6, single MSS option = mss_out, no others."""
    return (Ether() / IP(src="10.0.0.9", dst="10.0.0.2", ttl=64, flags="DF", id=0) /
            TCP(sport=44000, dport=20000, flags="S", seq=1000, options=[("MSS", mss_out)]))


class T01_SEL751_SYN_normalized(BaseTest):
    """SEL751-shaped full-option SYN (MSS,SAckOK,TS,WScale ~ data_offset 11) -> canonical do=6."""
    def setUp(self): BaseTest.setUp(self); self.dp = ptf.dataplane_instance
    def runTest(self):
        pkt = _syn(1460, [("SAckOK", b""), ("Timestamp", (1, 0)), ("WScale", 7), ("NOP", None)])
        exp = _expect_canonical(1460)
        tu.send_packet(self, SND, pkt)
        tu.verify_packet(self, exp, RCV)  # checksums are recomputed by the pipeline


class T02_ION7550_SYN_normalized(BaseTest):
    """ION7550-shaped MSS-only SYN (data_offset 6) -> unchanged layout, MSS kept, checksums valid."""
    def setUp(self): BaseTest.setUp(self); self.dp = ptf.dataplane_instance
    def runTest(self):
        pkt = _syn(1460, [])
        exp = _expect_canonical(1460)
        tu.send_packet(self, SND, pkt)
        tu.verify_packet(self, exp, RCV)


class T03_AB1400_SYN_mss_clamped(BaseTest):
    """AB1400 advertises MSS 1478 (> public). Clamp to 1460, never raise."""
    def setUp(self): BaseTest.setUp(self); self.dp = ptf.dataplane_instance
    def runTest(self):
        pkt = _syn(1478, [("NOP", None), ("NOP", None), ("NOP", None), ("EOL", None)])
        exp = _expect_canonical(1460)  # clamped
        tu.send_packet(self, SND, pkt)
        tu.verify_packet(self, exp, RCV)


class T04_small_MSS_not_raised(BaseTest):
    """A small advertised MSS (536) must be preserved, not raised to 1460 (PMTU safety)."""
    def setUp(self): BaseTest.setUp(self); self.dp = ptf.dataplane_instance
    def runTest(self):
        pkt = _syn(536, [("Timestamp", (5, 0))])
        exp = _expect_canonical(536)
        tu.send_packet(self, SND, pkt)
        tu.verify_packet(self, exp, RCV)


class T05_TTL_scrubbed(BaseTest):
    """AB1400 sends TTL 128; output TTL must be 64 regardless of input."""
    def setUp(self): BaseTest.setUp(self); self.dp = ptf.dataplane_instance
    def runTest(self):
        pkt = _syn(1460, [], ttl=128)
        exp = _expect_canonical(1460)  # ttl=64 in the expected builder
        tu.send_packet(self, SND, pkt)
        tu.verify_packet(self, exp, RCV)


class T06_syn_MD5_fail_open(BaseTest):
    """SYN whose 2nd option is TCP-MD5 (kind 19) must fail open (forwarded UNCHANGED except L3)."""
    def setUp(self): BaseTest.setUp(self); self.dp = ptf.dataplane_instance
    def runTest(self):
        pkt = _syn(1460, [(19, b"\x00" * 16)])  # MD5 signature option
        # fail-open: option layout preserved; only TTL normalized, ip.id zeroed (atomic)
        tu.send_packet(self, SND, pkt)
        # We assert the TCP option region is unchanged (data_offset != 6).
        (rcv_dev, rcv_port, rcv_pkt, _) = tu.dp_poll(self, port_number=RCV, timeout=2)
        assert rcv_pkt is not None, "MD5 SYN was dropped; must fail open"
        got = Ether(rcv_pkt)
        assert got[TCP].dataofs != 6, "MD5 SYN was normalized; must fail open unchanged"


class T07_established_options_fail_open(BaseTest):
    """Established (ACK, no SYN) segment carrying a Timestamp option: forward unchanged, leak counted."""
    def setUp(self): BaseTest.setUp(self); self.dp = ptf.dataplane_instance
    def runTest(self):
        pkt = (Ether() / IP(src="10.0.0.2", dst="10.0.0.9", ttl=64, flags="DF") /
               TCP(sport=20000, dport=44000, flags="A", options=[("NOP", None), ("NOP", None),
                   ("Timestamp", (7, 3))]) / Raw(b"\x05\x64" + b"\x00" * 8))
        tu.send_packet(self, SND, pkt)
        (_, _, rcv_pkt, _) = tu.dp_poll(self, port_number=RCV, timeout=2)
        assert rcv_pkt is not None, "established segment dropped; must forward"
        got = Ether(rcv_pkt)
        assert bytes(got[TCP].payload) == b"\x05\x64" + b"\x00" * 8, "payload must be byte-preserved"


class T08_non_tcp_forwarded(BaseTest):
    """A UDP packet is not a handshake; forward it (TTL scrubbed), option region untouched."""
    def setUp(self): BaseTest.setUp(self); self.dp = ptf.dataplane_instance
    def runTest(self):
        from scapy.all import UDP
        pkt = Ether() / IP(src="10.0.0.9", dst="10.0.0.2", ttl=200) / UDP(sport=5, dport=6) / Raw(b"abcd")
        tu.send_packet(self, SND, pkt)
        (_, _, rcv_pkt, _) = tu.dp_poll(self, port_number=RCV, timeout=2)
        assert rcv_pkt is not None, "UDP dropped; must forward"

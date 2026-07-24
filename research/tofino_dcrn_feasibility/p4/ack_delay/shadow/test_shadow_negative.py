#!/usr/bin/env python3
"""
Phase-1 negative tests for the shadow classifier reference model (charter §G.8). Synthetic frames;
no switch, no relay. Confirms the classifier never mislabels a non-transaction frame as a valid
DNP3 READ/RESPONSE, and labels each edge case sensibly.
"""
import os, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from shadow_refmodel import classify, FIN, SYN, RST, ACK

M, O = 40000, 20000  # a master ephemeral port, the outstation DNP3 port


def dnp3_read(seq_ok=True):
    # 0x0564 | len=11 | ctrl | dst=0 | src=1 | crc | transport | app_control(0xC0) | func=1 | obj...
    return bytes([0x05, 0x64, 11, 0xC4, 0x00, 0x00, 0x01, 0x00, 0, 0, 0xC0, 0xC1, 0x01, 0x3C, 0x01])


def dnp3_response():
    return bytes([0x05, 0x64, 115, 0x44, 0x01, 0x00, 0x00, 0x00, 0, 0, 0xC0, 0x81, 0x81, 0x80, 0x00])


class TestShadowNegatives(unittest.TestCase):
    def test_dnp3_read_positive(self):        # sanity: a real READ classifies as READ
        c, f = classify("10.0.0.9", "10.0.0.7", M, O, ACK, dnp3_read())
        self.assertEqual(c, "DNP3_READ"); self.assertEqual(f["dnp3_func"], 1)

    def test_dnp3_response_positive(self):
        c, f = classify("10.0.0.7", "10.0.0.9", O, M, ACK, dnp3_response())
        self.assertEqual(c, "DNP3_RESPONSE"); self.assertEqual(f["dnp3_func"], 129)

    def test_malformed_magic(self):           # 0x0563 not 0x0564
        pl = bytearray(dnp3_read()); pl[1] = 0x63
        c, _ = classify("10.0.0.9", "10.0.0.7", M, O, ACK, bytes(pl))
        self.assertEqual(c, "MALFORMED")

    def test_link_only_frame(self):           # link_len==5, no app layer -> not an application request
        link = bytes([0x05, 0x64, 5, 0xC9, 0x00, 0x00, 0x01, 0x00, 0, 0])
        c, _ = classify("10.0.0.7", "10.0.0.9", O, M, ACK, link)
        self.assertEqual(c, "LINK_STATUS_OR_OTHER_DNP3")
        self.assertNotIn(c, ("DNP3_READ", "DNP3_RESPONSE"))

    def test_truncated_payload(self):         # 0x0564 but too short to reach the func code
        c, _ = classify("10.0.0.9", "10.0.0.7", M, O, ACK, bytes([0x05, 0x64, 11, 0xC4]))
        self.assertNotIn(c, ("DNP3_READ", "DNP3_RESPONSE"))

    # ---- parser-hardening regression (GATE-1 finding: link-only frames must pass through, not drop) ----
    def test_link_only_master_to_outstation(self):   # link_len==5, dst 20000 -> LINK_OTHER, never MALFORMED
        link = bytes([0x05, 0x64, 5, 0x8b, 0x00, 0x00, 0x01, 0x00, 0xce, 0x91])
        c, _ = classify("192.168.10.1", "192.168.10.7", M, O, ACK, link)
        self.assertEqual(c, "LINK_STATUS_OR_OTHER_DNP3")
        self.assertNotEqual(c, "MALFORMED")
        self.assertNotIn(c, ("DNP3_READ", "DNP3_RESPONSE"))

    def test_link_only_outstation_to_master(self):   # link_len==5, src 20000 -> LINK_OTHER, never MALFORMED
        link = bytes([0x05, 0x64, 5, 0x0b, 0x01, 0x00, 0x00, 0x00, 0x12, 0x34])
        c, _ = classify("192.168.10.7", "192.168.10.1", O, M, ACK, link)
        self.assertEqual(c, "LINK_STATUS_OR_OTHER_DNP3")
        self.assertNotEqual(c, "MALFORMED")

    def test_link_claims_userdata_but_absent(self):  # link_len>5 but payload truncated -> safe, not READ/RESP
        c, _ = classify("10.0.0.9", "10.0.0.7", M, O, ACK, bytes([0x05, 0x64, 11, 0xC4, 0x00, 0x00]))
        self.assertNotIn(c, ("DNP3_READ", "DNP3_RESPONSE"))   # no over-read into a func code

    def test_link_only_not_malformed_either_direction(self):
        link = bytes([0x05, 0x64, 5, 0xC9, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00])
        for (s, d, sp, dp) in [("10.0.0.1", "10.0.0.7", M, O), ("10.0.0.7", "10.0.0.1", O, M)]:
            c, _ = classify(s, d, sp, dp, ACK, link)
            self.assertNotEqual(c, "MALFORMED")

    def test_wrong_tcp_port(self):            # DNP3 bytes but not on port 20000 -> unrelated
        c, _ = classify("10.0.0.9", "10.0.0.7", M, 80, ACK, dnp3_read())
        self.assertEqual(c, "UNRELATED")

    def test_wrong_dnp3_addresses(self):      # still a READ (addresses are for the txn core, not the shadow)
        pl = bytearray(dnp3_read()); pl[4] = 0x63; pl[6] = 0x62  # dst/src != 0/1
        c, f = classify("10.0.0.9", "10.0.0.7", M, O, ACK, bytes(pl))
        self.assertEqual(c, "DNP3_READ")     # shadow classifies by function; addr-matching is Phase 2
        self.assertNotEqual(f["dnp3_dst"], 0)

    def test_fin(self):
        c, _ = classify("10.0.0.9", "10.0.0.7", M, O, FIN | ACK, b"")
        self.assertEqual(c, "TCP_FIN")

    def test_rst(self):
        c, _ = classify("10.0.0.7", "10.0.0.9", O, M, RST, b"")
        self.assertEqual(c, "TCP_RST")

    def test_unrelated_pure_ack(self):        # a pure ACK on a non-DNP3 flow
        c, _ = classify("10.0.0.5", "10.0.0.6", 1234, 5678, ACK, b"")
        self.assertEqual(c, "PURE_ACK")       # zero-payload ACK is never parsed as DNP3

    def test_outstation_pure_ack_not_dnp3(self):  # the separate CLRT ACK: PURE_ACK, never DNP3
        c, f = classify("10.0.0.7", "10.0.0.9", O, M, ACK, b"")
        self.assertEqual(c, "PURE_ACK"); self.assertEqual(f["payload_len"], 0)

    def test_retransmitted_request_still_read(self):  # a re-sent READ is still classified READ
        c, _ = classify("10.0.0.9", "10.0.0.7", M, O, ACK, dnp3_read())
        self.assertEqual(c, "DNP3_READ")       # dedup/retransmission is an offline/Phase-2 concern

    def test_second_request_while_active_still_read(self):  # shadow is stateless per packet
        c, _ = classify("10.0.0.9", "10.0.0.7", M, O, ACK, dnp3_read())
        self.assertEqual(c, "DNP3_READ")       # one-outstanding enforcement is Phase 2, not the shadow

    def test_syn_not_pure_ack(self):          # a bare SYN to 20000 is not a pure ACK and not DNP3
        c, _ = classify("10.0.0.9", "10.0.0.7", M, O, SYN, b"")
        self.assertNotIn(c, ("PURE_ACK", "DNP3_READ", "DNP3_RESPONSE"))


if __name__ == "__main__":
    unittest.main(verbosity=2)

"""SBO admission defects A and E, tested with the bytes captured on silicon (combined_silicon_02/block_off_1,
reproduced in DNP3_Combined_Hardware_Debug_and_Reproducibility_Prompt.md Appendix A). Uses
test_response_only_binding as the whole-N source interpreter.

Defect A: the SELECT/OPERATE response's func+IIN1 term was exact 0x8100; the real outstation sets IIN1 0x90
(NEED_TIME 0x10 + DEVICE_RESTART 0x80), so the SELECT association never advanced and the OPERATE was refused.
The term is now ternary 0x8100&&&0xff6f: IIN1 in {00,10,80,90} is admitted, every other indication bit and a
genuine CROB command failure (rtail.status != 0) still rejected.

Defect E: a command-bearing native frame with a FIN/RST flag combination (e.g. a late OPERATE retransmission
with FIN+PSH+ACK 0x19) fell through native_tcp's `default:accept` and was forwarded around the mechanism. It is
now dropped before the lap, so no rejected command reaches the outstation, a callback, or T.
"""
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import test_response_only_binding as h  # noqa: E402

SELECT = bytes.fromhex('05641ac40a0001008a1cd4c4030c01280100010001016400000055756400000000005b')
REPLY = bytes.fromhex('05641c4401000a007636d4c48190000c012801000100010164004a3300006400000000005b')
OPERATE = bytes.fromhex('05641ac40a0001008a1cd5c5040c01280100010001016400000011ee6400000000005b')
HEAD, USER = h.codec.decode_frame(REPLY)
TIN = h.rs.handoff_port(h.make_n.generate())
OWNER_SELECT, OWNER_OPERATE_READY = 0x90001, 0xa0001


def reply(iin1=0x90, status=0x00):
    """The captured SELECT response with its IIN1 (user[3]) and CROB status (user[-1]) set; CRCs recomputed."""
    user = bytearray(USER)
    user[3] = iin1
    user[-1] = status
    return h.codec.build_frame(HEAD, bytes(user))


def run_sbo(response, operate_flags=24):
    """SELECT, its response, then the OPERATE. Returns (owner after the response, OPERATE outcome)."""
    p = h.fresh()
    p.inject(h.rs.IN_CLIENT, h.vectors.packet(24, 101, 901, payload=SELECT))
    p.inject(h.rs.IN_SERVER, h.vectors.packet(24, 901, 136, reverse=True, payload=response))
    owner = p.state()['owner']
    out = p.inject(h.rs.IN_CLIENT, h.vectors.packet(operate_flags, 136, 938, payload=OPERATE))
    return owner, out


class DefectA(unittest.TestCase):
    def test_normal_indications_advance_the_select_and_admit_the_operate(self):
        """IIN1 in {00,10,80,90}: NEED_TIME and DEVICE_RESTART are normal. The owner must advance and the
        OPERATE must be handed to T. 0x90 is the value captured on silicon; before the fix it was refused."""
        for iin1 in (0x00, 0x10, 0x80, 0x90):
            owner, out = run_sbo(reply(iin1=iin1))
            self.assertEqual(owner, OWNER_OPERATE_READY, hex(iin1))
            self.assertFalse(out.dropped, hex(iin1))
            self.assertEqual([port for port, _ in out.emitted], [TIN], hex(iin1))

    def test_command_failure_status_does_not_advance(self):
        """A genuine CROB command failure is reported in rtail.status, not IIN1. A non-zero status must keep the
        owner at SELECT and drop the OPERATE, whatever the (normal) IIN1 is."""
        for status in (0x01, 0x02, 0x04, 0x08):
            owner, out = run_sbo(reply(iin1=0x90, status=status))
            self.assertEqual(owner, OWNER_SELECT, hex(status))
            self.assertTrue(out.dropped, hex(status))
            self.assertEqual(out.emitted, [], hex(status))

    def test_abnormal_indication_bits_do_not_advance(self):
        """The mask frees only NEED_TIME (0x10) and DEVICE_RESTART (0x80). Any other IIN1 bit set
        (ALL_STATIONS/class/LOCAL/DEVICE_TROUBLE) must not be admitted: the SELECT does not advance."""
        for iin1 in (0x01, 0x02, 0x04, 0x08, 0x20, 0x40, 0x11, 0xc0):
            if iin1 & 0x6f == 0:        # {00,10,80,90} are the admitted set; skip them here
                continue
            owner, out = run_sbo(reply(iin1=iin1))
            self.assertEqual(owner, OWNER_SELECT, hex(iin1))
            self.assertTrue(out.dropped, hex(iin1))

    def test_iin2_must_stay_zero(self):
        """IIN2 is hdr.first.w1's high byte (user[4]); it stays an exact 0x00 in the key. A non-zero IIN2 is
        not a normal-startup indication and must not advance the SELECT."""
        user = bytearray(USER)
        user[3] = 0x90
        user[4] = 0x04          # IIN2 bit set
        owner, out = run_sbo(h.codec.build_frame(HEAD, bytes(user)))
        self.assertEqual(owner, OWNER_SELECT)
        self.assertTrue(out.dropped)


class DefectE(unittest.TestCase):
    def test_fin_psh_ack_operate_is_dropped_not_forwarded(self):
        """The silicon case: a late OPERATE retransmission with FIN+PSH+ACK (0x19) while the SELECT is valid.
        It must be dropped -- not forwarded around the mechanism, no T handoff, owner unchanged."""
        p = h.fresh()
        p.inject(h.rs.IN_CLIENT, h.vectors.packet(24, 101, 901, payload=SELECT))
        p.inject(h.rs.IN_SERVER, h.vectors.packet(24, 901, 136, reverse=True, payload=reply(iin1=0x00)))
        before = p.state()['owner']
        out = p.inject(h.rs.IN_CLIENT, h.vectors.packet(25, 136, 938, payload=OPERATE))
        self.assertTrue(out.dropped)
        self.assertEqual(out.emitted, [])
        self.assertEqual(p.state()['owner'], before)

    def test_every_command_bearing_fin_or_rst_form_is_dropped(self):
        """Any FIN(0x01)- or RST(0x04)-bearing flag combination on a command-sized frame is rejected, so none
        can bypass. The clean forms 0x10 and 0x18 are the only admitted ones."""
        for flags in (0x11, 0x19, 0x14, 0x1c, 0x15, 0x05, 0x01, 0x04):
            owner, out = run_sbo(reply(iin1=0x00), operate_flags=flags)
            self.assertTrue(out.dropped, hex(flags))
            self.assertEqual(out.emitted, [], hex(flags))

    def test_clean_operate_is_still_admitted(self):
        """0x10 (ACK) and 0x18 (PSH+ACK) must still reach T."""
        for flags in (0x10, 0x18):
            owner, out = run_sbo(reply(iin1=0x00), operate_flags=flags)
            self.assertFalse(out.dropped, hex(flags))
            self.assertEqual([port for port, _ in out.emitted], [TIN], hex(flags))

    def test_a_fin_select_is_also_rejected(self):
        """The reject covers any command (SELECT as well as OPERATE) carrying a close."""
        p = h.fresh()
        out = p.inject(h.rs.IN_CLIENT, h.vectors.packet(25, 101, 901, payload=SELECT))
        self.assertTrue(out.dropped)
        self.assertEqual(out.emitted, [])

    def test_non_command_traffic_is_unaffected(self):
        """native_tcp only sees IP-length-75 command frames, so the reject cannot touch other traffic. A bare
        FIN+ACK close (no DNP3 payload, IP length 40) takes the regular close path and is still handled, not
        dropped as a rejected command; a bare ACK still forwards."""
        p = h.fresh()
        out = p.inject(h.rs.IN_CLIENT, h.vectors.packet(17, 101, 901))   # FIN+ACK, no payload: a real close
        self.assertFalse(out.dropped)
        self.assertEqual([port for port, _ in out.emitted], [TIN])       # forwarded to T as a close event
        p = h.fresh()
        out = p.inject(h.rs.IN_CLIENT, h.vectors.packet(16, 101, 901))   # bare ACK
        self.assertFalse(out.dropped)


if __name__ == '__main__':
    unittest.main()

"""Actual receiving parser admission agrees with device-port handoff constants."""
import struct
import re
import unittest
import whole_program as w
from pathlib import Path


class BoundaryAdmission(unittest.TestCase):
    def test_n_producer_and_t_private_receiving_parsers_share_the_approved_ports(self):
        n=(w.ARCH/'integration/connection/binding/native_binding.p4').read_text()
        for name,key in (('READ_HANDOFF_PORT','T_IN'),('STEP3_M_PORT','N_TO_M'),('RETURN_PORT','N_RETURN')):
            self.assertEqual(int(re.search(r'const PortId_t '+name+r'=9w(\d+)',n)[1]),w.PORTS[key])
        src=w.ExtSource((w.READ/'read_timing.p4').read_text(),w.READ)
        typed=w.event_frame(9,w.REQUEST_FRAME)
        src.begin_pass(w.PORTS['T_IN']);self.assertTrue(src.packet_parser(typed)[0])
        held=struct.pack('>IIIIBBH',1,1,1,0x10000,9,1,0)+typed
        src.begin_pass(w.PORTS['HELD_RETURN']);self.assertTrue(src.packet_parser(held)[0])
        service=struct.pack('>IIIB3xIII',1,1,1,1,0,0,0)+w.REQUEST_FRAME
        src.begin_pass(w.PORTS['HB_RETURN']);self.assertTrue(src.packet_parser(service)[0])
        src.begin_pass(w.PORTS['N_RETURN']);self.assertFalse(src.packet_parser(typed)[0])

    def test_m_receives_both_approved_device_ports_and_rejects_old_local_port(self):
        source=w.ARCH/'integration/core/m/m_skeleton.p4'
        # Equivalent extern identifier used by the existing interpreter; exact
        # compiled source is retained separately for the model acceptance.
        src=w.ExtSource(source.read_text().replace('ipcheck','ic').replace('repaircheck','tc'),source.parent)
        raw=struct.pack('>IIIHH',17,1,0x90001,0x0308,0)+w.pure_ack()
        for port,expected in ((w.PORTS['N_TO_M'],True),(w.PORTS['T_TO_M'],True),(68,False)):
            src.begin_pass(port);accepted,cursor=src.packet_parser(raw)
            self.assertEqual(accepted,expected,(port,src.parser_states))
            if expected:self.assertEqual(src.env['m.parsed'],1)


if __name__=='__main__':unittest.main()

"""Packet association plus source-action/table expiry regressions, entirely offline.

These fixtures do not prove Tofino parser/CRC behavior, BOR OPERATE, connection
incarnation/FIN handling, real token-ring scheduling or physical byte departure.
"""
import struct
import sys
import unittest
from pathlib import Path

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
sys.path.insert(0,str(HERE.parent/'size'))
from p4_pass_sim import P4Sim
import rrc
import test_rrc_split as fixtures

MS=1_000_000
FLOW=('192.168.10.1','192.168.10.7',40000,20000)


def wire(kind, seq=None, ack=None, app=5, flow=FLOW, flags=None):
    master,relay,client,server=flow
    outbound=kind=='REQ'
    src,dst=(master,relay) if outbound else (relay,master)
    sport,dport=(client,server) if outbound else (server,client)
    payload=b'' if kind=='ACK' else fixtures.dnp3_frame(bytes([
        0xc0,0xc0|app,1 if outbound else 0x81,0,0,0x3c,1,6]))
    seq=(1000 if outbound else 4000) if seq is None else seq
    ack=(4000 if outbound else 1020) if ack is None else ack
    ip=bytearray(struct.pack('>BBHHHBBH4s4s',0x45,0,40+len(payload),7,0,64,6,0,
        bytes(map(int,src.split('.'))),bytes(map(int,dst.split('.')))))
    struct.pack_into('>H',ip,10,rrc._csum(bytes(ip)))
    tcp=bytearray(struct.pack('>HHIIBBHHH',sport,dport,seq,ack,5<<4,(0x10 if kind=='ACK' else 0x18) if flags is None else flags,4096,0,0))
    struct.pack_into('>H',tcp,16,rrc._csum(bytes(ip[12:20])+struct.pack('>BBH',0,6,len(tcp)+len(payload))+bytes(tcp)+payload))
    return bytes(12)+b'\x08\x00'+bytes(ip)+bytes(tcp)+payload


class PacketAssociation(unittest.TestCase):
    def sim(self, events, **kw):
        return P4Sim(10*MS,MS,configured_flow=FLOW,**kw).run(events)

    def test_dnp3_requires_ack_bit_with_psh_allowed(self):
        s=self.sim([(0,'PACKET',wire('REQ',flags=0x08)),
                    (MS,'PACKET',wire('REQ',flags=0x18))])
        self.assertEqual(s.counters.get('parser_subset_bypass'),1)
        self.assertEqual(s.counters.get('arm_fresh'),1)
        self.assertEqual(s.regs['reg_exp_ack'],1020)

    def test_packet_fields_write_real_source_trackers(self):
        s=self.sim([(0,'PACKET',wire('REQ')),(MS,'PACKET',wire('ACK')),(2*MS,'PACKET',wire('RESP'))])
        self.assertEqual(s.regs['reg_exp_relay_seq'],4000)
        self.assertEqual(s.regs['reg_session_port'],40000)
        self.assertEqual(s.regs['reg_exp_ack'],1020)
        self.assertEqual(s.regs['reg_app_seq'],5)
        self.assertEqual(s.counters.get('completed'),1)

    def test_wrong_byte_fields_cannot_mark_response_ready(self):
        variants=[dict(seq=4001),dict(ack=1021),dict(app=6),
                  dict(flow=(FLOW[0],FLOW[1],40001,20000)),
                  dict(flow=('192.168.10.2',FLOW[1],40000,20000))]
        for variant in variants:
            with self.subTest(variant=variant):
                bad=wire('RESP',**variant)
                s=self.sim([(0,'PACKET',wire('REQ')),(MS,'PACKET',wire('ACK')),
                            (2*MS,'PACKET',bad),(3*MS,'PACKET',wire('RESP'))])
                self.assertEqual(s.counters.get('completed'),1)
                self.assertIn(('RESP',2*MS,bad,'forwarded_unchanged'),s.packet_outs)
                self.assertGreaterEqual(next(t for k,t,_ in s.outs if k=='ACK'),10*MS-256)

    def test_busy_request_preserves_actual_trackers(self):
        s=self.sim([(0,'PACKET',wire('REQ')),(MS,'PACKET',wire('REQ',seq=2000,ack=8000,app=6)),
                    (2*MS,'PACKET',wire('ACK')),(3*MS,'PACKET',wire('RESP'))])
        self.assertEqual(s.regs['reg_exp_ack'],1020)
        self.assertEqual(s.regs['reg_exp_relay_seq'],4000)
        self.assertEqual(s.regs['reg_app_seq'],5)
        self.assertEqual(s.counters.get('out_arm_busy'),1)
        self.assertEqual(s.counters.get('completed'),1)

    def test_tcp_and_app_wrap_are_real_packet_fields(self):
        seq=0xfffffff0; end=(seq+20)&0xffffffff
        s=self.sim([(0,'PACKET',wire('REQ',seq=seq,app=15)),(MS,'PACKET',wire('ACK',ack=end)),
            (2*MS,'PACKET',wire('RESP',ack=end,app=15)),
            (20*MS,'PACKET',wire('REQ',seq=end,app=0)),(21*MS,'PACKET',wire('ACK',ack=end+20)),
            (22*MS,'PACKET',wire('RESP',ack=end+20,app=15)),(23*MS,'PACKET',wire('RESP',ack=end+20,app=0))])
        self.assertEqual(s.counters.get('completed'),2)
        self.assertEqual(s.regs['reg_app_seq'],0)
        self.assertEqual(s.regs['reg_exp_ack'],24)

    def test_duplicate_acks_retain_queue_multiplicity(self):
        s=self.sim([(0,'PACKET',wire('REQ')),(MS,'PACKET',wire('ACK')),
                    (2*MS,'PACKET',wire('ACK')),(3*MS,'PACKET',wire('RESP'))])
        self.assertEqual(len([o for o in s.packet_outs if o[0]=='ACK']),2)
        self.assertEqual(s.counters.get('completed'),1)

    def test_stale_response_return_does_not_clear_new_full_owner(self):
        s=self.sim([(0,'PACKET',wire('REQ')),(MS,'PACKET',wire('ACK')),(2*MS,'PACKET',wire('RESP'))])
        stale=s.cookie
        s.request(20*MS,raw=wire('REQ',app=6))
        current=s.regs['reg_owner'];tag=s.regs['reg_tag']
        s._resp_release(21*MS,cookie=stale)
        self.assertEqual(s.regs['reg_owner'],current)
        self.assertEqual(s.regs['reg_tag'],tag)


class ExpiryPackets(unittest.TestCase):
    def sim(self, events, gap=MS, **kw):
        return P4Sim(10*MS,gap,configured_flow=FLOW,expiry_enabled=1,heartbeat_ns=100_000,**kw).run(events)

    def test_associated_pending_duplicate_is_suppressed(self):
        s=self.sim([(0,'PACKET',wire('REQ')),(MS,'PACKET',wire('ACK')),
                    (2*MS,'PACKET',wire('RESP')),(3*MS,'PACKET',wire('RESP'))])
        self.assertEqual(s.counters.get('dup_response_dropped'),1)
        self.assertEqual(len([o for o in s.packet_outs if o[0]=='RESP']),1)
        self.assertEqual(s.counters.get('completed'),1)

    def test_stale_pulse_and_commit_cannot_retire_new_owner(self):
        s=P4Sim(10*MS,MS,configured_flow=FLOW,expiry_enabled=1)
        s.request(0,raw=wire('REQ'))
        stale=s.cookie
        s.pulse_return(31*MS,stale)
        s.request(40*MS,raw=wire('REQ',app=6))
        owner,tag=s.regs['reg_owner'],s.regs['reg_tag']
        s.pulse_return(41*MS,stale)
        s.held_commit(42*MS,'RESP',dict(raw=wire('RESP'),cookie=stale),'normal')
        self.assertEqual((s.regs['reg_owner'],s.regs['reg_tag']),(owner,tag))
        self.assertEqual(s.counters.get('stale_expiry_return'),1)
        self.assertFalse(s.packet_outs)

    def test_both_lost_reservoirs_are_recovered_without_endpoint_feedback(self):
        s=self.sim([(0,'PACKET',wire('REQ')),(1*MS,'LOSE','ACK'),(1*MS,'LOSE','RESP'),
                    (40*MS,'PACKET',wire('REQ',app=6)),(41*MS,'PACKET',wire('ACK')),
                    (42*MS,'PACKET',wire('RESP',app=6))])
        self.assertEqual(s.counters.get('arm_fresh'),2)
        self.assertGreaterEqual(s.counters.get('expiry_retired',0),1)
        self.assertEqual(s.regs['reg_owner']&0x80000000,0)
        self.assertEqual(s.counters.get('completed'),1)

    def test_late_ready_response_preserves_full_gap_beyond_readiness_expiry(self):
        s=self.sim([(0,'PACKET',wire('REQ')),(MS,'PACKET',wire('ACK')),(29*MS,'PACKET',wire('RESP'))],gap=8*MS)
        ack,resp=[o for o in s.outs if o[0] in ('ACK','RESP')]
        self.assertGreaterEqual(resp[1]-ack[1],8*MS-256)
        self.assertLessEqual(resp[1]-ack[1],8*MS+4000)

    def test_readiness_scan_cannot_cut_gap_at_admitted_boundary(self):
        # The old scan saw unarmed T_RESP at 30ms and its cookie-only return
        # retired the same owner after ACK commitment armed a future full gap.
        for ready_ns in (29_998_000,29_999_000):
            with self.subTest(ready_ns=ready_ns):
                s=self.sim([(0,'PACKET',wire('REQ')),(MS,'PACKET',wire('ACK')),
                            (ready_ns,'PACKET',wire('RESP'))],gap=8*MS)
                ack,resp=[o for o in s.outs if o[0] in ('ACK','RESP')]
                if ack[2] == 'normal':
                    self.assertGreaterEqual(resp[1]-ack[1],8*MS-256)
                    self.assertEqual(s.counters.get('completed'),1)
                else:
                    # When expiry wins before phase-two ACK commitment, the
                    # source explicitly labels native fallback; no normal full
                    # gap guarantee applies to this readiness boundary race.
                    self.assertEqual(ready_ns,29_999_000)
                    self.assertEqual((ack[2],resp[2]),('expiry_native','expiry_native'))
                    self.assertEqual(s.counters.get('held_expiry_native'),2)
                    self.assertEqual(s.counters.get('source_count_50'),2)
                    self.assertIsNone(s.counters.get('completed'))
                if ready_ns == 29_998_000:
                    self.assertEqual(ack[2],'normal')

    def test_enabled_single_reservoir_loss_rechecks_held_departure(self):
        for slot in ('ACK','RESP'):
            with self.subTest(slot=slot):
                s=self.sim([(0,'PACKET',wire('REQ')),(MS,'PACKET',wire('ACK')),
                    (2*MS,'PACKET',wire('RESP')),(3*MS,'LOSE',slot)])
                ack,resp=[o for o in s.outs if o[0] in ('ACK','RESP')]
                self.assertGreaterEqual(ack[1],10*MS-256)
                self.assertGreaterEqual(resp[1]-ack[1],MS-256)

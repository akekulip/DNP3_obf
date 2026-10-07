import importlib
import struct
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[2] / 'framework/size'))
import case4_padding
try:
    api = importlib.import_module('reference')
except ModuleNotFoundError:
    api = None


def checksum(data):
    if len(data) % 2:
        data += b'\0'
    value = sum(struct.unpack('!' + 'H'*(len(data)//2), data))
    while value >> 16:
        value = (value & 0xffff) + (value >> 16)
    return (~value) & 0xffff


FLOW = (0x0a000001, 0x0a000002, 30001, 20000)


def packet(flags, seq, ack=0, *, reverse=False, payload=b'', mss=None):
    src, dst, sport, dport = FLOW
    if reverse:
        src, dst, sport, dport = dst, src, dport, sport
    options = b'' if mss is None else struct.pack('!BBH', 2, 4, mss)
    tcp = struct.pack('!HHIIBBHHH', sport, dport, seq & 0xffffffff,
        ack & 0xffffffff, ((20+len(options))//4)<<4, flags, 4096, 0, 0) + options + payload
    pseudo = struct.pack('!IIBBH', src, dst, 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack('!H', checksum(pseudo+tcp)) + tcp[18:]
    ip = struct.pack('!BBHHHBBHII', 0x45, 0, 20+len(tcp), 1, 0x4000, 64, 6, 0, src, dst)
    ip = ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:]
    return bytes.fromhex('001122334455aabbccddeeff0800') + ip + tcp


def control(fc=3, app=0):
    return case4_padding.build_frame(bytes.fromhex('05641ac40a000100'),
        bytes((0xc0, 0xc0|app, fc)) + bytes.fromhex('0c0128010001000101640000006400000000'))


class Connection(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(api, 'protected packet-backed connection producer missing')
        self.c = api.Connection(FLOW, allowed_ports={9,12})

    def finish(self, raw, port=9):
        e = self.c.begin(raw, port)
        self.assertIsNotNone(e)
        for _ in range(3):
            e = self.c.advance(e)
        self.assertEqual(e.outcome, 'forward')
        self.assertIsNone(self.c.work)

    def established(self, select=False):
        self.finish(packet(2, 100, mss=1460))
        self.finish(packet(18, 900, 101, reverse=True, mss=1460), 12)
        self.finish(packet(24 if select else 16, 101, 901,
            payload=control() if select else b''))

    def test_unconfigured_port_cannot_mutate_or_mint_work(self):
        before = self.c.snapshot()
        self.assertIsNone(self.c.begin(packet(2,100,mss=1460), 77))
        self.assertEqual(self.c.snapshot(), before)

    def test_checksum_flags_tuple_and_unsupported_options_refuse(self):
        original = packet(2,100,mss=1460)
        for raw in (packet(3,100,mss=1460), packet(6,100,mss=1460),
                    packet(2,100,1,mss=1460), packet(2,100,mss=56),
                    original[:40]+bytes((original[40]^1,))+original[41:]):
            before = self.c.snapshot()
            self.assertIsNone(self.c.begin(raw,9))
            self.assertEqual(self.c.snapshot(),before)
        wrong = api.Connection((FLOW[0],FLOW[1],30002,20000),allowed_ports={9})
        self.assertIsNone(wrong.begin(original,9))

    def test_three_internal_returns_and_wrap_publish_actual_original(self):
        self.finish(packet(2,0xffffffff,mss=1460))
        self.assertEqual(self.c.client_next,0)
        self.finish(packet(18,0xffffffff,0,reverse=True,mss=1460),12)
        self.finish(packet(16,0,0))
        self.assertEqual(self.c.phase,5)
        self.assertEqual(self.c.epoch,1)

    def test_final_ack_select_is_fully_validated_and_not_silently_dropped(self):
        self.established(select=True)
        self.assertEqual(self.c.client_next,101+35)
        self.assertEqual(self.c.selected_objects,case4_padding.decode_frame(control())[1][3:])
        self.assertEqual(self.c.select_app_sequence,0)

    def test_wrong_final_sequence_or_control_crc_never_claims_owner(self):
        self.finish(packet(2,100,mss=1460))
        self.finish(packet(18,900,101,reverse=True,mss=1460),12)
        bad = bytearray(control());bad[26] ^= 1
        for raw in (packet(16,100,901),packet(16,101,902),packet(24,101,901,payload=bytes(bad))):
            before=self.c.snapshot();self.assertIsNone(self.c.begin(raw,9))
            self.assertEqual(self.c.snapshot(),before)

    def test_out_of_window_or_invalid_rst_fin_does_not_close(self):
        self.established()
        for flags,seq,ack in ((3,101,901),(5,101,901),(20,100,901),(17,101,900),(4,100,0)):
            before=self.c.snapshot();self.assertIsNone(self.c.begin(packet(flags,seq,ack),9))
            self.assertEqual(self.c.snapshot(),before)
        self.finish(packet(20,101,901))
        self.assertEqual(self.c.phase,7)

    def test_close_pending_producer_prevents_publication_and_reuse(self):
        self.finish(packet(2,100,mss=1460))
        pending=self.c.begin(packet(18,900,101,reverse=True,mss=1460),12)
        pending=self.c.advance(pending)
        close=self.c.begin(packet(20,101,901),9)
        self.assertIsNotNone(close)
        close=self.c.advance(close)
        self.assertEqual(self.c.phase,6)
        self.assertIsNotNone(self.c.work)
        before=self.c.snapshot()
        self.assertIsNone(self.c.begin(packet(2,200,mss=1460),9))
        self.assertEqual(self.c.snapshot(),before)
        pending=self.c.advance(pending)
        self.assertEqual(pending.outcome,'abort')
        self.assertIsNone(self.c.work)
        self.assertEqual(self.c.phase,7)

    def test_foreign_epoch_work_or_original_cannot_overwrite(self):
        e=self.c.begin(packet(2,100,mss=1460),9);e=self.c.advance(e)
        from dataclasses import replace
        for bad in (replace(e,epoch=e.epoch+1),replace(e,work_generation=e.work_generation+1),
                    replace(e,original=packet(2,200,mss=1460))):
            before=self.c.snapshot();self.assertEqual(self.c.advance(bad).outcome,'refused')
            self.assertEqual(self.c.snapshot(),before)
        self.c.advance(self.c.advance(e))
        before=self.c.snapshot();self.assertEqual(self.c.advance(e).outcome,'refused')
        self.assertEqual(self.c.snapshot(),before)

    def test_nonwrapping_counters_and_busy_work_refuse_without_overwrite(self):
        self.c.work_counter=0xffffffff
        before=self.c.snapshot();self.assertIsNone(self.c.begin(packet(2,100,mss=1460),9))
        self.assertEqual(self.c.snapshot(),before)

    def test_actual_epoch_salu_returns_the_bound_post_write_epoch(self):
        sys.path.insert(0,str(HERE.parents[1]/'protocol'))
        from source_eval import Source
        import re
        text=(HERE.parent/'handshake.p4').read_text()
        text=re.sub(r'\br\b','rv',text)
        source=Source(text,{'hdr.envelope.epoch':123},registers={('epoch',0):0})
        self.assertEqual(source.register('write_epoch',0),123)
        self.assertEqual(source.registers[('epoch',0)],123)

    def test_actual_record_table_cannot_use_unqualified_read_phase_as_write_permission(self):
        sys.path.insert(0,str(HERE.parents[1]/'protocol'))
        from source_eval import Source
        import re
        text=re.sub(r'\br\b','rv',(HERE.parent/'handshake.p4').read_text())
        source=Source(text,{'m.stage':1,'m.kind':1,'m.work_phase':1,'m.work_op':0,
            'hdr.envelope.epoch':123},registers={('epoch',0):9})
        source.table('epoch_t')
        self.assertEqual(source.registers[('epoch',0)],9)

    def test_actual_network_gate_refuses_relabelled_private_original(self):
        sys.path.insert(0,str(HERE.parents[1]/'protocol'))
        from source_eval import Source
        text=(HERE.parent/'handshake.p4').read_text().replace(',_,',',8w0&&&8w0,').replace('8w1..8w255','8w64')
        good={'m.parsed':1,'m.kind':1,'hdr.tcp.flags':2,'m.ip_error':0,
            'm.tcp_sum':0xffeb,'hdr.ip.ttl':64,'hdr.tcp.reserved':0,
            'hdr.tcp.urgent':0,'m.network_valid':0}
        source=Source(text,good);source.table('network')
        self.assertEqual(source.env['m.network_valid'],1)
        source=Source(text,dict(good,**{'hdr.tcp.flags':18}));source.table('network')
        self.assertEqual(source.env['m.network_valid'],0)

    def test_qualified_close_return_carries_nonzero_epoch_generation(self):
        sys.path.insert(0,str(HERE.parents[1]/'protocol'))
        from source_eval import Source
        source=Source((HERE.parent/'handshake.p4').read_text(),
            {'m.epoch':19,'hdr.work_generation.generation':0})
        source.action('first_close')
        self.assertEqual(source.env['hdr.work_generation.generation'],19)

    def test_private_prefix_cannot_be_fresh_or_change_original_event_kind(self):
        import struct
        from reference import parse_envelope
        original=packet(2,100,mss=1460)
        valid=struct.pack('!IIIHH',1,1,0,0x0101,0)+original
        self.assertEqual(parse_envelope(valid)[0],(1,1,0,0x0101))
        for epoch,generation,event,reserved,inner in (
                (1,1,0x0001,0,original),(1,1,0x0401,0,original),
                (1,1,0x0102,0,original),(1,1,0x0101,1,original),
                (0,1,0x0101,0,original),(1,0,0x0101,0,original)):
            with self.assertRaises(ValueError):
                parse_envelope(struct.pack('!IIIHH',epoch,generation,0,event,reserved)+inner)
        # Independently cross-check exact source parser event admission, rather
        # than inferring it from the source's permissive metadata defaults.
        import re
        text=(HERE.parent/'handshake.p4').read_text()
        body=re.search(r'state envelope_event\{(.*?)\}',text,re.S)
        self.assertIsNotNone(body)
        events={int(value,16) for value in re.findall(r'16w(0x[0-9a-f]+):',body.group(1))}
        self.assertNotIn(1,events)
        self.assertEqual(events,{0x101,0x102,0x103,0x104,0x1ff,
            0x201,0x202,0x203,0x2ff,0x301,0x302,0x303,0x3ff})

    def test_actual_work_dispatch_refuses_exhausted_zero_generation_without_claim(self):
        text=(HERE/'work_record.p4').read_text()
        self.assertIn('action unavailable_work()',text)
        sys.path.insert(0,str(HERE.parents[1]/'protocol'))
        from source_eval import Source
        import re
        text=re.sub(r'\boperation\b','m.work_op',text)
        text=re.sub(r'\bwork_generation\b','m.generation',text)
        text=re.sub(r'\bobserved_phase\b','m.work_phase',text)
        text=re.sub(r'\s*([=:;{}()])\s*',r'\1',text)
        source=Source((HERE.parent/'handshake.p4').read_text()+text,
            {'m.work_op':1,'m.generation':0,'m.work_phase':99})
        source.table('dispatch')
        self.assertEqual(source.env['m.work_phase'],0)
        self.assertEqual(source.registers,{})
        self.c.work_counter=0
        a=self.c.begin(packet(2,100,mss=1460),9)
        b=self.c.begin(packet(2,200,mss=1460),9)
        self.c.advance(a)
        before=self.c.snapshot();self.assertEqual(self.c.advance(b).outcome,'refused')
        self.assertEqual(self.c.snapshot(),before)

if __name__=='__main__':unittest.main()

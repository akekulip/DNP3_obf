"""Independent bounded preprocessing expectations; no I/O or TNA execution."""
import ipaddress
from pathlib import Path
import struct
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'size'))
import rrc
import case4_padding as pad
try: import case4_preprocess as pre
except ImportError: pre=None

MASK=0xffffffff
BODY=bytes.fromhex('0101640000006400000000')


def frame(function=3, app=0, transport=0, index=1):
    user=bytes([0xc0|transport,0xc0|app,function])+bytes.fromhex('0c01280100')+struct.pack('<H',index)+BODY
    return pad.build_frame(bytes.fromhex('056400c40a000100'),user)


def packet(payload=b'',seq=1000,ack=9000,flags=24,reverse=False,options=b'',version=4,fragment=0,urgent=0):
    ips=('10.0.0.2','10.0.0.1') if reverse else ('10.0.0.1','10.0.0.2')
    ports=(20000,12000) if reverse else (12000,20000)
    eth=bytes.fromhex('0200000000010200000000020800' if reverse else '0200000000020200000000010800')
    ip=bytearray(20);ip[0]=(version<<4)|5;ip[8]=64;ip[9]=6
    struct.pack_into('>HH',ip,2,40+len(options)+len(payload),1);struct.pack_into('>H',ip,6,fragment)
    ip[12:16]=ipaddress.ip_address(ips[0]).packed;ip[16:20]=ipaddress.ip_address(ips[1]).packed
    struct.pack_into('>H',ip,10,rrc._csum(bytes(ip)))
    tcp=bytearray(20+len(options));struct.pack_into('>HHII',tcp,0,*ports,seq&MASK,ack&MASK)
    tcp[12]=(len(tcp)//4)<<4;tcp[13]=flags;struct.pack_into('>HH',tcp,14,1000,0);struct.pack_into('>H',tcp,18,urgent);tcp[20:]=options
    struct.pack_into('>H',tcp,16,rrc._csum(bytes(ip[12:20])+struct.pack('>BBH',0,6,len(tcp)+len(payload))+bytes(tcp)+payload))
    return eth+bytes(ip)+bytes(tcp)+payload


class Preprocessing(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(pre,'bounded preprocessing oracle missing')
        self.flow=pre.Flow('10.0.0.1','10.0.0.2',12000,20000)
        self.decoy=pad.Decoy(201,BODY)
        self.pipe=pre.Preprocessor(self.flow,7,self.decoy)
        self.base=1000;self.server=9000

    def process(self,raw,time=0,**kw):return self.pipe.process(raw,time,cookie=7,**kw)
    def handshake(self,base=1000,server=9000,mss=1460):
        self.base=base;self.server=server
        for raw in (packet(seq=base-1,ack=0,flags=2,options=b'\x02\x04'+struct.pack('>H',mss)),
                    packet(seq=server-1,ack=base,flags=18,reverse=True,options=b'\x02\x04'+struct.pack('>H',mss)),
                    packet(seq=base,ack=server,flags=16)):
            self.process(raw)
    def select(self,app=0,transport=0):
        self.native=frame(app=app,transport=transport)
        self.image=pad.expand_control(self.native,self.decoy)[0]
        return self.process(packet(self.native,seq=self.base,ack=self.server))
    def operate(self):return frame(4,app=1,transport=1)

    def test_missing_handshake_or_initial_fragment_sticky_exclusion(self):
        result=self.select();self.assertEqual(result.outputs,(packet(self.native),));self.assertTrue(self.pipe.excluded)
        self.handshake();self.assertEqual(self.select().outcome,'EXCLUDED');self.assertFalse(self.pipe.ledger.entries)
        self.pipe=pre.Preprocessor(self.flow,7,self.decoy);self.handshake()
        native=frame();a=packet(native[:20]);b=packet(native[20:],seq=1020)
        self.assertEqual(self.process(a).outputs,(a,));self.assertEqual(self.process(b).outputs,(b,));self.assertTrue(self.pipe.excluded)
        self.assertEqual(self.select().outcome,'EXCLUDED')

    def test_verified_exact_handshake_and_select_full_crc(self):
        self.handshake();result=self.select()
        self.assertEqual(result.outcome,'INSERT_SELECT');self.assertTrue(result.full_validation)
        self.assertEqual(rrc.parse(result.outputs[0]).payload,self.image);self.assertEqual(result.dynamic_wire_end,1055)
        self.assertEqual(result.original_observation_ns,0)
        for position in (8,26,34):
            self.pipe=pre.Preprocessor(self.flow,7,self.decoy);self.handshake()
            damaged=bytearray(frame());damaged[position]^=1
            raw=packet(bytes(damaged));self.assertEqual(self.process(raw).outputs,(raw,));self.assertTrue(self.pipe.excluded)

    def test_fragmented_operate_reorders_duplicates_without_deadline_extension(self):
        self.handshake();self.select();op=self.operate()
        first=self.process(packet(op[15:],seq=1050),time=0)
        self.assertEqual(first.outputs,());self.assertEqual(first.outcome,'ASSEMBLING')
        self.assertEqual(self.pipe.assembly_deadline_ns,30000000)
        self.process(packet(op[15:],seq=1050),time=10000000)
        self.assertEqual(self.pipe.assembly_deadline_ns,30000000)
        done=self.process(packet(op[:15],seq=1035),time=29999999)
        self.assertEqual(done.outcome,'INSERT_OPERATE');self.assertTrue(done.full_validation)
        self.assertEqual(done.original_observation_ns,0);self.assertEqual(done.dynamic_wire_end,1110)
        image=rrc.parse(done.outputs[0]);self.assertEqual((image.seq,len(image.payload)),(1055,55))
        self.assertTrue(rrc.dnp3_frame_ok(image.payload));self.assertEqual(len(self.pipe.ledger.entries),2)

    def test_expiry_conflict_out_of_range_crc_object_and_hop_faults_are_sticky(self):
        for reason in ('expiry','conflict','out_of_range','crc','objects','hops','flags'):
            with self.subTest(reason=reason):
                self.pipe=pre.Preprocessor(self.flow,7,self.decoy);self.handshake();self.select();op=self.operate()
                self.process(packet(op[:10],seq=1035),time=10)
                if reason=='expiry':result=self.process(packet(op[10:],seq=1045),time=30000010)
                elif reason=='conflict':result=self.process(packet(bytes([op[0]^1]),seq=1035),time=20)
                elif reason=='out_of_range':result=self.process(packet(b'x',seq=1070),time=20)
                elif reason=='crc':result=self.process(packet(op[10:-1]+bytes([op[-1]^1]),seq=1045),time=20)
                elif reason=='objects':result=self.process(packet(frame(4,1,1,index=2)[10:],seq=1045),time=20)
                elif reason=='hops':result=self.process(packet(op[10:],seq=1045),time=20,hops=17)
                else:result=self.process(packet(op[10:],seq=1045,flags=25),time=20)
                self.assertEqual(result.outcome,'TRANSPORT_FAULT');self.assertEqual(result.outputs,());self.assertEqual(len(self.pipe.ledger.entries),1)
                self.assertEqual(self.process(packet(op,seq=1035),time=25).outputs,())
                replay=self.process(packet(self.native[-1:],seq=1034),time=26)
                self.assertEqual(rrc.parse(replay.outputs[0]).payload,self.image[34:]);self.assertEqual(len(self.pipe.ledger.entries),1)
                self.assertTrue(replay.full_validation);self.assertFalse(replay.associated)

    def test_overlap_into_uncommitted_operate_never_forwards_suffix(self):
        self.handshake();self.select();op=self.operate()
        result=self.process(packet(self.native[20:]+op[:5],seq=1020))
        self.assertEqual(result.outcome,'ASSEMBLING')
        self.assertEqual(rrc.parse(result.outputs[0]).payload,self.image[20:]);self.assertFalse(result.full_validation)
        done=self.process(packet(op[5:],seq=1040),time=10)
        self.assertEqual(len(rrc.parse(done.outputs[0]).payload),55)

    def test_network_checks_options_mss_and_unsupported_flags_exclude_before_insert(self):
        for bad in ('ip_crc','tcp_crc','ipv4_version','fragment','reserved_fragment','urgent','syn_payload','options','mss'):
            with self.subTest(bad=bad):
                self.pipe=pre.Preprocessor(self.flow,7,self.decoy)
                if bad=='mss':self.handshake(mss=56);raw=packet(frame())
                else:
                    self.handshake();raw=packet(frame())
                    if bad=='ip_crc':x=bytearray(raw);x[24]^=1;raw=bytes(x)
                    if bad=='tcp_crc':x=bytearray(raw);x[50]^=1;raw=bytes(x)
                    if bad=='ipv4_version':raw=packet(frame(),version=6)
                    if bad=='fragment':raw=packet(frame(),fragment=1)
                    if bad=='reserved_fragment':raw=packet(frame(),fragment=0x8000)
                    if bad=='urgent':raw=packet(frame(),urgent=1)
                    if bad=='syn_payload':raw=packet(frame(),flags=26)
                    if bad=='options':raw=packet(frame(),options=b'\x01\x01\x01\x01')
                self.assertEqual(self.process(raw).outputs,(raw,));self.assertTrue(self.pipe.excluded)

    def test_wrong_tuple_or_old_cookie_cannot_poison_active_connection(self):
        self.handshake();self.select();before=tuple(self.pipe.ledger.entries)
        wrong=pre.Flow('10.0.0.1','10.0.0.2',12001,20000)
        raw=bytearray(packet(b'x',seq=1035));struct.pack_into('>H',raw,34,wrong.source_port)
        self.assertEqual(self.process(bytes(raw)).outcome,'FOREIGN_FLOW')
        self.assertEqual(self.pipe.process(packet(b'x',seq=1035),0,cookie=6).outcome,'STALE_COOKIE')
        self.assertEqual(tuple(self.pipe.ledger.entries),before);self.assertFalse(self.pipe.faulted)

    def test_both_sequence_and_absolute_clock_wrap_app_sequence_wrap(self):
        self.handshake(base=0xfffffff0,server=0xfffffff8);self.select(app=15,transport=63)
        op=frame(4,app=0,transport=0);origin=0xfffffff0
        self.process(packet(op[:15],seq=(self.base+35)&MASK,ack=self.server),time=origin)
        result=self.process(packet(op[15:],seq=(self.base+50)&MASK,ack=self.server),time=origin+100)
        self.assertEqual(result.outcome,'INSERT_OPERATE');self.assertEqual(result.dynamic_wire_end,(self.base+110)&MASK)
        self.assertEqual(result.original_observation_ns,origin)

    def test_ack_window_and_raw_close_keep_ledger_until_explicit_drain_abandonment(self):
        self.handshake();self.select()
        ack=self.process(packet(seq=9000,ack=1035,flags=16,reverse=True))
        p=rrc.parse(ack.outputs[0]);self.assertEqual(p.ack,1034)
        close=self.process(packet(seq=1035,ack=9000,flags=17));self.assertEqual(rrc.parse(close.outputs[0]).seq,1055)
        self.assertEqual(len(self.pipe.ledger.entries),1);self.assertTrue(self.pipe.faulted)
        for values in ((False,True,True),(True,False,True),(True,True,False)):
            with self.assertRaises(ValueError):self.pipe.retire(cookie=7,verified_close=values[0],drained=values[1],abandoned=values[2])
        self.assertEqual(len(self.pipe.ledger.entries),1)
        self.pipe.retire(cookie=7,verified_close=True,drained=True,abandoned=True)
        self.assertEqual(self.process(packet(frame())).outcome,'RETIRED')

    def test_complete_response_crc_association_and_byte_preserving_carve(self):
        self.handshake();self.select()
        head,user=pad.decode_frame(self.image)
        response=pad.build_frame(bytes.fromhex('0564004401000a00'),bytes([0xc0,0xc0,0x81,0,0])+user[3:])
        raw=packet(response,seq=9000,ack=1055,reverse=True)
        result=self.process(raw)
        self.assertEqual(result.outcome,'RESPONSE_READY');self.assertTrue(result.full_validation);self.assertTrue(result.associated)
        pieces=[rrc.parse(x) for x in result.outputs];self.assertEqual([len(p.payload) for p in pieces],[28,29]);self.assertEqual(b''.join(p.payload for p in pieces),response)
        self.assertTrue(all(rrc.ip_ok(p) and rrc.tcp_ok(p) and p.ack==1035 for p in pieces))
        for index in (8,26,44,56):
            self.pipe=pre.Preprocessor(self.flow,7,self.decoy);self.handshake();self.select()
            bad=bytearray(response);bad[index]^=1
            result=self.process(packet(bytes(bad),seq=9000,ack=1055,reverse=True))
            self.assertFalse(result.associated);self.assertFalse(result.full_validation)

    def test_dnp3_link_control_and_transport_application_flags_are_profile_gates(self):
        for function in (3,4):
            self.pipe=pre.Preprocessor(self.flow,7,self.decoy);self.handshake()
            if function==4:self.select()
            original=frame(function,app=function-3,transport=function-3)
            header,user=pad.decode_frame(original);header=bytearray(header);header[3]=0xc3
            changed=pad.build_frame(bytes(header),user);raw=packet(changed,seq=1000+35*(function-3))
            result=self.process(raw)
            self.assertEqual(result.outcome,'EXCLUDED' if function==3 else 'TRANSPORT_FAULT')
            self.assertEqual(result.outputs,(raw,) if function==3 else ())
        for transport,application,control in ((0x40,0xc0,0x44),(0xc0,0xe0,0x44),(0xc0,0xc0,0xc4)):
            self.pipe=pre.Preprocessor(self.flow,7,self.decoy);self.handshake();self.select()
            _,user=pad.decode_frame(self.image);header=bytearray.fromhex('0564004401000a00');header[3]=control
            response=pad.build_frame(bytes(header),bytes([transport,application,129,0,0])+user[3:])
            result=self.process(packet(response,seq=9000,ack=1055,reverse=True))
            self.assertFalse(result.associated);self.assertFalse(result.full_validation)

    def test_independent_tick_expiry_and_old_cookie_do_not_extend_deadline(self):
        self.handshake();self.select();op=self.operate()
        self.process(packet(op[:10],seq=1035),time=0)
        result=self.pipe.process(packet(op[10:],seq=1045),20000000,cookie=6)
        self.assertEqual(result.outcome,'STALE_COOKIE');self.assertEqual(self.pipe.assembly_deadline_ns,30000000)
        self.assertFalse(self.pipe.faulted)
        self.assertEqual(self.pipe.tick(30000000).outcome,'TRANSPORT_FAULT')
        self.assertEqual(self.pipe.tick(30000000).original_observation_ns,0)
        self.assertEqual(len(self.pipe.ledger.entries),1)

    def test_all_partial_ack_zero_window_edges_after_two_commits_and_wrap(self):
        for base in (1000,0xfffffff0):
            self.pipe=pre.Preprocessor(self.flow,7,self.decoy);self.handshake(base=base);self.select()
            self.process(packet(self.operate(),seq=(base+35)&MASK),hops=16)
            def inverse(value):
                if value<35:return value
                if value<55:return 34
                if value<90:return value-20
                if value<110:return 69
                return value-40
            for offset in range(111):
                for window in (0,1,20,65535):
                    raw=bytearray(packet(seq=9000,ack=(base+offset)&MASK,flags=16,reverse=True))
                    struct.pack_into('>H',raw,48,window)
                    parsed=rrc.parse(bytes(raw));raw=rrc._build(parsed,b'',parsed.seq,parsed.flags)
                    output=rrc.parse(self.process(raw).outputs[0])
                    self.assertEqual(output.ack,(base+inverse(offset))&MASK)
                    mapped=struct.unpack_from('>H',output.raw,output.tcp_off+14)[0]
                    self.assertEqual(mapped,inverse(offset+window)-inverse(offset))
                    self.assertLessEqual(mapped,window)

    def test_wrong_response_app_tcp_address_and_response_transport_counter_not_ready(self):
        self.handshake();self.select();_,selected=pad.decode_frame(self.image)
        header=bytes.fromhex('0564004401000a00')
        for app,seq,ack,badhead in ((1,9000,1055,header),(0,9001,1055,header),(0,9000,1054,header),(0,9000,1055,bytes.fromhex('0564004402000a00'))):
            response=pad.build_frame(badhead,bytes([0xc0,0xc0|app,129,0,0])+selected[3:])
            result=self.process(packet(response,seq=seq,ack=ack,reverse=True))
            self.assertFalse(result.associated)
        good=pad.build_frame(header,bytes([0xc5,0xc0,129,0,0])+selected[3:])
        self.assertTrue(self.process(packet(good,seq=9000,ack=1055,reverse=True)).associated)
        self.process(packet(self.operate(),seq=1035));_,second=pad.decode_frame(self.pipe.ledger.entries[1].transformed)
        wrong=pad.build_frame(header,bytes([0xc5,0xc1,129,0,0])+second[3:])
        self.assertFalse(self.process(packet(wrong,seq=9057,ack=1110,reverse=True)).associated)

    def test_fault_new_command_drops_while_rst_ack_and_cached_bytes_translate(self):
        self.handshake();self.select();self.pipe.quarantine('lost internal envelope')
        self.assertEqual(self.process(packet(self.operate(),seq=1035)).outputs,())
        ack=self.process(packet(seq=1035,flags=16));self.assertEqual(rrc.parse(ack.outputs[0]).seq,1055)
        reset=self.process(packet(seq=1035,flags=20));self.assertEqual(rrc.parse(reset.outputs[0]).seq,1055)
        self.assertEqual(len(self.pipe.ledger.entries),1)
        with self.assertRaises(ValueError):self.pipe.retire(cookie=6,verified_close=True,drained=True,abandoned=True)
        self.assertEqual(len(self.pipe.ledger.entries),1)

    def test_identical_handshake_retransmission_preserves_verified_identity_and_freezes_mss(self):
        self.handshake()
        synack=packet(seq=8999,ack=1000,flags=18,reverse=True,options=b'\x02\x04\x05\xb4')
        self.assertEqual(self.process(synack).outcome,'HANDSHAKE');self.assertFalse(self.pipe.excluded)
        self.assertEqual(self.pipe.handshake,'VERIFIED')
        self.assertEqual(self.select().outcome,'INSERT_SELECT')
        self.pipe=pre.Preprocessor(self.flow,7,self.decoy)
        self.process(packet(seq=999,ack=0,flags=2,options=b'\x02\x04\x05\xb4'))
        changed=packet(seq=999,ack=0,flags=2,options=b'\x02\x04\x05\x78')
        self.assertEqual(self.process(changed).outcome,'EXCLUDED');self.assertTrue(self.pipe.excluded)

    def test_duplicate_response_is_transport_replay_without_new_readiness(self):
        self.handshake();self.select();_,selected=pad.decode_frame(self.image)
        response=pad.build_frame(bytes.fromhex('0564004401000a00'),bytes([0xc0,0xc0,129,0,0])+selected[3:])
        raw=packet(response,seq=9000,ack=1055,reverse=True)
        self.assertTrue(self.process(raw).associated)
        replay=self.process(raw)
        self.assertFalse(replay.associated);self.assertEqual(replay.outcome,'RESPONSE_REPLAY')
        self.assertEqual(b''.join(rrc.parse(x).payload for x in replay.outputs),response)

    def test_ambiguous_close_and_future_ack_fault_without_erasing_images(self):
        for raw in (packet(seq=(1000+(1<<31))&MASK,flags=17),
                    packet(seq=9000,ack=1000+100000,flags=16,reverse=True)):
            with self.subTest(raw=raw.hex()):
                self.pipe=pre.Preprocessor(self.flow,7,self.decoy);self.handshake();self.select()
                result=self.process(raw)
                self.assertEqual(result.outcome,'TRANSPORT_FAULT');self.assertEqual(result.outputs,())
                self.assertEqual(len(self.pipe.ledger.entries),1)

    def test_reset_without_ack_does_not_interpret_irrelevant_ack_field(self):
        self.handshake(base=1<<31);self.select()
        reset=packet(seq=9000,ack=0,flags=4,reverse=True)
        result=self.process(reset)
        self.assertEqual(result.outcome,'CLOSED_TRANSLATED');self.assertEqual(result.outputs,(reset,))
        self.assertEqual(len(self.pipe.ledger.entries),1)

if __name__=='__main__':unittest.main()

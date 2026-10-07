"""Packet-derived reverse normalization against independent RequestLedger.

The accepted first-SELECT generator is the RED baseline until transport.py exists.
No register presets establish a successful mapping or native association.
"""
import copy
import importlib
import unittest
import test_m_prepare as mp
import test_e_prepare as ep
import test_n_ready as nr
from case4_transport import RequestLedger
from transport_source import TransportSource

MASK=0xffffffff


def roles():
    try:
        return importlib.import_module('transport').generate_roles()
    except ModuleNotFoundError as error:
        if error.name!='transport':raise
        return importlib.import_module('split').generate_roles()


def packet(ack,window,start=100,payload=b''):
    raw=bytearray(mp.vectors.packet(24 if payload else 16,901,ack,True,payload=payload))
    raw[48:50]=window.to_bytes(2,'big');raw[50:52]=b'\0\0'
    pseudo=raw[26:34]+bytes((0,6))+len(raw[34:]).to_bytes(2,'big')
    raw[50:52]=mp.vectors.checksum(pseudo+raw[34:]).to_bytes(2,'big')
    return bytes(raw)


def completed(start=100):
    r=roles();n=mp.Pipeline(r['n3.p4'],mp.vectors.topology(),include_dir=mp.HERE.parent)
    for port,frame in ((1,mp.vectors.packet(2,(start-1)&MASK,mss=1500)),(2,mp.vectors.packet(18,900,start,True,mss=1500)),(1,mp.vectors.packet(16,start,901))):
        assert not n.inject(port,frame).dropped
    selected=n.inject(1,mp.vectors.packet(24,start,901,payload=mp.vectors.native_select()))
    m=TransportSource(r['m3.p4']);m.install('forwarding',(196,),'route',(452,));m.install('forwarding',(198,),'route',(452,))
    m.install('connection',(mp.vectors.CLIENT,mp.vectors.SERVER,mp.vectors.CLIENT_PORT,mp.vectors.SERVER_PORT),'allow_connection',())
    # This is exact tuple configuration, not a packet/proof or geometry preset.
    if 'allow_reverse' in r['m3.p4']:
        m.install('connection',(mp.vectors.SERVER,mp.vectors.CLIENT,mp.vectors.SERVER_PORT,mp.vectors.CLIENT_PORT),'allow_reverse',())
    e=ep.e_source(r['e3.p4']);bridge=mp.WireSource(r['e3.p4']);f=ep.e_source(r['f.p4'])
    def service(raw,port):
        dropped,out=ep.EPrepare().execute(e,raw,port);assert not dropped
        dropped,out=mp.MPrepare().execute(bridge,out,port);assert not dropped
        return out
    dropped,prepared=mp.MPrepare().execute(m,selected.emitted[0][1]);assert not dropped
    ready=service(prepared,452)
    qualified,_=nr.NativeReady().one(n,ready);activate,_=nr.NativeReady().one(n,qualified[1])
    dropped,dirty=mp.MPrepare().execute(m,activate[1]);assert not dropped
    dropped,query=mp.MPrepare().execute(m,dirty,198);assert not dropped
    authority,_=nr.NativeReady().one(n,service(query,452))
    final,_=nr.NativeReady().one(n,service(authority[1],452))
    dropped,endpoint=ep.EPrepare().execute(f,final[1],2);assert not dropped
    terminal,_=nr.NativeReady().one(n,service(f.mirror_headers[0][1]+endpoint,453))
    drained,_=nr.NativeReady().one(n,service(terminal[1],453));nr.NativeReady().one(n,drained[1])
    assert n.state()['work']['phase']==9
    return n,m


def normalize(m,raw):
    """Execute actual private output; no expected normalization logic."""
    dropped,out=mp.MPrepare().execute(m,raw,199)
    if not dropped and m.env['tm.ucast_egress_port']==199:
        return mp.MPrepare().execute(m,out,199)
    return dropped,out


class ReverseTransport(unittest.TestCase):
    def test_snapshot_carries_actual_full_geometry_and_position_zero_wrap(self):
        for start in (0,100,0xffffffdd,0xfffffff0):
            n,m=completed(start);raw=packet((start+55)&MASK,65535,start)
            before=copy.deepcopy(m.cells)
            dropped,snapshot=mp.MPrepare().execute(m,raw,199)
            self.assertFalse(dropped);self.assertEqual(m.env['tm.ucast_egress_port'],199)
            self.assertEqual(snapshot[:4],bytes.fromhex('16c40006'))
            self.assertEqual(int.from_bytes(snapshot[12:16],'big'),before[('','geo_first')][0])
            self.assertEqual(int.from_bytes(snapshot[16:20],'big'),before[('','ledger_position')][0])
            self.assertEqual(snapshot[20:],raw)
            self.assertEqual(m.cells,before)
            dropped,mapped=mp.MPrepare().execute(m,snapshot,199)
            self.assertFalse(dropped)
            self.assertEqual(mapped[16:],packet((start+35)&MASK,65535,start))
            self.assertEqual(m.cells,before)

    def test_snapshot_geometry_words_are_reread_full_width_before_return(self):
        for field,offset in (('boundary',12),('position',16)):
            for mask in (1,0x80000000):
                n,m=completed();dropped,snapshot=mp.MPrepare().execute(m,packet(155,20),199)
                self.assertFalse(dropped)
                self.assertEqual(snapshot[20:],packet(155,20))
                bad=bytearray(snapshot)
                bad[offset:offset+4]=(int.from_bytes(bad[offset:offset+4],'big')^mask).to_bytes(4,'big')
                before=copy.deepcopy(m.cells)
                self.assertTrue(mp.MPrepare().execute(m,bytes(bad),199)[0],(field,mask))
                self.assertEqual(m.cells,before)

    def test_coherent_snapshot_coordinates_cannot_replace_current_geometry(self):
        # Keep boundary-position==35, so only actual full-cell rereads can
        # reject the changed record; an internal relation check is insufficient.
        for delta in (1,0x80000000):
            n,m=completed();dropped,snapshot=mp.MPrepare().execute(m,packet(155,20),199)
            self.assertFalse(dropped)
            bad=bytearray(snapshot)
            for offset in (12,16):
                bad[offset:offset+4]=((int.from_bytes(bad[offset:offset+4],'big')+delta)&MASK).to_bytes(4,'big')
            self.assertEqual((int.from_bytes(bad[12:16],'big')-int.from_bytes(bad[16:20],'big'))&MASK,35)
            before=copy.deepcopy(m.cells)
            self.assertTrue(mp.MPrepare().execute(m,bytes(bad),199)[0],delta)
            self.assertEqual(m.cells,before)

    def test_raw_reverse_requires_actual_snapshot_return_before_normalizing(self):
        n,m=completed();raw=packet(155,20);before=copy.deepcopy(m.cells)
        dropped,snapshot=mp.MPrepare().execute(m,raw,199)
        self.assertFalse(dropped);self.assertEqual(m.env['tm.ucast_egress_port'],199)
        self.assertEqual(snapshot[:4],bytes.fromhex('16c40006'))
        self.assertEqual(int.from_bytes(snapshot[4:8],'big'),before[('','reservation')][0]['generation'])
        self.assertEqual(int.from_bytes(snapshot[8:12],'big'),0x90001)
        self.assertEqual(snapshot[20:],raw)
        self.assertEqual(m.cells,before)
        # Withheld return cannot emit or alter state: only the real next visit maps.
        self.assertEqual(n.state()['work']['phase'],9)
        dropped,mapped=mp.MPrepare().execute(m,snapshot,199)
        self.assertFalse(dropped);self.assertEqual(m.env['tm.ucast_egress_port'],68)
        self.assertEqual(mapped[16:],packet(135,20))
        self.assertEqual(m.cells,before)

    def test_snapshot_foreign_full_refs_or_concurrent_publication_refuse_readonly(self):
        for fault in ('generation','owner','phase','tag_generation','context_epoch','reservation_generation','geometry','position'):
            n,m=completed();dropped,snapshot=mp.MPrepare().execute(m,packet(155,20),199)
            self.assertFalse(dropped);self.assertEqual(m.env['tm.ucast_egress_port'],199)
            snapshot=bytearray(snapshot)
            if fault in ('generation','owner'):
                offset=4 if fault=='generation' else 8
                snapshot[offset:offset+4]=(int.from_bytes(snapshot[offset:offset+4],'big')^0x80000000).to_bytes(4,'big')
            elif fault=='phase':m.cells[('','reservation')][0]['phase']=1
            elif fault=='tag_generation':m.cells[('','ledger_tag')][0]['generation']^=0x80000000
            elif fault=='context_epoch':m.cells[('','producer_context')][0]['epoch']^=0x80000000
            elif fault=='reservation_generation':m.cells[('','reservation')][0]['generation']^=0x80000000
            else:m.cells[('', 'geo_first' if fault=='geometry' else 'ledger_position')][0]^=0x80000000
            before=copy.deepcopy(m.cells)
            self.assertTrue(mp.MPrepare().execute(m,bytes(snapshot),199)[0],fault)
            self.assertEqual(m.cells,before,fault)

    def test_snapshot_revalidates_network_tuple_marker_and_nonzero_refs(self):
        for fault in ('tuple','tcp','marker','legacy12','zero_generation','zero_owner'):
            n,m=completed();dropped,snapshot=mp.MPrepare().execute(m,packet(155,20),199)
            self.assertFalse(dropped);self.assertEqual(m.env['tm.ucast_egress_port'],199)
            bad=bytearray(snapshot)
            if fault=='tuple':bad[20+34:20+36]=(1000).to_bytes(2,'big')
            elif fault=='tcp':bad[-1]^=1
            elif fault=='marker':bad[:4]=(0x16c40007).to_bytes(4,'big')
            elif fault=='legacy12':bad[:4]=(0x16c40005).to_bytes(4,'big');del bad[12:20]
            else:
                offset=4 if fault=='zero_generation' else 8;bad[offset:offset+4]=bytes(4)
            before=copy.deepcopy(m.cells)
            self.assertTrue(mp.MPrepare().execute(m,bytes(bad),199)[0],fault)
            self.assertEqual(m.cells,before,fault)

    def test_external_reverse_steers_before_any_n_mutation(self):
        n,m=completed();before=copy.deepcopy(n.src.cells)
        out=n.inject(2,packet(155,20))
        self.assertEqual(out.emitted,[(199,packet(155,20))])
        self.assertEqual(n.src.cells,before)

    def test_m_left_and_right_inverse_match_oracle_zero_wrap_and_boundaries(self):
        for start in (0,100,0xfffffff0):
            n,m=completed(start);ledger=RequestLedger(start)
            native=mp.vectors.native_select();image=mp.case4_padding.expand_control(native,mp.vectors.DECOY)[0]
            ledger.forward(start,native,image)
            for offset in (0,34,35,36,54,55,56,70):
                for window in (0,1,19,20,21,4096,65535):
                    with self.subTest(start=start,offset=offset,window=window):
                        ack=(start+offset)&MASK;raw=packet(ack,window,start)
                        before=copy.deepcopy(m.cells)
                        dropped,out=normalize(m,raw)
                        self.assertFalse(dropped,'published geometry refused')
                        self.assertEqual(m.cells,before,'normalization mutated bank')
                        self.assertEqual(m.env['tm.ucast_egress_port'],68)
                        self.assertEqual(out[:4],(1).to_bytes(4,'big'))
                        self.assertEqual(out[12:16],bytes.fromhex('00000004'))
                        frame=out[16:]
                        actual=(int.from_bytes(frame[42:46],'big'),int.from_bytes(frame[48:50],'big'))
                        self.assertEqual(actual,ledger.reverse(ack,window))
                        self.assertEqual(mp.folded(frame[26:34]+bytes((0,6))+len(frame[34:]).to_bytes(2,'big')+frame[34:]),65535)

    def test_normalized_ack_reaches_client_without_double_inverse(self):
        for start in (0,100,0xfffffff0):
            n,m=completed(start)
            for offset in (34,35,54,55):
                dropped,out=normalize(m,packet((start+offset)&MASK,0,start))
                self.assertFalse(dropped)
                result=n.inject(68,out);self.assertFalse(result.dropped,result.drop_reason)
                self.assertEqual(len(result.emitted),1);self.assertEqual(result.emitted[0][0],1)
                expected=(start+(34 if offset<55 else 35))&MASK
                self.assertEqual(int.from_bytes(result.emitted[0][1][42:46],'big'),expected)
                self.assertEqual(n.state()['owner'],0x120001)
                self.assertIn(n.state()['work']['phase'],(4,9))

    def test_actual_matching57_response_is_associated_and_forwarded_once(self):
        for start in (0,100,0xfffffff0):
            n,m=completed(start);payload=mp.vectors.native_response()
            raw=packet((start+55)&MASK,4096,start,payload)
            self.assertEqual(n.inject(2,raw).emitted,[(199,raw)])
            dropped,mapped=normalize(m,raw);self.assertFalse(dropped)
            result=n.inject(68,mapped);self.assertFalse(result.dropped,result.drop_reason)
            self.assertEqual(result.emitted,[(1,packet((start+35)&MASK,4096,start,payload))])
            self.assertEqual(n.state()['owner'],0xa0001)
            self.assertEqual(n.state()['work']['phase'],4)

    def test_foreign_epoch_uses_genuine_current_epoch_abort_and_loss_keeps_pin(self):
        n,m=completed();dropped,mapped=normalize(m,packet(155,0))
        self.assertFalse(dropped);bad=bytearray(mapped);bad[:4]=(0x80000001).to_bytes(4,'big')
        before=copy.deepcopy(n.src.cells)
        _,abort,reason=n.run_pass(1,68,bytes(bad));self.assertIsNotNone(abort,reason)
        self.assertEqual(abort[0],68);self.assertEqual(abort[1][:4],bytes.fromhex('80000001'))
        self.assertEqual(abort[1][12:16],bytes.fromhex('01150004'))
        self.assertEqual(n.state()['work']['phase'],1)
        # Withhold the real return: no other packet invents its completion.
        lost=copy.deepcopy(n.src.cells)
        self.assertTrue(n.inject(68,mapped).dropped)
        self.assertEqual(n.state()['work'],{'generation':5,'phase':1})
        for name in ('owner','epoch','client','server'):
            self.assertEqual(n.state()[name],before[('',name)][0])
        _,stamped,reason=n.run_pass(1,68,abort[1]);self.assertIsNotNone(stamped,reason)
        self.assertEqual(stamped[1][:4],bytes.fromhex('00000001'))
        self.assertEqual(stamped[1][12:16],bytes.fromhex('02ff0004'))
        self.assertEqual(n.state()['work']['phase'],2)
        result=n.inject(68,stamped[1]);self.assertTrue(result.dropped)
        self.assertEqual(n.state()['work']['phase'],4)
        for key,value in before.items():
            if key[1] not in ('counter','work','active_work_generation','count_busy') and key[0]!='work':
                self.assertEqual(n.src.cells[key],value,key)

    def test_invalid_dnp3_or_profile_normalized_return_cannot_leak_prefix(self):
        for fault in ('crc','profile','tuple','tcp'):
            n,m=completed();payload=bytearray(mp.vectors.native_response())
            if fault=='crc':payload[-1]^=1
            elif fault=='profile':
                head,user=mp.case4_padding.decode_frame(payload);user=bytearray(user);user[2]=0x82
                payload=mp.case4_padding.build_frame(head[:8],user)
            raw=packet(155,4096,payload=bytes(payload))
            dropped,out=normalize(m,raw);self.assertFalse(dropped)
            if fault=='tuple':
                out=bytearray(out);out[16+34:16+36]=(1000).to_bytes(2,'big')
            elif fault=='tcp':out=out[:-1]+bytes((out[-1]^1,))
            before=copy.deepcopy(n.src.cells)
            result=n.inject(68,bytes(out));self.assertTrue(result.dropped,fault)
            self.assertEqual(result.emitted,[])
            self.assertEqual(n.src.cells,before,fault)

    def test_malformed_private_return_stops_one_pass_and_keeps_actual_pin(self):
        for offset,size,value in ((0,4,0),(4,4,0),(14,2,5)):
            n,m=completed();_,mapped=normalize(m,packet(155,0))
            foreign=bytearray(mapped);foreign[:4]=(0x80000001).to_bytes(4,'big')
            _,abort,_=n.run_pass(1,68,bytes(foreign));self.assertIsNotNone(abort)
            bad=bytearray(mapped);bad[offset:offset+size]=value.to_bytes(size,'big')
            before=copy.deepcopy(n.src.cells)
            action,out,reason=n.run_pass(1,68,bytes(bad))
            self.assertIsNone(out,(offset,reason))
            self.assertEqual(n.src.cells,before)
            self.assertEqual(n.state()['work']['phase'],1)

    def test_each_genuine_abort_return_loss_keeps_pin_and_wrong_generation_cannot_advance(self):
        for lost_stage in (1,2,3):
            n,m=completed();_,mapped=normalize(m,packet(155,0))
            bad=bytearray(mapped);bad[:4]=(0x80000001).to_bytes(4,'big')
            _,out,_=n.run_pass(1,68,bytes(bad))
            for stage in range(1,lost_stage):
                _,out,reason=n.run_pass(1,68,out[1]);self.assertIsNotNone(out,reason)
            self.assertEqual(n.state()['work']['phase'],lost_stage)
            before=copy.deepcopy(n.src.cells)
            for gen in (4,0x80000005):
                stale=bytearray(out[1]);stale[4:8]=gen.to_bytes(4,'big')
                _,foreign,_=n.run_pass(1,68,bytes(stale));self.assertIsNone(foreign)
                self.assertEqual(n.src.cells,before)
            # No timeout/counter reset manufactures the withheld return.
            self.assertEqual(n.state()['owner'],0x120001)
            result=n.inject(68,out[1]);self.assertTrue(result.dropped)
            self.assertEqual(n.state()['work']['phase'],4)
            self.assertEqual(n.state()['owner'],0x120001)

    def test_genuine_fin_before_or_after_epoch_stamp_drains_only_real_return(self):
        for close_stage in (1,2,3):
            with self.subTest(close_stage=close_stage):
                n,m=completed();_,mapped=normalize(m,packet(155,0))
                foreign=bytearray(mapped);foreign[:4]=(0x80000001).to_bytes(4,'big')
                _,out,reason=n.run_pass(1,68,bytes(foreign));self.assertIsNotNone(out,reason)
                for _ in range(1,close_stage):
                    _,out,reason=n.run_pass(1,68,out[1]);self.assertIsNotNone(out,reason)
                close=mp.vectors.packet(17,135,901)
                original=n.inject(1,close)
                self.assertEqual(len(original.emitted),1)
                self.assertEqual(original.emitted[0][0],325,'existing typed reset forwarding to T')
                self.assertEqual(original.emitted[0][1][-len(close):],close)
                self.assertEqual(n.state()['owner'],0x60001)
                self.assertEqual(n.state()['work']['phase'],close_stage)
                pinned=copy.deepcopy(n.src.cells)
                # A withheld real return leaves quarantine and Work pinned.
                self.assertEqual(n.src.cells,pinned)
                result=n.inject(68,out[1]);self.assertTrue(result.dropped)
                self.assertEqual(result.emitted,[])
                self.assertEqual(n.state()['work']['phase'],4)
                self.assertEqual(n.state()['owner'],0x60001)
                self.assertEqual(n.state()['epoch'],1)
                for key,value in pinned.items():
                    if key[1] not in ('work','count_busy') and key[0]!='work':
                        self.assertEqual(n.src.cells[key],value,key)

    def test_stamp_rejects_other_full_width_expected_owner_changes(self):
        for owner in (0x110001,0x120002,0x80120001,0x60001):
            n,m=completed();_,mapped=normalize(m,packet(155,0))
            foreign=bytearray(mapped);foreign[:4]=(0x80000001).to_bytes(4,'big')
            _,out,_=n.run_pass(1,68,bytes(foreign))
            altered=bytearray(out[1]);altered[8:12]=owner.to_bytes(4,'big')
            _,emitted,_=n.run_pass(1,68,bytes(altered))
            self.assertIsNone(emitted,hex(owner))
            self.assertEqual(n.state()['owner'],0x120001)
            self.assertEqual(n.state()['work']['phase'],2)

    def test_stamped_abort_epoch_pair_qualifies_before_work_advance(self):
        for stage in (2,3):
            for field in (0,8):
                n,m=completed();_,mapped=normalize(m,packet(155,0))
                foreign=bytearray(mapped);foreign[:4]=(0x80000001).to_bytes(4,'big')
                _,out,_=n.run_pass(1,68,bytes(foreign))
                for _ in range(1,stage):
                    _,out,reason=n.run_pass(1,68,out[1]);self.assertIsNotNone(out,reason)
                self.assertEqual(out[1][:4],out[1][8:12],'actual N stamp pair')
                bad=bytearray(out[1]);bad[field:field+4]=(0x80000001).to_bytes(4,'big')
                before=copy.deepcopy(n.src.cells)
                _,emitted,_=n.run_pass(1,68,bytes(bad));self.assertIsNone(emitted)
                self.assertEqual(n.src.cells,before)
                result=n.inject(68,out[1]);self.assertTrue(result.dropped)
                self.assertEqual(n.state()['work']['phase'],4)

    def test_valid_forward_tuple_is_not_reverse_admission(self):
        n,m=completed();before=copy.deepcopy(m.cells)
        frame=mp.vectors.packet(16,155,901)
        self.assertTrue(mp.MPrepare().execute(m,frame,199)[0])
        self.assertEqual(m.cells,before)

    def test_foreign_tuple_network_and_incomplete_ledger_refuse_without_m_mutation(self):
        for fault in ('tuple','tcp','tag','context','reservation','geometry'):
            n,m=completed();raw=bytearray(packet(155,20))
            if fault=='tuple':raw[34:36]=(1000).to_bytes(2,'big')
            elif fault=='tcp':raw[-1]^=1
            elif fault=='tag':m.cells[('','ledger_tag')][0]['generation']^=0x80000000
            elif fault=='context':m.cells[('','producer_context')][0]['epoch']^=0x80000000
            elif fault=='reservation':m.cells[('','reservation')][0]['phase']=1
            else:m.cells[('','geo_first')][0]^=0x80000000
            before=copy.deepcopy(m.cells)
            self.assertTrue(normalize(m,bytes(raw))[0],fault)
            self.assertEqual(m.cells,before)


if __name__=='__main__':unittest.main()

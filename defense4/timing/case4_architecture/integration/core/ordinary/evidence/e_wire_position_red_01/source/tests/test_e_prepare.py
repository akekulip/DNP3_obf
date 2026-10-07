"""Execute actual E parser/actions/banks/deparser, not expected cache logic."""
import copy
import re
import unittest
import test_m_prepare as mp
HERE=mp.HERE
vectors=mp.vectors
from source_wire import WireSource


def e_source():
    text=(HERE.parent/'e.p4').read_text()
    # Select the actual egress source control for the existing AST engine.
    names={'IgParser':'UnusedParser','Ingress':'UnusedIngress','IgDeparser':'UnusedDeparser',
           'EgParser':'IgParser','Egress':'Ingress','EgDeparser':'IgDeparser'}
    text=re.sub(r'\b('+ '|'.join(names)+r')\b',lambda m:names[m[0]],text)
    result=WireSource(text);result.width['eg.egress_port']=9
    result.install('connection',(vectors.CLIENT,vectors.SERVER,vectors.CLIENT_PORT,vectors.SERVER_PORT),'allow_connection',())
    return result


class EPrepare(unittest.TestCase):
    def prepared(self,start=0):
        helper=mp.MPrepare();raw,_=helper.handoff(start)
        dropped,out=helper.execute(helper.receiver(),raw)
        self.assertFalse(dropped);return out

    def execute(self,e,raw,port=68):
        e.begin_pass(0);e.env['eg.egress_port']=port
        accepted,cursor=e.packet_parser(raw)
        if not accepted:return True,b''
        e.apply_control()
        return bool(e.env.get('md.drop_ctl',0)&1),e.render_wire()+raw[cursor:]

    def test_all14_image_words_stored_before_typed_ready_with_full_identity(self):
        for start in (0,100,0xfffffff0):
            with self.subTest(start=start):
                raw=self.prepared(start);e=e_source()
                dropped,out=self.execute(e,raw)
                self.assertFalse(dropped)
                self.assertEqual(out[:12],raw[:12]);self.assertEqual(out[16:],raw[16:])
                self.assertEqual(out[12:16],bytes.fromhex('05140002'))
                words=[int.from_bytes(raw[78+i*4:78+i*4+4],'big') for i in range(13)]
                words.append(int.from_bytes(raw[130:133],'big'))
                for i,word in enumerate(words):self.assertEqual(e.cells[('', 'image_%d'%i)][0],word)
                self.assertEqual(e.cells[('', 'reservation')][0]['phase'],1)
                self.assertEqual(e.cells[('', 'wire_position')][0],start)
                self.assertEqual(e.cells[('', 'cache_tag')][0],{'epoch':int.from_bytes(raw[:4],'big'),'generation':int.from_bytes(raw[16:20],'big')})
                self.assertEqual(e.cells[('', 'cache_owner')][0],int.from_bytes(raw[20:24],'big'))
                before=copy.deepcopy(e.cells)
                dropped,_=self.execute(e,raw)
                self.assertTrue(dropped);self.assertEqual(e.cells,before)

    def test_every_actual_store_completion_is_required_for_publication(self):
        raw=self.prepared()
        for missing in range(14):
            e=e_source();e.begin_pass(0);e.env['eg.egress_port']=68
            accepted,_=e.packet_parser(raw);self.assertTrue(accepted)
            # Invoke actual write actions; a missing completed store prevents publication.
            e.frame=__import__('interp_ext').Frame(e.controls['Ingress'],'')
            for i in range(14):
                if i!=missing:e.apply_table('store_%d_t'%i)
            e.apply_table('publish_tag_t');e.apply_table('publish_owner_t');e.apply_table('ready_t')
            self.assertEqual(e.cells[('','cache_tag')][0],{'epoch':0,'generation':0})
            self.assertEqual(e.cells[('','cache_owner')][0],0)
            self.assertTrue(e.env.get('md.drop_ctl',0)&1)

    def test_malformed_full_identity_or_network_never_changes_any_bank(self):
        raw=self.prepared();cases=[]
        for begin,end,value in ((0,4,0),(4,8,0),(8,12,0x110001),(12,14,0x0614),(14,16,1),(16,20,2),(20,24,0x90002)):
            bad=bytearray(raw);bad[begin:end]=value.to_bytes(end-begin,'big');cases.append(bytes(bad))
        bad=bytearray(raw);bad[-1]^=1;cases.append(bytes(bad))
        for bad in cases:
            e=e_source();before=copy.deepcopy(e.cells)
            dropped,_=self.execute(e,bad)
            self.assertTrue(dropped);self.assertEqual(e.cells,before)
        e=e_source();before=copy.deepcopy(e.cells)
        dropped,_=self.execute(e,raw,1);self.assertTrue(dropped);self.assertEqual(e.cells,before)


if __name__=='__main__':unittest.main()

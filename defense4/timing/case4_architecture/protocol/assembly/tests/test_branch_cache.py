"""Execute actual root padding and actual cache guard/body with scoped control callbacks."""
import sys
import re
import unittest
from pathlib import Path
HERE=Path(__file__).resolve().parents[1];sys.path.insert(0,str(HERE));sys.path.insert(0,str(HERE.parent));sys.path.insert(0,str(HERE.parent.parents[1]/'framework/size'))
from assembly_eval import Source
from source_eval import block
import test_denied_writer as denied
class CacheScope(Source):
    def register(self,name,index):
        self.calls.append((name,index))
        old=self.text;self.text=re.sub(r'\br\b','rv',self.text)
        try:return super().register(name,index)
        finally:self.text=old
    def action(self,name,args=()):
        if name=='cache_apply':self.run(block(block(self.text,'control Cache'),'apply{'));return
        return super().action(name,args)
class BranchCache(unittest.TestCase):
    def test_actual_denial_gate_prevents_shared_bank_mutation(self):
        path=HERE.parent.parents[0]/'integration/branch_cache.p4';text=path.read_text()
        prefix=text[:text.index('header forward_eth_h')].replace('padding_headers_t','headers_t').replace('padding_meta_t','meta_t')
        cache='struct headers_t{}\nstruct meta_t{'+block(text,'struct cache_meta_t')+'}\ncontrol Cache(inout meta_t m){'+block(text,'control Cache')+'}'
        marker='if(md.drop_ctl==3w0&&m.padding.changed==1w1)'
        guard=marker+'{'+block(block(text,'control Ingress('),marker)+'}'
        guard=guard.replace('m.padding.image_word','m.pad_word').replace('m.padding.changed','m.pad_changed').replace('m.padding.image_slot','m.pad_slot').replace('m.cache.','m.').replace('cache.apply(m.cache)','cache_apply()')
        for allowed in (False,True):
            p=denied.DeniedWriter().load(prefix);p.runtime['forwarding']=('route',(12,)) if allowed else ('deny',())
            p.run(block(block(prefix,'control padding_Ingress'),'apply{'))
            s=CacheScope(cache,{'md.drop_ctl':p.env.get('md.drop_ctl',0),'m.pad_changed':p.env['m.changed'],'m.pad_slot':p.env['m.image_slot'],**{f'm.pad_word{i}':p.env[f'm.image_word{i}'] for i in range(14)}})
            s.calls=[];s.run(guard)
            self.assertEqual(len(s.calls),14 if allowed else 0)
            self.assertEqual(len(s.registers),14 if allowed else 0)
            if allowed:
                for i in range(14):self.assertEqual(s.registers[(f'image_{i}',0)],p.env[f'm.image_word{i}'])
    def test_actual_replay_denial_gate_prevents_shared_reads(self):
        text=(HERE.parent.parents[0]/'integration/branch_cache.p4').read_text()
        prefix=text[text.index('header replay_eth_h'):text.index('struct cache_meta_t')].replace('replay_headers_t','headers_t').replace('replay_meta_t','meta_t')
        cache=prefix+'\nstruct cache_meta_t{'+block(text,'struct cache_meta_t')+'}\ncontrol Cache(inout cache_meta_t m){'+block(text,'control Cache')+'}'
        marker='if(md.drop_ctl==3w0&&m.replay.render==1w1)'
        guard=marker+'{'+block(block(text,'control Ingress('),marker)+'}'
        guard=guard.replace('m.cache.','m.').replace('m.replay.','m.out_').replace('hdr.replay.','hdr.').replace('cache.apply(m.cache)','cache_apply()')
        for allowed,matching in ((False,True),(True,False),(True,True)):
            fields={'m.parsed':1,'m.ip_error':False,'m.tcp_sum':0xffeb,'hdr.native.data':7 if matching else 8}
            inner=Source(prefix,fields,{'forwarding':('route',(12,)) if allowed else ('deny',()),'replay':('cached',(1000,7,0))})
            inner.run(block(block(prefix,'control replay_Ingress'),'apply{'))
            s=CacheScope(cache,{'md.drop_ctl':inner.env.get('md.drop_ctl',0),**{k.replace('m.','m.out_'):v for k,v in inner.env.items() if k.startswith('m.')}},registers={(f'image_{i}',0):0x12345600+i for i in range(14)})
            s.calls=[];s.run(guard);self.assertEqual(len(s.calls),14 if allowed and matching else 0)
            if allowed and matching:
                self.assertEqual(s.env['hdr.image.w13'],(0x12345600+13)>>8);self.assertEqual(s.env['hdr.tcp.seq'],1000)

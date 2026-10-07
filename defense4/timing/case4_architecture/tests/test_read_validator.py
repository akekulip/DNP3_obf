"""Exact frozen READ profile, supporting control-fragment differential only."""
import sys
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'protocol'))
sys.path.insert(0,str(ROOT.parent/'framework/size'))
from source_eval import block
from source_control import Source
import case4_padding as codec


def fields(source,payload,response):
    result={'m.parsed':1,'m.ip_error':False,'m.tcp_sum':0xffeb,'hdr.ip.ttl':64}
    names=['dl','first','second','tail'] if response else ['dl','request']
    cursor=0
    for header in names:
        for field,width in source.width.items():
            if not field.startswith('hdr.'+header+'.'):continue
            size=width//8
            result[field]=int.from_bytes(payload[cursor:cursor+size],'big');cursor+=size
    if cursor!=len(payload):raise AssertionError('source header does not consume the full frame')
    return result


class ReadValidator(unittest.TestCase):
    def setUp(self):
        self.text=(ROOT/'integration/read/validator.p4').read_text()
        self.request=bytes.fromhex('05640dc400000100f387c0c0010a020000165a2c')
        self.response=codec.build_frame(bytes.fromhex('0564004401000000'),
            bytes.fromhex('c0c08180000a02000016')+bytes(range(23)))
        self.assertEqual(len(self.request),20)
        self.assertEqual(len(self.response),49)

    def observe(self,payload,response=False,admitted=True,parser_error=0):
        source=Source(self.text)
        source.env.update(fields(source,payload,response))
        source.env['m.kind']=2 if response else 1
        source.env['p.parser_err']=parser_error
        links=(0x0100,0) if response else (0,0x0100)
        source.runtime={'connection':('reverse' if response else 'forward',(9,*links))}
        if admitted:source.runtime['forwarding']=('route',(64,))
        source.run(block(block(self.text,'control Ingress'),'\n apply{'))
        return source

    def test_complete_native_request_and_response_are_observed_without_rewrite(self):
        for payload,response in ((self.request,False),(self.response,True)):
            source=self.observe(payload,response)
            self.assertEqual(source.registers[('qualified',int(response))],1)
            names=['dl','first','second','tail'] if response else ['dl','request']
            self.assertEqual(b''.join(source.render(name) for name in names),payload)

    def test_every_crc_and_crc_valid_wrong_profile_refused(self):
        for payload,response,positions in ((self.request,False,(8,18)),(self.response,True,(8,26,44,47))):
            for position in positions:
                bad=bytearray(payload);bad[position]^=1
                self.assertEqual(self.observe(bytes(bad),response).registers,{})
        head,user=codec.decode_frame(self.request)
        bad=bytearray(user);bad[3]=11
        self.assertEqual(self.observe(codec.build_frame(head,bytes(bad))).registers,{})

    def test_denied_forwarding_and_invalid_network_never_mutate(self):
        self.assertEqual(self.observe(self.request,admitted=False).registers,{})
        source=Source(self.text);source.env.update(fields(source,self.request,False))
        source.env.update({'m.kind':1,'m.ip_error':1})
        source.runtime={'forwarding':('route',(64,)),'connection':('forward',(64,0,0x0100))}
        source.run(block(block(self.text,'control Ingress'),'\n apply{'))
        self.assertEqual(source.registers,{})

    def test_crc_valid_wrong_link_addresses_never_count_as_profile(self):
        for payload,response in ((self.request,False),(self.response,True)):
            head,user=codec.decode_frame(payload)
            for offset in (4,6):
                wrong=bytearray(head);wrong[offset]^=2
                self.assertEqual(self.observe(codec.build_frame(bytes(wrong),user),response).registers,{})

    def test_target_parser_error_refuses_even_complete_valid_bytes(self):
        for payload,response in ((self.request,False),(self.response,True)):
            self.assertEqual(self.observe(payload,response,parser_error=1).registers,{})

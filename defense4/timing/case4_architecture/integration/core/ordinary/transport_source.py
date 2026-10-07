"""Execute the candidate's actual third parser Checksum field lists.

The frozen source interpreter recognizes only ic/tc. This named extension adds
rc using the same existing Checksum semantics, never mapping/expected logic.
"""
import re
from interp_ext import ParserError
from source_wire import WireSource


class TransportSource(WireSource):
    def __init__(self,text,include_dir=None):
        # Actual standard packet lookahead, with its explicit source width.
        text=re.sub(r'pkt\.lookahead<bit<(\d+)>>\(\)',r'pkt.lookahead_bits(\1)',text)
        super().__init__(text,include_dir)

    def pkt_call(self,method,args):
        if method=='lookahead_bits':
            width=self.ev(args[0])[0]
            if width%8:raise ValueError('lookahead requires byte-aligned width')
            size=width//8
            if self.cursor+size>len(self.raw):raise ParserError('truncated lookahead')
            return int.from_bytes(self.raw[self.cursor:self.cursor+size],'big'),width
        return super().pkt_call(method,args)

    def call(self,path,args,node=None):
        owner,_,method=path.rpartition('.')
        if owner in ('rc','rcd') and self.csum is not None:
            self.csum.setdefault(owner,bytearray())
            return self.csum_call(owner,method,args)
        return super().call(path,args,node)

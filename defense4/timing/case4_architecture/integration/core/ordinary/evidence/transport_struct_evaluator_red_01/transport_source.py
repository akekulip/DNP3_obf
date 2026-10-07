"""Execute the candidate's actual third parser Checksum field lists.

The frozen source interpreter recognizes only ic/tc. This named extension adds
rc using the same existing Checksum semantics, never mapping/expected logic.
"""
from source_wire import WireSource


class TransportSource(WireSource):
    def call(self,path,args,node=None):
        owner,_,method=path.rpartition('.')
        if owner in ('rc','rcd') and self.csum is not None:
            self.csum.setdefault(owner,bytearray())
            return self.csum_call(owner,method,args)
        return super().call(path,args,node)

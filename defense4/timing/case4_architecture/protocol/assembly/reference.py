"""Independent bounded expected assembly; no TNA/endpoint proof."""
from __future__ import annotations
from dataclasses import dataclass,field
MASK=0xffffffff
@dataclass
class Assembly:
    generation:int
    origin:int|None=None
    data:bytearray=field(default_factory=lambda:bytearray(35))
    seen:int=0
    fault:bool=False
    def add(self,generation,offset,data,now,hops=0):
        if generation!=self.generation:return 'foreign'
        if self.fault:return 'fault'
        if self.origin is None:self.origin=now
        if (now-self.origin)&MASK>=30_000_000 or hops>16 or offset<0 or not data or offset+len(data)>35:
            self.fault=True;return 'fault'
        for i,byte in enumerate(data,offset):
            if self.seen>>i&1 and self.data[i]!=byte:self.fault=True;return 'fault'
        for i,byte in enumerate(data,offset):self.data[i]=byte;self.seen|=1<<i
        return 'complete' if self.seen==(1<<35)-1 else 'pending'

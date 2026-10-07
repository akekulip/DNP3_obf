"""Exact-byte expected records for offline target materialization experiments."""
from dataclasses import dataclass
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'framework/size'))
import case4_padding as codec

@dataclass(frozen=True)
class ExactImage:
    image: bytes
    @classmethod
    def capture(cls,image):
        codec.decode_frame(image)
        if len(image)!=55:raise ValueError('fixed 55-byte image required')
        return cls(bytes(image))
    def render(self):return self.image
    def replay(self,offset,length):
        if not 0<=offset<35 or not 1<=length<=35-offset:raise ValueError('native cached slice required')
        # Native final byte carries the growth. No autonomous packet generation.
        end=offset+length
        return self.image[offset:end+20 if end==35 else end]
    def words(self):
        data=self.image+b'\0'
        return tuple(int.from_bytes(data[i:i+4],'big') for i in range(0,56,4))

@dataclass(frozen=True)
class Canonical:
    header: bytes
    transport: int
    application: int
    function: int
    native_objects: bytes
    decoy: bytes
    @classmethod
    def capture(cls,native,decoy):
        head,user=codec.decode_frame(native)
        expanded,delta=codec.expand_control(native,decoy)
        if delta!=20:raise ValueError('eligible native control required')
        return cls(head,user[0],user[1],user[2],user[3:],decoy.index.to_bytes(2,'little')+decoy.body)
    def render(self):
        user=bytes((self.transport,self.application,self.function))+self.native_objects
        user+=bytes.fromhex('0c01280100')+self.decoy
        return codec.build_frame(self.header,user)
    def replay(self,offset,length):return ExactImage.capture(self.render()).replay(offset,length)

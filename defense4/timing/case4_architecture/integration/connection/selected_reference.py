"""Packet-backed selected-context reference, not a target connection producer.

Uses the independent Connection oracle's established epoch and exact TCP positions.
Actual target epoch composition, bounded fragments and verified retirement remain
required; no supplied valid flag or adjacent-row inference admits a control phase.
"""
from dataclasses import dataclass, replace
import hashlib
from reference import Envelope, MASK32, parse_packet
from case4_padding import decode_frame, expand_control


@dataclass(frozen=True)
class SelectedRecord:
    connection_epoch: int
    work_generation: int
    native_start: int
    native_end: int
    server_start: int
    app_sequence: int
    header: bytes
    objects: bytes
    expanded_objects: bytes


class SelectedPublisher:
    def __init__(self,connection,decoy):
        self.connection=connection;self.decoy=decoy
        self.work=self.scratch=self.record=None
        self.accepted=False

    def snapshot(self):
        return dict(connection=self.connection.snapshot(),work=None if self.work is None else dict(self.work),
            scratch=self.scratch,record=self.record,accepted=self.accepted)

    def _control(self,raw,port,operation):
        if port not in self.connection.allowed_ports:
            raise ValueError('unconfigured ingress')
        p=parse_packet(raw)
        if p.flow!=self.connection.flow or p.flags not in (16,24) or p.mss is not None:
            raise ValueError('supported master control required')
        head,user=decode_frame(p.payload)
        if (len(p.payload)!=35 or head[3]!=0xc4 or len(user)!=21 or
                user[0]&0xc0!=0xc0 or user[1]&0xf0!=0xc0 or user[2]!=operation or
                user[3:8]!=bytes.fromhex('0c01280100') or user[-1]!=0):
            raise ValueError('unsupported native control profile')
        image,delta=expand_control(p.payload,self.decoy)
        if delta!=20:
            raise ValueError('configured decoy must differ from actual real index')
        return p,head,user,decode_frame(image)[1][3:]

    def begin_select(self,raw,port):
        c=self.connection
        if c.phase!=5 or c.work is not None or self.work is not None or self.record is not None or c.work_counter==MASK32:
            return None
        try:p,head,user,objects=self._control(raw,port,3)
        except ValueError:return None
        if p.seq!=c.client_next or p.ack!=c.server_next:return None
        c.work_counter+=1
        e=Envelope(c.epoch,c.work_counter,c.cell,'select',raw,stage='write')
        self.work=dict(epoch=e.epoch,generation=e.work_generation,cell=e.expected_cell,
            image_sha256=hashlib.sha256(raw).hexdigest(),stage='write',aborted=False)
        c.work=dict(self.work,producer='selected')
        return e

    def advance(self,e):
        if e.outcome is not None:return e
        w=self.work;c=self.connection
        if (w is None or e.epoch!=w['epoch'] or e.work_generation!=w['generation'] or
                e.expected_cell!=w['cell'] or e.stage!=w['stage'] or
                hashlib.sha256(e.original).hexdigest()!=w['image_sha256']):
            return replace(e,outcome='refused')
        current=c.phase==5 and c.epoch==e.epoch and c.cell==e.expected_cell
        if not current:w['aborted']=True
        if e.stage=='write':
            if not w['aborted']:
                p,head,user,objects=self._control(e.original,next(iter(c.allowed_ports)),3)
                self.scratch=SelectedRecord(e.epoch,e.work_generation,p.seq,(p.seq+35)&MASK32,
                    p.ack,user[1]&15,head,user[3:],objects)
            w['stage']='publish';return replace(e,stage='publish')
        if e.stage=='publish':
            if not w['aborted']:
                self.record=self.scratch;c.client_next=self.record.native_end
            w['stage']='terminal';return replace(e,stage='terminal')
        aborted=w['aborted'];self.work=None;self.scratch=None;c.work=None
        return replace(e,outcome='refused' if aborted else'forward')

    def accept_select_response(self,raw,port):
        r=self.record;c=self.connection
        if r is None or self.work is not None or c.phase!=5 or c.epoch!=r.connection_epoch or port not in c.allowed_ports:
            return False
        try:
            p=parse_packet(raw);head,user=decode_frame(p.payload)
        except ValueError:return False
        if (p.flow!=c.reverse or p.flags not in (16,24) or p.mss is not None or
                p.seq!=r.server_start or p.ack!=r.native_end or len(p.payload)!=57 or
                head[3]!=0x44 or head[4:6]!=r.header[6:8] or head[6:8]!=r.header[4:6] or
                len(user)!=41 or user[0]&0xc0!=0xc0 or user[1]!=0xc0|r.app_sequence or
                user[2:5]!=bytes((0x81,0,0)) or user[5:]!=r.expanded_objects):
            return False
        self.accepted=True;c.server_next=(p.seq+57)&MASK32
        return True

    def admit_operate(self,raw,port,*,policy_enabled=True):
        r=self.record;c=self.connection
        if not policy_enabled or not self.accepted or r is None or c.phase!=5 or c.epoch!=r.connection_epoch:
            return False
        try:p,head,user,objects=self._control(raw,port,4)
        except ValueError:return False
        return (p.seq==r.native_end and p.ack==c.server_next and head[4:8]==r.header[4:8]
            and user[1]&15==(r.app_sequence+1)&15 and user[3:]==r.objects and objects==r.expanded_objects)

"""Independent bounded connection/producer oracle over actual Ethernet bytes.

No device access or target-model claim. This oracle accepts a final ACK carrying
one CRC-valid native SELECT; the isolated MSS P4 candidate does not yet implement
that data-bearing path. FIN/RST only quarantine: verified retirement/reuse,
stream translation, general options/assembly and hardware acquisition are absent.
"""
from __future__ import annotations
from dataclasses import dataclass, replace
import hashlib
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / 'framework/size'))
from case4_padding import decode_frame

MASK32 = 0xffffffff


def _checksum(data):
    if len(data) % 2:
        data += b'\0'
    total = sum(struct.unpack('!'+'H'*(len(data)//2), data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


@dataclass(frozen=True)
class Packet:
    flow: tuple
    flags: int
    seq: int
    ack: int
    payload: bytes
    mss: int | None


def parse_packet(raw):
    if len(raw) < 54 or raw[12:14] != b'\x08\x00':
        raise ValueError('complete untagged IPv4/TCP required')
    ip = raw[14:34]
    size = int.from_bytes(ip[2:4], 'big')
    if (ip[0] != 0x45 or ip[9] != 6 or ip[8] == 0 or _checksum(ip) != 0
            or int.from_bytes(ip[6:8], 'big') not in (0, 0x4000)
            or size < 40 or len(raw) < 14+size):
        raise ValueError('invalid IPv4 envelope')
    tcp = raw[34:14+size]
    sport, dport, seq, ack = struct.unpack('!HHII', tcp[:12])
    src, dst = struct.unpack('!II', ip[12:20])
    pseudo = struct.pack('!IIBBH', src, dst, 0, 6, len(tcp))
    header_size = (tcp[12] >> 4)*4
    if (header_size not in (20,24) or len(tcp) < header_size or tcp[12] & 15
            or tcp[18:20] != b'\0\0' or _checksum(pseudo+tcp) != 0):
        raise ValueError('invalid supported TCP envelope')
    mss = None
    if header_size == 24:
        if tcp[20:22] != b'\x02\x04':
            raise ValueError('unsupported TCP options')
        mss = int.from_bytes(tcp[22:24], 'big')
    return Packet((src,dst,sport,dport),tcp[13],seq,ack,tcp[header_size:],mss)


def parse_envelope(raw):
    """Decode the isolated pure-handshake 16-byte private return contract.

    This validates bytes, not the hardware port provenance or WorkRecord pin.
    Those require actual topology and the current atomic-generation check.
    """
    if len(raw)<16:
        raise ValueError('complete private prefix required')
    epoch,generation,expected,event,reserved=struct.unpack('!IIIHH',raw[:16])
    allowed={0x101,0x102,0x103,0x104,0x1ff,0x201,0x202,0x203,0x2ff,
        0x301,0x302,0x303,0x3ff}
    if not epoch or not generation or reserved or event not in allowed:
        raise ValueError('invalid private return identity/stage/event')
    packet=parse_packet(raw[16:])
    if packet.payload:
        raise ValueError('isolated target handshake does not parse SELECT payload')
    kind=1 if packet.flags==2 and packet.mss is not None else (
        2 if packet.flags==18 and packet.mss is not None else (
        3 if packet.flags==16 and packet.mss is None else (
        4 if packet.flags in (17,20,4) and packet.mss is None else 0)))
    if not kind or event&255 not in (kind,255):
        raise ValueError('private event differs from the retained actual packet')
    return (epoch,generation,expected,event),packet


def _select(payload):
    head,user = decode_frame(payload)
    if (len(payload) != 35 or head[3] != 0xc4 or len(user) != 21
            or user[0] & 0xc0 != 0xc0 or user[1] & 0xf0 != 0xc0
            or user[2] != 3 or user[3:8] != bytes.fromhex('0c01280100') or user[-1] != 0):
        raise ValueError('final ACK payload must be the complete supported SELECT')
    return user


@dataclass(frozen=True)
class Envelope:
    epoch: int
    work_generation: int
    expected_cell: int
    event: str
    original: bytes
    stage: str = 'claim'
    outcome: str | None = None


class Connection:
    def __init__(self, flow, *, allowed_ports):
        self.flow = tuple(flow)
        self.reverse = (flow[1],flow[0],flow[3],flow[2])
        self.allowed_ports = frozenset(allowed_ports)
        self.cell = self.epoch = self.work_counter = self.generation = 0
        self.client_next = self.server_next = 0
        self.work = None
        self.selected_objects = None
        self.select_app_sequence = None

    @property
    def phase(self):
        return self.cell >> 16

    def snapshot(self):
        return dict(cell=self.cell,epoch=self.epoch,work_counter=self.work_counter,
            generation=self.generation,client_next=self.client_next,server_next=self.server_next,
            work=None if self.work is None else dict(self.work),selected_objects=self.selected_objects,
            select_app_sequence=self.select_app_sequence)

    def _event(self, p):
        forward = p.flow == self.flow
        if p.flow not in (self.flow,self.reverse):
            return None
        if p.flags == 2 and forward and self.phase == 0:
            return 'syn' if p.mss is not None and p.mss >= 57 and not p.payload and p.ack == 0 else None
        if p.flags == 18 and not forward and self.phase == 2:
            return 'synack' if p.mss is not None and p.mss >= 57 and not p.payload and p.ack == self.client_next else None
        if p.flags in (16,24) and forward and self.phase == 4:
            if p.mss is not None or p.seq != self.client_next or p.ack != self.server_next:
                return None
            if p.payload:
                _select(p.payload)
            return 'ack'
        if p.flags in (4,20,17) and not p.payload and p.mss is None and self.phase in (2,3,4,5):
            expected_seq,expected_ack = ((self.client_next,self.server_next) if forward
                                         else (self.server_next,self.client_next))
            if p.seq == expected_seq and (p.flags == 4 or p.ack == expected_ack):
                return 'close'
        return None

    def begin(self, raw, ingress_port):
        if ingress_port not in self.allowed_ports:
            return None
        try:
            p = parse_packet(raw)
            event = self._event(p)
        except ValueError:
            return None
        if event is None or (self.work is not None and event != 'close'):
            return None
        if event == 'close':
            return Envelope(self.epoch,0,self.cell,event,raw)
        if self.work_counter == MASK32 or (event == 'syn' and self.generation == 65535):
            return None
        self.work_counter += 1
        epoch = self.work_counter if event == 'syn' else self.epoch
        return Envelope(epoch,self.work_counter,self.cell,event,raw)

    def advance(self, e):
        if e.outcome is not None:
            return e
        if e.event == 'close':
            if e.expected_cell != self.cell or e.epoch != self.epoch:
                return replace(e,outcome='refused')
            self.cell = (6 if self.work is not None else 7)<<16 | self.generation
            return replace(e,outcome='forward')
        if e.stage == 'claim':
            if self.work is not None or e.expected_cell != self.cell:
                return replace(e,outcome='refused')
            p = parse_packet(e.original)
            if self._event(p) != e.event:
                return replace(e,outcome='refused')
            if e.event == 'syn':
                self.generation += 1
                self.epoch = e.epoch
                self.client_next = (p.seq+1)&MASK32
            elif e.event == 'synack':
                self.server_next = (p.seq+1)&MASK32
            elif p.payload:
                user = _select(p.payload)
                self.selected_objects = user[3:]
                self.select_app_sequence = user[1]&15
                self.client_next = (p.seq+len(p.payload))&MASK32
            claimed = {'syn':1,'synack':3,'ack':5}[e.event]
            self.cell = claimed<<16 | self.generation
            self.work = dict(epoch=e.epoch,generation=e.work_generation,
                image_sha256=hashlib.sha256(e.original).hexdigest(),stage='publish')
            return replace(e,expected_cell=self.cell,stage='publish')
        if (self.work is None or e.epoch != self.work['epoch'] or e.epoch != self.epoch
                or e.work_generation != self.work['generation']
                or hashlib.sha256(e.original).hexdigest() != self.work['image_sha256']
                or e.stage != self.work['stage']):
            return replace(e,outcome='refused')
        if self.phase == 6:
            self.work = None
            self.cell = 7<<16 | self.generation
            return replace(e,outcome='abort')
        if e.expected_cell != self.cell:
            return replace(e,outcome='refused')
        if e.stage == 'publish':
            self.cell = {'syn':2,'synack':4,'ack':5}[e.event]<<16 | self.generation
            self.work['stage'] = 'terminal'
            return replace(e,expected_cell=self.cell,stage='terminal')
        self.work = None
        return replace(e,outcome='forward')

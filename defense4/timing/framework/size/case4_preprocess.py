"""Bounded, pure offline Case 4 preprocessing oracle; no packet I/O.

This is an expected software pipeline, not evidence that a TNA producer exists.
One exact connection incarnation, explicit MSS-only three-way handshake,
configured software profile (real point 1, inert point 201), and one SBO pair.
Unverified/unsupported admission bypasses bytes and permanently excludes new
insertion. After a committed image, failures quarantine new command bytes while
retaining cached replay and ACK/window translation. No ACK is fabricated.

OPERATE reassembly is exactly 35 bytes and a 35-bit mask, with an absolute 30 ms
first-fragment deadline. observed_ns is an absolute software timestamp (including
zero), not a wrapped target register. TCP/app/transport sequence fields wrap.
Explicit retirement requires caller evidence of close, drain and abandonment;
raw FIN/RST alone never erases translation. Such caller assertions are not a
proof that a physical dataplane lifecycle was measured or implemented.
"""
from dataclasses import dataclass
import ipaddress
import struct

import rrc
from case4_padding import Decoy, decode_frame, expand_control
from case4_transport import RequestLedger, MASK, HALF

BODY = bytes.fromhex('0101640000006400000000')
DEADLINE_NS = 30_000_000
MAX_HOPS = 16
FULL_MASK = (1 << 35) - 1


@dataclass(frozen=True)
class Flow:
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int

    def __post_init__(self):
        for value in (self.source_ip, self.destination_ip):
            if ipaddress.ip_address(value).version != 4: raise ValueError('IPv4 tuple required')
        if not all(0 < value <= 65535 for value in (self.source_port, self.destination_port)):
            raise ValueError('valid nonzero TCP ports required')

    def direction(self, raw):
        # Identify only a complete tuple, independently of its validity. Bad
        # matching checksums/version may exclude this flow; unrelated traffic
        # can never poison its protected state.
        if len(raw) < 54 or raw[12:14] != b'\x08\x00' or raw[23] != 6: return None
        ihl = (raw[14] & 15) * 4
        if ihl < 20 or len(raw) < 14 + ihl + 4: return None
        src, dst = str(ipaddress.ip_address(raw[26:30])), str(ipaddress.ip_address(raw[30:34]))
        sport, dport = struct.unpack_from('>HH', raw, 14 + ihl)
        actual = (src, dst, sport, dport)
        if actual == (self.source_ip, self.destination_ip, self.source_port, self.destination_port): return 'forward'
        if actual == (self.destination_ip, self.source_ip, self.destination_port, self.source_port): return 'reverse'
        return None


@dataclass(frozen=True)
class Result:
    outputs: tuple
    outcome: str
    dynamic_wire_end: object
    original_observation_ns: int
    full_validation: bool = False
    associated: bool = False
    reason: str = ''


class Preprocessor:
    def __init__(self, flow, cookie, decoy):
        if not isinstance(flow, Flow) or not isinstance(cookie, int) or not 0 < cookie <= MASK:
            raise ValueError('immutable Flow and nonzero uint32 incarnation cookie required')
        if decoy.index != 201 or bytes(decoy.body) != BODY:
            raise ValueError('only the configured software inert point 201 profile is supported')
        self.flow, self.cookie = flow, cookie
        self.decoy = Decoy(decoy.index, bytes(decoy.body))
        self.ledger = RequestLedger(0)
        self.excluded = False
        self.faulted = False
        self.retired = False
        self.handshake = 'NONE'
        self.client_base = self.server_base = None
        self.client_mss = self.server_mss = None
        self.selected_user = self.selected_header = None
        self.assembly = bytearray(35)
        self.assembly_mask = 0
        self.assembly_origin_ns = self.assembly_deadline_ns = None
        self.assembly_template = None
        self.response_transport = {}
        self.response_images = {}

    @property
    def dynamic_wire_end(self):
        if not self.ledger.entries: return None
        last = self.ledger.entries[-1]
        return (self.ledger.base_seq + last.end + sum(e.delta for e in self.ledger.entries)) & MASK

    def result(self, outputs, outcome, observed_ns, validated=False, associated=False, reason=''):
        return Result(tuple(outputs), outcome, self.dynamic_wire_end, observed_ns, validated, associated, reason)

    def quarantine(self, reason):
        self.faulted = True
        self.ledger.exclude(reason)

    def fault(self, observed_ns, reason, outputs=()):
        self.quarantine(reason)
        return self.result(outputs, 'TRANSPORT_FAULT', observed_ns, reason=reason)

    def reject(self, raw, observed_ns, reason):
        if self.ledger.entries: return self.fault(observed_ns, reason)
        self.excluded = True
        return self.result((raw,), 'EXCLUDED', observed_ns, reason=reason)

    def tick(self, now_ns):
        if now_ns < 0: raise ValueError('absolute nonnegative timestamp required')
        if self.assembly_deadline_ns is not None and len(self.ledger.entries) == 1 and now_ns >= self.assembly_deadline_ns:
            return self.fault(self.assembly_origin_ns, 'absolute OPERATE assembly deadline')
        return self.result((), 'TRANSPORT_FAULT' if self.faulted else 'IDLE', now_ns)

    def retire(self, *, cookie, verified_close, drained, abandoned):
        if cookie != self.cookie: raise ValueError('stale incarnation cannot retire protected state')
        if not (verified_close is True and drained is True and abandoned is True):
            raise ValueError('verified close, drain and abandonment are all required')
        self.retired = True
        self.ledger.entries.clear()
        self.assembly_mask = 0
        self.assembly_template = None

    @staticmethod
    def network(packet):
        if packet is None or packet.ihl != 20: return 'IPv4 without options required'
        if struct.unpack_from('>H', packet.raw, 20)[0] & 0xbfff: return 'fragment/reserved IPv4 flag'
        if not packet.raw[22]: return 'zero TTL'
        if not rrc.ip_ok(packet) or not rrc.tcp_ok(packet): return 'IPv4/TCP checksum'
        if packet.raw[packet.tcp_off + 12] & 15: return 'TCP reserved/NS bits'
        if packet.flags & 0xe0 or struct.unpack_from('>H', packet.raw, packet.tcp_off + 18)[0]: return 'TCP flags/urgent pointer'
        return ''

    @staticmethod
    def mss(packet):
        options = packet.raw[packet.tcp_off+20:packet.tcp_off+packet.doff]
        if len(options) != 4 or options[:2] != b'\x02\x04': return None
        value = int.from_bytes(options[2:], 'big')
        return value if value >= 57 else None

    def admit(self, packet, direction, raw, observed_ns):
        if packet.flags & 2:
            if self.ledger.entries: return self.fault(observed_ns, 'new SYN inside committed incarnation')
            if packet.payload or self.mss(packet) is None: return self.reject(raw, observed_ns, 'explicit MSS-only handshake with MSS >=57 required')
            if direction == 'forward' and packet.flags == 2:
                base = (packet.seq + 1) & MASK
                if self.client_base is not None and base != self.client_base: return self.reject(raw, observed_ns, 'changed client incarnation')
                if self.client_mss is not None and self.mss(packet) != self.client_mss: return self.reject(raw, observed_ns, 'changed negotiated client MSS')
                self.client_base = base
                self.client_mss = self.mss(packet)
                if self.handshake == 'NONE': self.handshake = 'SYN'
                return self.result((raw,), 'HANDSHAKE', observed_ns)
            if direction == 'reverse' and packet.flags == 18 and self.handshake in ('SYN','SYNACK','VERIFIED') and packet.ack == self.client_base:
                base = (packet.seq + 1) & MASK
                if self.server_base is not None and base != self.server_base: return self.reject(raw, observed_ns, 'changed server incarnation')
                if self.server_mss is not None and self.mss(packet) != self.server_mss: return self.reject(raw, observed_ns, 'changed negotiated server MSS')
                self.server_base = base; self.server_mss = self.mss(packet)
                if self.handshake != 'VERIFIED': self.handshake = 'SYNACK'
                return self.result((raw,), 'HANDSHAKE', observed_ns)
            return self.reject(raw, observed_ns, 'invalid SYN/SYNACK identity')
        if packet.doff != 20: return self.reject(raw, observed_ns, 'TCP options after handshake unsupported')
        if self.handshake == 'SYNACK' and direction == 'forward' and packet.flags in (16,24) and packet.seq == self.client_base and packet.ack == self.server_base:
            self.handshake = 'VERIFIED'
            if not packet.payload: return self.result((raw,), 'HANDSHAKE', observed_ns)
        return None

    def process(self, raw, observed_ns, *, cookie, hops=0):
        raw = bytes(raw)
        if observed_ns < 0 or not isinstance(hops, int) or hops < 0: raise ValueError('nonnegative absolute timestamp and hop count required')
        if cookie != self.cookie: return self.result((), 'STALE_COOKIE', observed_ns)
        if self.retired: return self.result((), 'RETIRED', observed_ns)
        direction = self.flow.direction(raw)
        if direction is None: return self.result((raw,), 'FOREIGN_FLOW', observed_ns)
        packet = rrc.parse(raw)
        reason = self.network(packet)
        if reason: return self.reject(raw, observed_ns, reason)
        admitted = self.admit(packet, direction, raw, observed_ns)
        if admitted is not None: return admitted
        if packet.flags & (1|4):
            if packet.payload: return self.reject(raw, observed_ns, 'payload with FIN/RST unsupported')
            try: output = self.translate(packet, direction)
            except ValueError as error: return self.reject(raw, observed_ns, str(error))
            if self.ledger.entries: self.quarantine('raw close; explicit verified drain/abandonment required')
            else: self.excluded = True
            return self.result((output,), 'CLOSED_TRANSLATED', observed_ns)
        if packet.flags not in (16,24): return self.reject(raw, observed_ns, 'ACK-only or PSH/ACK required')
        if direction == 'reverse': return self.response(packet, raw, observed_ns)
        if not packet.payload:
            try: output = self.translate(packet, direction)
            except ValueError as error: return self.reject(raw, observed_ns, str(error))
            return self.result((output,), 'TRANSLATED_ACK', observed_ns)
        if not self.ledger.entries:
            if self.excluded: return self.result((raw,), 'EXCLUDED', observed_ns)
            if self.handshake != 'VERIFIED': return self.reject(raw, observed_ns, 'missing verified handshake')
            if hops > MAX_HOPS: return self.reject(raw, observed_ns, 'processing pass limit')
            if packet.seq != self.client_base: return self.reject(raw, observed_ns, 'initial native stream offset unsupported')
            return self.insert_select(packet, raw, observed_ns)
        return self.command(packet, observed_ns, hops)

    def translate(self, packet, direction):
        if not self.ledger.entries: return packet.raw
        if direction == 'forward':
            offset = self.ledger._offset(packet.seq)
            if not 0 <= offset <= self.ledger.entries[-1].end+1:
                raise ValueError('empty control/ACK sequence outside committed native range')
            mapped = self.ledger.forward(packet.seq, packet.payload)
            return rrc._build(packet, mapped.payload, mapped.seq, packet.flags)
        if not packet.flags & 16: return packet.raw
        window = struct.unpack_from('>H', packet.raw, packet.tcp_off + 14)[0]
        if packet.flags & 16:
            wire = self.ledger._offset(packet.ack)
            end = self.ledger.entries[-1].end + sum(entry.delta for entry in self.ledger.entries)
            if not 0 <= wire <= end+1 or wire+window >= HALF:
                raise ValueError('ACK/window edge outside committed modular wire range')
        ack, window = self.ledger.reverse(packet.ack, window)
        raw = bytearray(packet.raw)
        struct.pack_into('>I', raw, packet.tcp_off+8, ack)
        struct.pack_into('>H', raw, packet.tcp_off+14, window)
        return rrc._build(rrc.parse(bytes(raw)), packet.payload, packet.seq, packet.flags)

    def native_profile(self, frame, function):
        header, user = decode_frame(frame)
        image, delta = expand_control(frame, self.decoy)
        if (delta != 20 or header[3:] != bytes.fromhex('c40a000100') or user[2] != function or
                user[8:10] != b'\x01\x00' or user[10:] != BODY):
            raise ValueError('unsupported configured native CROB profile')
        return header, user, image

    def insert_select(self, packet, raw, observed_ns):
        try: header, user, image = self.native_profile(packet.payload, 3)
        except ValueError as error: return self.reject(raw, observed_ns, str(error))
        self.ledger = RequestLedger(packet.seq)
        mapped = self.ledger.forward(packet.seq, packet.payload, image)
        self.selected_header, self.selected_user = header, user
        return self.result((rrc._build(packet,mapped.payload,mapped.seq,packet.flags),), 'INSERT_SELECT', observed_ns, True)

    def command(self, packet, observed_ns, hops):
        try: start = self.ledger._offset(packet.seq)
        except ValueError as error: return self.fault(observed_ns, str(error))
        end = start + len(packet.payload)
        committed_end = self.ledger.entries[-1].end
        if start < 0 or end >= HALF: return self.fault(observed_ns, 'native range outside bounded connection')
        outputs = []
        if start < committed_end:
            count = min(len(packet.payload), committed_end-start)
            try: replay = self.ledger.forward(packet.seq, packet.payload[:count])
            except ValueError as error: return self.fault(observed_ns, str(error))
            outputs.append(rrc._build(packet,replay.payload,replay.seq,packet.flags))
            start += count
            if count == len(packet.payload): return self.result(outputs,'CACHED_REPLAY',observed_ns,True)
            suffix = packet.payload[count:]
        else: suffix = packet.payload
        if self.faulted: return self.result(outputs,'TRANSPORT_FAULT',observed_ns,reason='sticky quarantine')
        if len(self.ledger.entries) != 1 or start < 35 or start+len(suffix)>70:
            return self.fault(observed_ns,'uncommitted native OPERATE range',outputs)
        if hops > MAX_HOPS: return self.fault(observed_ns,'processing pass limit',outputs)
        if self.assembly_deadline_ns is None:
            self.assembly_origin_ns = observed_ns
            self.assembly_deadline_ns = observed_ns + DEADLINE_NS
            self.assembly_template = packet
        if observed_ns < self.assembly_origin_ns: return self.fault(self.assembly_origin_ns,'nonmonotone assembly timestamp',outputs)
        if observed_ns >= self.assembly_deadline_ns: return self.fault(self.assembly_origin_ns,'absolute OPERATE assembly deadline',outputs)
        for index, value in enumerate(suffix,start-35):
            if self.assembly_mask & (1 << index) and self.assembly[index] != value:
                return self.fault(self.assembly_origin_ns,'conflicting OPERATE overlap',outputs)
            self.assembly[index] = value; self.assembly_mask |= 1 << index
        if self.assembly_mask != FULL_MASK: return self.result(outputs,'ASSEMBLING',self.assembly_origin_ns)
        native = bytes(self.assembly)
        try:
            header, user, image = self.native_profile(native,4)
            if (header[3:] != self.selected_header[3:] or user[3:] != self.selected_user[3:] or
                    user[0] & 63 != (self.selected_user[0]+1) & 63 or user[1] & 15 != (self.selected_user[1]+1) & 15):
                raise ValueError('OPERATE selected set/address/application or transport sequence mismatch')
            mapped = self.ledger.forward((self.ledger.base_seq+35)&MASK,native,image)
        except ValueError as error: return self.fault(self.assembly_origin_ns,str(error),outputs)
        outputs.append(rrc._build(self.assembly_template,mapped.payload,mapped.seq,packet.flags))
        return self.result(outputs,'INSERT_OPERATE',self.assembly_origin_ns,True)

    def response(self, packet, raw, observed_ns):
        if not self.ledger.entries: return self.result((raw,),'BYPASS',observed_ns)
        try: translated = self.translate(packet,'reverse')
        except ValueError as error: return self.fault(observed_ns,str(error))
        if len(packet.payload) != 57:
            return self.result((translated,),'RESPONSE_BYPASS' if packet.payload else 'TRANSLATED_ACK',observed_ns)
        try: header, user = decode_frame(packet.payload)
        except ValueError as error: return self.fault(observed_ns,'response '+str(error))
        if (len(user) != 41 or header[3] != 0x44 or user[0] & 0xc0 != 0xc0 or
                user[1] & 0xf0 != 0xc0 or user[2] != 129):
            return self.fault(observed_ns, 'response is not a complete supported transport/application fragment')
        if self.faulted:
            return self.result((translated,), 'TRANSPORT_FAULT', observed_ns, reason='sticky quarantine; no new readiness event')
        for index, entry in enumerate(self.ledger.entries):
            wire_end = (self.ledger.base_seq+entry.end+20*(index+1))&MASK
            _, command = decode_frame(entry.transformed)
            body = bytearray(user[5:]); expected = bytearray(command[3:])
            if len(body)==36: body[17]=body[35]=0
            addresses = header[4:6] == self.selected_header[6:8] and header[6:8] == self.selected_header[4:6]
            transport = user[0] & 63
            transport_matches = (transport == self.response_transport[index] if index in self.response_transport else
                                 index == 0 or (0 in self.response_transport and transport == (self.response_transport[0]+1)&63))
            if (packet.ack == wire_end and packet.seq == (self.server_base+57*index)&MASK and addresses and
                    len(user)==41 and user[0]&0xc0==0xc0 and user[1]&0xf0==0xc0 and user[2]==129 and
                    user[1]&15==command[1]&15 and body==expected and transport_matches):
                self.response_transport[index] = transport
                pieces = rrc.carve(translated,profile='RRC_57_CUT28')
                if pieces is None: return self.fault(observed_ns,'validated response cannot be carved')
                if index in self.response_images:
                    if packet.payload != self.response_images[index]: return self.fault(observed_ns,'conflicting response retransmission image')
                    return self.result(pieces,'RESPONSE_REPLAY',observed_ns,True)
                self.response_images[index] = packet.payload
                return self.result(pieces,'RESPONSE_READY',observed_ns,True,True)
        return self.result((translated,),'RESPONSE_BYPASS',observed_ns,True,reason='valid whole response does not match protected association')

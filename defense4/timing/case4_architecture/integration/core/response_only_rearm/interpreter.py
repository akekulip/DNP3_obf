"""Candidate-only source adapters; reuse the repository AST interpreter.

E's identity hash is evaluated exactly. No-output SALUs gain an ignored output
for the existing interpreter, with all original state statements retained.
Diagnostic Counters are omitted. Parser/control/register behavior is actual P4;
this adapter does not execute deparser checksum externs or model hardware queues.
"""
import re
import struct
import sys
from baseline import INTEG

sys.path.insert(0, str(INTEG / 'core' / 'harness'))
from interp_ext import ExtSource


def source_text(text):
    """Ignore CP annotations and evaluate N's single-field identity exactly.

    ExtSource understands only CUSTOM declarations. This 32-to-32 identity
    has precisely the value of its input; all stateful statements are retained.
    """
    text = re.sub(r'@name\("[^"]+"\)', '', text)
    text = re.sub(r'@(?:stage|placement_priority)\(-?\d+\)', '', text)
    text = text.replace('Hash<bit<32>>(HashAlgorithm_t.IDENTITY) wire_ack_stamp;', '')
    return text.replace('wire_ack_stamp.get({hdr.tcp.ack})', 'hdr.tcp.ack')


def e_source(text):
    text = source_text(text)
    prefix = text[:text.index('parser IgParser(')]
    body = text[text.index('parser EgParser('):text.index('\nPipeline(')]
    body = body.replace('parser EgParser(', 'parser IgParser(')
    body = body.replace('control Egress(', 'control Ingress(')
    body = body.replace('control EgDeparser(', 'control IgDeparser(')
    body = body.replace('tcp_old', 'tc')
    body = body.replace('slot_t', 'bit<4>')
    body = re.sub(r'Counter<.*?>\([^;]*\)\s*outcome;', '', body)
    body = body.replace('outcome.count(m.result);', '')
    body = body.replace('HashAlgorithm_t.IDENTITY)', 'HashAlgorithm_t.CUSTOM, identity_poly)')
    body = re.sub(r'void apply\(inout (bit<\d+>|pair32) (\w+)\)\s*\{',
                  r'void apply(inout \1 \2, out bit<8> ignored) { ignored = 0;', body)
    return prefix + body


class ESource(ExtSource):
    def __init__(self, text):
        super().__init__(e_source(text), INTEG)
        self.width.update({'eg.egress_port': 9, 'm.idx': 4})
        # The generic action binder treats aliases as bool; slot_t is bit<4>.
        for name, (params, statements) in self.controls['Ingress'].actions.items():
            self.controls['Ingress'].actions[name] = ([(p, 4 if p == 'idx' else w) for p, w in params], statements)

    def hash(self, name, items):
        if self.frame.ctrl.hashes[name] == 'identity_poly':
            result = 0
            for field in items[1]:
                value, width = self.ev(field)
                result = (result << width) | value
            return result, 32
        return super().hash(name, items)

    def inject(self, port, raw):
        self.begin_pass(0)
        self.env['eg.egress_port'] = port
        accepted, cursor = self.packet_parser(raw)
        if not accepted:
            raise AssertionError(self.parse_error or 'E parser rejected')
        self.apply_control('Ingress')
        return None if self.env.get('md.drop_ctl', 0) else self.deparse() + raw[cursor:]


def checksum_oracle(raw):
    """Independent expected checksum for source composition's E return lap.

    This supplies the checksum extern behavior missing from ExtSource. It is
    explicitly an adapter assumption; compiled model/ASIC must prove the
    candidate deparser's checksum implementation independently.
    """
    prefix = 16 if raw[:14] != bytes.fromhex('001122334455aabbccddeeff0800') else 0
    frame = bytearray(raw[prefix:])
    if len(frame) < 54 or frame[14] != 0x45 or frame[23] != 6:
        return raw
    def checksum(data):
        data += bytes(len(data) & 1)
        total = sum(struct.unpack('!%dH' % (len(data) // 2), data))
        while total >> 16:
            total = (total & 0xffff) + (total >> 16)
        return (~total) & 0xffff
    length = int.from_bytes(frame[16:18], 'big') - 20
    tcp = frame[34:34 + length]
    tcp[16:18] = bytes(2)
    pseudo = bytes(frame[26:34]) + bytes((0, 6)) + struct.pack('!H', length)
    frame[50:52] = struct.pack('!H', checksum(pseudo + tcp))
    return raw[:prefix] + bytes(frame)

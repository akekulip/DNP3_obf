"""Whole-program SOURCE-LEVEL driver for read_timing.p4 on top of integration/core/harness.

Reuses the harness interpreter (ExtSource) without editing it. This is a source interpreter,
not the Tofino compiler, ASIC, traffic manager or packet generator; nothing here is
target-verified. What it adds, in this file only:
  * a text shim: the harness hard-codes struct/parser/control names (headers_t, meta_t,
    IgParser, IgDeparser), the `m.`/`ig.`/`tm.` prefixes and checksum names (ic, tc); the shim renames
    the P4 text accordingly (no semantic edit) and supplies the tna pktgen timer header and
    the global timestamp as `ig.global_tstamp`;
  * OriginalCredit control registration (the harness instantiates only Ingress and
    ExpectedWorkRecord; ExtSource.reset_registers is the hook);
  * two harness defects worked around by subclass overrides (eager `<<` in binary, hex struct
    initializers split at the `x`);
  * a small event-queue scheduler with explicit recirculation latency, because the harness
    Pipeline recirculates on one fixed port only and T loops on three.
Time is the model's only clock: each pass sees `ig.global_tstamp` = its event time in ns.
Recirculation latency is a parameter, NOT a measurement of the target.
"""
import heapq
import re
import struct
import sys
from pathlib import Path

ARCH = Path(__file__).resolve().parents[3]
HARNESS = ARCH / 'integration/core/harness'
sys.path[:0] = [str(HARNESS), str(ARCH.parent / 'framework/size'), str(ARCH / 'integration/connection')]
import interp_ext  # noqa: E402
from interp_ext import Control, ExtSource  # noqa: E402
import vectors  # noqa: E402  (pure ACK builder)

READ = ARCH / 'integration/read'
PORTS = {name: int(value) for name, value in
         re.findall(r'const\s+PortId_t\s+(\w+)\s*=\s*9w(\d+)', (READ / 'ports.p4').read_text())}
TIMER = ('header pktgen_timer_header_t { bit<3> pad0; bit<2> pipe_id; bit<3> app_id; bit<8> pad1;'
         ' bit<16> batch_id; bit<16> packet_id; }\n')


def harness_text(text):
    text = re.sub(r'^\s*#include\s+<[^>]+>', '', text, flags=re.M)
    text = text.replace('struct header_t', 'struct headers_t').replace('struct metadata_t', 'struct meta_t')
    text = text.replace('IngressParser', 'IgParser').replace('IngressDeparser', 'IgDeparser')
    text = re.sub(r'\bmd\.(?!drop_ctl)', 'm.', text)
    text = text.replace('ig_intr_md.ingress_port', 'ig.ingress_port').replace('ig_tm_md.', 'tm.')
    text = text.replace('ig_dprsr_md.drop_ctl', 'md.drop_ctl').replace('ig_prsr_md.global_tstamp', 'ig.global_tstamp')
    text = text.replace('pkt.extract(ig_intr_md); pkt.advance(PORT_METADATA_SIZE);', '')
    text = text.replace('ipv4_checksum', 'ic').replace('tcp_checksum', 'tc')
    return TIMER + text


class TSource(ExtSource):
    def __init__(self, text, include_dir):
        super().__init__(harness_text(text), include_dir)
        self.width['ig.global_tstamp'] = 48

    def binary(self, node):
        """ExtSource.binary builds a dict of every operator result eagerly, so `x & 0xffffff00`
        also evaluates `x << 4294967040` (about 0.28 s per pass). Same semantics, lazy operators."""
        op = node[1]
        if op in ('&&', '||', '++', '==', '!=', '<', '>', '<=', '>='):
            return super().binary(node)
        (a, aw), (b, bw) = self.ev(node[2]), self.ev(node[3])
        width = aw if aw is not None else bw
        value = {'+': lambda: a + b, '-': lambda: a - b, '*': lambda: a * b, '&': lambda: a & b,
                 '|': lambda: a | b, '^': lambda: a ^ b, '<<': lambda: a << b, '>>': lambda: a >> b,
                 '/': lambda: a // b if b else 0, '%': lambda: a % b if b else 0}[op]()
        return (value & ((1 << width) - 1) if width is not None else value), width

    def initial(self, typ, init):
        """ExtSource.initial reads `{1, 0x10000}` as 1, 0, 10000 (hex split at the x). Parse literals whole."""
        if typ.startswith('bit<'):
            return int(init, 0)
        values = [int(v, 0) for v in re.findall(r'0[xX][0-9a-fA-F]+|\d+', init)]
        return {f: v for (f, _), v in zip(self.structs[typ], values)}

    def reset_registers(self):
        for name in re.findall(r'\bcontrol\s+(\w+)\s*\(', self.text):
            if name == 'OriginalCredit' and name not in self.controls:
                self.controls[name] = Control(self.text, name)
        super().reset_registers()


def pure_ack(seq=1000, ack=2000):
    return vectors.packet(16, seq, ack)


def typed_frame(kind):
    """Typed producer seam frame: 20-byte envelope (kind, stage 0, reserved 0) + opaque Ethernet."""
    envelope = struct.pack('!IIIIBBH', 0, 0, 0, 0, kind, 0, 0)
    return envelope + bytes.fromhex('001122334455aabbccddeeff0800') + bytes(24)


def pktgen_frame():
    return bytes(6) + bytes.fromhex('001122334455aabbccddeeff0800') + bytes(18)


class Sim:
    def __init__(self, text, include_dir, loop_ns=50_000, params=None, loopbacks=None):
        self.LOOPBACKS = tuple(loopbacks or (PORTS['HELD_RETURN'], PORTS['HB_RETURN']))
        self.src = TSource(text, include_dir)
        self.loop_ns = loop_ns
        self.queue, self.order = [], 0
        self.emitted, self.drops, self.log = [], [], []
        self.lose = lambda time, port, raw: False
        if params:
            self.src.install('deadline_offsets', (), 'prepare_deadlines', list(params))

    def cell(self, name):
        return self.src.cells[('', name)][0]

    def at(self, time, port, raw):
        self.order += 1
        heapq.heappush(self.queue, (time, self.order, port, bytes(raw)))

    def run(self, until):
        src = self.src
        while self.queue and self.queue[0][0] <= until:
            time, _, port, raw = heapq.heappop(self.queue)
            src.begin_pass(port)
            src.env['ig.global_tstamp'] = time
            accepted, cursor = src.packet_parser(raw)
            if src.parse_error:
                self.drops.append((time, port, 'parser: ' + src.parse_error))
                continue
            src.apply_control('Ingress')
            self.log.append((time, port, list(src.events)))
            if src.env.get('md.drop_ctl', 0) & 1:
                self.drops.append((time, port, 'drop_ctl'))
                continue
            out = src.deparse() + raw[cursor:]
            egress = src.env.get('tm.ucast_egress_port', 0)
            if egress in self.LOOPBACKS:
                if not self.lose(time, egress, out):
                    self.at(time + self.loop_ns, egress, out)
                else:
                    self.drops.append((time, egress, 'lost in loop (test injected)'))
            else:
                self.emitted.append((time, egress, out))

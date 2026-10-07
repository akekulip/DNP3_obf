"""Whole-program SOURCE-LEVEL scheduler for read_timing.p4 on integration/core/harness.

The unmodified P4 text runs in the harness interpreter (ExtSource normalizes the TNA names via
tna_dialect). This is a source interpreter, not the Tofino compiler, ASIC, traffic manager or
packet generator; nothing here is target-verified. This file only adds an event-queue scheduler
with an explicit recirculation latency, because harness.Pipeline recirculates on one fixed port
and T loops on several. Each pass sees `ig.global_tstamp` = its event time in ns; the latency is
a parameter, NOT a measurement of the target.
"""
import heapq
import re
import struct
import sys
from pathlib import Path

ARCH = Path(__file__).resolve().parents[3]
HARNESS = ARCH / 'integration/core/harness'
sys.path[:0] = [str(HARNESS), str(ARCH.parent / 'framework/size'), str(ARCH / 'integration/connection')]
from interp_ext import ExtSource  # noqa: E402
import vectors  # noqa: E402  (pure ACK builder)

READ = ARCH / 'integration/read'
PORTS = {name: int(value) for name, value in
         re.findall(r'const\s+PortId_t\s+(\w+)\s*=\s*9w(\d+)', (READ / 'ports.p4').read_text())}


def pure_ack(seq=1000, ack=2000):
    return vectors.packet(16, seq, ack)


ETH = bytes.fromhex('001122334455aabbccddeeff0800')
REQUEST_FRAME = ETH + bytes(range(46))          # opaque original READ request
RESPONSE_FRAME = ETH + bytes(range(100, 124))   # opaque original response


def event_frame(kind, original, epoch=1, t0q=0):
    """N's typed event (tev_h: epoch, wgen, t0q, kind, stage 0, reserved 0) followed by the original."""
    return struct.pack('!IIIBBH', epoch, 0, t0q, kind, 0, 0) + original


def pktgen_frame(pipe=2):
    """Generator packet: 6-byte timer header (first byte 000 pp aaa: pipe pp, app 0) + Ethernet. The model
    delivers these with ingress_port 0 (model_28 RESULT (d)); the frozen probe (pipe 0, port 68) uses pipe=0."""
    return bytes([pipe << 3]) + bytes(5) + bytes.fromhex('001122334455aabbccddeeff0800') + bytes(18)


class Sim:
    def __init__(self, text, include_dir, loop_ns=50_000, params=None, loopbacks=None):
        self.LOOPBACKS = tuple(loopbacks or (PORTS['HELD_RETURN'], PORTS['HB_RETURN']))
        self.src = ExtSource(text, include_dir)
        self.loop_ns = loop_ns
        self.queue, self.order = [], 0
        self.emitted, self.drops, self.log = [], [], []
        self.lose = lambda time, port, raw: False
        self.duplicate = lambda time, port, raw: False      # enqueue a second copy of a loop packet
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
                    if self.duplicate(time, egress, out):
                        self.at(time + self.loop_ns + 7_000, egress, out)
                else:
                    self.drops.append((time, egress, 'lost in loop (test injected)'))
            else:
                self.emitted.append((time, egress, out))

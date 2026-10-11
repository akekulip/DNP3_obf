"""Source-level scheduler for the queue-resident READ timing role T (read_queue_timing.p4).

The P4 text runs unmodified in the integration/core/harness interpreter (parser, Ingress, deparser).
Everything the interpreter does not model is added HERE, explicitly, and is an assumption of the
test, not a property of the target:

* Traffic manager: each ladder port (HELD_RETURN, HB_RETURN) has eight FIFO queues served strictly
  by qid (7 highest), one packet per `service_ns`; a served packet re-enters ingress on the same
  port `loop_ns` later. This is the strict-priority ladder the control plane must configure
  (qid == priority); the simulator does not prove the switch is configured that way.
* Mirror + packet generator: a pass that sets `mirror_type == 1` produces (a) the clone, which
  recirculates into ingress on PKTGEN_RETURN (ports.p4) and (b) `2 * k` generated tokens
  (recirc-pattern app; key = the low 24 bits of the 4-byte clone tag, packet_id 0..2k-1) that reach
  ingress with ingress_port 0 behind the 6-byte generator header, as the model delivers them
  (model_28 RESULT (d)).
* Clock: `ig.global_tstamp` of a pass is its event time in ns.

Nothing here is compiler, model or hardware evidence.
"""
import heapq
import os
import struct
import sys
from collections import deque
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import whole_program as w  # noqa: E402  (ExtSource import path, frames, PORTS)

READ = w.READ
SOURCE = Path(os.environ.get('T_QUEUE_SOURCE', READ / 'read_queue_timing.p4'))
PORTS = w.PORTS
LADDER, OP_LADDER = PORTS['HELD_RETURN'], PORTS['HB_RETURN']
FORWARD, RELAY = PORTS['FORWARD_PORT'], PORTS['RELAY_PORT']
PKTGEN_PIPE = int(__import__('re').search(r'const\s+bit<2>\s+PKTGEN_PIPE\s*=\s*(\d+)', (w.READ / 'ports.p4').read_text())[1])
PKTGEN_PORT = PORTS['PKTGEN_RETURN']  # where the mirror clone recirculates (ports.p4; two-pipe layout: 196)


def q(ns):
    """The 256 ns clock grid (low eight bits clear), as N quantizes t0q."""
    return ns & ~0xff


DA, READINESS, CAP, GAP, OP_J = q(500_000), q(3_000_000), q(4_000_000), q(200_000), q(600_000)
BUDGET = 60_000
T0 = 1 << 24

ACK_FRAME, RSP_FRAME, REQ_FRAME = w.pure_ack(), w.RESPONSE_FRAME, w.REQUEST_FRAME
OP_FRAME = w.ETH + bytes(range(200, 230))
CHILD1, CHILD2 = w.ETH + bytes(range(100, 114)), w.ETH + bytes(range(114, 124))

# Ladder roles as the design names them (read_queue_timing.p4 header comment); the tests only
# use them to read the simulator's queue records, never to drive the program.
ROLE = {11: 'ACK_BLK', 12: 'RESP_BLK', 13: 'OP_BLK', 14: 'ACK_HELD', 15: 'RESP_HELD', 16: 'OP_HELD'}
LAD_BYTES = 8


def params(da=DA, readiness=READINESS, cap=CAP, gap=GAP, op_j=OP_J, budget=BUDGET, enabled=1):
    return [da, readiness, cap, gap, op_j, budget, enabled]


class QueueSim:
    def __init__(self, k=2, service_ns=30_000, loop_ns=20_000, pktgen_ns=10_000, source=SOURCE, **kw):
        self.src = w.ExtSource(Path(source).read_text(), READ)
        self.src.width.update({'tm.qid': 5, 'md.mirror_type': 3})
        self.k, self.service_ns, self.loop_ns, self.pktgen_ns = k, service_ns, loop_ns, pktgen_ns
        self.set_params(**kw)
        self.heap, self.order = [], 0
        self.queues = {LADDER: [deque() for _ in range(8)], OP_LADDER: [deque() for _ in range(8)]}
        self.busy_until = {LADDER: 0, OP_LADDER: 0}
        self.serving = {LADDER: False, OP_LADDER: False}
        self.emitted, self.drops, self.log, self.enqueued = [], [], [], []
        self.lose = lambda time, port, qid, raw: False

    # ---- configuration -----------------------------------------------------------------------
    def set_params(self, **kw):
        table = self.src.controls['Ingress'].tables['params']
        table['runtime'] = []
        self.src.install('params', (), 'set_params', params(**kw))

    def cell(self, name, index=0):
        return self.src.cells[('', name)][index]

    def counter(self, code):
        return self.src.cells[('', 'outcomes')][code]

    def consts(self):
        return {k: v for k, (v, _) in self.src.consts.items()}

    # ---- event queue -------------------------------------------------------------------------
    def at(self, time, port, raw, kind='ingress'):
        self.order += 1
        heapq.heappush(self.heap, (time, self.order, kind, port, bytes(raw)))

    def event(self, time, kind, original, epoch=1, stage=0, t0q=None):
        t0q = q(time) if t0q is None else t0q
        self.at(time, PORTS['T_IN'], struct.pack('!IIIBBH', epoch, 0, t0q, kind, stage, 0) + original)

    def handoff(self, time, raw):
        """A T_IN frame exactly as N emitted it (tev header + original), e.g. bytes captured from
        N's own source run; nothing is rebuilt, so wgen/epoch/t0q are whatever N produced."""
        self.at(time, PORTS['T_IN'], raw)

    def request(self, time, epoch=1):
        self.event(time, 9, REQ_FRAME, epoch)

    def ack(self, time, epoch=1, frame=ACK_FRAME):
        self.event(time, 10, frame, epoch)

    def response(self, time, epoch=1, frame=RSP_FRAME, child=0):
        self.event(time, 11, frame, epoch, stage=child)

    def operate(self, time, epoch=1, frame=OP_FRAME):
        self.event(time, 12, frame, epoch)

    def reset(self, time, epoch=1, stage=0, frame=None):
        self.event(time, 4, frame if frame is not None else w.ETH + bytes(6), epoch, stage=stage)

    def call(self, time, fn):
        self.order += 1
        heapq.heappush(self.heap, (time, self.order, 'call', 0, fn))

    def token(self, time, gen, packet_id, profile=1):
        """A generator token exactly as the generator would deliver it (stale-token injection)."""
        self.at(time, 0, bytes([PKTGEN_PIPE << 3 | profile]) + bytes([profile]) + struct.pack('!HH', gen, packet_id) + bytes(10))

    def read(self, base, ack_off=50_000, rsp_off=100_000, epoch=1):
        self.request(base, epoch)
        if ack_off is not None:
            self.ack(base + ack_off, epoch)
        if rsp_off is not None:
            self.response(base + rsp_off, epoch)

    # ---- traffic manager ---------------------------------------------------------------------
    def enqueue(self, time, port, qid, raw):
        self.enqueued.append((time, port, qid, raw))
        if self.lose(time, port, qid, raw):
            self.drops.append((time, port, 'lost in queue (test injected)'))
            return
        self.queues[port][qid].append(raw)
        if not self.serving[port]:
            self.serving[port] = True
            self.at(max(time, self.busy_until[port]), port, b'', kind='serve')

    def serve(self, time, port):
        for qid in range(7, -1, -1):
            if self.queues[port][qid]:
                raw = self.queues[port][qid].popleft()
                self.busy_until[port] = time + self.service_ns
                self.at(time + self.service_ns + self.loop_ns, port, raw)
                self.at(time + self.service_ns, port, b'', kind='serve')
                return
        self.serving[port] = False

    # ---- one ingress pass --------------------------------------------------------------------
    def ingress(self, time, port, raw):
        src = self.src
        src.begin_pass(port)
        src.env['ig.global_tstamp'] = time
        accepted, cursor = src.packet_parser(raw)
        if src.parse_error or not accepted:
            self.drops.append((time, port, 'parser: %s' % (src.parse_error or 'reject')))
            self.log.append((time, port, raw, ['parser reject']))
            return
        src.apply_control('Ingress')
        self.log.append((time, port, raw, list(src.events)))
        if src.env.get('md.mirror_type', 0) == 1:
            tag = src.env.get('m.clone_tag', 0)
            self.at(time + self.pktgen_ns // 2, PKTGEN_PORT, struct.pack('!I', tag) + raw)
            pipe_app = PKTGEN_PIPE << 3 | ((tag >> 16) & 0x7)
            for packet_id in range(2 * self.k):
                generated = bytes([pipe_app]) + struct.pack('!I', tag & 0xffffff)[1:] + struct.pack('!H', packet_id)
                self.at(time + self.pktgen_ns + 100 * packet_id, 0, generated + bytes(10))
        if src.env.get('md.drop_ctl', 0) & 1:
            self.drops.append((time, port, 'drop_ctl'))
            return
        out = src.deparse() + raw[cursor:]
        egress = src.env.get('tm.ucast_egress_port', 0)
        if egress in self.queues:
            self.enqueue(time, egress, src.env.get('tm.qid', 0), out)
        else:
            self.emitted.append((time, egress, out))

    def run(self, until):
        while self.heap and self.heap[0][0] <= until:
            time, _, kind, port, raw = heapq.heappop(self.heap)
            if kind == 'serve':
                self.serve(time, port)
            elif kind == 'call':
                raw(self)
            else:
                self.ingress(time, port, raw)
        return self

    # ---- observations ------------------------------------------------------------------------
    def emissions(self, frame, port=None):
        return [t for t, p, raw in self.emitted if raw == frame and (port is None or p == port)]

    def held_records(self, frame):
        """(time, port, qid, role, gen) of every enqueue whose payload after the ladder header is `frame`."""
        found = []
        for time, port, qid, raw in self.enqueued:
            if raw[LAD_BYTES:] == frame:
                role, child, gen = raw[0], raw[1], struct.unpack('!H', raw[2:4])[0]
                found.append((time, port, qid, ROLE.get(role, role), gen, child))
        return found

    def ladder_passes(self, frame):
        """Ingress passes on a ladder port whose payload after the ladder header is `frame`."""
        return [t for t, p, raw, _ in self.log if p in self.queues and raw[LAD_BYTES:] == frame]

    def token_passes(self):
        return [t for t, p, raw, _ in self.log if p in self.queues and raw[0] in (11, 12, 13)]

    def token_enqueues(self):
        return [(t, p, qid, ROLE[raw[0]]) for t, p, qid, raw in self.enqueued if raw[0] in (11, 12, 13)]

    def pass_time(self, frame, action):
        """Ingress time of the ladder pass of `frame` that ran `action` (e.g. the ACK commit)."""
        for time, port, raw, events in self.log:
            if port in self.queues and raw[LAD_BYTES:] == frame and ('action ' + action) in events:
                return time
        return None

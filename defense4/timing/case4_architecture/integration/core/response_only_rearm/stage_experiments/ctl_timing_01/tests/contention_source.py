"""Source-level N/E/T pipeline whose N passes are scheduled one lap at a time (PLAN_m5.md S1).

The retained SourcePipeline (response_only_rearm/source_pipeline.py) runs all of a packet's N passes back to back
inside one inject, so nothing can arrive between two laps of N's work cell. Here every N pass is one event in a
time-ordered queue: a pass that egresses to RETURN_PORT re-enters `lap_ns` later, and a packet arriving between
two laps of another packet's lifecycle is processed between them. This is how an outstation's standalone ACK and
its response contend for N's single work cell.

The P4 text is a ctl_timing build's own source, cut into roles with the same port remapping as
combined_nt_01.source_role. Assumptions are the harness's and QueueSim's (one pass = one lap; FIFO by time, ties
in arrival order); nothing here is compiler, model or hardware evidence.
"""
import heapq
import importlib.util
import re
import sys
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
CTL = HERE.parent
RR = CTL.parents[1]
sys.path.insert(0, str(RR))


def _module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


combined = _module('contention_combined', CTL.parent / 'combined_nt_01/generate.py')

import make_e  # noqa: E402
import make_n  # noqa: E402
import make_t  # noqa: E402
import source_pipeline as sp  # noqa: E402

rs, qs, vectors, cp = sp.rs, sp.qs, sp.vectors, sp.cp
MASTER_PORT, RELAY_PORT, RETURN_PORT = 9, 64, 68
BUSY_DROP, BUSY_PASS = 0, 1


def role(text, name):
    """combined_nt_01.source_role for an arbitrary composite source text."""
    part = combined.segment(text, name)
    prefix = {'N': 'n', 'E': 'r', 'T': 't'}[name]
    part = re.sub(r'\b' + prefix + r'_(\w+)', r'\1', part)
    if name == 'N':
        part = part.replace('N_ACK_RETURN=9w48;', 'N_ACK_RETURN=9w70;')
        part = part.replace('READ_HANDOFF_PORT=9w180;', 'READ_HANDOFF_PORT=9w197;')
    elif name == 'E':
        part = part.replace('9w48: provenance;', '9w70: provenance; 9w64: provenance;')
        part += '\nPipeline() source_adapter_marker;\n'
    else:
        for key, old, new in (('T_IN', 180, 197), ('HB_RETURN', 181, 198),
                              ('HELD_RETURN', 182, 199), ('RELAY_PORT', 9, 64)):
            part, count = re.subn(r'(const PortId_t ' + key + r'\s*=\s*)9w' + str(old) + r';',
                                  r'\g<1>9w' + str(new) + ';', part)
            assert count == 1, key
    return '#include <core.p4>\n#include <tna.p4>\n' + part


class LapPipeline(sp.SourcePipeline):
    """SourcePipeline over `source` (a composite .p4 path) with N scheduled pass by pass."""

    def __init__(self, source, lap_ns=1000, pb=qs.q(2_000_000), **timing):
        text = Path(source).read_text()
        self._patches = [patch.object(module, 'generate', lambda name=name: role(text, name))
                         for module, name in ((make_n, 'N'), (make_e, 'E'), (make_t, 'T'))]
        for p in self._patches:
            p.start()
        try:
            super().__init__(**timing)
        finally:
            for p in self._patches:
                p.stop()
        # control-timed T (m3+) takes the piggyback bound pb as an eighth set_params argument
        if len(self.t.src.controls['Ingress'].actions['set_params'][0]) == 8:
            self.t.src.controls['Ingress'].tables['params']['runtime'] = []
            self.t.src.install('params', (), 'set_params', qs.params(**timing) + [pb])
        self.lap_ns, self.heap, self.order = lap_ns, [], 0
        self.passes = []          # (time, port, frame, events, egress or None, drop reason or None)

    # ---- N, one pass per event ------------------------------------------------------------------
    def ingress(self, time, port, frame):
        self.order += 1
        heapq.heappush(self.heap, (time, self.order, port, bytes(frame)))

    def _pass(self, time, port, raw):
        self.n.time = time
        events, result, reason = self.n.run_pass(1, port, raw)
        self.passes.append((time, port, raw, events, result[0] if result else None, reason))
        if result is None:
            return
        egress, out = result
        if egress == RETURN_PORT:
            self.ingress(time + self.lap_ns, RETURN_PORT, out)
        else:
            self.egress(time + self.lap_ns, egress, out)

    def run(self, until):
        while self.heap and self.heap[0][0] <= until:
            time, _, port, raw = heapq.heappop(self.heap)
            self.t.run(time)
            self._pass(time, port, raw)
        self.t.run(until)
        self.now = max(self.now, until)
        return self

    def settle(self, horizon=20_000_000):
        """Run until neither N's lap queue nor T's queue holds an event within `horizon` ns."""
        end = self.now + horizon
        while True:
            pending = [h[0][0] for h in (self.heap, self.t.heap) if h]
            if not pending or min(pending) > end:
                return self.run(end)
            self.run(max(min(pending), self.now))

    def send(self, frame, master=True, time=None):
        self.now = self.now + 50_000 if time is None else time
        self.ingress(self.now, MASTER_PORT if master else RELAY_PORT, frame)
        return self.run(self.now + 20_000)

    def at(self, time, frame, master=False):
        """Queue an arrival without running anything."""
        self.ingress(time, MASTER_PORT if master else RELAY_PORT, frame)

    # ---- observations ---------------------------------------------------------------------------
    def busy(self, index):
        return self.n.src.cells[('', 'count_busy')][index]

    def to_master(self, since=0):
        return [(t, raw) for t, port, raw in self.wire if port == MASTER_PORT and t >= since]


# ---- the contended exchange (PLAN_m5.md S1) -------------------------------------------------------
OUTCOMES = ('UNMATCHED', 'HELD_REWAIT', 'ACK_COMMIT', 'RESP_RELEASE', 'RESP_DUP_DROP', 'OP_RELEASE', 'TOKEN_STALE',
            'HELD_STALE_FLUSH', 'ACK_FALLBACK', 'RESP_FALLBACK')
REQ_TO_ACK_NS = 200_000          # inside QueueSim's DA/readiness window, as on the separate-ACK fixtures
ACK_LEN, RESPONSE_LEN = 54, 115  # master-visible frames: bare ACK; 61-octet DNP3 response (E-padded)


def control_response(app, fc):
    """The 37-octet native control response test_composite builds from the SELECT/OPERATE vector."""
    _, user = rs.case4_padding.decode_frame(vectors.native_select(app, fc))
    objects = bytearray(user[3:])
    objects[17] = 0
    return rs.case4_padding.build_frame(bytes.fromhex('05641c4401000a00'),
                                        user[:2] + bytes((0x81, 0, 0)) + bytes(objects))


def transaction(kind):
    """(request, outstation ACK, outstation response) for one kind on a fresh connection; OPERATE's request
    acknowledges the 61-octet padded SELECT response the master saw (901 + 61)."""
    if kind == 'READ':
        return (rs.request_packet(seq=101, ack=901), rs.ack_packet(seq=901, ack=121),
                rs.response_packet(seq=901, ack=121))
    if kind == 'SELECT':
        return (vectors.packet(24, 101, 901, payload=vectors.native_select(0, 3)),
                vectors.packet(16, 901, 136, reverse=True),
                vectors.packet(24, 901, 136, reverse=True, payload=control_response(0, 3)))
    assert kind == 'OPERATE', kind
    return (vectors.packet(24, 136, 962, payload=vectors.native_select(1, 4)),
            vectors.packet(16, 938, 171, reverse=True),
            vectors.packet(24, 938, 171, reverse=True, payload=control_response(1, 4)))


def outcomes(p):
    cells = p.t.src.cells[('', 'outcomes')]
    return {name: cells[i] for i, name in enumerate(OUTCOMES)}


def contended(source, kind, offset_laps, lap_ns=1000):
    """The outstation's bare ACK reaches N, and its response follows `offset_laps` laps (+1 ns) later, so it
    arrives while the ACK's lifecycle still holds (or has just left) N's work cell. OPERATE first completes a
    SELECT and waits out T's J hold so the ACK follows the OPERATE's departure. Returns what the master saw
    after the ACK and the counter deltas."""
    p = LapPipeline(source, lap_ns=lap_ns).handshake()
    if kind == 'OPERATE':
        request, ack, response = transaction('SELECT')
        t = p.now + 100_000
        p.at(t, request, master=True)
        p.at(t + REQ_TO_ACK_NS, ack)
        p.at(t + 2 * REQ_TO_ACK_NS, response)
        p.now = t
        p.settle()
    request, ack, response = transaction(kind)
    before, busy0, seen = outcomes(p), [p.busy(i) for i in range(4)], len(p.to_master())
    t = p.now + 100_000
    p.at(t, request, master=True)
    t_ack = t + (5 * REQ_TO_ACK_NS if kind == 'OPERATE' else REQ_TO_ACK_NS)   # OPERATE departs after J
    p.at(t_ack, ack)
    p.at(t_ack + offset_laps * lap_ns + 1, response)
    p.now = t
    p.settle()
    after = outcomes(p)
    return {'master': [(stamp - t_ack, raw) for stamp, raw in p.to_master()[seen:]],
            'response': response, 'ack': ack,
            'busy': [p.busy(i) - busy0[i] for i in range(4)],
            'outcomes': {k: after[k] - before[k] for k in OUTCOMES},
            'owner_state': p.n.state()['owner'] >> 16, 'pipeline': p}


def delivered_once_after_ack(r):
    """The master saw the bare ACK and then exactly one 61-octet response, both released by T's committed path
    (ACK_COMMIT and RESP_RELEASE, no fallback), and N busy-dropped nothing."""
    lens = [len(raw) for _, raw in r['master']]
    o = r['outcomes']
    return (lens == [ACK_LEN, RESPONSE_LEN] and r['busy'][BUSY_DROP] == 0
            and o['ACK_COMMIT'] == 1 and o['RESP_RELEASE'] == 1
            and o['ACK_FALLBACK'] == 0 and o['RESP_FALLBACK'] == 0)


# ---- retry frames (m5) ----------------------------------------------------------------------------
RETRY_EVENT = 0x0400
STALE, EXHAUSTED, RETRY, DUPLICATE = 4, 3, 2, 5      # count_busy cells (m5)


def retry_frames(p):
    """Every frame that entered N on RETURN_PORT carrying the retry event, in order."""
    return [raw for _t, port, raw, _e, _g, _r in p.passes
            if port == RETURN_PORT and int.from_bytes(raw[12:14], 'big') == RETRY_EVENT]


def envelope(raw, epoch=None, generation=None, budget=None, event=None, reserved=None):
    """A copy of a loop frame with envelope fields replaced (epoch, generation, expected_cell, event, reserved)."""
    fields = [int.from_bytes(raw[i:i + 4], 'big') for i in (0, 4, 8)] + \
             [int.from_bytes(raw[12:14], 'big'), int.from_bytes(raw[14:16], 'big')]
    for i, value in enumerate((epoch, generation, budget, event, reserved)):
        if value is not None:
            fields[i] = value
    head = b''.join(v.to_bytes(4, 'big') for v in fields[:3]) + fields[3].to_bytes(2, 'big') + fields[4].to_bytes(2, 'big')
    return head + raw[16:]


def n_state(p):
    state = p.n.state()
    state['retry_epoch'] = p.n.src.cells.get(('', 'retry_epoch'), [None])[0]
    return state

"""Shared scenario helpers for the whole-program READ tests (source-level, see whole_program.py).

Decision instants. A heartbeat tick injects a pktgen packet at P0 that snapshots anchor/seen/
deadline; its first return pass P1 = P0 + L evaluates eligibility with the clock of P1 and writes
the release/ready bit. Original loops see that bit on their next pass, so a release is emitted in
(P1, P1 + L]. The oracle (join_reference) therefore runs with heartbeat phase P0 + L and
arrivals shifted by L (an observation must precede the snapshot). A request commits its
association at P3 = request + 3L; originals are injected later than that unless a test races them.
"""
import importlib.util
import sys

import whole_program as w

ARCH, READ = w.ARCH, w.READ
spec = importlib.util.spec_from_file_location('join_reference', READ / 'join_reference.py')
jr = importlib.util.module_from_spec(spec)
sys.modules['join_reference'] = jr
spec.loader.exec_module(jr)

TEXT = (READ / 'read_timing.p4').read_text()
PROBE_DIR = ARCH / 'ownership/p4'
PROBE = (PROBE_DIR / 'held_timing_expected_probe.p4').read_text()

T = 1 << 24
PERIOD, L = jr.HEARTBEAT_NS, 50_000
PHASE = T % PERIOD
ACK_FRAME, RSP_FRAME, REQ_FRAME = w.pure_ack(), w.RESPONSE_FRAME, w.REQUEST_FRAME
ACK_OFF, RSP_OFF = 217_000, 413_000     # after the request commits (3L) and off the tick passes
CELLS = ('admission_anchor', 'observations', 'releases', 'committed_response_deadline', 'ready_response')
MS = 1_000_000


def params(d_ms):
    return (jr.DA_NS[d_ms], jr.READINESS_NS, jr.GAP_NS, jr.CAP_NS)


def new_sim(d_ms=5, **kw):
    return w.Sim(TEXT, READ, loop_ns=L, params=params(d_ms), **kw)


def ticks(sim, start, stop, port=0, frame=None):
    """Generator ticks every PERIOD; port 0 + pipe-2 timer header is how the model delivers them."""
    frame = frame or w.pktgen_frame()
    k = 0
    while T + k * PERIOD < stop:
        if T + k * PERIOD >= start:
            sim.at(T + k * PERIOD, port, frame)
        k += 1


def request(sim, time, epoch=1, frame=REQ_FRAME):
    sim.at(time, w.PORTS['T_IN'], w.event_frame(9, frame, epoch, jr.quantize(time)))


def ack(sim, time, epoch=1, frame=ACK_FRAME):
    sim.at(time, w.PORTS['T_IN'], w.event_frame(10, frame, epoch))


def response(sim, time, epoch=1, frame=RSP_FRAME):
    sim.at(time, w.PORTS['T_IN'], w.event_frame(11, frame, epoch))


def operate(sim, time, epoch=1, frame=ACK_FRAME):
    sim.at(time, w.PORTS['T_IN'], w.event_frame(12, frame, epoch))


def reset(sim, time, epoch=1):
    sim.at(time, w.PORTS['T_IN'], w.event_frame(4, w.ETH + bytes(6), epoch))


def read(sim, base, ack_off=ACK_OFF, rsp_off=RSP_OFF, epoch=1):
    """One READ: request at base, then the ACK and/or response originals (None = absent)."""
    request(sim, base, epoch)
    if ack_off is not None:
        ack(sim, base + ack_off, epoch)
    if rsp_off is not None:
        response(sim, base + rsp_off, epoch)


def admissions(sim, after=0):
    found = {}
    for time, _, events in sim.log:
        if time < after:
            continue
        for event in events:
            if event in ('action relay_ack', 'action relay_response'):
                found.setdefault(event, time)
    return found.get('action relay_ack'), found.get('action relay_response')


def emitted(sim, frame, after=0, port=None):
    return [time for time, p, raw in sim.emitted
            if raw == frame and time >= after and (port is None or p == port)]


def cell(sim, name):
    return sim.cell(name)


def oracle(sim, d_ms, adm_a, adm_r, anchor_word=None):
    word = sim.cell('admission_anchor')['word'] if anchor_word is None else anchor_word
    shift = lambda t: None if t is None else t + L
    return jr.ticked(word - 1, d_ms, shift(adm_a), shift(adm_r), phase=PHASE + L)


def assert_window(test, observed, release_visible, label):
    test.assertTrue(release_visible < observed <= release_visible + L,
                    '%s: emitted %d, release visible %d (window +%d)' % (label, observed, release_visible, L))

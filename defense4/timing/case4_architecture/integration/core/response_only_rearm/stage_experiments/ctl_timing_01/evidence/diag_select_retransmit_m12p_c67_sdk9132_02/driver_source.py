"""Diagnostic (not a gate driver): relay retransmission of a released, un-ACKed SELECT response, mixed vs integrity.

H-M1b (WORKING_NOTES 2026-10-25): on the physical relay the c67 loss_mixed t3 trial (first padded SELECT response
dropped at the master host after capture) ends in OPERATE TIMEOUT, and the retransmitted copy reached the master
~21 ms later than in the loss_full trial. This asks the compiled model whether T holds the relay's retransmission
about D after a mixed READ and not after an integrity READ. Per connection (history class fixed), each cycle runs a
timed READ, a timed SELECT whose response the master does not ACK, the relay's identical retransmission, then the
master ACK and a timed OPERATE. The retransmission's T (pipe-1) passes and their model clock are recorded; the hold
is a measurement, not a verdict. Model behavior only, not host or ASIC timing.
"""
import collections
import hashlib
import json
import os
import traceback
from pathlib import Path

import model_log_view as view
from model_relay_sbo import RelayGate, mp, verify_control_delivery

GAP_NS = 20_000_000          # the failing d20_loss_mixed_950 configuration
UNIT_NS = 256                # md.now = global_tstamp[39:8] & ~1
OUTCOMES = (2, 3, 5, 8, 9)


def t_summary(records):
    """The pipe-1 (T) passes in a window: ports, actions and the model-clock span they cover."""
    rows = [r for r in records if r['pipe'] == 1]
    stamps = [r['t_units'] & ~1 for r in rows if type(r.get('t_units')) is int]
    span = (stamps[-1] - stamps[0]) & 0xffffffff if len(stamps) > 1 else 0
    return dict(passes=len(rows), ports=dict(collections.Counter(r['port'] for r in rows)),
                actions=dict(collections.Counter(a for r in rows for a in r['actions'])),
                first_units=stamps[0] if stamps else None, last_units=stamps[-1] if stamps else None,
                span_units=span, span_ms=span * UNIT_NS / 1e6,
                rows=[dict(port=r['port'], t_units=r['t_units'], actions=r['actions']) for r in rows])


class RetransmitGate(RelayGate):
    def outcomes(self):
        return [self.h.scalar(self.m.register_read('p1.t_Ingress.outcomes', i, pipe=1)) for i in OUTCOMES]

    def select_with_retransmission(self, tag, cseq, nsq, wsq):
        request, native, image = self.frames('CONTROL', fc=3)
        self.exchange(tag + '_request', self.v.packet(24, cseq, wsq, payload=request),
                      self.v.packet(24, cseq, nsq, payload=request))
        cseq += len(request)
        ack = self.v.packet(16, nsq, cseq, reverse=True)
        response = self.v.packet(24, nsq, cseq, reverse=True, payload=native)
        wire_ack = mp.rp.preserve_options(ack, self.v.packet(16, wsq, cseq, reverse=True))
        expected = mp.rp.preserve_options(response, self.v.packet(24, wsq, cseq, reverse=True, payload=image))
        log = view.log_path()

        # the original timed pair, as in RelayGate.actual_exchange(timed=True)
        self.m.drain(self.ports)
        offset, before = view.size(log), self.outcomes()
        self.m.send(self.relay.dev_port, ack)
        self.m.send(self.relay.dev_port, response)
        got = self.m.capture(self.ports, timeout=4, quiet=.4)
        frames = got.get(self.master.dev_port, [])
        exact = len(frames) == 2 and all(self.h.same_frame(f, want, want) for f, want in zip(frames, (wire_ack, expected)))
        self.add(tag + '_timed_ACK_then_complete_response', True, exact, received=got)
        verify_control_delivery(native, frames[-1])
        view.wait_idle(log)
        original = t_summary(view.records_since(log, offset))
        original['outcome_deltas'] = dict(zip(map(str, OUTCOMES), [a - b for a, b in zip(self.outcomes(), before)]))

        # the master never ACKs it (the physical loss rule drops it after capture); the relay retransmits it
        mp.rp.advance_timestamp()
        retransmission = self.v.packet(24, nsq, cseq, reverse=True, payload=native)
        want = mp.rp.preserve_options(retransmission, self.v.packet(24, wsq, cseq, reverse=True, payload=image))
        self.m.drain(self.ports)
        offset, before, encoding = view.size(log), self.outcomes(), self.encoding_state()
        self.m.send(self.relay.dev_port, retransmission)
        got = self.m.capture(self.ports, timeout=4, quiet=.4)
        frames = got.get(self.master.dev_port, [])
        delivered = len(frames) == 1 and self.h.same_frame(frames[0], want, retransmission)
        view.wait_idle(log)
        held = t_summary(view.records_since(log, offset))
        held['outcome_deltas'] = dict(zip(map(str, OUTCOMES), [a - b for a, b in zip(self.outcomes(), before)]))
        after = self.encoding_state()
        held['encoding_deltas'] = {k: (after[k] - encoding[k]) & 0xffffffff for k in after}
        held['delivered_exact_image_once'] = delivered
        held['frames_per_port'] = {str(port): len(items) for port, items in got.items()}
        # recorded, never a pass/fail of the hypothesis
        self.report.add(tag + '_retransmission_observation', 'recorded', 'recorded', ok=True,
                        original_pair=original, retransmission=held)
        self.observations.append(dict(tag=tag, history=self.history, original_pair=original, retransmission=held))

        self.exchange(tag + '_mapped_complete_ACK', self.v.packet(16, cseq, wsq + len(image)),
                      self.v.packet(16, cseq, nsq + len(native)))
        return cseq, nsq + len(native), wsq + len(image)

    def run(self):
        if not self.response_ready_v2:
            raise ValueError('diagnostic requires the response_ready_ack_d_v2 profile')
        self.observations = []
        meta = self.report.record['meta']
        meta.update(planned_connections=2, gap_ns=GAP_NS, hypothesis='H-M1b', completed_connections=[])
        for connection, history in enumerate(('mixed', 'integrity')):
            self.history = history
            state = self.handshake(10000 + 100000 * connection, 20000 + 100000 * connection, 'c%d_' % connection)
            self.control_boundary_probed = True          # boundary probes belong to the gate driver
            self.m.set_default('p1.t_Ingress.params', 't_Ingress.set_params',
                dict(da=1_000_000, readiness=2_000_000_000, cap=1_500_000_000, gap=GAP_NS,
                     op_j=200_000_000, budget=240_000, pb=1_000_000_000, enabled=1))
            for cycle in range(2):
                tag = 'c%d_%d_%s' % (connection, cycle, history)
                state = self.actual_exchange(tag, history, *state, k=cycle, timed=True)
                state = self.select_with_retransmission(tag + '_SELECT', *state)
                before = self.h.scalar(self.m.register_read('p1.t_Ingress.outcomes', 5, pipe=1))
                state = self.actual_exchange(tag + '_OPERATE', 'CONTROL', *state, fc=4, timed=True)
                after = self.h.scalar(self.m.register_read('p1.t_Ingress.outcomes', 5, pipe=1))
                self.add(tag + '_J_release_once', 1, after - before)
            self.close(*state, 'c%d_close' % connection)
            meta['completed_connections'].append(connection)
        meta['observations'] = self.observations


def main():
    h = mp.load('_relay_helpers', Path(__file__).resolve().parents[3] / 'response_only/model_drive_composite.py')
    cp = mp.load('_relay_cp', Path(__file__).resolve().parents[2] / 'cp.py')
    inputs = json.loads(Path(os.environ['PORT_MAP']).read_text())
    if inputs['supported_profile'].get('endpoint_profile') != 'sel751':
        raise ValueError('diagnostic requires the sel751 source-bound profile')
    report = h.Report(os.environ['PROG'], physical=False,
                      scope='diagnostic H-M1b: SELECT-response retransmission after mixed vs integrity READ, T on, D=20 ms',
                      driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    gate = RetransmitGate(report, h.Model(ports=[], enable=False), h, cp)
    try:
        gate.configure(); gate.run()
    except Exception:
        report.add('exception', 'none', traceback.format_exc(), ok=False)
    report.add('all_planned_connections_completed', 2, len(report.record['meta'].get('completed_connections', [])))
    return 0 if report.finish(Path(os.environ['OUT']) / 'relay_select_retransmit_results.json') else 1


if __name__ == '__main__':
    raise SystemExit(main())

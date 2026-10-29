"""Current guarded SEL-751 SELECT/OPERATE model cases, including transport-correct delivery of application errors."""
import hashlib
import json
import os
import sys
import time
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import model_packets as mp
from two_read_templates import select_templates

from relay_sbo_vectors import OBJECTS as OBJECTS, frame as frame, control_frame, control_image

__all__ = ['OBJECTS', 'frame', 'control_frame', 'control_image', 'RelayGate',
           'verify_control_delivery', 'main', 'mp']


def verify_control_delivery(native, received):
    """Decode captured bytes independently: valid network/link checksums and all32 original app octets."""
    mp.assert_ip_tcp(received)
    payload = mp.tcp_payload(received)
    frames = mp.rp.split_frames(payload)
    if len(payload) != 60 or [len(item) for item in frames] != [28, 32]:
        raise AssertionError('captured control image is not 60 octets in [28,32] frames')
    for item in frames:
        mp.std.deframe(item)
    fragments, errors = mp.std.reassemble(frames)
    original = mp.std.deframe(native)[1][1:]
    if errors or len(fragments) != 1 or len(original) != 32 or fragments[0][0] != original:
        raise AssertionError('captured control image changed or truncated native application bytes')
    return dict(application_octets=len(fragments[0][0]), frames=[len(item) for item in frames],
                application_hex=fragments[0][0].hex())


def verify_encoding_effect(before, after, commits=1, replays=0, growth=11):
    actual = dict(commit=after['commit'] - before['commit'], replay=after['replay'] - before['replay'],
                  growth=(after['growth'] - before['growth']) & 0xffffffff)
    expected = dict(commit=commits, replay=replays, growth=growth)
    if actual != expected:
        raise AssertionError('control accounting %r != %r' % (actual, expected))
    return actual


def verify_partial_ack(sent, normalized, native_start, wire_start):
    """An interior ACK is normalized to the native START for N to withhold, with options preserved."""
    offset = (mp.tcp_ack(sent) - wire_start) & 0xffffffff
    if offset not in (28, 29, 59):
        raise AssertionError('not one of the explicit whole49 interior ACK probes')
    distance = 60 - offset
    expected = bytearray(sent)
    expected[42:46] = (native_start & 0xffffffff).to_bytes(4, 'big')
    window = mp.rp.reverse_window(int.from_bytes(sent[48:50], 'big'), distance, 49)
    expected[48:50] = window.to_bytes(2, 'big')
    expected = mp.fix_checksums(bytes(expected))
    mp.assert_ip_tcp(normalized)
    trailer = normalized[len(expected):]
    if (normalized[:len(expected)] != expected or any(trailer)
            or len(trailer) > max(0, 64 - len(sent))):
        raise AssertionError('interior ACK normalization changed the native frontier, window, or options')
    return dict(wire_offset=offset, native_ack=native_start, window=window)


class RelayGate(mp.PacketGate):
    def configure(self):
        super().configure()
        inputs = json.loads(Path(os.environ['PORT_MAP']).read_text())
        self.timing_contract = (inputs.get('supported_profile') or {}).get('timing_contract')
        self.response_ready_v2 = self.timing_contract in ('response_ready_ack_d_v2', 'response_ready_ack_d_no_j_v3')
        self.templates, self.template_path = select_templates(ROOT / 'tests/fixtures/vectors', mp.rp.SHAPES)
        self.seqs = dict(master=0, app=0, server=0)
        gc = self.h.gc
        mirror = self.m.table('$mirror.cfg', raw=True)
        mirror.entry_add(gc.Target(device_id=0, pipe_id=0xffff),
            [mirror.make_key([gc.KeyTuple('$sid', 7)])],
            [mirror.make_data([gc.DataTuple('$direction', str_val='INGRESS'),
                               gc.DataTuple('$ucast_egress_port', self.h.PKTGEN_RETURN),
                               gc.DataTuple('$ucast_egress_port_valid', bool_val=True),
                               gc.DataTuple('$session_enable', bool_val=True)], '$normal')])

    def handshake(self, cseq, sseq, tag=''):
        self.seqs = dict(master=0, app=0, server=0)
        self.control_boundary_probed = False
        return super().handshake(cseq, sseq, tag)

    def encoding_state(self):
        counter = self.m.table('p0.r_Egress.outcome')
        for operation in ('Sync', 'SyncCounters'):
            try:
                counter.operations_execute(self.m.target, operation)
                break
            except Exception:
                pass
        result = dict(growth=self.growth())
        for name, code in (('commit', 1), ('replay', 4)):
            values = list(counter.entry_get(self.m.target,
                [counter.make_key([self.h.gc.KeyTuple('$COUNTER_INDEX', code)])], {'from_hw': True}))
            if len(values) != 1:
                raise ValueError('missing E %s outcome counter' % name)
            value = values[0][0].to_dict()['$COUNTER_SPEC_PKTS']
            result[name] = sum(value) if isinstance(value, list) else value
        return result

    def probe_control_boundary(self, tag, cseq, nsq, wsq, native, image):
        before = self.encoding_state()
        for offset in (28, 29, 59):
            sent = self.v.packet(16, cseq, wsq + offset)
            mp.rp.advance_timestamp()
            got = self.m.exchange(self.master.dev_port, sent, self.ports + [self.pm.n_ack_return],
                                  timeout=.5, quiet=.03)
            private = [raw for raw in got[self.pm.n_ack_return] if len(raw) >= 70 and raw[12] == 0xe1]
            self.add(tag + '_partial%d_no_public_departure' % offset, 0,
                     sum(len(got[port]) for port in self.ports), received=got)
            self.add(tag + '_partial%d_private_normalization_once' % offset, 1, len(private), received=got)
            details = verify_partial_ack(sent, private[0][16:], nsq, wsq)
            self.add(tag + '_partial%d_native_start_withheld' % offset, nsq, details['native_ack'], **details)
            effect = verify_encoding_effect(before, self.encoding_state(), commits=0, growth=0)
            self.add(tag + '_partial%d_no_commit_or_growth' % offset,
                     dict(commit=0, replay=0, growth=0), effect)
        replay = self.v.packet(24, nsq, cseq, reverse=True, payload=native)
        expected = self.v.packet(24, wsq, cseq, reverse=True, payload=image)
        got = self.exchange(tag + '_whole49_retransmission_before_ACK', replay, expected, reverse=True)
        verify_control_delivery(native, got)
        effect = verify_encoding_effect(before, self.encoding_state(), commits=0, replays=1, growth=0)
        self.add(tag + '_replay_once_no_second_commit_or_growth', dict(commit=0, replay=1, growth=0), effect)

    def frames(self, cls, k=0, fc=3, statuses=(0, 0)):
        qseq, app, sseq = self.seqs['master'], self.seqs['app'], self.seqs['server']
        if cls == 'CONTROL':
            request = control_frame(qseq, app, fc=fc)
            native = control_frame(sseq, app, response=True, statuses=statuses)
            image = control_image(native)
        else:
            template = self.templates['v%d' % (k % 2)]['classes'][cls]
            def resequence(raw, seq):
                header, user = mp.std.deframe(bytes.fromhex(raw))
                # Link addresses in these relay captures are already relay0/master1.
                return mp.std.frame(header, bytes([0xc0 | seq, (user[1] & 0xf0) | app]) + user[2:])
            request = resequence(template['request'], qseq)
            native = resequence(template['native'], sseq)
            image = mp.rp.construct(native)
        self.seqs = dict(master=(qseq + 1) & 63, app=(app + 1) & 15, server=(sseq + 1) & 63)
        return request, native, image

    def actual_exchange(self, tag, cls, cseq, nsq, wsq, k=0, fc=3, statuses=(0, 0), timed=False):
        request, native, image = self.frames(cls, k, fc, statuses)
        self.exchange(tag + '_request', self.v.packet(24, cseq, wsq, payload=request),
                      self.v.packet(24, cseq, nsq, payload=request))
        cseq += len(request)
        ack = self.v.packet(16, nsq, cseq, reverse=True)
        wire_ack = self.v.packet(16, wsq, cseq, reverse=True)
        response = self.v.packet(24, nsq, cseq, reverse=True, payload=native)
        wire_ack = mp.rp.preserve_options(ack, wire_ack)
        expected = mp.rp.preserve_options(response, self.v.packet(24, wsq, cseq, reverse=True, payload=image))
        encoding_before = self.encoding_state() if cls == 'CONTROL' else None
        expected_replays = 0
        if timed:
            self.m.drain(self.ports)
            before = [self.h.scalar(self.m.register_read('p1.t_Ingress.outcomes', i, pipe=1)) for i in (2, 3, 8, 9)]
            self.m.send(self.relay.dev_port, ack)
            self.m.send(self.relay.dev_port, response)
            self.captures['sent'].extend((time.time_ns() // 1000, item) for item in (ack, response))
            got = self.m.capture(self.ports, timeout=4, quiet=.4)
            frames = got.get(self.master.dev_port, [])
            self.captures['received'].extend((time.time_ns() // 1000, item) for items in got.values() for item in items)
            exact = len(frames) == 2 and all(self.h.same_frame(f, want, want) for f, want in zip(frames, (wire_ack, expected)))
            self.add(tag + '_timed_ACK_then_complete_response', True, exact, received=got)
            for item in frames:
                mp.assert_ip_tcp(item)
            received_response = frames[-1]
            if mp.rp.TCP_TIMESTAMPS:
                self.add(tag + '_timed_timestamp_delivery_order', True, mp.rp.timestamp_order_ok(frames))
            after = [self.h.scalar(self.m.register_read('p1.t_Ingress.outcomes', i, pipe=1)) for i in (2, 3, 8, 9)]
            self.add(tag + ('_committed_no_request_retry' if self.response_ready_v2 else '_committed_no_fallback'), [1, 1, 0, 0], [a - b for a, b in zip(after, before)])
        else:
            self.exchange(tag + '_ACK', ack, wire_ack, reverse=True)
            received_response = self.exchange(tag + '_complete_response', response, expected, reverse=True)
            mp.assert_ip_tcp(received_response)
        if cls == 'CONTROL':
            info = verify_control_delivery(native, received_response)
            self.add(tag + '_captured_all32_application_octets', mp.std.deframe(native)[1][1:].hex(),
                     info['application_hex'])
            self.add(tag + '_captured_wire_partition', [28, 32], info['frames'])
            effect = verify_encoding_effect(encoding_before, self.encoding_state())
            self.add(tag + '_one_commit_and_11_growth', dict(commit=1, replay=0, growth=11), effect)
            if not self.control_boundary_probed:
                self.probe_control_boundary(tag, cseq, nsq, wsq, native, image)
                self.control_boundary_probed = True
                expected_replays = 1
        self.exchange(tag + '_mapped_complete_ACK', self.v.packet(16, cseq, wsq + len(image)),
                      self.v.packet(16, cseq, nsq + len(native)))
        if cls == 'CONTROL':
            effect = verify_encoding_effect(encoding_before, self.encoding_state(), replays=expected_replays)
            self.add(tag + '_logical_response_single_commit_and_11_growth',
                     dict(commit=1, replay=expected_replays, growth=11), effect)
        return cseq, nsq + len(native), wsq + len(image)

    def run(self):
        self.report.record['meta']['planned_connections'] = 3
        completed = self.report.record['meta']['completed_connections'] = []
        for connection in range(3):
            state = self.handshake(10000 + 100000 * connection, 20000 + 100000 * connection, 'c%d_' % connection)
            timed = connection == 1
            self.m.set_default('p1.t_Ingress.params', 't_Ingress.set_params',
                dict(da=1_000_000, readiness=2_000_000_000, cap=1_500_000_000, gap=50_000_000,
                     op_j=200_000_000, budget=240_000, pb=1_000_000_000, enabled=int(timed)))
            for cycle in range(8):
                for cls in ('mixed', 'integrity'):
                    tag = 'c%d_%d_%s' % (connection, cycle, cls)
                    state = self.actual_exchange(tag, cls, *state, k=cycle, timed=timed)
                    state = self.actual_exchange(tag + '_SELECT', 'CONTROL', *state, fc=3, timed=timed)
                    before = self.h.scalar(self.m.register_read('p1.t_Ingress.outcomes', 5, pipe=1))
                    state = self.actual_exchange(tag + '_OPERATE', 'CONTROL', *state, fc=4, timed=timed)
                    after = self.h.scalar(self.m.register_read('p1.t_Ingress.outcomes', 5, pipe=1))
                    if timed and self.timing_contract != 'response_ready_ack_d_no_j_v3':
                        self.add(tag + '_J_release_once', 1, after - before)
            self.close(*state, 'c%d_close' % connection)
            completed.append(connection)


def main():
    h = mp.load('_relay_helpers', HERE / 'model_drive_composite.py')
    cp = mp.load('_relay_cp', HERE / 'cp.py')
    inputs = json.loads(Path(os.environ['PORT_MAP']).read_text())
    if inputs['supported_profile'].get('endpoint_profile') != 'sel751':
        raise ValueError('relay SBO gate requires sel751 source-bound profile')
    report = h.Report(os.environ['PROG'], physical=False, scope='whole49 actual SEL751 two-CROB and two-READ model gate',
                      driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    gate = RelayGate(report, h.Model(ports=[], enable=False), h, cp)
    try:
        gate.configure(); gate.run()
    except Exception:
        report.add('exception', 'none', traceback.format_exc(), ok=False)
    planned = report.record['meta'].get('planned_connections', 3)
    report.add('all_planned_connections_completed', planned, len(report.record['meta'].get('completed_connections', [])))
    return 0 if report.finish(Path(os.environ['OUT']) / 'relay_sbo_results.json') else 1


if __name__ == '__main__':
    raise SystemExit(main())

"""Strict response-ready compiled-model gate; acceptance uses T's clock, never wall time.

Wall deadlines only bound driver I/O. Captured complete relay responses are the existing
91/134/49-octet fixtures. Failure to reach a planned model-clock construction fails coverage.
"""
import copy
import hashlib
import json
import os
import re
import select
import socket
import struct
import sys
import time
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
UNIT_NS, WRAP = 256, 1 << 32
D_VALUES = (5_000_000, 10_000_000, 15_000_000, 20_000_000)
WAIT_NS = 500_000_000
NAMES = ('UNMATCHED', 'HELD_REWAIT', 'ACK_COMMIT', 'RESP_RELEASE', 'RESP_DUP_DROP', 'OP_RELEASE',
         'TOKEN_STALE', 'HELD_STALE_FLUSH', 'WAIT_EXPIRED', 'EXPIRED_DROP', 'TOKEN_TMO',
         'HELD_OFF_FLUSH', 'TOKEN_OFF', 'REQ_BYPASS', 'OLD_EPOCH_DROP', 'GEN_EXHAUSTED', 'OP_DUP_DROP')


def delta(later, earlier):
    return None if later is None or earlier is None else (later - earlier) % WRAP




class LiveIngress:
    """Incrementally read model ingress evidence; each log byte is parsed once during live waits.

    The state machine matches reset_application_check.ingress_records, including its
    per-pipe attribution across interleaved egress records. Full retained evidence is
    still independently reparsed after the exchange resolves.
    """
    def __init__(self, path, offset):
        import reset_application_check as rac
        self.path, self.offset, self.rac = path, offset, rac
        self.pending, self.first = b'', bool(offset)
        self.records, self.current, self.dumping = [], {}, {}
        self.latest_units = None
        self.transitions, self.state_register, self.state_before = [], False, None

    def poll(self):
        with open(self.path, 'rb') as log:
            log.seek(self.offset)
            chunk = log.read()
            self.offset = log.tell()
        data = self.pending + chunk
        complete = data.rfind(b'\n')
        if complete < 0:
            self.pending = data
            return
        self.pending = data[complete + 1:]
        lines = data[:complete + 1].decode(errors='replace').splitlines()
        if self.first and lines:
            if not lines[0].startswith(':'):
                lines = lines[1:]
            self.first = False
        for raw in lines:
            match = self.rac.LINE.match(raw)
            if not match:
                continue
            wall, pipe, text = match.group(1), int(match.group(2)), match.group(3).strip()
            if text.startswith('==========') and 'Ingress Pkt from port' in text:
                port = int(re.search(r'Ingress Pkt from port (\d+)', text).group(1))
                record = dict(wall=wall, pipe=pipe, frame='', actions=[], t_units=None,
                              port=port, ordinal=len(self.records))
                self.records.append(record)
                self.current[pipe], self.dumping[pipe] = record, 'header'
                if pipe == 1:
                    self.state_register, self.state_before = False, None
                continue
            if text.startswith('=========='):
                self.dumping[pipe] = None
                continue
            if text == 'Packet :':
                if self.dumping.get(pipe) == 'header':
                    self.dumping[pipe] = 'ingress'
                continue
            if self.dumping.get(pipe) == 'ingress' and self.rac.HEX.match(text):
                self.current[pipe]['frame'] += text.replace(' ', '')
                continue
            if self.dumping.get(pipe) == 'ingress':
                self.dumping[pipe] = None
            if 'global_tstamp[39:8]' in text and 'to value' in text and pipe in self.current and \
                    self.current[pipe]['t_units'] is None:
                self.current[pipe]['t_units'] = int(re.search(r'to value\s+(0x[0-9a-f]+)', text).group(1), 16) & ~1
                if pipe == 1:
                    self.latest_units = self.current[pipe]['t_units']
                continue
            action = self.rac.ACTION.search(text)
            if action:
                owner = 1 if action.group(1).startswith('t_') else 0
                if owner in self.current:
                    self.current[owner]['actions'].append(action.group(1))
            if pipe == 1 and '----- register:' in text:
                self.state_register = 't_Ingress.ack_done_reg -----' in text
                self.state_before = None
            if pipe == 1 and self.state_register and 'Before stateful alu execution:' in text:
                self.state_before = int(text.rsplit(':', 1)[1], 16)
            if pipe == 1 and self.state_register and 'After stateful alu execution:' in text:
                stamp = self.current.get(1, {}).get('t_units')
                if stamp is not None and self.state_before is not None:
                    self.transitions.append(dict(t_units=stamp, before=self.state_before,
                                                 after=int(text.rsplit(':', 1)[1], 16)))
                self.state_register, self.state_before = False, None

    @property
    def expired(self):
        return any(event['before'] >> 16 != 2 and event['after'] >> 16 == 2 for event in self.transitions)

    def action(self, name):
        return next((record for record in self.records if 't_Ingress.' + name in record['actions']), None)

    def frame(self, port, raw):
        frame = raw.hex()
        return next((record for record in self.records if record['port'] == port and
                     record['frame'].startswith(frame)), None)

def completion_transitions(lines, register_name='ack_done_reg'):
    """Observe the actual ACK completion SALU state transition on that ingress pass's T clock."""
    import reset_application_check as rac
    stamp, register, before, transitions = None, False, None, []
    for line in lines:
        match = rac.LINE.match(line.rstrip('\n'))
        if not match or int(match.group(2)) != 1:
            continue
        text = match.group(3).strip()
        if text.startswith('==========') and 'Ingress Pkt from port' in text:
            stamp, register, before = None, False, None
        if 'global_tstamp[39:8]' in text and 'to value' in text and stamp is None:
            stamp = int(re.search(r'to value\s+(0x[0-9a-f]+)', text).group(1), 16) & ~1
        if '----- register:' in text:
            register = ('t_Ingress.' + register_name + ' -----') in text
            before = None
        if register and 'Before stateful alu execution:' in text:
            before = int(text.rsplit(':', 1)[1], 16)
        if register and 'After stateful alu execution:' in text:
            after = int(text.rsplit(':', 1)[1], 16)
            if stamp is not None and before is not None:
                transitions.append(dict(t_units=stamp, before=before, after=after))
            register, before = False, None
    return transitions


def arrival_order_problems(point):
    """Socket send order is only a stimulus; qualification requires the observed T arrival order."""
    order = point.get('order')
    ack, response = point.get('held_ack_units'), point.get('response_arrival_units')
    ack_ordinal, response_ordinal = point.get('ack_arrival_ordinal'), point.get('response_arrival_ordinal')
    if order not in ('ack_first', 'response_first') or any(type(value) is not int for value in
            (ack, response, ack_ordinal, response_ordinal)):
        return ['actual T ACK/response arrival order was not measured']
    if ack == response:
        observed = 'ack_first' if ack_ordinal < response_ordinal else 'response_first'
        valid = ack_ordinal != response_ordinal
    else:
        observed = 'ack_first' if delta(response, ack) < WRAP // 2 else 'response_first'
        valid = True
    return [] if valid and observed == order else ['declared %s arrival order was not constructed at T' % order]

def committed_problems(point, gap_units, wait_units):
    """Causal proof using actual T arrival, atomic commit and release pass timestamps."""
    problems = arrival_order_problems(point)
    t0, arrival, commit, release = (point.get(k) for k in
        ('t0_units', 'response_arrival_units', 'ack_release_units', 'response_release_units'))
    if any(v is None for v in (t0, arrival, commit, release)):
        return ['missing T-clock admission/whole-response/ACK-commit/response-release evidence']
    if delta(commit, arrival) >= WRAP // 2:
        problems.append('ACK committed before matching whole response reached T')
    if delta(commit, t0) >= wait_units:
        problems.append('ACK committed at or after WAITING expiry')
    if delta(release, commit) < gap_units:
        problems.append('response released before ACK commit + D')
    if point.get('lane') != dict(ACK_COMMIT=1, RESP_RELEASE=1, WAIT_EXPIRED=0, EXPIRED_DROP=0):
        problems.append('not exactly one committed ACK and response without expiry')
    if point.get('master_frames') != ['ack', 'response']:
        problems.append('wire frames differ from exact genuine ACK then whole encoded response')
    return problems




def timer_from_read_seed(seed, token_builder, buffer):
    """Model stimulus from an actual mirrored READ seed; T must produce the ladder frame itself."""
    if len(seed) < 20 or seed[:2] != b'\xe1\x00' or seed[16:20] != b'\x09\x00\x00\x00':
        raise ValueError('a captured READ clone is required for the model timer')
    generation = int.from_bytes(seed[2:4], 'big')
    if not 0 < generation < 0xffff:
        raise ValueError('captured READ clone has no usable generation')
    return token_builder(gen=generation, packet_id=0, profile=0, pipe=1)[:6] + buffer


def post_release_replay_problems(point):
    problems = []
    if point.get('exact_frame') is not True or point.get('output_frames') != 1:
        problems.append('post-release replay did not deliver exactly one complete encoded response')
    if point.get('encoding_delta') != dict(commit=0, replay=1, growth=0):
        problems.append('post-release replay changed logical commit/growth or did not count one replay')
    if point.get('lane_delta') != dict(ACK_COMMIT=0, RESP_RELEASE=0, WAIT_EXPIRED=0, EXPIRED_DROP=0):
        problems.append('post-release replay changed T completion/expiry')
    release, arrival = point.get('primary_release_units'), point.get('replay_arrival_units')
    if release is None or arrival is None or delta(arrival, release) >= WRAP // 2:
        problems.append('replay was not observed at T after the original response released')
    return problems


def token_source_problems(point):
    """Bind an expired-A blocker to the observed READ seed, explicit timer, and actual T emission."""
    source, artifacts = point.get('token_source') or {}, point.get('artifacts') or {}
    problems = []
    try:
        seed, timer, blocker = [bytes.fromhex(source[key]) for key in
            ('seed_frame_hex', 'timer_frame_hex', 'blocker_frame_hex')]
    except (KeyError, TypeError, ValueError):
        return ['missing captured seed/model timer/source-produced blocker provenance']
    generation = point.get('generation_after')
    if seed.hex() != artifacts.get('seed') or blocker.hex() != artifacts.get('token') or len(seed) < 20 or \
            seed[:2] != b'\xe1\x00' or seed[16:20] != b'\x09\x00\x00\x00' or int.from_bytes(seed[2:4], 'big') != generation:
        problems.append('model timer source is not the actual A READ clone/generation')
    if len(timer) != 66 or timer[:2] != b'\x08\x00' or int.from_bytes(timer[2:4], 'big') != generation or \
            timer[4:6] != b'\x00\x00' or timer[10:12] != b'\x08\x00':
        problems.append('model timer is not the valid pipe1/app0/A-generation/ACK token format')
    if len(blocker) != 68 or blocker[:2] != b'\x0b\x00' or int.from_bytes(blocker[2:4], 'big') != generation or \
            blocker[8:] != timer[6:] or not 0 < int.from_bytes(blocker[4:8], 'big') <= 240000:
        problems.append('role11 artifact was not the blocker emitted from that timer')
    if source.get('source_action') != 't_Ingress.seed_ack_blocker' or source.get('timer_port') != 196 or source.get('blocker_port') != 182:
        problems.append('compiled T seeding action and HELD_RETURN ingress not observed')
    expiry = point.get('atomic_expiry_units') or []
    seed_stamp, blocker_stamp = source.get('source_t_units'), source.get('blocker_t_units')
    if len(expiry) != 1 or seed_stamp is None or blocker_stamp is None or \
            delta(seed_stamp, expiry[0]) >= WRAP // 2 or delta(blocker_stamp, seed_stamp) >= WRAP // 2:
        problems.append('expired A/source-token/source-blocker model-clock provenance missing')
    if source.get('lane_delta') != dict(ACK_COMMIT=0, RESP_RELEASE=0, WAIT_EXPIRED=0) or \
            source.get('state_after') != (0x20000 | (generation or 0)):
        problems.append('model timer reopened or changed expired A completion')
    return problems

def generation_isolation_problems(point):
    """Require A's artifact to be observed during the intended B phase, with B's state intact."""
    problems = []
    probe = point.get('stale_probe') or {}
    kind, phase = probe.get('kind'), probe.get('phase')
    if kind not in ('late_ACK', 'stale_response', 'expired_token') or phase not in ('waiting', 'committed'):
        return ['missing generation A-to-B artifact/phase declaration']
    generation = point.get('generation_after')
    if not isinstance(generation, int) or not isinstance(point.get('generation_before'), int) or \
            generation != point['generation_before'] + 1 or             not isinstance(probe.get('source_generation'), int) or not 0 < probe['source_generation'] < generation:
        problems.append('A/B generations not distinct or B allocated more than once')
    ordinal = probe.get('ingress_ordinal')
    lower = probe.get('held_ack_ordinal' if phase == 'waiting' else 'ack_commit_ordinal')
    upper = probe.get('response_arrival_ordinal' if phase == 'waiting' else 'response_release_ordinal')
    if any(not isinstance(value, int) for value in (ordinal, lower, upper)) or not lower < ordinal < upper:
        problems.append('old A artifact ingress was not established during B ' + phase)
    if kind == 'expired_token':
        if probe.get('source_epoch') == point.get('epoch'):
            problems.append('expired A did not recover through a new handshake before B')
        stamp = probe.get('ingress_t_units')
        if stamp is None:
            problems.append('expired A token has no actual T-clock ingress')
        elif phase == 'committed' and (point.get('ack_release_units') is None or
                point.get('response_release_units') is None or
                delta(stamp, point['ack_release_units']) >= WRAP // 2 or
                delta(point['response_release_units'], stamp) >= WRAP // 2):
            problems.append('expired A token did not enter T between B commit and response release')
    elif probe.get('source_epoch') != point.get('epoch'):
        problems.append('late A native packet did not exercise same-connection B')
    units = point.get('written_units') or {}
    if not isinstance(units.get('gap'), int) or not isinstance(units.get('response_wait_timeout'), int):
        problems.append('missing actual B timing units')
    else:
        problems.extend(committed_problems(point, units['gap'], units['response_wait_timeout']))
    if point.get('atomic_commit_units') != [point.get('ack_release_units')] or point.get('atomic_expiry_units') != []:
        problems.append('old A artifact changed B atomic completion')
    state_events = point.get('ack_state_transitions') or []
    if not state_events:
        problems.append('B completion state was not measured during A artifact injection')
    for event in state_events:
        expected_status = 1 if point.get('ack_release_units') is not None and delta(
            event['t_units'], point['ack_release_units']) < WRAP // 2 else 0
        if event['after'] != ((generation or 0) | (expected_status << 16)):
            problems.append('old A artifact transiently changed B completion generation/status')
            break
    commit, t0 = point.get('ack_release_units'), point.get('t0_units')
    for register, expected in (('t0_reg', t0), ('gen_alloc_reg', generation), ('cur_epoch_reg', point.get('epoch'))):
        events = (point.get('lane_registers') or {}).get(register) or []
        if not events or any(event['after'] != expected for event in events):
            problems.append('old A artifact changed or left unmeasured B ' + register)
    for register, expected in (('ack_commit_at_reg', commit), ('ack_commit_gen_reg', generation)):
        events = [event for event in (point.get('lane_registers') or {}).get(register, [])
                  if commit is not None and delta(event['t_units'], commit) < WRAP // 2]
        if not events or any(event['after'] != expected for event in events):
            problems.append('old A artifact changed or left unmeasured B ' + register)
    return problems

def main(*, control_only=False):
    sys.path.insert(0, str(HERE))
    from model_profile import from_env, RESPONSE_READY
    profile = from_env()
    if profile.get('timing_contract') != RESPONSE_READY:
        raise ValueError('response_ready requires source-bound response_ready_ack_d_v1')
    from model_relay_sbo import RelayGate, mp
    import model_log_view as view
    import reset_application_check as rac
    sys.path.insert(0, str(HERE.parents[2]))
    from model_driver import veth_for

    class ReadyGate(RelayGate):
        def configure(self):
            super().configure()
            self.log = view.log_path()
            if self.log is None:
                raise ValueError('model T-clock log is required')
            self.fast = {}
            for port in self.ports:
                sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
                sock.bind((veth_for(port), 0))
                self.fast[port] = sock
                self.m._listen(port)
            for port in (self.pm.t_in, self.pm.held_return, self.pm.hb_return):
                sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
                sock.bind((veth_for(port), 0))
                self.fast[port] = sock
            port = self.h.PKTGEN_RETURN
            if port not in self.fast:
                sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
                sock.bind((veth_for(port), 0))
                self.fast[port] = sock
            self.isn = 1_000_000
            self.points = self.report.record['meta'].setdefault('points', [])

        def outcomes(self):
            return {name: self.h.scalar(self.m.register_read('p1.t_Ingress.outcomes', i, pipe=1))
                    for i, name in enumerate(NAMES)}

        def collect(self, duration=.01):
            socks = {self.m._listen(port): port for port in self.ports}
            ready, _, _ = select.select(list(socks), [], [], duration)
            frames = []
            for sock in ready:
                while True:
                    try:
                        data, addr = sock.recvfrom(4096)
                    except BlockingIOError:
                        break
                    if addr[2] != 4:
                        frames.append((socks[sock], data))
            return frames

        def all_records(self, offset):
            records = rac.ingress_records(view.lines_since(self.log, offset))
            for index, record in enumerate(records):
                record['ordinal'] = index
                if record['t_units'] is not None:
                    record['raw_t_units'] = record['t_units']
                    record['t_units'] &= ~1
            return records

        def records(self, offset):
            return [record for record in self.all_records(offset) if record['pipe'] == 1]

        def clock_wait(self, live, target_ns, captured):
            end = time.monotonic() + 10
            while time.monotonic() < end:
                captured.extend(self.collect(.001))
                live.poll()
                anchor = live.action('admit_t0')
                if anchor and live.latest_units is not None and delta(
                        live.latest_units, anchor['t_units']) * UNIT_NS >= target_ns:
                    return True
            return False

        def set_timing(self, gap, enabled=1):
            self.m.set_default('p1.t_Ingress.params', 't_Ingress.set_params',
                dict(gap=gap, op_j=2_400_000, response_wait_timeout=WAIT_NS, budget=240_000, enabled=enabled))
            self.written = json.loads((Path(os.environ['OUT']) / 't_params_written.json').read_text())[-1]['written']

        def new_connection(self, tag):
            self.isn += 100_000
            return self.handshake(self.isn, self.isn + 50_000, tag + '_')

        def exchange_ready(self, tag, cls, state, fc=3, order='ack_first', response_at_ns=0, absent=False,
                           duplicate=False, reset=False, invalid=None, retransmit=False, cross_expiry=False,
                           no_ack=False, stale_probe=None, expire_before_response=False):
            c, n, w = state
            request, native, image = self.frames(cls, 0, fc)
            cend = c + len(request)
            mp.rp.advance_timestamp()
            req = self.v.packet(24, c, w, payload=request)
            req_want = self.v.packet(24, c, n, payload=request)
            mp.rp.advance_timestamp()
            ack = self.v.packet(16, n, cend, reverse=True)
            ack_want = mp.rp.preserve_options(ack, self.v.packet(16, w, cend, reverse=True))
            mp.rp.advance_timestamp()
            rsp = self.v.packet(24, n, cend, reverse=True, payload=native)
            rsp_want = mp.rp.preserve_options(rsp, self.v.packet(24, w, cend, reverse=True, payload=image))
            observer_rpc = []

            def observe_rpc(label, call):
                start = time.monotonic_ns()
                value = call()
                observer_rpc.append(dict(label=label, start_monotonic_ns=start, end_monotonic_ns=time.monotonic_ns()))
                return value

            before = observe_rpc('outcomes_before_request', self.outcomes)
            encoding = observe_rpc('encoding_before_request', self.encoding_state)
            generation_before = self.h.scalar(self.m.register_read('p1.t_Ingress.gen_alloc_reg', 0, pipe=1))
            epoch = self.h.scalar(self.m.register_read('p1.t_Ingress.cur_epoch_reg', 0, pipe=1))
            offset = view.size(self.log)
            live = LiveIngress(self.log, offset)
            self.m.drain(self.ports)
            captured, send_marks = [], []

            def send(port, frame, label):
                start, wall = time.monotonic_ns(), time.time_ns()
                self.fast[port].send(frame)
                send_marks.append(dict(label=label, port=port, start_monotonic_ns=start,
                    end_monotonic_ns=time.monotonic_ns(), start_wall_ns=wall, octets=len(frame)))

            send(self.master.dev_port, req, 'request')
            end = time.monotonic() + 10
            relayed = False
            while time.monotonic() < end:
                captured.extend(self.collect())
                if any(port == self.relay.dev_port and self.h.same_frame(raw, req_want, req)
                       for port, raw in captured):
                    relayed = True
                    relay_observed_ns = time.monotonic_ns()
                    break
            # Critical path: act on the genuine relay-bound request before reporting,
            # log parsing or BFRT reads can spend the exchange's fixed 500ms budget.
            if not relayed:
                self.add(tag + '_request_relayed_once', 1, 0)
                raise AssertionError(tag + ': request did not reach relay')
            phase_checks = None
            clock_target_observed, held_before_reset, forced_expiry_units = None, None, None
            response_inject_clock_units = None
            if order == 'ack_first' and not no_ack:
                send(self.relay.dev_port, ack, 'ack')
                if duplicate:
                    send(self.relay.dev_port, ack, 'ack')
            if stale_probe and stale_probe['phase'] == 'waiting':
                phase_checks = self.inject_stale_probe(tag, stale_probe, live, captured, 'hold_ack')
            if retransmit:
                send(self.master.dev_port, req, 'request_retransmission')
            if invalid is not None:
                bad_native = native[:-1] if invalid == 'incomplete' else native
                bad_seq = n if invalid == 'incomplete' else n + 100000
                send(self.relay.dev_port,
                    self.v.packet(24, bad_seq, cend, reverse=True, payload=bad_native), 'invalid_response')
            if response_at_ns:
                clock_target_observed = self.clock_wait(live, response_at_ns, captured)
            if expire_before_response:
                end = time.monotonic() + 10
                while time.monotonic() < end:
                    captured.extend(self.collect(.001))
                    live.poll()
                    if live.expired:
                        forced_expiry_units = next(event['t_units'] for event in live.transitions
                            if event['before'] >> 16 != 2 and event['after'] >> 16 == 2)
                        break
                if forced_expiry_units is None:
                    raise AssertionError(tag + ': actual expiry before response was not observed')
            if reset:
                end = time.monotonic() + 3
                held_before_reset = False
                while time.monotonic() < end:
                    captured.extend(self.collect(.001))
                    live.poll()
                    if live.action('hold_ack') is not None:
                        held_before_reset = True
                        break
                rst = self.v.packet(20, cend, w)
                send(self.master.dev_port, rst, 'reset')
            elif not absent:
                response_inject_clock_units = live.latest_units
                send(self.relay.dev_port, rsp, 'response')
                if order == 'response_first':
                    send(self.relay.dev_port, ack, 'ack')
            if stale_probe and stale_probe['phase'] == 'committed':
                phase_checks = self.inject_stale_probe(tag, stale_probe, live, captured, 'release_ack_commit')
            self.add(tag + '_request_relayed_once', 1, sum(port == self.relay.dev_port and
                self.h.same_frame(raw, req_want, req) for port, raw in captured))
            if clock_target_observed is not None:
                self.add(tag + '_model_clock_target_observed', True, clock_target_observed)
            if held_before_reset is not None:
                self.add(tag + '_held_ACK_established_before_RST', True, held_before_reset)
            if phase_checks is not None:
                self.add(tag + '_B_' + stale_probe['phase'] + '_phase_observed_before_old_A_packet', True, phase_checks[0])
                self.add(tag + '_old_A_artifact_actual_ingress_observed', True, phase_checks[1])
            actions = lambda record: [action.split('.')[-1] for action in record['actions']]
            end = time.monotonic() + 12
            resolution = None
            while time.monotonic() < end:
                captured.extend(self.collect(.003))
                live.poll()
                output_complete = any(port == self.master.dev_port and self.h.same_frame(raw, rsp_want, rsp)
                                      for port, raw in captured)
                if live.expired or output_complete or (reset and live.action('close_epoch') is not None):
                    resolution = dict(reason='expired' if live.expired else 'response_public' if output_complete else 'reset',
                                      monotonic_ns=time.monotonic_ns())
                    tail = self.m.capture(self.ports, timeout=.6, quiet=.15)
                    captured.extend((port, raw) for port, frames in tail.items() for raw in frames)
                    break
            if resolution is None:
                self.add(tag + '_observed_resolution', True, False, send_marks=send_marks,
                         observed_ingress=len(live.records))
                raise AssertionError(tag + ': no observed T expiry/reset or public whole response')
            after = observe_rpc('outcomes_after_resolution', self.outcomes)
            all_records = self.all_records(offset)
            recs = [record for record in all_records if record['pipe'] == 1]
            anchors = [record for record in recs if 'admit_t0' in actions(record)]
            if not anchors:
                raise AssertionError(tag + ': no actual admission timestamp')
            t0 = anchors[0]['t_units']
            self.add(tag + '_one_actual_request_admission_anchor', 1, len(anchors))
            transitions = completion_transitions(view.lines_since(self.log, offset))
            commits = [event['t_units'] for event in transitions
                       if event['before'] >> 16 != 1 and event['after'] >> 16 == 1]
            expiries = [event['t_units'] for event in transitions
                       if event['before'] >> 16 != 2 and event['after'] >> 16 == 2]
            def first_action(name):
                return next((r['t_units'] for r in recs if name in actions(r)), None)
            key = '%04x%04x%08x%08x' % (self.v.SERVER_PORT, self.v.CLIENT_PORT, n, cend)
            # Match the native/encoded DNP3 bytes as well as its complete TCP identity.
            response_recs = [r for r in recs if key in r['frame'] and
                             (native.hex() in r['frame'] or image.hex() in r['frame'])]
            master = [raw for port, raw in captured if port == self.master.dev_port]
            labels = ['ack' if self.h.same_frame(raw, ack_want, ack) else
                      'response' if self.h.same_frame(raw, rsp_want, rsp) else 'other' for raw in master]
            row = dict(tag=tag, cls=cls, fc=fc, order=order, response_target_ns=response_at_ns,
                       native_octets=len(native), image_octets=len(image), t0_units=t0,
                       response_arrival_units=response_recs[0]['t_units'] if response_recs else None,
                       ack_release_units=first_action('release_ack_commit'),
                       response_release_units=first_action('release_response_counted'),
                       lane={k: after[k] - before[k] for k in ('ACK_COMMIT', 'RESP_RELEASE', 'WAIT_EXPIRED', 'EXPIRED_DROP')},
                       master_frames=labels, encoding_before=encoding, encoding_after=self.encoding_state(),
                       written_units=dict(self.written),
                       operate_anchor_units=first_action('arm_operate_anchor'),
                       operate_release_units=first_action('release_operate_counted'),
                       operate_release_count=after['OP_RELEASE'] - before['OP_RELEASE'],
                       atomic_commit_units=commits, atomic_expiry_units=expiries,
                       held_ack_units=first_action('hold_ack'),
                       ack_arrival_ordinal=next((record['ordinal'] for record in recs
                           if 'hold_ack' in actions(record)), None),
                       response_arrival_ordinal=response_recs[0]['ordinal'] if response_recs else None,
                       reset_application_units=first_action('close_epoch'),
                       generation_before=generation_before,
                       generation_after=self.h.scalar(self.m.register_read('p1.t_Ingress.gen_alloc_reg', 0, pipe=1)),
                       epoch=epoch, ack_state_transitions=transitions,
                       observer_io=dict(send_marks=send_marks, rpc_windows=observer_rpc, resolution=resolution,
                           request_relayed_monotonic_ns=relay_observed_ns),
                       duplicate_schedule='two ACK copies then one native response; response replay after release' if duplicate else None,
                       forced_expiry_before_response_units=forced_expiry_units,
                       last_observed_T_clock_before_response_send_units=response_inject_clock_units)
            if stale_probe:
                row['lane_registers'] = {name: completion_transitions(view.lines_since(self.log, offset), name)
                    for name in ('t0_reg', 'gen_alloc_reg', 'cur_epoch_reg', 'ack_commit_at_reg', 'ack_commit_gen_reg')}
            blockers = [bytes.fromhex(record['frame']) for record in recs
                        if record['port'] == self.pm.held_return and record['frame'].startswith(
                            '0b00%04x' % (row['generation_after'] & 0xffff))]
            seeds = [bytes.fromhex(record['frame']) for record in recs
                     if record['port'] == self.h.PKTGEN_RETURN and record['frame'].startswith(
                         'e100%04x' % (row['generation_after'] & 0xffff))]
            self.last_exchange_artifacts = dict(ack=ack, response=rsp, token=blockers[0] if blockers else None,
                seed=seeds[0] if seeds else None,
                generation=row['generation_after'], epoch=epoch, tag=tag)
            row['artifacts'] = dict(ack=ack.hex(), response=rsp.hex(), token=blockers[0].hex() if blockers else None,
                                    seed=seeds[0].hex() if seeds else None)
            if stale_probe:
                probe = {key: value for key, value in stale_probe.items() if key != 'frame'}
                artifact = next((record for record in all_records if record['port'] == stale_probe['port']
                    and record['frame'].startswith(stale_probe['frame'].hex())), None)
                probe['frame_hex'] = stale_probe['frame'].hex()
                probe['ingress_ordinal'] = artifact['ordinal'] if artifact else None
                probe['ingress_t_units'] = artifact['t_units'] if artifact else None
                for label, action in (('held_ack_ordinal', 'hold_ack'),
                                      ('ack_commit_ordinal', 'release_ack_commit'),
                                      ('response_arrival_ordinal', None),
                                      ('response_release_ordinal', 'release_response_counted')):
                    candidates = response_recs if action is None else [record for record in recs if action in actions(record)]
                    probe[label] = candidates[0]['ordinal'] if candidates else None
                row['stale_probe'] = probe
            self.points.append(row)
            if fc == 4:
                hold = delta(row['operate_release_units'], row['operate_anchor_units'])
                self.add(tag + '_independent_J_full_hold_and_single_release', True,
                         row['operate_release_count'] == 1 and hold is not None and hold >= self.written['op_j'],
                         point=row)
            if absent or reset or no_ack or expire_before_response:
                self.add(tag + '_no_early_ACK_or_response', [], labels)
                self.add(tag + '_no_commit_or_release', [0, 0], [row['lane']['ACK_COMMIT'], row['lane']['RESP_RELEASE']])
                if absent or no_ack or expire_before_response:
                    self.add(tag + '_expired_once', 1, row['lane']['WAIT_EXPIRED'])
                    self.add(tag + '_atomic_expiry_at_or_after_real_deadline', True,
                        len(expiries) == 1 and delta(expiries[0], t0) >= self.written['response_wait_timeout'],
                        point=row)
                    # An already expired transaction cannot be reopened by its matching late packets.
                    stale_before = self.outcomes()
                    send(self.relay.dev_port, ack, 'ack')
                    send(self.relay.dev_port, rsp, 'response')
                    tail = []
                    end = time.monotonic() + .5
                    while time.monotonic() < end:
                        tail.extend(self.collect(.02))
                    self.add(tag + '_late_matching_packets_stay_dropped', [],
                             [raw.hex() for port, raw in tail if port == self.master.dev_port])
                    stale_after = self.outcomes()
                    self.add(tag + '_late_packets_no_commit', [0, 0],
                             [stale_after[k] - stale_before[k] for k in ('ACK_COMMIT', 'RESP_RELEASE')])
                return cend, n, w
            problems = committed_problems(row, self.written['gap'], self.written['response_wait_timeout'])
            if commits != [row['ack_release_units']] or expiries:
                problems.append('atomic completion transition differs from one ACK commit without expiry')
            if cross_expiry and (row['response_release_units'] is None or
                    delta(row['response_release_units'], t0) < self.written['response_wait_timeout']):
                problems.append('planned response release across 500ms was not constructed')
            if stale_probe:
                problems.extend(generation_isolation_problems(row))
            self.add(tag + '_T_clock_ACK_then_D_proof', [], problems, point=row)
            effect = row['encoding_after']
            self.add(tag + '_one_growth_commit', [1, len(image) - len(native)],
                     [effect['commit'] - encoding['commit'], (effect['growth'] - encoding['growth']) & 0xffffffff])
            for raw in master:
                mp.assert_ip_tcp(raw)
            if cls == 'CONTROL' and master:
                from model_relay_sbo import verify_control_delivery
                verify_control_delivery(native, master[-1])
            if duplicate:
                self.post_release_replay(tag, row, rsp, rsp_want)
            self.exchange(tag + '_mapped_complete_ACK', self.v.packet(16, cend, w + len(image)),
                          self.v.packet(16, cend, n + len(native)))
            return cend, n + len(native), w + len(image)

        def post_release_replay(self, tag, row, native_packet, expected_packet):
            before_e, before_t = self.encoding_state(), self.outcomes()
            offset = view.size(self.log)
            received = self.exchange(tag + '_legitimate_response_replay_after_release',
                                     native_packet, expected_packet, reverse=True)
            after_e, after_t = self.encoding_state(), self.outcomes()
            recs = self.records(offset)
            response = next((record for record in recs if record['port'] == self.pm.t_in and
                native_packet[34:46].hex() in record['frame'] and
                any(action.endswith('.passthrough_tev_forward') for action in record['actions'])), None)
            replay = dict(exact_frame=self.h.same_frame(received, expected_packet, native_packet), output_frames=1,
                encoding_delta=dict(commit=after_e['commit'] - before_e['commit'],
                    replay=after_e['replay'] - before_e['replay'], growth=(after_e['growth'] - before_e['growth']) & 0xffffffff),
                lane_delta={name: after_t[name] - before_t[name] for name in
                            ('ACK_COMMIT', 'RESP_RELEASE', 'WAIT_EXPIRED', 'EXPIRED_DROP')},
                primary_release_units=row['response_release_units'],
                replay_arrival_units=response['t_units'] if response else None)
            row['post_release_replay'] = replay
            self.add(tag + '_post_release_replay_no_second_commit_or_growth', [], post_release_replay_problems(replay), replay=replay)

        def source_produced_A_blocker(self, tag, point):
            seed_hex = (point.get('artifacts') or {}).get('seed')
            self.add(tag + '_captured_READ_clone_seed_available', True, bool(seed_hex))
            seed = bytes.fromhex(seed_hex)
            helper = mp.load('_response_ready_pktgen_format', HERE.parents[2] / 'response_only/model_drive_pktgen_port.py')
            sys.path.insert(0, str(HERE.parents[2] / 'response_only/hw'))
            import t_config
            timer = timer_from_read_seed(seed, helper.token, t_config.token_buffer())
            self.add(tag + '_timer_bound_to_actual_A_generation', point['generation_after'], int.from_bytes(timer[2:4], 'big'))
            before = self.outcomes()
            offset = view.size(self.log)
            live = LiveIngress(self.log, offset)
            self.m.drain(self.ports)
            self.fast[self.h.PKTGEN_RETURN].send(timer)
            captured, blocker, source = [], None, None
            end = time.monotonic() + 10
            prefix = '0b00%04x' % point['generation_after']
            while time.monotonic() < end:
                captured.extend(self.collect(.001))
                live.poll()
                source = live.action('seed_ack_blocker')
                blocker = next((record for record in live.records if record['port'] == self.pm.held_return and
                    record['frame'].startswith(prefix) and len(record['frame']) >= 2 * (8 + t_config.TOKEN_LEN)), None)
                if source is not None and blocker is not None and source['port'] == self.h.PKTGEN_RETURN and \
                        source['frame'].startswith(timer.hex()):
                    break
            self.add(tag + '_actual_T_seed_ack_blocker_and_role11_return_observed', True,
                     source is not None and blocker is not None and source['port'] == self.h.PKTGEN_RETURN
                     and source['frame'].startswith(timer.hex()))
            self.add(tag + '_timer_and_blocker_no_public_packet', [],
                     [frame.hex() for _port, frame in captured])
            after = self.outcomes()
            self.add(tag + '_timer_cannot_reopen_expired_A', [0, 0, 0],
                [after[name] - before[name] for name in ('ACK_COMMIT', 'RESP_RELEASE', 'WAIT_EXPIRED')])
            raw = bytes.fromhex(blocker['frame'])
            point['artifacts']['token'] = raw.hex()
            point['token_source'] = dict(scope='explicit model timer stimulus; role11 emitted by compiled T; no physical pktgen claim',
                seed_frame_hex=seed_hex, timer_frame_hex=timer.hex(), timer_port=self.h.PKTGEN_RETURN,
                source_action='t_Ingress.seed_ack_blocker', source_t_units=source['t_units'],
                blocker_port=blocker['port'], blocker_t_units=blocker['t_units'], blocker_frame_hex=raw.hex(),
                lane_delta={name: after[name] - before[name] for name in ('ACK_COMMIT', 'RESP_RELEASE', 'WAIT_EXPIRED')},
                state_after=self.h.scalar(self.m.register_read('p1.t_Ingress.ack_done_reg', 0, pipe=1)))
            self.add(tag + '_source_produced_expired_A_blocker_provenance', [], token_source_problems(point))
            self.last_exchange_artifacts['token'] = raw

        def inject_stale_probe(self, tag, probe, live, captured, prerequisite):
            """Observe B's phase incrementally; defer report work until all stimuli are sent."""
            end = time.monotonic() + 10
            ready = False
            while time.monotonic() < end:
                captured.extend(self.collect(.001))
                live.poll()
                if live.action(prerequisite) is not None:
                    ready = True
                    break
            if not ready:
                raise AssertionError(tag + ': B prerequisite phase not observed')
            probe['send_start_monotonic_ns'] = time.monotonic_ns()
            self.fast[probe['port']].send(probe['frame'])
            probe['send_end_monotonic_ns'] = time.monotonic_ns()
            end = time.monotonic() + 10
            seen = False
            while time.monotonic() < end:
                captured.extend(self.collect(.001))
                live.poll()
                if live.frame(probe['port'], probe['frame']) is not None:
                    seen = True
                    break
            return ready, seen

        def generation_isolation(self):
            for kind in ('late_ACK', 'stale_response', 'expired_token'):
                for phase in ('waiting', 'committed'):
                    tag = 'generation_A_%s_%s_B' % (kind, phase)
                    self.set_timing(20_000_000)
                    state = self.new_connection(tag + '_A')
                    state = self.exchange_ready(tag + '_A', 'mixed', state, absent=kind == 'expired_token')
                    if kind == 'expired_token':
                        self.source_produced_A_blocker(tag, self.points[-1])
                    old = dict(self.last_exchange_artifacts)
                    if kind == 'expired_token':
                        self.exchange(tag + '_A_RST', self.v.packet(20, state[0], state[2]),
                                      self.v.packet(20, state[0], state[1]))
                        state = self.new_connection(tag + '_B')
                    frame = old[{'late_ACK': 'ack', 'stale_response': 'response', 'expired_token': 'token'}[kind]]
                    self.add(tag + '_genuine_A_artifact_available', True, frame is not None)
                    probe = dict(kind=kind, phase=phase, frame=frame,
                        port=self.pm.held_return if kind == 'expired_token' else self.relay.dev_port,
                        source_tag=old['tag'], source_generation=old['generation'], source_epoch=old['epoch'])
                    state = self.exchange_ready(tag, 'integrity', state, stale_probe=probe)
                    self.close(*state, tag + '_close')

        def negative_state(self):
            names = {'N': ('owner', 'epoch', 'client', 'server'),
                     'E': ('epoch', 'mode', 'front', 'acct', 'img_end', 'img_start', 'img_wend'),
                     'T': ('cur_epoch_reg', 'gen_alloc_reg', 'op_gen_alloc_reg', 't0_reg', 'op_t0_reg',
                           'ack_done_reg', 'resp_done_reg', 'op_done_reg', 'child_seen0_reg',
                           'ack_commit_at_reg', 'ack_commit_gen_reg')}
            prefixes = {'N': 'p0.n_Ingress.', 'E': 'p0.r_Egress.', 'T': 'p1.t_Ingress.'}
            result = {domain: {name: self.m.register_read(prefixes[domain] + name, 0,
                       pipe=1 if domain == 'T' else 0) for name in registers}
                      for domain, registers in names.items()}
            result['T']['outcomes'] = [self.h.scalar(self.m.register_read('p1.t_Ingress.outcomes', i, pipe=1))
                                       for i in range(25)]
            return result

        def invalid_child_ids(self):
            self.add('single_child_source_profile_declared', 1, profile['t_child_count'])
            self.set_timing(5_000_000)
            state = self.new_connection('single_child_ids')
            state = self.exchange_ready('single_child_live_READ', 'mixed', state)
            state = self.exchange_ready('single_child_live_SELECT', 'CONTROL', state)
            state = self.exchange_ready('single_child_live_OPERATE', 'CONTROL', state, fc=4)
            epoch = self.h.scalar(self.m.register_read('p1.t_Ingress.cur_epoch_reg', 0, pipe=1))
            read_gen = self.h.scalar(self.m.register_read('p1.t_Ingress.gen_alloc_reg', 0, pipe=1))
            op_gen = self.h.scalar(self.m.register_read('p1.t_Ingress.op_gen_alloc_reg', 0, pipe=1))
            self.add('single_child_negative_live_epoch_and_generations', True,
                0 < epoch < 0x80000000 and 0 < read_gen < 0xffff and 0 < op_gen < 0xffff)
            _request, _native, image = self.frames('mixed')
            opaque = self.v.packet(24, state[2], state[0], reverse=True, payload=image)
            rows = self.report.record['meta']['single_child_probes'] = []

            def probe(kind, role, child, port, frame, policy_off=False):
                before = self.negative_state()
                self.m.drain(self.ports)
                got = self.m.exchange(port, frame, self.ports, timeout=.6, quiet=.1)
                after = self.negative_state()
                expected = copy.deepcopy(before)
                if policy_off and child == 0:
                    expected['T']['outcomes'][NAMES.index('TOKEN_OFF')] = (
                        expected['T']['outcomes'][NAMES.index('TOKEN_OFF')] + 1) & 0xffffffff
                row = dict(kind=kind, role=role, child=child, policy_off=policy_off, epoch=epoch,
                    read_generation=read_gen, operate_generation=op_gen,
                    before=before, expected_after=expected, after=after, output_frames=sum(map(len, got.values())))
                rows.append(row)
                tag = 'single_child_%s_role%s_child%d' % (kind, role, child)
                self.add(tag + '_no_output', 0, row['output_frames'], received=got)
                self.add(tag + ('_positive_TOKEN_OFF_once' if policy_off and child == 0 else '_state_unchanged'),
                         expected, after)

            for child in (1, 2, 255):
                probe('response', None, child, self.pm.t_in,
                      struct.pack('!IIIBBH', epoch, 0, 0, 11, child, 0) + opaque)
                for role in (14, 15, 16):
                    probe('held', role, child, self.pm.hb_return if role == 16 else self.pm.held_return,
                          struct.pack('!BBHI', role, child, op_gen if role == 16 else read_gen, epoch) + opaque)
            self.set_timing(5_000_000, enabled=0)
            for role in (11, 12, 13):
                for child in (0, 1, 2, 255):
                    probe('blocker', role, child, self.pm.hb_return if role == 13 else self.pm.held_return,
                          struct.pack('!BBHI', role, child, op_gen if role == 13 else read_gen, 240000) + opaque,
                          policy_off=True)
            self.set_timing(5_000_000)
            self.report.record['meta'].update(single_child_negative_ids=[1, 2, 255],
                single_child_negative_ladder_roles=[11, 12, 13, 14, 15, 16],
                single_child_blocker_positive_control='policy-off TOKEN_OFF once, child 0')
            self.close(*state, 'single_child_close')

        def disabled_and_exhaustion(self):
            self.set_timing(5_000_000, enabled=0)
            state = self.new_connection('timing_off')
            before = self.outcomes()
            generation = self.h.scalar(self.m.register_read('p1.t_Ingress.gen_alloc_reg', 0, pipe=1))
            state = self.actual_exchange('timing_off_READ', 'mixed', *state)
            state = self.actual_exchange('timing_off_SELECT', 'CONTROL', *state, fc=3)
            state = self.actual_exchange('timing_off_OPERATE', 'CONTROL', *state, fc=4)
            after = self.outcomes()
            self.add('timing_off_no_lane_commit_release_or_generation', [0, 0, 0, generation],
                [after[k] - before[k] for k in ('ACK_COMMIT', 'RESP_RELEASE', 'OP_RELEASE')] +
                [self.h.scalar(self.m.register_read('p1.t_Ingress.gen_alloc_reg', 0, pipe=1))])
            self.close(*state, 'timing_off_close')
            self.set_timing(5_000_000)
            for kind in ('READ', 'OPERATE'):
                state = self.new_connection('exhaust_' + kind)
                self.m.register_write('p1.t_Ingress.gen_alloc_reg', 0,
                    {'t_Ingress.gen_alloc_reg.f1': 0xfffd if kind == 'OPERATE' else 0xfffe}, pipe=1)
                if kind == 'OPERATE':
                    state = self.exchange_ready('exhaust_last_SELECT', 'CONTROL', state)
                c, n, w = state
                request, _native, _image = self.frames('mixed' if kind == 'READ' else 'CONTROL', fc=4 if kind == 'OPERATE' else 3)
                before = self.outcomes()
                self.exchange('exhaust_' + kind + '_request_dropped',
                    self.v.packet(24, c, w, payload=request), allow_drop=True)
                after = self.outcomes()
                self.add('exhaust_' + kind + '_counted_without_downgrade', [1, 0, 0, 0],
                    [after[k] - before[k] for k in ('GEN_EXHAUSTED', 'ACK_COMMIT', 'RESP_RELEASE', 'OP_RELEASE')])
                self.m.register_write('p1.t_Ingress.gen_alloc_reg', 0,
                    {'t_Ingress.gen_alloc_reg.f1': 100}, pipe=1)
                self.exchange('exhaust_' + kind + '_RST', self.v.packet(20, c + len(request), w),
                              self.v.packet(20, c + len(request), n))

        def edge_case(self, mode):
            self.set_timing(20_000_000)
            state = self.new_connection(mode)
            state = self.exchange_ready(mode, 'mixed', state,
                response_at_ns=98_000_000 if mode == 'late98ms' else
                    360_000_000 if mode == 'commit_across_expiry' else 0,
                absent=mode in ('absent', 'wrong_response', 'incomplete_response'),
                invalid='incomplete' if mode == 'incomplete_response' else
                    'wrong' if mode == 'wrong_response' else None,
                duplicate=mode in ('duplicate_ack_response', 'duplicate_over_bound'), reset=mode == 'reset_held',
                retransmit=mode == 'request_retransmission', cross_expiry=mode == 'commit_across_expiry',
                no_ack=mode == 'response_without_ACK', expire_before_response=mode == 'duplicate_over_bound')
            if mode != 'reset_held':
                # The state returned on expiry is the last master-observed wire frontier,
                # even after N admitted a late response which T dropped before E committed.
                self.exchange(mode + '_RST', self.v.packet(20, state[0], state[2]),
                              self.v.packet(20, state[0], state[1]))
            if mode == 'duplicate_over_bound':
                recovered = self.new_connection(mode + '_reconnect')
                recovered = self.exchange_ready(mode + '_reconnect', 'mixed', recovered)
                self.points[-1]['recovery_of'] = mode
                self.close(*recovered, mode + '_reconnect_close')

        def run(self):
            first = ('duplicate_over_bound', 'commit_across_expiry')
            later = ('late98ms', 'absent', 'response_without_ACK', 'wrong_response', 'incomplete_response',
                     'duplicate_ack_response', 'request_retransmission', 'reset_held')
            matrix = ['D%d_%s' % (gap // 1000000, order) for gap in D_VALUES
                      for order in ('ack_first', 'response_first')]
            planned = ([] if control_only else list(first)) + matrix + ([] if control_only else list(later) +
                ['generation_A_to_B_isolation']) + ['invalid_child_ids', 'disabled_and_exhaustion']
            self.report.record['meta']['planned_cases'] = planned
            done = self.report.record['meta']['completed_cases'] = []
            if not control_only:
                for mode in first:
                    self.edge_case(mode)
                    done.append(mode)
            for gap in D_VALUES:
                self.set_timing(gap)
                for order in ('ack_first', 'response_first'):
                    tag = 'D%d_%s' % (gap // 1000000, order)
                    state = self.new_connection(tag)
                    for cls in ('mixed', 'integrity'):
                        state = self.exchange_ready(tag + '_' + cls, cls, state, order=order)
                        state = self.exchange_ready(tag + '_' + cls + '_SELECT', 'CONTROL', state, order=order)
                        state = self.exchange_ready(tag + '_' + cls + '_OPERATE', 'CONTROL', state, fc=4, order=order)
                    self.close(*state, tag + '_close')
                    done.append(tag)
            if not control_only:
                for mode in later:
                    self.edge_case(mode)
                    done.append(mode)
                self.generation_isolation()
                done.append('generation_A_to_B_isolation')
            self.invalid_child_ids()
            done.append('invalid_child_ids')
            self.disabled_and_exhaustion()
            done.append('disabled_and_exhaustion')
            self.add('all_planned_cases_completed', planned, done)

    h = mp.load('_response_ready_helpers', HERE.parents[2] / 'response_only/model_drive_composite.py')
    cp = mp.load('_response_ready_cp', HERE.parents[1] / 'cp.py')
    report = h.Report(os.environ['PROG'], physical=False,
                      scope='response-ready ACK commit + full D on T clock; real 500ms WAITING expiry',
                      timing_contract=RESPONSE_READY,
                      boundary_scope='runtime observes commit before expiry and full D across 500ms; '
                                     'exact deadline equality is an emitted-source test',
                      driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    gate = ReadyGate(report, h.Model(ports=[], enable=False), h, cp)
    try:
        gate.configure()
        gate.run()
    except Exception:
        report.add('exception', 'none', traceback.format_exc(), ok=False)
    filename = 'control_timing_results.json' if control_only else 'response_ready_results.json'
    return 0 if report.finish(Path(os.environ['OUT']) / filename) else 1


if __name__ == '__main__':
    raise SystemExit(main())

"""Compiled v2 response-ready gate: whole response -> one genuine ACK -> response+D.

No exchange-age deadline or successful bypass exists. Wall deadlines only bound
harness I/O. Packet retention, retries, D/J and cleanup are proved on the model clock.
Enlarged D/J are explicitly model-only retention constructions; the 48-point matrix
uses D=5/10/15/20ms and J=2.4ms without borrowing those constructions.
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
NO_J_CONTRACT = 'response_ready_ack_d_no_j_v3'
UNIT_NS, WRAP = 256, 1 << 32
D_VALUES = (5_000_000, 10_000_000, 15_000_000, 20_000_000)
MODEL_HOLD_NS = 1_000_000_000
NAMES = ('UNMATCHED', 'HELD_REWAIT', 'ACK_COMMIT', 'RESP_RELEASE', 'RESP_DUP_DROP', 'OP_RELEASE',
         'TOKEN_STALE', 'HELD_STALE_FLUSH', 'REQ_DUP_DROP', 'REQ_DUP_FORWARD', 'TOKEN_TMO',
         'HELD_OFF_FLUSH', 'TOKEN_OFF', 'REQ_BYPASS', 'OLD_EPOCH_DROP', 'GEN_EXHAUSTED', 'OP_DUP_DROP')
LANE = ('ACK_COMMIT', 'RESP_RELEASE', 'REQ_DUP_DROP', 'REQ_DUP_FORWARD', 'OP_DUP_DROP')


def lane_names(point):
    return LANE[:-1] if point.get('timing_contract') == NO_J_CONTRACT else LANE


def delta(later, earlier):
    return None if later is None or earlier is None else (later - earlier) % WRAP


def child_ingress_problems(row):
    """Bind the child-id control to its actual compiled ingress branch, without a synthetic counter."""
    kind, role, child = (row.get(key) for key in ('kind', 'role', 'child'))
    no_j = row.get('timing_contract') == NO_J_CONTRACT
    if no_j and ('operate_generation' in row or any(name in ((row.get('before') or {}).get('T') or {})
            for name in ('op_gen_alloc_reg','op_t0_reg','op_done_reg'))):
        return ['no-J child proof contains removed OPERATE state']
    port = 180 if kind == 'response' else 181 if role in (13, 16) else 182
    try:
        frame = bytes.fromhex(row['stimulus_frame_hex'])
        if kind == 'response':
            header = struct.pack('!IIIBBH', row['epoch'], 0, 0, 11, child, 0)
        else:
            generation = row['operate_generation'] if role in (13, 16) else row['read_generation']
            header = struct.pack('!BBHI', role, child, generation, 240000 if kind == 'blocker' else row['epoch'])
    except (KeyError, TypeError, ValueError, struct.error):
        return ['missing or malformed child stimulus identity']
    problems = []
    def measured(name):
        value = ((row.get('before') or {}).get('T') or {}).get(name)
        cells = [item for item in value.values() if isinstance(item, list)] if isinstance(value, dict) else []
        return cells[0][0] if len(cells) == 1 and len(cells[0]) == 1 else None
    if any(measured(register) != row.get(key) for register, key in
           ((('cur_epoch_reg', 'epoch'), ('gen_alloc_reg', 'read_generation')) +
            (() if no_j else (('op_gen_alloc_reg', 'operate_generation'),)))):
        problems.append('child stimulus identity differs from measured live T epoch/generations')
    if kind == 'blocker' and child == 0:
        register = {11: 'ack_done_reg', 12: 'resp_done_reg', 13: 'op_done_reg'}.get(role)
        if register is None or measured(register) != generation:
            problems.append('positive child0 blocker does not target a measured completed generation')
    if row.get('stimulus_port') != port or not frame.startswith(header) or len(frame) <= len(header):
        problems.append('child stimulus has wrong ingress, role, child, generation or epoch')
    records = row.get('model_ingress')
    if not isinstance(records, list) or len(records) != 1:
        return problems + ['child probe requires exactly one actual T ingress record']
    record = records[0]
    # AF_PACKET inputs carry the same four-byte zero trailer observed throughout this model harness.
    if record.get('pipe') != 1 or record.get('port') != port or record.get('frame') != (frame + bytes(4)).hex() or \
            type(record.get('t_units')) is not int or type(record.get('ordinal')) is not int:
        problems.append('actual child model ingress differs from the complete injected frame/port')
    actions = record.get('actions')
    stops = [action for action in actions if action.startswith('t_Ingress.stop_blocking')] if isinstance(actions, list) else None
    if stops != (['t_Ingress.stop_blocking'] if kind == 'blocker' and child == 0 else []):
        problems.append('valid child0 stop branch missing or invalid child reached a stop branch')
    return problems


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

def committed_problems(point, gap_units):
    problems = arrival_order_problems(point)
    arrival, commit, release = (point.get(key) for key in
        ('response_arrival_units', 'ack_release_units', 'response_release_units'))
    if any(value is None for value in (arrival, commit, release)):
        return problems + ['missing whole-response/ACK-commit/response-release T-clock evidence']
    if delta(commit, arrival) >= WRAP // 2:
        problems.append('ACK committed before matching whole response reached T')
    if delta(release, commit) < gap_units:
        problems.append('response released before ACK commit + full D')
    lane = point.get('lane') or {}
    if lane.get('ACK_COMMIT') != 1 or lane.get('RESP_RELEASE') != 1:
        problems.append('not exactly one committed ACK and response')
    if point.get('master_frames') != ['ack', 'response']:
        problems.append('wire frames differ from exact genuine ACK then whole encoded response')
    return problems


def cleanup_problems(point, phase):
    problems=[]
    reset=point.get('reset_application_units');lane=point.get('lane') or {}
    held=point.get('held_ack_units') if phase=='ack_held' else point.get('response_arrival_units')
    if reset is None or held is None or delta(reset,held)>=WRAP//2 or point.get('reset_forwarded_count')!=1:
        problems.append('reset did not clean up an actually retained original at the last observed frontier')
    expected=0 if phase=='ack_held' else 1
    if lane.get('ACK_COMMIT')!=expected or lane.get('RESP_RELEASE')!=0 or point.get('response_release_units') is not None:
        problems.append('reset leaked or released a retained original')
    if point.get('master_frames')!=([] if phase=='ack_held' else ['ack']):
        problems.append('unexpected master frame during held-original cleanup')
    if phase=='response_held':
        commit=point.get('ack_release_units');gap=(point.get('written_units') or {}).get('gap')
        if commit is None or reset is None or type(gap) is not int or not 0<=delta(reset,commit)<gap:
            problems.append('response was not retained in its original D window when reset applied')
    return problems


def post_release_replay_problems(point):
    problems = []
    if point.get('exact_frame') is not True or point.get('output_frames') != 1:
        problems.append('replay did not deliver exactly one complete encoded response')
    if point.get('encoding_delta') != dict(commit=0, replay=1, growth=0):
        problems.append('replay changed logical commit/growth or did not count one replay')
    if any((point.get('lane_delta') or {}).get(name) != 0 for name in lane_names(point)):
        problems.append('response replay changed T completion/request-retry state')
    release, arrival = point.get('primary_release_units'), point.get('replay_arrival_units')
    if release is None or arrival is None or delta(arrival, release) >= WRAP // 2:
        problems.append('replay was not observed after original response release')
    return problems


def timer_from_read_seed(seed, token_builder, buffer):
    if len(seed) < 20 or seed[:2] != b'\xe1\x00' or seed[16:20] != b'\x09\x00\x00\x00':
        raise ValueError('captured READ clone required for model timer')
    generation = int.from_bytes(seed[2:4], 'big')
    if not 0 < generation < 0xffff:
        raise ValueError('captured READ clone has no usable generation')
    return token_builder(gen=generation, packet_id=0, profile=0, pipe=1)[:6] + buffer


def token_source_problems(point):
    source, artifacts = point.get('token_source') or {}, point.get('artifacts') or {}
    try:
        seed, timer, ingress, blocker = [bytes.fromhex(source[key]) for key in
            ('seed_frame_hex', 'timer_frame_hex', 'timer_ingress_frame_hex', 'blocker_frame_hex')]
    except (KeyError, TypeError, ValueError):
        return ['missing captured seed/model timer/source-produced blocker provenance']
    generation, problems = point.get('generation_after'), []
    if seed.hex() != artifacts.get('seed') or blocker.hex() != artifacts.get('token') or len(seed) < 20 or \
            seed[:2] != b'\xe1\x00' or seed[16:20] != b'\x09\x00\x00\x00' or int.from_bytes(seed[2:4], 'big') != generation:
        problems.append('timer source differs from actual A READ clone/generation')
    if len(timer) != 66 or timer[:2] != b'\x08\x00' or int.from_bytes(timer[2:4], 'big') != generation or \
            timer[4:6] != b'\x00\x00' or timer[10:12] != b'\x08\x00' or ingress != timer + bytes(4):
        problems.append('timer/input trailer differs from valid model pipe1/app0/A-generation ACK stimulus')
    if len(blocker) != len(ingress) + 2 or blocker[:2] != b'\x0b\x00' or int.from_bytes(blocker[2:4], 'big') != generation or \
            blocker[8:] != ingress[6:] or int.from_bytes(blocker[4:8], 'big') != 240000:
        problems.append('role11 artifact differs from source-produced timer payload/budget')
    if source.get('source_action') != 't_Ingress.seed_ack_blocker' or source.get('timer_port') != 196 or source.get('blocker_port') != 182:
        problems.append('compiled seeding action/HELD_RETURN ingress not observed')
    source_u, blocker_u, release_u = source.get('source_t_units'), source.get('blocker_t_units'), point.get('response_release_units')
    if any(value is None for value in (source_u, blocker_u, release_u)) or \
            delta(source_u, release_u) >= WRAP // 2 or delta(blocker_u, source_u) >= WRAP // 2:
        problems.append('completed A/source-token/source-blocker causal evidence missing')
    if source.get('state_after') != generation or any((source.get('lane_delta') or {}).get(name) != 0 for name in lane_names(point)):
        problems.append('timer changed completed A ownership/completion')
    return problems


def lane_integrity_problems(point):
    problems = []
    generation, commit = point.get('generation_after'), point.get('ack_release_units')
    if generation != point.get('generation_before', -2) + 1:
        problems.append('logical request allocated more than one timing generation')
    for register, expected in (('gen_alloc_reg', generation), ('cur_epoch_reg', point.get('epoch'))):
        events = (point.get('lane_registers') or {}).get(register) or []
        if not events or any(event['after'] != expected for event in events):
            problems.append('unmeasured or changed lane ownership: ' + register)
    for register, expected in (('ack_commit_at_reg', commit), ('ack_commit_gen_reg', generation)):
        events = [event for event in (point.get('lane_registers') or {}).get(register, [])
                  if commit is not None and delta(event['t_units'], commit) < WRAP // 2]
        if not events or any(event['after'] != expected for event in events):
            problems.append('D restarted or genuine commit changed: ' + register)
    events = point.get('ack_state_transitions') or []
    commits = [event for event in events if event['before'] != event['after'] and event['after'] == generation]
    if len(commits) != 1 or commits[0]['t_units'] != commit:
        problems.append('ACK generation word did not commit exactly once at genuine release')
    if any(event['after'] != generation for event in events if commit is not None and
           delta(event['t_units'], commit) < WRAP // 2):
        problems.append('completed ACK generation transiently changed')
    return problems


def generation_isolation_problems(point):
    probe = point.get('stale_probe') or {}
    problems = lane_integrity_problems(point)
    gap=(point.get('written_units') or {}).get('gap')
    problems += committed_problems(point,gap) if type(gap) is int else ['B timing units not measured']
    kind, phase = probe.get('kind'), probe.get('phase')
    if kind not in ('late_ACK', 'stale_response', 'stale_token') or phase not in ('waiting', 'committed'):
        return problems + ['missing A artifact/B phase declaration']
    if not isinstance(probe.get('source_generation'), int) or not 0 < probe['source_generation'] < point.get('generation_after', 0):
        problems.append('A/B generations not distinct')
    lower = probe.get('held_ack_ordinal' if phase == 'waiting' else 'ack_commit_ordinal')
    upper = probe.get('response_arrival_ordinal' if phase == 'waiting' else 'response_release_ordinal')
    ordinal = probe.get('ingress_ordinal')
    if any(type(value) is not int for value in (lower, upper, ordinal)) or not lower < ordinal < upper:
        problems.append('A artifact not observed during B ' + str(phase))
    if (probe.get('source_epoch') != point.get('epoch')) is not (kind == 'stale_token'):
        problems.append('wrong same-connection or new-handshake A/B construction')
    return problems


def retry_problems(point):
    proof = point.get('request_retry') or {}
    phase = proof.get('phase')
    no_j = point.get('timing_contract') == NO_J_CONTRACT
    if phase == 'disabled':
        problems = []
        if point.get('generation_after') != point.get('generation_before') or (not no_j and point.get('op_generation_after') != point.get('op_generation_before')):
            problems.append('disabled retry allocated a timing generation')
        expected_lane = dict(ACK_COMMIT=0, RESP_RELEASE=0, REQ_DUP_DROP=0, REQ_DUP_FORWARD=1)
        if not no_j:
            expected_lane['OP_DUP_DROP'] = 0
        if (point.get('lane') or {}) != expected_lane or (not no_j and point.get('operate_release_count') != 0):
            problems.append('disabled retry did not forward once without hold/release')
        if proof.get('relay_request_copies') != 2 or proof.get('ingress_units') is None:
            problems.append('disabled retry delivery/T ingress not proved')
        return problems
    problems = lane_integrity_problems(point)
    if no_j and phase == 'op_J':
        return problems + ['no-J retry cannot claim a removed OPERATE hold window']
    if phase not in ('op_J', 'response_D', 'waiting', 'after_release'):
        return problems + ['missing request-retry construction']
    expected = 'OP_DUP_DROP' if phase == 'op_J' else 'REQ_DUP_DROP' if phase == 'response_D' else 'REQ_DUP_FORWARD'
    lane = point.get('lane') or {}
    if lane.get(expected) != 1 or any(lane.get(name) != 0 for name in
            lane_names(point)[2:] if name != expected):
        problems.append('request retry did not take exactly its qualified drop/forward outcome')
    forwarded = phase in ('waiting', 'after_release')
    if proof.get('relay_request_copies') != (2 if forwarded else 1):
        problems.append('request retry relay delivery differs from retention policy')
    retry = proof.get('ingress_units')
    lower, upper = (point.get('operate_anchor_units'), point.get('operate_release_units')) if phase == 'op_J' else \
        (point.get('ack_release_units'), point.get('response_release_units')) if phase == 'response_D' else \
        (point.get('held_ack_units'), point.get('response_arrival_units')) if phase == 'waiting' else \
        (point.get('response_release_units'), None)
    if retry is None or lower is None or delta(retry, lower) >= WRAP // 2 or \
            (upper is not None and delta(upper, retry) >= WRAP // 2):
        problems.append('request retry was not observed in the intended ownership window')
    if point.get('fc') == 4 and not no_j:
        op_generation = point.get('op_generation_after')
        if op_generation != point.get('op_generation_before', -2) + 1:
            problems.append('OPERATE retry allocated or restarted J')
        expected_anchor = (point.get('operate_anchor_units') or 0) | 1
        for name, value in (('op_gen_alloc_reg', op_generation), ('op_t0_reg', expected_anchor)):
            events = (point.get('lane_registers') or {}).get(name) or []
            if not events or any(event['after'] != value for event in events):
                problems.append('OPERATE retry changed ' + name)
    return problems


def removed_operate_token_problems(row):
    """A dropped obsolete format requires its complete actual model ingress record."""
    try:
        frame = bytes.fromhex(row['stimulus_frame_hex'])
    except (KeyError, TypeError, ValueError):
        return ['missing obsolete OPERATE token stimulus']
    records = row.get('model_ingress')
    if not isinstance(records, list) or len(records) != 1:
        return ['obsolete OPERATE token requires exactly one actual T ingress record']
    record = records[0]
    problems = []
    if record.get('pipe') != 1 or record.get('port') != row.get('stimulus_port') or record.get('frame') != (frame + bytes(4)).hex():
        problems.append('obsolete OPERATE token differs from actual injected ingress')
    if row.get('before') != row.get('after') or row.get('output_frames') != 0 or not row.get('before'):
        problems.append('obsolete OPERATE token changed state or produced output')
    if any(action in record.get('actions', []) for action in ('t_Ingress.admit_request','t_Ingress.release_ack_commit',
            't_Ingress.release_response_counted','t_Ingress.stop_blocking','t_Ingress.seed_ack_blocker')):
        problems.append('obsolete OPERATE token entered a surviving timing action')
    return problems


def no_j_operate_problems(point):
    """Prove original OPERATE admission before a deliberately withheld response."""
    problems = []
    arrival, response = point.get('request_arrival_units'), point.get('response_arrival_units')
    if point.get('timing_contract') != NO_J_CONTRACT or point.get('fc') != 4:
        problems.append('no-J OPERATE contract not declared')
    if point.get('request_relay_observed_before_response') is not True:
        problems.append('original OPERATE was not observed at relay before whole response injection')
    actions = point.get('request_admission_actions') or []
    if 't_Ingress.admit_request' not in actions or any('operate' in action for action in actions):
        problems.append('original OPERATE did not use common immediate admission')
    if type(arrival) is not int or type(response) is not int or not 2_400_000 < delta(response, arrival) * UNIT_NS < (WRAP // 2) * UNIT_NS:
        problems.append('whole response was not withheld beyond the removed 2.4ms J')
    if 'op_j' in (point.get('written_units') or {}) or any(
            name in (point.get('lane_registers') or {}) for name in ('op_gen_alloc_reg', 'op_t0_reg', 'op_done_reg')):
        problems.append('no-J proof contains removed OPERATE hold state')
    return problems


def main(*, control_only=False, duplicate_only=False):
    sys.path.insert(0, str(HERE))
    from model_profile import from_env, RESPONSE_READY, RESPONSE_READY_CONTRACTS, RESPONSE_READY_NO_J
    profile = from_env()
    contract = profile.get('timing_contract')
    no_j = contract == RESPONSE_READY_NO_J
    if contract not in RESPONSE_READY_CONTRACTS:
        raise ValueError('strict response_ready requires an explicit source-bound response-ready contract')
    active_lane = LANE[:-1] if no_j else LANE
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
            for port in (self.pm.t_in, self.pm.held_return) + (() if no_j else (self.pm.hb_return,)):
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
                    for i, name in enumerate(NAMES) if not no_j or name not in ('OP_RELEASE','OP_DUP_DROP')}

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

        def set_timing(self, gap, enabled=1, op_j=2_400_000):
            values = dict(gap=gap, budget=240000, enabled=enabled)
            if not no_j:
                values['op_j'] = op_j
            self.m.set_default('p1.t_Ingress.params', 't_Ingress.set_params', values)
            self.written = json.loads((Path(os.environ['OUT']) / 't_params_written.json').read_text())[-1]['written']

        def new_connection(self, tag):
            self.isn += 100_000
            return self.handshake(self.isn, self.isn + 50_000, tag + '_')

        def wait_live(self, live, captured, predicate, label):
            end = time.monotonic() + 15
            while time.monotonic() < end:
                captured.extend(self.collect(.001))
                live.poll()
                if predicate():
                    return
            raise AssertionError(label + ': model-clock/causal construction not observed')

        def wait_age(self, live, captured, ns):
            def reached():
                anchor = live.action('admit_request') or live.action('hold_operate')
                return anchor and live.latest_units is not None and delta(live.latest_units, anchor['t_units']) * UNIT_NS >= ns
            self.wait_live(live, captured, reached, 'response waiting age')

        def exchange_ready(self, tag, cls, state, fc=3, order='ack_first', wait_response_ns=0,
                           wait_ack_ns=0, invalid=None, duplicate=False, reset_phase=None,
                           stale_probe=None, retry_phase=None):
            c, n, w = state
            request, native, image = self.frames(cls, 0, fc)
            cend = c + len(request)
            mp.rp.advance_timestamp()
            req = self.v.packet(24, c, w, payload=request)
            want_req = mp.rp.preserve_options(req, self.v.packet(24, c, n, payload=request))
            mp.rp.advance_timestamp()
            ack = self.v.packet(16, n, cend, reverse=True)
            want_ack = mp.rp.preserve_options(ack, self.v.packet(16, w, cend, reverse=True))
            mp.rp.advance_timestamp()
            rsp = self.v.packet(24, n, cend, reverse=True, payload=native)
            want_rsp = mp.rp.preserve_options(rsp, self.v.packet(24, w, cend, reverse=True, payload=image))
            before, encoding = self.outcomes(), self.encoding_state()
            generation_before = self.h.scalar(self.m.register_read('p1.t_Ingress.gen_alloc_reg', 0, pipe=1))
            op_before = None if no_j else self.h.scalar(self.m.register_read('p1.t_Ingress.op_gen_alloc_reg', 0, pipe=1))
            epoch = self.h.scalar(self.m.register_read('p1.t_Ingress.cur_epoch_reg', 0, pipe=1))
            offset = view.size(self.log)
            live, captured, marks = LiveIngress(self.log, offset), [], []
            def send(port, frame, label):
                start = time.monotonic_ns()
                self.fast[port].send(frame)
                marks.append(dict(label=label, port=port, start_monotonic_ns=start, end_monotonic_ns=time.monotonic_ns()))
            def relay_copies():
                return sum(port == self.relay.dev_port and self.h.same_frame(frame, want_req, req) for port, frame in captured)
            m = self.m
            m.drain(self.ports)
            send(self.master.dev_port, req, 'request')
            end, j_retry_sent = time.monotonic() + 15, False
            while time.monotonic() < end:
                captured.extend(self.collect(.001))
                if retry_phase == 'op_J':
                    live.poll()
                    if not j_retry_sent and live.action('hold_operate') is not None:
                        send(self.master.dev_port, req, 'request_retry_op_J')
                        j_retry_sent = True
                if relay_copies():
                    break
            if not relay_copies():
                raise AssertionError(tag + ': genuine original request not observed at relay')
            # Zero-delay ordinary cases inject the genuine pair before reporting,
            # parsing or BFRT work can perturb the packet path.
            if order == 'ack_first' and not wait_ack_ns:
                send(self.relay.dev_port, ack, 'ack')
                if duplicate:
                    send(self.relay.dev_port, ack, 'duplicate_ack')
            if stale_probe and stale_probe['phase'] == 'waiting':
                self.inject_stale_probe(tag, stale_probe, live, captured, 'hold_ack')
            if invalid:
                bad = native[:-1] if invalid == 'incomplete' else native
                seq = n if invalid == 'incomplete' else n + 100000
                send(self.relay.dev_port, self.v.packet(24, seq, cend, reverse=True, payload=bad), 'invalid_response')
            if wait_response_ns or retry_phase == 'waiting':
                self.wait_age(live, captured, max(wait_response_ns, MODEL_HOLD_NS if retry_phase == 'waiting' else 0))
            pre_completion = None
            if retry_phase == 'waiting':
                send(self.master.dev_port, req, 'request_retry_waiting')
                self.wait_live(live, captured, lambda: relay_copies() == 2, tag + ' retry forwarded')
            rst = self.v.packet(20, cend, w)
            want_rst = mp.rp.preserve_options(rst, self.v.packet(20, cend, n))
            if reset_phase == 'ack_held':
                self.wait_live(live, captured, lambda: live.action('hold_ack') is not None, tag + ' ACK held')
                pre_completion = [frame.hex() for port, frame in captured if port == self.master.dev_port]
                send(self.master.dev_port, rst, 'reset_held_ACK')
            else:
                if wait_response_ns or retry_phase == 'waiting' or invalid:
                    pre_completion = [frame.hex() for port, frame in captured if port == self.master.dev_port]
                send(self.relay.dev_port, rsp, 'whole_response')
                if wait_ack_ns:
                    self.wait_age(live, captured, wait_ack_ns)
                    pre_completion = [frame.hex() for port, frame in captured if port == self.master.dev_port]
                    send(self.relay.dev_port, ack, 'late_genuine_ack')
                elif order == 'response_first':
                    send(self.relay.dev_port, ack, 'ack')
            if retry_phase == 'response_D' or reset_phase == 'response_held':
                self.wait_live(live, captured, lambda: live.action('release_ack_commit') is not None, tag + ' ACK committed')
                if retry_phase == 'response_D':
                    send(self.master.dev_port, req, 'request_retry_response_D')
                else:
                    send(self.master.dev_port, rst, 'reset_held_response')
            if stale_probe and stale_probe['phase'] == 'committed':
                self.inject_stale_probe(tag, stale_probe, live, captured, 'release_ack_commit')
            end = time.monotonic() + 15
            while time.monotonic() < end:
                captured.extend(self.collect(.003))
                if reset_phase:
                    live.poll()
                    resolved = live.action('close_epoch') is not None and any(port == self.relay.dev_port and
                        self.h.same_frame(frame, want_rst, rst) for port, frame in captured)
                else:
                    resolved = any(port == self.master.dev_port and self.h.same_frame(frame, want_rsp, rsp)
                                   for port, frame in captured)
                if resolved:
                    tail = m.capture(self.ports, timeout=.6, quiet=.15)
                    captured.extend((port, frame) for port, frames in tail.items() for frame in frames)
                    break
            else:
                raise AssertionError(tag + ': no observed cleanup or public complete response')
            # All BFRT reads are after complete release or observed reset cleanup.
            after, encoded = self.outcomes(), self.encoding_state()
            records = self.all_records(offset)
            trecs = [record for record in records if record['pipe'] == 1]
            acts = lambda record: [action.split('.')[-1] for action in record['actions']]
            find = lambda action: next((record for record in trecs if action in acts(record)), None)
            stamp = lambda action: find(action)['t_units'] if find(action) else None
            response_recs = [record for record in trecs if record['port'] == self.pm.t_in and
                rsp[34:46].hex() in record['frame'] and (native.hex() in record['frame'] or image.hex() in record['frame'])]
            masters = [frame for port, frame in captured if port == self.master.dev_port]
            labels = ['ack' if self.h.same_frame(frame, want_ack, ack) else 'response' if self.h.same_frame(frame, want_rsp, rsp)
                      else 'other' for frame in masters]
            generation = self.h.scalar(m.register_read('p1.t_Ingress.gen_alloc_reg', 0, pipe=1))
            row = dict(tag=tag, cls=cls, fc=fc, order=order, native_octets=len(native), image_octets=len(image),
                timing_contract=contract, request_relay_observed_before_response=relay_copies() >= 1,
                request_admission_actions=find('admit_request')['actions'] if find('admit_request') else [],
                request_arrival_units=stamp('admit_request') if no_j or cls != 'CONTROL' or fc != 4 else stamp('hold_operate'),
                held_ack_units=stamp('hold_ack'), ack_arrival_ordinal=find('hold_ack')['ordinal'] if find('hold_ack') else None,
                response_arrival_units=response_recs[0]['t_units'] if response_recs else None,
                response_arrival_ordinal=response_recs[0]['ordinal'] if response_recs else None,
                ack_release_units=stamp('release_ack_commit'), response_release_units=stamp('release_response_counted'),
                operate_anchor_units=stamp('arm_operate_anchor'), operate_release_units=stamp('release_operate_counted'),
                operate_release_count=None if no_j else after['OP_RELEASE']-before['OP_RELEASE'], master_frames=labels,
                lane={name: after[name]-before[name] for name in active_lane}, encoding_before=encoding, encoding_after=encoded,
                generation_before=generation_before, generation_after=generation,
                op_generation_before=op_before, op_generation_after=None if no_j else self.h.scalar(m.register_read('p1.t_Ingress.op_gen_alloc_reg',0,pipe=1)),
                epoch=epoch, written_units=dict(self.written), model_only_hold_override=retry_phase in ('op_J','response_D') or reset_phase=='response_held' or bool(stale_probe and stale_probe['phase']=='committed'),
                wait_response_target_ns=wait_response_ns, wait_ack_target_ns=wait_ack_ns,
                pre_completion_master_frames=pre_completion, send_marks=marks,
                reset_application_units=stamp('close_epoch'),
                reset_forwarded_count=sum(port==self.relay.dev_port and self.h.same_frame(frame,want_rst,rst) for port,frame in captured))
            row['ack_state_transitions'] = completion_transitions(view.lines_since(self.log, offset))
            row['lane_registers'] = {name: completion_transitions(view.lines_since(self.log, offset), name) for name in
                (('gen_alloc_reg','cur_epoch_reg','ack_commit_at_reg','ack_commit_gen_reg') +
                 (() if no_j else ('op_gen_alloc_reg','op_t0_reg')))}
            if no_j:
                for key in ('op_generation_before','op_generation_after','operate_anchor_units','operate_release_units','operate_release_count'):
                    row.pop(key, None)
            seeds = [bytes.fromhex(record['frame']) for record in trecs if record['port']==self.h.PKTGEN_RETURN and
                     record['frame'].startswith('e100%04x'%generation)]
            self.last_exchange_artifacts = dict(ack=ack,response=rsp,token=None,seed=seeds[0] if seeds else None,
                                               generation=generation,epoch=epoch,tag=tag)
            row['artifacts'] = dict(ack=ack.hex(),response=rsp.hex(),token=None,seed=seeds[0].hex() if seeds else None)
            if stale_probe:
                probe={key:value for key,value in stale_probe.items() if key!='frame'}
                artifact=next((record for record in records if record['port']==stale_probe['port'] and
                               record['frame'].startswith(stale_probe['frame'].hex())),None)
                probe.update(frame_hex=stale_probe['frame'].hex(),ingress_ordinal=artifact['ordinal'] if artifact else None,
                    ingress_t_units=artifact['t_units'] if artifact else None,
                    held_ack_ordinal=find('hold_ack')['ordinal'] if find('hold_ack') else None,
                    ack_commit_ordinal=find('release_ack_commit')['ordinal'] if find('release_ack_commit') else None,
                    response_arrival_ordinal=row['response_arrival_ordinal'],
                    response_release_ordinal=find('release_response_counted')['ordinal'] if find('release_response_counted') else None)
                row['stale_probe']=probe
            self.points.append(row)
            self.add(tag+'_original_request_relayed',True,relay_copies()>=1)
            if pre_completion is not None:
                self.add(tag+'_no_successful_release_without_missing_original',[],pre_completion)
            if reset_phase:
                self.add(tag+'_actual_held_original_cleanup',[],cleanup_problems(row,reset_phase),point=row)
                self.add(tag+'_RST_last_observed_frontier_forwarded_once',1,sum(port==self.relay.dev_port and self.h.same_frame(frame,want_rst,rst) for port,frame in captured))
                self.add(tag+'_cleanup_no_response_release',0,row['lane']['RESP_RELEASE'])
                self.add(tag+'_cleanup_no_master_payload',False,'response' in labels)
                self.add(tag+'_cleanup_T_epoch_observed',True,row['reset_application_units'] is not None)
                return cend,n,w
            enabled = bool(self.written['enabled'])
            problems=committed_problems(row,self.written['gap'])+lane_integrity_problems(row) if enabled else []
            if not enabled and labels != ['ack','response']:
                problems.append('disabled original exchange did not deliver exact ACK/encoded response')
            if not no_j and enabled and fc!=4 and (row['op_generation_after']!=op_before or row['operate_release_count']!=0):
                problems.append('non-OPERATE request changed the J domain')
            if not no_j and fc==4 and enabled:
                if row['op_generation_after']!=op_before+1:
                    problems.append('original OPERATE did not allocate exactly one J generation')
                hold=delta(row['operate_release_units'],row['operate_anchor_units'])
                if hold is None or hold<self.written['op_j'] or row['operate_release_count']!=1:
                    problems.append('independent J/single OPERATE release not proved')
            if no_j and fc==4 and enabled and wait_response_ns > 2_400_000:
                problems += no_j_operate_problems(row)
            if stale_probe:
                problems+=generation_isolation_problems(row)
            self.add(tag+'_T_clock_whole_response_ACK_full_D',[],problems,point=row)
            self.add(tag+'_one_growth_commit',[1,len(image)-len(native)],
                     [encoded['commit']-encoding['commit'],(encoded['growth']-encoding['growth'])&0xffffffff])
            for frame in masters:mp.assert_ip_tcp(frame)
            if cls=='CONTROL':
                from model_relay_sbo import verify_control_delivery
                verify_control_delivery(native,masters[-1])
            if duplicate:self.post_release_replay(tag,row,rsp,want_rsp)
            if retry_phase in ('after_release','disabled'):
                # TCP may update ACK on a retransmitted request. Acknowledge the
                # observed image while retaining the original request sequence/body.
                retry=self.v.packet(24,c,w+len(image),payload=request)
                expected=mp.rp.preserve_options(retry,self.v.packet(24,c,n+len(native),payload=request))
                retry_offset=view.size(self.log)
                before_retry_t,before_retry_e=self.outcomes(),self.encoding_state()
                got=self.exchange(tag+'_retry_after_release_forwarded',retry,expected)
                retry_records=self.all_records(retry_offset)
                actual=next((record for record in retry_records if record['pipe']==1 and record['port']==self.pm.t_in and
                             record['frame'][24:26] in ('0f','10') and req[34:42].hex() in record['frame']),None)
                after_retry_t=self.outcomes()
                row['lane']={name:after_retry_t[name]-before[name] for name in active_lane}
                if not no_j:
                    row['operate_release_count']=after_retry_t['OP_RELEASE']-before['OP_RELEASE']
                row['request_retry']=dict(phase=retry_phase,relay_request_copies=2,
                    ingress_units=actual['t_units'] if actual else None)
                after_retry_e=self.encoding_state()
                self.add(tag+'_retry_no_second_growth',[0,0],[after_retry_e['commit']-before_retry_e['commit'],
                    (after_retry_e['growth']-before_retry_e['growth'])&0xffffffff])
                row['generation_after']=self.h.scalar(m.register_read('p1.t_Ingress.gen_alloc_reg',0,pipe=1))
                if not no_j:
                    row['op_generation_after']=self.h.scalar(m.register_read('p1.t_Ingress.op_gen_alloc_reg',0,pipe=1))
                row['ack_state_transitions']+=completion_transitions(view.lines_since(self.log,retry_offset))
                for name in row['lane_registers']:
                    row['lane_registers'][name]+=completion_transitions(view.lines_since(self.log,retry_offset),name)
            elif retry_phase:
                actual=next((record for record in trecs if record['port']==self.pm.t_in and
                             record['frame'][24:26] in ('0f','10') and req[34:42].hex() in record['frame']),None)
                row['request_retry']=dict(phase=retry_phase,relay_request_copies=relay_copies(),
                                         ingress_units=actual['t_units'] if actual else None)
            if retry_phase:self.add(tag+'_qualified_request_retry_policy',[],retry_problems(row),point=row)
            self.exchange(tag+'_mapped_complete_ACK',self.v.packet(16,cend,w+len(image)),self.v.packet(16,cend,n+len(native)))
            return cend,n+len(native),w+len(image)

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
            replay = dict(timing_contract=contract, exact_frame=self.h.same_frame(received, expected_packet, native_packet), output_frames=1,
                encoding_delta=dict(commit=after_e['commit'] - before_e['commit'],
                    replay=after_e['replay'] - before_e['replay'], growth=(after_e['growth'] - before_e['growth']) & 0xffffffff),
                lane_delta={name: after_t[name] - before_t[name] for name in
                            active_lane},
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
                    record['t_units'] is not None and record['frame'].startswith(prefix) and
                    len(record['frame']) >= 2 * (8 + t_config.TOKEN_LEN)), None)
                if source is not None and blocker is not None and source['port'] == self.h.PKTGEN_RETURN and \
                        source['frame'].startswith(timer.hex()):
                    break
            self.add(tag + '_actual_T_seed_ack_blocker_and_role11_return_observed', True,
                     source is not None and blocker is not None and source['port'] == self.h.PKTGEN_RETURN
                     and source['frame'].startswith(timer.hex()))
            self.add(tag + '_timer_and_blocker_no_public_packet', [],
                     [frame.hex() for _port, frame in captured])
            after = self.outcomes()
            self.add(tag + '_timer_preserves_completed_A', [0, 0],
                [after[name] - before[name] for name in ('ACK_COMMIT', 'RESP_RELEASE')])
            raw = bytes.fromhex(blocker['frame'])
            point['artifacts']['token'] = raw.hex()
            point['token_source'] = dict(scope='explicit model timer stimulus; role11 emitted by compiled T; no physical pktgen claim',
                seed_frame_hex=seed_hex, timer_frame_hex=timer.hex(), timer_ingress_frame_hex=source['frame'],
                timer_port=self.h.PKTGEN_RETURN,
                source_action='t_Ingress.seed_ack_blocker', source_t_units=source['t_units'],
                blocker_port=blocker['port'], blocker_t_units=blocker['t_units'], blocker_frame_hex=raw.hex(),
                lane_delta={name: after[name] - before[name] for name in active_lane},
                state_after=self.h.scalar(self.m.register_read('p1.t_Ingress.ack_done_reg', 0, pipe=1)))
            self.add(tag + '_source_produced_completed_A_blocker_provenance', [], token_source_problems(point))
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

        def generation_isolation(self, kinds=('late_ACK','stale_response','stale_token')):
            for kind in kinds:
                for phase in ('waiting','committed'):
                    tag='generation_A_%s_%s_B'%(kind,phase)
                    self.set_timing(20_000_000)
                    state=self.new_connection(tag+'_A')
                    state=self.exchange_ready(tag+'_A','mixed',state)
                    if kind=='stale_token':self.source_produced_A_blocker(tag,self.points[-1])
                    old=dict(self.last_exchange_artifacts)
                    if kind=='stale_token':
                        self.close(*state,tag+'_A_close')
                        state=self.new_connection(tag+'_B')
                    if phase=='committed':self.set_timing(MODEL_HOLD_NS)
                    frame=old[{'late_ACK':'ack','stale_response':'response','stale_token':'token'}[kind]]
                    self.add(tag+'_genuine_A_artifact_available',True,frame is not None)
                    probe=dict(kind=kind,phase=phase,frame=frame,
                        port=self.pm.held_return if kind=='stale_token' else self.relay.dev_port,
                        source_tag=old['tag'],source_generation=old['generation'],source_epoch=old['epoch'])
                    state=self.exchange_ready(tag,'integrity',state,stale_probe=probe)
                    self.close(*state,tag+'_close')

        def request_retries(self):
            cases=([] if no_j else [('OPERATE','op_J')])+[(kind,phase) for phase in ('response_D','waiting','after_release')
                for kind in ('READ','READ_integrity','SELECT','OPERATE')]+[(kind,'disabled') for kind in ('READ','READ_integrity','SELECT','OPERATE')]
            for kind,phase in cases:
                tag='retry_%s_%s'%(kind,phase)
                self.set_timing(20_000_000)
                state=self.new_connection(tag)
                if kind=='OPERATE':state=self.exchange_ready(tag+'_SELECT','CONTROL',state)
                self.set_timing(MODEL_HOLD_NS if phase=='response_D' else 20_000_000,
                                enabled=int(phase!='disabled'),
                                op_j=MODEL_HOLD_NS if phase=='op_J' else 2_400_000)
                state=self.exchange_ready(tag,'mixed' if kind=='READ' else 'integrity' if kind=='READ_integrity' else 'CONTROL',state,
                    fc=4 if kind=='OPERATE' else 3,retry_phase=phase)
                self.close(*state,tag+'_close')

        def waiting_and_cleanup(self):
            for case in ('late_response','late_ACK','wrong_response','incomplete_response','reset_ACK','reset_response','response_replay'):
                self.set_timing(MODEL_HOLD_NS if case=='reset_response' else 20_000_000)
                state=self.new_connection(case)
                state=self.exchange_ready(case,'mixed',state,
                    order='response_first' if case=='late_ACK' else 'ack_first',
                    wait_response_ns=MODEL_HOLD_NS if case in ('late_response','wrong_response','incomplete_response') else 0,
                    wait_ack_ns=MODEL_HOLD_NS if case=='late_ACK' else 0,
                    invalid='wrong' if case=='wrong_response' else 'incomplete' if case=='incomplete_response' else None,
                    reset_phase='ack_held' if case=='reset_ACK' else 'response_held' if case=='reset_response' else None,
                    duplicate=case=='response_replay')
                if case.startswith('reset_'):
                    self.set_timing(20_000_000)
                    state=self.new_connection(case+'_recovery')
                    state=self.exchange_ready(case+'_recovery','mixed',state)
                self.close(*state,case+'_close')

        def negative_state(self):
            names = {'N': ('owner', 'epoch', 'client', 'server'),
                     'E': ('epoch', 'mode', 'front', 'acct', 'img_end', 'img_start', 'img_wend'),
                     'T': ('cur_epoch_reg', 'gen_alloc_reg', 'op_gen_alloc_reg', 'op_t0_reg',
                           'ack_done_reg', 'resp_done_reg', 'op_done_reg', 'child_seen0_reg',
                           'ack_commit_at_reg', 'ack_commit_gen_reg')}
            prefixes = {'N': 'p0.n_Ingress.', 'E': 'p0.r_Egress.', 'T': 'p1.t_Ingress.'}
            if no_j:
                names['T'] = tuple(name for name in names['T'] if name not in ('op_gen_alloc_reg','op_t0_reg','op_done_reg'))
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
            op_gen = None if no_j else self.h.scalar(self.m.register_read('p1.t_Ingress.op_gen_alloc_reg', 0, pipe=1))
            self.add('single_child_negative_live_epoch_and_generations', True,
                0 < epoch < 0x80000000 and 0 < read_gen < 0xffff and (no_j or 0 < op_gen < 0xffff))
            _request, _native, image = self.frames('mixed')
            opaque = self.v.packet(24, state[2], state[0], reverse=True, payload=image)
            rows = self.report.record['meta']['single_child_probes'] = []

            def probe(kind, role, child, port, frame, policy_off=False):
                before = self.negative_state()
                self.m.drain(self.ports)
                offset = view.size(self.log)
                got = self.m.exchange(port, frame, self.ports, timeout=.6, quiet=.1)
                after = self.negative_state()
                expected = copy.deepcopy(before)
                row = dict(kind=kind, role=role, child=child, policy_off=policy_off, epoch=epoch,
                    read_generation=read_gen, operate_generation=op_gen,
                    before=before, expected_after=expected, after=after, output_frames=sum(map(len, got.values())),
                    stimulus_port=port, stimulus_frame_hex=frame.hex(), model_ingress=self.records(offset))
                row['timing_contract'] = contract
                if no_j:
                    row.pop('operate_generation')
                rows.append(row)
                tag = 'single_child_%s_role%s_child%d' % (kind, role, child)
                self.add(tag + '_no_output', 0, row['output_frames'], received=got)
                self.add(tag + '_state_unchanged', expected, after)
                self.add(tag + '_compiled_ingress_branch', [], child_ingress_problems(row))

            for child in (1, 2, 255):
                probe('response', None, child, self.pm.t_in,
                      struct.pack('!IIIBBH', epoch, 0, 0, 11, child, 0) + opaque)
                for role in ((14, 15) if no_j else (14, 15, 16)):
                    probe('held', role, child, self.pm.hb_return if role == 16 else self.pm.held_return,
                          struct.pack('!BBHI', role, child, op_gen if role == 16 else read_gen, epoch) + opaque)
            self.set_timing(5_000_000, enabled=0)
            for role in ((11, 12) if no_j else (11, 12, 13)):
                for child in (0, 1, 2, 255):
                    probe('blocker', role, child, self.pm.hb_return if role == 13 else self.pm.held_return,
                          struct.pack('!BBHI', role, child, op_gen if role == 13 else read_gen, 240000) + opaque,
                          policy_off=True)
            self.set_timing(5_000_000)
            self.report.record['meta'].update(single_child_negative_ids=[1, 2, 255],
                single_child_negative_ladder_roles=[11, 12, 14, 15] if no_j else [11, 12, 13, 14, 15, 16],
                single_child_blocker_positive_control='child0 actual stop_blocking action; all state/counters unchanged')
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
            release_names = ('ACK_COMMIT','RESP_RELEASE') + (() if no_j else ('OP_RELEASE',))
            self.add('timing_off_no_lane_commit_release_or_generation', [0] * len(release_names) + [generation],
                [after[k] - before[k] for k in release_names] +
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
                names = ('GEN_EXHAUSTED',) + release_names
                self.add('exhaust_' + kind + '_counted_without_downgrade', [1] + [0] * len(release_names),
                    [after[k] - before[k] for k in names])
                self.m.register_write('p1.t_Ingress.gen_alloc_reg', 0,
                    {'t_Ingress.gen_alloc_reg.f1': 100}, pipe=1)
                self.exchange('exhaust_' + kind + '_RST', self.v.packet(20, c + len(request), w),
                              self.v.packet(20, c + len(request), n))

        def removed_operate_tokens(self):
            """Observe rejection of the removed J formats on both current and old ports."""
            self.set_timing(5_000_000)
            state = self.new_connection('removed_operate_tokens')
            state = self.exchange_ready('removed_token_SELECT', 'CONTROL', state)
            state = self.exchange_ready('removed_token_OPERATE', 'CONTROL', state, fc=4)
            live = self.negative_state()
            generation = self.h.scalar(live['T']['gen_alloc_reg'])
            epoch = self.h.scalar(live['T']['cur_epoch_reg'])
            opaque = self.v.packet(16, state[2], state[0], reverse=True)
            rows = self.report.record['meta']['removed_operate_token_probes'] = []
            cases = [('role%d_port%d' % (role, port), port,
                      struct.pack('!BBHI', role, 0, generation, 240000 if role == 13 else epoch) + opaque)
                     for role in (13, 16) for port in (self.pm.held_return, self.pm.hb_return)]
            cases += [('app1', self.h.PKTGEN_RETURN, bytes((9, 1)) + struct.pack('!HH', generation, 0) + opaque),
                      ('E101', self.h.PKTGEN_RETURN, bytes.fromhex('e101') + struct.pack('!HIIIBBH', generation, epoch, 0, 0, 12, 0, 0) + opaque)]
            for name, port, frame in cases:
                before = self.negative_state()
                self.m.drain(self.ports)
                offset = view.size(self.log)
                got = self.m.exchange(port, frame, self.ports, timeout=.6, quiet=.1)
                after = self.negative_state()
                row = dict(name=name, stimulus_port=port, stimulus_frame_hex=frame.hex(),
                           before=before, after=after, output_frames=sum(map(len, got.values())),
                           model_ingress=self.records(offset))
                rows.append(row)
                self.add('removed_operate_' + name + '_no_output', 0, row['output_frames'])
                self.add('removed_operate_' + name + '_state_unchanged', before, after)
                self.add('removed_operate_' + name + '_actual_ingress', [], removed_operate_token_problems(row))
            self.close(*state, 'removed_operate_token_close')

        def immediate_operate(self):
            self.set_timing(20_000_000)
            state = self.new_connection('no_j_immediate_OPERATE')
            state = self.exchange_ready('no_j_immediate_SELECT', 'CONTROL', state)
            state = self.exchange_ready('no_j_immediate_OPERATE', 'CONTROL', state, fc=4, wait_response_ns=20_000_000)
            self.add('no_j_immediate_OPERATE_before_withheld_response', [], no_j_operate_problems(self.points[-1]))
            self.close(*state, 'no_j_immediate_close')

        def run(self):
            if duplicate_only:
                planned = ['request_retry_policy','waiting_and_cleanup']
                self.report.record['meta']['planned_cases'] = planned
                done = self.report.record['meta']['completed_cases'] = []
                self.request_retries();done.append('request_retry_policy')
                self.waiting_and_cleanup();done.append('waiting_and_cleanup')
                self.add('all_planned_cases_completed', planned, done)
                return
            matrix=['D%d_%s'%(gap//1000000,order) for gap in D_VALUES for order in ('ack_first','response_first')]
            planned=(['no_j_immediate_OPERATE','removed_operate_tokens'] if no_j else [])+['invalid_child_ids']+([] if control_only else ['request_retry_policy','stale_token_isolation'])+matrix+(
                [] if control_only else ['waiting_and_cleanup','generation_A_to_B_isolation'])+['disabled_and_exhaustion']
            self.report.record['meta']['planned_cases']=planned
            done=self.report.record['meta']['completed_cases']=[]
            if no_j:
                self.immediate_operate();done.append('no_j_immediate_OPERATE')
                self.removed_operate_tokens();done.append('removed_operate_tokens')
            self.invalid_child_ids();done.append('invalid_child_ids')
            if not control_only:
                self.request_retries();done.append('request_retry_policy')
                self.generation_isolation(kinds=('stale_token',));done.append('stale_token_isolation')
            for gap in D_VALUES:
                self.set_timing(gap)
                for order in ('ack_first','response_first'):
                    tag='D%d_%s'%(gap//1000000,order)
                    state=self.new_connection(tag)
                    for cls in ('mixed','integrity'):
                        state=self.exchange_ready(tag+'_'+cls,cls,state,order=order)
                        state=self.exchange_ready(tag+'_'+cls+'_SELECT','CONTROL',state,order=order)
                        state=self.exchange_ready(tag+'_'+cls+'_OPERATE','CONTROL',state,fc=4,order=order)
                    self.close(*state,tag+'_close');done.append(tag)
            if not control_only:
                self.waiting_and_cleanup();done.append('waiting_and_cleanup')
                self.generation_isolation(kinds=('late_ACK','stale_response'));done.append('generation_A_to_B_isolation')
            self.disabled_and_exhaustion();done.append('disabled_and_exhaustion')
            self.add('all_planned_cases_completed',planned,done)

    h=mp.load('_response_ready_helpers',HERE.parents[2]/'response_only/model_drive_composite.py')
    cp=mp.load('_response_ready_cp',HERE.parents[1]/'cp.py')
    report=h.Report(os.environ['PROG'],physical=False,timing_contract=contract,
        scope='whole response/genuine ACK/full D; retention-qualified retries and cleanup; no exchange age cap',
        driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    gate=ReadyGate(report,h.Model(ports=[],enable=False),h,cp)
    try:
        gate.configure();gate.run()
    except Exception:
        report.add('exception','none',traceback.format_exc(),ok=False)
    filename='dup_results.json' if duplicate_only else 'control_timing_results.json' if control_only else 'response_ready_results.json'
    return 0 if report.finish(Path(os.environ['OUT'])/filename) else 1


if __name__=='__main__':
    raise SystemExit(main())

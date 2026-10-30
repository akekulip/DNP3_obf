"""Connection-start loss paths on the compiled model. A separate labelled scenario, NOT a gate driver.

N has one global work cell (n_ExpectedWorkRecord, Register(1)). A frame's stage-0 pass claims it (phase 4 -> 1) and
its laps on port 68 return it (1 -> 2 -> 3 -> 4). A frame whose stage-0 claim finds the cell held goes to busy_t:
pure ACKs retry, requests (READ, SELECT, OPERATE) take busy_drop. Scenarios, each for a mixed (25 B) and an integrity
(27 B) first READ:
  H1        final ACK and first READ back to back: the ACK holds the cell when the READ reaches stage 0.
  H2        first READ fully processed (owner 0xd/0xe, client advanced), then the final ACK: first_event has no row
            for it, keeps the snapshot's event code 255, and the laps take abort_work -> terminal_abort.
  H2r       the READ and the final ACK back to back: the ACK finds the cell held by the READ, busy-retries, and
            claims only after the READ has advanced the connection (the same late-ACK state through the retry path).
  collision the relay SELECT response is in N's laps when the master OPERATE reaches stage 0 (cycle READ -> SELECT
            -> OPERATE). The OPERATE is injected before the master could have received the response: this tests
            the dataplane rule, not a causal master.
  H1prime   the cell is forced busy by register write (as model_fin_busy) and the READ arrives: a control, reported
            apart from the genuine-processing cases.
Every case reads its state from the model's own log (the work-cell, owner and client SALU values of each pass)
before its outcome. Verdict: state reached + loss = reproduced; state reached + no loss = falsified for this path;
state not reached = not reproduced (not disproven). Run with scripts/model/run_connection_start.py."""
import hashlib
import json
import os
import re
import time
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent

CLASSES = ('mixed', 'integrity')
READ_LENGTH = {'mixed': 25, 'integrity': 27}
SCENARIO_ORDER = ('H1', 'H2', 'H2r', 'collision', 'H1prime')
BUSY_DROP = r'Execute (?:Default )?Action: n_Ingress\.busy_drop\b'
TERMINAL_ABORT = r'Execute (?:Default )?Action: n_Ingress\.terminal_abort\b'
SCENARIOS = dict(
    H1=dict(evidence_kind='genuine_processing', send_order=('final_ACK', 'READ'), spacing='back_to_back',
            lost_frame='READ', decisive_action='busy_drop',
            state_check='the final ACK generation holds the work cell (phase 1-3) at the READ stage-0 claim'),
    H2=dict(evidence_kind='genuine_processing', send_order=('READ', 'final_ACK'), spacing='sequential',
            lost_frame='final_ACK', decisive_action='terminal_abort',
            state_check='owner 0xd/0xe and client advanced by the READ at the ACK stage-0 claim'),
    H2r=dict(evidence_kind='genuine_processing', send_order=('READ', 'final_ACK'), spacing='back_to_back',
             lost_frame='final_ACK', decisive_action='terminal_abort',
             state_check='owner 0xd/0xe and client advanced by the READ at the ACK successful stage-0 claim'),
    collision=dict(evidence_kind='genuine_processing', send_order=('SELECT_response', 'OPERATE'),
                   spacing='back_to_back', lost_frame='OPERATE', decisive_action='busy_drop',
                   state_check='the SELECT response generation holds the work cell (phase 1-3) at the OPERATE '
                               'stage-0 claim'),
    H1prime=dict(evidence_kind='forced_register', send_order=('READ',), spacing='single', lost_frame='READ',
                 decisive_action='busy_drop',
                 state_check='the seeded generation holds the work cell (phase 1) at the READ stage-0 claim'))
CASES = tuple(dict(case='%s_%s' % (s, c), scenario=s, read_class=c, read_length=READ_LENGTH[c], **SCENARIOS[s])
              for c in CLASSES for s in SCENARIO_ORDER)
FORCED_SEED = 0x7ffffffe
MASTER_MAC, RELAY_MAC = bytes.fromhex('3cfdfecc5dc0'), bytes.fromhex('0030a7024ca2')


def verdict(state_reached, loss_seen):
    if not state_reached:
        return 'not_reproduced_state_not_reached'
    return 'reproduced' if loss_seen else 'falsified_for_this_path'


def decode_work(value):
    """The work cell as the model logs it: one 64-bit word, phase in the high half, generation in the low half."""
    return dict(phase=value >> 32, generation=value & 0xffffffff)


# ---- model log ---------------------------------------------------------------------------------------------------
LINE = re.compile(r'^:\d\d-\d\d \d\d:\d\d:\d\d\.\d+:\s+:(0x[0-9a-f]+|-):(0x[0-9a-f]+|-):<\d+,[-\d]+,[-\d]+>:(.*)$')
HEX = re.compile(r'^(?:[0-9a-f]{2} )*[0-9a-f]{2} ?$')


def segment(data):
    """TCP fields of the master<->relay frame inside data (an N pass may carry an envelope before Ethernet)."""
    for macs, direction in ((RELAY_MAC + MASTER_MAC, 'm2r'), (MASTER_MAC + RELAY_MAC, 'r2m')):
        at = data.find(macs + b'\x08\x00')
        if at >= 0 and len(data) >= at + 54:
            ip = at + 14
            ihl, total = (data[ip] & 15) * 4, int.from_bytes(data[ip + 2:ip + 4], 'big')
            tcp = ip + ihl
            return dict(direction=direction, seq=int.from_bytes(data[tcp + 4:tcp + 8], 'big'),
                        ack=int.from_bytes(data[tcp + 8:tcp + 12], 'big'), flags=data[tcp + 13],
                        payload_len=total - ihl - (data[tcp + 12] >> 4) * 4), at
    return None, -1


def parse_passes(lines):
    """Ingress passes in log order: {id, port, segment, event, steps}. Only lines carrying the pass's ingress id
    and no egress id are attributed to it; the parser's own second dump is not taken as the frame."""
    passes, by_id, dumping = [], {}, {}
    for raw in lines:
        match = LINE.match(raw.rstrip('\n'))
        if not match:
            continue
        ing, egr, text = match.group(1), match.group(2), match.group(3).strip()
        if ing == '-' or egr != '-':
            continue
        if text.startswith('==========') and 'Ingress Pkt from port' in text:
            record = dict(id=ing, port=int(re.search(r'from port (\d+)', text).group(1)), data='', steps=[])
            passes.append(record)
            by_id[ing], dumping[ing] = record, 'header'
            continue
        record = by_id.get(ing)
        if record is None:
            continue
        if text.startswith('=========='):
            dumping[ing] = None
        elif text == 'Packet :':
            dumping[ing] = 'frame' if dumping.get(ing) == 'header' else None
        elif dumping.get(ing) == 'frame' and HEX.match(text):
            record['data'] += text.replace(' ', '')
        else:
            dumping[ing] = None
            table = re.match(r'Ingress : Table (\S+) is (.*)$', text)
            action = re.match(r'Execute (Default )?Action: (\S+)', text)
            salu = re.match(r'(Before|After) stateful alu execution: (0x[0-9a-f]+)', text)
            if table:
                record['_table'] = (table.group(1), table.group(2))
            elif action:
                name, status = record.get('_table', (None, None))
                record['steps'].append(dict(table=name, status=status, action=action.group(2),
                                            default=bool(action.group(1)), salu=None))
            elif salu and record['steps']:
                step = record['steps'][-1]
                step['salu'] = (step['salu'] or [None, None])
                step['salu'][0 if salu.group(1) == 'Before' else 1] = int(salu.group(2), 16)
    for record in passes:
        record.pop('_table', None)
        data = bytes.fromhex(record.pop('data'))
        record['segment'], at = segment(data)
        record['event'] = list(data[12:14]) if at >= 16 else None
        for step in record['steps']:
            step['salu'] = tuple(step['salu']) if step['salu'] else None
    return passes


def action_names(record):
    return [step['action'].rsplit('.', 1)[-1] for step in record['steps']]


def salu(record, name):
    for step in record['steps']:
        if step['action'].rsplit('.', 1)[-1] == name and step['salu']:
            return step['salu']
    return None


def table_step(record, table):
    return next((dict(step) for step in record['steps'] if step['table'] == table), None)


def matches(seg, want):
    return seg is not None and all(seg.get(key) == value for key, value in want.items())


def brief(record):
    return dict(id=record['id'], port=record['port'], event=record['event'], actions=action_names(record))


def claims(passes, want):
    """The stage-0 passes of one TCP segment: those that ran the work claim (go_new or a retry)."""
    return [p for p in passes if matches(p['segment'], want) and salu(p, 'claim_work') is not None]


def cell_held_state(passes, holder, victim):
    """Genuine-processing state: the holder's claimed generation is still in the cell (phase 1-3) when the victim's
    stage-0 claim runs."""
    held = [p for p in claims(passes, holder) if decode_work(salu(p, 'claim_work')[0])['phase'] == 4]
    hit = claims(passes, victim)
    if not held or not hit:
        return dict(reached=False, reason='holder claim found: %s; victim claim found: %s' % (bool(held), bool(hit)))
    generation = decode_work(salu(held[0], 'claim_work')[1])['generation']
    before = decode_work(salu(hit[0], 'claim_work')[0])
    return dict(reached=before['phase'] in (1, 2, 3) and before['generation'] == generation,
                holder_pass=brief(held[0]), holder_generation=generation,
                holder_cell_after=decode_work(salu(held[0], 'claim_work')[1]),
                victim_pass=brief(hit[0]), victim_cell_before=before, victim_actions=action_names(hit[0]))


def forced_state(passes, victim, seed):
    hit = claims(passes, victim)
    if not hit:
        return dict(reached=False, reason='no stage-0 claim of the victim in the log')
    before = decode_work(salu(hit[0], 'claim_work')[0])
    return dict(reached=before['phase'] in (1, 2, 3) and before['generation'] == seed, seeded_generation=seed,
                victim_pass=brief(hit[0]), victim_cell_before=before, victim_actions=action_names(hit[0]))


def late_ack_state(passes, ack, expected_client):
    """The ACK's successful stage-0 claim: owner and client as that pass read them, first_event, then its laps."""
    attempts = claims(passes, ack)
    won = [p for p in attempts if decode_work(salu(p, 'claim_work')[0])['phase'] == 4]
    if not won:
        return dict(reached=False, reason='no successful stage-0 claim of the ACK',
                    attempts=[brief(p) for p in attempts])
    first = won[0]
    owner, client = salu(first, 'owner_read'), salu(first, 'load_client')
    owner_value = owner[0] if owner else None
    client_value = client[0] if client else None
    laps = []
    for record in passes[passes.index(first) + 1:]:
        if record['port'] == 68 and matches(record['segment'], ack):
            laps.append(brief(record))
            if {'terminal_abort', 'terminal_ack', 'terminal_strip'} & set(laps[-1]['actions']):
                break
    return dict(reached=owner_value is not None and (owner_value >> 16) in (0xd, 0xe) and client_value == expected_client,
                owner=owner_value, owner_state=None if owner_value is None else owner_value >> 16,
                client=client_value, expected_client=expected_client,
                claim_cell_before=decode_work(salu(first, 'claim_work')[0]), stage0_pass=brief(first),
                first_event=table_step(first, 'n_Ingress.first_event'),
                retries_before_claim=[brief(p) for p in attempts[:attempts.index(first)]], laps=laps)


def late_ack_outcome(state):
    event = state.get('first_event') or {}
    laps = state.get('laps') or []
    return dict(first_event_default_noaction=bool(event.get('default')) and event.get('action') == 'NoAction',
                event_code_255_on_lap=any(lap['event'] and lap['event'][1] == 255 for lap in laps),
                abort_work=any('abort_work' in lap['actions'] for lap in laps),
                terminal_abort=any('terminal_abort' in lap['actions'] for lap in laps))


def label_frames(got, sent):
    out = {}
    for port, frames in got.items():
        rows = []
        for raw in frames:
            seg, _at = segment(raw)
            label = next((name for name, want in sent.items() if matches(seg, want)), None)
            rows.append(dict(label=label, segment=seg, hex=raw.hex()))
        out[str(port)] = rows
    return out


def seg(direction, seq, flags, payload_len):
    return dict(direction=direction, seq=seq & 0xffffffff, flags=flags, payload_len=payload_len)


# ---- model run ---------------------------------------------------------------------------------------------------
class Run:
    """One model: the relay gate's setup, pre-bound sockets for back-to-back frames, the model log."""

    def __init__(self, gate, view, rp):
        import socket
        from model_driver import veth_for
        self.gate, self.m, self.v, self.rp, self.view = gate, gate.m, gate.v, rp, view
        self.log, self.ports = view.log_path(), gate.ports
        if self.log is None:
            raise ValueError('the scenario needs exactly one model log')
        self.fast = {}
        for port in self.ports:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            sock.bind((veth_for(port), 0))
            self.fast[port] = sock

    def packet(self, *args, **kwargs):
        self.rp.advance_timestamp()
        return self.v.packet(*args, **kwargs)

    def registers(self):
        out = {}
        for name in ('work.work', 'owner', 'client', 'server', 'epoch'):
            values = self.m.register_read('p0.n_Ingress.' + name, 0, pipe=0)
            out[name] = {k.rsplit('.', 1)[-1]: (v[0] if isinstance(v, list) else v) for k, v in values.items()}
        return out

    def observe(self, frames, pattern=None, offset=None):
        """Send frames back to back from the pre-bound sockets; wait for the decisive action and for quiescence."""
        self.m.drain(self.ports)
        if offset is None:
            offset = self.view.wait_idle(self.log, quiet=0.5, timeout=20)[0]
        start = time.monotonic()
        for port, frame in frames:
            self.fast[port].send(frame)
        spacing = time.monotonic() - start
        line, waited = (self.view.wait_for(self.log, offset, pattern, timeout=8)[:2] if pattern else (None, None))
        got = self.m.capture(self.ports, timeout=4, quiet=1.0)
        self.view.wait_idle(self.log, quiet=0.5, timeout=20)
        for port, more in self.m.capture(self.ports, timeout=0.6, quiet=0.3).items():
            got.setdefault(port, []).extend(more)
        return dict(offset=offset, send_spacing_s=spacing, decisive_line=line, decisive_wait_s=waited, got=got)

    def passes(self, offset):
        return parse_passes(self.view.lines_since(self.log, offset))

    def open(self, c, s, tag):
        """SYN and SYN-ACK through the gate's exact exchange; the final ACK is the case's to send."""
        v, g = self.v, self.gate
        g.exchange(tag + '_SYN', v.packet(2, c, mss=1460), v.packet(2, c, mss=1460))
        g.exchange(tag + '_SYNACK', v.packet(18, s, c + 1, reverse=True, mss=1460),
                   v.packet(18, s, c + 1, reverse=True, mss=1460), reverse=True)
        return c + 1, s + 1

    def close(self, wire_ack):
        """Reset at N's own client sequence, so a dropped or delivered request leaves no ambiguity."""
        client = self.registers()['client']
        seq = next(iter(client.values()))
        obs = self.observe([(self.gate.master.dev_port, self.packet(20, seq, wire_ack))])
        rows = label_frames(obs['got'], {'RST': dict(direction='m2r', seq=seq, flags=0x14)})
        return dict(rst_seq=seq, rst_forwarded=sum(r['label'] == 'RST' for r in rows.get('64', [])),
                    registers_after=self.registers())

    def retransmit(self, request, c, w, port64_label='READ'):
        frame = self.packet(24, c, w, payload=request)
        obs = self.observe([(self.gate.master.dev_port, frame)])
        rows = label_frames(obs['got'], {port64_label: seg('m2r', c, 0x18, len(request))})
        return sum(r['label'] == port64_label for r in rows.get('64', []))


def run_case(run, case, index, progress):
    """One case on a fresh connection. Returns the case record (state evidence, actions, port-64 frames, verdict).
    progress['wire'] tracks the master's wire ACK so a failed case can still be reset."""
    rp = run.rp
    c, s = 1_000_000 * (index + 1) + 100, 1_000_000 * (index + 1) + 900
    request = rp.read_frames(0, 0, case['read_class'], 0)[0]
    if len(request) != case['read_length']:
        raise ValueError('READ fixture length %d != %d' % (len(request), case['read_length']))
    record = dict(case, isn=dict(master=c, relay=s), registers_before=run.registers())
    scenario, master = case['scenario'], run.gate.master.dev_port
    progress['wire'] = wire = s + 1
    if scenario in ('H1', 'H2', 'H2r'):
        c, s = run.open(c, s, case['case'])
        wire = s
        ack, read = run.packet(16, c, s), run.packet(24, c, s, payload=request)
        sent = {'final_ACK': seg('m2r', c, 0x10, 0), 'READ': seg('m2r', c, 0x18, len(request))}
        if scenario == 'H1':
            obs = [run.observe([(master, ack), (master, read)], BUSY_DROP)]
        elif scenario == 'H2r':
            obs = [run.observe([(master, read), (master, ack)], TERMINAL_ABORT)]
        else:   # the ACK built before the READ (the segment the master sent first) arrives after it
            obs = [run.observe([(master, read)])]
            obs.append(run.observe([(master, ack)], TERMINAL_ABORT))
        passes = run.passes(obs[0]['offset'])
        if scenario == 'H1':
            state = cell_held_state(passes, sent['final_ACK'], sent['READ'])
            decisive = 'busy_drop' in state.get('victim_actions', [])
        else:
            state = late_ack_state(passes, sent['final_ACK'], expected_client=(c + len(request)) & 0xffffffff)
            state['outcome'] = late_ack_outcome(state)
            decisive = all(state['outcome'].values())
    elif scenario == 'collision':
        c, s, wire = run.gate.handshake(c, s, case['case'] + '_')
        progress['wire'] = wire
        c, s, wire = run.gate.actual_exchange(case['case'] + '_READ', case['read_class'], c, s, wire, k=0)
        progress['wire'] = wire
        select, native, image = run.gate.frames('CONTROL', fc=3)
        run.gate.exchange(case['case'] + '_SELECT_request', run.v.packet(24, c, wire, payload=select),
                          run.v.packet(24, c, s, payload=select))
        c += len(select)
        ack = run.v.packet(16, s, c, reverse=True)
        run.gate.exchange(case['case'] + '_SELECT_relay_ACK', ack,
                          rp.preserve_options(ack, run.v.packet(16, wire, c, reverse=True)), reverse=True)
        operate = run.gate.frames('CONTROL', fc=4)[0]
        response = run.packet(24, s, c, reverse=True, payload=native)
        operate_frame = run.packet(24, c, wire + len(image), payload=operate)
        sent = {'SELECT_response': seg('r2m', s, 0x18, len(native)), 'OPERATE': seg('m2r', c, 0x18, len(operate))}
        obs = [run.observe([(run.gate.relay.dev_port, response), (master, operate_frame)], BUSY_DROP)]
        passes = run.passes(obs[0]['offset'])
        state = cell_held_state(passes, sent['SELECT_response'], sent['OPERATE'])
        decisive = 'busy_drop' in state.get('victim_actions', [])
        s, wire = s + len(native), wire + len(image)
        progress['wire'] = wire
        record['select_image_to_master'] = sum(len(f) > 54 and f.find(image) >= 0
                                                for f in obs[0]['got'].get(master, []))
    else:   # H1prime: forced register, a control
        c, s, wire = run.gate.handshake(c, s, case['case'] + '_')
        progress['wire'] = wire
        read = run.packet(24, c, wire, payload=request)
        sent = {'READ': seg('m2r', c, 0x18, len(request))}
        names = {'n_Ingress.work.work.generation': FORCED_SEED, 'n_Ingress.work.work.phase': 1}
        run.m.register_write('p0.n_Ingress.work.work', 0, names, pipe=0)
        try:
            obs = [run.observe([(master, read)], BUSY_DROP)]
            record['forced_cell_before_release'] = run.registers()['work.work']
        finally:
            names['n_Ingress.work.work.phase'] = 4
            run.m.register_write('p0.n_Ingress.work.work', 0, names, pipe=0)
        passes = run.passes(obs[0]['offset'])
        state = forced_state(passes, sent['READ'], FORCED_SEED)
        decisive = 'busy_drop' in state.get('victim_actions', [])
    frames = {}
    for item in obs:
        for port, rows in label_frames(item['got'], sent).items():
            frames.setdefault(port, []).extend(rows)
    lost = case['lost_frame']
    lost_on_relay = not any(row['label'] == lost for row in frames.get('64', []))
    record.update(state_evidence=state, port64_frames=frames.get('64', []), port9_frames=frames.get('9', []),
                  observations=[{k: v for k, v in item.items() if k != 'got'} for item in obs],
                  lost_frame_absent_on_port64=lost_on_relay, decisive_action_seen=decisive,
                  action_trace=[dict(brief(p), label=next((n for n, w in sent.items() if matches(p['segment'], w)),
                                                          None)) for p in passes
                                if p['port'] in (48, 64, 68) and p['segment'] is not None])
    record['verdict'] = verdict(state.get('reached') is True, lost_on_relay and decisive)
    if lost == 'READ' and lost_on_relay:   # the master's retransmission, as on hardware after the RTO
        record['retransmitted_READ_forwarded'] = run.retransmit(request, c, wire)
    record['cleanup'] = run.close(wire)
    return record


def main():
    import model_packets as mp
    from model_relay_sbo import RelayGate
    import model_log_view as view
    h = mp.load('_cs_helpers', HERE / 'model_drive_composite.py')
    cp = mp.load('_cs_cp', HERE / 'cp.py')
    out = Path(os.environ['OUT'])
    report = h.Report(os.environ['PROG'], physical=False, model_gate=False,
                      scope='connection-start loss paths H1/H2/H2r/collision/H1prime; labelled scenario, not gate',
                      driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                      cases=[case['case'] for case in CASES])
    gate = RelayGate(report, h.Model(ports=[], enable=False), h, cp)
    records = []
    try:
        gate.configure()
        report.record['meta']['t_params'] = 'PacketGate.configure default, enabled=0 (N work cell is pipe-0 only)'
        run = Run(gate, view, mp.rp)
        for index, case in enumerate(CASES):
            progress = {}
            try:
                record = run_case(run, case, index, progress)
            except Exception:
                record = dict(case, verdict='not_reproduced_state_not_reached', error=traceback.format_exc())
                try:
                    record['cleanup'] = run.close(progress.get('wire', 0))
                except Exception:
                    record['cleanup_error'] = traceback.format_exc()
            records.append(record)
            (out / ('case_%s.json' % case['case'])).write_text(json.dumps(record, indent=1, sort_keys=True) + '\n')
            report.add(case['case'], 'state evidence and verdict recorded', record['verdict'],
                       ok='error' not in record, evidence_kind=case['evidence_kind'])
    except Exception:
        report.add('exception', 'none', traceback.format_exc(), ok=False)
    report.record['meta']['reflectors'] = [r.summary() for r in getattr(gate, 'reflectors', [])]
    (out / 'connection_start_cases.json').write_text(json.dumps(
        [{k: r.get(k) for k in ('case', 'scenario', 'read_class', 'evidence_kind', 'verdict',
                                'lost_frame_absent_on_port64', 'decisive_action_seen')} for r in records],
        indent=1) + '\n')
    return 0 if report.finish(out / 'connection_start_results.json') else 1


if __name__ == '__main__':
    raise SystemExit(main())

"""Identity-targeted physical relay loss: the drop selects the intended TRANSACTION (operation, ordinal among first
transmissions, exact TCP SEQ/ACK frontier) through an iptables u32 match, not the Nth occurrence of a packet class.

Regression source: rc01_hw_c52_20261024_26_loss_full_950 trial t0 (request_full:3). READ #1 was retransmitted by
the master ~210 ms after its first copy, so the occurrence chain counted that copy and dropped READ #2
(SEQ 2394027640) instead of READ #3 (SEQ 2394027667)."""
import json
import re
import struct
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import relay_loss  # noqa: E402
import wire_check  # noqa: E402

T0 = (HERE.parents[2] / 'integration/core/response_only_rearm/stage_experiments/read_complete_01/evidence/hw_blocks/'
      'rc01_hw_c52_20261024_26_loss_full_950/physical_relay/combined/'
      'rc01_hw_c52_20261024_26_loss_full_950_physical_relay_combined_t0')
T6 = Path(str(T0)[:-1] + '6')
PORT_T0, PORT_T6 = 59970, 59976
# The retained captures are not part of a tracked-source export (test_markers copies no .pcap); there these skip.
needs_t0 = pytest.mark.skipif(not (T0 / 'in.pcap').is_file() or not (T0 / 'out.pcap').is_file(),
                              reason='retained t0 captures absent (source-only export)')
needs_t6 = pytest.mark.skipif(not (T6 / 'in.pcap').is_file() or not (T6 / 'out.pcap').is_file(),
                              reason='retained t6 captures absent (source-only export)')


# ---------------------------------------------------------------------------------------------------------- helpers

def u32_eval(expression, ip_packet):
    """Independent interpreter for the one u32 form the rules use, 'A>>B&M@O=V' (iptables-extensions u32): read the
    32-bit word at A, shift right B, AND M -> the TCP header offset (IHL*4); then read the word O bytes past it."""
    m = re.fullmatch(r'(0x[0-9a-fA-F]+|\d+)>>(0x[0-9a-fA-F]+|\d+)&(0x[0-9a-fA-F]+|\d+)@(0x[0-9a-fA-F]+|\d+)='
                     r'(0x[0-9a-fA-F]+|\d+)', expression)
    assert m, expression
    a, b, mask, off, want = (int(x, 0) for x in m.groups())
    word = lambda at: struct.unpack('!I', ip_packet[at:at + 4])[0]
    base = (word(a) >> b) & mask
    return word(base + off) == want


def rule_hits(rule, ip_packet):
    """Does one rendered physical rule (argument list) match an IPv4 packet on its u32, length and TCP flags?"""
    expression = rule[rule.index('--u32') + 1]
    length = int(rule[rule.index('--length') + 1])
    flags = rule[rule.index('--tcp-flags') + 2]
    want = sum({'ACK': 0x10, 'PSH': 0x08, 'FIN': 0x01, 'SYN': 0x02, 'RST': 0x04}[f] for f in flags.split(','))
    ihl = (ip_packet[0] & 0x0F) * 4
    return (u32_eval(expression, ip_packet) and int.from_bytes(ip_packet[2:4], 'big') == length and
            ip_packet[ihl + 13] & 0x1F == want)


def ipv4_tcp(seq, ack, flags=0x10, payload=b'', options=b''):
    """Minimal IPv4/TCP packet (TCP header 32 bytes with a 12-byte timestamp option, as on the relay link)."""
    tcp = struct.pack('!HHIIBBHHH', 59970, 20000, seq, ack, (32 // 4) << 4, flags, 501, 0, 0) + b'\x01\x01\x08\x0a' + bytes(8)
    ihl = (20 + len(options)) // 4
    total = ihl * 4 + len(tcp) + len(payload)
    ip = struct.pack('!BBHHHBBH4s4s', 0x40 | ihl, 0, total, 0, 0x4000, 64, 6, 0,
                     bytes([192, 168, 10, 1]), bytes([192, 168, 10, 7]))
    return ip + options + tcp + payload


class FakeIptables:
    """iptables -S/-C/-I/-D/-L on one in-memory chain, recording every command."""
    def __init__(self, fail_insert=False, lose_after_insert=False):
        self.rules, self.calls = [], []
        self.fail_insert, self.lose_after_insert = fail_insert, lose_after_insert

    def __call__(self, command):
        self.calls.append(list(command))
        if command[0] == 'dmesg':
            return SimpleNamespace(returncode=0, stdout='', stderr='')
        if command == ['iptables', '-V']:
            return SimpleNamespace(returncode=0, stdout='iptables v1.8.4 (legacy)\n', stderr='')
        assert command[:2] == ['iptables', '-w']
        op, chain, args = command[2], command[3], command[4:]
        ok = SimpleNamespace(returncode=0, stdout='', stderr='')
        if op == '-S':
            return SimpleNamespace(returncode=0, stdout='-P %s ACCEPT\n' % chain +
                                   ''.join('-A %s %s\n' % (chain, ' '.join(r)) for r in self.rules), stderr='')
        if op == '-C':
            return SimpleNamespace(returncode=0 if args in self.rules else 1, stdout='', stderr='')
        if op == '-I':
            if self.fail_insert:
                return SimpleNamespace(returncode=2, stdout='', stderr="Couldn't load match `u32'")
            if not self.lose_after_insert:
                self.rules.insert(int(args[0]) - 1, args[1:])
            return ok
        if op == '-D':
            self.rules.remove(args)
            return ok
        if op == '-L':
            return SimpleNamespace(returncode=0, stdout='', stderr='')
        raise AssertionError(command)


def t0_master():
    return json.loads((T0 / 'master.json').read_text())


def replay(spec, master_records, master_isn, relay_isn):
    """Drive the identity resolver exactly as the master does: before each send, (operation, request length, bytes
    received so far). Returns the (key, value) it armed and the transaction position."""
    target = relay_loss.IdentityTarget(spec)
    target.set_isns(master_isn, relay_isn)
    received, hits = 0, []
    for position, record in enumerate(master_records):
        hit = target.before_send(record['operation'], len(record['request_wire_hex']) // 2, received)
        if hit:
            hits.append((position, hit))
        received += len(record['received_wire_hex']) // 2
    return hits


# ------------------------------------------------------------------------------------------------- (a) the t0 miss

@needs_t0
def test_t0_occurrence_model_hits_read2_identity_resolver_hits_read3():
    spec_occ = relay_loss.parse_drop('request_full:3', 'full', 1)
    result = json.loads((T0 / 'result.json').read_text())
    assert result['loss']['spec'] == spec_occ                     # legacy parse of the retained spec is unchanged
    outs, _ = wire_check.parse(str(T0 / 'out.pcap'))
    cls = [s for s in outs if s['sport'] == PORT_T0 and s['ip_len'] == spec_occ['ip_len'] and s['flags'] & 0x1F == 0x18]
    # Occurrence model: the 3rd class packet the master emitted. READ #1 went out twice (same SEQ), so the 3rd is
    # READ #2 -- exactly what the kernel LOG of the real trial recorded.
    assert [s['seq'] for s in cls[:2]] == [2394027613, 2394027613]
    assert cls[spec_occ['occurrence'] - 1]['seq'] == 2394027640 == result['loss']['kernel_packet']['SEQ']
    # Identity resolver: ISNs from the master's own receive capture (SYN-ACK), then the master's own sends.
    master_isn, relay_isn = relay_loss.syn_ack_isns(str(T0 / 'in.pcap'), PORT_T0)
    assert (master_isn, relay_isn) == (2394027612, 741443162)
    spec = relay_loss.parse_drop('request_full:3:identity', 'full', 1)
    hits = replay(spec, t0_master()['records'], master_isn, relay_isn)
    assert hits == [(2, ('SEQ', 2394027667))]
    wire = json.loads((T0 / 'relay_wire.json').read_text())
    reads = [x for x in wire['exchanges'] if x['operation'] == 'READ']
    assert reads[spec['index']]['request']['sequence_start'] == 2394027667
    # the post-run gate accepts the identity drop and still rejects what the occurrence chain actually hit
    report = dict(exact=True, restoration=dict(restored=True), spec=spec,
                  identity=dict(armed=True, key='SEQ', value=2394027667),
                  kernel_packet=dict(result['loss']['kernel_packet'], SEQ=2394027667))
    assert relay_loss.target_checks(report, wire, PORT_T0) == []
    report['kernel_packet']['SEQ'] = 2394027640
    assert relay_loss.target_checks(report, wire, PORT_T0)


@needs_t0
def test_retransmission_of_earlier_request_cannot_match_identity_rule():
    master_isn, relay_isn = relay_loss.syn_ack_isns(str(T0 / 'in.pcap'), PORT_T0)
    spec = relay_loss.parse_drop('request_full:3:identity', 'full', 1)
    (_pos, (key, value)), = replay(spec, t0_master()['records'], master_isn, relay_isn)
    rule = relay_loss.identity_rules([['-p', 'tcp', '-m', 'length', '--length', '79', '--tcp-flags',
                                       'SYN,RST,ACK,FIN,PSH', 'ACK,PSH'] + relay_loss.loss.LIMIT + ['-j', 'DROP']],
                                     key, value)[0]
    outs, _ = wire_check.parse(str(T0 / 'out.pcap'))
    hits = [s['seq'] for s in outs if s['sport'] == PORT_T0 and rule_hits(rule, s['frame'][14:])]
    assert hits == [2394027667]              # READ #1 (both copies) and READ #2 carry other SEQs


# ------------------------------------------------------------------------------ (b) rule rendering and semantics

def test_u32_expressions_exact_strings():
    assert relay_loss.u32_expression('SEQ', 2394027667) == '0>>22&0x3C@4=0x8eb1f693'
    assert relay_loss.u32_expression('ACK', 741443321) == '0>>22&0x3C@8=0x2c3186f9'
    assert relay_loss.u32_expression('SEQ', 0) == '0>>22&0x3C@4=0x00000000'
    with pytest.raises(ValueError):
        relay_loss.u32_expression('WIN', 1)
    with pytest.raises(ValueError):
        relay_loss.u32_expression('SEQ', 1 << 32)


@pytest.mark.parametrize('options', [b'', b'\x01\x01\x01\x01', b'\x01' * 8])
def test_u32_expression_follows_ihl(options):
    pkt = ipv4_tcp(0x8EB1F693, 0x2C3186F9, 0x18, b'x' * 27, options)
    assert u32_eval(relay_loss.u32_expression('SEQ', 0x8EB1F693), pkt)
    assert u32_eval(relay_loss.u32_expression('ACK', 0x2C3186F9), pkt)
    assert not u32_eval(relay_loss.u32_expression('SEQ', 0x2C3186F9), pkt)
    assert not u32_eval(relay_loss.u32_expression('ACK', 0x8EB1F693), pkt)


@needs_t0
def test_u32_expression_on_retained_relay_frames():
    """Every captured master/relay segment of t0: the SEQ and ACK expressions read the real TCP fields."""
    for name in ('out.pcap', 'in.pcap'):
        segs, _ = wire_check.parse(str(T0 / name))
        assert segs
        for s in segs:
            ip = s['frame'][14:]
            assert u32_eval(relay_loss.u32_expression('SEQ', s['seq']), ip)
            assert u32_eval(relay_loss.u32_expression('ACK', s['ack']), ip)
            assert not u32_eval(relay_loss.u32_expression('SEQ', (s['seq'] + 1) & 0xFFFFFFFF), ip)


def test_identity_rules_render_u32_before_one_shot_limit_with_log():
    spec = relay_loss.parse_drop('request_full:3:identity', 'full', 1)
    rule, prefix = relay_loss.owned_rule(spec, 59970, 'lab', run=FakeIptables(), identity=('SEQ', 2394027667))
    common = ('-p tcp -s 192.168.10.1 -d 192.168.10.7 --sport 59970 --dport 20000 -m length --length 79 '
              '--tcp-flags SYN,RST,ACK,FIN,PSH ACK,PSH -m u32 --u32 0>>22&0x3C@4=0x8eb1f693 '
              '-m limit --limit 1/hour --limit-burst 1 -j ')
    assert [' '.join(r) for r in rule.rules] == [
        common + 'LOG --log-prefix %s  --log-tcp-sequence' % prefix, common + 'DROP']
    assert rule.chain == 'OUTPUT'
    # u32 precedes the limit match: a non-target packet of the class never consumes the one-shot token
    for r in rule.rules:
        assert r.index('--u32') < r.index('limit')
    ack_spec = relay_loss.parse_drop('ack_sep:3:identity', 'full', 1)
    ack_rule, _ = relay_loss.owned_rule(ack_spec, 59971, 'lab', run=FakeIptables(), identity=('ACK', 1506223019))
    assert ack_rule.chain == 'INPUT'
    assert ['-m', 'u32', '--u32', '0>>22&0x3C@8=0x59c723ab'] == ack_rule.rules[-1][17:21]
    assert ack_rule.rules[-1][:4] == ['-p', 'tcp', '-s', '192.168.10.7']


def test_identity_spec_is_explicit_and_legacy_parse_is_unchanged():
    legacy = relay_loss.parse_drop('request_full:3', 'full', 1)
    assert 'target' not in legacy and legacy['occurrence'] == 3
    ident = relay_loss.parse_drop('request_full:3:identity', 'full', 1)
    assert ident['target'] == 'identity' and ident['occurrence'] == 1 and ident['match'] == 'SEQ'
    assert {k: v for k, v in ident.items() if k not in ('text', 'target', 'occurrence', 'match', 'response_payload')} \
        == {k: v for k, v in legacy.items() if k not in ('text', 'occurrence')}
    for bad in ('request_full:3:occurrence', 'request_full:3:identity:x', 'request_full:3:IDENTITY'):
        with pytest.raises(ValueError):
            relay_loss.parse_drop(bad, 'full', 1)


@pytest.mark.parametrize('selector,schedule,key', [
    ('request_mixed:2', 'mixed', 'SEQ'), ('request_full:2', 'full', 'SEQ'), ('select_req:1', 'mixed', 'SEQ'),
    ('operate_req:1', 'mixed', 'SEQ'), ('ack_sep:2', 'mixed', 'ACK'), ('read_resp_padded:2', 'full', 'SEQ'),
    ('select_resp_padded:1', 'full', 'SEQ'), ('operate_resp_padded:1', 'mixed', 'SEQ'),
    ('master_ack_of_padded_data:2', 'full', 'ACK')])
def test_every_physical_preset_resolves_to_its_transaction_frontier(selector, schedule, key):
    """Synthetic master: 3 READs, then SELECT/OPERATE; each request R bytes, each response P bytes."""
    spec = relay_loss.parse_drop(selector + ':identity', schedule, 1)
    assert spec['match'] == key
    read_req, read_img = (25, 141) if schedule == 'mixed' else (27, 158)
    script = [('READ', read_req, read_img)] * 3 + [('SELECT', 45, 60), ('OPERATE', 45, 60)]
    target = relay_loss.IdentityTarget(spec)
    target.set_isns(1000, 5000)
    sent = received = 0
    hits = []
    for operation, req, resp in script:
        hit = target.before_send(operation, req, received)
        if hit:
            hits.append((operation, sent, received, req, resp, hit))
        sent, received = sent + req, received + resp
    (operation, sent, received, req, resp, (k, value)), = hits
    assert operation == spec['operation'] and k == key
    frontier = spec['frontier']
    expected = {'request': 1001 + sent, 'request_ack': 1001 + sent + req, 'response': 5001 + received,
                'response_ack': 5001 + received + resp}[frontier]
    assert value == expected


def test_identity_target_wraps_sequence_space():
    spec = relay_loss.parse_drop('request_full:1:identity', 'full', 1)
    target = relay_loss.IdentityTarget(spec)
    target.set_isns(0xFFFFFFFF, 7)
    assert target.before_send('READ', 27, 0) == ('SEQ', 0)
    with pytest.raises(RuntimeError):
        relay_loss.IdentityTarget(spec).before_send('READ', 27, 0)     # no ISNs: fail closed, never guess


# ------------------------------------------------------- one-shot lifecycle, removal at trial end, fail-closed arming

def test_identity_arm_installs_only_before_target_and_removal_restores_chain(tmp_path):
    ipt = FakeIptables()
    spec = relay_loss.parse_drop('request_full:2:identity', 'full', 1)
    owner = relay_loss.RelayLoss(spec, 59970, 'lab', tmp_path / 'state.json', run=ipt)
    owner.install()
    assert ipt.rules == []                                       # nothing installed before the ISN is known
    owner.target.set_isns(100, 900)
    owner.before_send('READ', b'x' * 27, received=158)           # READ #1: not the target
    assert ipt.rules == []
    owner.before_send('READ', b'x' * 27, received=158)           # READ #2: armed immediately before its send
    assert len(ipt.rules) == 2 and all('0>>22&0x3C@4=0x00000080' in r for r in ipt.rules)
    state = json.loads((tmp_path / 'state.json').read_text())
    assert state['identity'] == ['SEQ', 128]
    owner.before_send('READ', b'x' * 27, received=316)           # later sends never re-arm
    assert len(ipt.rules) == 2
    report = owner.finish()
    assert ipt.rules == [] and not (tmp_path / 'state.json').exists()
    arm_ns = report['identity'].pop('arm_ns')
    assert type(arm_ns) is int and arm_ns > 0
    assert report['restoration']['restored'] and report['identity'] == dict(
        armed=True, key='SEQ', value=128, master_isn=100, relay_isn=900, operation='READ', index=1, error=None)
    assert report['iptables_version'] == 'iptables v1.8.4 (legacy)'      # backend recorded (one-shot precondition)
    assert report['mode'] == 'identity u32 one-shot (limit-burst-1)'


def test_identity_crash_restoration_reconstructs_armed_rules(tmp_path):
    ipt = FakeIptables()
    spec = relay_loss.parse_drop('read_resp_padded:1:identity', 'full', 1)
    owner = relay_loss.RelayLoss(spec, 59970, 'lab', tmp_path / 'state.json', run=ipt)
    owner.install()
    owner.target.set_isns(100, 900)
    owner.before_send('READ', b'x' * 27, received=0)
    assert len(ipt.rules) == 2
    restored = relay_loss.restore_owned(tmp_path / 'state.json', run=ipt)   # a fresh process, from the state file
    assert restored['restored'] and ipt.rules == []


def test_identity_never_armed_is_not_exact_and_restores(tmp_path):
    ipt = FakeIptables()
    owner = relay_loss.RelayLoss(relay_loss.parse_drop('request_full:5:identity', 'full', 1), 59970, 'lab',
                                 tmp_path / 'state.json', run=ipt)
    owner.install()
    report = owner.finish()
    assert not report['exact'] and report['identity']['armed'] is False
    assert report['restoration']['restored'] and not (tmp_path / 'state.json').exists()
    assert not [c for c in ipt.calls if c[2:3] == ['-D']]


@pytest.mark.parametrize('kind', ['fail_insert', 'lose_after_insert'])
def test_identity_arm_failure_fails_closed(tmp_path, kind):
    ipt = FakeIptables(**{kind: True})
    owner = relay_loss.RelayLoss(relay_loss.parse_drop('request_full:1:identity', 'full', 1), 59970, 'lab',
                                 tmp_path / 'state.json', run=ipt)
    owner.install()
    owner.target.set_isns(100, 900)
    with pytest.raises(RuntimeError):
        owner.before_send('READ', b'x' * 27, received=0)
    report = owner.finish()
    assert not report['exact'] and report['identity']['armed'] is False and report['identity']['error']
    assert report['restoration']['restored']


def test_on_connect_without_syn_ack_fails_closed(tmp_path):
    owner = relay_loss.RelayLoss(relay_loss.parse_drop('request_full:1:identity', 'full', 1), 59970, 'lab',
                                 tmp_path / 'state.json', run=FakeIptables(), capture=str(tmp_path / 'missing.pcap'))
    with pytest.raises(RuntimeError):
        owner.on_connect(timeout_s=0.2)


@needs_t0
def test_on_connect_reads_isns_from_capture(tmp_path):
    owner = relay_loss.RelayLoss(relay_loss.parse_drop('request_full:3:identity', 'full', 1), PORT_T0, 'lab',
                                 tmp_path / 'state.json', run=FakeIptables(), capture=str(T0 / 'in.pcap'))
    owner.on_connect(timeout_s=1)
    assert (owner.target.master_isn, owner.target.relay_isn) == (2394027612, 741443162)


def test_master_workload_arms_before_the_target_send_only(monkeypatch):
    import relay_master
    from session import Outcome
    order = []

    class FakeSession:
        sock = object()
        def __init__(self, *args, **kwargs): pass
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def transaction(self, **kwargs):
            order.append(('send', kwargs['operation']))
            return Outcome(operation=kwargs['operation'], function=kwargs['function'], app_seq=kwargs['app_seq'],
                           outcome='OK')

    class Target:
        def on_connect(self):
            order.append(('connect',))
        def before_send(self, operation, frame, sock):
            assert sock is FakeSession.sock and isinstance(frame, bytes)
            order.append(('before', operation))

    monkeypatch.setenv('DEFENSE4_HW_AUTHORIZED', '1')
    monkeypatch.setattr(relay_master, 'Session', FakeSession)
    rec = relay_master.workload(59410, 2, schedule='full', read_pause_ms=0, loss_target=Target())
    assert rec['ok']
    assert order == [('connect',), ('before', 'READ'), ('send', 'READ'), ('before', 'READ'), ('send', 'READ'),
                     ('before', 'SELECT'), ('send', 'SELECT'), ('before', 'OPERATE'), ('send', 'OPERATE')]


def test_master_workload_arm_failure_stops_before_send(monkeypatch):
    import relay_master
    sent = []

    class FakeSession:
        sock = object()
        def __init__(self, *args, **kwargs): pass
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def transaction(self, **kwargs):
            sent.append(kwargs['operation'])
            raise AssertionError('must not send after a failed arm')

    class Target:
        def on_connect(self): pass
        def before_send(self, operation, frame, sock):
            raise RuntimeError('identity loss rule not confirmed installed')

    monkeypatch.setenv('DEFENSE4_HW_AUTHORIZED', '1')
    monkeypatch.setattr(relay_master, 'Session', FakeSession)
    with pytest.raises(RuntimeError):
        relay_master.workload(59410, 2, schedule='full', read_pause_ms=0, loss_target=Target())
    assert sent == []


# ------------------------------------------------------------------------- (d) ACK frontiers and FIN-adjacent ACKs

@needs_t6
def test_master_ack_identity_on_t6_hits_response_ack_not_fin_ack():
    """t6 (master_ack_of_padded_data:1): the master's pure ACK of READ #1's padded response. The identity ACK value
    equals the logged ACK; the master's ACK of the relay FIN (frontier + 1 of the last response) can never match."""
    result = json.loads((T6 / 'result.json').read_text())
    master_isn, relay_isn = relay_loss.syn_ack_isns(str(T6 / 'in.pcap'), PORT_T6)
    spec = relay_loss.parse_drop('master_ack_of_padded_data:1:identity', 'full', 1)
    records = json.loads((T6 / 'master.json').read_text())['records']
    (_pos, (key, value)), = replay(spec, records, master_isn, relay_isn)
    assert (key, value) == ('ACK', result['loss']['kernel_packet']['ACK'])
    rule, _ = relay_loss.owned_rule(spec, PORT_T6, 'lab', run=FakeIptables(), identity=(key, value))
    outs, _ = wire_check.parse(str(T6 / 'out.pcap'))
    fin_acks = [s for s in outs if s['sport'] == PORT_T6 and s['flags'] & 0x1F == 0x10 and s['len'] == 0][-1:]
    assert fin_acks and not rule_hits(rule.rules[-1], fin_acks[0]['frame'][14:])
    # nothing that reached the wire matches (the one hit was dropped before tcpdump's TX tap)
    assert not [s for s in outs if s['sport'] == PORT_T6 and rule_hits(rule.rules[-1], s['frame'][14:])]


def test_ack_preset_for_last_read_does_not_hit_the_fin_ack():
    """The last READ's response ends at F; the relay FIN then sits at F and the master's ACK of it carries F + 1,
    while the master's own FIN carries ACK F (FIN flag set). Neither matches the pure-ACK identity rule ACK=F."""
    spec = relay_loss.parse_drop('master_ack_of_padded_data:3:identity', 'full', 1)
    target = relay_loss.IdentityTarget(spec)
    target.set_isns(1000, 5000)
    for i in range(3):
        hit = target.before_send('READ', 27, 158 * i)
    key, frontier = hit
    assert (key, frontier) == ('ACK', 5001 + 3 * 158)
    rule, _ = relay_loss.owned_rule(spec, 59970, 'lab', run=FakeIptables(), identity=hit)
    drop = rule.rules[-1]
    pure_ack = ipv4_tcp(1082, frontier, 0x10)
    ack_of_fin = ipv4_tcp(1083, frontier + 1, 0x10)
    master_fin = ipv4_tcp(1082, frontier, 0x11)
    next_request = ipv4_tcp(1082, frontier, 0x18, b'x' * 27)
    assert rule_hits(drop, pure_ack)
    assert not rule_hits(drop, ack_of_fin) and not rule_hits(drop, master_fin) and not rule_hits(drop, next_request)


def test_ack_sep_identity_excludes_response_and_fin_with_same_ack():
    spec = relay_loss.parse_drop('ack_sep:2:identity', 'mixed', 1)
    target = relay_loss.IdentityTarget(spec)
    target.set_isns(1000, 5000)
    target.before_send('READ', 25, 0)
    key, value = target.before_send('READ', 25, 141)
    assert (key, value) == ('ACK', 1001 + 50)
    rule, _ = relay_loss.owned_rule(spec, 59970, 'lab', run=FakeIptables(), identity=(key, value))
    drop = rule.rules[-1]
    sep_ack = ipv4_tcp(5142, value, 0x10)
    response = ipv4_tcp(5142, value, 0x18, b'r' * 141)
    relay_fin = ipv4_tcp(5283, value, 0x11)
    previous_sep_ack = ipv4_tcp(5001, value - 25, 0x10)
    assert rule_hits(drop, sep_ack)
    assert not any(rule_hits(drop, p) for p in (response, relay_fin, previous_sep_ack))


def test_target_checks_rejects_identity_value_not_logged():
    spec = relay_loss.parse_drop('read_resp_padded:3:identity', 'mixed', 1)
    wire = dict(exchanges=[dict(operation='READ', request=dict(sequence_start=100 + i, sequence_end=101 + i),
                              response=dict(sequence_start=200 + i, sequence_end=393 + i)) for i in range(3)])
    report = dict(exact=True, restoration=dict(restored=True), spec=spec,
                  identity=dict(armed=True, key='SEQ', value=202),
                  kernel_packet=dict(SRC='192.168.10.7', DST='192.168.10.1', SPT=20000, DPT=59410,
                                     LEN=193, SEQ=202, ACK=103))
    assert relay_loss.target_checks(report, wire, 59410) == []
    report['identity']['value'] = 201
    assert relay_loss.target_checks(report, wire, 59410)
    report['identity'] = dict(armed=False, key='SEQ', value=None)
    assert relay_loss.target_checks(report, wire, 59410)


# ---------------------------------------------------------------------------------- campaign config compatibility

def test_campaign_accepts_explicit_identity_target_and_keeps_legacy_entries():
    import campaign as cp
    base = dict(trials=dict(reads_per_trial=20), arms=[], loss=dict(presets=dict(
        legacy=[dict({'class': 'request_full', 'n': 3})])))
    cp.validate_loss_and_scenarios(dict(base, endpoint_profile='sel751'))
    ident = dict(base, endpoint_profile='sel751',
                 loss=dict(presets=dict(p=[{'class': 'request_full', 'n': 3, 'target': 'identity'}])))
    cp.validate_loss_and_scenarios(ident)
    for bad in ({'class': 'request_full', 'n': 3, 'target': 'occurrence'},
                {'class': 'request_full', 'n': 3, 'target': 'identity', 'x': 1}):
        with pytest.raises(ValueError):
            cp.validate_loss_and_scenarios(dict(base, endpoint_profile='sel751', loss=dict(presets=dict(p=[bad]))))
    with pytest.raises(ValueError):          # identity targeting is implemented only on the physical relay path
        cp.validate_loss_and_scenarios(dict(base, loss=dict(presets=dict(
            p=[{'class': 'request', 'n': 3, 'target': 'identity'}]))))
    assert cp.drop_text({'class': 'request_full', 'n': 3}) == 'request_full:3'
    assert cp.drop_text({'class': 'request_full', 'n': 3, 'target': 'identity'}) == 'request_full:3:identity'


# ------------------------------------------- M2: an aborted identity arm leaves no relay_wire.json -> recorded failure

def _verdict_without_wire(tmp_path, rc, result=True):
    import campaign as cp

    class Fake:
        verdict_loss = cp.Campaign.verdict_loss

        def __init__(self):
            self.cfg = dict(endpoint_profile='sel751')
            self.rn = SimpleNamespace(dry=False)
            self.soft_failures = []

        def relay_verdict(self, trial, *args, **kwargs):
            trial.update(failures=['master transaction failed'], ok=False, observed={},
                         dimension_verdicts=dict(application=False))

    if result:
        (tmp_path / 'result.json').write_text(json.dumps(dict(error='identity loss arm failed', loss=dict(
            exact=False, identity=dict(armed=False, error='identity loss rules not confirmed installed')))))
    fake, trial = Fake(), {}
    fake.verdict_loss(trial, {}, 'label_t0', str(tmp_path), SimpleNamespace(rc=rc), {}, 'physical_relay', {}, 59970)
    return fake, trial


@pytest.mark.parametrize('result', [True, False])
def test_missing_relay_wire_is_a_recorded_trial_failure_and_the_block_continues(tmp_path, result):
    fake, trial = _verdict_without_wire(tmp_path, rc=1, result=result)
    assert fake.soft_failures == ['label_t0']
    assert trial['ok'] is False and trial['dimension_verdicts']['loss_target'] is False
    assert any('relay_wire.json' in f for f in trial['failures']) or any('result.json' in f for f in trial['failures'])
    assert json.loads((tmp_path / 'trial.json').read_text())['ok'] is False


def test_missing_relay_wire_with_infrastructure_failure_still_stops(tmp_path):
    import campaign as cp
    with pytest.raises(cp.StepFailed):
        _verdict_without_wire(tmp_path, rc=255)

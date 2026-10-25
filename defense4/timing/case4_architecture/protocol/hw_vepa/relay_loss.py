"""Physical SEL-751 loss selectors and recoverable ownership of exact host firewall rules."""
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import struct
import subprocess
import time

import loss
from endpoint_profiles import MASTER_IP, RELAY_IP, RELAY_PORT


def sh(argv):
    return subprocess.run(list(argv), capture_output=True, text=True)


def firewall_snapshot(run=sh):
    result = {}
    for chain in ('INPUT', 'OUTPUT'):
        observed = run(['iptables', '-w', '-S', chain])
        if observed.returncode:
            raise RuntimeError('physical firewall baseline unavailable: ' + observed.stderr)
        result[chain] = [line.strip() for line in observed.stdout.splitlines() if line.strip()]
    return result


def parse_drop(text, schedule, padding):
    if schedule not in ('mixed', 'full') or padding not in (0, 1):
        raise ValueError('physical loss requires one declared READ class and padding bit')
    match = re.fullmatch(r'([a-z0-9_]+):([1-9][0-9]?)(:identity)?', text)
    if not match:
        raise ValueError('physical loss requires a known CLASS:N[:identity] with N in 1..99')
    name, n, identity = match.group(1), int(match.group(2)), bool(match.group(3))
    read_image = 141 if schedule == 'mixed' else 158
    definitions = {
        'request_mixed': ('M>O', 25, 'ACK,PSH', 0, 'READ', n - 1, 'request'),
        'request_full': ('M>O', 27, 'ACK,PSH', 0, 'READ', n - 1, 'request'),
        'read_resp_padded': ('O>M', read_image, 'ACK,PSH', 0, 'READ', n - 1, 'response'),
        'select_resp_padded': ('O>M', 60, 'ACK,PSH', 0, 'SELECT', n - 1, 'response'),
        'operate_resp_padded': ('O>M', 60, 'ACK,PSH', 1, 'OPERATE', n - 1, 'response'),
        'operate_req': ('M>O', 45, 'ACK,PSH', 1, 'OPERATE', n - 1, 'request'),
        'select_req': ('M>O', 45, 'ACK,PSH', 0, 'SELECT', n - 1, 'request'),
        'ack_sep': ('O>M', 0, 'ACK', 0, 'READ', n - 1, 'request_ack'),
        'master_ack_of_padded_data': ('M>O', 0, 'ACK', 1, 'READ', n - 1, 'response_ack'),
    }
    if name not in definitions or (name == 'request_mixed' and schedule != 'mixed') or \
            (name == 'request_full' and schedule != 'full') or ('padded' in name and not padding):
        raise ValueError('selector is not present on this physical workload: ' + name)
    direction, payload, flags, offset, operation, index, frontier = definitions[name]
    spec = dict(text=text, schedule=schedule, padding=padding, **{'class': name}, n=n,
                dir=direction, ip_len=52 + payload, flags=flags, occurrence=n + offset,
                chain='INPUT' if direction == 'O>M' else 'OUTPUT', base=name,
                operation=operation, index=index, frontier=frontier, length_only=False)
    if identity:
        # Identity mode (explicit ':identity'): one LOG + one DROP rule that also match the exact TCP SEQ/ACK of
        # the intended transaction, armed by the master immediately before it sends that transaction's request.
        # occurrence 1 = the first packet carrying that identity; its own retransmission passes (one-shot).
        spec.update(target=IDENTITY, occurrence=1, match='ACK' if frontier.endswith('_ack') else 'SEQ',
                    response_payload=read_image if frontier == 'response_ack' else None)
    return spec


IDENTITY = 'identity'
U32_OFFSET = {'SEQ': 4, 'ACK': 8}          # byte offset of the field inside the TCP header


def u32_expression(key, value):
    """xt_u32 test of one TCP header word: `0>>22&0x3C` is the IPv4 IHL*4 (the TCP header offset, options
    included), `@N` reads the 32-bit word N bytes past it (4 = sequence number, 8 = acknowledgment number)."""
    if key not in U32_OFFSET or type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
        raise ValueError('identity match needs SEQ or ACK and a 32-bit value')
    return '0>>22&0x3C@%d=0x%08x' % (U32_OFFSET[key], value)


def identity_rules(rules, key, value):
    """Each rule with the u32 identity match inserted BEFORE its `-m limit`: matches are evaluated in order, so a
    packet of the class with another SEQ/ACK fails the u32 test and never consumes the one-shot limit token."""
    match = ['-m', 'u32', '--u32', u32_expression(key, value)]
    out = []
    for rule in rules:
        at = next(i for i in range(len(rule) - 1) if rule[i:i + 2] == ['-m', 'limit'])
        out.append(rule[:at] + match + rule[at:])
    return out


def syn_ack_isns(in_pcap, master_port):
    """(master ISN, relay ISN) from the relay's SYN-ACK in the master's receive capture: its SEQ is the relay ISN,
    its ACK the master ISN + 1. ValueError unless exactly one distinct SYN-ACK of this connection is present."""
    import wire_check
    segments, _ = wire_check.parse(in_pcap)
    found = {(s['seq'], s['ack']) for s in segments
             if (s['src'], s['dst'], s['sport'], s['dport']) == (RELAY_IP, MASTER_IP, RELAY_PORT, master_port)
             and s['flags'] & 0x17 == 0x12}
    if len(found) != 1:
        raise ValueError('expected one SYN-ACK of port %d in %s, found %d' % (master_port, in_pcap, len(found)))
    (relay_isn, ack), = found
    return (ack - 1) & 0xFFFFFFFF, relay_isn


TCP_INFO_BYTES_RECEIVED = 128      # struct tcp_info: __u64 tcpi_bytes_received (Linux >= 4.1, <linux/tcp.h>)


def tcp_bytes_received(sock):
    """Payload octets the kernel has accepted in order on this socket (rcv_nxt - ISN - 1)."""
    info = sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, TCP_INFO_BYTES_RECEIVED + 8)
    if len(info) < TCP_INFO_BYTES_RECEIVED + 8:
        raise RuntimeError('kernel tcp_info has no tcpi_bytes_received')
    return struct.unpack_from('=Q', info, TCP_INFO_BYTES_RECEIVED)[0]


class IdentityTarget:
    """Resolves the intended transaction from what the master itself sends and receives. Call before_send() for
    EVERY application request, in order, before it is handed to the socket; it returns (key, value) exactly once,
    for the spec's operation at ordinal `index` among first transmissions, and None otherwise.

      request       SEQ = master ISN + 1 + octets sent before the request
      request_ack   ACK = that + the request length            (relay's separate pure ACK of the request)
      response      SEQ = relay ISN + 1 + octets received before the response
      response_ack  ACK = that + the padded response length    (master's pure ACK of the response)"""
    def __init__(self, spec):
        self.spec, self.master_isn, self.relay_isn = spec, None, None
        self.sent, self.counts, self.hit = 0, {}, None

    def set_isns(self, master_isn, relay_isn):
        self.master_isn, self.relay_isn = master_isn, relay_isn

    def before_send(self, operation, frame_len, received):
        if self.master_isn is None or self.relay_isn is None:
            raise RuntimeError('identity loss target has no connection ISNs; refusing to guess')
        ordinal = self.counts.get(operation, 0)
        self.counts[operation] = ordinal + 1
        sent, self.sent = self.sent, self.sent + frame_len
        if self.hit is not None or operation != self.spec['operation'] or ordinal != self.spec['index']:
            return None
        frontier = self.spec['frontier']
        value = {'request': self.master_isn + 1 + sent,
                 'request_ack': self.master_isn + 1 + sent + frame_len,
                 'response': self.relay_isn + 1 + received,
                 'response_ack': self.relay_isn + 1 + received + (self.spec.get('response_payload') or 0)}[frontier]
        self.hit = (self.spec['match'], value & 0xFFFFFFFF)
        return self.hit


def owned_rule(spec, port, label, run=sh, identity=None):
    if type(port) is not int or not 1024 <= port <= 65535 or not re.fullmatch(r'[A-Za-z0-9_]+', label):
        raise ValueError('invalid physical loss ownership identity')
    if spec != parse_drop(spec['text'], spec['schedule'], spec['padding']):
        raise ValueError('physical loss specification changed')
    prefix = 'D4R' + hashlib.sha256((label + str(port) + spec['text']).encode()).hexdigest()[:16]
    rule = loss.LossRule(lambda _ns, *args: run(list(args)), spec, MASTER_IP, RELAY_IP, port, RELAY_PORT,
                         chain=spec['chain'], log_prefix=prefix)
    if spec.get('target') == IDENTITY:
        rule.MODE = IDENTITY_MODE
    if identity is not None:
        if spec.get('target') != IDENTITY or identity[0] != spec['match']:
            raise ValueError('identity match given for a spec that does not declare it')
        rule.rules = identity_rules(rule.rules, *identity)
    return rule, prefix


IDENTITY_MODE = 'identity u32 one-shot (limit-burst-1)'


def restore_owned(path, run=sh):
    path = Path(path)
    if not path.exists():
        return dict(applied=False, errors=[], restored=True)
    errors = []
    try:
        state = json.loads(path.read_text())
        identity = state.get('identity')
        rule, prefix = owned_rule(state['spec'], state['port'], state['label'], run=run,
                                  identity=tuple(identity) if identity else None)
        if prefix != state['prefix'] or not isinstance(state['before'], list):
            raise ValueError('physical loss ownership/baseline mismatch')
        # an identity loss that was never armed installed nothing: there is no exact rule to look for
        armed = state['spec'].get('target') != IDENTITY or identity is not None
        for arguments in rule.rules if armed else ():
            checked = rule._ipt('-C', rule.chain, *arguments)
            if checked.returncode == 0:
                deleted = rule._ipt('-D', rule.chain, *arguments)
                if deleted.returncode:
                    errors.append('owned physical loss rule removal failed: ' + deleted.stderr)
            elif checked.returncode != 1:
                errors.append('owned physical loss rule presence check failed: ' + checked.stderr)
        after = rule._chain()
        if after is None or after != state['before']:
            errors.append('physical host firewall differs from pre-loss baseline')
        if not errors:
            path.unlink()
        return dict(applied=True, errors=errors, restored=not errors, before=state['before'], after=after)
    except (OSError, ValueError, KeyError, TypeError) as error:
        return dict(applied=True, errors=[str(error)], restored=False)


class RelayLoss:
    """Owner of one physical loss. Occurrence mode (legacy CLASS:N) installs its chain in install(). Identity mode
    (CLASS:N:identity) records ownership in install() but inserts nothing; on_connect() reads the ISNs from the
    master's receive capture, and before_send() -- called by the master before every request -- arms the u32
    rules immediately before the target request leaves, confirming them with iptables -C. Any failure raises, so
    the master never sends the target unarmed; finish() always removes and reports."""
    def __init__(self, spec, port, label, state_path, run=sh, capture=None):
        self.spec, self.port, self.label, self.state_path, self.run = spec, port, label, Path(state_path), run
        self.rule, self.prefix = owned_rule(spec, port, label, run=run)
        self.identity = spec.get('target') == IDENTITY
        self.capture, self.target = capture, IdentityTarget(spec) if self.identity else None
        self.armed, self.arm_error, self.before, self.arm_ns = None, None, None, None

    def install(self):
        if self.state_path.exists():
            raise RuntimeError('pending physical loss ownership exists; restore before traffic')
        before = self.rule._chain()
        if before is None:
            raise RuntimeError('physical host firewall baseline unavailable')
        if any(self.rule._ipt('-C', self.rule.chain, *arguments).returncode != 1 for arguments in self.rule.rules):
            raise RuntimeError('physical loss rules already exist or cannot be checked')
        self.before = before
        self._write_state(None, create=True)
        if not self.identity:
            self.rule.install()
        return self

    def _write_state(self, identity, create=False):
        state = dict(spec=self.spec, port=self.port, label=self.label, prefix=self.prefix, before=self.before)
        if self.identity:
            state['identity'] = list(identity) if identity else None
        if create:
            with self.state_path.open('x') as stream:
                json.dump(state, stream)
            return
        temporary = self.state_path.with_name(self.state_path.name + '.tmp')
        with temporary.open('w') as stream:
            json.dump(state, stream)
            stream.flush()
            os.fsync(stream.fileno())       # the armed identity must be on disk before the rules go in
        os.replace(str(temporary), str(self.state_path))

    def on_connect(self, timeout_s=2.0):
        """Poll the live receive capture for this connection's SYN-ACK; fail closed when it is not there."""
        deadline, last = time.monotonic() + timeout_s, None
        while True:
            try:
                self.target.set_isns(*syn_ack_isns(self.capture, self.port))
                return
            except Exception as error:      # a live pcap may end in an unfinished record
                last = error
            if time.monotonic() >= deadline:
                self.arm_error = 'connection ISNs not observed: %s' % last
                raise RuntimeError('identity loss: ' + self.arm_error)
            time.sleep(0.02)

    def before_send(self, operation, frame, sock=None, received=None):
        try:
            hit = self.target.before_send(operation, len(frame),
                                          tcp_bytes_received(sock) if received is None else received)
        except Exception as error:
            self.arm_error = self.arm_error or str(error)
            raise
        if hit is not None:
            self.arm(*hit)

    def arm(self, key, value):
        started = time.monotonic_ns() if hasattr(time, 'monotonic_ns') else None
        try:
            if self.armed is not None:
                raise RuntimeError('identity loss rule already armed')
            rule, _prefix = owned_rule(self.spec, self.port, self.label, run=self.run, identity=(key, value))
            if any(rule._ipt('-C', rule.chain, *arguments).returncode != 1 for arguments in rule.rules):
                raise RuntimeError('identity loss rules already exist or cannot be checked')
            self._write_state((key, value))             # ownership first, so a crash can still remove them
            self.rule = rule
            rule.install()
            if any(rule._ipt('-C', rule.chain, *arguments).returncode != 0 for arguments in rule.rules):
                raise RuntimeError('identity loss rules not confirmed installed before the send')
            self.armed = (key, value)
        except Exception as error:
            self.arm_error = str(error)
            raise RuntimeError('identity loss arm failed (trial fails closed): %s' % error)
        finally:
            self.arm_ns = time.monotonic_ns() - started if started is not None else None

    def finish(self):
        self.rule.finish()
        # One-shot rests on each limit token staying spent until the trial ends; on a legacy (non-nft) backend
        # a whole-table rewrite by anyone else may re-initialise it (LOSS_TARGETING.md), so record the backend.
        try:
            version = self.run(['iptables', '-V'])
            iptables_version = version.stdout.strip() if version.returncode == 0 else 'error: ' + version.stderr.strip()
        except Exception as error:
            iptables_version = 'error: %s' % error
        result = self.run(['dmesg', '--color=never'])
        lines = [line for line in result.stdout.splitlines() if self.prefix + ' ' in line]
        restoration = restore_owned(self.state_path, run=self.run)
        self.rule.state_after = restoration.get('after')
        self.rule.removed = restoration['restored']
        self.rule.remove_errors = restoration['errors']
        report = self.rule.record()
        logs = [row for row in self.rule.counter_list[:len(self.rule.rules)] if row['target'] == 'LOG']
        parsed = None
        if len(lines) == 1:
            fields = dict(re.findall(r'\b(SRC|DST|LEN|SPT|DPT|SEQ|ACK)=([^ ]+)', lines[0]))
            try:
                parsed = {key: int(fields[key]) for key in ('LEN', 'SPT', 'DPT', 'SEQ', 'ACK')}
                parsed.update(SRC=fields['SRC'], DST=fields['DST'])
            except (KeyError, ValueError):
                parsed = None
        report.update(spec=self.spec, kernel_log=lines[:16], kernel_packet=parsed, log_rc=result.returncode,
                      restoration=restoration, observation_point='master host ' + self.spec['chain'],
                      switch_sides_observed=False, iptables_version=iptables_version)
        report['exact'] = bool(report['exact'] and len(logs) == 1 and logs[0]['pkts'] == 1 and
                               logs[0]['bytes'] == self.spec['ip_len'] and result.returncode == 0 and parsed)
        if self.identity:
            key, value = self.armed or (self.spec['match'], None)
            report['identity'] = dict(armed=self.armed is not None, key=key, value=value,
                                      master_isn=self.target.master_isn, relay_isn=self.target.relay_isn,
                                      operation=self.spec['operation'], index=self.spec['index'], error=self.arm_error,
                                      arm_ns=self.arm_ns)
            report['exact'] = bool(report['exact'] and self.armed is not None)
        return report


def target_checks(report, wire, master_port):
    failures = []
    if not report.get('exact') or not report.get('restoration', {}).get('restored'):
        failures.append('physical loss counter/log/restoration proof missing or failed')
    spec, packet = report.get('spec') or {}, report.get('kernel_packet') or {}
    matching = [row for row in wire.get('exchanges', []) if row['operation'] == spec.get('operation')]
    try:
        row = matching[spec['index']]
        frontier = spec['frontier']
        wanted = row['request'] if frontier in ('request', 'request_ack') else row['response']
        key = 'ACK' if frontier.endswith('_ack') else 'SEQ'
        value = wanted['sequence_end'] if key == 'ACK' else wanted['sequence_start']
        source, destination = (MASTER_IP, RELAY_IP) if spec['dir'] == 'M>O' else (RELAY_IP, MASTER_IP)
        sport, dport = (master_port, RELAY_PORT) if spec['dir'] == 'M>O' else (RELAY_PORT, master_port)
        if packet.get(key) != value or packet.get('SRC') != source or packet.get('DST') != destination or \
                packet.get('LEN') != spec['ip_len'] or packet.get('SPT') != sport or packet.get('DPT') != dport:
            failures.append('logged dropped packet differs from the intended transaction TCP frontier')
        if spec.get('target') == IDENTITY:
            identity = report.get('identity') or {}
            if not identity.get('armed') or identity.get('key') != key or packet.get(key) != identity.get('value'):
                failures.append('identity rule was not armed at the logged packet\'s TCP frontier')
    except (KeyError, IndexError, TypeError):
        failures.append('intended physical loss transaction missing or incomplete')
    return failures


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Read-only physical firewall restoration observation')
    parser.add_argument('--snapshot', action='store_true', required=True)
    parser.parse_args()
    print(json.dumps(dict(chains=firewall_snapshot(),
                          pending_owner=(Path(__file__).resolve().parent / 'relay_loss_state.json').exists())))

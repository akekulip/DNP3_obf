"""Physical SEL-751 loss selectors and recoverable ownership of exact host firewall rules."""
import hashlib
import json
from pathlib import Path
import re
import subprocess

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
    match = re.fullmatch(r'([a-z0-9_]+):([1-9][0-9]?)', text)
    if not match:
        raise ValueError('physical loss requires a known CLASS:N with N in 1..99')
    name, n = match.group(1), int(match.group(2))
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
    return dict(text=text, schedule=schedule, padding=padding, **{'class': name}, n=n,
                dir=direction, ip_len=52 + payload, flags=flags, occurrence=n + offset,
                chain='INPUT' if direction == 'O>M' else 'OUTPUT', base=name,
                operation=operation, index=index, frontier=frontier, length_only=False)


def owned_rule(spec, port, label, run=sh):
    if type(port) is not int or not 1024 <= port <= 65535 or not re.fullmatch(r'[A-Za-z0-9_]+', label):
        raise ValueError('invalid physical loss ownership identity')
    if spec != parse_drop(spec['text'], spec['schedule'], spec['padding']):
        raise ValueError('physical loss specification changed')
    prefix = 'D4R' + hashlib.sha256((label + str(port) + spec['text']).encode()).hexdigest()[:16]
    rule = loss.LossRule(lambda _ns, *args: run(list(args)), spec, MASTER_IP, RELAY_IP, port, RELAY_PORT,
                         chain=spec['chain'], log_prefix=prefix)
    return rule, prefix


def restore_owned(path, run=sh):
    path = Path(path)
    if not path.exists():
        return dict(applied=False, errors=[], restored=True)
    errors = []
    try:
        state = json.loads(path.read_text())
        rule, prefix = owned_rule(state['spec'], state['port'], state['label'], run=run)
        if prefix != state['prefix'] or not isinstance(state['before'], list):
            raise ValueError('physical loss ownership/baseline mismatch')
        for arguments in rule.rules:
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
    def __init__(self, spec, port, label, state_path, run=sh):
        self.spec, self.port, self.label, self.state_path, self.run = spec, port, label, Path(state_path), run
        self.rule, self.prefix = owned_rule(spec, port, label, run=run)

    def install(self):
        if self.state_path.exists():
            raise RuntimeError('pending physical loss ownership exists; restore before traffic')
        before = self.rule._chain()
        if before is None:
            raise RuntimeError('physical host firewall baseline unavailable')
        if any(self.rule._ipt('-C', self.rule.chain, *arguments).returncode != 1 for arguments in self.rule.rules):
            raise RuntimeError('physical loss rules already exist or cannot be checked')
        with self.state_path.open('x') as stream:
            json.dump(dict(spec=self.spec, port=self.port, label=self.label, prefix=self.prefix, before=before), stream)
        self.rule.install()
        return self

    def finish(self):
        self.rule.finish()
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
                      switch_sides_observed=False)
        report['exact'] = bool(report['exact'] and len(logs) == 1 and logs[0]['pkts'] == 1 and
                               logs[0]['bytes'] == self.spec['ip_len'] and result.returncode == 0 and parsed)
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

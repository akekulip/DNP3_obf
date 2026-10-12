"""Deterministic one-packet loss for the VEPA rig: packet classes, iptables rule construction, and the rule's
lifecycle. Stdlib only; runs on Vision (imported by vision_run.py under `sudo python3`) and on the workstation.

A class selects exactly one kind of packet by direction, IP total length and TCP flags, computed from the real
wire shapes (no TCP options: the namespace profile turns timestamps/SACK/window scaling off):

  M>O  READ request       20 B DNP3 payload -> IP length 60, flags ACK,PSH
  M>O  SELECT/OPERATE req 35 B payload      -> IP length 75   (1st = SELECT, 2nd = OPERATE)
  O>M  native responses   49 B / 37 B       -> IP length 89 / 77
  O>M  PADDED responses   58 B (READ and SELECT/OPERATE alike) -> IP length 98 (READs first, then SELECT, OPERATE)
  either direction pure ACK                 -> IP length 40, flags ACK only (the handshake ACK is master pure ACK #1)

`--drop CLASS[:N]` drops the Nth (1-based) packet of the class on a connection, at the INGRESS (INPUT chain) of the
receiving namespace: M>O classes in the outstation's namespace, O>M classes in the master's. The frame has then
already crossed the switch (and been padded/held by it), exactly "a returned frame lost before the endpoint".

How exactness is obtained. The N-1 packets before the target are passed by N-1 rules and the target by one more:
rule k (k < N) = class match + `-m limit --limit 1/hour --limit-burst 1` -> ACCEPT, rule N = the same match -> DROP.
A burst-1 limit rule matches exactly once (its single token refills in an hour), and the kernel takes the token
atomically per packet, so rule k consumes the k-th matching packet and the N-th hits the DROP rule: no polling, no
delete race, nothing to slip between a counter read and a rule deletion. Burst 1 on every rule (rather than one rule
with burst N-1) also keeps the credit arithmetic of xt_limit far from its 32-bit overflow. Counters are then read
back (`iptables -L -v -n -x`): the DROP rule must show exactly 1 packet of exactly the class's IP length and the
ACCEPT rules N-1 packets in total. That proves the rules fired, not WHICH packet it was in the capture; see
identify() for that. Rules are removed in a finally block and the chain is compared with its state before.
"""
import re

NS_M, NS_O = 'ns_vepa_a', 'ns_vepa_b'
MAX_N = 100                    # occurrence cap (one rule per earlier packet)
MAX_OCCURRENCE = 200
LIMIT = ['-m', 'limit', '--limit', '1/hour', '--limit-burst', '1']
FLAGS_MASK = 'SYN,RST,ACK,FIN,PSH'

CLASSES = {
    'request': {'dir': 'M>O', 'ip_len': 60, 'flags': 'ACK,PSH', 'what': 'READ request, 20 B payload'},
    'control_req': {'dir': 'M>O', 'ip_len': 75, 'flags': 'ACK,PSH', 'what': 'SELECT (1st) / OPERATE (2nd) request, 35 B'},
    'master_ack': {'dir': 'M>O', 'ip_len': 40, 'flags': 'ACK', 'what': 'master pure ACK (#1 is the handshake ACK)'},
    'ack_sep': {'dir': 'O>M', 'ip_len': 40, 'flags': 'ACK', 'what': 'outstation pure ACK (the separate ACK of a request)'},
    'read_resp_native': {'dir': 'O>M', 'ip_len': 89, 'flags': 'ACK,PSH', 'what': 'native READ response, 49 B'},
    'control_resp_native': {'dir': 'O>M', 'ip_len': 77, 'flags': 'ACK,PSH', 'what': 'native SELECT/OPERATE response, 37 B'},
    'resp_padded': {'dir': 'O>M', 'ip_len': 98, 'flags': 'ACK,PSH', 'what': 'padded response as returned by the switch, 58 B'},
}
# alias -> (base class, occurrence offset given the READ count): the position of the packet inside the base class
ALIASES = {
    'read_resp_padded': ('resp_padded', lambda reads: 0),
    'select_resp_padded': ('resp_padded', lambda reads: reads),
    'operate_resp_padded': ('resp_padded', lambda reads: reads + 1),
    'select_resp_native': ('control_resp_native', lambda reads: 0),
    'operate_resp_native': ('control_resp_native', lambda reads: 1),
    'select_req': ('control_req', lambda reads: 0),
    'operate_req': ('control_req', lambda reads: 1),
    'master_ack_of_padded': ('master_ack', lambda reads: 1),
}


def names():
    return sorted(set(CLASSES) | set(ALIASES))


def receiver_ns(direction):
    return NS_O if direction == 'M>O' else NS_M


def parse_drop(text, reads):
    """'CLASS[:N]' -> spec dict {class, n, base, occurrence, ip_len, dir, flags}; ValueError when malformed."""
    parts = str(text).split(':')
    if len(parts) > 2 or not parts[0]:
        raise ValueError('--drop wants CLASS[:N], got %r' % text)
    name = parts[0]
    n = 1
    if len(parts) == 2:
        if not parts[1].isdigit():
            raise ValueError('--drop %s: N must be a positive integer' % text)
        n = int(parts[1])
    if name not in CLASSES and name not in ALIASES:
        raise ValueError('unknown loss class %r; classes: %s' % (name, ', '.join(names())))
    if not 1 <= n <= MAX_N:
        raise ValueError('--drop %s: N must be 1..%d' % (text, MAX_N))
    base, off = (name, 0) if name in CLASSES else (ALIASES[name][0], ALIASES[name][1](reads))
    spec = dict(CLASSES[base], **{'class': name, 'n': n, 'base': base, 'occurrence': n + off})
    if spec['occurrence'] > MAX_OCCURRENCE:
        raise ValueError('--drop %s: occurrence %d beyond %d' % (text, spec['occurrence'], MAX_OCCURRENCE))
    return spec


def build_rules(spec, ip_m, ip_o, master_port, outstation_port):
    """(namespace, [rule argument lists]): occurrence-1 ACCEPT rules then one DROP rule, all burst-1 limit matches."""
    if spec['dir'] == 'M>O':
        src, dst, sport, dport = ip_m, ip_o, master_port, outstation_port
    else:
        src, dst, sport, dport = ip_o, ip_m, outstation_port, master_port
    match = ['-p', 'tcp', '-s', src, '-d', dst, '--sport', str(sport), '--dport', str(dport),
             '-m', 'length', '--length', str(spec['ip_len']), '--tcp-flags', FLAGS_MASK, spec['flags']] + LIMIT
    rules = [match + ['-j', 'ACCEPT'] for _ in range(spec['occurrence'] - 1)] + [match + ['-j', 'DROP']]
    return receiver_ns(spec['dir']), rules


_LINE = re.compile(r'^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\w+)\s')


class LossRule:
    """Installs the rules of one drop in the receiving namespace and always takes them out again.

    nsx(ns, *cmd) must behave like `ip netns exec ns cmd...` (returncode/stdout/stderr)."""
    MODE = 'limit-burst-1 chain (kernel-atomic)'

    def __init__(self, nsx, spec, ip_m, ip_o, master_port, outstation_port):
        self.nsx, self.spec = nsx, spec
        self.ns, self.rules = build_rules(spec, ip_m, ip_o, master_port, outstation_port)
        self.installed, self.finished = [], False
        self.state_before = self.state_after = None
        self.remove_errors, self.removed = [], False
        self.counter_list, self.counter_error = [], None

    def _ipt(self, *args):
        return self.nsx(self.ns, 'iptables', '-w', *args)

    def _chain(self):
        r = self._ipt('-S', 'INPUT')
        return [l.strip() for l in r.stdout.splitlines() if l.strip()] if r.returncode == 0 else None

    def install(self):
        self.state_before = self._chain()
        try:
            for i, rule in enumerate(self.rules, 1):
                r = self._ipt('-I', 'INPUT', str(i), *rule)
                if r.returncode:
                    raise RuntimeError('iptables insert %d/%d failed in %s: %s' % (i, len(self.rules), self.ns,
                                                                                   (r.stderr or '').strip()))
                self.installed.append(rule)
        except RuntimeError:
            self.remove()                       # roll back whatever went in before reporting the failure
            raise
        return self

    def counters(self):
        r = self._ipt('-L', 'INPUT', '-v', '-n', '-x', '--line-numbers')
        if r.returncode:
            raise RuntimeError('iptables -L failed in %s: %s' % (self.ns, (r.stderr or '').strip()))
        out = []
        for line in r.stdout.splitlines():
            m = _LINE.match(line)
            if m:
                out.append({'pos': int(m.group(1)), 'target': m.group(4), 'pkts': int(m.group(2)),
                            'bytes': int(m.group(3))})
        return out

    def finish(self):
        """Read the counters once, after the traffic. A failed read is recorded, never raised."""
        try:
            self.counter_list = self.counters()
        except RuntimeError as e:
            self.counter_list, self.counter_error = [], str(e)
        self.finished = True

    def remove(self):
        for rule in self.installed:
            r = self._ipt('-D', 'INPUT', *rule)
            if r.returncode:
                self.remove_errors.append('delete failed: %s' % (r.stderr or '').strip())
        self.installed = []
        self.state_after = self._chain()
        self.removed = not self.remove_errors

    def __enter__(self):
        return self.install()

    def __exit__(self, *exc):
        if not self.finished:
            self.finish()
        self.remove()
        return False

    def record(self):
        drop = next((c for c in self.counter_list if c['target'] == 'DROP'), None)
        accepts = [c for c in self.counter_list if c['target'] == 'ACCEPT']
        earlier = sum(c['pkts'] for c in accepts)
        s = self.spec
        exact = bool(drop and drop['pkts'] == 1 and drop['bytes'] == s['ip_len'] and
                     len(accepts) == s['occurrence'] - 1 and earlier == s['occurrence'] - 1 and
                     all(c['pkts'] == 1 for c in accepts))
        return {'class': s['class'], 'n': s['n'], 'occurrence': s['occurrence'], 'base': s['base'],
                'dir': s['dir'], 'ip_len': s['ip_len'], 'flags': s['flags'], 'ns': self.ns, 'chain': 'INPUT',
                'mode': self.MODE, 'rules': [' '.join(r) for r in self.rules], 'counters': self.counter_list,
                'counter_error': self.counter_error,
                'dropped_packets': drop['pkts'] if drop else None, 'dropped_bytes': drop['bytes'] if drop else None,
                'earlier_matches': earlier, 'exact': exact, 'removed': self.removed,
                'remove_errors': self.remove_errors, 'state_before': self.state_before,
                'state_after': self.state_after,
                'state_restored': self.state_before is not None and self.state_before == self.state_after}

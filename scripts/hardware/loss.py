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
ACCEPT rules N-1 packets in total. That proves the rules fired, not WHICH packet it was in the capture. Rules are
removed in a finally block and the chain is compared with its state before.
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
    # Single-frame READ-response drop selectors. Each picks a packet by IP length, flags and occurrence only, so it
    # is LENGTH-LEVEL and makes NO per-class claim: it cannot tell apart READ classes delivered at the same on-wire
    # length. read_resp_247 targets "a 247-byte READ response" -- on the base fixture class0 and integrity are BOTH
    # 247 B (IP 287) and rotate4 interleaves them, so one selector covers both without naming the class.
    # read_resp_analog likewise targets "a 141-byte READ response" (IP 181): 141 is base analog's native length AND
    # the image a range READ is padded to, so in a MIXED (rotate4) schedule a 141-byte drop may be a padded range
    # response, not analog -- the selector claims only the length, never "analog" (the record marks it length_only).
    # A per-class read_resp_class0 / read_resp_integrity drop would mis-stamp the class and is not offered. Class-
    # SPECIFIC recovery for a single-frame class needs a single-class workload (candidate_series series_read_class),
    # where that class is the only READ on the wire so its response length is unambiguous. The natively segmented
    # large-DB class0/integrity (two frames) have no single-length selector at all.
    'read_resp_analog': {'dir': 'O>M', 'ip_len': 40 + 141, 'flags': 'ACK,PSH', 'what': 'a 141 B single-frame READ response (base analog or a range READ padded to 141; not distinguished)'},
    'read_resp_247': {'dir': 'O>M', 'ip_len': 40 + 247, 'flags': 'ACK,PSH', 'what': 'a 247 B single-frame READ response (base class0 or integrity; not distinguished)'},
    # Two-READ-target profile (m12p_c23+). Native arms: the mixed READ's 91 B single-frame response (the full READ's
    # native is read_resp_247). Padded arms: each READ leaves as a padded IMAGE -- two link frames in ONE TCP segment
    # (141 = [50, 91], 271 = [24, 247]) -- so these selectors name the image length, not a single frame. Every one is
    # length-level (LENGTH_ONLY). Within this profile's mixed_full workload the four READ lengths (91/247 native,
    # 141/271 padded) and the SBO lengths (37/61) do not collide, so a drop at one of them is the one workload READ
    # of that length; the selector still claims only the length, and a class claim rests on the workload declaration.
    'read_resp_91': {'dir': 'O>M', 'ip_len': 40 + 91, 'flags': 'ACK,PSH', 'what': 'a 91 B single-frame READ response (two-READ profile: the native mixed READ)'},
    'read_resp_padded_141': {'dir': 'O>M', 'ip_len': 40 + 141, 'flags': 'ACK,PSH', 'what': 'a 141 B padded READ image in one TCP segment (two-READ profile: link frames [50, 91])'},
    'read_resp_padded_271': {'dir': 'O>M', 'ip_len': 40 + 271, 'flags': 'ACK,PSH', 'what': 'a 271 B padded READ image in one TCP segment (two-READ profile: link frames [24, 247])'},
    # Two-READ profile requests (the range `request` above is 20 B): measured from the M1 live capture
    # (read_complete_01/vectors/two_read_templates.json, request_len). Used with a single-class workload (schedule
    # mixed or full), where the request of that length is the only READ request on the connection.
    'request_mixed': {'dir': 'M>O', 'ip_len': 40 + 25, 'flags': 'ACK,PSH', 'what': 'mixed READ request (g1v2 0-15 + g30v1 0-7), 25 B payload'},
    'request_full': {'dir': 'M>O', 'ip_len': 40 + 27, 'flags': 'ACK,PSH', 'what': 'full/integrity READ request (class 0-3), 27 B payload'},
}
# Single-frame READ-response drop selector -> the response link-octet length it targets. One selector per length:
# the selector is length-unique and makes no per-class claim. A campaign that combines a READ-class schedule with
# a loss preset is restricted to these, and only when that length exists as a single link frame on the database.
READ_RESP_LEN = {'read_resp_analog': 141, 'read_resp_247': 247, 'read_resp_91': 91}
# Padded-image selectors (two-READ profile): selector -> the padded image length (TCP payload octets) it targets.
PADDED_READ_LEN = {'read_resp_padded_141': 141, 'read_resp_padded_271': 271}
# The length selectors are length-level: a drop they pick is stamped `length_only` in the spec/record so no reader
# or downstream check reads it as a per-class claim. A class-specific recovery claim comes from a single-class
# workload (candidate_series series_read_class), not from one of these selectors in a mixed schedule.
LENGTH_ONLY = frozenset(READ_RESP_LEN) | frozenset(PADDED_READ_LEN)
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
    'master_ack_of_padded_data': ('master_ack', lambda reads: 1),
}
# Classes marked data_ack in the drop spec: the target is an in-session master pure ACK that newly acknowledges a
# padded data frontier (not the handshake ACK, not the ACK of a FIN); `master_ack_of_padded` selects by occurrence only.
DATA_ACK = {'master_ack_of_padded_data'}
PADDED_LEN = 58
# @LEN / @LEN/READLEN bound. LEN is the padded response's TCP PAYLOAD length -- the aggregate encoded DNP3 octets of
# one solicited response carried in one TCP segment (e.g. 271 = link frames [24, 247]) -- and the selector matches
# ONE IP packet of total length 40 + LEN. Its bound is therefore the IP/TCP packet capacity (Ethernet MTU 1500 - 20
# IP - 20 TCP = 1460), NOT the user-octet capacity of one DNP3 link frame (<= 250 user octets, <= 292 encoded): the
# earlier upper bound 249 conflated the two and rejected the 271-octet aggregate. Per-frame limits are not checked
# here; they stay with the DNP3 frame checks (wire_check / dnp3_std deframe), which verify every link frame and CRC.
MIN_PAYLOAD_LEN, MAX_PAYLOAD_LEN = 50, 1460


def names():
    return sorted(set(CLASSES) | set(ALIASES))


def receiver_ns(direction):
    return NS_O if direction == 'M>O' else NS_M


def parse_drop(text, reads):
    """'CLASS[:N][@LEN]' -> spec dict {class, n, base, occurrence, ip_len, dir, flags, padded_len}; ValueError when
    malformed. @LEN declares the build's padded response length (default 58): the padded class then matches IP length
    40 + LEN and the data-ACK gate looks for a LEN-octet frontier. It travels inside the drop string so Vision's
    vision_run.py --drop needs no extra flag."""
    text, _, plen = str(text).partition('@')
    padded_len, read_len = PADDED_LEN, None
    if plen:
        # @LEN, or @LEN/READLEN on a build whose padded READ length differs from the control length
        # (read_complete_01 policy: @61/141): the SELECT/OPERATE padded responses are then the only packets of
        # IP length 40+LEN, so their aliases count from the first of them, not after the READs.
        plen, slash, rlen = plen.partition('/')
        if slash and not rlen:
            raise ValueError('--drop %s@%s/: READLEN missing after /' % (text, plen))
        for value in (plen, rlen) if rlen else (plen,):
            if not value.isdigit() or not MIN_PAYLOAD_LEN <= int(value) <= MAX_PAYLOAD_LEN:
                raise ValueError('--drop %s@%s: LEN must be an integer %d..%d (the response TCP payload octets)'
                                 % (text, value, MIN_PAYLOAD_LEN, MAX_PAYLOAD_LEN))
        padded_len = int(plen)
        read_len = int(rlen) if rlen else None
    parts = text.split(':')
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
    if read_len is not None and read_len != padded_len and name in ('select_resp_padded', 'operate_resp_padded'):
        off -= reads
    spec = dict(CLASSES[base], **{'class': name, 'n': n, 'base': base, 'occurrence': n + off,
                                  'data_ack': name in DATA_ACK, 'padded_len': padded_len,
                                  'length_only': name in LENGTH_ONLY})
    if base == 'resp_padded':
        spec['ip_len'] = 40 + padded_len
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

    def __init__(self, nsx, spec, ip_m, ip_o, master_port, outstation_port, chain='INPUT', log_prefix=None):
        self.nsx, self.spec = nsx, spec
        self.ns, self.rules = build_rules(spec, ip_m, ip_o, master_port, outstation_port)
        self.chain = chain
        if chain not in ('INPUT', 'OUTPUT'):
            raise ValueError('loss chain must be INPUT or OUTPUT')
        if log_prefix is not None:
            if not re.fullmatch(r'D4R[0-9a-f]{16}', log_prefix):
                raise ValueError('invalid owned relay loss log identity')
            self.rules.insert(-1, self.rules[-1][:-2] + ['-j', 'LOG', '--log-prefix', log_prefix + ' ',
                                                       '--log-tcp-sequence'])
        self.installed, self.finished = [], False
        self.state_before = self.state_after = None
        self.remove_errors, self.removed = [], False
        self.counter_list, self.counter_error = [], None

    def _ipt(self, *args):
        return self.nsx(self.ns, 'iptables', '-w', *args)

    def _chain(self):
        r = self._ipt('-S', self.chain)
        return [l.strip() for l in r.stdout.splitlines() if l.strip()] if r.returncode == 0 else None

    def install(self):
        self.state_before = self._chain()
        try:
            for i, rule in enumerate(self.rules, 1):
                r = self._ipt('-I', self.chain, str(i), *rule)
                if r.returncode:
                    raise RuntimeError('iptables insert %d/%d failed in %s: %s' % (i, len(self.rules), self.ns,
                                                                                   (r.stderr or '').strip()))
                self.installed.append(rule)
        except RuntimeError:
            self.remove()                       # roll back whatever went in before reporting the failure
            raise
        return self

    def counters(self):
        r = self._ipt('-L', self.chain, '-v', '-n', '-x', '--line-numbers')
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
            r = self._ipt('-D', self.chain, *rule)
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
        owned = [c for c in self.counter_list if c['pos'] <= len(self.rules)]
        drop = next((c for c in owned if c['target'] == 'DROP'), None)
        accepts = [c for c in owned if c['target'] == 'ACCEPT']
        earlier = sum(c['pkts'] for c in accepts)
        s = self.spec
        exact = bool(drop and drop['pkts'] == 1 and drop['bytes'] == s['ip_len'] and
                     len(accepts) == s['occurrence'] - 1 and earlier == s['occurrence'] - 1 and
                     all(c['pkts'] == 1 for c in accepts))
        return {'class': s['class'], 'n': s['n'], 'occurrence': s['occurrence'], 'base': s['base'],
                'dir': s['dir'], 'ip_len': s['ip_len'], 'flags': s['flags'], 'length_only': s.get('length_only', False),
                'ns': self.ns, 'chain': self.chain,
                'mode': self.MODE, 'rules': [' '.join(r) for r in self.rules], 'counters': self.counter_list,
                'counter_error': self.counter_error,
                'dropped_packets': drop['pkts'] if drop else None, 'dropped_bytes': drop['bytes'] if drop else None,
                'earlier_matches': earlier, 'exact': exact, 'removed': self.removed,
                'remove_errors': self.remove_errors, 'state_before': self.state_before,
                'state_after': self.state_after,
                'state_restored': self.state_before is not None and self.state_before == self.state_after}

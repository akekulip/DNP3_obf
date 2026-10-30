"""The master-ACK rule of results/analysis/ack_behaviour/DESIGN.json as pure functions (no model access).

A probe and the master segments it is compared with are dicts in the master's own coordinates as sent on dev9:
order (master send order), seq, ack (wire), window (16-bit field), tsval, payload_len, options (option kinds)."""
import struct

import model_connection_start as cs

RULE = {
    'obsolete': ('A pure master ACK is obsolete only if a later forwarded master segment already carries everything it '
                 'carries: a sequence at or beyond, an acknowledgment at or beyond, the same advertised window, and no '
                 'newer timestamp or supported option.'),
    'suppression': 'An obsolete ACK may be suppressed, but only with connection and transaction state unchanged.',
    'valid': 'Any ACK carrying new acknowledgment or window information is valid and must reach the relay.'}
OUTCOMES = ('meets the rule', 'meets the rule by suppressing an obsolete ACK', 'violates the rule')
STATE_KEYS = ('owner', 'client', 'server', 'epoch', 'application_state', 'retry_epoch', 'work_phase')
M32 = 0xffffffff
OPTION_NAMES = {8: 'ts', 2: 'mss', 3: 'wscale', 4: 'sackok', 5: 'sack'}


def seq_ge(a, b):
    """a at or beyond b in 32-bit serial arithmetic."""
    return ((a - b) & M32) < 0x80000000


def covers(later, probe):
    """The registered 'covers' relation: later already carries everything the probe carries."""
    ts_ok = probe.get('tsval') is None or (later.get('tsval') is not None and seq_ge(later['tsval'], probe['tsval']))
    return (later['order'] > probe['order']
            and seq_ge(later['seq'], (probe['seq'] + probe.get('payload_len', 0)) & M32)
            and seq_ge(later['ack'], probe['ack'])
            and later['window'] == probe['window']
            and ts_ok
            and set(probe.get('options') or ()) <= set(later.get('options') or ()))


def obsolete(probe, forwarded_before):
    return any(covers(segment, probe) for segment in forwarded_before)


def covering(probe, forwarded_before):
    return [segment.get('name') for segment in forwarded_before if covers(segment, probe)]


def new_information(probe, forwarded_before):
    """forwarded_before in arrival order at the relay."""
    if not forwarded_before:
        return dict(new_ack=True, new_window=True)
    highest = forwarded_before[0]['ack']
    for segment in forwarded_before[1:]:
        if not seq_ge(highest, segment['ack']):
            highest = segment['ack']
    return dict(new_ack=not seq_ge(highest, probe['ack']), new_window=probe['window'] != forwarded_before[-1]['window'])


def state_unchanged(before, after):
    """N connection and transaction state; the generation counters are deliberately not compared."""
    return before.get('owner') is not None and all(before.get(k) == after.get(k) for k in STATE_KEYS)


def classify(forwarded, is_obsolete, unchanged):
    if forwarded:
        return OUTCOMES[0]
    if is_obsolete and unchanged:
        return OUTCOMES[1]
    return OUTCOMES[2]


def relay_replies(forwarded, seq, rcv_nxt):
    """RFC 9293: the relay answers an unacceptable segment (SEG.SEQ before RCV.NXT) with an ACK."""
    return bool(forwarded) and not seq_ge(seq, rcv_nxt)


def tcp_fields(frame):
    """Direction, seq, ack, flags, payload length, window, TSval/TSecr and option kinds of a master/relay frame."""
    ip = 14
    ihl = (frame[ip] & 15) * 4
    total = struct.unpack('!H', frame[ip + 2:ip + 4])[0]
    tcp = ip + ihl
    offset = (frame[tcp + 12] >> 4) * 4
    seg, _at = cs.segment(frame)
    out = dict(direction=seg['direction'] if seg else None, seq=struct.unpack('!I', frame[tcp + 4:tcp + 8])[0],
               ack=struct.unpack('!I', frame[tcp + 8:tcp + 12])[0], flags=frame[tcp + 13],
               payload_len=total - ihl - offset, window=struct.unpack('!H', frame[tcp + 14:tcp + 16])[0],
               tsval=None, tsecr=None, options=[])
    at, end = tcp + 20, tcp + offset
    while at < end:
        kind = frame[at]
        if kind == 0:
            break
        if kind == 1:
            at += 1
            continue
        length = frame[at + 1]
        if length < 2:
            break
        out['options'].append(OPTION_NAMES.get(kind, 'k%d' % kind))
        if kind == 8 and length == 10:
            out['tsval'], out['tsecr'] = struct.unpack('!II', frame[at + 2:at + 10])
        at += length
    return out


def _checksum(data):
    if len(data) % 2:
        data += b'\0'
    total = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def with_window(frame, window):
    """The frame with its TCP window field set and the TCP checksum recomputed (as model_rearm's window probes)."""
    out = bytearray(frame)
    ihl = (out[14] & 15) * 4
    tcp = 14 + ihl
    end = 14 + struct.unpack('!H', out[16:18])[0]
    out[tcp + 14:tcp + 16] = struct.pack('!H', window)
    out[tcp + 16:tcp + 18] = b'\0\0'
    pseudo = bytes(out[26:34]) + struct.pack('!BBH', 0, 6, end - tcp)
    out[tcp + 16:tcp + 18] = struct.pack('!H', _checksum(pseudo + bytes(out[tcp:end])))
    return bytes(out)


def claimed_before(passes, first, second):
    """True when first's successful stage-0 claim (cell free, phase 4) precedes second's in the log; True when only
    first claimed, False when only second did, None when neither did."""
    def index(want):
        for i, record in enumerate(passes):
            if cs.matches(record['segment'], want):
                value = cs.salu(record, 'claim_work')
                if value is not None and cs.decode_work(value[0])['phase'] == 4:
                    return i
        return None
    a, b = index(first), index(second)
    if a is None and b is None:
        return None
    if b is None:
        return True
    if a is None:
        return False
    return a < b

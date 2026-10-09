"""Local Tofino-1 model run of case4_response_path.p4 (padder + mapper, one egress pass), in lockstep
with the software model.

Functional model execution only: not hardware, not timing.

  integration/core/launch_model.sh -p <build>/out -o <build>/model_NN -P "1 2" -d protocol/model_drive_response_path.py

Port 1 is the outstation side, port 2 the master side; both are pipe 0, and the entries are installed
through response_path_cp, which refuses a cross-pipe connection. Every packet goes first to the
software model (framework/size/case4_response_mapper.py, tested against the case4_transport oracle),
with the padder verdict taken from the pad58b codec on the payload's leading frame -- including CRC
checks, for every flag combination. The model says what must leave the switch byte for byte: the
padded image (pad58b codec) plus any native suffix when it says pad, the native bytes otherwise, with
IPv4 and TCP checksums recomputed in full here. It also names the one outcome counter the P4 must bump.

Asserted by name: exactly one commit per original response; every retransmission of a committed
response -- including merged ones and one carrying FIN -- leaves as the same image at the same wire
position; partial ACKs inside an image never strand its tail; the padder pads only on commit/replay
(never on a refused, CRC-invalid, native-mode or unconfigured flow); CRC-invalid frames are never
committed and a CRC-invalid replay is dropped.
"""
import os
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CASE4 = HERE.parent
sys.path[:0] = [str(HERE), str(CASE4 / 'integration' / 'core'), str(CASE4.parent / 'framework' / 'size')]
from model_driver import Model, Report, same_frame, gc  # noqa: E402
import case4_pad58b as b  # noqa: E402
import case4_padding as pad  # noqa: E402
import case4_response_mapper as rm  # noqa: E402
import response_path_cp as cp  # noqa: E402

OUTST, MASTER = 1, 2
ETH = bytes.fromhex('0a0000000002' '0a0000000001') + b'\x08\x00'
O_IP, M_IP = bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2])
O_PORT = 20000
LINK_HEAD = bytes.fromhex('056419c40a000100')
CTL_POINTS = [b.AnalogFloatPoint(301, 10.0, 0), b.AnalogFloatPoint(302, 20.0, 0)]
MSS = b'\x02\x04\x05\xb4'
MSS_WSCALE = MSS + b'\x01\x03\x03\x07'
TIMESTAMPS = b'\x01\x01\x08\x0a' + b'\x00\x00\x00\x01' + b'\x00\x00\x00\x02'
CODES = {'commit': 1, 'translate': 2, 'zero': 3, 'replay': 4, 'stale': 5, 'drop_overlap': 6,
         'drop_ahead': 7, 'drop_unsupported': 8, 'rev_translate': 9, 'withhold': 10,
         'drop_stale': 11, 'passthrough': 12, 'arm_map': 13, 'arm_nat': 14, 'drop_merged': 15}
MASK = 0xffffffff


def csum(data):
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def packet(src, dst, sport, dport, seq, ack, flags, window, payload=b'', options=b''):
    off = (20 + len(options)) // 4
    tcp = struct.pack('!HHIIBBHHH', sport, dport, seq & MASK, ack & MASK, off << 4, flags, window, 0, 0) + options
    pseudo = src + dst + struct.pack('!BBH', 0, 6, len(tcp) + len(payload))
    tcp = tcp[:16] + struct.pack('!H', csum(pseudo + tcp + payload)) + tcp[18:]
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(payload), 0x1234, 0x4000, 64, 6, 0, src, dst)
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    return ETH + ip + tcp + payload


def read_frame(n):
    data = bytes((n * 7 + i) & 0xff for i in range(23))
    return pad.build_frame(LINK_HEAD, bytes([0xc0 | (n & 15), 0xc0 | (n & 15), 0x81, 0x80, 0]) + b.HEADER_READ23 + data)


def control_frame(n):
    return pad.build_frame(LINK_HEAD, bytes([0xc0 | (n & 15), 0xc0 | (n & 15), 0x81, 0, 0]) + b.HEADER_CROB28 +
                           bytes([0x05, 0x00, 0x03, 0x01, 0x64, 0, 0, 0, 0x64, 0, 0, 0, 0x00]))


def padder(payload):
    image, delta = b.pad_read_response(payload)
    if delta:
        return delta, image
    image, delta = b.pad_control_response(payload, CTL_POINTS)
    return delta, image


def leading(payload):
    """(delta, image, frame_len) for a complete, CRC-valid eligible frame at the payload start."""
    if len(payload) >= 10 and payload[:2] == b'\x05\x64' and payload[2] >= 5:
        n = payload[2] - 5
        flen = 10 + n + 2 * ((n + 15) // 16)
        if len(payload) >= flen:
            delta, image = padder(payload[:flen])
            if delta:
                return delta, image, flen
    return 0, None, 0


m = Model(ports=[OUTST, MASTER])
rep = Report(os.environ['PROG'], physical=False, scope='fused padder+mapper egress; real CRC verdict; padded images on the wire')
rep.add('ports_enabled', {}, m.port_errors, ok=not m.port_errors)
m.add('Ingress.forwarding', {'ig.ingress_port': OUTST}, 'Ingress.route', {'port': MASTER})
m.add('Ingress.forwarding', {'ig.ingress_port': MASTER}, 'Ingress.route', {'port': OUTST})
counter = m.table('Egress.outcome')


def counts():
    for op in ('Sync', 'SyncCounters'):
        try:
            counter.operations_execute(m.target, op)
            break
        except Exception:
            pass
    out = {}
    for code in range(16):
        for data, _k in counter.entry_get(m.target, [counter.make_key([gc.KeyTuple('$COUNTER_INDEX', code)])], {'from_hw': True}):
            v = data.to_dict()['$COUNTER_SPEC_PKTS']
            out[code] = sum(v) if isinstance(v, list) else v
    return out


class Conn:
    """One connection: native outstation, software mapper mirror, simulated master."""

    def __init__(self, slot, mport, isn, mseq):
        self.slot, self.mport, self.isn, self.mseq = slot, mport, isn & MASK, mseq & MASK
        self.sw = rm.ResponseMapper(merged_suffix_ok=False)    # the Tofino-1 profile
        self.snd_nxt = self.snd_una = (isn + 1) & MASK
        self.rcv_nxt = (isn + 1) & MASK          # master, wire space
        self.wire = bytearray()                   # bytes the master holds
        self.wnd = 8192
        self.last = None
        self.segs = []
        self.m_ip = bytes([10, 0, 0, 2 + slot])
        for table, key, action, data in cp.connection_entries(
                slot, cp.Endpoint('10.0.0.1', O_PORT, OUTST), cp.Endpoint('10.0.0.%d' % (2 + slot), mport, MASTER)):
            m.add(table, key, action, data)

    def run(self, name, in_port, sent, expected, code):
        before = counts()
        out_port = MASTER if in_port == OUTST else OUTST
        got = m.exchange(in_port, sent, [OUTST, MASTER], timeout=1.5, quiet=0.3)
        after = counts()
        delta = {c: after[c] - before[c] for c in after if after[c] != before[c]}
        if expected is None:
            ok = not got[OUTST] and not got[MASTER]
        else:
            ok = (len(got[out_port]) == 1 and not got[in_port] and same_frame(got[out_port][0], expected, sent))
        rep.add(name, 'frame' if expected is not None else 'dropped',
                'frame' if (expected is not None and ok) else ('dropped' if not got[out_port] else 'mismatch'),
                ok=ok, sent=sent, want=expected, received=[g.hex() for g in got[out_port]])
        rep.add(name + '_outcome', {code: 1}, delta)
        return ok

    # outstation -> master
    def fwd(self, name, seq, payload, flags=0x18, lose=False, options=b'', supported=True):
        delta, image, flen = leading(payload)     # the padder's real verdict, whatever the flags
        res = self.sw.forward(seq, len(payload), delta, fin=bool(flags & 1), rst=bool(flags & 4), supported=supported)
        wire = image + payload[flen:] if res.pad else payload
        sent = packet(O_IP, self.m_ip, O_PORT, self.mport, seq, self.mseq, flags, 4096, payload, options)
        exp = None if res.dropped else packet(O_IP, self.m_ip, O_PORT, self.mport, res.seq, self.mseq, flags, 4096, wire, options)
        code = CODES['drop_unsupported' if res.case == 'drop_unsupported' else res.case]
        self.run(name, OUTST, sent, exp, code)
        if not res.dropped and not lose:
            self.master_receive(res.seq, wire)
        self.last = res
        return res

    def master_receive(self, wseq, data):
        off = rm.signed(wseq - self.rcv_nxt)
        base = len(self.wire)
        for i, byte in enumerate(data):
            pos = base + off + i
            if 0 <= pos < base and self.wire[pos] != byte:
                rep.add('replayed_byte_identical', True, False)
                return
        if off > 0:
            return
        take = data[-off:][:self.wnd]
        self.wire += take
        self.rcv_nxt = (self.rcv_nxt + len(take)) & MASK

    # master -> outstation
    def rev(self, name, ack=None, window=None, payload=b'', flags=0x10):
        ack = self.rcv_nxt if ack is None else ack & MASK
        window = self.wnd if window is None else window
        res = self.sw.reverse(ack, window)
        sent = packet(self.m_ip, O_IP, self.mport, O_PORT, self.mseq, ack, flags, window, payload)
        exp = None if res.dropped else packet(self.m_ip, O_IP, self.mport, O_PORT, self.mseq, res.ack, flags, res.window, payload)
        code = CODES['rev_translate' if res.case == 'translate' else res.case]
        self.run(name, MASTER, sent, exp, code)
        self.mseq = (self.mseq + len(payload)) & MASK
        if flags & 0x10 and not res.dropped and rm.signed(res.ack - self.snd_una) > 0:
            self.snd_una = res.ack
        return res

    def respond(self, name, frame, lose=False):
        seq = self.snd_nxt
        self.snd_nxt = (seq + len(frame)) & MASK
        self.segs.append((seq, frame))
        return self.fwd(name, seq, frame, lose=lose)

    def retransmit(self, name, merge=False, flags=0x18):
        parts = []
        for seq, data in self.segs:
            if rm.signed(seq + len(data) - self.snd_una) > 0:
                cut = max(0, rm.signed(self.snd_una - seq))
                parts.append(((seq + cut) & MASK, data[cut:]))
        if merge and parts:                       # Linux tcp_retrans_collapse
            parts = [(parts[0][0], b''.join(d for _, d in parts))]
        return [self.fwd(name, s, d, flags=flags) for s, d in parts]


# ---------------------------------------------------------------------------------------- slot 0
c = Conn(0, 40000, 0xffffff80, 7000)        # wraps after the second response
c.rev('master_SYN', ack=0, window=8192, flags=0x02)                       # no ACK: untouched
c.sw.syn_ack(c.isn)
c.run('outstation_SYNACK_mss_only_arms', OUTST,
      packet(O_IP, c.m_ip, O_PORT, 40000, c.isn, 7001, 0x12, 8192, b'', MSS),
      packet(O_IP, c.m_ip, O_PORT, 40000, c.isn, 7001, 0x12, 8192, b'', MSS), CODES['arm_map'])
c.mseq = 7001
c.rev('master_handshake_ACK')

# P1 + P2: repeated READs and a SELECT/OPERATE pair, each with a spurious retransmission.
commits, replays = [], []
for i, frame in enumerate([read_frame(0), read_frame(1), read_frame(2), control_frame(3), control_frame(4), read_frame(5)]):
    c.rev('request_%d' % i, payload=bytes(20), flags=0x18)
    commits.append(c.respond('response_%d' % i, frame))
    replays.extend(c.retransmit('spurious_rto_%d' % i))
rep.add('P1_exactly_once_commits', ['commit'] * 6, [r.case for r in commits])
rep.add('P2_spurious_copies_replay_at_committed_seq', [(r.seq, True) for r in commits], [(r.seq, r.pad) for r in replays])
c.rev('ack_all_1')

# P2: lost image, dup ACK holds it back, retransmission reconstructs it.
c.rev('request_6', payload=bytes(20), flags=0x18)
lost = c.respond('response_6_lost', read_frame(6), lose=True)
c.rev('dup_ack_at_image_start')
again = c.retransmit('rto_after_loss')
rep.add('P2_lost_image_replayed_identically', [(lost.seq, True, 'replay')], [(r.seq, r.pad, r.case) for r in again])
c.rev('ack_after_replay')

# P3: partial ACK inside the native part (READ, 30 bytes) and inside the inserted tail (CONTROL, 45).
for name, frame, k in (('read_partial_30', read_frame(7), 30), ('control_partial_tail_45', control_frame(8), 45)):
    c.rev('request_' + name, payload=bytes(20), flags=0x18)
    c.wnd = k
    first = c.respond(name, frame)
    held = c.rev(name + '_ack_zero_window', window=0)
    opened = c.rev(name + '_ack_window_65535', window=65535)
    c.wnd = 65535
    again = c.retransmit(name + '_rto')
    done = c.rev(name + '_final_ack')
    rep.add('P3_' + name + '_not_stranded',
            ['withhold', 'withhold', 'replay', 'translate', True],
            [held.case, opened.case] + [r.case for r in again] + [done.case, c.snd_una == c.snd_nxt and
                                                                    len(c.wire) == (c.rcv_nxt - (c.isn + 1)) & MASK])
    c.wnd = 8192

# Refusal: second response before the first image is acknowledged stays native.
c.rev('request_9', payload=bytes(20), flags=0x18)
c.respond('response_9_commit', read_frame(9))
refused = c.respond('response_10_refused', read_frame(10))
rep.add('refused_response_is_native', 'translate', refused.case)
c.rev('ack_both')

# code-review HIGH 1: merged retransmission of a committed image plus a refused response.
c.rev('request_11', payload=bytes(20), flags=0x18)
c.respond('response_11_commit_lost', control_frame(11), lose=True)
c.respond('response_12_refused_lost', read_frame(12), lose=True)
c.rev('dup_ack_before_merge')
merged = c.retransmit('merged_rto', merge=True)
rep.add('merged_retransmission_with_suffix_dropped_and_counted', [('drop_merged', False)], [(r.case, r.pad) for r in merged])
plain = c.retransmit('plain_rto_after_merge')               # a non-collapsing retransmission completes it
rep.add('plain_copies_after_merge_replay_then_translate', ['replay', 'translate'], [r.case for r in plain])
c.rev('ack_after_merge')

# code-review MEDIUM 4: whole-frame retransmission carrying FIN, with the padder's real verdict.
c.rev('request_13', payload=bytes(20), flags=0x18)
c.respond('response_13_commit_lost', read_frame(13), lose=True)
c.rev('dup_ack_before_fin')
fin_copy = c.retransmit('fin_whole_frame_rto', flags=0x19)
rep.add('fin_whole_frame_retransmission_replays', [('replay', True)], [(r.case, r.pad) for r in fin_copy])
c.rev('ack_after_fin_copy')

# CRC rejection with the padder's own verdict: never committed, and a corrupted replay is dropped.
c.rev('request_14', payload=bytes(20), flags=0x18)
bad = bytearray(read_frame(14)); bad[30] ^= 1                      # block-1 data, its CRC now wrong
r = c.respond('crc_invalid_response_native', bytes(bad))
rep.add('crc_invalid_never_committed', ('translate', False), (r.case, r.pad))
c.rev('ack_crc_invalid')
c.rev('request_15', payload=bytes(20), flags=0x18)
good = read_frame(15)
first = c.respond('response_15_commit_lost', good, lose=True)
corrupt = bytearray(good); corrupt[47] ^= 1                        # tail CRC
r = c.fwd('crc_invalid_replay_dropped', c.segs[-1][0], bytes(corrupt))
rep.add('crc_invalid_replay_dropped', 'drop_overlap', r.case)
again = c.retransmit('response_15_rto')
rep.add('good_replay_after_corrupt_copy', [(first.seq, True)], [(x.seq, x.pad) for x in again])
c.rev('ack_after_15')

# code-review MEDIUM 3: a non-SYN segment with a 4-byte option (TCP offset 6) on a mapped connection.
c.fwd('tcp_offset6_on_mapped_drop', c.snd_nxt, bytes(10), options=b'\x01\x01\x01\x01', supported=False)

# Pad gate: an eligible frame on an unconfigured flow leaves untouched (outcome 0, never padded).
stray = packet(O_IP, bytes([10, 0, 0, 99]), O_PORT, 40099, 1234, 5678, 0x18, 4096, read_frame(16))
c.run('unconfigured_flow_eligible_frame_untouched', OUTST, stray, stray, 0)

# Zero-length keepalive, unsupported overlap, ahead, TCP options on a mapped connection, stale ACK, FIN.
c.fwd('keepalive_zero', (c.snd_una - 1) & MASK, b'', flags=0x10)
img_start = c.sw.img_start
c.fwd('overlap_drop', (img_start + 1) & MASK, read_frame(9)[1:11])
c.fwd('ahead_drop', (c.snd_nxt + 100) & MASK, bytes(10))
c.fwd('tcp_options_on_mapped_drop', c.snd_nxt, bytes(10), options=TIMESTAMPS, supported=False)
c.rev('stale_ack_drop', ack=(c.sw.img_wend - 200) & MASK)
c.fwd('fin_translated', c.snd_nxt, b'', flags=0x11)

# Register readback against the software mirror (acct.hi holds U = W - A).
regs = {n: m.register_read('Egress.' + n, 0) for n in ('mode', 'front', 'acct', 'img_end', 'img_start', 'img_wend')}


def reg(name, suffix):
    v = next(v for k, v in regs[name].items() if k.endswith(suffix))
    return v[0] if isinstance(v, list) else v


want = {'mode': c.sw.mode, 'front': c.sw.front, 'acct.lo': c.sw.acct_w, 'acct.hi': (c.sw.acct_w - c.sw.acct_a) & MASK,
        'img_end': c.sw.img_end, 'img_start': c.sw.img_start, 'img_wend': c.sw.img_wend}
try:
    have = {'mode': reg('mode', '.f1'), 'front': reg('front', '.f1'), 'acct.lo': reg('acct', '.lo'),
            'acct.hi': reg('acct', '.hi'), 'img_end': reg('img_end', '.f1'),
            'img_start': reg('img_start', '.f1'), 'img_wend': reg('img_wend', '.f1')}
except StopIteration:
    have = 'unreadable'
rep.add('registers_match_software_model', want, have, raw=str(regs))

# ---------------------------------------------------------------------------------------- slot 1
n = Conn(1, 40001, 5000, 9000)
n.sw.syn_ack(5000, mss_only=False)
n.run('SYNACK_with_wscale_stays_native', OUTST,
      packet(O_IP, n.m_ip, O_PORT, 40001, 5000, 9001, 0x12, 8192, b'', MSS_WSCALE),
      packet(O_IP, n.m_ip, O_PORT, 40001, 5000, 9001, 0x12, 8192, b'', MSS_WSCALE), CODES['arm_nat'])
n.mseq = 9001
nat = n.respond('native_mode_eligible_response_untouched', read_frame(1))
rep.add('native_mode_never_pads', ('passthrough', False), (nat.case, nat.pad))

sys.exit(0 if rep.finish(os.path.join(os.environ['OUT'], 'cases.json')) else 1)

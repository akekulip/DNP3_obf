"""Response-side mapper against the case4_transport oracle. Software only, no endpoint claim.

Each scenario runs three actors over one TCP connection: a native outstation sender (retransmits
from snd_una, trimming the acknowledged head as Linux does), the mapper under test, and a master
receiver that accepts only in-window, in-order bytes and checks that any byte it is sent twice is
the same byte both times. The pad58b codec plays the padder.

Every forwarded segment is compared with `RequestLedger.forward` and every ACK with
`RequestLedger.reverse`. The oracle's own commit path (`replacement=`) is used while its two-entry
capacity allows; beyond that the image is appended to the same oracle instance after the test has
checked the commit preconditions independently, and all translation still runs through the
oracle's code.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'size'))
import case4_padding as pad
import case4_pad58b as b
import case4_response_mapper as rm
from case4_transport import RequestLedger, Image

MASK = 0xffffffff
LINK_HEAD = bytes.fromhex('056419c40a000100')
CTL_POINTS = [b.AnalogFloatPoint(301, 10.0, 0), b.AnalogFloatPoint(302, 20.0, 0)]


def read_frame(n):
    data = bytes((n * 7 + i) & 0xff for i in range(23))
    return pad.build_frame(LINK_HEAD, bytes([0xc0 | (n & 0x0f), 0xc0 | (n & 0x0f), 0x81, 0x80, 0])
                           + b.HEADER_READ23 + data)


def control_frame(n, code=0x03):
    user = bytes([0xc0 | (n & 0x0f), 0xc0 | (n & 0x0f), 0x81, 0, 0]) + b.HEADER_CROB28 + bytes(
        [0x05, 0x00, code, 0x01, 0x64, 0, 0, 0, 0x64, 0, 0, 0, 0x00])
    return pad.build_frame(LINK_HEAD, user)


def padder(payload):
    """(delta, image) as the pad58b padder would produce for this exact payload."""
    image, delta = b.pad_read_response(payload)
    if delta:
        return delta, image
    image, delta = b.pad_control_response(payload, CTL_POINTS)
    return delta, image


def leading(payload):
    """(delta, image, frame_len) for a complete eligible frame at the start of the payload."""
    if len(payload) >= 10 and payload[:2] == b'\x05\x64' and payload[2] >= 5:
        n = payload[2] - 5
        flen = 10 + n + 2 * ((n + 15) // 16)
        if len(payload) >= flen:
            delta, image = padder(payload[:flen])
            if delta:
                return delta, image, flen
    return 0, None, 0


def ser(x):
    return rm.signed(x)


class Lab:
    def __init__(self, test, isn, pad_enable=True, merged_suffix_ok=True):
        self.t = test
        self.isn1 = (isn + 1) & MASK
        self.m = rm.ResponseMapper(pad_enable, merged_suffix_ok)
        self.m.syn_ack(isn)
        self.o = RequestLedger(self.isn1)
        self.segments = []                 # original (seq, payload) in send order
        self.snd_nxt = self.snd_una = self.isn1
        self.frontier = self.isn1          # test's own native frontier
        self.rcv_nxt = self.isn1           # master, wire space
        self.master = bytearray()
        self.expected = bytearray()        # wire stream the master must end up with
        self.last_ack_seen = self.isn1     # last wire ACK the mapper saw (test's own copy)
        self.wnd = 65535
        self.cases = []

    # outstation ------------------------------------------------------------------------------
    def write(self, frame, lose=False):
        seq = self.snd_nxt
        self.segments.append((seq, frame))
        self.snd_nxt = (seq + len(frame)) & MASK
        return self.transmit(seq, frame, lose=lose)

    def retransmit(self, lose=False, merge=False, fin=False):
        """RTO: resend everything from snd_una, head-trimmed. merge=True collapses all of it into
        one segment, as Linux does with tcp_retrans_collapse=1 (the default)."""
        parts = []
        for seq, data in self.segments:
            end = (seq + len(data)) & MASK
            if ser(end - self.snd_una) <= 0:
                continue
            cut = max(0, ser(self.snd_una - seq))
            parts.append(((seq + cut) & MASK, data[cut:]))
        if merge and parts:
            parts = [(parts[0][0], b''.join(d for _, d in parts))]
        return [self.transmit(s, d, lose=lose, fin=fin and i == len(parts) - 1) for i, (s, d) in enumerate(parts)]

    # switch ----------------------------------------------------------------------------------
    def transmit(self, seq, payload, lose=False, fin=False):
        delta, image, flen = leading(payload)
        at_frontier = seq == self.frontier
        # independent commit preconditions (spec section 4)
        wire_frontier = (self.isn1 + self.o._wire_offset(self.o._offset(self.frontier))) & MASK
        should_commit = (at_frontier and delta and len(payload) == flen and not fin and
                         self.m.pad_enable and self.last_ack_seen == wire_frontier)
        res = self.m.forward(seq, len(payload), delta, fin=fin)
        self.cases.append(res.case)
        self.t.assertEqual(res.case == 'commit', bool(should_commit), (res, seq))
        if res.case == 'commit':
            if len(self.o.entries) < 2:    # the oracle's own commit path
                o = self.o.forward(seq, payload, replacement=image)
                self.t.assertTrue(o.inserted)
            else:
                self.o.entries.append(Image(self.o._offset(seq), payload, image))
                o = self.o.forward(seq, payload)
        elif not res.dropped:
            o = self.o.forward(seq, payload)
        if at_frontier and not res.dropped:
            self.frontier = (seq + len(payload)) & MASK
            self.expected += image if res.case == 'commit' else payload
        if res.dropped:
            self.t.assertIn(res.case, ('drop_overlap', 'drop_ahead', 'drop_merged'))
            return res
        wire = image + payload[flen:] if res.pad else payload
        if res.pad:
            self.t.assertEqual(flen + delta, rm.IMAGE_LEN)
        if res.case == 'stale' and not self.after_previous_image(seq):
            # Older than the previous image: the spec promises only that it is wholly below the
            # master's rcv_nxt, which a receiver discards without looking at the bytes.
            self.t.assertLessEqual(ser(res.seq + len(wire) - self.rcv_nxt), 0)
            return res
        self.t.assertEqual((res.seq, wire), (o.seq, o.payload), res.case)
        if not lose:
            self.receive(res.seq, wire)
        return res

    def prev_image_end(self):
        return self.isn1 if len(self.o.entries) < 2 else (self.isn1 + self.o.entries[-2].end) & MASK

    def after_previous_image(self, seq):
        return len(self.o.entries) < 2 or ser(seq - self.prev_image_end()) >= 0

    # master ----------------------------------------------------------------------------------
    def receive(self, wseq, data):
        off = ser(wseq - self.rcv_nxt)
        base = len(self.master)
        for i, byte in enumerate(data):       # bytes already held must be identical
            pos = base + off + i
            if 0 <= pos < base:
                self.t.assertEqual(self.master[pos], byte, 'replayed byte differs from first copy')
        if off > 0:
            return                             # out of order: dropped by this simple receiver
        take = data[-off:][:self.wnd]
        self.master += take
        self.rcv_nxt = (self.rcv_nxt + len(take)) & MASK

    def ack(self, wnd=None):
        if wnd is not None:
            self.wnd = wnd
        a, w = self.rcv_nxt, self.wnd
        res = self.m.reverse(a, w)
        self.last_ack_seen = a          # spec: A is the latest master ACK seen by the switch
        o_ack, o_win = self.o.reverse(a, w)
        img = self.image_bounds()
        if res.case == 'translate':
            self.t.assertEqual((res.ack, res.window), (o_ack, o_win))
        elif res.case == 'withhold':
            e_start, e_end, ws, we = img
            self.t.assertTrue(ser(a - ws) >= 0 and ser(a - we) < 0)
            self.t.assertEqual(res.ack, e_start)
            self.t.assertLessEqual(ser(res.ack - o_ack), 0)          # never ahead of the oracle
            self.t.assertLess(ser(o_ack - e_end), 0)                 # oracle withholds too
            self.t.assertLessEqual(ser(res.ack + res.window - (o_ack + o_win)), 0)
        else:
            self.t.fail(res)
        # safety: no native ACK ever exceeds the oracle's for the same packet; snd_una is a max over
        # these and the oracle is monotone, so the outstation never retires bytes the master lacks
        self.t.assertLessEqual(ser(res.ack - o_ack), 0)
        self.snd_una = res.ack if ser(res.ack - self.snd_una) > 0 else self.snd_una
        return res

    def image_bounds(self):
        m = self.m
        return m.img_start, m.img_end, (m.img_wend - rm.IMAGE_LEN) & MASK, m.img_wend

    def done(self):
        self.t.assertEqual(bytes(self.master), bytes(self.expected))
        self.t.assertEqual(self.snd_una, self.snd_nxt)
        self.t.assertEqual(self.rcv_nxt, (self.isn1 + len(self.expected)) & MASK)


class Mapper(unittest.TestCase):
    ISNS = (1000, 0xffffffff - 120)      # second one wraps inside the first few responses

    def test_frames_are_eligible_profiles(self):
        self.assertEqual(padder(read_frame(1))[0], 9)
        self.assertEqual(padder(control_frame(1))[0], 21)
        self.assertEqual(len(read_frame(1)), 49)
        self.assertEqual(len(control_frame(1)), 37)

    def test_select_operate_on_pristine_oracle_two_commits(self):
        for isn in self.ISNS:
            lab = Lab(self, isn)
            first = lab.write(control_frame(1, 0x03))          # SELECT echo
            lab.ack()                                          # OPERATE request carries this
            second = lab.write(control_frame(2, 0x03))         # OPERATE echo
            lab.ack()
            self.assertEqual((first.case, second.case), ('commit', 'commit'))
            self.assertEqual(len(lab.o.entries), 2)            # no injection used
            self.assertEqual(second.seq, (lab.isn1 + 58) & MASK)
            lab.done()

    def test_repeated_reads_and_sbo_each_commit_exactly_once(self):
        for isn in self.ISNS:
            lab = Lab(self, isn)
            frames = [read_frame(i) for i in range(4)] + [control_frame(5), control_frame(6)] + \
                     [read_frame(i) for i in range(7, 12)]
            commits = []
            for f in frames:
                commits.append(lab.write(f))
                lab.retransmit()      # spurious RTO copy before the ACK: replay, never a commit
                lab.ack()
                lab.retransmit()      # nothing outstanding: no-op
            self.assertEqual([c.case for c in commits], ['commit'] * len(frames))
            self.assertEqual(lab.cases.count('commit'), len(frames))
            self.assertEqual(lab.cases.count('replay'), len(frames))
            self.assertEqual([c.seq for c in commits],
                             [(lab.isn1 + 58 * i) & MASK for i in range(len(frames))])
            lab.done()

    def test_lost_image_is_reconstructed_identically(self):
        for isn in self.ISNS:
            lab = Lab(self, isn)
            for i in range(3):
                first = lab.write(read_frame(i), lose=True)    # switch -> master copy lost
                lab.ack()                                      # dup ACK: nothing new
                again = lab.retransmit()
                self.assertEqual([r.case for r in again], ['replay'])
                self.assertEqual((again[0].seq, again[0].pad), (first.seq, True))
                lab.ack()
            lab.done()

    def test_partial_ack_anywhere_in_image_does_not_strand_tail(self):
        for isn in self.ISNS:
            for make in (read_frame, control_frame):
                for k in range(1, 58):
                    lab = Lab(self, isn)
                    lab.write(make(0)); lab.ack()
                    lab.wnd = k                                 # master takes only k bytes
                    lab.write(make(1))
                    res = lab.ack(wnd=0)                        # partial ACK, zero window
                    self.assertEqual((res.case, res.window), ('withhold', 0))
                    self.assertNotEqual(lab.snd_una, lab.snd_nxt)
                    res = lab.ack(wnd=4096)                     # window update
                    self.assertEqual(res.case, 'withhold')
                    again = lab.retransmit()                    # whole native frame
                    self.assertEqual([r.case for r in again], ['replay'])
                    res = lab.ack()
                    self.assertEqual(res.case, 'translate')
                    lab.write(make(2)); lab.ack()               # next one still commits
                    self.assertEqual(lab.cases.count('commit'), 3)
                    lab.done()

    def test_refused_response_is_native_forever(self):
        lab = Lab(self, 5000)
        lab.write(read_frame(0))                 # commit, not yet acknowledged
        second = lab.write(read_frame(1))        # A != W: refused, native length
        self.assertEqual(second.case, 'translate')
        lab.ack()
        again = lab.retransmit()
        self.assertEqual(again, [])              # both acknowledged already
        lab.write(read_frame(2), lose=True)      # commit
        lab.ack()
        lab.retransmit()
        lab.ack()
        lab.done()
        # a refused range retransmitted later is never padded
        lab = Lab(self, 5000)
        lab.write(read_frame(0))
        lab.write(read_frame(1), lose=True)      # refused and lost
        lab.ack()                                # acks only the image
        again = lab.retransmit()
        self.assertEqual([r.case for r in again], ['translate'])
        lab.ack()
        lab.done()

    def test_policy_off_mid_connection_keeps_translating(self):
        lab = Lab(self, 77)
        for i in range(3):
            lab.write(read_frame(i)); lab.ack()
        lab.m.pad_enable = False
        for i in range(3, 5):
            r = lab.write(read_frame(i))
            self.assertEqual(r.case, 'translate')
            self.assertEqual(r.seq, (lab.isn1 + 3 * 58 + (i - 3) * 49) & MASK)
            lab.ack()
        lab.m.pad_enable = True
        lab.write(control_frame(9)); lab.ack()
        self.assertEqual(lab.cases.count('commit'), 4)
        lab.done()

    def test_stale_duplicate_of_previous_image_is_wholly_old(self):
        lab = Lab(self, 9000)
        lab.write(read_frame(0)); lab.ack()
        lab.write(read_frame(1)); lab.ack()
        lab.write(read_frame(2)); lab.ack()
        seq, data = lab.segments[1]               # in-flight copy of an older response
        res = lab.transmit(seq, data)
        self.assertEqual(res.case, 'stale')
        seq, data = lab.segments[0]
        res = lab.transmit(seq, data)             # older than the previous image
        self.assertEqual(res.case, 'stale')
        lab.done()

    def test_unsupported_overlap_and_ahead_are_dropped_without_state_change(self):
        lab = Lab(self, 300)
        lab.write(read_frame(0))
        frame = lab.segments[0][1]
        state = vars(lab.m).copy()
        self.assertEqual(lab.m.forward(lab.isn1 + 1, 48).case, 'drop_overlap')
        self.assertEqual(lab.m.forward(lab.isn1, 20).case, 'drop_overlap')
        self.assertEqual(lab.m.forward(lab.isn1 + 48, 1).case, 'drop_overlap')
        self.assertEqual(lab.m.forward(lab.isn1 + 49 + 10, 5).case, 'drop_ahead')
        self.assertEqual(lab.m.forward(lab.isn1 + 49, 5, supported=False).case, 'drop_unsupported')
        self.assertEqual(lab.m.reverse(lab.isn1, 100, supported=False).case, 'drop_unsupported')
        self.assertEqual(vars(lab.m), state)
        # a replay whose verdict is not eligible (corrupted copy) is dropped, not sent native
        self.assertEqual(lab.m.forward(lab.isn1, len(frame), 0).case, 'drop_overlap')
        lab.ack(); lab.done()

    def test_zero_length_keepalive_and_fin_match_oracle(self):
        lab = Lab(self, 0xffffffff - 3)
        r = lab.transmit((lab.isn1 - 1) & MASK, b'')      # keepalive before any data
        self.assertEqual((r.case, r.seq), ('zero', (lab.isn1 - 1) & MASK))
        lab.write(read_frame(0)); lab.ack()
        r = lab.transmit((lab.snd_una - 1) & MASK, b'')   # keepalive after an image
        self.assertEqual(r.case, 'zero')
        fin = lab.m.forward(lab.snd_nxt, 0, fin=True)
        self.assertEqual((fin.case, fin.seq), ('translate', (lab.isn1 + 58) & MASK))
        self.assertEqual(lab.m.front, (lab.snd_nxt + 1) & MASK)
        lab.done()

    def test_reverse_sweep_against_oracle_both_edges(self):
        for isn in self.ISNS:
            for make in (read_frame, control_frame):
                lab = Lab(self, isn)
                lab.write(read_frame(0)); lab.ack()
                lab.write(make(1))
                e_start, e_end, ws, we = lab.image_bounds()
                last_right = None
                for off in range(-70, 130):
                    a = (we + off) & MASK
                    for w in (0, 1, 8, 9, 20, 21, 57, 58, 59, 200, 65535):
                        m = rm.ResponseMapper(); vars(m).update(vars(lab.m))
                        res = m.reverse(a, w)
                        o_ack, o_win = lab.o.reverse(a, w)
                        if off >= 0:
                            self.assertEqual((res.case, res.ack, res.window), ('translate', o_ack, o_win))
                        elif off >= -58:
                            self.assertEqual((res.case, res.ack), ('withhold', e_start))
                            self.assertLessEqual(ser(res.ack - o_ack), 0)
                            self.assertLess(ser(o_ack - e_end), 0)
                            self.assertGreaterEqual(res.window, 0)
                            self.assertLessEqual(ser(res.ack + res.window - (o_ack + o_win)), 0)
                        else:
                            self.assertEqual(res.case, 'drop_stale')
                    # monotone native right edge as the master's ACK advances with w fixed
                    if off >= -58:
                        res = rm.ResponseMapper(); vars(res).update(vars(lab.m))
                        res = res.reverse(a, 100)
                        right = (res.ack + res.window) & MASK
                        if last_right is not None:
                            self.assertGreaterEqual(ser(right - last_right), 0)
                        last_right = right
                lab.ack(); lab.done()

    def test_reordered_older_ack_only_refuses_a_commit(self):
        lab = Lab(self, 4000)
        lab.write(read_frame(0)); lab.ack()
        lab.write(read_frame(1)); lab.ack()
        current = lab.rcv_nxt
        lab.rcv_nxt = (current - 58) & MASK           # an older ACK arrives late
        old = lab.ack()
        self.assertEqual(old.case, 'withhold')        # ws of the latest image: harmless
        lab.rcv_nxt = current
        refused = lab.write(read_frame(2))            # A != W: refused, native
        self.assertEqual(refused.case, 'translate')
        lab.ack()
        self.assertEqual(lab.write(read_frame(3)).case, 'commit')
        lab.ack(); lab.done()

    def test_native_mode_passthrough_never_pads(self):
        m = rm.ResponseMapper()
        m.syn_ack(10, mss_only=False)
        f = read_frame(0)
        r = m.forward(11, len(f), 9)
        self.assertEqual((r.case, r.seq, r.pad), ('passthrough', 11, False))
        self.assertEqual(m.reverse(60, 100).case, 'passthrough')
        # unarmed slot (no SYN-ACK seen) is native too
        self.assertEqual(rm.ResponseMapper().forward(1, 49, 9).case, 'passthrough')

    def test_merged_retransmission_replays_image_then_native_suffix(self):
        # code-review HIGH 1 reproduction: commit, refuse a second response, lose both,
        # retransmit as one collapsed segment.
        for isn in self.ISNS:
            for second in (read_frame(1), control_frame(2), bytes(range(30))):
                lab = Lab(self, isn)
                lab.write(read_frame(0)); lab.ack()
                lab.write(control_frame(0), lose=True)          # commit, lost
                refused = lab.write(second, lose=True)          # refused or plain data, lost
                self.assertEqual(refused.case, 'translate')
                lab.ack()                                       # dup ACK at the image start
                merged = lab.retransmit(merge=True)
                self.assertEqual([r.case for r in merged], ['replay'])
                again = lab.retransmit(merge=True)              # still unacknowledged copy
                self.assertEqual([r.case for r in again], ['replay'])
                lab.ack(); lab.done()

    def test_tofino_profile_drops_merged_suffix_and_recovers_on_a_plain_copy(self):
        lab = Lab(self, 0xffffffff - 50, merged_suffix_ok=False)
        lab.write(read_frame(0)); lab.ack()
        lab.write(control_frame(0), lose=True)
        lab.write(read_frame(1), lose=True)
        lab.ack()
        self.assertEqual([r.case for r in lab.retransmit(merge=True)], ['drop_merged'])
        whole_fin = lab.retransmit(merge=False)                 # a non-collapsing stack: plain copies
        self.assertEqual([r.case for r in whole_fin], ['replay', 'translate'])
        lab.ack(); lab.done()
        # the FIN-only extension of a whole frame is not a suffix and still replays
        lab = Lab(self, 7, merged_suffix_ok=False)
        lab.write(read_frame(0), lose=True); lab.ack()
        self.assertEqual([r.case for r in lab.retransmit(fin=True)], ['replay'])

    def test_merged_retransmission_after_partial_ack_in_image(self):
        lab = Lab(self, 66)
        lab.write(read_frame(0)); lab.ack()
        lab.wnd = 20
        lab.write(read_frame(1))                                # master takes 20 bytes
        lab.write(read_frame(2))                                # refused (A != W), dropped by window
        lab.ack(wnd=4096)
        self.assertEqual([r.case for r in lab.retransmit(merge=True)], ['replay'])
        lab.ack(); lab.done()

    def test_whole_frame_retransmission_with_fin_replays(self):
        lab = Lab(self, 0xffffffff - 30)
        lab.write(read_frame(0)); lab.ack()
        lab.write(read_frame(1), lose=True)
        lab.ack()
        r = lab.retransmit(fin=True)                            # outstation closes meanwhile
        self.assertEqual([(x.case, x.pad) for x in r], [('replay', True)])
        self.assertEqual(lab.m.front, lab.snd_nxt)              # FIN was never at the frontier here
        lab.ack(); lab.done()

    def test_coalesced_first_transmission_never_commits(self):
        lab = Lab(self, 12)
        lab.write(read_frame(0)); lab.ack()
        r = lab.write(read_frame(1) + bytes(5))                 # frame plus more bytes, first copy
        self.assertEqual(r.case, 'translate')
        lab.ack()
        self.assertEqual(lab.write(read_frame(2)).case, 'commit')
        lab.ack(); lab.done()

    def test_first_transmission_with_fin_never_commits(self):
        lab = Lab(self, 12)
        seq = lab.snd_nxt; f = read_frame(0)
        lab.segments.append((seq, f)); lab.snd_nxt = (seq + len(f)) & MASK
        r = lab.transmit(seq, f, fin=True)
        self.assertEqual(r.case, 'translate')
        lab.ack(); lab.done()

    def test_rearm_on_retransmitted_syn_ack_before_data_is_idempotent(self):
        m = rm.ResponseMapper(); m.syn_ack(41)
        before = vars(m).copy(); m.syn_ack(41)
        self.assertEqual(vars(m), before)


if __name__ == '__main__':
    unittest.main()

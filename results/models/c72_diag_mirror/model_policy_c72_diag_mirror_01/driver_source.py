"""Current two-READ encoding/mapping and committed-image ACK boundary checks.

Independent decoding checks padding prefixes, original object suffixes, per-image growth and TCP coordinates."""
import hashlib
import json
import os
import sys
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

HERE = Path(__file__).resolve().parent
REARM = HERE
sys.path[:0] = [str(Path(__file__).resolve().parent), str(Path(__file__).resolve().parent.parent / 'checks'), str(Path(__file__).resolve().parent.parent / 'hardware')]
import model_packets as mp  # noqa: E402
import pad_oracle as po  # noqa: E402

R_TRANSLATE, R_WITHHOLD, R_STALE = 9, 10, 11

std = mp.std
C = json.loads((ROOT / 'tests/fixtures/vectors/constants.json').read_text())['shapes']['range_g10v2_23']
TEMPLATES = json.loads((ROOT / 'tests/fixtures/vectors/read_class_templates.json').read_text())['databases']['base']
CLASS_ORDER = ('range', 'analog', 'class0', 'integrity')      # the fixture endpoint's rotate4 order
# Two-READ-target build (inputs.json policy.constants_file): every READ slot alternates the two workloads from the
# hardware endpoint's own captures (two_read_templates.json, fixture variants v0/v1), each padded to its own image.
TWO_READ = mp.rp.TWO_READ


def _two_templates():
    """Use the same strict captured-template selector as the timing gate."""
    from two_read_templates import select_templates
    return select_templates(ROOT / 'tests/fixtures/vectors', mp.rp.SHAPES)[0]


TWO_TEMPLATES = _two_templates() if TWO_READ else None
TWO_ORDER = ('mixed', 'integrity')


def build_passthrough():
    """The pass-through READ classes the build under test declares (response_only.inputs.json), or none."""
    path = os.environ.get('PORT_MAP')
    return json.loads(Path(path).read_text()).get('passthrough_reads') or {} if path else {}


def resequence(frame, transport, app, dst=None, src=None):
    """A captured one-frame DNP3 message re-addressed to the model connection's link addresses and given a new
    transport sequence and application control, re-framed so every block CRC is valid (std.frame). The fixture
    captures carry the testbed's own link addresses (outstation 0x000a, master 0x0001); the model's range builders
    and the installed read_connection row use 0x0000/0x0100, so an un-readdressed frame trips N's link-address
    guard (m.badh)."""
    hdr, user = std.deframe(frame)
    hdr = bytearray(hdr)
    if dst is not None:
        hdr[4:6] = dst.to_bytes(2, 'big')   # the model's link builders pack dst/src big-endian
    if src is not None:
        hdr[6:8] = src.to_bytes(2, 'big')
    return std.frame(bytes(hdr), bytes([(user[0] & 0xC0) | (transport & 63), (user[1] & 0xF0) | (app & 0x0F)]) + user[2:])
IMAGE = C['target']
PAD_FIRST = C['reserved_first_index']
NPAD = C['padding_points']


def construct(native):
    """Switch construction from the derived constants (same function derive.py proved equal to pad_read)."""
    hdr, user = std.deframe(native)
    seq = user[0] & 63
    prefix = std.frame(hdr[:2] + bytes([C['prefix_link_len']]) + hdr[3:],
                       bytes([0x40 | seq]) + user[1:5] + bytes.fromhex(C['padobj_head']))
    cont = std.frame(hdr, bytes([(user[0] & std.FIN) | ((seq + 1) & 63)]) + bytes(4) + user[5:])
    return prefix + cont


class PolicyGate(mp.PacketGate):
    def check_prefix_image(self, name, native, image):
        frames = po._split_frames(image)
        frags, events = std.reassemble(frames)
        self.add(name + '_reassembles', (1, []), (len(frags), events))
        if len(frags) != 1:
            return
        _, pts = std.check_read_response(std.fragment_user(frags[0][0]))
        _, orig = std.check_read_response(std.deframe(native)[1])
        self.add(name + '_originals_are_suffix', orig, pts[NPAD:])
        self.add(name + '_padding_is_reserved_prefix', [(1, 2, PAD_FIRST + i, b'\x00') for i in range(NPAD)],
                 [(g, v, i, d) for g, v, i, d in pts[:NPAD]])

    def read_exchange(self, name, cseq, native_sseq, wire_sseq, seq=0, statuses=None,
                      iin=b'\x80\x00', expect_growth=True):
        request = self.rs.request_packet(seq=cseq, ack=wire_sseq, app=0xc0 | (seq & 15))
        self.exchange(name + '_request', request, self.rs.request_packet(seq=cseq, ack=native_sseq, app=0xc0 | (seq & 15)))
        ack = self.rs.ack_packet(seq=native_sseq, ack=cseq + 20)
        self.exchange(name + '_server_ack', ack, self.rs.ack_packet(seq=wire_sseq, ack=cseq + 20), reverse=True)
        native = mp.read_frame(seq, statuses, app=0xc0 | (seq & 0x0f), iin=iin)
        image = construct(native)
        self.add(name + '_expected_len', IMAGE, len(image))
        self.check_prefix_image(name, native, image)
        got = self.exchange(name + '_response',
                            self.v.packet(24, native_sseq, cseq + 20, reverse=True, payload=native),
                            self.v.packet(24, wire_sseq, cseq + 20, reverse=True, payload=image), reverse=True)
        self.add(name + '_payload_len', IMAGE, len(mp.tcp_payload(got)))
        self.check_prefix_image(name + '_wire', native, mp.tcp_payload(got))
        if expect_growth:
            self.exchange(name + '_mapped_ack', self.v.packet(16, cseq + 20, wire_sseq + IMAGE),
                          self.v.packet(16, cseq + 20, native_sseq + mp.READ_NATIVE))
        return cseq + 20, native_sseq + mp.READ_NATIVE, wire_sseq + IMAGE

    def class_read_exchange(self, name, cls, cseq, native_sseq, wire_sseq, seq):
        """A pass-through READ class from real captured bytes: N must admit the request and the response, which
        leaves the switch UNCHANGED (already at a policy target), mapped at native size."""
        t = TEMPLATES[cls]
        # transport sequence 0, as the range builders (read_support.request_frame/response_frame) send it
        request = resequence(bytes.fromhex(t['request']), 0, 0xC0 | (seq & 15), dst=0x0000, src=0x0100)
        self.exchange(name + '_request', self.v.packet(24, cseq, wire_sseq, payload=request),
                      self.v.packet(24, cseq, native_sseq, payload=request))
        qlen = len(request)
        self.exchange(name + '_server_ack', self.rs.ack_packet(seq=native_sseq, ack=cseq + qlen),
                      self.rs.ack_packet(seq=wire_sseq, ack=cseq + qlen), reverse=True)
        native = resequence(bytes.fromhex(t['native']), 0, 0xC0 | (seq & 15), dst=0x0100, src=0x0000)
        self.add(name + '_policy_status', 'already_at_target', t['status'])
        got = self.exchange(name + '_response',
                            self.v.packet(24, native_sseq, cseq + qlen, reverse=True, payload=native),
                            self.v.packet(24, wire_sseq, cseq + qlen, reverse=True, payload=native), reverse=True)
        self.add(name + '_payload_unchanged', native.hex(), mp.tcp_payload(got).hex())
        n = len(native)
        self.exchange(name + '_mapped_ack', self.v.packet(16, cseq + qlen, wire_sseq + n),
                      self.v.packet(16, cseq + qlen, native_sseq + n))
        return cseq + qlen, native_sseq + n, wire_sseq + n

    def two_read_frames(self, cls, k, seq):
        """Request and native response of one two-READ workload (captured bytes, fixture variant k % 2), re-addressed
        to the model connection and re-sequenced (transport 0, application sequence seq)."""
        t = TWO_TEMPLATES['v%d' % (k % 2)]['classes'][cls]
        request = resequence(bytes.fromhex(t['request']), 0, 0xC0 | (seq & 15), dst=0x0000, src=0x0100)
        native = resequence(bytes.fromhex(t['native']), 0, 0xC0 | (seq & 15), dst=0x0100, src=0x0000)
        return request, native

    def two_read_exchange(self, name, cls, cseq, nsq, wsq, k):
        """One two-READ workload: N admits the request, the response leaves padded to ITS OWN image byte-exact
        (rp.construct, the derivation proved == pad_read), the wire bytes decode independently (dnp3_std: one
        fragment, originals unchanged as the suffix, exactly the reserved padding as the prefix), and the master's ACK
        of the whole image maps back to the native end."""
        request, native = self.two_read_frames(cls, k, k & 63)
        qlen = len(request)
        self.exchange(name + '_request', self.v.packet(24, cseq, wsq, payload=request),
                      self.v.packet(24, cseq, nsq, payload=request))
        self.exchange(name + '_server_ack', self.rs.ack_packet(seq=nsq, ack=cseq + qlen),
                      self.rs.ack_packet(seq=wsq, ack=cseq + qlen), reverse=True)
        image = mp.rp.construct(native)
        target = mp.rp.SHAPES[len(native)]['target']
        self.add(name + '_expected_image', target, len(image))
        got = self.exchange(name + '_response',
                            self.v.packet(24, nsq, cseq + qlen, reverse=True, payload=native),
                            self.v.packet(24, wsq, cseq + qlen, reverse=True, payload=image), reverse=True)
        wire = mp.tcp_payload(got)
        self.add(name + '_payload_len', target, len(wire))
        info = mp.rp.check_read_image(native, wire)
        self.add(name + '_independent_decode', (target, mp.rp.SHAPES[len(native)]['padding_points']),
                 (info['image_len'], info['padding_points']), frames=info['frames'])
        n, img = len(native), len(image)
        self.exchange(name + '_mapped_ack', self.v.packet(16, cseq + qlen, wsq + img),
                      self.v.packet(16, cseq + qlen, nsq + n))
        return cseq + qlen, nsq + n, wsq + img

    def read(self, cseq, nsq, wsq, k):
        if TWO_READ:
            cls = TWO_ORDER[k % 2]
            return self.two_read_exchange('read_%03d_%s' % (k, cls), cls, cseq, nsq, wsq, k)
        cls = CLASS_ORDER[k % 4] if PASSTHROUGH else 'range'
        if cls != 'range':
            if cls not in PASSTHROUGH:
                raise AssertionError('class %s scheduled but not declared by the build' % cls)
            return self.class_read_exchange('read_%03d_%s' % (k, cls), cls, cseq, nsq, wsq, k & 63)
        statuses = [((k * 11 + j * 17) & 0xff) | (0x80 if j in (0, 7, 22) else 0) for j in range(23)]
        return self.read_exchange('read_%03d' % k, cseq, nsq, wsq, seq=k & 63, statuses=statuses,
                                  iin=bytes([0x80 if k & 1 else 0, k & 0x10]))

    def sbo(self, cseq, nsq, wsq, k, fc):
        # a SELECT and its OPERATE carry the SAME control object (pair = k // 2); only fc and sequences differ
        pair = k // 2
        return self.control_exchange('%s_%03d' % ('select' if fc == 3 else 'operate', k), cseq, nsq, wsq,
                                     seq=k & 63, app=k & 0x0f, fc=fc, index=1 + (pair & 7), code=1 + (pair & 7),
                                     count=1, on=0x1000 + pair * 3, off=0x2000 + pair * 5)

    def run_interleaved(self, cycles=16):
        cseq, nsq, wsq = self.handshake(100, 900, 'base_')
        k = 0
        cseq, nsq, wsq = self.read(cseq, nsq, wsq, k)
        for cycle in range(cycles):                         # R -> S -> O -> R, repeated (both transitions)
            cseq, nsq, wsq = self.sbo(cseq, nsq, wsq, 2 * cycle, 3)
            cseq, nsq, wsq = self.sbo(cseq, nsq, wsq, 2 * cycle + 1, 4)
            k += 1
            cseq, nsq, wsq = self.read(cseq, nsq, wsq, k)
            if cycle % 4 == 3:                              # READ -> READ back to back as well
                k += 1
                cseq, nsq, wsq = self.read(cseq, nsq, wsq, k)
        self.close(cseq, nsq, wsq, 'close')


PASSTHROUGH = build_passthrough()


class PolicyBoundaryGate(PolicyGate):
    def e_counts(self):
        """Read E classification observations from the SDK model action log adapter.
        gc (bfrt_grpc) is only importable inside the launched SDE env; reuse the one model_drive_composite
        already imported from model_driver."""
        gc = self.h.gc
        counter = self.m.table('p0.r_Egress.outcome')
        for op in ('Sync', 'SyncCounters'):
            try:
                counter.operations_execute(self.m.target, op)
                break
            except Exception:
                pass
        got = {}
        for code in range(16):
            for data, _k in counter.entry_get(self.m.target, [counter.make_key([gc.KeyTuple('$COUNTER_INDEX', code)])],
                                               {'from_hw': True}):
                v = data.to_dict()['$COUNTER_SPEC_PKTS']
                got[code] = sum(v) if isinstance(v, list) else v
        return got

    def _probe(self, name, cseq, ack_wire, expect_code):
        """Send one forward ACK; record which outcome code incremented (the classification)."""
        before = self.e_counts()
        pkt = self.v.packet(16, cseq, ack_wire)
        got = self.m.exchange(self.master.dev_port, pkt, self.ports, timeout=3, quiet=.15)
        after = self.e_counts()
        delta = {c: after.get(c, 0) - before.get(c, 0) for c in range(16) if after.get(c, 0) != before.get(c, 0)}
        fwd = any(f for fs in got.values() for f in fs)
        # translate (9) also emits a forwarded unparsed departure counted as code 0; withhold (10) and
        # stale (11) emit no departure. Pass iff the EXPECTED result code incremented by exactly 1.
        ok = delta.get(expect_code, 0) == 1
        self.report.add(name, 'result %d incremented' % expect_code,
                        'deltas %s, egress %s' % (delta, 'frame' if fwd else 'none'),
                        ok=ok, sent=pkt, received=got)
        print('  %-18s expect result %-2d -> deltas=%s egress=%s  %s'
              % (name, expect_code, delta, 'frame' if fwd else 'none', 'PASS' if ok else 'FAIL'))
        return delta

    def _boundary(self, prefix, cseq, we, L):
        """Probe the admit/stale boundary of an outstanding image: ack = we - d; d=L is the image START
        (expect withhold), d=L+1 is strictly before it (expect stale)."""
        self._probe('%s_start_d%d' % (prefix, L), cseq, (we - L) & 0xffffffff, R_WITHHOLD)
        self._probe('%s_before_d%d' % (prefix, L + 1), cseq, (we - L - 1) & 0xffffffff, R_STALE)

    def _retire(self, cseq, we, tag):
        """Ack the full outstanding image (d=0 -> translate/forward), advancing the connection frontier so
        the next request/response can commit on the SAME connection (the transition cases)."""
        self._probe(tag + '_retire', cseq, we, R_TRANSLATE)

    def _commit_sbo(self, cseq, nsq, wsq, tag, seq=0):
        """Control request and the profile-sized control response, with its image left outstanding."""
        req = mp.control_request(seq=seq, app=seq & 0xf, fc=3, index=1, code=1, count=1, on=0x1000, off=0x2000)
        self.exchange(tag + '_request', self.v.packet(24, cseq, wsq, payload=req),
                      self.v.packet(24, cseq, nsq, payload=req))
        native = mp.control_response(seq=seq, app=seq & 0xf, fc=3, index=1, code=1, count=1, on=0x1000, off=0x2000)
        image = mp.encode61.ctl61(native)
        self.exchange(tag + '_response61', self.v.packet(24, nsq, cseq + mp.CONTROL_REQUEST, reverse=True, payload=native),
                      self.v.packet(24, wsq, cseq + mp.CONTROL_REQUEST, reverse=True, payload=image), reverse=True)
        img_start = wsq
        return cseq + mp.CONTROL_REQUEST, nsq + mp.CONTROL_NATIVE, wsq + mp.IMAGE_LEN, img_start, mp.IMAGE_LEN

    def _commit_read(self, cseq, nsq, wsq, tag):
        req = self.rs.request_packet(seq=cseq, ack=wsq, app=0xc0)
        self.exchange(tag + '_request', req, self.rs.request_packet(seq=cseq, ack=nsq, app=0xc0))
        ack = self.rs.ack_packet(seq=nsq, ack=cseq + 20)
        self.exchange(tag + '_server_ack', ack, self.rs.ack_packet(seq=wsq, ack=cseq + 20), reverse=True)
        cseq += 20
        native = mp.read_frame(0, [0x81] * 23, app=0xc0)
        self.exchange(tag + '_response', self.v.packet(24, nsq, cseq, reverse=True, payload=native),
                      self.v.packet(24, wsq, cseq, reverse=True, payload=construct(native)), reverse=True)
        return cseq, nsq + mp.READ_NATIVE, wsq + IMAGE, wsq, IMAGE

    def _commit_two(self, cseq, nsq, wsq, tag, cls, seq=0):
        """Commit one two-READ workload's padded image and leave it OUTSTANDING (image start, image length L)."""
        request, native = self.two_read_frames(cls, seq, seq)
        qlen = len(request)
        self.exchange(tag + '_request', self.v.packet(24, cseq, wsq, payload=request),
                      self.v.packet(24, cseq, nsq, payload=request))
        self.exchange(tag + '_server_ack', self.rs.ack_packet(seq=nsq, ack=cseq + qlen),
                      self.rs.ack_packet(seq=wsq, ack=cseq + qlen), reverse=True)
        image = mp.rp.construct(native)
        self.exchange(tag + '_response', self.v.packet(24, nsq, cseq + qlen, reverse=True, payload=native),
                      self.v.packet(24, wsq, cseq + qlen, reverse=True, payload=image), reverse=True)
        return cseq + qlen, nsq + len(native), wsq + len(image), wsq, len(image)

    def run_two(self):
        """Two-READ build: the per-committed-image reverse boundary (d = 0 translate, d = L withhold, d = L + 1 stale)
        for each image ALONE -- mixed 141, full 271, SBO 61 -- and right after a transition in every order between
        them (READ->SBO, SBO->READ, mixed->full, full->mixed, READ->READ, SBO->SBO); then C5 for each READ image."""
        commit = {'mx': lambda c, n, w, t: self._commit_two(c, n, w, t, 'mixed'),
                  'full': lambda c, n, w, t: self._commit_two(c, n, w, t, 'integrity', seq=1),
                  'sbo': self._commit_sbo}
        isn = 1000
        selected = TWO_TEMPLATES['v0']['classes']
        labels = (('mx', 'READ%d' % mp.rp.SHAPES[len(bytes.fromhex(selected['mixed']['native']))]['target']),
                  ('full', 'READ%d' % mp.rp.SHAPES[len(bytes.fromhex(selected['integrity']['native']))]['target']),
                  ('sbo', 'SBO%d' % mp.IMAGE_LEN))
        for name, label in labels:
            cseq, nsq, wsq = self.handshake(isn, isn + 800, name + '_')
            cseq, nsq, we, _s, L = commit[name](cseq, nsq, wsq, name)
            self._bound(label, cseq, we, L)
            self.close(cseq, nsq, we, name + '_close')
            isn += 4000
        orders = (('mx', 'sbo'), ('sbo', 'mx'), ('full', 'sbo'), ('sbo', 'full'), ('mx', 'full'), ('full', 'mx'),
                  ('mx', 'mx'), ('full', 'full'), ('sbo', 'sbo'))
        for i, (a, b) in enumerate(orders):
            cseq, nsq, wsq = self.handshake(isn, isn + 800, 'tr%d_' % i)
            cseq, nsq, we, _s, _L = commit[a](cseq, nsq, wsq, 'tr%da' % i)
            self._retire(cseq, we, 'tr%da' % i)
            cseq, nsq, we, _s, L = commit[b](cseq, nsq, we, 'tr%db' % i)
            self._bound('TR_%s_to_%s_%d' % (a, b, L), cseq, we, L)
            self._retire(cseq, we, 'tr%db' % i)
            self.close(cseq, nsq, we, 'tr%d_close' % i)
            isn += 4000
        for cls, seq in (('mixed', 2), ('integrity', 3)):
            self.c5_two(cls, seq, isn)
            isn += 4000

    def c5_two(self, cls, seq, isn):
        """C5 per READ image: an outstation pure ACK at the committed image's NATIVE START, delivered after the
        response, must not be mis-mapped (any emitted frame carries the image's WIRE START); control: a pure ACK at
        the native END is forwarded at the wire END."""
        cseq, nsq, wsq = self.handshake(isn, isn + 800, 'c5%s_' % cls)
        native_start, wire_start = nsq, wsq
        cseq, nsq, we, _s, L = self._commit_two(cseq, nsq, wsq, 'c5%s' % cls, cls, seq=seq)
        pkt = self.v.packet(16, native_start, cseq, reverse=True)
        got = self.m.exchange(self.relay.dev_port, pkt, self.ports, timeout=3, quiet=.15)
        frames = [f for fs in got.values() for f in fs]
        expected = self.v.packet(16, wire_start, cseq, reverse=True)
        self.report.add('c5_%s_%d_native_start' % (cls, L), 'no mis-mapped emission (any frame == wire start)',
                        'frames %d' % len(frames), ok=all(bytes(f) == bytes(expected) for f in frames),
                        sent=pkt, received=got)
        self.exchange('c5_%s_control_native_end' % cls, self.v.packet(16, nsq, cseq, reverse=True),
                      self.v.packet(16, we, cseq, reverse=True), reverse=True)
        self._retire(cseq, we, 'c5%s' % cls)
        self.close(cseq, nsq, we, 'c5%s_close' % cls)

    def _bound(self, prefix, cseq, we, L):
        """Classification at the edges of the outstanding image as THIS build implements them. The withhold
        window is the max image (141), so the READ image boundary is exact; for the 61-octet SBO image the
        region d in [62, 141] is withheld, not stale-dropped (C3 per-image exactness did not place: see
        P4_PLACEMENT_FINDINGS.md) -- asserted under an explicit LIMITATION name, never as a pass of C3."""
        self._probe('%s_end_d0' % prefix, cseq, we, R_TRANSLATE)
        self._probe('%s_start_d%d' % (prefix, L), cseq, (we - L) & 0xffffffff, R_WITHHOLD)
        if L == IMAGE or mp.rp.READ_BOUNDARY == 'cimg':
            # per-committed-image boundary (make_m12 --c3 cimg): one octet before the committed image's own start
            # is stale for every image, including the 61-octet SBO image
            self._probe('%s_before_d%d' % (prefix, L + 1), cseq, (we - L - 1) & 0xffffffff, R_STALE)
        else:
            # max-image ladder (b08): the SBO image's pre-start region d in [L+1, IMAGE] is withheld, not stale --
            # a documented limitation (P4_PLACEMENT_FINDINGS.md), asserted under its own name, never as a C3 pass
            self._probe('%s_LIMITATION_prestart_withheld_d%d' % (prefix, L + 1), cseq, (we - L - 1) & 0xffffffff, R_WITHHOLD)
            self._probe('%s_LIMITATION_prestart_withheld_d%d' % (prefix, IMAGE), cseq, (we - IMAGE) & 0xffffffff, R_WITHHOLD)
            self._probe('%s_before_maximage_d%d' % (prefix, IMAGE + 1), cseq, (we - IMAGE - 1) & 0xffffffff, R_STALE)

    def c5_delayed_pure_ack(self):
        """C5 on the INTEGRATED path. Commit a READ image (outstanding), then an outstation pure ACK whose seq is
        the image's NATIVE START (sent before the response, delivered after it). Pass iff nothing mis-mapped
        leaves the switch: any frame emitted toward the master must carry the image's WIRE START (wend - 141);
        no emission at all is recorded as the disposition with the E outcome-counter delta (0 = never reached
        E, i.e. refused upstream). Control: a pure ACK at the native END must be forwarded at the wire END."""
        cseq, nsq, wsq = self.handshake(31000, 31800, 'c5_')   # ISN unused by the cases above (N refuses a repeated SYN)
        native_start, wire_start = nsq, wsq
        cseq, nsq, we, _s, _L = self._commit_read(cseq, nsq, wsq, 'c5rd')
        before = self.e_counts()
        pkt = self.v.packet(16, native_start, cseq, reverse=True)
        got = self.m.exchange(self.relay.dev_port, pkt, self.ports, timeout=3, quiet=.15)
        after = self.e_counts()
        delta = {c: after.get(c, 0) - before.get(c, 0) for c in range(16) if after.get(c, 0) != before.get(c, 0)}
        frames = [f for fs in got.values() for f in fs]
        expected = self.v.packet(16, wire_start, cseq, reverse=True)
        ok = all(bytes(f) == bytes(expected) for f in frames)
        self.report.add('c5_delayed_pure_ack_native_start', 'no mis-mapped emission (any frame == wire start)',
                        'frames %d, E outcome deltas %s, all_wire_start=%s' % (len(frames), delta, ok),
                        ok=ok, sent=pkt, received=got)
        print('  c5 delayed pure ACK at native start: frames=%d E-deltas=%s ok=%s' % (len(frames), delta, ok))
        self.exchange('c5_control_pure_ack_native_end', self.v.packet(16, nsq, cseq, reverse=True),
                      self.v.packet(16, we, cseq, reverse=True), reverse=True)
        self._retire(cseq, we, 'c5rd')
        self.close(cseq, nsq, we, 'c5_close')

    def run(self):
        if TWO_READ:
            return self.run_two()
        cseq, nsq, wsq = self.handshake(1000, 1800, 'rd_')
        cseq, nsq, we, _s, L = self._commit_read(cseq, nsq, wsq, 'rd')
        self._bound('READ141', cseq, we, L)
        self.close(cseq, nsq, we, 'rd_close')
        cseq, nsq, wsq = self.handshake(5000, 5800, 'sb_')
        cseq, nsq, we, _s, L = self._commit_sbo(cseq, nsq, wsq, 'sb')
        self._bound('SBO61', cseq, we, L)
        self.close(cseq, nsq, we, 'sb_close')
        for i, order in enumerate((('read', 'sbo'), ('sbo', 'read'), ('read', 'read'), ('sbo', 'sbo'))):
            cseq, nsq, wsq = self.handshake(9000 + 4000 * i, 9800 + 4000 * i, 'tr%d_' % i)
            first = self._commit_read if order[0] == 'read' else self._commit_sbo
            second = self._commit_read if order[1] == 'read' else self._commit_sbo
            cseq, nsq, we, _s, _L = first(cseq, nsq, wsq, 'tr%da' % i)
            self._retire(cseq, we, 'tr%da' % i)
            cseq, nsq, we, _s, L = second(cseq, nsq, we, 'tr%db' % i)
            self._bound('TR_%s_to_%s_%d' % (order[0], order[1], L), cseq, we, L)
            self._retire(cseq, we, 'tr%db' % i)
            self.close(cseq, nsq, we, 'tr%d_close' % i)
        self.c5_delayed_pure_ack()


def model_main():
    h = mp.load('_pol_helpers', HERE / 'model_drive_composite.py')
    cp = mp.load('_pol_cp', HERE / 'cp.py')
    out = Path(os.environ['OUT'])
    mode = os.environ.get('POLICY_CASE', 'interleaved')
    report = h.Report(os.environ['PROG'], physical=False, scope='m12 policy (read_complete_01 phase A) %s gate' % mode,
                      driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    gate = None
    try:
        cls = PolicyGate if mode == 'interleaved' else PolicyBoundaryGate
        gate = cls(report, h.Model(ports=[], enable=False), h, cp)
        gate.configure()
        gate.run_interleaved() if mode == 'interleaved' else gate.run()
    except Exception:
        report.add('exception', 'none', traceback.format_exc(), ok=False)
    if gate is not None:
        import pcaptk
        for name, packets in gate.captures.items():
            pcaptk.write_pcap(str(out / (name + '.pcap')), packets)
    return 0 if report.finish(out / 'packet_results.json') else 1


if __name__ == '__main__':
    raise SystemExit(model_main())

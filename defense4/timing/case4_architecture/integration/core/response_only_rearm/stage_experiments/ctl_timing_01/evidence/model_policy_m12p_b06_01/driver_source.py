"""Compiled-model gate for the read_complete_01 policy build (phase A): range READ 49 -> 141 + SBO 37 -> 61.

Expected READ bytes are rebuilt from read_complete_01/vectors/constants.json (derived from the reference
encoder and proven byte-equal to general_read_padding.pad_read on 512 natives); each model egress is also
decoded independently: one reassembled fragment, original points as the suffix, 64 synthetic G1V2 points
(indices 1024..1087, flags/value 0) as the prefix. Cases:
  A. interleaved READ -> SELECT -> OPERATE -> READ cycles on ONE connection (both size transitions, both
     directions, repeated), each response mapped to its own image with per-response seq/ack translation;
  B. C3 committed-image ACK boundary for BOTH images (READ 141, SBO 61), alone and right after a transition
     in each direction: d = image -> withhold (10), d = image + 1 -> stale (11), d = 0 -> translate (9);
  C. C5: a delayed outstation pure ACK carrying the native START of the committed READ image maps to the
     wire START (wend - 141), not the wire end.
Timing disabled here (encoding/mapping gate); timing-enabled mixed traffic is control_timing's job.
Run: python3 run_model.py <build> policy N --milestone m12
"""
import hashlib
import json
import os
import sys
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
REARM = HERE.parents[1]
sys.path[:0] = [str(HERE)]
import model_packets as mp  # noqa: E402
import model_prefix as pfx  # noqa: E402
import model_fullread_boundary as fb  # noqa: E402

std = mp.std
C = json.loads((HERE.parent / 'read_complete_01/vectors/constants.json').read_text())['shapes']['range_g10v2_23']
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


class PolicyGate(pfx.PrefixGate):
    def check_prefix_image(self, name, native, image):
        frames = pfx.po._split_frames(image)
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

    def read(self, cseq, nsq, wsq, k):
        statuses = [((k * 11 + j * 17) & 0xff) | (0x80 if j in (0, 7, 22) else 0) for j in range(23)]
        return self.read_exchange('read_%03d' % k, cseq, nsq, wsq, seq=k & 63, statuses=statuses,
                                  iin=bytes([0x80 if k & 1 else 0, k & 0x10]))

    def sbo(self, cseq, nsq, wsq, k, fc):
        return self.control_exchange('%s_%03d' % ('select' if fc == 3 else 'operate', k), cseq, nsq, wsq,
                                     seq=k & 63, app=k & 0x0f, fc=fc, index=1 + (k & 7), code=1 + (k & 7),
                                     count=1, on=0x1000 + k * 3, off=0x2000 + k * 5)

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


class PolicyBoundaryGate(PolicyGate):
    e_counts = fb.BoundaryGate.e_counts
    _probe = fb.BoundaryGate._probe
    _boundary = fb.BoundaryGate._boundary
    _retire = fb.BoundaryGate._retire
    _commit_sbo = fb.BoundaryGate._commit_sbo

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

    def c5_delayed_pure_ack(self):
        """Commit a READ image (left outstanding), then the outstation's pure ACK whose seq is the image's
        NATIVE START (sent before the response, delivered after it): its wire seq must be the image's wire
        start, wsq_before = we - IMAGE."""
        cseq, nsq, wsq = self.handshake(17000, 17800, 'c5_')
        native_start, wire_start = nsq, wsq
        cseq, nsq, we, _s, _L = self._commit_read(cseq, nsq, wsq, 'c5rd')
        self.exchange('c5_delayed_pure_ack_native_start',
                      self.v.packet(16, native_start, cseq, reverse=True),
                      self.v.packet(16, wire_start, cseq, reverse=True), reverse=True)
        self._retire(cseq, we, 'c5rd')
        self.close(cseq, nsq, we, 'c5_close')

    def run(self):
        cseq, nsq, wsq = self.handshake(1000, 1800, 'rd_')
        cseq, nsq, we, _s, L = self._commit_read(cseq, nsq, wsq, 'rd')
        self._boundary('READ141', cseq, we, L)
        self.close(cseq, nsq, we, 'rd_close')
        cseq, nsq, wsq = self.handshake(5000, 5800, 'sb_')
        cseq, nsq, we, _s, L = self._commit_sbo(cseq, nsq, wsq, 'sb')
        self._boundary('SBO61', cseq, we, L)
        self.close(cseq, nsq, we, 'sb_close')
        for i, order in enumerate((('read', 'sbo'), ('sbo', 'read'), ('read', 'read'), ('sbo', 'sbo'))):
            cseq, nsq, wsq = self.handshake(9000 + 4000 * i, 9800 + 4000 * i, 'tr%d_' % i)
            first = self._commit_read if order[0] == 'read' else self._commit_sbo
            second = self._commit_read if order[1] == 'read' else self._commit_sbo
            cseq, nsq, we, _s, _L = first(cseq, nsq, wsq, 'tr%da' % i)
            self._retire(cseq, we, 'tr%da' % i)
            cseq, nsq, we, _s, L = second(cseq, nsq, we, 'tr%db' % i)
            self._boundary('TR_%s_to_%s_%d' % (order[0], order[1], L), cseq, we, L)
            self._retire(cseq, we, 'tr%db' % i)
            self.close(cseq, nsq, we, 'tr%d_close' % i)
        self.c5_delayed_pure_ack()


def model_main():
    h = mp.load('_pol_helpers', REARM.parent / 'response_only/model_drive_composite.py')
    cp = mp.load('_pol_cp', REARM / 'cp.py')
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

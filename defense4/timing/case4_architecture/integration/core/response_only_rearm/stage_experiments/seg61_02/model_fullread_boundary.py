"""C3 committed-image ACK-boundary regression for the full-READ (247->269) candidate.

The review found that capping the classify_rev withhold ladder classified a LEGITIMATE ACK of the image
START (m.r = -image, e.g. a duplicate ACK / window probe on a lost response) as STALE and dropped it. The
fix makes classify_rev cover the FULL committed image: m.r in [-image, -1] -> rev_withhold (result 10),
m.r < -image -> rev_drop STALE (result 11), m.r >= 0 -> rev_translate (result 9).

This driver COMMITS a 269 image (left outstanding), then drives master->outstation ACKs across the
boundary and reads the EXISTING E `outcome` counter (p0.r_Egress.outcome, indexed by m.result) to see
which classification each ACK receives -- withhold (admitted) vs stale-drop. This establishes the
CLASSIFICATION boundary (the C3 defect), not end-to-end delivery. We do NOT infer disposition from an
empty external capture; the counter delta is the evidence. Timing disabled. One fresh connection per case
(the N incarnation guard rejects a new SYN while a connection is live).

  m.r = 0    (ack=image_end)    -> expect result 9  (translate)
  m.r = -1   (ack=end-1)        -> expect result 10 (withhold, within image)
  m.r = -269 (ack=image_start)  -> expect result 10 (withhold) -- the C3 fix (was stale-dropped under the cap)
  m.r = -270 (ack=start-1)      -> expect result 11 (stale drop, strictly before the image)

Run: python3 run_model.py <full build> fullread_boundary N --milestone m12
"""
import hashlib
import os
import sys
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
REARM = HERE.parents[1]
CORE = HERE.parents[2]
sys.path[:0] = [str(HERE), str(CORE)]
import model_packets as mp  # noqa: E402
import model_fullread as fr  # noqa: E402

R_TRANSLATE, R_WITHHOLD, R_STALE = 9, 10, 11


class BoundaryGate(fr.FullReadGate):
    def e_counts(self):
        """Read the E outcome counter (p0.r_Egress.outcome) indexed by m.result -> {code: packets}.
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

    def _commit_read(self, cseq, nsq, wsq, tag):
        """Request + server ack + full READ response (247->269), image left OUTSTANDING. Returns advanced
        (cseq, nsq, wsq) and the committed image's wire start (= wsq before the response)."""
        req = fr.integrity_request(0)
        self.exchange(tag + '_request', self.v.packet(24, cseq, wsq, payload=req),
                      self.v.packet(24, cseq, nsq, payload=req))
        ack = self.rs.ack_packet(seq=nsq, ack=cseq + fr.INTEGRITY_REQ_NATIVE)
        self.exchange(tag + '_server_ack', ack, self.rs.ack_packet(seq=wsq, ack=cseq + fr.INTEGRITY_REQ_NATIVE), reverse=True)
        cseq += fr.INTEGRITY_REQ_NATIVE
        native = fr.full_native(0)
        image, _info = fr.pp.prepend_padding(native, fr.IMAGE)
        self.exchange(tag + '_response', self.v.packet(24, nsq, cseq, reverse=True, payload=native),
                      self.v.packet(24, wsq, cseq, reverse=True, payload=image), reverse=True)
        img_start = wsq
        return cseq, nsq + fr.FULL_NATIVE, wsq + fr.IMAGE, img_start, fr.IMAGE

    def _commit_sbo(self, cseq, nsq, wsq, tag, seq=0):
        """SELECT/OPERATE request + 61-byte control response (37->61), image left OUTSTANDING."""
        req = mp.control_request(seq=seq, app=seq & 0xf, fc=3, index=1, code=1, count=1, on=0x1000, off=0x2000)
        self.exchange(tag + '_request', self.v.packet(24, cseq, wsq, payload=req),
                      self.v.packet(24, cseq, nsq, payload=req))
        native = mp.control_response(seq=seq, app=seq & 0xf, fc=3, index=1, code=1, count=1, on=0x1000, off=0x2000)
        image = mp.encode61.ctl61(native)
        self.exchange(tag + '_response61', self.v.packet(24, nsq, cseq + mp.CONTROL_REQUEST, reverse=True, payload=native),
                      self.v.packet(24, wsq, cseq + mp.CONTROL_REQUEST, reverse=True, payload=image), reverse=True)
        img_start = wsq
        return cseq + mp.CONTROL_REQUEST, nsq + mp.CONTROL_NATIVE, wsq + mp.IMAGE_LEN, img_start, mp.IMAGE_LEN

    def _retire(self, cseq, we, tag):
        """Ack the full outstanding image (d=0 -> translate/forward), advancing the connection frontier so
        the next request/response can commit on the SAME connection (the transition cases)."""
        self._probe(tag + '_retire', cseq, we, R_TRANSLATE)

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

    def run(self):
        # 1) READ boundary (fresh connection): d=269 withhold, d=270 stale.
        cseq, nsq, wsq = self.handshake(1000, 1800, 'rd_')
        cseq, nsq, we, _s, L = self._commit_read(cseq, nsq, wsq, 'rd')
        self._boundary('READ', cseq, we, L)
        self.close(cseq, nsq, we, 'rd_close')
        # 2) SBO boundary (fresh connection): d=61 withhold, d=62 stale.
        cseq, nsq, wsq = self.handshake(5000, 5800, 'sb_')
        cseq, nsq, we, _s, L = self._commit_sbo(cseq, nsq, wsq, 'sb')
        self._boundary('SBO', cseq, we, L)
        self.close(cseq, nsq, we, 'sb_close')
        # 3) transition 269->61 on ONE connection: commit+retire READ, then outstanding SBO, probe SBO.
        cseq, nsq, wsq = self.handshake(9000, 9800, 'tr1_')
        cseq, nsq, we, _s, _L = self._commit_read(cseq, nsq, wsq, 'tr1rd')
        self._retire(cseq, we, 'tr1rd')
        cseq, nsq, we, _s, L = self._commit_sbo(cseq, nsq, we, 'tr1sb')
        self._boundary('TR_269to61_SBO', cseq, we, L)
        self.close(cseq, nsq, we, 'tr1_close')
        # 4) transition 61->269 on ONE connection: commit+retire SBO, then outstanding READ, probe READ.
        cseq, nsq, wsq = self.handshake(13000, 13800, 'tr2_')
        cseq, nsq, we, _s, _L = self._commit_sbo(cseq, nsq, wsq, 'tr2sb')
        self._retire(cseq, we, 'tr2sb')
        cseq, nsq, we, _s, L = self._commit_read(cseq, nsq, we, 'tr2rd')
        self._boundary('TR_61to269_READ', cseq, we, L)
        self.close(cseq, nsq, we, 'tr2_close')


def model_main():
    h = mp.load('_fb_helpers', REARM.parent / 'response_only/model_drive_composite.py')
    cp = mp.load('_fb_cp', REARM / 'cp.py')
    out = Path(os.environ['OUT'])
    report = h.Report(os.environ['PROG'], physical=False, scope='m12 full-READ C3 committed-image ACK boundary (outcome-counter classification)',
                      driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    gate = None
    try:
        gate = BoundaryGate(report, h.Model(ports=[], enable=False), h, cp)
        gate.configure()
        gate.run()
    except Exception:
        report.add('exception', 'none', traceback.format_exc(), ok=False)
    if gate is not None:
        import pcaptk
        for name, packets in gate.captures.items():
            pcaptk.write_pcap(str(out / (name + '.pcap')), packets)
    return 0 if report.finish(out / 'packet_results.json') else 1


if __name__ == '__main__':
    raise SystemExit(model_main())

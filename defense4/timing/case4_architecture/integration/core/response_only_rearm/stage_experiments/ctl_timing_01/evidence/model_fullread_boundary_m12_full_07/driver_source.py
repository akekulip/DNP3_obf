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

    def _commit_image(self, base, tag):
        """Handshake + request + server ack + full response on a FRESH connection, image left OUTSTANDING."""
        cseq, nsq, wsq = self.handshake(base, base + 800, tag + '_')
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
        return cseq, nsq, wsq

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

    def run(self):
        cases = [('end_mr0',      0,          R_TRANSLATE),
                 ('within_mr-1',  1,          R_WITHHOLD),
                 ('within_mr-100', 100,       R_WITHHOLD),
                 ('start_mr-269', fr.IMAGE,   R_WITHHOLD),   # image START -- the C3 fix
                 ('before_mr-270', fr.IMAGE+1, R_STALE),     # strictly before the image
                 ('before_mr-299', fr.IMAGE+30, R_STALE)]
        for i, (name, d, expect_code) in enumerate(cases):
            cseq, nsq, wsq = self._commit_image(1000 + i * 4000, name)
            ack = (wsq + fr.IMAGE - d) & 0xffffffff
            self._probe(name, cseq, ack, expect_code)
            self.close(cseq, nsq + fr.FULL_NATIVE, wsq + fr.IMAGE, name + '_close')


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

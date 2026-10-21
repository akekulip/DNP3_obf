"""C2 corruption regression for the full-READ shallow-parse admission.

Demonstrates the HONEST admission: the switch validates what it parses (link + block0 DNP3 CRCs) and
forwards the rest endpoint-owned. Three cases, each on a fresh connection:
  (a) bad first-block CRC            -> DROPPED (the switch's validated scope; bcrc != 0x993a).
  (b) bad TCP checksum, block0 OK    -> FORWARDED (whole-segment TCP checksum uncomputable under the
                                        shallow parse, waived; the master's TCP rejects it -> retransmit).
  (c) bad DNP3 tail CRC, valid TCP   -> FORWARDED (tail endpoint-owned; the master's DNP3 app rejects it).
A clean control case confirms forwarding on an intact response. This shows the fabricated-success bypass
is gone: a corrupt block0 is no longer admitted, while tail/TCP-checksum corruption is forwarded (not
silently validated) for endpoint recovery. Timing disabled (admission behaviour only).
Run: python3 run_model.py <full build> fullread_corrupt N --milestone m12
"""
import hashlib
import os
import sys
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
REARM = HERE.parents[1]
sys.path[:0] = [str(HERE)]
import model_packets as mp  # noqa: E402
import model_fullread as fr  # noqa: E402

TCP_CKSUM_OFF = 14 + 20 + 16  # eth(14)+ip(20)+tcp cksum field at tcp offset 16 (response has no options)


class CorruptGate(fr.FullReadGate):
    def _case(self, name, base, seq, corrupt_payload, corrupt_packet, expect_forward):
        cseq, nsq, wsq = self.handshake(base, base + 800, name + '_')
        req = fr.integrity_request(seq)
        self.exchange(name + '_request', self.v.packet(24, cseq, wsq, payload=req),
                      self.v.packet(24, cseq, nsq, payload=req))
        ack = self.rs.ack_packet(seq=nsq, ack=cseq + fr.INTEGRITY_REQ_NATIVE)
        self.exchange(name + '_server_ack', ack, self.rs.ack_packet(seq=wsq, ack=cseq + fr.INTEGRITY_REQ_NATIVE), reverse=True)
        cseq += fr.INTEGRITY_REQ_NATIVE
        native = fr.full_native(seq)
        if corrupt_payload:
            native = corrupt_payload(native)
        pkt = self.v.packet(24, nsq, cseq, reverse=True, payload=native)
        if corrupt_packet:
            pkt = corrupt_packet(pkt)
        got = self.m.exchange(self.relay.dev_port, pkt, self.ports, timeout=3, quiet=.15)
        flat = [f for fs in got.values() for f in fs]
        self.add(name, 'forward' if expect_forward else 'drop', 'forward' if flat else 'drop',
                 ok=(bool(flat) == expect_forward), sent=pkt, received=got)
        # close this connection before the next case (the N incarnation guard rejects a new SYN while the
        # prior connection is live). A forwarded full response advanced the image by 247 native / 269 wire.
        if flat:
            nsq += fr.FULL_NATIVE
            wsq += fr.IMAGE
        self.close(cseq, nsq, wsq, name + '_close')

    def run(self):
        flip = lambda off: (lambda b: b[:off] + bytes([b[off] ^ 0xff]) + b[off + 1:])
        # (control) intact response -> forwarded
        self._case('clean', 1000, 5, None, None, True)
        # (a) bad first-block CRC (flip a block0 data byte; link/TCP checksum stay valid) -> DROP
        self._case('bad_block0', 2000, 6, flip(12), None, False)
        # (b) bad TCP checksum (block0 intact) -> FORWARD (endpoint TCP rejects)
        self._case('bad_tcp_cksum', 3000, 7, None, flip(TCP_CKSUM_OFF), True)
        # (c) bad DNP3 tail CRC, valid TCP checksum (flip a tail byte >28; packet checksum recomputed) -> FORWARD
        self._case('bad_tail_crc', 4000, 8, flip(120), None, True)


def model_main():
    h = mp.load('_cc_helpers', REARM.parent / 'response_only/model_drive_composite.py')
    cp = mp.load('_cc_cp', REARM / 'cp.py')
    out = Path(os.environ['OUT'])
    report = h.Report(os.environ['PROG'], physical=False, scope='m12 full-READ C2 corruption admission',
                      driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    gate = None
    try:
        gate = CorruptGate(report, h.Model(ports=[], enable=False), h, cp)
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

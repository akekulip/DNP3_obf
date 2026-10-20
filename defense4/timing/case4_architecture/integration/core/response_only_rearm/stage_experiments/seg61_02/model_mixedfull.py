"""Mixed FULL READ (247->269) + SBO (37->61) one-connection model gate -- the final NOMAD deliverable.

Proves the variable-image candidate carries the full integrity READ at wire 269 and SELECT/OPERATE at
wire 61 on ONE connection, each mapped to its own size with correct per-response seq/ack translation.
Mirrors the shipped packets-gate structure the N work-generation lifecycle requires (read block seq
0..63, then control block), with the full READ (model_fullread) instead of the old re-encode. Timing
disabled. Run: python3 run_model.py <full build> mixedfull N --milestone m12
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


class MixedFullGate(fr.FullReadGate):
    def run(self):
        cseq, nsq, wsq = self.handshake(100, 900, 'base_')
        for seq in range(64):
            cseq, nsq, wsq = self.full_read_exchange('full_%02d' % seq, cseq, nsq, wsq, seq=seq)
        for seq in range(64):
            cseq, nsq, wsq = self.control_exchange('sbo_%02d' % seq, cseq, nsq, wsq, seq=seq,
                                                   app=seq & 0x0f, fc=3 + (seq & 1), index=1 + seq // 2,
                                                   code=1 + ((seq // 2) & 0x0f), count=1,
                                                   on=0x1000 + (seq // 2) * 3, off=0x2000 + (seq // 2) * 5)
        self.close(cseq, nsq, wsq, 'close')


def model_main():
    h = mp.load('_mf_helpers', REARM.parent / 'response_only/model_drive_composite.py')
    cp = mp.load('_mf_cp', REARM / 'cp.py')
    out = Path(os.environ['OUT'])
    report = h.Report(os.environ['PROG'], physical=False, scope='m12 mixed full-READ 269 + SBO 61 one-connection gate',
                      driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    gate = None
    try:
        gate = MixedFullGate(report, h.Model(ports=[], enable=False), h, cp)
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

"""Mixed READ(73) + SBO(61) one-connection model gate for the VARIABLE-image mapper (m12, step 1).

This is the real proof that the per-response variable image carries TWO different wire sizes on ONE
connection: a range READ padded to 73 (prefix construction) and a SELECT/OPERATE response reframed to 61
(the m11_09 SBO path), interleaved, with the forward seq advancing by each response's own encoded length
and the reverse ACKs translating wire->native per response (wire+73->native+49, wire+61->native+37).

Reuses PrefixGate from model_prefix (prefix read_exchange @73) and its inherited control_exchange (@61)
from model_packets. Timing is disabled (encoding/mapping validation only). Run:
  python3 run_model.py <build> mixed N --milestone m12
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
import model_prefix as pfx  # noqa: E402


class MixedGate(pfx.PrefixGate):
    def run(self):
        cseq, nsq, wsq = self.handshake(100, 900, 'base_')
        # Mirror the shipped packets-gate structure (read block seq 0..63, then control block), which
        # the N work-generation lifecycle requires to bind control requests -- but with the PREFIX read
        # (73) instead of the old re-encode (61). This is the mixed READ(73)+SBO(61) one-connection proof.
        for seq in range(64):
            statuses = [((seq * 11 + j * 17) & 0xff) | (0x80 if j in (0, 7, 22) else 0) for j in range(23)]
            cseq, nsq, wsq = self.read_exchange('read_seq_%02d' % seq, cseq, nsq, wsq, seq=seq,
                                                statuses=statuses, iin=bytes([0x80 if seq & 1 else 0, seq & 0x10]))
        for seq in range(64):
            cseq, nsq, wsq = self.control_exchange('sbo_seq_%02d' % seq, cseq, nsq, wsq, seq=seq,
                                                   app=seq & 0x0f, fc=3 + (seq & 1), index=1 + seq // 2,
                                                   code=1 + ((seq // 2) & 0x0f), count=1,
                                                   on=0x1000 + (seq // 2) * 3, off=0x2000 + (seq // 2) * 5)
        self.close(cseq, nsq, wsq, 'close')


def model_main():
    h = mp.load('_mixed_helpers', REARM.parent / 'response_only/model_drive_composite.py')
    cp = mp.load('_mixed_cp', REARM / 'cp.py')
    out = Path(os.environ['OUT'])
    report = h.Report(os.environ['PROG'], physical=False, scope='m12 mixed READ73+SBO61 one-connection gate',
                      driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    gate = None
    try:
        gate = MixedGate(report, h.Model(ports=[], enable=False), h, cp)
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

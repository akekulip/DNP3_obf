"""Compiled-model packet gate for the m12 READ PREFIX padder (range READ 49 -> 73).

Reuses model_packets' PacketGate harness (handshake, control plane, exchange/capture) but drives the
READ with the prefix construction (prepend.py) at IMAGE=73 and checks the model's ACTUAL egress bytes:
byte-exact equality to the prefix-encoded packet (which proves the link CRCs, the Hash-derived block
CRCs and the TCP/IP checksums), reassembly into one fragment with the padding points as the PREFIX and
the originals as the suffix, and correct reverse-ACK mapping (wire+73 -> native+49).

Run under launch_model.sh (via run_model.py <build> prefix N --milestone m12).
"""
import hashlib
import os
import sys
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
REARM = HERE.parents[1]
sys.path[:0] = [str(HERE), str(HERE.parent / 'read_reencode_01'), str(HERE.parent / 'full_read_01')]
import model_packets as mp  # noqa: E402
import dnp3_std as std  # noqa: E402
import pad_oracle as po  # noqa: E402
import prepend as pp  # noqa: E402

IMAGE = 73


class PrefixGate(mp.PacketGate):
    def check_prefix_image(self, name, native, image):
        frames = po._split_frames(image)
        frags, events = std.reassemble(frames)
        self.add(name + '_reassembles', (1, []), (len(frags), events))
        app = frags[0][0]
        _, pts = std.check_read_response(std.fragment_user(app))
        _, orig = std.check_read_response(std.deframe(native)[1])
        npad = len(pts) - len(orig)
        self.add(name + '_originals_are_suffix', orig, pts[npad:])
        self.add(name + '_padding_is_prefix', True,
                 all(g == 1 and v == 2 and d == b'\x00' for g, v, _i, d in pts[:npad]))

    def read_exchange(self, name, cseq, native_sseq, wire_sseq, seq=0, statuses=None,
                      iin=b'\x80\x00', expect_growth=True):
        request = self.rs.request_packet(seq=cseq, ack=wire_sseq, app=0xc0 | (seq & 15))
        self.exchange(name + '_request', request, self.rs.request_packet(seq=cseq, ack=native_sseq, app=0xc0 | (seq & 15)))
        ack = self.rs.ack_packet(seq=native_sseq, ack=cseq + 20)
        self.exchange(name + '_server_ack', ack, self.rs.ack_packet(seq=wire_sseq, ack=cseq + 20), reverse=True)
        native = mp.read_frame(seq, statuses, app=0xc0 | (seq & 0x0f), iin=iin)
        image, _info = pp.prepend_padding(native, IMAGE)
        self.check_prefix_image(name, native, image)              # independent oracle on the EXPECTED bytes
        got = self.exchange(name + '_response',
                            self.v.packet(24, native_sseq, cseq + 20, reverse=True, payload=native),
                            self.v.packet(24, wire_sseq, cseq + 20, reverse=True, payload=image),
                            reverse=True)
        self.add(name + '_payload_len', IMAGE, len(mp.tcp_payload(got)))
        self.check_prefix_image(name + '_wire', native, mp.tcp_payload(got))
        if expect_growth:
            self.exchange(name + '_mapped_ack',
                          self.v.packet(16, cseq + 20, wire_sseq + IMAGE),
                          self.v.packet(16, cseq + 20, native_sseq + mp.READ_NATIVE))
        return cseq + 20, native_sseq + mp.READ_NATIVE, wire_sseq + IMAGE
        # the model's own output bytes re-checked by the independent oracle
        self.check_prefix_image(name + '_wire', native, mp.tcp_payload(got))
        if expect_growth:
            self.exchange(name + '_mapped_ack',
                          self.v.packet(16, cseq + 20, wire_sseq + IMAGE),
                          self.v.packet(16, cseq + 20, native_sseq + mp.READ_NATIVE))
        return cseq + 20, native_sseq + mp.READ_NATIVE, wire_sseq + IMAGE

    def run(self):
        cseq, native_sseq, wire_sseq = self.handshake(100, 900, 'base_')
        for seq in (0, 1, 7, 31, 62, 63):
            statuses = [((seq * 11 + i * 17) & 0xff) | (0x80 if i in (0, 7, 22) else 0) for i in range(23)]
            cseq, native_sseq, wire_sseq = self.read_exchange(
                'read_seq_%02d' % seq, cseq, native_sseq, wire_sseq, seq=seq, statuses=statuses,
                iin=bytes([0x80 if seq & 1 else 0, seq & 0x10]))
        self.close(cseq, native_sseq, wire_sseq, 'close')


def model_main():
    h = mp.load('_prefix_helpers', REARM.parent / 'response_only/model_drive_composite.py')
    cp = mp.load('_prefix_cp', REARM / 'cp.py')
    out = Path(os.environ['OUT'])
    report = h.Report(os.environ['PROG'], physical=False, scope='m12 READ prefix packet gate',
                      driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    gate = None
    try:
        gate = PrefixGate(report, h.Model(ports=[], enable=False), h, cp)
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

"""Compiled-model packet gate for the FULL integrity READ (247 -> 269) prefix padder.

Sends the real 247-byte integrity READ response (re-sequenced per exchange) and checks the model's egress
is byte-exact to prepend_padding(native, 269): the +22-byte leading padding frame + the continuation
(first block rewritten, 219-byte tail verbatim), all CRCs valid, and the reassembled fragment carries the
synthetic g1 padding points as a PREFIX with the outstation's original objects preserved as the suffix.
Reverse ACK maps wire+269 -> native+247. Timing disabled (encoding/mapping validation only).

Run: python3 run_model.py <build> fullread N --milestone m12
"""
import hashlib
import os
import sys
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
REARM = HERE.parents[1]
STAGE = HERE.parent
sys.path[:0] = [str(HERE), str(STAGE / 'full_read_01'), str(STAGE / 'read_reencode_01')]
import model_packets as mp  # noqa: E402
import model_prefix as pfx  # noqa: E402
import dnp3_std as std  # noqa: E402
import prepend as pp  # noqa: E402
import fullread as fr  # noqa: E402

IMAGE = 269
FULL_NATIVE = 247

# the captured integrity response frame (header + user), re-sequenced per exchange
_t = fr.transactions(str(STAGE / 'full_read_01/evidence/native_integrity_base/capture.pcap'))[0]
_CAP = bytes.fromhex(_t['response_frames_hex'][0])
_HDR, _USER = std.deframe(_CAP)


def full_native(seq):
    """The 247-byte integrity response rebuilt with transport sequence `seq` (FIR+FIN). The link src is
    re-addressed to 0 to match the model's configured read_connection (link_dst=1/link_src=0, the same as
    the range read); the capture's src=10 would otherwise set m.badh and miss the guard."""
    hdr = _HDR[:6] + b'\x00\x00'               # keep start/len/ctrl/dst(=1), set src=0
    user = bytearray(_USER)
    user[0] = 0xc0 | (seq & 0x3f)              # transport octet FIR+FIN+seq
    user[1] = (user[1] & 0xf0) | (seq & 0x0f)  # app-control seq nibble (read req/resp matching keys on it)
    native = std.frame(hdr, bytes(user))
    assert len(native) == FULL_NATIVE, len(native)
    return native


INTEGRITY_REQ_NATIVE = 27  # 27-byte integrity READ request (G60V2/V3/V4/V1 qual 0x06)


def integrity_request(seq):
    """The real 27-byte integrity READ request, addressed like the model's range request (dl dst=0/src=1,
    ctrl 0xc4) so read_connection/badh match, with the app-control seq nibble set to `seq`."""
    user = bytes([0xc0 | (seq & 0x3f), 0xc0 | (seq & 0x0f), 0x01,
                  0x3c, 0x02, 0x06, 0x3c, 0x03, 0x06, 0x3c, 0x04, 0x06, 0x3c, 0x01, 0x06])
    head = bytes.fromhex('0564') + bytes([5 + len(user)]) + bytes([0xc4]) + (0).to_bytes(2, 'little') + (1).to_bytes(2, 'little')
    frame = std.frame(head, user)
    assert len(frame) == INTEGRITY_REQ_NATIVE, len(frame)
    return frame


class FullReadGate(pfx.PrefixGate):
    def full_read_exchange(self, name, cseq, native_sseq, wire_sseq, seq=0):
        req = integrity_request(seq)
        self.exchange(name + '_request', self.v.packet(24, cseq, wire_sseq, payload=req),
                      self.v.packet(24, cseq, native_sseq, payload=req))
        ack = self.rs.ack_packet(seq=native_sseq, ack=cseq + INTEGRITY_REQ_NATIVE)
        self.exchange(name + '_server_ack', ack, self.rs.ack_packet(seq=wire_sseq, ack=cseq + INTEGRITY_REQ_NATIVE), reverse=True)
        cseq += INTEGRITY_REQ_NATIVE
        native = full_native(seq)
        image, _info = pp.prepend_padding(native, IMAGE)
        self.add(name + '_image_len', IMAGE, len(image))
        self.check_prefix_image(name, native, image)              # oracle on the EXPECTED bytes
        got = self.exchange(name + '_response',
                            self.v.packet(24, native_sseq, cseq, reverse=True, payload=native),
                            self.v.packet(24, wire_sseq, cseq, reverse=True, payload=image),
                            reverse=True)
        self.add(name + '_payload_len', IMAGE, len(mp.tcp_payload(got)))
        self.check_prefix_image(name + '_wire', native, mp.tcp_payload(got))   # model's OWN output bytes
        self.exchange(name + '_mapped_ack',
                      self.v.packet(16, cseq, wire_sseq + IMAGE),
                      self.v.packet(16, cseq, native_sseq + FULL_NATIVE))
        return cseq, native_sseq + FULL_NATIVE, wire_sseq + IMAGE

    def run(self):
        cseq, nsq, wsq = self.handshake(100, 900, 'base_')
        for seq in (0, 1, 7, 31, 62, 63):
            cseq, nsq, wsq = self.full_read_exchange('full_%02d' % seq, cseq, nsq, wsq, seq=seq)
        self.close(cseq, nsq, wsq, 'close')


def model_main():
    h = mp.load('_fr_helpers', REARM.parent / 'response_only/model_drive_composite.py')
    cp = mp.load('_fr_cp', REARM / 'cp.py')
    out = Path(os.environ['OUT'])
    report = h.Report(os.environ['PROG'], physical=False, scope='m12 full READ 247->269 prefix gate',
                      driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    gate = None
    try:
        gate = FullReadGate(report, h.Model(ports=[], enable=False), h, cp)
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

"""Harness glue for the M canary: source-level interpreter plus the independent oracles."""
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ARCH = HERE.parents[3]
sys.path.insert(0, str(ARCH / 'integration/core/harness'))
sys.path.insert(0, str(ARCH.parent / 'framework/size'))

from driver import Config, Pipeline  # noqa: E402
import vectors  # noqa: E402
import case4_padding  # noqa: E402
import case4_transport  # noqa: E402
from scapy.layers.inet import IP, TCP  # noqa: E402
from scapy.layers.l2 import Ether  # noqa: E402
from scapy.packet import Raw  # noqa: E402

import os
SOURCE = Path(os.environ.get('M_SOURCE', HERE.parent / 'm_skeleton.p4'))  # M_SOURCE: mutation checks only
# These existing control-path cases arrive from N; READ arrivals from T use197
# and both receiving boundaries are covered by test_task1_boundaries.py.
M_IN, M_OUT = 196, 64
CLIENT, SERVER, CPORT, SPORT = '10.0.0.1', '10.0.0.2', 42000, 20000
MASK = 0xffffffff
KIND_SELECT, KIND_RESPONSE, KIND_OPERATE, KIND_FWD, KIND_REPLAY, KIND_REV = 5, 6, 7, 8, 12, 13


def envelope(epoch, generation, kind, phase=0, stage=1):
    return struct.pack('>IIIHH', epoch, generation, phase << 16, (stage << 8) | kind, 0)


def tcp_frame(payload, seq, ack, window, flags, reverse=False):
    src, dst, sport, dport = (SERVER, CLIENT, SPORT, CPORT) if reverse else (CLIENT, SERVER, CPORT, SPORT)
    return bytes(Ether(dst='00:11:22:33:44:55', src='66:77:88:99:aa:bb') /
                 IP(src=src, dst=dst, id=420, flags='DF') /
                 TCP(sport=sport, dport=dport, seq=seq, ack=ack, window=window, flags=flags) / Raw(payload))


class MPipeline(Pipeline):
    def state(self):  # the base class reads N's registers
        return {}

    def reg(self, name, index=0):
        if name == 'led_id' and ('', 'led_select_id') in self.src.cells:
            name, index = ('led_select_id' if index == 0 else 'led_operate_id'), 0
        return next(v for (path, n), v in self.src.cells.items() if n == name)[index]


def m_pipeline():
    # The interpreter hard-wires the checksum instance names 'ic' and 'tc' (harness/interp_ext.py:336).
    # Rename the M source's instances for execution only; the compiled source is untouched.
    text = SOURCE.read_text().replace('ipcheck', 'ic').replace('repaircheck', 'tc')
    # isValid() is not interpreted; the parser makes these headers valid exactly for these lengths.
    # parser_err is not interpreted either: the driver drops a parser error before the control runs.
    text = text.replace('p.parser_err==16w0', '16w0==16w0')
    text = text.replace('hdr.native.isValid()', '(hdr.ip.len==16w75)').replace('hdr.replay.isValid()', '(hdr.ip.len==16w41)')
    pipe = MPipeline(text, Config({}, []), include_dir=SOURCE.parent)
    pipe.src.install('forwarding', (M_IN,), 'route', (M_OUT,))
    ip = lambda text: int.from_bytes(bytes(int(x) for x in text.split('.')), 'big')
    pipe.src.install('connection', (ip(CLIENT), ip(SERVER), CPORT, SPORT), 'configure', (1,))
    pipe.src.install('connection', (ip(SERVER), ip(CLIENT), SPORT, CPORT), 'configure', (2,))
    return pipe


def send(pipe, kind, frame, epoch=17, generation=1, phase=0):
    out = pipe.inject(M_IN, envelope(epoch, generation, kind, phase) + frame)
    return out


def decoded(out):
    """(seq, ack, window) of the emitted frame, with the 16-byte envelope still attached."""
    assert not out.dropped, out.drop_reason
    port, raw = out.emitted[0]
    assert port == M_OUT
    ip = raw[16 + 14:]
    return struct.unpack('>III', ip[24:28] + ip[28:32] + b'\0\0' + ip[34:36]) if False else (
        struct.unpack('>I', ip[24:28])[0], struct.unpack('>I', ip[28:32])[0], struct.unpack('>H', ip[34:36])[0])


def native(fc):
    return vectors.native_select(0, fc)


def image(fc):
    return case4_padding.expand_control(native(fc), vectors.DECOY)[0]


def oracle(base):
    """Two committed images through the independent transport oracle."""
    ledger = case4_transport.RequestLedger(base)
    first = ledger.forward(base, native(3), image(3))
    second = ledger.forward((base + 35) & MASK, native(4), image(4))
    assert first.inserted and second.inserted
    return ledger, first, second

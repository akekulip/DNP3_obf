"""Whole-program helpers for the native READ kinds (9 REQ, 10 ACK, 11 RSP).

Source-level interpretation through integration/core/harness, not the compiler or ASIC. The
only text change is `p.global_tstamp` -> `ig.global_tstamp`, because the harness models the
intrinsic as an environment input; the evaluation of the timestamp is the program's own.
"""
import re
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
ARCH = HERE.parents[2]
HARNESS = ARCH / 'integration/core/harness'
sys.path[:0] = [str(HARNESS), str(ARCH.parent / 'framework/size'), str(ARCH / 'integration/connection')]
import case4_padding  # noqa: E402
import driver  # noqa: E402
import vectors  # noqa: E402

SOURCE = HERE / 'native_binding.p4'
CLIENT, SERVER, CPORT, SPORT = vectors.CLIENT, vectors.SERVER, vectors.CLIENT_PORT, vectors.SERVER_PORT
IN_CLIENT, IN_SERVER = vectors.IN_CLIENT, vectors.IN_SERVER
T0_BASE, T0_STEP = 0x123456789a, 0x1000


def handoff_port(text=None):
    """READ_HANDOFF_PORT of the given program text (default: native_binding.p4, the legacy three-pipe 325)."""
    return int(re.search(r'const\s+PortId_t\s+READ_HANDOFF_PORT\s*=\s*9w(\d+)', text or SOURCE.read_text())[1])


def request_frame(app=0xc0, dst=0x0000, src=0x0100):
    head = struct.pack('>HxBHH', 0x0564, 0xc4, dst, src)
    return case4_padding.build_frame(head, bytes([0xc0, app, 0x01, 0x0a, 0x02, 0x00, 0x00, 0x16]))


def response_frame(app=0xc0, dst=0x0100, src=0x0000):
    head = struct.pack('>HxBHH', 0x0564, 0x44, dst, src)
    return case4_padding.build_frame(head, bytes([0xc0, app, 0x81, 0x80, 0x00, 0x0a, 0x02, 0x00, 0x00, 0x16])
                                     + bytes(range(23)))


def request_packet(seq=1000, ack=2000, **kw):
    return vectors.packet(24, seq, ack, payload=request_frame(**kw))


def response_packet(seq=2000, ack=1020, **kw):
    return vectors.packet(24, seq, ack, reverse=True, payload=response_frame(**kw))


def ack_packet(seq=2000, ack=1020):
    return vectors.packet(16, seq, ack, reverse=True)


def tev(epoch, generation, t0q, kind):
    return struct.pack('>IIIBBH', epoch, generation, t0q, kind, 0, 0)


class ReadPipeline(driver.Pipeline):
    """Pipeline whose ingress timestamp advances every pass, with READ links installed."""

    def __init__(self, text=None, **kw):
        text = (text or SOURCE.read_text()).replace('p.global_tstamp', 'ig.global_tstamp')
        super().__init__(text, vectors.topology(), include_dir=HERE, **kw)
        self.src.width['ig.global_tstamp'] = 48
        self.src.install('read_connection', (CLIENT, SERVER, CPORT, SPORT), 'read_configure', (0x0000, 0x0100))
        self.src.install('read_connection', (SERVER, CLIENT, SPORT, CPORT), 'read_configure', (0x0100, 0x0000))
        self.stamps = []
        self.mutate = {}          # pass number -> callable(pipe), run just before that pass


    def run_pass(self, number, port, raw):
        if number in self.mutate:
            self.mutate[number](self)
        self.src.env['ig.global_tstamp'] = T0_BASE + T0_STEP * (number - 1) + 0x5b
        self.stamps.append(self.src.env['ig.global_tstamp'])
        return super().run_pass(number, port, raw)

    def start(self, owner, client, server, epoch=17, app=None, work=None):
        self.preset(owner=owner, client=client, server=server, epoch=epoch, work=work)
        if app is not None:
            self.src.cells[('', 'read_app')][0] = app
        return self

    def banks(self):
        names = ('application', 'frozen_decoy_off', 'pair_real_links_real_tcp_src', 'pair_real_tcp_dst_real_tcp_ports',
                 'pair_real_object_real_on', 'pair_real_off_native_start', 'pair_native_end_server_start',
                 'pair_frozen_decoy_object_frozen_decoy_on')
        return {n: self.src.cells[('', n)][0] for n in names}

    def read_app(self):
        return self.src.cells[('', 'read_app')][0]

    def trace_text(self, outcome):
        return '\n'.join(e for t in outcome.trace for e in t)


def drop_runtime(pipe, table):
    """Remove every controller-installed entry of one table (a removed flow or profile)."""
    pipe.src.controls['Ingress'].tables[table]['runtime'].clear()


PRIVATE_EVENTS = {0x0101, 0x0102, 0x0103, 0x0104, 0x0105, 0x0106, 0x0107, 0x0108, 0x0109, 0x010a, 0x010b, 0x01ff,
                  0x0201, 0x0202, 0x0203, 0x0204, 0x0205, 0x0206, 0x0207, 0x0208, 0x0209, 0x020a, 0x020b, 0x02ff}


def assert_invariants(case, pipe, outcome, original, max_passes=6, handoff_ok=True):
    """Absolute properties that hold for every packet, independent of any oracle."""
    case.assertNotIn('recirculation limit', outcome.drop_reason or '')
    case.assertLessEqual(outcome.passes, max_passes)
    handoff = handoff_port(getattr(getattr(pipe, 'src', None), 'text', None))   # program under test (pipe may be None)
    for port, data in outcome.emitted:
        if port == handoff and handoff_ok:
            case.assertEqual(data[16:], original, 'handoff carries the original unchanged behind the tev')
            case.assertEqual(data[8:12][3], 0)
        else:
            case.assertEqual(data, original, 'a front-panel egress is the original, never a private header')

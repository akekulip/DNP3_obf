"""Independent native READ packet builders used by current model scenarios."""
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(Path(__file__).resolve().parent), str(Path(__file__).resolve().parent.parent / 'checks'), str(Path(__file__).resolve().parent.parent / 'hardware')]
import case4_padding  # noqa: E402
import vectors  # noqa: E402

CLIENT, SERVER, CPORT, SPORT = vectors.CLIENT, vectors.SERVER, vectors.CLIENT_PORT, vectors.SERVER_PORT
IN_CLIENT, IN_SERVER = vectors.IN_CLIENT, vectors.IN_SERVER
T0_BASE, T0_STEP = 0x123456789a, 0x1000


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


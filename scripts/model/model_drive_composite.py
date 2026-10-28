"""Shared packet builders, endpoint configuration and loop reflectors for current model drivers."""
import os
import socket
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

HERE = Path(__file__).resolve().parent
INTEG = HERE.parent.parent
CASE4 = INTEG.parent
sys.path[:0] = [str(Path(__file__).resolve().parent), str(Path(__file__).resolve().parent.parent / 'checks'), str(Path(__file__).resolve().parent.parent / 'hardware')]
from model_driver import Model as Model, Report as Report, same_frame as same_frame, gc as gc  # noqa: E402
import case4_padding as codec  # noqa: E402
import cp as cp  # noqa: E402
import port_map  # noqa: E402
import response_path_cp as rp  # noqa: E402
import vectors  # noqa: E402
import read_support
rs = read_support  # public packet-builder proxy

__all__ = ['Model', 'Report', 'same_frame', 'gc', 'cp', 'rs', 'RESERVED_TYPES', 'type_violation',
           'vectors', 'codec', 'port_map', 'rp', 'PM', 'MASTER', 'OUTSTATION', 'MASTER_PORT',
           'OUTST_PORT', 'N_ACK_RETURN', 'T_IN', 'PKTGEN_RETURN', 'SID', 'LOOP_PORTS', 'FRONT_LOOPS',
           'native_response37', 'loop_type_violations', 'Reflector', 'Sink', 'scalar']

MASTER_PORT, PKTGEN_RETURN, SID = 9, port_map.PKTGEN_RETURN, 7   # read/ports.p4, two-pipe
PM = port_map.load(os.environ['PORT_MAP']) if os.environ.get('PORT_MAP') else port_map.DEFAULT
OUTST_PORT, N_ACK_RETURN, T_IN = PM.relay_port, PM.n_ack_return, PM.t_in
LOOP_PORTS = [port_map.RETURN_PORT, N_ACK_RETURN, PKTGEN_RETURN, T_IN, PM.held_return]
FRONT_LOOPS = [p for p in LOOP_PORTS if p % 128 < 64]      # front-panel: loop only in MAC loopback
MASTER = rp.Endpoint('10.0.0.1', vectors.CLIENT_PORT, MASTER_PORT)       # vectors.CLIENT
OUTSTATION = rp.Endpoint('10.0.0.2', vectors.SERVER_PORT, OUTST_PORT)    # vectors.SERVER


def native_response37(app, fc, status=0, iin1=0):
    """The 37-byte native SELECT/OPERATE response. iin1 is the IIN1 indication byte (0x90 = NEED_TIME +
    DEVICE_RESTART is what the real outstation sends; the default 0x00 keeps the earlier callers unchanged)."""
    _head, user = codec.decode_frame(vectors.native_select(app, fc))
    objects = bytearray(user[3:])
    objects[17] = status
    return codec.build_frame(bytes.fromhex('05641c4401000a00'), user[:2] + bytes((0x81, iin1, 0)) + bytes(objects))


from port_map import RESERVED_TYPES as RESERVED_TYPES, type_violation  # noqa: E402,F401  (the loop-port EtherType rule)


def loop_type_violations(reflectors):
    """{port: [{'bytes_12_13', 'why', 'first_16_bytes'}]} for every bad value seen on a reflected loop port."""
    bad = {}
    for r in reflectors:
        for value, sample in sorted(r.types.items()):
            why = type_violation(value)
            if why:
                bad.setdefault(str(r.port), []).append(dict(bytes_12_13='0x%04x' % value, why=why, first_16_bytes=sample))
    return bad


class Sink(threading.Thread):
    """MIRROR_SINK probe: counts every frame the model sends to `port` (not reflected) and keeps each distinct
    first-32-bit value with a sample. Used to see whether T's deparser really emits clones on passes that never
    set mirror_type (sessions 1-6 are pointed here, 0 is not a valid session; the real session 7 stays on
    PKTGEN_RETURN)."""

    def __init__(self, port):
        super().__init__(daemon=True)
        self.port, self.frames, self.heads = port, 0, {}
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        self.sock.bind(('veth%d' % (2 * port + 1), 0))

    def run(self):
        while True:
            frame, addr = self.sock.recvfrom(65535)
            if addr[2] == socket.PACKET_OUTGOING:
                continue
            self.frames += 1
            self.heads.setdefault(frame[:4].hex(), [0, frame[:24].hex()])[0] += 1

    def summary(self):
        return dict(frames=self.frames, first_32_bits={k: dict(count=v[0], sample=v[1]) for k, v in sorted(self.heads.items())})


class Reflector(threading.Thread):
    """Stand-in for a front-panel port in MAC loopback: every frame the model transmits on dev_port comes
    straight back in on it, unchanged. Counts the frames, keeps the shortest and longest length, and records
    every distinct wire bytes 12-13 value (with the first frame's first 16 bytes), because the model does not
    filter what a real MAC would."""

    def __init__(self, port):
        super().__init__(daemon=True)
        self.port, self.frames, self.shortest, self.longest, self.first = port, 0, None, 0, {}
        self.types = {}
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        self.sock.bind(('veth%d' % (2 * port + 1), 0))

    def run(self):
        while True:
            frame, addr = self.sock.recvfrom(65535)
            if addr[2] == socket.PACKET_OUTGOING:      # our own reflection, seen again on the way out
                continue
            self.frames += 1
            self.longest = max(self.longest, len(frame))
            if self.shortest is None or len(frame) < self.shortest:
                self.shortest = len(frame)
            self.first.setdefault(len(frame), frame[:16].hex())
            if len(frame) >= 14:
                self.types.setdefault(int.from_bytes(frame[12:14], 'big'), frame[:16].hex())
            self.sock.send(frame)

    def summary(self):
        return dict(frames=self.frames, shortest=self.shortest, longest=self.longest,
                    first_16_bytes_by_length={str(k): v for k, v in sorted(self.first.items())},
                    bytes_12_13_seen={'0x%04x' % k: v for k, v in sorted(self.types.items())})


def scalar(regs):
    """First value of a register_read() dict (pipe 0 for a per-pipe list)."""
    v = next(iter(regs.values()))
    return v[0] if isinstance(v, list) else v


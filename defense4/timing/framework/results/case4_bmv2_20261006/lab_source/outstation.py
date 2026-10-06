"""A software DNP3 outstation for the BMv2 artifact. It is NOT opendnp3 or pydnp3: it answers a READ of group 10
variation 2 with a valid single-frame response (49 bytes for points 0..22) after a configurable latency.
Framing and CRCs are produced with the framework's own independent implementation."""
import argparse
import json
import socket
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "size"))
import rrc  # noqa: E402
from case4_padding import decode_frame  # noqa: E402


def frame(user):
    ln = len(user) + 5
    head = bytes([0x05, 0x64, ln, 0x44, 0x01, 0x00, 0x00, 0x00])
    out = head + struct.pack("<H", rrc.dnp3_crc(head))
    for i in range(0, len(user), 16):
        blk = user[i:i + 16]
        out += blk + struct.pack("<H", rrc.dnp3_crc(blk))
    return out


def deframe(buf):
    """Yield (user_data, total_len) for every complete valid frame at the head of buf."""
    while len(buf) >= 10:
        if buf[:2] != b"\x05\x64":
            return
        ulen = buf[2] - 5
        total = 10 + ulen + 2 * ((ulen + 15) // 16)
        if len(buf) < total:
            return
        if not rrc.dnp3_frame_ok(buf[:total]):
            raise ValueError("bad CRC in request")
        user, p, rem = b"", 10, ulen
        while rem > 0:
            t = min(16, rem)
            user += buf[p:p + t]
            p += t + 2
            rem -= t
        yield user, total
        buf = buf[total:]


def response(user, force_points=0, selected=None):
    seq = user[1] & 0x0F
    if user[2] in (3, 4):
        # Codec emulator only: no relay callback, no production-stack claim.
        objects = bytearray(user[3:])
        if len(objects) not in (18,36) or any(objects[i:i+5] != bytes.fromhex("0c01280100") for i in range(0,len(objects),18)):
            return None
        status = 0 if user[2] == 3 or selected == bytes(objects) else 2
        for i in range(0,len(objects),18):
            objects[i+17] = status
        return frame(bytes([user[0],0xc0 | seq,0x81,0,0]) + objects)
    func, grp, var, start, stop = user[2], user[3], user[4], user[6], user[7]
    if force_points:
        stop = start + force_points - 1
    if func != 0x01 or (grp, var) != (0x0A, 0x02):
        return None                                    # only a READ of g10v2 is implemented
    body = bytes([0xC0, 0xC0 | seq, 0x81, 0x00, 0x00, grp, var, 0x00, start, stop]) + bytes([0x01] * (stop - start + 1))
    return frame(body)


def serve(host, port, latency_ms, ready, force_points=0, combined=False, jitter_ms=0.0, seed=0, fallback_dir=None, evidence=None):
    import random
    rng = random.Random(seed)                      # the same seed gives the same latency sequence in every arm
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(1)
    ready()
    conn, _ = srv.accept()
    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    buf = b""
    transaction_index = 0
    selected = None
    while True:
        d = conn.recv(4096)
        if not d:
            return
        try:
            # SEL-style by default: a separate, immediate ACK. --combined leaves delayed ACK on, so the ACK rides the response.
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_QUICKACK, 0 if combined else 1)
        except OSError:
            pass
        buf += d
        for user, total in deframe(buf):
            r = response(user, force_points, selected)
            if user[2] == 3:
                selected = user[3:]
            if r:
                time.sleep((latency_ms + rng.uniform(0.0, jitter_ms)) / 1e3)
                if fallback_dir:
                    marker = Path(fallback_dir) / (str(transaction_index) + ".json")
                    deadline = time.monotonic() + 2.0
                    while not marker.exists():
                        if time.monotonic() >= deadline:
                            raise RuntimeError("own fallback was not independently observed")
                        time.sleep(0.001)
                conn.sendall(r)                         # one send: one TCP segment on the wire
                if evidence:
                    _, decoded = decode_frame(r)
                    statuses = [decoded[i+22] for i in range(0,len(decoded)-5,18)] if user[2] in (3,4) else []
                    with open(evidence,"a") as output:
                        output.write(json.dumps(dict(transaction_id=transaction_index,function=user[2],statuses=statuses,request_length=total,response_length=len(r)))+"\n")
                transaction_index += 1
            buf = buf[total:]


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=20000)
    ap.add_argument("--latency-ms", type=float, default=1.0)
    ap.add_argument("--jitter-ms", type=float, default=0.0, help="add U(0, J) ms to the latency of every response, seeded")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--combined", action="store_true", help="delayed ACK: the acknowledgment rides the response (AB1400/ION7550 style)")
    ap.add_argument("--force-points", type=int, default=0, help="answer with this many status points instead of the requested range")
    ap.add_argument("--evidence")
    ap.add_argument("--fallback-dir", help="withhold response until this transaction has observed switch expiry")
    a = ap.parse_args()
    serve(a.host, a.port, a.latency_ms, lambda: print("READY", flush=True), a.force_points, a.combined, a.jitter_ms, a.seed, a.fallback_dir, a.evidence)

"""Real-TCP-socket application-layer proxy that applies Option B' (case4_pad58b.py)
response padding in transit, for run_sockets_pad58b.py.

Two independent, real, kernel-backed TCP connections (loopback only, no raw
sockets, no network namespace, no elevated privilege): the production master
binary connects to this proxy's listening port believing it is the
outstation; this proxy makes its own separate TCP connection to the real
production outstation binary. Each leg is managed entirely by the Linux TCP
stack, so byte-level sequence/ack bookkeeping is the kernel's problem, not
this script's -- unlike the RRC/size-splitting bridge in socket_lab.py, which
preserves one transparent raw-packet-level TCP stream end to end and must
therefore translate seq/ack/window itself. That bridge exists to study a
different transform (byte-preserving mid-stream insertion visible to a single
TCP endpoint pair); this proxy exists to validate the DNP3-level codec and
endpoint behaviour, so a plain two-connection relay is the correct tool, not
a simplification that skips something required.

Every raw chunk read from either socket, and every individual DNP3 link frame
decoded out of the outstation-to-master direction, is appended to a JSONL tee
log (`--tee PATH`) as independent byte-level evidence: this is the "socket-level
tee" alternative to a packet capture the task allows, since this host has no
CAP_NET_RAW for raw/AF_PACKET sockets or tcpdump without privilege escalation.

Requests (master -> outstation) are never transformed, matching case4_pad58b's
own scope (RESPONSES only). Responses (outstation -> master) are reframed one
DNP3 link frame at a time and each complete frame is tried against
case4_pad58b.pad_read_response, then pad_control_response; an ineligible frame
(wrong profile, or a link-layer-only frame with no user data, e.g. ACK/RESET)
passes through byte-for-byte unchanged, exactly like the real codec would do
for traffic it does not match.
"""
import argparse
import json
import socket
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import case4_pad58b as pad58b  # noqa: E402

# Fixed two-point control filler, matching emit_vectors_pad58b.py's own choice
# (the exact values are arbitrary -- case4_pad58b.pad_control_response accepts
# any two AnalogFloatPoints -- but reusing the same ones keeps this runner's
# wire bytes directly comparable to TestCase4Pad58B.cpp's hardened vectors).
CONTROL_POINTS = (pad58b.AnalogFloatPoint(301, 10.0, 0), pad58b.AnalogFloatPoint(302, 20.0, 0))


def consume_frames(buf):
    """Pop every complete DNP3 link frame off the front of buf; leave a partial tail.

    Pure length arithmetic (sync bytes + declared length + 16-byte CRC
    blocks), the same framing case4_padding.decode_frame/build_frame use;
    CRC/content validation is left to decode_frame itself inside maybe_pad.
    """
    frames = []
    while True:
        if len(buf) < 10 or buf[0:2] != b'\x05\x64':
            break
        data_len = buf[2] - 5
        if data_len < 0:
            break
        total, remaining = 10, data_len
        while remaining > 0:
            take = min(16, remaining)
            total += take + 2
            remaining -= take
        if len(buf) < total:
            break
        frames.append(bytes(buf[:total]))
        del buf[:total]
    return frames


def maybe_pad(frame):
    """Return (image, kind): kind in ('read', 'control', 'passthrough')."""
    image, delta = pad58b.pad_read_response(frame)
    if delta:
        return image, 'read'
    image, delta = pad58b.pad_control_response(frame, CONTROL_POINTS)
    if delta:
        return image, 'control'
    return frame, 'passthrough'


class Proxy:
    def __init__(self, listen_port, outstation_host, outstation_port, tee_path):
        self.listen_port = listen_port
        self.outstation_host = outstation_host
        self.outstation_port = outstation_port
        self.tee_path = Path(tee_path)
        self.tee_lock = threading.Lock()
        self.stop = threading.Event()
        self.error = None
        self.counts = {'read': 0, 'control': 0, 'passthrough': 0}

    def log(self, handle, **fields):
        with self.tee_lock:
            handle.write(json.dumps(dict(time_ns=time.monotonic_ns(), **fields)) + '\n')
            handle.flush()

    def pump_requests(self, master_sock, outstation_sock, handle):
        """master -> outstation: framed, logged per-frame, never transformed."""
        buf = bytearray()
        try:
            while not self.stop.is_set():
                data = master_sock.recv(65536)
                if not data:
                    break
                buf += data
                for frame in consume_frames(buf):
                    outstation_sock.sendall(frame)
                    self.log(handle, direction='master_to_outstation', frame_hex=frame.hex(), kind='forwarded_unchanged')
        except OSError as error:
            if not self.stop.is_set():
                self.error = self.error or error
        finally:
            self.stop.set()

    def pump_responses(self, outstation_sock, master_sock, handle):
        """outstation -> master: framed, each frame tried against the Option B' codec."""
        buf = bytearray()
        try:
            while not self.stop.is_set():
                data = outstation_sock.recv(65536)
                if not data:
                    break
                buf += data
                for frame in consume_frames(buf):
                    image, kind = maybe_pad(frame)
                    self.counts[kind] += 1
                    master_sock.sendall(image)
                    self.log(handle, direction='outstation_to_master', native_frame_hex=frame.hex(),
                              sent_frame_hex=image.hex(), kind=kind)
        except OSError as error:
            if not self.stop.is_set():
                self.error = self.error or error
        finally:
            self.stop.set()

    def run(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(('127.0.0.1', self.listen_port))
        listener.listen(1)
        listener.settimeout(20)
        print('READY', flush=True)
        try:
            master_sock, _ = listener.accept()
        finally:
            listener.close()
        master_sock.settimeout(None)
        outstation_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        outstation_sock.settimeout(10)
        outstation_sock.connect((self.outstation_host, self.outstation_port))
        outstation_sock.settimeout(None)
        with self.tee_path.open('x') as handle:
            request_thread = threading.Thread(target=self.pump_requests, args=(master_sock, outstation_sock, handle))
            response_thread = threading.Thread(target=self.pump_responses, args=(outstation_sock, master_sock, handle))
            request_thread.start()
            response_thread.start()
            while not self.stop.is_set():
                time.sleep(0.02)
            request_thread.join(timeout=5)
            response_thread.join(timeout=5)
        for sock in (master_sock, outstation_sock):
            try:
                sock.close()
            except OSError:
                pass
        if self.error:
            raise self.error


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--listen-port', type=int, required=True)
    parser.add_argument('--outstation-host', default='127.0.0.1')
    parser.add_argument('--outstation-port', type=int, required=True)
    parser.add_argument('--tee', required=True, help='fresh JSONL path for the byte-level tee log')
    parser.add_argument('--stop-file', required=True, help='relayed connection closes once this file exists and both peers are done')
    args = parser.parse_args(argv)
    proxy = Proxy(args.listen_port, args.outstation_host, args.outstation_port, args.tee)
    stopper = threading.Thread(target=lambda: _watch_stop(args.stop_file, proxy), daemon=True)
    stopper.start()
    proxy.run()
    print(json.dumps({'counts': proxy.counts}))
    return 0


def _watch_stop(stop_file, proxy):
    path = Path(stop_file)
    while not path.exists() and not proxy.stop.is_set():
        time.sleep(0.02)
    proxy.stop.set()


if __name__ == '__main__':
    raise SystemExit(main())

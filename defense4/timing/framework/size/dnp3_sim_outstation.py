#!/usr/bin/env python3
"""Minimal local DNP3 outstation simulator -- a test fixture for dnp3_read_client.py only.

Accepts exactly one TCP connection, waits for a single complete DNP3 link
frame from the client, and replies with one fixed, well-formed Class 0 READ
response reporting two configured Binary Input points (index 0 = ON, index 1
= OFF, see POINTS below). It implements no DNP3 application-layer state
machine beyond this: it logs the request's function code for diagnostics but
does not branch on it, and it has no SELECT/OPERATE handling at all.

This exists solely so the fixed-source-port READ client can be exercised and
verified end to end without touching any real network host. It imposes no
address restriction of its own -- run it bound to 127.0.0.1 (or another
address you control) for that purpose.
"""
import argparse
import socket
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dnp3_read_client import build_link_frame, split_frames, RESPONSE_CONTROL
import rrc

# Fixed response content this fixture always reports: (point index, state).
# Indices must be contiguous starting at 0 -- build_class0_response() assumes it.
POINTS = [(0, True), (1, False)]


def build_class0_response(dest, source):
    transport = bytes([0xC0])                           # FIR=1, FIN=1, SEQ=0
    app = bytearray([0xC0, 0x81, 0x00, 0x00])            # app control; FC=0x81 RESPONSE; IIN=0x0000
    app += bytes([0x01, 0x02, 0x00, POINTS[0][0], POINTS[-1][0]])  # g1v2, qualifier 0x00, start, stop
    for _, state in POINTS:
        app.append(0x01 | (0x80 if state else 0x00))     # ONLINE (bit0) + STATE (bit7)
    return build_link_frame(dest, source, transport + bytes(app), control=RESPONSE_CONTROL)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--local-ip", required=True)
    p.add_argument("--local-port", required=True, type=int)
    p.add_argument("--accept-timeout", type=float, default=10.0)
    p.add_argument("--recv-timeout", type=float, default=5.0)
    args = p.parse_args(argv)

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((args.local_ip, args.local_port))
    bound = listener.getsockname()
    listener.listen(1)
    print("simulated outstation listening on %s:%d" % bound)
    sys.stdout.flush()

    listener.settimeout(args.accept_timeout)
    try:
        conn, peer = listener.accept()
    except socket.timeout:
        print("FAIL: no connection within %.1fs" % args.accept_timeout, file=sys.stderr)
        return 1
    print("accepted connection from %s:%d" % peer)

    conn.settimeout(args.recv_timeout)
    buf, frames = b"", []
    while not frames:
        try:
            chunk = conn.recv(4096)
        except socket.timeout:
            print("FAIL: no request received within %.1fs" % args.recv_timeout, file=sys.stderr)
            conn.close(); listener.close()
            return 1
        if not chunk:
            print("FAIL: client closed before sending a complete request", file=sys.stderr)
            conn.close(); listener.close()
            return 1
        buf += chunk
        frames, buf = split_frames(buf)

    request = frames[0]
    req_ok = rrc.dnp3_frame_ok(request)
    dest, source = struct.unpack_from("<HH", request, 4)
    func_code = None
    if req_ok and request[2] >= 7:
        func_code = request[12]  # link header (10) + transport header (1) + app control (1)
    print("received request frame: %d bytes, control=0x%02x, dest=%d, source=%d, crc_ok=%s, app_fc=%s, hex=%s"
          % (len(request), request[3], dest, source, req_ok, func_code, request.hex()))

    # Respond to whoever asked: response dest = request's source (the master
    # address the client used), response source = request's dest (the
    # outstation address the client used).
    response = build_class0_response(source, dest)
    conn.sendall(response)
    print("sent response frame: %d bytes, hex=%s" % (len(response), response.hex()))
    print("reported points: %s" % POINTS)

    conn.close()
    listener.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

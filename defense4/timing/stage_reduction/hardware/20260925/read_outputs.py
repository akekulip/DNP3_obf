#!/usr/bin/env python3
"""Non-actuating G10V2 read of all 32 output-status points, with CRC checks."""
import json
import os
import socket
import time

from dnp3_codec import Reassembler
import frozen_builders  # Adds the unchanged frozen builder directory to sys.path.
from dnp3_wire import build_frame

if os.environ.get("DEFENSE4_HW_AUTHORIZED") != "1":
    raise SystemExit("REFUSED: DEFENSE4_HW_AUTHORIZED=1 is required")
request = bytes([0xC0, 0xC9, 1, 10, 2, 0, 0, 31])
assert request[2] == 1  # READ only.
frame = build_frame(request, dst=0, src=1, ctrl=0xC4)
rx = Reassembler(verify_crc=True)
deadline = time.monotonic() + 3
with socket.create_connection(("192.168.10.7", 20000), timeout=3,
                              source_address=("192.168.10.1", 0)) as sock:
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.sendall(frame)
    while time.monotonic() < deadline:
        sock.settimeout(max(0.001, deadline - time.monotonic()))
        chunk = sock.recv(4096)
        if not chunk:
            raise SystemExit("Peer closed before output-status response")
        rx.feed(chunk)
        for parsed in rx.frames():
            u = parsed.user_data
            if len(u) < 5 or u[1] & 15 != 9:
                continue
            assert u[2] == 0x81 and u[5:10] == bytes([10, 2, 0, 0, 31]), u.hex()
            assert len(u) == 42, "Missing or extra output-status points"
            flags = list(u[10:])
            closed = [i for i, flag in enumerate(flags) if flag & 0x80]
            online = all(flag & 1 for flag in flags)
            print(json.dumps({"points": 32, "flags": flags, "closed_points": closed,
                              "all_open": not closed, "all_online": online,
                              "iin": u[3:5].hex()}))
            raise SystemExit(0 if not closed and online else 1)
raise SystemExit("No matching complete output-status response")

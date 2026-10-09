#!/usr/bin/env python3
"""Minimal DNP3-over-TCP READ-only client with an explicit, fixed local source port.

Sends exactly one Class 0 (integrity poll) READ request -- function code 1, a
single object header (group 60, variation 1, qualifier 0x06, "Class 0 data,
no range field") -- over a TCP connection whose local (source) address and
port are bound explicitly with socket.bind() before connect(), so the full
four-tuple is known before the TCP handshake starts. This is for a switch
control plane that pre-installs forwarding/connection-table state keyed on
the exact four-tuple ahead of time, with no dynamic connection admission.

Structurally READ-only by construction: there is no SELECT/OPERATE code path
anywhere in this file, and none should ever be added here. A command-sending
client is a different, separate script.

CRC: reuses rrc.dnp3_crc, the one audited DNP3 CRC-16 (polynomial 0x3D65)
implementation already in this directory, instead of reimplementing it.

Safety: this script enforces no address restriction of its own -- --remote-ip
is caller-supplied and unchecked. Point it only at hosts you are authorized
to test against.
"""
import argparse
import socket
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import rrc  # dnp3_crc, dnp3_frame_ok

SYNC = b"\x05\x64"
REQUEST_CONTROL = 0xC4   # DIR=1,PRM=1,FCB=0,FCV=0,FC=4 (unconfirmed user data, master->outstation)
RESPONSE_CONTROL = 0x44  # DIR=0,PRM=1,FCB=0,FCV=0,FC=4 (unconfirmed user data, outstation->master)


def build_link_frame(dest, source, user, control=REQUEST_CONTROL):
    """One DNP3 link frame: 10-byte header + one CRC per <=16-byte user-data block.

    `user` is transport header + application fragment, already assembled by
    the caller; this function only does link-layer framing and CRCs. `control`
    defaults to the master's own request control byte; a response builder
    (not this file -- this client never builds responses) must pass
    RESPONSE_CONTROL explicitly, since DIR depends on which end is sending.
    """
    if not 0 <= len(user) <= 250:
        raise ValueError("user data must fit in one transport segment (0..250 bytes)")
    if not 0 <= dest <= 0xFFFF or not 0 <= source <= 0xFFFF:
        raise ValueError("link addresses must be 16-bit")
    header = bytearray(8)
    header[0:2] = SYNC
    header[2] = len(user) + 5
    header[3] = control
    struct.pack_into("<H", header, 4, dest)
    struct.pack_into("<H", header, 6, source)
    out = bytes(header) + struct.pack("<H", rrc.dnp3_crc(bytes(header)))
    for i in range(0, len(user), 16):
        block = user[i:i + 16]
        out += block + struct.pack("<H", rrc.dnp3_crc(block))
    return out


def build_class0_read(dest, source, app_seq=0):
    """Transport header + application-layer READ(fc=1) { g60v1 qualifier 0x06 }."""
    transport = bytes([0xC0])                                  # FIR=1, FIN=1, SEQ=0
    app = bytes([0xC0 | (app_seq & 0x0F), 0x01, 0x3C, 0x01, 0x06])
    # app control: FIR=1,FIN=1,CON=0,UNS=0,SEQ=app_seq; function code 1 = READ;
    # object header: group 60, variation 1, qualifier 0x06 (Class 0, no range field)
    return build_link_frame(dest, source, transport + app)


def split_frames(buf):
    """Return (complete DNP3 link frames found at the front of buf, leftover bytes)."""
    frames = []
    i = 0
    while i + 10 <= len(buf) and buf[i:i + 2] == SYNC:
        length = buf[i + 2]
        if length < 5:
            break
        left, total = length - 5, 10
        while left > 0:
            take = min(16, left)
            total += take + 2
            left -= take
        if i + total > len(buf):
            break
        frames.append(buf[i:i + total])
        i += total
    return frames, buf[i:]


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--local-ip", required=True, help="local address to bind before connect()")
    p.add_argument("--local-port", required=True, type=int, help="exact local source port to bind")
    p.add_argument("--remote-ip", required=True, help="outstation address")
    p.add_argument("--remote-port", required=True, type=int, help="outstation TCP port")
    p.add_argument("--master-addr", type=int, default=1, help="DNP3 link source address (default 1)")
    p.add_argument("--outstation-addr", type=int, default=10, help="DNP3 link destination address (default 10)")
    p.add_argument("--connect-timeout", type=float, default=5.0)
    p.add_argument("--read-timeout", type=float, default=3.0, help="max wait for the first response byte")
    p.add_argument("--idle-timeout", type=float, default=0.2, help="wait for trailing bytes after the first arrive")
    args = p.parse_args(argv)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((args.local_ip, args.local_port))
    except OSError as error:
        print("FAIL: could not bind %s:%d: %s" % (args.local_ip, args.local_port, error), file=sys.stderr)
        return 1
    bound = sock.getsockname()
    print("bound local socket to %s:%d (requested %s:%d)" % (bound[0], bound[1], args.local_ip, args.local_port))
    if bound[1] != args.local_port:
        sock.close()
        print("FAIL: kernel did not honor the requested local port", file=sys.stderr)
        return 1

    sock.settimeout(args.connect_timeout)
    try:
        sock.connect((args.remote_ip, args.remote_port))
    except OSError as error:
        sock.close()
        print("FAIL: connect to %s:%d failed: %s" % (args.remote_ip, args.remote_port, error), file=sys.stderr)
        return 1
    print("connected %s:%d -> %s:%d" % (bound[0], bound[1], args.remote_ip, args.remote_port))

    request = build_class0_read(args.outstation_addr, args.master_addr)
    if not rrc.dnp3_frame_ok(request):
        sock.close()
        print("FAIL: self-built request frame failed its own CRC check", file=sys.stderr)
        return 1
    try:
        sock.sendall(request)
    except OSError as error:
        sock.close()
        print("FAIL: send failed: %s" % error, file=sys.stderr)
        return 1
    print("sent Class 0 READ request: %d bytes, hex=%s" % (len(request), request.hex()))

    sock.settimeout(args.read_timeout)
    buf, got_first = b"", False
    deadline = time.monotonic() + args.read_timeout + 10 * args.idle_timeout
    while time.monotonic() < deadline:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
        if not got_first:
            got_first = True
            sock.settimeout(args.idle_timeout)
    sock.close()

    frames, leftover = split_frames(buf)
    print("received %d total byte(s), %d complete DNP3 link frame(s), %d leftover byte(s)"
          % (len(buf), len(frames), len(leftover)))
    if not frames:
        print("FAIL: no complete DNP3 response frame received", file=sys.stderr)
        return 1

    all_ok = True
    for idx, frame in enumerate(frames):
        ok = rrc.dnp3_frame_ok(frame)
        all_ok = all_ok and ok
        dest, source = struct.unpack_from("<HH", frame, 4)
        print("  frame %d: %d bytes, control=0x%02x, dest=%d, source=%d, crc_ok=%s, hex=%s"
              % (idx, len(frame), frame[3], dest, source, ok, frame.hex()))
    if leftover:
        print("WARNING: %d trailing byte(s) did not form a complete frame: %s" % (len(leftover), leftover.hex()))

    if not all_ok:
        print("FAIL: at least one response frame failed its link/data CRC", file=sys.stderr)
        return 1

    print("PASS: fixed-source-port Class 0 READ request/response exchange completed, all CRCs valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

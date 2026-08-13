#!/usr/bin/env python3
"""DNP3 SELECT-ONLY probe (isolation audit helper).

SAFETY: This tool can emit ONLY a DNP3 Application-layer SELECT (function code
0x03). It contains NO OPERATE (0x04), DirectOperate (0x05/0x06), or any other
actuation. A SELECT arms a control point for a later OPERATE and by DNP3 design
does NOT actuate any output on its own; this tool never sends the follow-up
OPERATE. Use only against control points independently proven to energize
nothing. Read-only/SELECT-only by construction.

Builds a single unconfirmed-user-data link frame carrying a 2-CROB (G12V1)
SELECT to the given Binary-Output indices, sends it over TCP/20000, and prints
the request and the outstation's response as hex plus the parsed CROB status.

Usage: dnp3_select_only.py <host> <dest_link> <src_link> <idx1> <idx2> [--send]
Default is dry-run (prints frame, sends nothing). --send transmits one SELECT.
"""
import socket, struct, sys

APP_FC_SELECT = 0x03  # the ONLY function code this tool will ever emit

def crc16(data):
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if crc & 1 else crc >> 1
    return (~crc) & 0xFFFF

def block(data):
    return data + struct.pack('<H', crc16(data))

def crob(index):
    # 1-byte index prefix + 11-byte CROB (LATCH_ON, count=1, 0 on/off, status req=0)
    return bytes([index, 0x03, 0x01]) + struct.pack('<I', 0) + struct.pack('<I', 0) + bytes([0x00])

def build_select(indices, seq=0):
    app = bytes([0xC0 | (seq & 0x0F), APP_FC_SELECT])      # FIR/FIN, SELECT
    app += bytes([0x0C, 0x01, 0x17, len(indices)])         # G12V1, qual 0x17, count
    for idx in indices:
        app += crob(idx)
    return app

def build_frame(dest, src, app):
    tpdu = bytes([0xC0]) + app                             # transport FIR/FIN/SEQ0
    length = 5 + len(tpdu)
    hdr = bytes([0x05, 0x64, length, 0xC4]) + struct.pack('<H', dest) + struct.pack('<H', src)
    frame = block(hdr)
    i = 0
    while i < len(tpdu):
        frame += block(tpdu[i:i+16]); i += 16
    return frame

def parse_response(raw):
    # strip link header (10 bytes) + transport (skip CRC-framed user blocks)
    if len(raw) < 10 or raw[0] != 0x05 or raw[1] != 0x64:
        return "no/short link frame", None
    length = raw[2]
    ctrl = raw[3]
    body = bytearray()
    off = 10
    remaining = length - 5
    while remaining > 0 and off < len(raw):
        take = min(16, remaining)
        body += raw[off:off+take]
        off += take + 2
        remaining -= take
    if not body:
        return "empty body", None
    tpdu = bytes(body)
    app = tpdu[1:]                    # drop transport byte
    if len(app) < 4:
        return "short app", None
    app_ctrl, fc = app[0], app[1]
    iin = struct.unpack('<H', app[2:4])[0]
    info = "app_ctrl=0x%02x func=0x%02x IIN=0x%04x" % (app_ctrl, fc, iin)
    # parse echoed G12V1 with status codes
    statuses = []
    p = 4
    if p+4 <= len(app) and app[p] == 0x0C and app[p+1] == 0x01:
        qual, count = app[p+2], app[p+3]; p += 4
        for _ in range(count):
            if p+12 > len(app): break
            idx = app[p]; status = app[p+11]
            statuses.append((idx, status)); p += 12
    return info, statuses

def main():
    host = sys.argv[1]; dest = int(sys.argv[2]); src = int(sys.argv[3])
    idxs = [int(sys.argv[4]), int(sys.argv[5])]
    send = '--send' in sys.argv
    frame = build_frame(dest, src, build_select(idxs))
    print("SELECT-ONLY frame (func=0x03) to %s dest=%d src=%d indices=%s" % (host, dest, src, idxs))
    print("REQUEST HEX: " + frame.hex())
    if not send:
        print("DRY-RUN: nothing sent."); return
    s = socket.create_connection((host, 20000), timeout=8)
    s.sendall(frame)
    s.settimeout(4.0)
    resp = b""
    try:
        while True:
            b = s.recv(4096)
            if not b: break
            resp += b
            if len(resp) >= 10: break
    except socket.timeout:
        pass
    s.close()
    print("RESPONSE HEX: " + resp.hex())
    info, statuses = parse_response(resp)
    print("RESPONSE PARSED: " + info)
    STATUS = {0:"SUCCESS", 1:"TIMEOUT", 2:"NO_SELECT", 3:"FORMAT_ERROR",
              4:"NOT_SUPPORTED", 5:"ALREADY_ACTIVE", 6:"HARDWARE_ERROR",
              7:"LOCAL", 8:"TOO_MANY_OBJS", 9:"NOT_AUTHORIZED"}
    if statuses:
        for idx, st in statuses:
            print("  CROB index %d -> status %d (%s)" % (idx, st, STATUS.get(st, "?")))

if __name__ == "__main__":
    main()

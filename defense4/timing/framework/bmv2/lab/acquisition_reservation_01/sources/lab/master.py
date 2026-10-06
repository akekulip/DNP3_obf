"""Python codec emulator master; endpoint-stack acceptance is a separate gate."""
import argparse
import json
import sys
import socket
import time
from pathlib import Path

HARNESS = Path(__file__).resolve().parents[3] / "active_harness"
sys.path.insert(0, str(HARNESS))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "size"))
from dnp3_codec import FUNC_READ, FUNC_SELECT, FUNC_OPERATE
from frozen_builders import read_frame
from session import Session
from case4_padding import build_frame, decode_frame


def control_frame(seq, function):
    objects = bytes.fromhex("0c0128010001000101640000006400000000")
    return build_frame(bytes.fromhex("056400c40a000100"),
                       bytes([0xc0 | (seq & 0x3f), 0xc0 | (seq & 0xf), function]) + objects)


def control_transactions(args):
    """Strict fixed-profile codec client; does not stand in for OpenDNP3."""
    rows = []
    with socket.create_connection((args.host,20000)) as conn:
        conn.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
        for index in range(args.count):
            phases = [("SELECT",FUNC_SELECT)] + ([("OPERATE",FUNC_OPERATE)] if args.operation == "SBO" else [])
            for phase_index,(operation,function) in enumerate(phases):
                seq = (index*len(phases)+phase_index)&15
                native = control_frame(seq,function)
                started = time.monotonic(); deadline = started + args.budget_ms/1000
                conn.sendall(native); buf = bytearray(); outcome = "TIMEOUT"; statuses = []
                while time.monotonic() < deadline:
                    conn.settimeout(max(0.001,deadline-time.monotonic()))
                    try:
                        data = conn.recv(4096)
                    except socket.timeout:
                        break
                    if not data:
                        outcome = "PEER_CLOSED"; break
                    buf += data
                    if len(buf) < 10:
                        continue
                    user_len = buf[2]-5
                    total = 10+user_len+2*((user_len+15)//16)
                    if len(buf) < total:
                        continue
                    try:
                        _,user = decode_frame(bytes(buf[:total])); _,request_user = decode_frame(native)
                        objects=user[5:]
                        valid = user[1]&15 == seq and user[2] == 0x81 and len(objects) in (18,36)
                        for start in range(0,len(objects),18):
                            valid = valid and objects[start:start+5] == bytes.fromhex("0c01280100")
                            statuses.append(objects[start+17])
                        valid = valid and objects[:17] == request_user[3:20] and all(status == 0 for status in statuses)
                        if len(objects) == 36:
                            valid = valid and objects[18:] == bytes.fromhex("0c01280100c9000101640000006400000000")
                        outcome="OK" if valid else "INVALID"
                    except (ValueError,IndexError):
                        outcome="INVALID"
                    break
                rows.append(dict(operation=operation,function=function,app_seq=seq,outcome=outcome,
                                 elapsed_ms=(time.monotonic()-started)*1000,statuses=statuses))
                if outcome != "OK":
                    break
            time.sleep(args.gap_ms/1000)
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="10.0.0.2")
    ap.add_argument("--count", type=int, default=5)
    ap.add_argument("--gap-ms", type=float, default=50.0)
    ap.add_argument("--budget-ms", type=float, default=500.0)
    ap.add_argument("--operation", choices=("READ", "SELECT", "SBO"), default="READ")
    a = ap.parse_args()
    if a.operation != "READ":
        print(json.dumps(control_transactions(a)))
        return
    rows = []
    with Session(a.host, 20000) as session:
        for index in range(a.count):
            phases = [("READ", FUNC_READ)] if a.operation == "READ" else [("SELECT", FUNC_SELECT)]
            if a.operation == "SBO":
                phases.append(("OPERATE", FUNC_OPERATE))
            for phase_index, (operation, function) in enumerate(phases):
                seq = (index * len(phases) + phase_index) & 0xf
                frame = read_frame(seq) if operation == "READ" else control_frame(seq, function)
                out = session.transaction(operation=operation, frame=frame, function=function, app_seq=seq, budget_ms=a.budget_ms)
                rows.append(out.as_dict())
                if out.outcome != "OK":
                    break
            time.sleep(a.gap_ms / 1e3)
    print(json.dumps(rows))


if __name__ == "__main__":
    main()

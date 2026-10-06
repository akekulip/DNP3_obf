"""Internal private-namespace service packet; never goes to either endpoint."""
import argparse
import socket
import time

parser = argparse.ArgumentParser()
parser.add_argument("--period-us", type=int, default=1000)
args = parser.parse_args()
if args.period_us <= 0:
    raise ValueError("positive heartbeat period required")
sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
sock.bind(("inj", 0))
packet = bytes.fromhex("02000000000102000000000388b6") + bytes(46)
while True:
    sock.send(packet)
    time.sleep(args.period_us / 1_000_000)

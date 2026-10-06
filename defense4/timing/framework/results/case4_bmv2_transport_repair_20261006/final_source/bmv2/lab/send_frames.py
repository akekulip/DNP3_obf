"""Replay explicit Ethernet fixtures inside the private emulator namespace."""
import json
import socket
import sys
import time

sock = socket.socket(socket.AF_PACKET,socket.SOCK_RAW)
sock.bind((sys.argv[1],0))
for entry in json.load(open(sys.argv[2])):
    sock.send(bytes.fromhex(entry["raw"]))
    time.sleep(entry.get("pause_ms",40)/1000)

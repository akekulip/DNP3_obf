"""Send crafted raw Ethernet frames from a given interface (run inside the sending namespace).
usage: inject.py IFACE DSTMAC SRCMAC ETYPE:COUNT[:PAYLOADLEN] ...   frames are sent in the order given."""
import socket
import struct
import sys

iface, dst, src = sys.argv[1], bytes.fromhex(sys.argv[2].replace(":", "")), bytes.fromhex(sys.argv[3].replace(":", ""))
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind((iface, 0))
n = 0
for spec in sys.argv[4:]:
    parts = spec.split(":")
    etype, count = int(parts[0], 16), int(parts[1])
    plen = int(parts[2]) if len(parts) > 2 else 46
    for _ in range(count):
        s.send(dst + src + struct.pack(">H", etype) + struct.pack(">H", n) + bytes(plen - 2))
        n += 1

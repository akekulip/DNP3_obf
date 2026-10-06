"""Raw AF_PACKET capture to a nanosecond classic pcap, with kernel receive timestamps.
Used instead of tcpdump, which cannot drop privileges inside an unprivileged user namespace.
Both directions on the interface are seen: what arrives from the veth peer and what the switch transmits."""
import signal
import socket
import struct
import sys

iface, out = sys.argv[1], sys.argv[2]
SO_TIMESTAMPNS = 35
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.bind((iface, 0))
s.setsockopt(socket.SOL_SOCKET, SO_TIMESTAMPNS, 1)
f = open(out, "wb")
f.write(struct.pack("<IHHiIII", 0xA1B23C4D, 2, 4, 0, 0, 65535, 1))        # nanosecond magic, written little-endian
f.flush()
stop = []
signal.signal(signal.SIGINT, lambda *a: stop.append(1))
signal.signal(signal.SIGTERM, lambda *a: stop.append(1))
s.settimeout(0.2)
while not stop:
    try:
        data, anc, _, _ = s.recvmsg(65535, 256)
    except socket.timeout:
        continue
    ts = None
    for level, typ, payload in anc:
        if level == socket.SOL_SOCKET and typ == SO_TIMESTAMPNS:
            sec, nsec = struct.unpack("ll", payload[:16])
            ts = (sec, nsec)
    if ts is None:
        import time
        t = time.time_ns()
        ts = (t // 10 ** 9, t % 10 ** 9)
    f.write(struct.pack("<IIII", ts[0], ts[1], len(data), len(data)) + data)
    f.flush()
f.close()

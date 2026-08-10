"""Shared helpers for Experiment 1 (offline TCP/IP header attribution).

Read-only over the frozen Defense 4 corpus. No live traffic, no hardware.
Deterministic: no randomness, sessions keyed by the 4-tuple, packets kept in
capture order. DNP3 listens on TCP port 20000, so the outstation is the
port-20000 side of every session.
"""
import hashlib
import os

from scapy.all import rdpcap, IP, TCP, Ether, Raw

DNP3_PORT = 20000
SRC_REPO = "/home/philip/Projects/DNP3"
TRAFFIC_TRACE = os.path.join(SRC_REPO, "Traffic Trace")
LARGE_READ = os.path.join(
    SRC_REPO, "dnp3_split_harness/captures/baseline/large_read.pcap"
)

# device label -> (short capture, long capture)
CORPUS = {
    "SEL751": ("SEL751.pcap", "SEL751L.pcap"),
    "ION7550": ("ION7550.pcap", "ION7550L.pcap"),
    "AB1400": ("AB1400.pcap", "AB1400L.pcap"),
}

# captures transformed/validated. Short captures are small enough to commit;
# the long "L" captures are transformed and validated too (their SYN-ACK is
# needed to show the SEL751 collapse), but their transformed copies are large
# and are gitignored (hashes recorded in the transform manifest).
SHORT_CAPS = ["SEL751.pcap", "ION7550.pcap", "AB1400.pcap"]
LONG_CAPS = ["SEL751L.pcap", "ION7550L.pcap", "AB1400L.pcap"]
ALL_CAPS = SHORT_CAPS + LONG_CAPS


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def pkt_type(tcp):
    """Coarse TCP lifecycle class from flags/payload."""
    fl = int(tcp.flags)
    syn, ack, fin, rst = fl & 0x02, fl & 0x10, fl & 0x01, fl & 0x04
    if syn and not ack:
        return "SYN"
    if syn and ack:
        return "SYN-ACK"
    if fin or rst:
        return "FIN/RST"
    if len(bytes(tcp.payload)) > 0:
        return "DATA"
    return "ACK"


def option_layout(tcp):
    """Ordered list of TCP option kind names, e.g. ['NOP','NOP','Timestamp']."""
    names = []
    for o in tcp.options:
        names.append(str(o[0]) if isinstance(o, (tuple, list)) else str(o))
    return names


def option_values(tcp):
    """Dict of interesting option values (MSS, WScale, SAckOK, Timestamp)."""
    vals = {}
    for o in tcp.options:
        if isinstance(o, (tuple, list)):
            k, v = o[0], (o[1] if len(o) > 1 else None)
            if k == "MSS":
                vals["mss"] = v
            elif k == "WScale":
                vals["wscale"] = v
            elif k == "SAckOK":
                vals["sackok"] = True
            elif k == "Timestamp":
                vals["tsval"] = v[0] if isinstance(v, (tuple, list)) else v
                vals["tsecr"] = v[1] if isinstance(v, (tuple, list)) and len(v) > 1 else None
    return vals


def dnp3_funccode(payload):
    """Best-effort DNP3 application function code for a request/response.

    DNP3-over-TCP frame: 0x05 0x64 | LEN | CTRL | DEST(2) | SRC(2) | CRC(2)
    then the first data block: TRANSPORT(1) | APP-CTRL(1) | FUNC(1) | ...
    So the function code sits at payload byte 14 when a frame is present.
    Returns int or None.
    """
    b = bytes(payload)
    if len(b) >= 15 and b[0] == 0x05 and b[1] == 0x64:
        return b[14]
    return None


DNP3_FUNC = {0: "CONFIRM", 1: "READ", 2: "WRITE", 3: "SELECT", 4: "OPERATE",
             5: "DIRECT_OPERATE", 129: "RESPONSE", 130: "UNSOL_RESPONSE"}


def load_sessions(path):
    """Return list of session dicts, each with packets in capture order and the
    outstation-side endpoint identified by TCP port 20000."""
    pkts = rdpcap(path)
    sessions = {}
    order = []
    for idx, pk in enumerate(pkts):
        if IP not in pk or TCP not in pk:
            continue
        ip, tcp = pk[IP], pk[TCP]
        key = tuple(sorted([(ip.src, int(tcp.sport)), (ip.dst, int(tcp.dport))]))
        if key not in sessions:
            sessions[key] = []
            order.append(key)
        sessions[key].append((idx, pk))
    out = []
    for key in order:
        recs = sessions[key]
        # outstation endpoint = the (ip,port) whose port == 20000
        oside = None
        for (ip, port) in key:
            if port == DNP3_PORT:
                oside = (ip, port)
        out.append({"key": key, "outstation": oside, "packets": recs})
    return out


def direction(pk, outstation):
    """'outstation' if this packet was sent BY the outstation, else 'master'."""
    tcp = pk[TCP]
    src = (pk[IP].src, int(tcp.sport))
    if outstation is not None and src == outstation:
        return "outstation"
    return "master"

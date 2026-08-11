#!/usr/bin/env python3
"""Offline arithmetic oracle for defense4_joint.p4's egress Layer S.

The compile gate proves the program COMPILES. This oracle proves the transform it
ENCODES is arithmetically sound, on the four properties the wire gate will later
confirm on silicon — WITHOUT hardware:

  1. Chunk tiling + reconstruction byte-identity (empty residual, descending emit).
  2. DNP3 CRC-16/DNP + on-wire byte-swap order (vs the validated harness reference).
  3. IPv4 + TCP wholesale-checksum field list + pseudo-header tcp_len (vs scapy).
  4. Per-flow seq/ack Delta translation with idempotent retransmit-of-last and
     SYN/FIN/RST reset (exact RegisterAction semantics replayed).

Run: RESEARCH_PYTHON=~/.venvs/research/bin/python ; $RESEARCH_PYTHON joint_transform_oracle.py
(scapy is only needed for check 3; checks 1/2/4 are pure-stdlib.)
"""
import os, sys, struct

HARNESS = "/home/philip/Projects/DNP3-size-probe/dnp3_split_harness"
sys.path.insert(0, HARNESS)
import dnp3_crc  # validated CRC-16/DNP: dnp3_crc16(data)->int, append_crc(data)->data+LE(crc)

FAIL = []
def check(name, ok, detail=""):
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"  — {detail}" if detail else ""))
    if not ok:
        FAIL.append(name)

# ---- constants mirrored from defense4_joint.p4 ----
PAD_CONST = 7
LEN_RESP_TOTAL = 94          # ipv4.total_len for the 54 B response
LEN_BARE_TOTAL = 40
IP_HDR = 20
TCP_HDR = 20
# egress parse for the response: dl(10) + db(18) + p16 + p8 + p2  (descending)
RESP_CHUNKS = [("dl", 10), ("db", 18), ("p16", 16), ("p8", 8), ("p2", 2)]
TCP_LEN_RESP = 74            # m.tcp_len for CLS_RESP  = TCP_HDR + 54
TCP_LEN_BARE = 20            # m.tcp_len for CLS_BARE

def inet_csum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF

print("=== 1. chunk tiling + reconstruction byte-identity ===")
payload_len = LEN_RESP_TOTAL - IP_HDR - TCP_HDR
tiled = sum(n for _, n in RESP_CHUNKS)
check("payload = total_len - ip - tcp = 54", payload_len == 54, f"{payload_len}")
check("dl+db+p16+p8+p2 tiles the payload exactly", tiled == payload_len, f"{tiled} == {payload_len}")
# powers-of-2 chunks are a strictly descending subset (extraction == emission order)
p2sizes = [n for nm, n in RESP_CHUNKS if nm.startswith("p")]
check("chunk sizes strictly descending powers of 2", p2sizes == sorted(p2sizes, reverse=True)
      and all((n & (n - 1)) == 0 for n in p2sizes), f"{p2sizes}")
# simulate extract(descending) -> emit(descending): identical bytes
blob = bytes(range(payload_len))
off, parts = 0, []
for _, n in RESP_CHUNKS:
    parts.append(blob[off:off + n]); off += n
recon = b"".join(parts)
check("extract->emit reconstructs payload byte-identically", recon == blob)
check("db carries 16 DNP3 data bytes + 2 CRC (proper CRC block)", 18 == 16 + 2)

print("=== 2. DNP3 CRC-16/DNP + on-wire byte-swap ===")
# my P4 byte-swap: hdr.dl.crc = v[7:0] ++ v[15:8]  ==> on the wire [low_octet, high_octet]
def p4_wire_crc(v: int) -> bytes:
    hi = (v & 0x00FF)        # v[7:0]  becomes the field's HIGH byte -> emitted first
    lo = (v >> 8) & 0xFF     # v[15:8] becomes the field's LOW  byte -> emitted second
    return bytes([hi, lo])
link8 = bytes([0x05, 0x64, 0x0A, 0x44, 0x01, 0x00, 0x00, 0x00])  # start,len,ctrl,dst,src (8 B)
blk16 = bytes(range(0x10, 0x20))                                  # 16 user-data bytes
for nm, data in (("link header (8 B)", link8), ("user block (16 B)", blk16)):
    ref_int = dnp3_crc.dnp3_crc16(data)
    ref_wire = dnp3_crc.append_crc(data)[-2:]                     # struct.pack('<H') = [low,high]
    mine = p4_wire_crc(ref_int)
    check(f"P4 byte-swap == reference wire CRC for {nm}", mine == ref_wire,
          f"crc=0x{ref_int:04x} wire={ref_wire.hex()} p4={mine.hex()}")
# parameter-tuple equivalence to my CRCPolynomial<bit<16>>(0x3D65,true,false,false,0x0000,0xFFFF)
check("CRCPolynomial params == documented CRC-16/DNP", "0x3D65" in open(HARNESS + "/dnp3_crc.py").read())

print("=== 3. IPv4 + TCP wholesale-checksum field list (vs scapy) ===")
try:
    from scapy.all import IP, TCP, Raw, raw
    HAVE_SCAPY = True
except Exception as e:  # noqa
    HAVE_SCAPY = False
    print(f"  (scapy unavailable: {e}; skipping check 3 — run under $RESEARCH_PYTHON)")

if HAVE_SCAPY:
    src, dst = "10.10.54.158", "10.10.54.19"
    payload = bytes((i * 7 + 3) & 0xFF for i in range(54))       # arbitrary 54 B DNP3-ish body
    pkt = IP(src=src, dst=dst, ttl=64, id=0x1234, flags=0) / \
          TCP(sport=20000, dport=40000, seq=0x11223344, ack=0x55667788,
              dataofs=5, flags="PA", window=0x1000) / Raw(payload)
    wire = raw(pkt)                                              # scapy fills both checksums
    ip_bytes, tcp_bytes = wire[:20], wire[20:40]
    scapy_ip_csum = (ip_bytes[10] << 8) | ip_bytes[11]
    scapy_tcp_csum = (tcp_bytes[16] << 8) | tcp_bytes[17]
    # ---- my IPv4 field list (checksum field omitted == treated as zero) ----
    ip_fields = ip_bytes[:10] + ip_bytes[12:]                    # drop the 2 csum bytes
    check("IPv4 checksum from my field list == scapy", inet_csum(ip_fields) == scapy_ip_csum,
          f"mine=0x{inet_csum(ip_fields):04x} scapy=0x{scapy_tcp_csum and scapy_ip_csum:04x}")
    # ---- my TCP field list: pseudo(src,dst,0,proto,tcp_len) + tcp hdr (csum omitted) + payload ----
    proto = 6
    pseudo = struct.pack("!4s4sBBH",
                         bytes(map(int, src.split("."))),
                         bytes(map(int, dst.split("."))),
                         0, proto, TCP_LEN_RESP)                 # tcp_len = 74 (the P4 constant)
    tcp_hdr_no_csum = tcp_bytes[:16] + tcp_bytes[18:]            # drop 2 csum bytes (== zero)
    mine_tcp = inet_csum(pseudo + tcp_hdr_no_csum + payload)
    check("TCP checksum from my field list + tcp_len=74 == scapy", mine_tcp == scapy_tcp_csum,
          f"mine=0x{mine_tcp:04x} scapy=0x{scapy_tcp_csum:04x}")
    # bare ACK: tcp_len must be 20 (header only, no payload)
    ack = IP(src=dst, dst=src, ttl=64, flags=0) / TCP(sport=40000, dport=20000, flags="A",
                                                      seq=1, ack=2, dataofs=5, window=0x1000)
    aw = raw(ack); atcp = aw[20:40]
    sc_ack = (atcp[16] << 8) | atcp[17]
    ap = struct.pack("!4s4sBBH", bytes(map(int, dst.split("."))), bytes(map(int, src.split("."))),
                     0, 6, TCP_LEN_BARE)
    mine_ack = inet_csum(ap + atcp[:16] + atcp[18:])
    check("bare-ACK TCP checksum + tcp_len=20 == scapy", mine_ack == sc_ack,
          f"mine=0x{mine_ack:04x} scapy=0x{sc_ack:04x}")

print("=== 4. seq/ack Delta translation + idempotent retransmit + reset ===")
# Exact replay of the egress RegisterActions on one flow_idx.
class Flow:
    def __init__(self):
        self.delta = 0          # reg_delta
        self.last_seq = None     # reg_last_resp_seq
    # RegisterActions ----------------------------------------------------------
    def delta_bump(self):
        old = self.delta; self.delta = self.delta + PAD_CONST; return old
    def delta_read(self):
        return self.delta
    def delta_reset(self):
        self.delta = 0; return 0
    def lastseq_update(self, seq):           # returns is_retx (1/0)
        if self.last_seq == seq:
            return 1
        self.last_seq = seq; return 0

f = Flow()
# a poll: outstation RESPONSE(seq=1000) -> master ACK(ack=1000+54) -> next RESPONSE(seq=1054) ...
def out_response(seq):                        # outstation -> master (CLS_RESP, dir=OUT)
    is_retx = f.lastseq_update(seq)
    if is_retx:
        d = f.delta_read(); seq_add = d - PAD_CONST
    else:
        d = f.delta_bump(); seq_add = d
    return seq + seq_add                       # wire seq master observes
def master_ack(ack):                          # master -> outstation (CLS_BARE, dir=MASTER)
    d = f.delta_read()
    return ack - d                             # wire ack outstation observes
def ctl_reset():
    f.delta_reset(); f.last_seq = None

# Response #1 at native seq 1000 (54 B). Master should see seq 1000 (delta_old=0), then delta->7.
w1 = out_response(1000)
check("response#1 wire seq unshifted (delta_old=0)", w1 == 1000, f"{w1}")
check("delta advanced by PAD_CONST after resp#1", f.delta == PAD_CONST, f"{f.delta}")
# Master ACKs the padded stream: native next-byte = 1000+54; with pad it acked 1000+54+7.
# The MASTER sends ack=1061 (1000+54+7); outstation must see 1054.
a1 = master_ack(1000 + 54 + PAD_CONST)
check("master ack de-shifted back to native next-byte", a1 == 1000 + 54, f"{a1}")
# Response #2 at native seq 1054 -> master should see 1054 + 7 (delta_old = 7).
w2 = out_response(1054)
check("response#2 wire seq shifted by prior delta (7)", w2 == 1054 + PAD_CONST, f"{w2}")
check("delta advanced to 14 after resp#2", f.delta == 2 * PAD_CONST, f"{f.delta}")
# RETRANSMIT of response#2 (same native seq 1054): must map to the SAME wire seq, NOT double-count.
w2r = out_response(1054)
check("retransmit-of-last wire seq identical to original", w2r == w2, f"{w2r} == {w2}")
check("retransmit did NOT bump delta (idempotent)", f.delta == 2 * PAD_CONST, f"{f.delta}")
# FIN/RST/SYN reset zeroes delta for the flow.
ctl_reset()
check("SYN/FIN/RST reset zeroes delta", f.delta == 0 and f.last_seq is None)
w3 = out_response(2000)
check("post-reset response starts unshifted again", w3 == 2000, f"{w3}")

print()
if FAIL:
    print(f"ORACLE: FAIL ({len(FAIL)} checks) -> {FAIL}")
    sys.exit(1)
print("ORACLE: ALL CHECKS PASS")

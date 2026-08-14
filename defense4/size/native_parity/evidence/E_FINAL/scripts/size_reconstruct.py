#!/usr/bin/env python3
"""TCP-sequence-based response reconstruction + validation (audit correction).
Per DNP3 request, collect the relay->master response segments, ORDER BY TCP SEQUENCE
(not arrival order), reconstruct the DNP3 0x81 frame, and validate:
  - segment vector (e.g. [28,21] or [49]) in SEQUENCE order
  - total bytes == 49
  - sequence-contiguous (no gap/overlap)
  - DNP3 block CRCs valid
  - IP/TCP checksums valid
  - source_copy_escape = 1 if a standalone 49-byte R2M app segment appears (defended leak)
Emits size-verdict CSV. Usage: size_reconstruct.py <pcap> <class> <mode>"""
import sys
from scapy.all import rdpcap, IP, TCP
sys.path.insert(0, "defense4/size/native_parity/h3_harness")
from dnp3_wire import dnp3_crc
M, R = "192.168.10.1", "192.168.10.7"
def is_dnp(b): return len(b) >= 2 and b[0] == 0x05 and b[1] == 0x64
def dnpfunc(b): return b[12] if len(b) >= 13 and is_dnp(b) else None
def crc_le(d):
    x = dnp3_crc(d); return bytes([x & 0xFF, (x >> 8) & 0xFF])
def validate_dnp3(frame):
    """Validate DNP3 link header CRC + each data block CRC. Return True if all pass."""
    if len(frame) < 10 or not is_dnp(frame): return False
    if frame[8:10] != crc_le(frame[0:8]): return False
    p = 10; ln = frame[2] - 5   # user-data length (bytes after the 8-byte header+crc)
    while ln > 0:
        blk = min(16, ln); data = frame[p:p+blk]
        if len(data) < blk: return False
        if frame[p+blk:p+blk+2] != crc_le(data): return False
        p += blk + 2; ln -= blk
    return True
def main():
    pcap, cls, mode = sys.argv[1], sys.argv[2], sys.argv[3]
    P = rdpcap(pcap)
    # per (sport) connection track; collect events with tcp seq + ip/tcp checksum validity
    def cksum_ok(pk):
        raw = bytes(pk[IP]); import copy
        p2 = pk[IP].__class__(raw)   # re-parse: scapy recomputes chksum on build
        del p2[IP].chksum
        if TCP in p2: del p2[TCP].chksum
        rb = bytes(p2.__class__(bytes(p2)))
        # compare recomputed to captured
        return (p2.__class__(rb)[IP].chksum == pk[IP].chksum) and \
               (p2.__class__(rb)[TCP].chksum == pk[TCP].chksum if TCP in pk else True)
    evs = []
    for pk in P:
        if IP not in pk or TCP not in pk: continue
        b = bytes(pk[TCP].payload)
        evs.append((float(pk.time), "M2R" if pk[IP].src == M else "R2M", dnpfunc(b),
                    len(b), int(pk[TCP].flags), int(pk[TCP].seq), b, pk))
    print("pcap,transaction,class,tcp_seq_1,len_1,tcp_seq_2,len_2,segment_vector,total_bytes,contiguous,crc_valid,cksum_valid,source_copy_escape")
    txn = 0; base = pcap.split("/")[-1]
    for i, (t, d, f, ln, fl, seq, b, pk) in enumerate(evs):
        if d == "M2R" and f in (1, 3, 4):
            # collect R2M app-data (len in 21/28/49) after this request until next request
            segs = []  # (seq, len, bytes, cksum_ok)
            for (tt, dd, ff, ll, ffl, sq, bb, ppk) in evs[i+1:]:
                if dd == "M2R" and ff in (1, 3, 4) and tt > t: break
                if dd == "R2M" and ll in (21, 28, 49) and ll > 0:
                    segs.append((sq, ll, bb, cksum_ok(ppk)))
            if not segs: continue
            segs.sort(key=lambda x: x[0])           # ORDER BY TCP SEQUENCE
            # take the contiguous run starting at the 05 64 frame
            start = next((k for k, s in enumerate(segs) if is_dnp(s[2])), None)
            if start is None: continue
            run = [segs[start]]; escape = 0
            j = start
            while j+1 < len(segs) and segs[j+1][0] == segs[j][0] + segs[j][1]:
                run.append(segs[j+1]); j += 1
            frame = b"".join(s[2] for s in run)
            vec = [s[1] for s in run]
            total = sum(vec)
            contiguous = all(run[k+1][0] == run[k][0] + run[k][1] for k in range(len(run)-1))
            crc_ok = validate_dnp3(frame) if total in (49,) else False
            ck_ok = all(s[3] for s in run)
            # source-copy escape: a lone 49-byte app segment in a DEFENDED capture
            if mode != "native" and any(s[1] == 49 and is_dnp(s[2]) for s in segs) and len(run) == 1 and vec == [49]:
                escape = 1
            s1 = run[0]; s2 = run[1] if len(run) > 1 else (None, None)
            txn += 1
            print("%s,%d,%s,%d,%d,%s,%s,%s,%d,%s,%s,%s,%d" % (
                base, txn, cls, s1[0], s1[1],
                str(s2[0]) if len(run) > 1 else "", str(s2[1]) if len(run) > 1 else "",
                "|".join(map(str, vec)), total, int(contiguous), int(crc_ok), int(ck_ok), escape))
if __name__ == "__main__": main()

import socket,time
exec(open("capture.py").read().split("s=socket.socket")[0])
s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3)); s.bind(("ens1",0)); s.settimeout(2)
def sr(fr):
    s.setblocking(False)
    try:
        while True: s.recv(65535)
    except: pass
    s.setblocking(True); s.settimeout(2); s.send(fr); t0=time.time()
    while time.time()-t0<2:
        try: pkt,sa=s.recvfrom(65535)
        except socket.timeout: return None
        if sa[2]==4: continue
        if len(pkt)<54 or pkt[12:14]!=b"\x08\x00" or pkt[23]!=6: continue
        ihl=(pkt[14]&0x0F)*4
        if (pkt[14+ihl+13]&0x12)==0x12: return pkt
    return None
def canon(pkt):  # bound to IP total_len; zero 5-tuple/seq/ack/checksums (per-connection, not identity)
    tl=(pkt[16]<<8)|pkt[17]; ip=bytearray(pkt[14:14+tl])
    ihl=(ip[0]&0x0F)*4; tcp=ip[ihl:]
    ip[10:12]=b"\x00\x00"; ip[12:20]=b"\x00"*8
    tcp[0:8]=b"\x00"*8; tcp[16:18]=b"\x00\x00"
    return bytes(ip[:ihl])+bytes(tcp)
regions={}
for d,fr in DEV.items():
    r=sr(fr)
    if r: regions[d]=canon(r); print(f"{d:8s} normalized packet (total_len-bounded, 5-tuple zeroed): {regions[d].hex()}")
vals=set(regions.values())
print(f"\nDISTINCT normalized packets across {len(regions)} devices: {len(vals)}")
print("BYTE-IDENTICAL ON SILICON:", "YES" if len(vals)==1 else "NO")

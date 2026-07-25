#!/usr/bin/env python3
# Outstation-side injector that PRESERVES the real per-txn native CLRT: ACK, sleep native_clrt, RESP.
import json,socket,sys,time
iface,lo,hi=sys.argv[1],int(sys.argv[2]),int(sys.argv[3])
fr=json.load(open('/tmp/relay_live.json'))['frames_list']
clrt=json.load(open('/tmp/native_clrt.json'))
s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW); s.bind((iface,0))
for i in range(lo,hi):
    acks=[f for f in fr if f['host']=='hulk' and f['txn']==i and f['role']=='PURE_ACK']
    rsp=[f for f in fr if f['host']=='hulk' and f['txn']==i and f['role']=='RESPONSE']
    for f in acks: s.send(bytes.fromhex(f['hex']))
    time.sleep(clrt[i%len(clrt)]/1000.0)   # real native ACK->RESP gap
    for f in rsp: s.send(bytes.fromhex(f['hex']))
print(json.dumps({"sent_txns":hi-lo}))

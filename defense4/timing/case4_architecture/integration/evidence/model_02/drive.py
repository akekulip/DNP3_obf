#!/usr/bin/env python3
"""Runs inside the model namespace: program ports + forwarding via BF Runtime gRPC, inject a frame, capture output."""
import sys, time, socket, struct, threading
P='/home/philip/bf-sde-9.13.1/install/lib/python3.8/site-packages'
sys.path[:0]=[P, P+'/tofino', P+'/tofino/bfrt_grpc']
import bfrt_grpc.client as gc
import os; PROG=os.environ.get('PROG','egress_wire')
IN_PORT, OUT_PORT = 9, 1           # dev ports; model maps dev port N -> veth(2N), peer veth(2N+1) is ours
tbl_prefix = sys.argv[1] if len(sys.argv)>1 else 'pipe.Ingress.forward'
iface = gc.ClientInterface('127.0.0.1:50052', client_id=1, device_id=0)
iface.bind_pipeline_config(PROG)
bfrt = iface.bfrt_info_get(PROG)
dev = gc.Target(device_id=0, pipe_id=0xffff)
port = bfrt.table_get('$PORT')
for p in (IN_PORT, OUT_PORT):
    port.entry_add(dev, [port.make_key([gc.KeyTuple('$DEV_PORT', p)])],
                   [port.make_data([gc.DataTuple('$SPEED', str_val='BF_SPEED_10G'),
                                    gc.DataTuple('$FEC', str_val='BF_FEC_TYP_NONE'),
                                    gc.DataTuple('$PORT_ENABLE', bool_val=True)])])
time.sleep(2)
fwd = bfrt.table_get(tbl_prefix + '.forwarding')
fwd.entry_add(dev, [fwd.make_key([gc.KeyTuple('ig.ingress_port', IN_PORT)])],
              [fwd.make_data([gc.DataTuple('port', OUT_PORT)], tbl_prefix.replace('pipe.','')+'.route')])
for k, d in port.entry_get(dev, [port.make_key([gc.KeyTuple('$DEV_PORT', OUT_PORT)])], {"from_hw": False}):
    print('port-state', d.to_dict() if hasattr(d,'to_dict') else d)
# frame
frame = bytes.fromhex('020000000002020000000001'+'0800')+bytes.fromhex(
  '45000028000040004006 0000 0a000001 0a000002'.replace(' ',''))+struct.pack('!HHIIBBHHH',1234,20000,1,1,0x50,0x18,8192,0,0)
frame = frame.ljust(60, b'\0')
rx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3)); rx.bind(('veth%d' % (2*OUT_PORT+1), 0)); rx.settimeout(0.5)
tx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW); tx.bind(('veth%d' % (2*IN_PORT+1), 0))
print('TX %d bytes on veth%d: %s' % (len(frame), 2*IN_PORT+1, frame.hex()))
tx.send(frame)
end = time.time()+4; got=[]
while time.time()<end:
    try: b = rx.recv(2048)
    except socket.timeout: continue
    if b[:6]==frame[:6] or b==frame: got.append(b); print('RX %d bytes on veth%d: %s' % (len(b), 2*OUT_PORT+1, b.hex()))
print('RESULT', 'FORWARDED' if got else 'NOT-SEEN', 'identical' if got and got[0]==frame else '')

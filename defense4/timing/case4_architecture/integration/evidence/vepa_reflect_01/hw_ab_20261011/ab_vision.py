"""Run as: sudo python3 ab_vision.py CASE SRC_MAC TAG   (on Vision)
Sends ONE 0x88b5 frame src=SRC_MAC dst=mvB from ns_vepa_a/mvA; listens on mvB in ns_vepa_b;
tcpdump on the parent; prints ethtool -S deltas."""
import subprocess, sys, time, json, re
case, src, tag = sys.argv[1], sys.argv[2], sys.argv[3]
PARENT = 'enp59s0f0np0'
DST = 'ee:df:16:18:b0:a5'
def ethtool():
    out = subprocess.run(['ethtool', '-S', PARENT], capture_output=True, text=True).stdout
    return {k.strip(): int(v) for k, v in re.findall(r'^\s*([^:]+):\s*(\d+)\s*$', out, re.M)}
listener = r'''
import socket,sys,time
s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x88b5)); s.bind(("mvB",0)); s.settimeout(3.0)
try:
    while True:
        f,a=s.recvfrom(2048)
        if f[18:22]==bytes.fromhex(sys.argv[1]): print("RECEIVED src=%s len=%d pkttype=%d"%(f[6:12].hex(),len(f),a[2])); break
except socket.timeout: print("TIMEOUT")
'''
sender = r'''
import socket,sys
s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW); s.bind(("mvA",0))
dst=bytes.fromhex(sys.argv[1].replace(":","")); src=bytes.fromhex(sys.argv[2].replace(":",""))
f=dst+src+b"\x88\xb5"+b"\x00\x00\x00\x01"+bytes.fromhex(sys.argv[3])+b"\x00"*8+b"\x00"*30
print("SENT", s.send(f))
'''
pcap = '/tmp/ab_%s.pcap' % case
td = subprocess.Popen(['tcpdump', '-i', PARENT, '-s0', '-U', '-n', '-e', '-w', pcap, 'ether proto 0x88b5'], stderr=subprocess.DEVNULL)
time.sleep(1.5)
before = ethtool()
ls = subprocess.Popen(['ip', 'netns', 'exec', 'ns_vepa_b', 'python3', '-c', listener, tag], stdout=subprocess.PIPE, text=True)
time.sleep(0.5)
print(subprocess.run(['ip', 'netns', 'exec', 'ns_vepa_a', 'python3', '-c', sender, DST, src, tag], capture_output=True, text=True).stdout.strip())
print('listener:', ls.communicate()[0].strip())
time.sleep(0.5)
after = ethtool()
td.terminate(); td.wait()
print('ethtool deltas:', json.dumps({k: after[k] - before.get(k, 0) for k in after if after[k] != before.get(k, 0)}))
print(subprocess.run(['tcpdump', '-r', pcap, '-n', '-e'], capture_output=True, text=True).stdout.strip())

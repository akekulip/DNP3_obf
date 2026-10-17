"""Independent classic-PCAP decoding and diagnostic correlation; stdlib only."""
import collections
import json
from pathlib import Path
import socket
import struct
import sys

root = Path(sys.argv[1])
def packets(path):
    data = path.read_bytes()
    magic = data[:4]
    endian = '<' if magic in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1') else '>'
    nano = magic in (b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d')
    assert struct.unpack_from(endian+'I', data, 20)[0] == 1
    at = 24
    rows = []
    while at < len(data):
        sec, frac, cap, orig = struct.unpack_from(endian+'IIII', data, at)
        at += 16
        frame = data[at:at+cap]; at += cap
        if frame[12:14] != b'\x08\x00': continue
        ip = frame[14:]
        if ip[9] != 6: continue
        ihl = (ip[0]&15)*4
        length = int.from_bytes(ip[2:4], 'big')
        tcp = ip[ihl:length]
        if len(tcp)<20:continue
        sport,dport,seq,ack = struct.unpack_from('!HHII',tcp)
        rows.append(dict(t=sec*1_000_000+frac/(1000 if nano else 1),
            src=socket.inet_ntoa(ip[12:16]),dst=socket.inet_ntoa(ip[16:20]),
            sport=sport,dport=dport,seq=seq,ack=ack,flags=tcp[13],payload=tcp[(tcp[12]>>4)*4:]))
    return rows

results=[]
for run in sorted(root.glob('ctl_m9d_ackdiag_b*_01')):
    for trial in sorted(run.glob('*/*/*_t*')):
        if not (trial/'timing.json').is_file():continue
        ex=json.loads((trial/'timing.json').read_text())['exchanges']
        snap=json.loads(next((trial/'snapshots').glob('*_after.json')).read_text())
        entries=snap['egress_diag']['entries']
        wire=packets(trial/'in.pcap')
        seen=collections.defaultdict(list)
        for f in wire:
            if f['sport']==20000:seen[f['ack']&0x3fff].append(f)
        out=[]; failures=[]; keys=[]
        for i,e in enumerate(ex):
            if e.get('clrt_us') is None:continue
            ats=e['t_req']+e['ack_lat_us']; rts=e['t_req']+e['rt_us']
            aa=[f for f in wire if f['sport']==20000 and not f['payload'] and f['flags']==16 and abs(f['t']-ats)<=0.1]
            rr=[f for f in wire if f['sport']==20000 and f['payload'] and abs(f['t']-rts)<=0.1]
            if len(aa)!=1 or len(rr)!=1:failures.append([i,'ambiguous or missing pair']);continue
            a,b=aa[0],rr[0]
            if (a['src'],a['dst'],a['sport'],a['dport'],a['ack'])!=(b['src'],b['dst'],b['sport'],b['dport'],b['ack']):failures.append([i,'tuple or ack mismatch']);continue
            key=a['ack']&0x3fff;keys.append(key)
            # Check final-register overwrite risk against every observed server packet sharing the index.
            relevant=seen[key]
            if len(relevant)!=2:failures.append([i,'register index has additional observed packets',len(relevant)])
            lo,hi=entries[str(key)];delta=(hi-lo)&0xffffffff
            if delta>=2**31:delta-=2**32
            out.append(dict(index=i,kind=e['kind'],host_gap_us=b['t']-a['t'],switch_gap_us=delta/1000,
                            host_error_us=abs(e['clrt_us']-950),key=key,payload_bytes=len(b['payload'])))
        if len(keys)!=len(set(keys)):failures.append(['index collision'])
        timed=trial.parent.name in ('combined','timing_only')
        results.append(dict(run=run.name,arm=trial.parent.name,timed=timed,matched=len(out),
            failures=failures,max_switch_error_us=max(abs(x['switch_gap_us']-950) for x in out),
            tails=[x for x in out if timed and x['host_error_us']>100],rows=out))
print(json.dumps(dict(timed_count=sum(x['matched'] for x in results if x['timed']),
    all_arm_count=sum(x['matched'] for x in results),results=results),indent=2))

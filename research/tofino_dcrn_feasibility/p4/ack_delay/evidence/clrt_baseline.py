# section 5.A — original PCAP analysis: native CLRT baseline + separate/combined verification
import sys
from scapy.all import rdpcap, IP, TCP
DEVS = {"SEL751":"10.0.0.1", "AB1400":"10.0.0.12", "ION7550":"10.0.0.11"}
MASTER = "10.0.0.3"; PORT = 20000

def analyze(pcap, dev, dip):
    pkts = rdpcap(pcap)
    # ordered events on the master<->device:20000 flow
    ev = []
    conns = set()
    retrans = 0; seen_seq = {}
    for p in pkts:
        if IP not in p or TCP not in p: continue
        ip, tcp = p[IP], p[TCP]
        if PORT not in (tcp.sport, tcp.dport): continue
        if not ((ip.src==MASTER and ip.dst==dip) or (ip.src==dip and ip.dst==MASTER)): continue
        plen = len(tcp.payload); t = float(p.time)
        flags = tcp.flags
        conns.add((tcp.sport, tcp.dport) if ip.src==MASTER else (tcp.dport, tcp.sport))
        # crude retrans: same (dir,seq,plen>0) seen again
        if plen>0:
            k=(ip.src, tcp.seq, plen)
            if k in seen_seq: retrans+=1
            seen_seq[k]=t
        direction = "req" if ip.src==MASTER else "dev"
        ev.append((t, direction, plen, int(flags), tcp.seq, tcp.ack))
    # transaction walk: master payload req -> (dev pure-ACK?) -> dev payload resp
    req_ack=[]; ack_resp=[]; req_resp=[]; sizes=[]
    n_req=n_pureack=n_resp=0; n_sep=0; n_comb=0
    i=0
    while i < len(ev):
        t,d,pl,fl,sq,ak = ev[i]
        if d=="req" and pl>0:
            n_req+=1; treq=t
            # look ahead for dev pure-ACK (pl==0) then dev resp (pl>0), until next req
            j=i+1; pure_ack_t=None; resp_t=None; resp_sz=None
            while j < len(ev):
                tj,dj,plj,flj,sqj,akj = ev[j]
                if dj=="req" and plj>0: break   # next request
                if dj=="dev" and plj==0 and pure_ack_t is None and resp_t is None:
                    pure_ack_t=tj; n_pureack+=1
                if dj=="dev" and plj>0 and resp_t is None:
                    resp_t=tj; resp_sz=plj; n_resp+=1; break
                j+=1
            if resp_t is not None:
                req_resp.append((resp_t-treq)*1000); sizes.append(resp_sz)
                if pure_ack_t is not None:
                    n_sep+=1
                    req_ack.append((pure_ack_t-treq)*1000)
                    ack_resp.append((resp_t-pure_ack_t)*1000)  # CLRT
                else:
                    n_comb+=1
            i=j
        else:
            i+=1
    def stat(x):
        if not x: return "n=0"
        x=sorted(x); n=len(x)
        return "n=%d median=%.2f mean=%.2f p10=%.2f p90=%.2f min=%.2f max=%.2f" % (
            n, x[n//2], sum(x)/n, x[max(0,n//10)], x[min(n-1,9*n//10)], x[0], x[-1])
    from collections import Counter
    szc = Counter(sizes)
    print("==== %s (%s) ====" % (dev, dip))
    print("  connections=%d  requests=%d  pure_ACKs=%d  responses=%d  retrans(payload)=%d" % (len(conns), n_req, n_pureack, n_resp, retrans))
    print("  MODE: separate=%d  combined=%d  -> %s" % (n_sep, n_comb, "SEPARATE-dominant" if n_sep>n_comb else "COMBINED-dominant"))
    print("  response sizes (B): %s" % dict(sorted(szc.items())))
    print("  request->ACK  ms : %s" % stat(req_ack))
    print("  ACK->response(CLRT)ms: %s" % stat(ack_resp))
    print("  request->response ms : %s" % stat(req_resp))

base = "/home/philip/Projects/DNP3/Traffic Trace"
for dev,dip in DEVS.items():
    analyze("%s/%s.pcap" % (base, dev), dev, dip)
    print()

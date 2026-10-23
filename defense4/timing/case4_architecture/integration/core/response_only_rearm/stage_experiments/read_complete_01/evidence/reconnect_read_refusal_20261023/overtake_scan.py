import sys,struct,glob,os,json
def rd(p):
    d=open(p,'rb').read();o=24;r=[]
    while o+16<=len(d):
        ts,us,inc,_=struct.unpack('<IIII',d[o:o+16]);r.append((ts+us/1e6,d[o+16:o+16+inc]));o+=16+inc
    return r
def parse(f):
    ihl=(f[14]&15)*4;t=14+ihl;tot=int.from_bytes(f[16:18],'big');doff=(f[t+12]>>4)*4
    return f[29],f[t+13],tot-ihl-doff,int.from_bytes(f[t+4:t+8],'big')
for c in sorted(glob.glob(sys.argv[1]+'/**/c[0-9]',recursive=True)):
    if not os.path.exists(c+'/out.pcap'): continue
    O=[(ts,)+parse(f) for ts,f in rd(c+'/out.pcap')];I=[(ts,)+parse(f) for ts,f in rd(c+'/in.pcap')]
    ack=next((x for x in O if x[1]==61 and x[2]==0x10 and x[3]==0),None)
    rq=next((x for x in O if x[1]==61 and x[3] in (20,25,27)),None)
    if not ack or not rq: continue
    acki=next((x for x in I if x[1]==61 and x[2]==0x10 and x[4]==ack[4]),None)
    rqi=next((x for x in I if x[1]==61 and x[3]==rq[3] and x[4]==rq[4]),None)
    dup=sum(1 for x in O if x[1]==61 and x[3]==rq[3] and x[4]==rq[4])
    unm=[]
    try: unm=json.load(open(c+'/wire.json'))['unmatched_sent']
    except Exception: pass
    print('%-95s ack_delay=%.2fms read_after_ack_sent=%.2fms overtook=%s first_read_copies=%d unmatched=%s'%(c[-95:],(acki[0]-ack[0])*1e3 if acki else -1,(rq[0]-ack[0])*1e3,(acki is not None and rq[0]<acki[0]),dup,[(u['sent_index'],u['len']) for u in unm]))

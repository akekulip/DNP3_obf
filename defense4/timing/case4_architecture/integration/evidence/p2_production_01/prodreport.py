import json,sys,subprocess,os
O=sys.argv[1]; labels=sys.argv[2:]
CC='protocol/hw_vepa/clrt_check.py'
PY=os.environ.get('RESEARCH_PYTHON','python3')
rows=[]
for lbl in labels:
    d='%s/%s'%(O,lbl)
    try:
        a=json.load(open(d+'/sna_%s.json'%lbl)); b=json.load(open(d+'/snb_%s.json'%lbl))
    except Exception as e:
        print(lbl,'missing snapshots',e); continue
    lp_a,lp_b=a.get('loop_ports',{}),b.get('loop_ports',{})
    fr=by=0; per={}
    for r in lp_a:
        va,vb=lp_a[r] or {},lp_b.get(r) or {}
        f=va.get('$FramesTransmittedAll',0)-vb.get('$FramesTransmittedAll',0)
        o=va.get('$OctetsTransmittedTotal',0)-vb.get('$OctetsTransmittedTotal',0)
        per[r]=(f,o); fr+=f; by+=o
    oc={k:a['outcomes'].get(k,0)-b['outcomes'].get(k,0) for k in a['outcomes']}
    fb=oc.get('OUT_ACK_FALLBACK',0)+oc.get('OUT_RESP_FALLBACK',0)
    m=json.load(open(d+'/master.json')); o=json.load(open(d+'/outstation.json'))
    r=subprocess.run([PY,CC,d+'/out.pcap',d+'/in.pcap'],capture_output=True,text=True)
    T=json.loads(r.stdout)['READ']
    c,ak,rt=T['clrt_us'],T['ack_lat_us'],T['rt_us']
    sh=a.get('shaping',{})
    rows.append((lbl,fr,by,per,oc,fb,m,o,c,ak,rt,T,sh))
base=rows[0] if rows else None
print('%-14s %11s %13s %7s | %6s %7s %6s %6s %6s | %s'%('config','loop_pkts','loop_bytes','x_pkts','CLRTmd','sdPop','sdSmp','ACKmd','RTmd','correctness'))
for lbl,fr,by,per,oc,fb,m,o,c,ak,rt,T,sh in rows:
    ok=(m.get('success') and m.get('all_reads_match_seed') and o.get('select_real')==1 and o.get('operate_real')==1 and not (o.get('operate_decoy') or o.get('select_decoy')) and fb==0 and oc.get('OUT_ACK_COMMIT')==50 and oc.get('OUT_RESP_RELEASE')==50 and oc.get('OUT_OP_RELEASE')==1)
    print('%-14s %11d %13d %7.1f | %6s %7s %6s %6s %6s | %s (commit=%s rel=%s op=%s fb=%d n=%s)'%(
        lbl,fr,by,(base[1]/fr if fr else 0),c['median'],c.get('sd_population'),c.get('sd_sample'),ak['median'],rt['median'],
        'OK' if ok else 'CHECK',oc.get('OUT_ACK_COMMIT'),oc.get('OUT_RESP_RELEASE'),oc.get('OUT_OP_RELEASE'),fb,c['n']))
print()
for lbl,fr,by,per,oc,fb,m,o,c,ak,rt,T,sh in rows:
    print(lbl,'per-port (pkts,bytes):',{k:v for k,v in per.items()},'| held_rewait(total)=',oc.get('OUT_HELD_REWAIT'),'| CLRT min/max/p95=',c['min'],c['max'],c.get('p95'),'| RT p95=',rt['p95'])
    if any((sh.get(r,{}) or {}).get('max_rate_enable') for r in sh): print('   achieved:',{r:(sh[r].get('achieved_pps'),sh[r].get('max_burst_size')) for r in ('ACK_BLOCK','ACK_HOLD','RESP_BLOCK','RESP_HOLD','OP_BLOCK','OP_HOLD') if r in sh})

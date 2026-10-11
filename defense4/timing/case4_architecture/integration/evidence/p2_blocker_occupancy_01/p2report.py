import json,sys,subprocess,os
O=sys.argv[1]; lbl=sys.argv[2]
d=O+'/'+lbl
a=json.load(open(d+'/sna_%s.json'%lbl)); b=json.load(open(d+'/snb_%s.json'%lbl))
rw=a.get('diag',{}).get('rewait',{}); bl=a.get('diag',{}).get('blocker_laps',{})
oc={k:a['outcomes'].get(k,0)-b['outcomes'].get(k,0) for k in a.get('outcomes',{})}
fb=oc.get('OUT_ACK_FALLBACK',0)+oc.get('OUT_RESP_FALLBACK',0)
m=json.load(open(d+'/master.json')); o=json.load(open(d+'/outstation.json'))
print(lbl)
print('  originals rewait ACK=%s RESP=%s OP=%s  total=%s'%(rw.get('ACK'),rw.get('RESP'),rw.get('OPERATE'),sum(v or 0 for v in rw.values())))
print('  blocker laps    ACK=%s RESP=%s OP=%s  total=%s'%(bl.get('ACK'),bl.get('RESP'),bl.get('OP'),sum(v or 0 for v in bl.values())))
print('  outcomes: ACK_COMMIT=%s RESP_REL=%s OP_REL=%s fallback=%d | master ok=%s reads=%s match=%s sel=%s op=%s decoy=%s'%(
  oc.get('OUT_ACK_COMMIT'),oc.get('OUT_RESP_RELEASE'),oc.get('OUT_OP_RELEASE'),fb,m.get('success'),m.get('reads_completed'),m.get('all_reads_match_seed'),o.get('select_real'),o.get('operate_real'),(o.get('operate_decoy') or 0)+(o.get('select_decoy') or 0)))
sh=a.get('shaping',{})
print('  achieved_pps:', {r:(sh.get(r,{}).get('achieved_pps'),sh.get(r,{}).get('max_burst_size'),sh.get(r,{}).get('max_rate_enable')) for r in ('ACK_BLOCK','ACK_HOLD','RESP_BLOCK','RESP_HOLD')})
r=subprocess.run([os.environ.get('RESEARCH_PYTHON','python3'),'protocol/hw_vepa/clrt_check.py',d+'/out.pcap',d+'/in.pcap'],capture_output=True,text=True)
try:
    t=json.loads(r.stdout)['READ']['clrt_us']
    print('  READ CLRT us: n=%s min=%s median=%s max=%s sd_pop=%s sd_sample=%s p95=%s'%(t['n'],t['min'],t['median'],t['max'],t.get('sd_population'),t.get('sd_sample'),t.get('p95')))
except Exception as e: print('  clrt err',e,r.stderr[-200:])

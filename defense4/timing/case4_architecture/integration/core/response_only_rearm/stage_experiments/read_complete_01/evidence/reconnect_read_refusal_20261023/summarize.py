import json,sys
L=json.load(open(sys.argv[1]+'/replay_steps.json'))
def g(r,k,f='f1'):
    v=r.get(k); return v.get(f) if isinstance(v,dict) else v
for s in L:
    if 'registers' not in s: print(s); continue
    r=s['registers']
    out={p:['%s%s'%(d.get('flags',d.get('head','?')[:8]),'' if 'src' not in d else d['src'][-3:]) for d in v] for p,v in s.get('out',{}).items() if v}
    busy=[g(r,'n_Ingress.count_busy[%d]'%i) for i in range(8)]
    first=[g(r,'n_Ingress.count_first[%d]'%i) for i in range(4)]
    w=r.get('n_Ingress.work.work[0]',{})
    print('%-18s out=%s work=(g%s,p%s) owner=%s epochN=%s cl=%s sv=%s ctr=%s busy=%s first=%s term=%s E(ep=%s isn=%s mode=%s)'%(s['step'],out,w.get('generation'),w.get('phase'),
      hex(g(r,'n_Ingress.owner[0]') or 0),g(r,'n_Ingress.epoch[0]'),g(r,'n_Ingress.client[0]'),g(r,'n_Ingress.server[0]'),g(r,'n_Ingress.counter[0]'),busy,first,[g(r,'n_Ingress.count_term[%d]'%i) for i in range(4)],
      g(r,'r_Egress.epoch[0]'),g(r,'r_Egress.master_isn[0]'),g(r,'r_Egress.mode[0]')))

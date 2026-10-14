"""Per-gress stage counts of two compiled outputs from their context.json (pipe p0: N ingress, E egress; p1: T).

  python3 stage_counts.py BASELINE_OUT EXPERIMENT_OUT
"""
import json,sys,collections
def stages(out):
    res={}
    for pipe,role in (('p0',None),('p1','T')):
        c=json.load(open('%s/%s/context.json'%(out,pipe)))
        per=collections.defaultdict(set); tables={}
        for t in c['tables']:
            gress=t.get('direction') or t.get('gress')
            for st in t.get('stage_tables',[]):
                per[gress].add(st['stage_number']); tables.setdefault(t['name'],set()).add((gress,st['stage_number']))
        for g,s in per.items():
            name={'p0':{'ingress':'N','egress':'E'},'p1':{'ingress':'T','egress':'p1_egress'}}[pipe].get(g,g)
            res[name]=max(s)+1
        res['_tables_%s'%pipe]=tables
    return res
a=stages(sys.argv[1]); b=stages(sys.argv[2])
print('baseline', {k:v for k,v in a.items() if not k.startswith('_')})
print('crc_exp ', {k:v for k,v in b.items() if not k.startswith('_')})
ta,tb=a['_tables_p0'],b['_tables_p0']
for n in sorted(set(ta)|set(tb)):
    if 'ctl' in n or 'crc' in n or ta.get(n)!=tb.get(n):
        if 'r_Egress' in n or 'egress' in str(ta.get(n,''))+str(tb.get(n,'')):
            print('%-45s %s -> %s'%(n, sorted(ta.get(n,[])), sorted(tb.get(n,[]))))

"""Select exact, strictly padded aggregate READ targets from retained native captures.
No hardware or classifier claim. Frequencies are experimental fixture frequencies.
"""
import collections,hashlib,itertools,json,pathlib,sys
ROOT=pathlib.Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'source/full_read_01'))
import fullread as fr
import general_read_padding as gp

def load():
    rows=[]; manifest=[]
    for directory in sorted((ROOT/'inputs').iterdir()):
        capture=directory/'capture.pcap'; meta=json.loads((directory/'run.json').read_text())
        ts=fr.transactions(capture)
        records=[r for r in fr.capture.tcp_records(capture) if r['dst'][1]==20000]
        requests=[r['frame'] for r in fr.direction_frames(records) if gp.std.deframe(r['frame'])[1][2]==1]
        assert len(ts)==len(requests)==meta['reads']
        for i,(t,q) in enumerate(zip(ts,requests)):
            raw=b''.join(bytes.fromhex(f) for f in t['response_frames_hex'])
            _,app=gp.one_fragment(raw)
            # Invoke the serializer's input validation, without inventing a response.
            r=gp.pad_read(q,raw,[len(raw)],pad_start=16,pad_stop=4095)
            assert r.status=='already_at_target'
            rows.append(dict(run=directory.name,exchange=i,request=q,response=raw,
                             native=len(raw),app_bytes=len(app),frames=t['link_frames'],tcp_segments=t['tcp_segments']))
        manifest.append(dict(run=directory.name,capture_sha256=hashlib.sha256(capture.read_bytes()).hexdigest(),reads=len(ts),mode=meta['mode'],database=meta['db']))
    return rows,manifest

def reachable(row):
    # Exact prefix construction, including 8/16-bit range transition and capacity.
    out=set();start=16
    for n in range(4,min(4095-start+1,2048-row['app_bytes'])+1):
        w=1 if start+n-1<=255 else 2; b=3+2*w+n
        if row['app_bytes']+b<=2048:out.add(row['native']+gp.prefix_size(b))
    return out

def solve(rows):
    counts=collections.Counter(r['native'] for r in rows);sizes=sorted(counts)
    groups={n:[r for r in rows if r['native']==n] for n in sizes}
    # Intersect across all represented shapes so a bucket cannot hide ineligibility.
    reach={n:set.intersection(*(reachable(r) for r in {r['app_bytes']:r for r in groups[n]}.values())) for n in sizes}
    candidates={}
    for t in sorted(set.union(*reach.values())):
        mask=tuple(n for n in sizes if t in reach[n])
        candidates.setdefault(mask,t) # Larger targets with the same coverage are dominated.
    best={}
    for k in (1,2,3):
      for targets in itertools.combinations(sorted(candidates.values()),k):
        mapping={n:next((t for t in targets if t in reach[n]),None) for n in sizes}
        if None in mapping.values() or len(set(mapping.values()))!=k:continue
        buckets={t:[n for n in sizes if mapping[n]==t] for t in targets}
        total=sum(counts[n]*(mapping[n]-n) for n in sizes)
        record=dict(targets=targets,mapping=mapping,buckets=buckets,total_added_bytes=total,
                    mean_added_bytes=total/len(rows),native_total_bytes=sum(n*c for n,c in counts.items()),
                    added_percent=100*total/sum(n*c for n,c in counts.items()),
                    merged_shape_buckets=sum(len(v)>1 for v in buckets.values()))
        if k not in best or (total,targets)<(best[k]['total_added_bytes'],best[k]['targets']):best[k]=record
    return dict(counts=dict(counts),exchanges=len(rows),best=best)

rows,manifest=load()
result=solve(rows);result['base_database_only']=solve([r for r in rows if r['run']!='native_integrity_large'])
result['input_manifest']=manifest
chosen=result['best'][3]['targets']
result['selection_rule']='minimum frequency-weighted added bytes, complete strictly-padded coverage, exactly 3 nonempty targets; compare 2-target alternative; no classifier optimization'
result['selected_targets']=chosen
verified=[]
for row in rows:
    r=gp.pad_read(row['request'],row['response'],chosen,pad_start=16,pad_stop=4095)
    assert r.status=='padded' and len(r.output)==result['best'][3]['mapping'][row['native']]
    _,app=gp.one_fragment(row['response']);_,padded_app=gp.one_fragment(r.output)
    assert padded_app[:4]==app[:4] and padded_app.endswith(app[4:])
    original=gp.std.check_read_response(gp.std.fragment_user(app))[1]
    padded=gp.std.check_read_response(gp.std.fragment_user(padded_app))[1]
    assert padded[r.padding_points:]==original
    verified.append(dict(run=row['run'],exchange=row['exchange'],native=row['native'],target=r.target,
                         native_frames=row['frames'],native_tcp_payloads=row['tcp_segments'],
                         output_frames=[len(f) for f in gp.split_frames(r.output)],
                         added=len(r.output)-len(row['response']),padding_points=r.padding_points,
                         output_sha256=hashlib.sha256(r.output).hexdigest()))
result['encoding_verified_exchanges']=len(verified)
(ROOT/'selection.json').write_text(json.dumps(result,indent=2))
(ROOT/'exchange_ledger.json').write_text(json.dumps(verified,indent=2))
print(json.dumps({k:v for k,v in result.items() if k not in ('input_manifest','base_database_only')},indent=2))
print('BASE DATABASE ONLY',json.dumps(result['base_database_only'],indent=2))

import pathlib,json,sys,argparse
ROOT=pathlib.Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
import live_check as l
ap=argparse.ArgumentParser();ap.add_argument('--binary',required=True);ap.add_argument('--output',required=True);args=ap.parse_args()
binary=pathlib.Path(args.binary).resolve();root=pathlib.Path(args.output).resolve();root.mkdir(exist_ok=False);summary=[]
for name,db in [('full','base'),('segmented','large')]:
 a,_=l.run(binary,root,name,'integrity',db,[163,269,399],1024,False)
 b,rs=l.run(binary,root,name,'integrity',db,[163,269,399],1024,True)
 rs=[r for r in rs if r['direction']=='response']
 for x,y,r in zip(a['scans'],b['scans'],rs):
  assert all(y['points'][k]==v for k,v in x['points'].items())
  n=r['padding']['padding_points'];extras=set(y['points'])-set(x['points'])
  assert extras=={'bi:'+str(i) for i in range(1024,1024+n)}
  assert all(y['points'][k]==[0,0] for k in extras)
  assert r['padding']['construction']=='resegment'
 assert a['iin']==b['iin']
 summary.append(dict(case=name,passed=16,native=len(bytes.fromhex(rs[0]['native'])),target=len(bytes.fromhex(rs[0]['sent'])),construction='resegment',original_points_preserved=True))
(root/'summary.json').write_text(json.dumps(summary,indent=2));print(json.dumps(summary,indent=2))

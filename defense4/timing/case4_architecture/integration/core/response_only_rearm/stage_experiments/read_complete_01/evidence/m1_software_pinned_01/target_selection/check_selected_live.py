import sys,pathlib,json,argparse
ROOT=pathlib.Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
import live_check as l
ap=argparse.ArgumentParser();ap.add_argument('--binary',required=True);ap.add_argument('--output',required=True);args=ap.parse_args()
out=pathlib.Path(args.output).resolve();out.mkdir(parents=True,exist_ok=False)
binary=pathlib.Path(args.binary).resolve();summary=[]
for name,mode in [('selected_range','range'),('selected_analog','analog')]:
 native,_=l.run(binary,out,name,mode,'base',[163,269,399],16,False)
 padded,records=l.run(binary,out,name,mode,'base',[163,269,399],16,True)
 responses=[r for r in records if r['direction']=='response']
 for a,b,r in zip(native['scans'],padded['scans'],responses):
  assert all(b['points'][k]==v for k,v in a['points'].items())
  n=r['padding']['padding_points'];extra=set(b['points'])-set(a['points'])
  assert extra=={'bi:'+str(i) for i in range(16,16+n)}
  assert all(b['points'][k]==[0,0] for k in extra)
  assert r['padding']['target']==163
 assert native['iin']==padded['iin']
 summary.append(dict(mode=mode,padded_polls=16,baseline_polls=16,target=163,originals_preserved=True,iin=padded['iin']))
(out/'summary.json').write_text(json.dumps(summary,indent=2));print(json.dumps(summary,indent=2))

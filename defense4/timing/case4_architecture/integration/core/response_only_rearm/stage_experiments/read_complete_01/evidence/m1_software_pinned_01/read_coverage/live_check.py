"""Live READ-only software endpoint check; two TCP legs, no P4 timing/mapper proof."""
import sys,pathlib,subprocess,socket,select,threading,json,os,argparse,collections
BASE=pathlib.Path(__file__).resolve().parent
sys.path.insert(0,str(BASE/'source/full_read_01'))
import general_read_padding as gp
s=gp.std

def consume(buf):
    out=[]
    while len(buf)>=3:
        if buf[:2]!=b'\x05\x64':raise ValueError('bad stream start')
        n=s.frame_length(buf[2]-5)
        if len(buf)<n:break
        out.append(bytes(buf[:n]));del buf[:n]
    return out

def run(binary,root,name,mode,db,targets,start,padded,reads=16):
    d=root/(name+('_padded' if padded else '_native'));d.mkdir()
    stop=d/'stop';env=dict(os.environ,FULL_READ_GATE='1')
    ls=socket.socket();ls.bind(('127.0.0.1',0));ls.listen(1)
    reserve=socket.socket();reserve.bind(('127.0.0.1',0));port=reserve.getsockname()[1];reserve.close()
    out=subprocess.Popen([str(binary),'outstation','127.0.0.1',str(port),str(stop),'45',db],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    records=[];errors=[];pending=[];requests=collections.deque()
    assert out.stdout.readline().strip()=='READY'
    def proxy():
      try:
        m,_=ls.accept();o=socket.create_connection(('127.0.0.1',port));buffers={m:bytearray(),o:bytearray()}
        with m,o:
          while True:
            ready,_,_=select.select([m,o],[],[],10)
            if not ready:raise TimeoutError('idle')
            for src in ready:
              data=src.recv(65536)
              if not data:return
              buffers[src]+=data
              for f in consume(buffers[src]):
                _,u=s.deframe(f)
                if src is m:
                  if len(u)<3 or u[2]!=1:raise ValueError('test fixture sent non-READ')
                  requests.append(f);o.sendall(f);records.append(dict(direction='request',native=f.hex(),sent=f.hex()))
                else:
                  pending.append(f)
                  if not u[0]&s.FIN:continue
                  native=b''.join(pending);pending.clear();q=requests.popleft();sent=native;info=None
                  if padded:
                    r=gp.pad_read(q,native,targets,pad_start=start,pad_stop=4095)
                    if r.status!='padded':raise AssertionError(r.status)
                    sent=r.output;info={k:v for k,v in vars(r).items() if k!='output'}
                  m.sendall(sent);records.append(dict(direction='response',native=native.hex(),sent=sent.hex(),padding=info))
      except Exception as e:errors.append(repr(e))
    t=threading.Thread(target=proxy,daemon=True);t.start()
    try:
      master=subprocess.run([str(binary),'master','127.0.0.1',str(ls.getsockname()[1]),str(stop),str(reads),mode,'1'],env=env,capture_output=True,text=True,timeout=35)
      t.join(11)
    finally:
      stop.touch();stdout,stderr=out.communicate(timeout=5);ls.close()
      (d/'outstation.log').write_text(stdout+stderr);(d/'wire.json').write_text(json.dumps(records,indent=2));(d/'errors.json').write_text(json.dumps(errors))
    (d/'master.json').write_text(master.stdout);(d/'master.stderr').write_text(master.stderr)
    assert not errors,errors
    assert not t.is_alive() and master.returncode==0
    result=json.loads(master.stdout)
    assert len(result['scans'])==reads and all(x['completed'] for x in result['scans'])
    assert result['tasks']=={'SUCCESS':reads},result['tasks']
    assert len([r for r in records if r['direction']=='response'])==reads
    return result,records

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--binary',required=True);ap.add_argument('--output',required=True);a=ap.parse_args()
    binary=pathlib.Path(a.binary).resolve();root=pathlib.Path(a.output).resolve();root.mkdir(parents=True,exist_ok=False)
    summary=[]
    # Reachability tests, NOT a distribution-derived deployment policy.
    cases=[('range','range','base',[73,269,399],16),('integrity','integrity','base',[73,269,399],16),('class0','class0','base',[292],16),('analog','analog','base',[165,269],16),('segmented','integrity','large',[269,399],16),('wide_multiframe','integrity','large',[800],1024)]
    for name,mode,db,targets,start in cases:
      native,_=run(binary,root,name,mode,db,targets,start,False)
      padded,records=run(binary,root,name,mode,db,targets,start,True)
      responses=[r for r in records if r['direction']=='response']
      for a,b,r in zip(native['scans'],padded['scans'],responses):
        assert all(b['points'][k]==v for k,v in a['points'].items())
        n=r['padding']['padding_points'];extra=set(b['points'])-set(a['points'])
        assert extra=={'bi:'+str(i) for i in range(start,start+n)}
        assert all(b['points'][k]==[0,0] for k in extra)
      assert native['iin']==padded['iin'] and native['other_types']==padded['other_types']
      summary.append(dict(name=name,mode=mode,db=db,reads=16,targets=targets,actual=responses[0]['padding'],iin=padded['iin'],native_frame_lengths=[len(x) for x in gp.split_frames(bytes.fromhex(responses[0]['native']))],output_frame_lengths=[len(x) for x in gp.split_frames(bytes.fromhex(responses[0]['sent']))],originals_preserved=True))
      (root/'summary.json').write_text(json.dumps(summary,indent=2));print(name,'PASS',summary[-1]['native_frame_lengths'],'->',summary[-1]['output_frame_lengths'],flush=True)
if __name__=='__main__':main()

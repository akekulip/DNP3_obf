"""Current-source N functional model regressions; isolated model, no physical target.
BFRT presets are diagnostic fixtures, not a live state/rearm API.
"""
import json,os,struct,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
sys.path[:0]=[str(HERE/'tests'),str(HERE.parents[1]/'core')]
import read_support as rs
import vectors
from model_driver import Model,same_frame,Report
COMPOSED=os.environ.get('TASK1_NT')=='1'
class NModel(Model):
 def table(self,name,raw=False):
  if COMPOSED and not raw and name.startswith('Ingress.'):name='p0.NIngress.'+name[len('Ingress.'):]
  return super().table(name,raw)
 def add(self,table,keys,action=None,data=None,priority=None,pipe=None):
  if COMPOSED and action and action.startswith('Ingress.'):action='NIngress.'+action[len('Ingress.'):]
  return super().add(table,keys,action,data,priority,pipe)
m=NModel(ports=[1,2,68,325,196,9,64])
r=Report('N-task1',physical=False,clock='functional only; no timing bound',padding='original Ethernet minimum-size zero padding only')
def cell(name,index=0):
 return {k:(v[0] if isinstance(v,list) else v) for k,v in m.register_read('Ingress.'+name,index,pipe=0).items() if k!='$REGISTER_INDEX'}
def put(name,values,index=0):
 t=m.table('Ingress.'+name);names=t.info.data_field_name_list_get()
 if isinstance(values,int):values={names[0]:values}
 else:values={next(n for n in names if n.endswith('.'+k)):v for k,v in values.items()}
 m.register_write('Ingress.'+name,index,values)
def scalar(name):return next(iter(cell(name).values()))
def state():return {k:cell(k) for k in ('owner','epoch','client','server','work.work','application','frozen_decoy_off','pair_real_links_real_tcp_src','pair_real_tcp_dst_real_tcp_ports','pair_real_object_real_on','pair_real_off_native_start','pair_native_end_server_start','pair_frozen_decoy_object_frozen_decoy_on','read_app')}
def start(owner=0x50001,client=1000,server=2000,epoch=17,work=(0,4)):
 for k,v in dict(owner=owner,client=client,server=server,epoch=epoch,counter=0,read_app=0).items():put(k,v)
 put('work.work',dict(generation=work[0],phase=work[1]))
def install():
 keys=('hdr.ip.src','hdr.ip.dst','hdr.tcp.sport','hdr.tcp.dport')
 for port,out in ((1,2),(2,1),(68,68)):m.add('Ingress.ports',{'ig.ingress_port':port},'Ingress.route',{'port':out})
 for vals,action,out,links in (((vectors.CLIENT,vectors.SERVER,vectors.CLIENT_PORT,vectors.SERVER_PORT),'forward_flow',2,(0,0x100)),((vectors.SERVER,vectors.CLIENT,vectors.SERVER_PORT,vectors.CLIENT_PORT),'reverse_flow',1,(0x100,0))):
  key=dict(zip(keys,vals));m.add('Ingress.connection',key,'Ingress.'+action,{'port':out});m.add('Ingress.read_connection',key,'Ingress.read_configure',dict(dst=links[0],src=links[1]))
  m.add('Ingress.data_connection',key,'Ingress.configure',dict(zip(('index','code','repeat','on','off'),vectors.decoy_config())))
def frames(port,raw):return m.exchange(port,raw,[1,2,325,196,9,64],timeout=.55,quiet=.04)
def only(got,port,raw):return len(got[port])==1 and same_frame(got[port][0],raw) and sum(map(len,got.values()))==1
ok=True
try:
 install()
 for phase in (13,14,15):
  for flags in (17,20,4):
   for reverse in (False,True):
    start(phase<<16|1,1020,2000)
    raw=vectors.frame(flags,2000 if reverse else 1020,1020 if reverse else 2000,reverse)
    got=frames(2 if reverse else 1,raw);out=got[325]
    expected=struct.pack('>IIIBBH',17,17,0,4,2 if reverse else 1,0)
    if COMPOSED:
     end=9 if reverse else 64
     good=only(got,end,raw) and scalar('owner')==0x70001
     q=m.register_read('p2.TIngress.quarantined_epoch',0,pipe=2)
     good=good and next(v[0] for k,v in q.items() if k.endswith('.f1'))==17
    else:good=len(out)==1 and out[0][:16]==expected and same_frame(out[0][16:],raw) and sum(map(len,got.values()))==1 and scalar('owner')==0x70001
    ok=r.add('close-%d-%d-%d'%(phase,flags,reverse),'one reset carrying original',got,good,raw=raw,state=state()) and ok
 start(0xe0001,1020,2000,work=(29,2));before=cell('work.work');raw=vectors.frame(17,1020,2000);prefix=struct.pack('>IIIHH',17,17,0xe0001,0x104,0)
 for name,p in (('busy-close',prefix),('duplicate-close',prefix),('stale-close',struct.pack('>IIIHH',18,18,0x60001,0x104,0))):
  old=state();got=frames(68,p+raw)
  good=cell('work.work')==before and scalar('owner')==0x60001 and (len(got[64 if COMPOSED else 325])==1 if name=='busy-close' else not any(got.values()))
  ok=r.add(name,'qualified close without Work mutation',got,good,before=old,state=state()) and ok
 packets={2:vectors.frame(18,900,101,True,1500),6:vectors.packet(24,2000,1075,True,payload=vectors.native_response()),9:rs.request_packet(),10:rs.ack_packet(),11:rs.response_packet(),16:vectors.packet(24,2000,1075,True,payload=vectors.native_response())}
 for kind,raw in packets.items():
  start(0xe0001,1000,2000,work=(1,1));before=state();prefix=struct.pack('>IIIHH',18,1,0xe0001,0x100|kind,0)
  if kind in (9,10,11):prefix+=struct.pack('>I',0x12345600)
  got=frames(68,prefix+raw);after=state();good=not any(got.values()) and all(after[k]==v for k,v in before.items() if k!='work.work') and next(v for k,v in cell('work.work').items() if k.endswith('.phase'))==4
  ok=r.add('foreign-kind%d'%kind,'no writer/terminal mutation',got,good,before=before,state=after) and ok
 for stage in (2,3):
  start((13 if stage==2 else 14)<<16|1,1020,2000,work=(1,stage));before=state();m.clear('Ingress.read_connection')
  raw=struct.pack('>IIIHHI',17,1,scalar('owner'),stage<<8|9,0,0x12345600)+rs.request_packet()
  got=frames(68,raw);good=not any(got.values()) and scalar('owner')==0x60001 and scalar('epoch')==17 and scalar('client')==1020 and scalar('server')==2000 and next(v for k,v in cell('work.work').items() if k.endswith('.phase'))==4
  ok=r.add('removed-before-pass%d'%(stage+1),'quarantine6, no envelope',got,good,before=before,state=state()) and ok
  for vals,links in (((vectors.CLIENT,vectors.SERVER,vectors.CLIENT_PORT,vectors.SERVER_PORT),(0,0x100)),((vectors.SERVER,vectors.CLIENT,vectors.SERVER_PORT,vectors.CLIENT_PORT),(0x100,0))):m.add('Ingress.read_connection',dict(zip(('hdr.ip.src','hdr.ip.dst','hdr.tcp.sport','hdr.tcp.dport'),vals)),'Ingress.read_configure',dict(dst=links[0],src=links[1]))
 # Paused-boundary diagnostic: actual FIN changes the owner while Work is at
 # phase3, then the exact carried terminal returns. The full source scheduler
 # separately derives this same state from the genuine request/ACK/response.
 for kind in (9,10,11):
  expected=0x50001 if kind==11 else 0xe0001
  raw={9:rs.request_packet(),10:rs.ack_packet(),11:rs.response_packet()}[kind]
  start(expected,1020,2049 if kind==11 else 2000,work=(1,3))
  before=cell('work.work')
  close=vectors.frame(17,1020,2049 if kind==11 else 2000)
  closed=frames(1,close)
  close_ok=only(closed,64 if COMPOSED else 325,close) if COMPOSED else len(closed[325])==1
  unchanged=cell('work.work')==before
  prefix=struct.pack('>IIIHHI',17,1,expected,0x300|kind,0,0x12345600)
  got=frames(68,prefix+raw)
  good=close_ok and unchanged and not any(got.values()) and next(v for k,v in cell('work.work').items() if k.endswith('.phase'))==4
  ok=r.add('close-before-terminal-kind%d'%kind,'actual close; no post-cancel service; genuine terminal',got,good,close_capture=closed,state=state()) and ok
  start(0x60002,1020,2000,work=(1,3));got=frames(68,prefix+raw)
  good=not any(got.values()) and scalar('owner')==0x60002 and next(v for k,v in cell('work.work').items() if k.endswith('.phase'))==4
  ok=r.add('stale-owner-terminal-kind%d'%kind,'full expected owner refuses; Work drains',got,good,state=state()) and ok
 start(0,0,0,epoch=0)
 for name,port,raw,out in (('SYN',1,vectors.frame(2,100,0,False,1500),2),('SYNACK',2,vectors.frame(18,900,101,True,1500),1),('finalACK',1,vectors.frame(16,101,901),2),('ACK-retry',1,vectors.frame(16,101,901),2)):
  got=frames(port,raw);ok=r.add(name,'original once',got,only(got,out,raw),state=state()) and ok
 if COMPOSED:
  for name,values in (('quarantined_epoch',{'TIngress.quarantined_epoch.f1':0}),('debt_cell',{'TIngress.debt_cell.f1':0}),('cookie_counter',{'TIngress.cookie_counter.cookie':0,'TIngress.cookie_counter.word':0})):
   m.register_write('p2.TIngress.'+name,0,values)
 start(0x50001,1000,2000);raw=rs.request_packet();got=frames(1,raw)
 good=(only(got,64,raw) if COMPOSED else len(got[325])==1 and got[325][0][12:16]==bytes.fromhex('09000000') and same_frame(got[325][0][16:],raw)) and scalar('owner')==0xe0001
 ok=r.add('READ-request','N/T request original once' if COMPOSED else 'typed request to T325',got,good,state=state()) and ok
finally:
 r.finish(Path(os.environ['OUT'])/'result.json')
sys.exit(0 if ok else 1)

"""Current-source T functional model checks. Only isolated model state is preset.
Typed reset cases consume exact retained N output bytes; no physical timing claim.
"""
import json,os,struct,sys,time
from pathlib import Path
HERE=Path(__file__).resolve().parent
sys.path[:0]=[str(HERE/'tests'),str(HERE.parent/'core')]
import whole_program as w
from model_driver import Model,same_frame,Report,gc
P=w.PORTS
class TModel(Model):
 def table(self,name,raw=False):
  if os.environ.get('TASK1_NT')=='1' and not raw and name.startswith('Ingress.'):name='p2.TIngress.'+name[len('Ingress.'):]
  return super().table(name,raw)
m=TModel(ports=[P['FORWARD_PORT'],P['RELAY_PORT'],P['T_IN'],P['HELD_RETURN']])
r=Report('T-task1',physical=False,clock='functional only; no measured heartbeat/drain bound',padding='minimum Ethernet zero padding only')
ok=True
regs=['work.work','timing_binding','admission_anchor','observations','releases','committed_response_deadline','ready_response','cookie_counter','debt_cell','quarantined_epoch','source_counter','holding_policy','credits.cell','bypass_counters']
def cell(name,index=0):return {k:(v[0] if isinstance(v,list) else v) for k,v in m.register_read('Ingress.'+name,index,pipe=2).items() if k!='$REGISTER_INDEX'}
def put(name,values,index=0):
 names=m.table('Ingress.'+name).info.data_field_name_list_get()
 if isinstance(values,int):values={n:values for n in names}
 else:values={next(n for n in names if n.endswith('.'+k)):v for k,v in values.items()}
 m.register_write('Ingress.'+name,index,values)
def scalar(name,index=0):return next(iter(cell(name,index).values()))
def reset():
 for name in regs:
  for index in range(3 if name=='credits.cell' else 4 if name=='bypass_counters' else 1):put(name,0,index)
 put('work.work',dict(generation=0,phase=4));put('holding_policy',1)
def state():
 out={name:cell(name) for name in regs if name not in ('credits.cell','bypass_counters')};out['credits']=[cell('credits.cell',i) for i in range(3)];return out
def receive(raw):return m.exchange(P['T_IN'],raw,[P['FORWARD_PORT'],P['RELAY_PORT']],timeout=.6,quiet=.04)
def req(epoch=17):return receive(w.event_frame(9,w.REQUEST_FRAME,epoch=epoch,t0q=0x12345600))
def original(got,port,raw):return len(got[port])==1 and same_frame(got[port][0],raw) and sum(map(len,got.values()))==1
try:
 n=json.loads(Path(sys.argv[1]).read_text());rows=[x for x in n['cases'] if x['name'].startswith('close-') and len(x['name'].split('-'))==4 and x['name'].split('-')[-1] in ('0','1')]
 # Composed N run observes the endpoint; build the expected typed input from the
 # exact recorded original and known N emitter semantics, not a claim of capture at325.
 composed=any(x.get('observed',{}).get('64') or x.get('observed',{}).get('9') for x in rows)
 for row in rows:
  reset();put('work.work',dict(generation=29,phase=2));put('timing_binding',dict(epoch=17,cookie=1));put('debt_cell',2)
  for i in (0,1):put('credits.cell',dict(epoch=17,credit=0x10101),i)
  before=state()
  if composed:
   reverse=int(row['name'].split('-')[-1]);raw=struct.pack('>IIIBBH',17,17,0,4,2 if reverse else 1,0)+bytes.fromhex(row['raw'])
  else:raw=bytes.fromhex(row['observed']['325'][0])
  got=receive(raw);after=state()
  direction=raw[13];port=P['FORWARD_PORT'] if direction==2 else P['RELAY_PORT']
  good=original(got,port,raw[16:]) and scalar('quarantined_epoch')==17 and before['work.work']==after['work.work'] and before['credits']==after['credits'] and scalar('debt_cell')==2
  ok=r.add('N-to-T-'+row['name'],'one original, credits and Work unchanged',got,good,input=raw,before=before,state=after) and ok
 reset();got=receive(w.event_frame(4,w.pure_ack(),epoch=17));ok=r.add('legacy-synthetic-reset','consumed',got,not any(got.values()) and scalar('quarantined_epoch')==17,state=state()) and ok
 reset();got=req();good=original(got,P['RELAY_PORT'],w.REQUEST_FRAME) and next(v for k,v in cell('timing_binding').items() if k.endswith('.cookie'))==1
 ok=r.add('READ-request-admission','request once + cookie1',got,good,state=state()) and ok
 before={name:cell(name) for name in ('timing_binding','admission_anchor','observations','releases','committed_response_deadline','ready_response')};put('cookie_counter',dict(cookie=0,word=0));got=req();after={name:cell(name) for name in before}
 ok=r.add('partial-counter-reset','counted refusal, tagged cells unchanged',got,original(got,P['RELAY_PORT'],w.REQUEST_FRAME) and before==after and scalar('bypass_counters',1)==1,before=before,state=state()) and ok
 reset();put('cookie_counter',dict(cookie=65534,word=0xfffe0000));put('credits.cell',dict(epoch=17,credit=0xfffe0000))
 got=req();ok=r.add('last-cookie65535','last admitted cookie65535',got,original(got,P['RELAY_PORT'],w.REQUEST_FRAME) and next(v for k,v in cell('timing_binding').items() if k.endswith('.cookie'))==65535,state=state()) and ok
 before=cell('timing_binding')
 for index in (1,2):
  got=req();ok=r.add('saturation-refusal%d'%index,'persistent counted refusal',got,original(got,P['RELAY_PORT'],w.REQUEST_FRAME) and cell('timing_binding')==before and scalar('bypass_counters',1)==index and next(v for k,v in cell('cookie_counter').items() if k.endswith('.cookie'))==65536,state=state()) and ok
 reset();put('holding_policy',0)
 for kind,raw,port in ((9,w.REQUEST_FRAME,P['RELAY_PORT']),(10,w.pure_ack(),P['FORWARD_PORT']),(11,w.RESPONSE_FRAME,P['FORWARD_PORT'])):
  got=receive(w.event_frame(kind,raw,epoch=17));ok=r.add('ordinary-policy-off-kind%d'%kind,'original once',got,original(got,port,raw),state=state()) and ok
 # Exercise the combined off-terminal selector through the real receipt CAS.
 for kind,raw in ((1,w.pure_ack()),(2,w.RESPONSE_FRAME),(3,w.REQUEST_FRAME)):
  reset();put('holding_policy',0);put('work.work',dict(generation=29,phase=2));put('debt_cell',1)
  put('credits.cell',dict(epoch=17,credit=0x10101),kind-1)
  before=cell('work.work');held=struct.pack('>IIIIBBH',17,29,1,0x10101,kind,4,0)+raw
  got=m.exchange(P['HELD_RETURN'],held,[P['FORWARD_PORT'],P['RELAY_PORT']],timeout=.6,quiet=.04)
  expected=not any(got.values()) if kind==3 else original(got,P['FORWARD_PORT'],raw)
  grant=next(v for k,v in cell('credits.cell',kind-1).items() if k.endswith('.credit'))==0x10100
  ok=r.add('off-terminal-kind%d'%kind,'one terminal debit; abort unsent OP',got,expected and grant and scalar('debt_cell')==0 and cell('work.work')==before,state=state()) and ok
  got=m.exchange(P['HELD_RETURN'],held,[P['FORWARD_PORT'],P['RELAY_PORT']],timeout=.6,quiet=.04)
  ok=r.add('duplicate-terminal-kind%d'%kind,'no second original/debit',got,not any(got.values()) and scalar('debt_cell')==0 and cell('work.work')==before,state=state()) and ok
 # Diagnostic paused request boundaries. These are actual parsed private
 # returns with matching Work; no claim of a CPU acquisition/rearm authority.
 for boundary in (1,2,3):
  for cause in ('reset','policy','foreign-reset'):
   reset();put('work.work',dict(generation=1,phase=boundary))
   minted=1 if boundary==3 else 0
   if minted:
    put('cookie_counter',dict(cookie=1,word=0x10000))
    put('credits.cell',dict(epoch=17,credit=0x10000),0)
   before=state()
   if cause=='policy':put('holding_policy',0)
   else:
    receive(w.event_frame(4,w.pure_ack(),epoch=18 if cause=='foreign-reset' else 17))
    if cause=='reset':receive(w.event_frame(4,w.pure_ack(),epoch=17))
   held=struct.pack('>IIIIBBH',17,1,minted,0x10000 if minted else 0,9,boundary,0)+w.event_frame(9,w.REQUEST_FRAME,epoch=17,t0q=0x12345600)
   got=m.exchange(P['HELD_RETURN'],held,[P['FORWARD_PORT'],P['RELAY_PORT']],timeout=.6,quiet=.04)
   after=state();binding_cookie=next(v for k,v in cell('timing_binding').items() if k.endswith('.cookie'))
   work_free=next(v for k,v in cell('work.work').items() if k.endswith('.phase'))==4
   if cause=='foreign-reset':
    good=binding_cookie==1 and original(got,P['RELAY_PORT'],w.REQUEST_FRAME) and work_free and scalar('debt_cell')==0
   else:
    frozen=('timing_binding','admission_anchor','observations','releases','committed_response_deadline','ready_response','cookie_counter','credits')
    good=all(before[key]==after[key] for key in frozen) and original(got,P['RELAY_PORT'],w.REQUEST_FRAME) and work_free and scalar('debt_cell')==0 and scalar('bypass_counters',2)==1
   ok=r.add('request-cancel-p%d-%s'%(boundary,cause),'no post-cancel publication; original once; cookie/debt conserved',got,good,before=before,state=after) and ok
   if cause!='foreign-reset':
    duplicate=m.exchange(P['HELD_RETURN'],held,[P['FORWARD_PORT'],P['RELAY_PORT']],timeout=.6,quiet=.04)
    ok=r.add('duplicate-cancel-p%d-%s'%(boundary,cause),'no repeated original/cookie/debit',duplicate,not any(duplicate.values()) and state()==after,state=state()) and ok
 # The model's actual one-shot packet generator services the independent heartbeat.
 # One shot per observation, no periodic flood, and no physical period/timing claim.
 reset()
 pc,pb,pa=(m.table('pktgen.'+name,raw=True) for name in ('port_cfg','pkt_buffer','app_cfg'))
 target=gc.Target(device_id=0)
 pc.entry_mod(target,[pc.make_key([gc.KeyTuple('dev_port',324)])],[pc.make_data([gc.DataTuple('pktgen_enable',bool_val=True)])])
 buf=w.pktgen_frame()[6:].ljust(64,b'\0')
 pb.entry_mod(target,[pb.make_key([gc.KeyTuple('pkt_buffer_offset',0),gc.KeyTuple('pkt_buffer_size',64)])],[pb.make_data([gc.DataTuple('buffer',bytearray(buf))])])
 fields=[gc.DataTuple(k,v) for k,v in dict(timer_nanosec=1000,pkt_len=64,pkt_buffer_offset=0,batch_count_cfg=0,packets_per_batch_cfg=0,ipg=0,ibg=0,trigger_counter=0,batch_counter=0,pkt_counter=0).items()]
 def app(enable):pa.entry_mod(target,[pa.make_key([gc.KeyTuple('app_id',0)])],[pa.make_data(fields+[gc.DataTuple('app_enable',bool_val=enable)],'trigger_timer_one_shot')])
 def tick():
  m.drain([P['FORWARD_PORT'],P['RELAY_PORT']]);app(False);app(True)
  return m.capture([P['FORWARD_PORT'],P['RELAY_PORT']],timeout=.5,quiet=.04)
 first=tick();reports=[x for x in first[P['FORWARD_PORT']] if x[:14]==w.ETH and len(x)>=30]
 ok=r.add('independent-heartbeat','real packet-generator report',first,bool(reports),state=state()) and ok
 if reports:
  t0=struct.unpack('>IIII',reports[-1][14:30])[3]&0xffffff00
  got=receive(w.event_frame(9,w.REQUEST_FRAME,epoch=17,t0q=t0));good=original(got,P['RELAY_PORT'],w.REQUEST_FRAME)
  ack=w.pure_ack();rsp=w.RESPONSE_FRAME
  captured=[]
  for kind,raw in ((10,ack),(11,rsp)):
   out=receive(w.event_frame(kind,raw,epoch=17));captured.extend(out[P['FORWARD_PORT']])
  tick_records=[]
  for attempt in range(16):
   out=tick();captured.extend(out[P['FORWARD_PORT']]);tick_records.append({str(k):[x.hex() for x in v] for k,v in out.items()})
   originals=[x for x in captured if same_frame(x,ack) or same_frame(x,rsp)]
   if len(originals)>=2:break
  originals=[x for x in captured if same_frame(x,ack) or same_frame(x,rsp)]
  normal=len(originals)==2 and same_frame(originals[0],ack) and same_frame(originals[1],rsp) and scalar('debt_cell')==0
  ok=r.add('holding-normal-ACK-response','ACK then response, each once, zero debt',originals,good and normal,t0q=t0,ticks=tick_records,state=state()) and ok
 app(False)
finally:r.finish(Path(os.environ['OUT'])/'result.json')
sys.exit(0 if ok else 1)

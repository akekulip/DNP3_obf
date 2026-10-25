"""The actual v2 exchange sends relay stimuli before observation and reads BFRT after resolution."""
import ast
import types
from pathlib import Path
import sys
import pytest

CTL=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(CTL))
import model_response_ready as ready


def method(name):
    tree=ast.parse((CTL/'model_response_ready.py').read_text())
    main=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='main')
    cls=next(node for node in main.body if isinstance(node,ast.ClassDef) and node.name=='ReadyGate')
    node=next(node for node in cls.body if isinstance(node,ast.FunctionDef) and node.name==name)
    ns=dict(ready.__dict__)
    ns.update(mp=types.SimpleNamespace(rp=types.SimpleNamespace(advance_timestamp=lambda:None,preserve_options=lambda a,b:b)),
              view=types.SimpleNamespace(size=lambda path:0))
    exec(compile(ast.Module(body=[node],type_ignores=[]),str(CTL/'model_response_ready.py'),'exec'),ns)
    return ns,name


@pytest.mark.parametrize('order,duplicate,expected',[
    ('ack_first',False,['ack','response']),('response_first',False,['response','ack']),
    ('ack_first',True,['ack','ack','response'])])
def test_actual_exchange_has_no_observer_or_bfrt_between_causal_stimulus_and_resolution(order,duplicate,expected):
    ns,name=method('exchange_ready');sent=[];request_sent=[False];polls=[0];resolved=[False]
    class End(Exception):pass
    def work(label):
        if request_sent[0]:assert sent==expected,label+' before complete relay stimulus'
    class Socket:
        def __init__(self,relay):self.relay=relay
        def send(self,raw):
            if self.relay:sent.append(raw.decode())
            else:request_sent[0]=True
    class Model:
        def register_read(self,*a,**k):work('register');return 7
        def drain(self,*a):work('drain')
        def capture(self,*a,**k):return {1:[],2:[]}
    class Gate:
        def __init__(self):
            self.master=types.SimpleNamespace(dev_port=1);self.relay=types.SimpleNamespace(dev_port=2)
            self.fast={1:Socket(False),2:Socket(True)};self.m=Model();self.ports=[1,2];self.log='unused'
            self.h=types.SimpleNamespace(scalar=lambda value:value,same_frame=lambda a,b,c:a==b)
            self.v=types.SimpleNamespace(packet=lambda flags,seq,ack,reverse=False,payload=b'':
                b'ack' if reverse and not payload else b'response' if reverse else b'request')
            self.calls=0
        def frames(self,*a):return b'Q',b'A',b'B'
        def outcomes(self):
            work('BFRT');self.calls+=1
            if self.calls>1:
                assert resolved[0],'BFRT read while original packet retained';raise End()
            return {name:0 for name in ready.NAMES}
        def encoding_state(self):work('counter');return dict(commit=0,replay=0,growth=0)
        def collect(self,*a):
            if sent!=expected:return [(2,b'request')]
            polls[0]+=1
            if polls[0]>=3:resolved[0]=True;return [(1,b'response')]
            return []
    ns['LiveIngress']=lambda *args:types.SimpleNamespace(records=[],transitions=[])
    with pytest.raises(End):ns[name](Gate(),'SELECT','CONTROL',(100,900,900),order=order,duplicate=duplicate)
    assert sent==expected


def line(text,pipe=1):return ':10-25 12:00:00.000001: :0x1:-:<0,%d,5>:%s\n'%(pipe,text)


def test_live_reader_matches_retained_parser_across_chunks_and_plain_ack_generation(tmp_path):
    import reset_application_check as rac
    text=''.join([line('========== Ingress Pkt from port 180 =========='),line('Packet :'),line('aa bb cc dd '),
        line('global_tstamp[39:8] to value 0x1001'),line('Execute Action: t_Ingress.admit_request'),
        line('========== Egress Pkt from TM to port 9 ==========',0),
        line('========== Ingress Pkt from port 182 =========='),line('Packet :'),line('0e 00 00 07 '),
        line('global_tstamp[39:8] to value 0x1011'),line('Execute Action: t_Ingress.release_ack_commit'),
        line('----- register: t_Ingress.ack_done_reg -----'),line('Before stateful alu execution: 0x00000006'),
        line('After stateful alu execution: 0x00000007')])
    path=tmp_path/'model.log';path.write_bytes(b'');reader=ready.LiveIngress(path,0);data=text.encode()
    for index in range(0,len(data),31):
        with path.open('ab') as f:f.write(data[index:index+31])
        reader.poll()
    expected=rac.ingress_records(text.splitlines(True))
    for ordinal,record in enumerate(expected):record['ordinal']=ordinal;record['t_units']&=~1
    assert reader.records==expected
    assert reader.transitions==[dict(t_units=0x1010,before=6,after=7)]
    reader.poll();assert len(reader.transitions)==1


def test_v2_full_plan_has_retry_tokens_matrix_and_cleanup_without_expiry_sections():
    ns,name=method('run');ns['control_only']=False
    class End(Exception):pass
    class Gate:
        report=types.SimpleNamespace(record=dict(meta={}))
        def invalid_child_ids(self):pass
        def request_retries(self):raise End()
    gate=Gate()
    with pytest.raises(End):ns[name](gate)
    planned=gate.report.record['meta']['planned_cases']
    assert planned[:3]==['invalid_child_ids','request_retry_policy','stale_token_isolation']
    assert len([tag for tag in planned if tag.startswith('D')])==8
    assert 'waiting_and_cleanup' in planned and 'invalid_child_ids' in planned
    assert not any('expir' in tag or 'bound' in tag for tag in planned)

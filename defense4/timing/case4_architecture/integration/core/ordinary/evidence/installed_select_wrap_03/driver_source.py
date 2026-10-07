#!/usr/bin/env python3
"""First SELECT using source-bound installed-SDK artifacts in an isolated model.

Configuration BFRT only: no register writes, packet synthesis by controller,
cache presets, endpoint service or physical hardware. One connection/trial.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import traceback

HERE=Path(__file__).resolve().parent
sys.path[:0]=[str(HERE.parent),str(HERE.parent/'harness')]
import vectors
from model_driver import Model,Report,same_frame,gc


class Programs(Model):
    """Two BFRT clients bind independent program layouts on the SAME device0."""
    def __init__(self,**kwargs):
        super().__init__(client_id=1,**kwargs)
        self.mapping=Model(prog='m3',enable=False,ports=[],client_id=2)
        self.cache=Model(prog='e3',enable=False,ports=[],client_id=3)

    def add(self,table,keys,action=None,data=None,priority=None,pipe=None):
        if table.startswith('p1.m_Ingress.'):
            name='Ingress.'+table[len('p1.m_Ingress.'):]
            action=action.replace('m_Ingress.','Ingress.') if action else None
            return self.mapping.add(name,keys,action,data,priority,pipe)
        if table.startswith('p3.e_Egress.'):
            name='Egress.'+table[len('p3.e_Egress.'):]
            action=action.replace('e_Egress.','Egress.') if action else None
            return self.cache.add(name,keys,action,data,priority,pipe)
        return super().add(table,keys,action,data,priority,pipe)

    def register_read(self,name,index,field=None,pipe=None):
        if name.startswith('p1.m_Ingress.'):
            return self.mapping.register_read('Ingress.'+name[len('p1.m_Ingress.'):],index,field,pipe)
        if name.startswith('p3.e_Egress.'):
            return self.cache.register_read('Egress.'+name[len('p3.e_Egress.'):],index,field,pipe)
        return super().register_read(name,index,field,pipe)


def only(out,port,frame):
    return len(out[port])==1 and same_frame(out[port][0],frame) and sum(map(len,out.values()))==1


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--start',type=lambda x:int(x,0),default=100)
    parser.add_argument('--no-port-enable',action='store_true',help='use model cold-added ports; MACs are not modeled')
    parser.add_argument('--syn-only',action='store_true',help='bounded external SYN capture before downstream work')
    parser.add_argument('--sources-dir',type=Path,required=True,help='exact source copies bound to the loaded compiler artifacts')
    args=parser.parse_args()
    source_dir=args.sources_dir.resolve()
    output=Path(os.environ['OUT'])
    report=Report(os.environ['PROG'],physical=False,proof_presets=False,
                  source_sha256=hashlib.sha256((source_dir/'nf.p4').read_bytes()).hexdigest(),m_source_sha256=hashlib.sha256((source_dir/'m3.p4').read_bytes()).hexdigest(),
                  driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  start=args.start,sdk=os.environ.get('SDE'),scope='installed-SDK first SELECT only; ACK/window/SBO/lifecycle gated')
    ok=False
    try:
        m=Programs(ports=[1,2,68,196,198,452,453],enable=not args.no_port_enable)
        report.record['meta']['front_port_enable_calls']=not args.no_port_enable
        report.record['meta']['port_enable_errors']=m.port_errors
        port=m.table('$PORT',raw=True)
        # SDK software starts at NONE and may skip a same-value setter while
        # the model MAC is still looped. Force a real transition, model only.
        if not args.no_port_enable:
            for mode in ('BF_LPBK_MAC_NEAR','BF_LPBK_NONE'):
                for p in (1,2):
                    port.entry_mod(m.target,[port.make_key([gc.KeyTuple('$DEV_PORT',p)])],
                        [port.make_data([gc.DataTuple('$LOOPBACK_MODE',str_val=mode)])])
        report.record['meta']['front_port_readback']={}
        for p in (1,2):
            rows=list(port.entry_get(m.target,[port.make_key([gc.KeyTuple('$DEV_PORT',p)])],{'from_hw':True}))
            value=rows[0][0].to_dict()
            report.record['meta']['front_port_readback'][str(p)]=value
            if value.get('$LOOPBACK_MODE')!='BF_LPBK_NONE':raise ValueError('front loop refusal')
        # Model --int-port-loop supplies only private local68..71 returns on pipes0/1/3.
        # Reserved198 is not a physical front port and needs no MAC loop mutation.
        for p,out in ((1,2),(2,1),(68,68)):
            m.add('p0.n_Ingress.ports',{'ig.ingress_port':p},'n_Ingress.route',{'port':out})
        keys=('hdr.ip.src','hdr.ip.dst','hdr.tcp.sport','hdr.tcp.dport')
        tuples=((vectors.CLIENT,vectors.SERVER,vectors.CLIENT_PORT,vectors.SERVER_PORT),
                (vectors.SERVER,vectors.CLIENT,vectors.SERVER_PORT,vectors.CLIENT_PORT))
        for values,direction,dest in ((tuples[0],'forward',2),(tuples[1],'reverse',1)):
            key=dict(zip(keys,values))
            m.add('p0.n_Ingress.connection',key,'n_Ingress.'+direction+'_flow',{'port':dest})
            m.add('p0.n_Ingress.data_connection',key,'n_Ingress.configure',dict(zip(('index','code','repeat','on','off'),vectors.decoy_config())))
        for p,dest in ((196,452),(198,452)):
            m.add('p1.m_Ingress.forwarding',{'ig.ingress_port':p},'m_Ingress.route',{'port':dest})
        m.add('p1.m_Ingress.connection',dict(zip(keys,tuples[0])),'m_Ingress.allow_connection')
        m.add('p3.e_Egress.connection',dict(zip(keys,tuples[0])),'e_Egress.allow_connection')
        m.add('p0.f_Egress.connection',dict(zip(keys,tuples[0])),'f_Egress.allow_connection')
        mirror=m.table('$mirror.cfg',raw=True)
        mirror.entry_add(m.target,[mirror.make_key([gc.KeyTuple('$sid',1)])],
            [mirror.make_data([gc.DataTuple('$direction',str_val='EGRESS'),gc.DataTuple('$ucast_egress_port',453),
                gc.DataTuple('$ucast_egress_port_valid',bool_val=True),gc.DataTuple('$session_enable',bool_val=True)],'$normal')])
        report.record['meta']['configuration_only']=True
        ok=True
        start=args.start&0xffffffff
        for name,p,frame,dest in (('SYN',1,vectors.packet(2,(start-1)&0xffffffff,mss=1500),2),
                                  ('SYNACK',2,vectors.packet(18,900,start,True,mss=1500),1),
                                  ('finalACK',1,vectors.packet(16,start,901),2)):
            got=m.exchange(p,frame,[1,2],timeout=1.5,quiet=.15)
            passed=report.add(name,'original exactly once',got,only(got,dest,frame),frame=frame)
            ok=passed and ok
            if not passed:raise ValueError('external handshake failed at '+name)
            if args.syn_only:return 0
        native=vectors.native_select()
        frame=vectors.packet(24,start,901,payload=native)
        padded=vectors.case4_padding.expand_control(native,vectors.DECOY)[0]
        expected=vectors.packet(24,start,901,payload=padded)
        got=m.exchange(1,frame,[1,2],timeout=3,quiet=.3)
        ok=report.add('SELECT35_to55','one independent exact109-byte endpoint frame',got,only(got,2,expected),frame=frame,expected_frame=expected) and ok
        # Only read actual produced lifetime/cache coordinates.
        state={name:m.register_read(name,0) for name in (
            'p0.n_Ingress.owner','p0.n_Ingress.epoch','p0.n_Ingress.work.work',
            'p1.m_Ingress.reservation','p1.m_Ingress.geo_first','p1.m_Ingress.ledger_position','p1.m_Ingress.ledger_tag',
            'p3.e_Egress.reservation','p3.e_Egress.cache_tag','p3.e_Egress.cache_owner','p3.e_Egress.wire_position')}
        report.record['state']=state
        def scalar(name,suffix):
            values=next(v for k,v in state[name].items() if k.endswith(suffix))
            return values[0] if isinstance(values,list) else values
        lifetime=scalar('p0.n_Ingress.work.work','.phase')==9 and scalar('p3.e_Egress.reservation','.phase')==4 and scalar('p1.m_Ingress.reservation','.phase')==4
        ok=report.add('genuine_downstream_completion','N9/M4/E4',state,lifetime) and ok
        ok=report.add('actual_native_coordinates','wire_start and full32 boundary',state,
            scalar('p1.m_Ingress.geo_first','.f1')==((start+35)&0xffffffff) and scalar('p1.m_Ingress.ledger_position','.f1')==start) and ok
    except BaseException as error:
        report.record['error']=type(error).__name__+': '+str(error)
        report.record['traceback']=traceback.format_exc()
        report.add('execution','successful actual model','error',False)
        ok=False
    finally:
        report.finish(output/'result.json')
        (output/'driver_source.py').write_bytes(Path(__file__).read_bytes())
        (output/'input_sources.json').write_text(json.dumps({name:hashlib.sha256((source_dir/name).read_bytes()).hexdigest() for name in ('nf.p4','m3.p4','e3.p4')},indent=2)+'\n')
    return 0 if ok else 1


if __name__=='__main__':sys.exit(main())

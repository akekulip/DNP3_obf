#!/usr/bin/env python3
"""Bounded same-device N/F0, M1, E3 placement candidate, licensed model only.

Derives the audited role bodies with explicit typed routes. E3 retains all
fourteen real image banks and lifetime checks. F0 has a current-generation
once-only receipt; it never reads or writes the cache. No controller proofs.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
from compose import role

HERE=Path(__file__).resolve().parent


def replace(text,old,new,count=1):
    if text.count(old)!=count:raise ValueError('source seam changed: '+old[:80])
    return text.replace(old,new)


def generate_roles():
    n=(HERE/'n.p4').read_text();e=(HERE/'e.p4').read_text();m=(HERE/'m.p4').read_text()
    n=replace(n,'16w0x0b14:ready_cache;','16w0x0b14:ready_cache;16w0x0d14:ready_cache;')
    n=replace(n,'action endpoint_egress(){tm.ucast_egress_port=9w2;',
              'action final_renderer(){tm.ucast_egress_port=9w2;tm.bypass_egress=1w0;}\n action endpoint_egress(){tm.ucast_egress_port=9w452;')
    n=replace(n,'action cache_terminal_egress(){tm.ucast_egress_port=RETURN_PORT;',
              'action cache_terminal_egress(){tm.ucast_egress_port=9w453;')
    n=replace(n,'actions={ready_qualified;activate_select;endpoint_egress;',
              'actions={ready_qualified;activate_select;final_renderer;endpoint_egress;')
    n=replace(n,'qualify_quarantine_cleanup;deny;}size=8;',
              'qualify_quarantine_cleanup;deny;}size=9;')
    n=replace(n,'(8w11,32w7,32w0,32w0x80000,32w0,32w0,32w0x110000&&&32w0xffff0000):endpoint_egress();',
              '(8w13,32w7,32w0,32w0x80000,32w0,32w0,32w0x110000&&&32w0xffff0000):final_renderer();(8w11,32w7,32w0,32w0x80000,32w0,32w0,32w0x110000&&&32w0xffff0000):endpoint_egress();')
    row='(8w11,8w20,8w20,8w1,8w1,_,_,_,_,_,_,32w0,32w0x80000,_):go_ret_nowork();'
    n=replace(n,row,row+row.replace('8w11,','8w13,',1))
    n=replace(n,'go_ret_abort;NoAction;}size=56;','go_ret_abort;NoAction;}size=57;')
    m=replace(m,'hdr.reference.event=16w0x0914;tm.ucast_egress_port=9w68;',
              'hdr.reference.event=16w0x0914;tm.ucast_egress_port=9w452;')

    # F0 uses the actual complete-frame parser and checksum field lists. All
    # receipt mutation follows parsed network and full reference admission.
    f=e[:e.index('control Egress(')]
    f=replace(f,'9w68:reference;9w2:emit_reference;','9w2:emit_reference;')
    f=replace(f,'(16w0x0b14,16w2):emit_cache;','(16w0x0d14,16w2):emit_cache;')
    endpoint=re.search(r' action endpoint_ready\(\)\{[^\n]+\}',e).group(0)
    f+='''control Egress(inout headers_t hdr,inout meta_t m,in egress_intrinsic_metadata_t eg,in egress_intrinsic_metadata_from_parser_t p,inout egress_intrinsic_metadata_for_deparser_t md,inout egress_intrinsic_metadata_for_output_port_t port){
 action deny(){md.drop_ctl=3w1;}
 action allow_connection(){m.enabled=1w1;}
 table connection{key={hdr.ip.src:exact;hdr.ip.dst:exact;hdr.tcp.sport:exact;hdr.tcp.dport:exact;}actions={allow_connection;NoAction;}size=1;default_action=NoAction();}
 Register<bit<32>,bit<1>>(1,0) emitted_generation;
 RegisterAction<bit<32>,bit<1>,bit<32>>(emitted_generation) claim_emit={void apply(inout bit<32> value,out bit<32> result){result=32w0;if(value<hdr.reference.generation){value=hdr.reference.generation;result=32w1;}}};
 action claim(){m.grant=claim_emit.execute(1w0);}
 table claim_t{key={m.enabled:exact;m.gen_diff:exact;m.owner_diff:exact;}actions={claim;deny;}size=1;const default_action=deny();const entries={(1w1,32w0,32w0x80000):claim();}}
'''+endpoint+'''
 apply{
  if(m.parsed==1w1&&!m.ip_error&&m.tcp_sum==16w0xFFEB&&hdr.ip.ttl!=8w0){
   connection.apply();
   m.gen_diff=hdr.reference.generation-hdr.cache.generation;
   m.owner_diff=hdr.reference.expected_owner-hdr.cache.expected_owner;
   claim_t.apply();if(m.grant==32w1){endpoint_ready();}else{deny();}
  }else{deny();}
 }
}
'''
    f+=e[e.index('control EgDeparser('):]

    cache=e
    cache=replace(cache,'bit<8> role;','bit<8> role;bit<8> service_port;')
    cache=replace(cache,'m.role=8w0;','m.role=8w0;m.service_port=8w0;')
    cache=replace(cache,'9w68:reference;9w2:emit_reference;',
                  '9w452:reference;9w453:completion_reference;')
    cache=replace(cache,' state emit_reference{',' state completion_reference{m.service_port=8w1;transition reference;}\n state loaded_reference{m.role=8w2;transition emit_cache;}\n state emit_reference{')
    cache=replace(cache,'(16w0x0914,16w2):query_cache;',
                  '(16w0x0b14,16w2):loaded_reference;(16w0x0914,16w2):query_cache;')
    cache=replace(cache,endpoint,' action endpoint_ready(){m.emit_ready=1w1;m.tcp_length=16w75;hdr.reference.event=16w0x0d14;}')
    cache=replace(cache,' compare_reference_t.apply();identity_t.apply();pin_identity_t.apply();',
                  ' service_gate_t.apply();\n  compare_reference_t.apply();identity_t.apply();pin_identity_t.apply();')
    cache=replace(cache,' apply{\n  // Read-only tuple',
                  ' table service_gate_t{key={m.service_port:exact;m.role:exact;}actions={NoAction;deny;}size=5;const default_action=deny();const entries={(8w0,8w0):NoAction();(8w0,8w1):NoAction();(8w0,8w2):NoAction();(8w1,8w3):NoAction();(8w1,8w4):NoAction();}}\n apply{\n  // Read-only tuple')
    # A failed role/port guard must return before even reservation inspection.
    cache=replace(cache,' service_gate_t.apply();\n  compare_reference_t',
                  ' service_gate_t.apply();\n  if(md.drop_ctl==3w0){\n  compare_reference_t')
    cache=replace(cache,' }\n\n}\ncontrol EgDeparser',' }\n }\n\n}\ncontrol EgDeparser')
    cache=replace(cache,'   mirror.emit<completion_h>(m.mirror_sid,{m.completion_epoch,m.completion_generation,m.completion_owner,m.completion_event,m.completion_format,m.completion_cache_generation,m.completion_cache_owner});\n','')
    cache=replace(cache,' Mirror() mirror;\n','')
    start=cache.index('parser IgParser(')
    end=cache.index('#ifndef ORDINARY_E_NO_MAIN',start)
    cache=cache[:start]+BRIDGE+cache[end:]
    return {'n3.p4':n,'m3.p4':m,'e3.p4':cache,'f.p4':f}


BRIDGE='''parser IgParser(packet_in pkt,out headers_t hdr,out meta_t m,out ingress_intrinsic_metadata_t ig){
 state start{pkt.extract(ig);pkt.advance(PORT_METADATA_SIZE);m.parsed=1w0;transition select(ig.ingress_port){9w452:reference;9w453:reference;default:reject;}}
 state reference{pkt.extract(hdr.reference);transition select(hdr.reference.epoch){32w0:reject;default:generation;}}
 state generation{transition select(hdr.reference.generation){32w0:reject;default:cache;}}
 state cache{pkt.extract(hdr.cache);transition select(hdr.reference.format){16w2:done;16w3:stamp;default:reject;}}
 state stamp{pkt.extract(hdr.completion);transition done;}
 state done{m.parsed=1w1;transition accept;}
}
control Ingress(inout headers_t hdr,inout meta_t m,in ingress_intrinsic_metadata_t ig,in ingress_intrinsic_metadata_from_parser_t p,inout ingress_intrinsic_metadata_for_deparser_t md,inout ingress_intrinsic_metadata_for_tm_t tm){
 action deny(){md.drop_ctl=3w1;}
 action to_n(){tm.ucast_egress_port=9w68;tm.bypass_egress=1w1;}
 table typed_route{key={ig.ingress_port:exact;hdr.reference.event:exact;hdr.reference.format:exact;hdr.reference.expected_owner[31:16]:exact;}actions={to_n;deny;}size=5;const default_action=deny();const entries={(9w452,16w0x0514,16w2,16w9):to_n();(9w452,16w0x0b14,16w2,16w17):to_n();(9w452,16w0x0d14,16w2,16w17):to_n();(9w453,16w0x1214,16w3,16w17):to_n();(9w453,16w0x0e14,16w2,16w17):to_n();}}
 apply{if(m.parsed==1w1){typed_route.apply();}else{deny();}}
}
control IgDeparser(packet_out pkt,inout headers_t hdr,in meta_t m,in ingress_intrinsic_metadata_for_deparser_t md){apply{pkt.emit(hdr);}}
'''


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('output',type=Path)
    args=parser.parse_args();args.output.mkdir(exist_ok=True)
    roles=generate_roles()
    for name,text in roles.items():(args.output/name).write_text(text)
    n=(HERE/'work_record.p4').read_text()+'\n'+roles['n3.p4']
    prefix='/* Partial ordinary SELECT split candidate, offline only. */\n#include <core.p4>\n#include <tna.p4>\n'
    nf=prefix+role(n,'n')+role(roles['f.p4'],'f')+'\nPipeline(n_IgParser(),n_Ingress(),n_IgDeparser(),f_EgParser(),f_Egress(),f_EgDeparser()) p0;Switch(p0) main;\n'
    (args.output/'nf.p4').write_text(nf)
    (args.output/'work_record.p4').write_bytes((HERE/'work_record.p4').read_bytes())
    identity={name:hashlib.sha256((HERE/name).read_bytes()).hexdigest() for name in ('n.p4','m.p4','e.p4','work_record.p4')}
    (args.output/'inputs.json').write_text(json.dumps({'inputs':identity,'generated':{name:hashlib.sha256((args.output/name).read_bytes()).hexdigest() for name in (*roles,'nf.p4')},'full_target':False},indent=2)+'\n')


if __name__=='__main__':main()

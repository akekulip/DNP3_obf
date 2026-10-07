#!/usr/bin/env python3
"""Wire composition experiment with actual shared egress image banks.

PRE RID1/2 selects response rendering; ordinary unicast uses the internally
generated cache descriptor. Holding/blocker paths are absent and cannot be
inferred from this resource experiment. Defaults deny; never deploy this probe.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import compose

ROLES=['cache','forward','reverse','carving','read']
FILES=dict(compose.ROLE_FILES,cache='egress/shared_egress.p4',read='../integration/read/validator.p4')
PATHS={'cache':[(9,75),(9,41)],'forward':[(9,40)],'reverse':[(64,40)],
       'carving':[(64,97)],'read':[(9,60),(64,89)]}


def closing_brace(text,opening):
    depth=1;end=opening+1
    while depth:
        depth+=(text[end]=='{')-(text[end]=='}');end+=1
    return end-1


def generate(selected_carve=False):
    original=compose.ROLE_FILES
    files=dict(FILES)
    if selected_carve:files['carving']='selected_carving.p4'
    try:
        compose.ROLE_FILES=files
        source=compose.generate(ROLES,role_paths=PATHS,initializers={'read':''})
    finally:
        compose.ROLE_FILES=original
    # A descriptor-free unicast must never enter the cache parser. Only an
    # admitted, fully validated response with an actual split context uses PRE.
    before='action route(PortId_t port){tm.ucast_egress_port=port;}'
    after='action route(PortId_t port){tm.ucast_egress_port=port;tm.bypass_egress=1w1;}'
    source=source.replace(before,after)
    source=source.replace('action split(bit<16> mgid){tm.mcast_grp_a=mgid;}',
        'action split(bit<16> mgid){tm.mcast_grp_a=mgid;tm.bypass_egress=1w0;}')
    guard='if(m.badh==1w0&&m.bad0==1w0&&m.bad1==1w0&&m.badt==1w0){'
    if source.count(guard)!=1:raise ValueError('carver admission guard changed')
    source=source.replace(guard,guard.replace('if(','if(md.drop_ctl==3w0&&',1))
    # A single operation-dispatch table per bank places both register actions
    # together. Separate store/load tables failed same-stage placement after
    # the independently guarded READ subcontrol was regenerated.
    start=source.index('control cache_Egress(')
    end=source.index('control cache_EgDeparser(',start)
    cache=source[start:end]
    cache=compose.remove_blocks(cache,r'^\s*table (?:store|load)_\d+_t')
    tables=''.join('table image_'+str(index)+'_t{key={hdr.descriptor.operation:exact;}'
        'actions={store_'+str(index)+';load_'+str(index)+';NoAction;}'
        'size=2;const default_action=NoAction();const entries={'
        '8w2:store_'+str(index)+'();8w1:load_'+str(index)+'();}}\n'
        for index in range(14))
    opening=cache.index(' apply{')+len(' apply')
    closing=closing_brace(cache,opening)
    body='''if(hdr.descriptor.generation==32w0){deny();}else{
if(hdr.descriptor.operation==8w2){form_last_t.apply();}
'''+''.join('image_'+str(index)+'_t.apply();' for index in range(14))+'''
if(hdr.descriptor.operation==8w1){render_t.apply();}
}m.tcp_length=16w75;'''
    cache=cache[:opening-len(' apply')]+tables+' apply{'+body+cache[closing:]
    source=source[:start]+cache+source[end:]
    ingress=source.index('control Ingress(')
    start=source.index('apply{',ingress)+len('apply')
    end=closing_brace(source,start)
    body=source[start+1:end]
    resets=''.join(f'm.{role}.changed=1w0;' for role in ROLES if role!='read')
    # Target error metadata qualifies admission before any role can mutate state.
    source=source[:start+1]+resets+'if(p.parser_err==16w0){'+body+'}else{md.drop_ctl=3w1;}'+source[end:]
    start=source.index('parser EgParser(')
    end=source.index('Pipeline(',start)
    egress='''parser EgParser(packet_in pkt,out headers_t hdr,out meta_t m,out egress_intrinsic_metadata_t eg){
 cache_EgParser() cache;carving_EgParser() carving;
 state start{pkt.extract(eg);transition select(eg.egress_rid){16w1:carving_state;16w2:carving_state;default:cache_state;}}
 state cache_state{m.role=8w1;cache.apply(pkt,hdr.cache,m.cache);transition accept;}
 state carving_state{m.role=8w2;carving.apply(pkt,hdr.carving,m.carving);transition accept;}}
control Egress(inout headers_t hdr,inout meta_t m,in egress_intrinsic_metadata_t eg,in egress_intrinsic_metadata_from_parser_t p,inout egress_intrinsic_metadata_for_deparser_t md,inout egress_intrinsic_metadata_for_output_port_t port){
 cache_Egress() cache;carving_Egress() carving;
 apply{m.cache.changed=1w0;m.carving.changed=1w0;if(p.parser_err==16w0){if(m.role==8w1){cache.apply(hdr.cache,m.cache,eg,p,md,port);}else if(m.role==8w2){carving.apply(hdr.carving,m.carving,eg,p,md,port);}else{md.drop_ctl=3w1;}}else{md.drop_ctl=3w1;}}}
control EgDeparser(packet_out pkt,inout headers_t hdr,in meta_t m,in egress_intrinsic_metadata_for_deparser_t md){
 cache_EgDeparser() cache;carving_EgDeparser() carving;
 apply{cache.apply(pkt,hdr.cache,m.cache,md);carving.apply(pkt,hdr.carving,m.carving,md);}}
'''
    return source[:start]+egress+source[end:]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output',type=Path)
    parser.add_argument('--selected-carve',action='store_true')
    args=parser.parse_args()
    args.output.write_text(generate(args.selected_carve))
    files=dict(FILES)
    if args.selected_carve:files['carving']='selected_carving.p4'
    inputs={role:hashlib.sha256((compose.ROOT/'protocol'/files[role]).read_bytes()).hexdigest() for role in ROLES}
    inputs['compose.py']=hashlib.sha256(Path(compose.__file__).read_bytes()).hexdigest()
    args.output.with_suffix('.inputs.json').write_text(json.dumps(inputs,indent=2)+'\n')


if __name__=='__main__':main()

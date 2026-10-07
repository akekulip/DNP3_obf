#!/usr/bin/env python3
"""Compose NEW executable primitives using mutually exclusive parser roles.

This tests coexistence of actual wire operations, not complete Case4 correctness.
It does not combine the historical response-ready ingress/proof/mapping sources.
Handshake, owner, replay publication and queue service remain integration gates.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
ROLE_FILES = {'padding': 'padding_cache_writer.p4', 'forward': 'mapping_forward.p4',
              'reverse': 'mapping_reverse.p4', 'carving': 'carving.p4',
              'replay': 'exact_replay.p4'}


def remove_blocks(source, pattern):
    matches=list(re.finditer(pattern, source, re.M))
    for match in reversed(matches):
        opening=source.index('{',match.start());depth=1;end=opening+1
        while depth:
            depth+=(source[end]=='{')-(source[end]=='}');end+=1
        if source[end:end+1]==';':end+=1
        source=source[:match.start()]+source[end:]
    return source


def cache_control():
    s='struct cache_meta_t{bit<8> operation;bit<1> slot;'+''.join(f'bit<32> w{i};' for i in range(14))+'}\n'
    s+='control Cache(inout cache_meta_t m){\n'
    for i in range(14):
        s+=f'Register<bit<32>,bit<1>>(2,0) image_{i};\n'
        s+=f'RegisterAction<bit<32>,bit<1>,bit<32>>(image_{i}) read_{i}={{void apply(inout bit<32> v,out bit<32> r){{r=v;}}}};\n'
        s+=f'RegisterAction<bit<32>,bit<1>,bit<32>>(image_{i}) write_{i}={{void apply(inout bit<32> v,out bit<32> r){{v=m.w{i};r=v;}}}};\n'
        s+=f'action load_{i}(){{m.w{i}=read_{i}.execute(m.slot);}}\n'
        s+=f'action store_{i}(){{write_{i}.execute(m.slot);}}\n'
        s+=f'table word_{i}{{key={{m.operation:exact;}}actions={{load_{i};store_{i};NoAction;}}size=2;const default_action=NoAction();const entries={{8w1:load_{i}();8w2:store_{i}();}}}}\n'
    return s+'apply{'+''.join(f'word_{i}.apply();' for i in range(14))+'}}\n'


def rename(source, role, shared_cache=False):
    """Namespace a complete primitive, leaving SDK type names unchanged."""
    if shared_cache and role in ('padding','replay'):
        source=re.sub(r'^Register<[^\n]+\simage_\d+;\n','',source,flags=re.M)
        source=remove_blocks(source,r'^RegisterAction<[^\n]+(?:write|read)_\d+=')
        source=remove_blocks(source,r'^action (?:store|load)_\d+\(')
        source=remove_blocks(source,r'^table (?:store|load)_\d+_t')
        source=re.sub(r'(?:store|load)_\d+_t\.apply\(\);','',source)
        if role=='replay':
            source=source.replace('last_slice_t.apply();','').replace('complete_t.apply();','')
    names = set(re.findall(r'\b(?:header|struct|parser|control)\s+(\w+)', source))
    for name in sorted(names, key=len, reverse=True):
        source = re.sub(r'\b' + name + r'\b', role + '_' + name, source)
    source = re.sub(r'^#include.*\n', '', source, flags=re.M)
    source = source.replace('"m.', '"m.'+role+'.').replace('"hdr.', '"hdr.'+role+'.')
    source = source[:source.index('Pipeline(')]
    # The outer parser owns intrinsic/port metadata. Subparsers parse original
    # Ethernet bytes only. Egress intrinsic is likewise extracted once.
    source = re.sub(r',\s*out ingress_intrinsic_metadata_t ig', '', source)
    source = re.sub(r',\s*out egress_intrinsic_metadata_t eg', '', source)
    source = source.replace('pkt.extract(ig);', '').replace('pkt.advance(PORT_METADATA_SIZE);', '')
    source = source.replace('pkt.extract(eg);', '')
    return source


def replay_render():
    return (''.join(f'hdr.replay.image.w{i}=m.cache.w{i};' for i in range(13))
        +'hdr.replay.image.w13=m.cache.w13[31:8];hdr.replay.image.setValid();hdr.replay.native.setInvalid();hdr.replay.tcp.seq=m.replay.wire_start;hdr.replay.ip.len=16w95;m.replay.ip_length=16w95;m.replay.tcp_length=16w75;')


def branch_cache_call(role):
    if role=='padding':
        return ('if(md.drop_ctl==3w0&&m.padding.changed==1w1){m.cache.operation=8w2;m.cache.slot=m.padding.image_slot;'
            +''.join(f'm.cache.w{i}=m.padding.image_word{i};' for i in range(14))+'cache.apply(m.cache);}')
    if role=='replay':
        return 'if(md.drop_ctl==3w0&&m.replay.render==1w1){m.cache.operation=8w1;m.cache.slot=m.replay.image_slot;cache.apply(m.cache);}'
    return ''


def generate(roles, shared_cache=False, split_carve_crc=False, branch_cache=False, early_cache=False,
             role_paths=None, initializers=None):
    if branch_cache and not shared_cache:
        raise ValueError('branch-local cache requires the actual shared banks')
    if early_cache and (not shared_cache or branch_cache):
        raise ValueError('early cache requires one shared-cache application')
    pieces = []
    for role in roles:
        source = (ROOT / 'protocol' / ROLE_FILES[role]).read_text()
        if split_carve_crc and role=='carving':
            source=source.replace('bit<16> crc;', 'bit<8> crc_lo;bit<8> crc_hi;')
            for header,expected,bad in (('dl','hcrc','badh'),('first','crc0','bad0'),('second','crc1','bad1'),('tail','crct','badt')):
                old=f'if(hdr.{header}.crc!=(m.{expected}[7:0]++m.{expected}[15:8])){{m.{bad}=1w1;}}'
                new=f'if(hdr.{header}.crc_lo!=m.{expected}[7:0]){{m.{bad}=1w1;}}if(hdr.{header}.crc_hi!=m.{expected}[15:8]){{m.{bad}=1w1;}}'
                if old not in source:raise ValueError('carver CRC guard changed')
                source=source.replace(old,new)
                source=source.replace(f'hdr.{header}.crc,',f'hdr.{header}.crc_lo,hdr.{header}.crc_hi,')
                source=source.replace(f'hdr.{header}.crc}}',f'hdr.{header}.crc_lo,hdr.{header}.crc_hi}}')
        pieces.append(rename(source, role, shared_cache))
    s = '/* Role-specific wire composition experiment. NEVER DEPLOY. No complete lifecycle. */\n'
    s += '#include <core.p4>\n#include <tna.p4>\n' + '\n'.join(pieces)
    if shared_cache:s += cache_control()
    s += 'header dispatch_h {bit<112> eth;bit<16> first;bit<16> len;}\n'
    s += 'struct headers_t {' + ''.join(f'{r}_headers_t {r};' for r in roles) + '}\n'
    s += 'struct meta_t {bit<8> role;'+('cache_meta_t cache;' if shared_cache else '') + ''.join(f'{r}_meta_t {r};' for r in roles) + '}\n'
    s += 'parser IgParser(packet_in pkt,out headers_t hdr,out meta_t m,out ingress_intrinsic_metadata_t ig){\n'
    s += ''.join(f'{r}_IgParser() {r};\n' for r in roles)
    initial=('m.cache.operation=8w0;' if shared_cache else '')+''.join(
        (initializers or {}).get(r, f'm.{r}.changed=1w0;' if r!='replay' else f'm.{r}.render=1w0;') for r in roles)
    s += 'state start{pkt.extract(ig);pkt.advance(PORT_METADATA_SIZE);m.role=8w0;'+initial+'transition dispatch;}\n'
    s += 'state dispatch{transition select(ig.ingress_port,pkt.lookahead<dispatch_h>().len){\n'
    paths = {'padding': [(9, 75)], 'forward': [(9, 40)], 'reverse': [(64, 40)],
             'carving': [(64, 97)], 'replay': [(9, 41)]}
    if role_paths is not None:paths=role_paths
    for role in roles:
        for port, length in paths[role]:
            s += f'(9w{port},16w{length}):{role}_state;\n'
    s += 'default:accept;}}\n'
    for i, role in enumerate(roles, 1):
        s += f'state {role}_state{{m.role=8w{i};{role}.apply(pkt,hdr.{role},m.{role});transition accept;}}\n'
    s += '}\n'
    s += 'control Ingress(inout headers_t hdr,inout meta_t m,in ingress_intrinsic_metadata_t ig,in ingress_intrinsic_metadata_from_parser_t p,inout ingress_intrinsic_metadata_for_deparser_t md,inout ingress_intrinsic_metadata_for_tm_t tm){\n'
    s += ''.join(f'{r}_Ingress() {r};\n' for r in roles)
    if shared_cache:s += 'Cache() cache;\n'
    s += 'apply{\n'
    if early_cache:
        first=True
        for i,role in enumerate(roles,1):
            if role not in ('padding','replay'):continue
            s += ('if' if first else 'else if')+f'(m.role==8w{i}){{{role}.apply(hdr.{role},m.{role},ig,p,md,tm);}}\n'
            first=False
        s += shared_cache_path(roles, True)
    first=True
    for i, role in enumerate(roles, 1):
        if early_cache and role in ('padding','replay'):continue
        s += ('if' if first else 'else if')+f'(m.role==8w{i}){{{role}.apply(hdr.{role},m.{role},ig,p,md,tm);'
        first=False
        if branch_cache:s += branch_cache_call(role)
        s += '}\n'
    if early_cache:
        excluded='&&'.join(f'm.role!=8w{roles.index(role)+1}' for role in ('padding','replay') if role in roles)
        if not first:s += 'else'
        s += '{if('+excluded+'){md.drop_ctl=3w1;}}'
    else:s += 'else{md.drop_ctl=3w1;}'
    if branch_cache and 'replay' in roles:
        s += 'if(m.cache.operation==8w1){'+replay_render()+'}'
    if shared_cache and not branch_cache and not early_cache:
        s += shared_cache_path(roles, False)
    s+='}}\n' 
    s += 'control IgDeparser(packet_out pkt,inout headers_t hdr,in meta_t m,in ingress_intrinsic_metadata_for_deparser_t md){\n'
    s += ''.join(f'{r}_IgDeparser() {r};\n' for r in roles)
    s += 'apply{\n'
    for role in roles:
        s += f'{role}.apply(pkt,hdr.{role},m.{role},md);\n'
    s += '}}\n'
    if 'carving' in roles:
        s += '''parser EgParser(packet_in pkt,out headers_t hdr,out meta_t m,out egress_intrinsic_metadata_t eg){
 carving_EgParser() carving;state start{pkt.extract(eg);carving.apply(pkt,hdr.carving,m.carving);transition accept;}}
control Egress(inout headers_t hdr,inout meta_t m,in egress_intrinsic_metadata_t eg,in egress_intrinsic_metadata_from_parser_t p,inout egress_intrinsic_metadata_for_deparser_t md,inout egress_intrinsic_metadata_for_output_port_t port){
 carving_Egress() carving;apply{carving.apply(hdr.carving,m.carving,eg,p,md,port);}}
control EgDeparser(packet_out pkt,inout headers_t hdr,in meta_t m,in egress_intrinsic_metadata_for_deparser_t md){carving_EgDeparser() carving;apply{carving.apply(pkt,hdr.carving,m.carving,md);}}
'''
    else:
        s += '''parser EgParser(packet_in pkt,out headers_t hdr,out meta_t m,out egress_intrinsic_metadata_t eg){state start{pkt.extract(eg);transition accept;}}
control Egress(inout headers_t hdr,inout meta_t m,in egress_intrinsic_metadata_t eg,in egress_intrinsic_metadata_from_parser_t p,inout egress_intrinsic_metadata_for_deparser_t md,inout egress_intrinsic_metadata_for_output_port_t port){apply{}}
control EgDeparser(packet_out pkt,inout headers_t hdr,in meta_t m,in egress_intrinsic_metadata_for_deparser_t md){apply{}}
'''
    s += 'Pipeline(IgParser(),Ingress(),IgDeparser(),EgParser(),Egress(),EgDeparser()) pipe;Switch(pipe) main;\n'
    return s


def shared_cache_path(roles, admitted):
    s=''
    guard='md.drop_ctl==3w0&&' if admitted else ''
    if 'padding' in roles:
        number=roles.index('padding')+1
        s+=f'if({guard}m.role==8w{number}&&m.padding.changed==1w1){{m.cache.operation=8w2;m.cache.slot=m.padding.image_slot;'+''.join(f'm.cache.w{i}=m.padding.image_word{i};' for i in range(14))+'}'
    if 'replay' in roles:
        number=roles.index('replay')+1
        s+=f'if({guard}m.role==8w{number}&&m.replay.render==1w1){{m.cache.operation=8w1;m.cache.slot=m.replay.image_slot;}}'
    s+='cache.apply(m.cache);'
    if 'replay' in roles:s+='if(m.cache.operation==8w1){'+replay_render()+'}'
    return s


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('--roles', nargs='+', choices=ROLE_FILES,
                        default=list(ROLE_FILES))
    parser.add_argument('--shared-cache', action='store_true')
    parser.add_argument('--split-carve-crc', action='store_true')
    parser.add_argument('--branch-cache', action='store_true')
    parser.add_argument('--early-cache', action='store_true')
    args = parser.parse_args()
    if args.shared_cache and args.roles[0]!='padding':
        parser.error('shared-cache experiment requires padding as first role')
    source = generate(args.roles, args.shared_cache, args.split_carve_crc, args.branch_cache, args.early_cache)
    args.output.write_text(source)
    identities = {r: hashlib.sha256((ROOT / 'protocol' / ROLE_FILES[r]).read_bytes()).hexdigest()
                  for r in args.roles}
    args.output.with_suffix('.inputs.json').write_text(json.dumps(identities, indent=2) + '\n')


if __name__ == '__main__':
    main()

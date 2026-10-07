"""Structural alternative: three real four-bank merge passes.

The retained assembler's 12-bank merge remains frozen. This candidate keeps
actual snapshots/CAS and full35 validation, but shortens per-pass merge lifetimes.
Live connection publication and protected whole-work lifetime remain required.
"""
from pathlib import Path
import sys

ARCH=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ARCH/'protocol/assembly'),str(ARCH/'protocol')]
from generate_producer import generate as producer
from generate_merge import merge_declarations
import re


def generate(byte_masks=False):
    source=producer()
    _,calls=merge_declarations()
    original='else if(hdr.ref.event==16w3){'+calls+'hdr.ref.event=16w2;}'
    if source.count(original)!=1:
        raise ValueError('retained merge branch changed')
    # Extract complete table calls by their bank suffix, preserving dependency
    # order. Each group is a genuine return, not another branch in one pass.
    tables=re.findall(r'(\w+)\.apply\(\);',calls)
    groups=[]
    for first,event,next_event in ((0,3,7),(4,7,8),(8,8,2)):
        selected=[name for name in tables
            if first<=int(re.search(r'_(\d+)(?:_t)?$',name)[1])<first+4]
        if len(selected)!=36:raise ValueError('merge dependency inventory changed')
        groups.append('else if(hdr.ref.event==16w'+str(event)+'){'
            +''.join(name+'.apply();' for name in selected)
            +'hdr.ref.event=16w'+str(next_event)+';}')
    source=source.replace(original,''.join(groups)).replace(
        '// Actual raw fragment candidate;',
        '// Three actual four-bank merge returns; full work authority still missing;')
    source=source.replace('if(hdr.fragment.hops>8w16)',
        'if(hdr.fragment.hops>=8w16)')
    # Floor the30ms threshold at the existing256ns clock quantum. At a true
    # elapsed30ms every possible origin/current residue meets this predicate.
    # It can expire up to383ns early; it cannot authorize a post30ms write.
    source=source.replace('if(m.age>=32w30000000)',
        'if(m.age>=32w29999872)')
    if byte_masks:
        # Keep the entire presence byte in the lookup. A three-bit key forced
        # incompatible 3/5-bit slices throughout otherwise full32 CAS operands.
        begin=source.index('table coverage{')
        end=source.index('\naction byte_0',begin)
        coverage=source[begin:end].replace('[26:24]:exact;','[31:24]:exact;')
        coverage=coverage.replace('3w7','8w7').replace('3w3','8w3')
        source=source[:begin]+coverage+source[end:]
    # Even a failed resource candidate must never turn a target parser error
    # into an origin/scratch/quarantine mutation before native admission.
    control=source.index('control Ingress(')
    opening=source.index('apply{tm.ucast_egress_port',control)+len('apply')
    depth=1;closing=opening+1
    while depth:
        depth+=(source[closing]=='{')-(source[closing]=='}');closing+=1
    source=source[:opening+1]+'if(p.parser_err==16w0){'+source[opening+1:closing-1]+'}else{md.drop_ctl=3w1;}'+source[closing-1:]
    return source


def worker():
    """Separate stateless merge worker; parent retains every scratch bank."""
    source=generate(byte_masks=True)
    declarations,calls=merge_declarations()
    tables=re.findall(r'(\w+)\.apply\(\);',calls)
    branches=[]
    for first,event,next_event in ((0,3,7),(4,7,8),(8,8,2)):
        selected=[name for name in tables
            if first<=int(re.search(r'_(\d+)(?:_t)?$',name)[1])<first+4]
        branches.append(('if' if first==0 else 'else if')
            +'(hdr.ref.event==16w'+str(event)+'){'
            +''.join(name+'.apply();' for name in selected)
            +'hdr.ref.event=16w'+str(next_event)+';}')
    control='''control Ingress(inout headers_t hdr,inout meta_t m,in ingress_intrinsic_metadata_t ig,in ingress_intrinsic_metadata_from_parser_t p,inout ingress_intrinsic_metadata_for_deparser_t md,inout ingress_intrinsic_metadata_for_tm_t tm){
action bad(){m.fault=1w1;}
'''+declarations+'''apply{tm.bypass_egress=1w1;tm.ucast_egress_port=9w68;
if(p.parser_err==16w0){if(m.private==1w1&&m.parsed==1w1&&!m.ip_error&&m.tcp_sum==16w0xffeb){
 if(hdr.ref.epoch!=32w0&&hdr.ref.generation!=32w0&&hdr.ref.reserved==16w0&&hdr.fragment.reserved==16w0){
  m.offset=hdr.fragment.offset;
  m.end=m.offset+m.full_length;
  if(m.offset<32w35&&m.end<32w36&&hdr.ip.ttl!=8w0&&hdr.fragment.length==m.length&&hdr.fragment.hops<8w16){
   hdr.fragment.hops=hdr.fragment.hops+8w1;
'''+''.join(branches)+'''else{bad();}
   if(m.fault==1w1){hdr.ref.event=16w6;}
  }else{md.drop_ctl=3w1;}
 }else{md.drop_ctl=3w1;}
}else{md.drop_ctl=3w1;}}else{md.drop_ctl=3w1;}
}}
'''
    start=source.index('control Ingress(')
    end=source.index('control IgDeparser(',start)
    # No scalar scratch bank, owner or origin state is copied to this worker.
    return source[:start]+control+source[end:]


def byte_worker(group=None,byte_containers=False,staged=False):
    """Byte operations in the stateless worker; authoritative CAS stays full32."""
    source=worker()
    begin=source.index('header words_h{')
    end=source.index('}',begin)+1
    words=''.join('bit<8> mask'+str(bank)+';'+''.join(
        'bit<8> data'+str(bank)+'_'+str(j)+';' for j in range(3)) for bank in range(12))
    source=source[:begin]+'header words_h{'+words+'}'+source[end:]
    source=source.replace('struct meta_t{','struct meta_t{'+''.join(
        'bit<8> byte_diff'+str(bank)+'_'+str(j)+';' for bank in range(12) for j in range(3)))
    decl='action bad(){m.fault=1w1;}\n'
    calls=[]
    for bank in range(12):
        base=bank*3;limit=min(3,35-base);entries=[];actions=[]
        for offset in range(35):
            first=max(0,offset-base)
            if first>=limit:continue
            for last in range(first,limit):
                lower=base+last-offset+1
                upper=35-offset if last==limit-1 else lower
                if lower<1 or upper<lower:continue
                mask=sum(1<<j for j in range(first,last+1))
                name='bytes_'+str(bank)+'_'+str(offset)+'_'+str(mask)
                actions.append(name)
                entries.append('(32w'+str(offset)+',16w'+str(lower)+'..16w'+str(upper)+'):'+name+'();')
                body='m.present'+str(bank)+'=32w'+str(mask)+';'
                body+='hdr.candidate.mask'+str(bank)+'=hdr.expected.mask'+str(bank)+'|8w'+str(mask)+';'
                for j in range(3):
                    expected='hdr.expected.data'+str(bank)+'_'+str(j)
                    covered=first<=j<=last
                    incoming='hdr.b'+str(base+j-offset)+'.data' if covered else expected
                    body+='hdr.candidate.data'+str(bank)+'_'+str(j)+'='+incoming+';'
                    body+='m.byte_diff'+str(bank)+'_'+str(j)+'='+(expected+'^'+incoming if covered else '8w0')+';'
                decl+='action '+name+'(){'+body+'}\n'
        absent='absent_bytes_'+str(bank)
        decl+='action '+absent+'(){m.present'+str(bank)+'=32w0;hdr.candidate.mask'+str(bank)+'=hdr.expected.mask'+str(bank)+';'+''.join(
            'hdr.candidate.data'+str(bank)+'_'+str(j)+'=hdr.expected.data'+str(bank)+'_'+str(j)+';m.byte_diff'+str(bank)+'_'+str(j)+'=8w0;' for j in range(3))+'}\n'
        decl+='table byte_patch_'+str(bank)+'{key={m.offset:exact;m.length:range;}actions={'+''.join(name+';' for name in actions)+absent+';}size='+str(len(entries))+';const default_action='+absent+'();const entries={'+''.join(entries)+'}}\n'
        mask_limit=1<<limit
        decl+='table mask_check_'+str(bank)+'{key={hdr.expected.mask'+str(bank)+':exact;}actions={bad;NoAction;}size='+str(mask_limit)+';const default_action=bad();const entries={'+''.join('8w'+str(mask)+':NoAction();' for mask in range(mask_limit))+'}}\n'
        call='mask_check_'+str(bank)+'.apply();byte_patch_'+str(bank)+'.apply();'
        for j in range(limit):
            call+='if(hdr.expected.mask'+str(bank)+'['+str(j)+':'+str(j)+']==1w1&&m.present'+str(bank)+'['+str(j)+':'+str(j)+']==1w1&&m.byte_diff'+str(bank)+'_'+str(j)+'!=8w0){bad();}'
        calls.append(call)
    start=source.index('control Ingress(')
    end=source.index('control IgDeparser(',start)
    old=source[start:end]
    apply=old[old.index('apply{tm.bypass_egress'):]
    for first,event,next_event in ((0,3,7),(4,7,8),(8,8,2)):
        marker=('if' if first==0 else 'else if')+'(hdr.ref.event==16w'+str(event)+')'
        opening=apply.index('{',apply.index(marker));depth=1;closing=opening+1
        while depth:
            depth+=(apply[closing]=='{')-(apply[closing]=='}');closing+=1
        apply=apply[:opening+1]+''.join(calls[first:first+4])+'hdr.ref.event=16w'+str(next_event)+';'+apply[closing-1:]
    signature=old[:old.index('{')+1]
    if group is not None:
        if group not in (0,1,2):raise ValueError('fixed group must be0,1 or2')
        for current,event in ((0,3),(1,7),(2,8)):
            if current==group:continue
            marker=('if' if current==0 else 'else if')+'(hdr.ref.event==16w'+str(event)+')'
            branch_start=apply.index(marker);opening=apply.index('{',branch_start);depth=1;branch_end=opening+1
            while depth:
                depth+=(apply[branch_end]=='{')-(apply[branch_end]=='}');branch_end+=1
            apply=apply[:branch_start]+apply[branch_end:]
        apply=apply.replace('else if(hdr.ref.event','if(hdr.ref.event',1)
    if staged:
        # Rotate incoming fragment bytes into their candidate positions first.
        # A later table compares aligned expected/candidate bytes, so a single
        # action no longer constrains a dynamic input to two destination roles.
        decl=re.sub(r'm\.byte_diff(\d+)_(\d+)=([^;]+);','',decl)
        for bank in range(12):
            name='compare_bytes_'+str(bank)
            decl+='action '+name+'(){'+''.join(
                'm.byte_diff'+str(bank)+'_'+str(j)+'=hdr.expected.data'+str(bank)+'_'+str(j)+'^hdr.candidate.data'+str(bank)+'_'+str(j)+';' for j in range(3))+'}\n'
            decl+='table '+name+'_t{actions={'+name+';}const default_action='+name+'();}\n'
            apply=apply.replace('byte_patch_'+str(bank)+'.apply();',
                'byte_patch_'+str(bank)+'.apply();'+name+'_t.apply();')
    annotations=''
    if byte_containers:
        if group is None:raise ValueError('byte alignment experiment requires a fixed group')
        fields=['hdr.b'+str(index)+'.data' for index in range(12)]
        for bank in range(group*4,group*4+4):
            fields.extend(('hdr.expected.mask'+str(bank),'hdr.candidate.mask'+str(bank)))
            for j in range(3):
                fields.extend(('hdr.expected.data'+str(bank)+'_'+str(j),
                    'hdr.candidate.data'+str(bank)+'_'+str(j),
                    'm.byte_diff'+str(bank)+'_'+str(j)))
        annotations=''.join('@pa_container_size("ingress", "'+field+'", 8)\n' for field in fields)
    return source[:start]+annotations+signature+'\n'+decl+apply+source[end:]


if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--byte-masks',action='store_true')
    parser.add_argument('--worker',action='store_true')
    parser.add_argument('--byte-worker',action='store_true')
    parser.add_argument('--fixed-group',type=int,choices=(0,1,2))
    parser.add_argument('--byte-containers',action='store_true')
    parser.add_argument('--staged',action='store_true')
    args=parser.parse_args()
    name=(('staged_worker_' if args.staged else 'fixed_worker_')+str(args.fixed_group)+'.p4') if args.fixed_group is not None else ('staged_worker.p4' if args.staged else ('byte_worker.p4' if args.byte_worker else ('worker.p4' if args.worker else 'producer.p4')))
    Path(__file__).with_name(name).write_text(
        byte_worker(args.fixed_group,args.byte_containers,args.staged) if args.byte_worker or args.fixed_group is not None or args.staged else (worker() if args.worker else generate(args.byte_masks)))

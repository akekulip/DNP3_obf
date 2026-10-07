"""Constant offset-specific exact overlap merge with executable12-bucket CAS backend."""
from pathlib import Path
from generate_buckets import generate as buckets

def merge_declarations():
    s='';calls=''
    for bank in range(12):
        k0=bank*3;limit=min(3,35-k0);entries=[];acts=[]
        # One action for each start offset and covered subset; length ranges are constant.
        for offset in range(35):
            first=max(0,offset-k0)
            if first>=limit:continue
            for last in range(first,limit):
                lower=k0+last-offset+1;upper=35-offset if last==limit-1 else lower
                if lower<1 or upper<lower:continue
                mask=sum(1<<j for j in range(first,last+1));name=f'patch_{bank}_{offset}_{mask}'
                terms=[f'hdr.b{k0+j-offset}.data' if first<=j<=last else '8w0' for j in range(3)]
                s+=f'action {name}(){{m.incoming{bank}=8w0++'+ '++'.join(terms)+f';m.present{bank}=32w{mask};}}\n'
                acts.append(name);entries.append(f'(32w{offset},16w{lower}..16w{upper}):{name}();')
        s+=f'action absent_{bank}(){{m.incoming{bank}=32w0;m.present{bank}=32w0;}}\n'
        s+=f'table patch_{bank}{{key={{m.offset:exact;m.length:range;}}actions={{'+''.join(a+';' for a in acts)+f'absent_{bank};}}size={len(entries)};const default_action=absent_{bank}();const entries={{'+''.join(entries)+'}}\n'
        # Lookup expands only the presence bits, not arbitrary runtime shifting.
        s+=f'action oldmask_{bank}(){{m.oldmask{bank}=hdr.expected.w{bank}>>24;}}table oldmask_{bank}_t{{actions={{oldmask_{bank};}}size=1;const default_action=oldmask_{bank}();}}\n'
        actions=[];rows=[]
        for old in range(8):
            for new in range(8):
                name=f'mask_{bank}_{old}_{new}';overlap=sum(255<<(16-8*j) for j in range(3) if old&new&(1<<j));erase=sum(255<<(16-8*j) for j in range(3) if new&(1<<j));encoded=(old|new)<<24
                s+=f'action {name}(){{m.overlap{bank}=32w{overlap};m.keep{bank}=32w{0xffffff^erase};m.newmask{bank}=32w{encoded};}}\n';actions.append(name);rows.append(f'(32w{old},32w{new}):{name}();')
        s+=f'table masks_{bank}{{key={{m.oldmask{bank}:exact;m.present{bank}:exact;}}actions={{'+''.join(a+';' for a in actions)+f'bad;}}size=64;const default_action=bad();const entries={{'+''.join(rows)+'}}\n'
        s+=f'action difference_{bank}(){{m.diff{bank}=hdr.expected.w{bank}^m.incoming{bank};}}table difference_{bank}_t{{actions={{difference_{bank};}}size=1;const default_action=difference_{bank}();}}\n'
        s+=f'action conflict_{bank}(){{m.diff{bank}=m.diff{bank}&m.overlap{bank};}}table conflict_{bank}_t{{actions={{conflict_{bank};}}size=1;const default_action=conflict_{bank}();}}\n'
        s+=f'table guard_{bank}{{key={{m.diff{bank}:exact;}}actions={{NoAction;bad;}}size=1;const default_action=bad();const entries={{32w0:NoAction();}}}}\n'
        s+=f'action retain_{bank}(){{hdr.candidate.w{bank}=hdr.expected.w{bank}&m.keep{bank};}}table retain_{bank}_t{{actions={{retain_{bank};}}size=1;const default_action=retain_{bank}();}}\n'
        s+=f'action merge_{bank}(){{hdr.candidate.w{bank}=hdr.candidate.w{bank}|m.incoming{bank};}}table merge_{bank}_t{{actions={{merge_{bank};}}size=1;const default_action=merge_{bank}();}}\n'
        s+=f'action finish_{bank}(){{hdr.candidate.w{bank}=hdr.candidate.w{bank}|m.newmask{bank};}}table finish_{bank}_t{{actions={{finish_{bank};}}size=1;const default_action=finish_{bank}();}}\n'
        calls+=f'patch_{bank}.apply();oldmask_{bank}_t.apply();masks_{bank}.apply();difference_{bank}_t.apply();conflict_{bank}_t.apply();guard_{bank}.apply();retain_{bank}_t.apply();merge_{bank}_t.apply();finish_{bank}_t.apply();'
    return s,calls

def generate():
    s=buckets();s=s.replace('header words_h','header byte_h{bit<8> data;}\nheader fragment_h{bit<32> offset;bit<16> length;bit<16> reserved;}\nheader words_h')
    s=s.replace('words_h candidate;}', 'words_h candidate;fragment_h fragment;'+''.join(f'byte_h b{i};' for i in range(35))+'}')
    fields='bit<32> offset;bit<16> length;bit<1> fault;'+''.join(f'bit<32> {field}{i};' for i in range(12) for field in ('incoming','present','oldmask','overlap','keep','newmask','diff'))
    s=s.replace('struct meta_t{','struct meta_t{'+fields)
    s=s.replace('state candidate{pkt.extract(hdr.candidate);transition accept;}', 'state candidate{pkt.extract(hdr.candidate);transition fragment;}state fragment{pkt.extract(hdr.fragment);m.offset=hdr.fragment.offset;m.length=hdr.fragment.length;m.fault=1w0;transition bytes;}state bytes{'+''.join(f'pkt.extract(hdr.b{i});' for i in range(35))+'transition accept;}')
    declarations,calls=merge_declarations();s=s.replace('action deny(){', 'action bad(){m.fault=1w1;}\n'+declarations+'action deny(){')
    # New merge role reads only caller-carried exact snapshots. CAS is a distinct real pass.
    s=s.replace('if(hdr.ref.event==16w1){','if(hdr.ref.event==16w3){'+calls+'if(m.fault==1w1){deny();}}else if(hdr.ref.event==16w1){')
    s=s.replace('pkt.emit(hdr.candidate);','pkt.emit(hdr.candidate);pkt.emit(hdr.fragment);'+''.join(f'pkt.emit(hdr.b{i});' for i in range(35)))
    return s
if __name__=='__main__':Path(__file__).with_name('merge.p4').write_text(generate())

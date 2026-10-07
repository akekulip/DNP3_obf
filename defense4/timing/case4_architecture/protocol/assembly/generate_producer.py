"""Actual raw fragment admission/merge/CAS/reconstruction candidate.

Immutable context table is an integration seam, not handshake/SELECT publisher.
Scalar scratch requires actual protected work pin and reset/debit integration.
"""
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from generate_images import common
from generate_scalar import scalar
from generate_merge import generate as merge

def generate():
    s=scalar(merge());base=common();start=s.index('header ref_h');s=base+s[start:]
    s=s.replace('struct headers_t{','header frame_h{'+''.join(f'bit<8> b{i};' for i in range(35))+'}\nstruct origin_t{bit<32> generation;bit<32> observation;}\nstruct headers_t{')
    s=s.replace('eth_h eth;','eth_h eth;ip_h ip;tcp_h tcp;frame_h frame;')
    s=s.replace('bit<16> reserved;}\nheader words_h','bit<32> arrival;bit<8> hops;bit<8> phase;bit<16> reserved;}\nheader words_h')
    fields='bit<32> full_length;bit<1> foreign;bit<32> sticky_fault;bit<16> tcp_length;bit<1> parsed;bit<1> private;bit<1> enabled;bool ip_error;bit<16> tcp_sum;bit<32> epoch;bit<32> native_start;bit<32> now;bit<32> observation;bit<32> age;bit<32> end;bit<1> bad_offset;bit<1> bad_end;bit<1> complete;bit<1> profile;bit<1> selected_match;bit<1> publish;bit<16> hcrc;bit<16> bcrc;bit<16> tcrc;bit<1> badh;bit<1> badb;bit<1> badt;'
    s=s.replace('struct meta_t{','struct meta_t{'+fields)
    parser='''parser IgParser(packet_in pkt,out headers_t hdr,out meta_t m,out ingress_intrinsic_metadata_t ig){Checksum() ic;Checksum() tc;
state start{pkt.extract(ig);pkt.advance(PORT_METADATA_SIZE);m.parsed=1w0;m.enabled=1w0;m.private=1w0;m.fault=1w0;m.foreign=1w0;m.publish=1w0;m.complete=1w0;m.profile=1w0;m.selected_match=1w0;m.badh=1w0;m.badb=1w0;m.badt=1w0;m.bad_offset=1w0;m.bad_end=1w0;transition select(ig.ingress_port){9w68:reference;9w69:eth;default:reject;}}
state reference{pkt.extract(hdr.ref);m.private=1w1;transition expected;}
state expected{pkt.extract(hdr.expected);transition candidate;}
state candidate{pkt.extract(hdr.candidate);transition fragment_control;}
state fragment_control{pkt.extract(hdr.fragment);transition eth;}
state eth{pkt.extract(hdr.eth);transition select(hdr.eth.type){16w0x0800:ip;default:reject;}}
state ip{pkt.extract(hdr.ip);ic.add(hdr.ip);m.ip_error=ic.verify();tc.subtract({hdr.ip.src,hdr.ip.dst,8w0,hdr.ip.proto,hdr.ip.len});transition select(hdr.ip.version,hdr.ip.ihl,hdr.ip.proto){(4w4,4w5,8w6):flags;default:reject;}}
state flags{transition select(hdr.ip.frag,hdr.ip.flags){(13w0,3w0):tcp;(13w0,3w2):tcp;default:reject;}}
state tcp{pkt.extract(hdr.tcp);tc.subtract(hdr.tcp);transition select(hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.flags,hdr.tcp.urgent){(4w5,4w0,8w16,16w0):length;(4w5,4w0,8w24,16w0):length;default:reject;}}
state length{transition select(hdr.ip.len){'''+''.join(f'16w{40+n}:fragment_{n};' for n in range(1,36))+'''default:reject;}}
'''
    for n in range(1,36):
        parser+=f'state fragment_{n}{{'+''.join(f'pkt.extract(hdr.b{i});' for i in range(n))+'tc.subtract({'+','.join(f'hdr.b{i}.data' for i in range(n))+'});'+f'm.length=16w{n};m.full_length=32w{n};m.tcp_sum=tc.get();m.parsed=1w1;transition accept;}}\n'
    parser+='}\n';a=s.index('parser IgParser');b=s.index('control Ingress',a);s=s[:a]+parser+s[b:]
    declarations='''Register<bit<32>,bit<1>>(1,32w0) transport_fault;
RegisterAction<bit<32>,bit<1>,bit<32>>(transport_fault) preserve_fault={void apply(inout bit<32> v,out bit<32> rv){if(m.fault==1w1){v=32w1;}rv=v;}};
action fault_record(){m.sticky_fault=preserve_fault.execute(1w0);}
table fault_record_t{actions={fault_record;}size=1;const default_action=fault_record();}
action context(bit<32> epoch,bit<32> generation,bit<32> native_start){m.enabled=1w1;m.epoch=epoch;m.generation=generation;m.native_start=native_start;}
table connection{key={hdr.ip.src:exact;hdr.ip.dst:exact;hdr.tcp.sport:exact;hdr.tcp.dport:exact;}actions={context;NoAction;}size=1;default_action=NoAction();}
// This externally installed immutable context does not replace actual connection/WorkRecord authority.
Register<origin_t,bit<1>>(1,{32w0,32w0}) origin;
RegisterAction<origin_t,bit<1>,bit<32>>(origin) observe={void apply(inout origin_t v,out bit<32> rv){if(v.generation<m.generation){v.generation=m.generation;v.observation=hdr.fragment.arrival;}rv=v.observation;}};
action clock_now(){m.now=((bit<32>)p.global_tstamp)&32w0xFFFFFF00;}
table clock_t{actions={clock_now;}size=1;const default_action=clock_now();}
action observation(){m.observation=observe.execute(1w0);}
table observation_t{actions={observation;}size=1;const default_action=observation();}
action elapsed(){m.age=m.now-m.observation;}
table elapsed_t{actions={elapsed;}size=1;const default_action=elapsed();}
action bounds(){m.offset=hdr.tcp.seq-m.native_start;}
table bounds_t{actions={bounds;}size=1;const default_action=bounds();}
action end_offset(){m.end=m.offset+m.full_length;}
table end_t{actions={end_offset;}size=1;const default_action=end_offset();}
action form(){hdr.ref.setValid();hdr.expected.setValid();hdr.candidate.setValid();hdr.fragment.setValid();hdr.ref.epoch=m.epoch;hdr.ref.generation=m.generation;hdr.ref.expected_cell=32w0;hdr.ref.event=16w1;hdr.ref.reserved=16w0;hdr.fragment.offset=m.offset;hdr.fragment.length=m.length;hdr.fragment.arrival=m.now;hdr.fragment.hops=8w1;hdr.fragment.phase=8w0;hdr.fragment.reserved=16w0;}
table form_t{actions={form;}size=1;const default_action=form();}
action retry(){hdr.ref.event=16w1;}
action written(){hdr.ref.event=16w4;}
action has_frame(){m.complete=1w1;}
'''
    maskkeys=''.join(f'hdr.expected.w{i}[26:24]:exact;' for i in range(12));masks=','.join('3w7' if i<11 else '3w3' for i in range(12))
    declarations+=f'table coverage{{key={{{maskkeys}}}actions={{has_frame;NoAction;}}size=1;const default_action=NoAction();const entries={{({masks}):has_frame();}}}}\n'
    for i in range(35):
        bank,j=divmod(i,3);upper=23-8*j;lower=upper-7
        declarations+=f'action byte_{i}(){{hdr.frame.b{i}=hdr.expected.w{bank}[{upper}:{lower}];}}table byte_{i}_t{{actions={{byte_{i};}}size=1;const default_action=byte_{i}();}}\n'
    declarations+='''action eligible(){m.profile=1w1;}
table frame_profile{key={hdr.frame.b0:exact;hdr.frame.b1:exact;hdr.frame.b2:exact;hdr.frame.b3:exact;hdr.frame.b10:ternary;hdr.frame.b11:ternary;hdr.frame.b12:exact;hdr.frame.b13:exact;hdr.frame.b14:exact;hdr.frame.b15:exact;hdr.frame.b16:exact;hdr.frame.b17:exact;hdr.frame.b32:exact;}
actions={eligible;NoAction;}size=1;const default_action=NoAction();const entries={(8w5,8w100,8w26,8w196,8w192&&&8w192,8w192&&&8w240,8w4,8w12,8w1,8w40,8w1,8w0,8w0):eligible();}}
action selected(){m.selected_match=1w1;}
'''
    selected=(4,5,6,7,11,18,19,20,21,22,23,24,25,28,29,30,31,32)
    declarations+='table selected_objects{key={'+''.join(f'hdr.frame.b{i}:exact;' for i in selected)+'}actions={selected;NoAction;}size=1;default_action=NoAction();}\n'
    declarations+='CRCPolynomial<bit<16>>(16w0x3D65,true,false,false,16w0,16w0xFFFF) poly;\n'
    for name,field,indices in (('head','hcrc',range(8)),('body','bcrc',range(10,26)),('tail','tcrc',range(28,33))):
        refs=','.join(f'hdr.frame.b{i}' for i in indices)
        declarations+=f'Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_{name};action crc_{name}(){{m.{field}=hash_{name}.get({{{refs}}});}}table crc_{name}_t{{actions={{crc_{name};}}size=1;const default_action=crc_{name}();}}\n'
    declarations+='action publish(){m.publish=1w1;hdr.frame.setValid();hdr.ref.setInvalid();hdr.expected.setInvalid();hdr.candidate.setInvalid();hdr.fragment.setInvalid();'+''.join(f'hdr.b{i}.setInvalid();' for i in range(35))+'hdr.ip.len=16w75;m.tcp_length=16w55;hdr.tcp.seq=m.native_start;}table publish_t{actions={publish;}size=1;const default_action=publish();}\n'
    s=s.replace('action deny(){',declarations+'action deny(){')
    # CAS collision is retry, not fabricated ACK or autonomous transmit.
    s=s.replace('actions={deny;NoAction;}size=1;const default_action=deny();const entries={('+','.join('32w0' for _ in range(12))+'):NoAction();}', 'actions={retry;written;}size=1;const default_action=retry();const entries={('+','.join('32w0' for _ in range(12))+'):written();}')
    old=s.index('apply{tm.ucast_egress_port=ig.ingress_port');end=s.index('\ncontrol IgDeparser',old)
    reads=''.join(f'read_{i}_t.apply();' for i in range(12));writes=''.join(f'write_{i}_t.apply();' for i in range(12))
    from generate_merge import merge_declarations
    _,merges=merge_declarations()
    validate='coverage.apply();if(m.complete==1w1){'+''.join(f'byte_{i}_t.apply();' for i in range(35))+'frame_profile.apply();selected_objects.apply();if(m.profile==1w1&&m.selected_match==1w1){crc_head_t.apply();crc_body_t.apply();crc_tail_t.apply();if((hdr.frame.b8++hdr.frame.b9)!=(m.hcrc[7:0]++m.hcrc[15:8])){m.badh=1w1;}if((hdr.frame.b26++hdr.frame.b27)!=(m.bcrc[7:0]++m.bcrc[15:8])){m.badb=1w1;}if((hdr.frame.b33++hdr.frame.b34)!=(m.tcrc[7:0]++m.tcrc[15:8])){m.badt=1w1;}if(m.badh==1w0&&m.badb==1w0&&m.badt==1w0){publish_t.apply();}else{bad();}}else{bad();}}'
    apply='''apply{tm.ucast_egress_port=9w68;tm.bypass_egress=1w1;clock_t.apply();connection.apply();if(m.parsed==1w1&&!m.ip_error&&m.tcp_sum==16w0xFFEB&&m.enabled==1w1){bounds_t.apply();if(m.offset>32w34){m.bad_offset=1w1;}end_t.apply();if(m.end>32w35){m.bad_end=1w1;}if(m.bad_offset==1w0&&m.bad_end==1w0&&m.generation!=32w0){if(m.private==1w0){form_t.apply();}if(hdr.ref.epoch!=m.epoch){m.foreign=1w1;bad();}if(hdr.ref.generation!=m.generation){m.foreign=1w1;bad();}if(hdr.fragment.hops>8w16){bad();}if(m.fault==1w0){observation_t.apply();elapsed_t.apply();if(m.age>=32w30000000){bad();}}if(m.fault==1w0){hdr.fragment.hops=hdr.fragment.hops+8w1;if(hdr.ref.event==16w1){'''+reads+'''hdr.ref.event=16w3;}else if(hdr.ref.event==16w3){'''+merges+'''hdr.ref.event=16w2;}else if(hdr.ref.event==16w2){'''+writes+'''result.apply();}else if(hdr.ref.event==16w4){'''+reads+validate+'''if(m.publish==1w0&&m.fault==1w0){deny();}}else{bad();}}}else{bad();}}else{bad();}if(m.fault==1w1){deny();}if(m.publish==1w1){tm.ucast_egress_port=9w70;}}}
'''
    apply=apply.replace(reads+'hdr.ref.event=16w3;', 'hdr.ref.event=16w3;').replace(reads+validate,validate)
    apply=apply.replace('hdr.fragment.hops=hdr.fragment.hops+8w1;', 'hdr.fragment.hops=hdr.fragment.hops+8w1;if(hdr.ref.event==16w1||hdr.ref.event==16w4){'+reads+'}')
    early='if(m.private==1w1){if(hdr.ref.epoch!=m.epoch){m.foreign=1w1;bad();}if(hdr.ref.generation!=m.generation){m.foreign=1w1;bad();}}if(m.enabled==1w1&&m.foreign==1w0&&m.generation!=32w0){if(m.private==1w1&&hdr.ref.event==16w6){bad();}fault_record_t.apply();if(m.sticky_fault!=32w0){bad();}}'
    apply=apply.replace('connection.apply();if(m.parsed', 'connection.apply();'+early+'if(m.fault==1w0&&m.parsed')
    apply=apply.replace('if(m.private==1w0){form_t.apply();}', '').replace('bounds_t.apply();','')
    apply=apply.replace('connection.apply();','connection.apply();bounds_t.apply();if(m.private==1w0&&m.enabled==1w1&&m.generation!=32w0){form_t.apply();}')
    apply=apply.replace('if(m.fault==1w1){deny();}', 'if(m.fault==1w1){if(m.enabled==1w1&&m.foreign==1w0&&m.generation!=32w0){if(m.private==1w1&&hdr.ref.event==16w6){deny();}else{hdr.ref.event=16w6;}}else{deny();}}')
    s=s[:old]+apply+s[end:]
    a=s.index('control IgDeparser');b=s.index('parser EgParser',a)
    deparser='''control IgDeparser(packet_out pkt,inout headers_t hdr,in meta_t m,in ingress_intrinsic_metadata_for_deparser_t md){Checksum() ic;Checksum() tc;apply{if(m.publish==1w1){hdr.ip.checksum=ic.update({hdr.ip.version,hdr.ip.ihl,hdr.ip.tos,hdr.ip.len,hdr.ip.id,hdr.ip.flags,hdr.ip.frag,hdr.ip.ttl,hdr.ip.proto,hdr.ip.src,hdr.ip.dst});hdr.tcp.checksum=tc.update({hdr.ip.src,hdr.ip.dst,8w0,hdr.ip.proto,m.tcp_length,hdr.tcp.sport,hdr.tcp.dport,hdr.tcp.seq,hdr.tcp.ack,hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.flags,hdr.tcp.window,hdr.tcp.urgent,'''+','.join(f'hdr.frame.b{i}' for i in range(35))+'''});}pkt.emit(hdr.ref);pkt.emit(hdr.expected);pkt.emit(hdr.candidate);pkt.emit(hdr.fragment);pkt.emit(hdr.eth);pkt.emit(hdr.ip);pkt.emit(hdr.tcp);pkt.emit(hdr.frame);'''+''.join(f'pkt.emit(hdr.b{i});' for i in range(35))+'''}}
'''
    s=s[:a]+deparser+s[b:]
    return s.replace('// Scalar CAS backend: caller must pin old work through all genuine terminal credits. Not a complete producer.','// Actual raw fragment candidate; still requires protected pin/reset/terminal and real immutable connection publisher.')
if __name__=='__main__':Path(__file__).with_name('producer.p4').write_text(generate())

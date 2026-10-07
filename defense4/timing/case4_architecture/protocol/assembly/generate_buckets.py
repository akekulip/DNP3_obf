"""Executable12 paired64 scratch banks: actual tagged snapshots and atomic CAS."""
from pathlib import Path

def declarations():
    s=''
    for i in range(12):
        s+=f'''Register<bucket_t,bit<1>>(1,{{32w0,32w0}}) bucket_{i};
RegisterAction<bucket_t,bit<1>,bit<32>>(bucket_{i}) snapshot_{i}={{void apply(inout bucket_t v,out bit<32> rv){{
 if(v.generation<m.generation){{v.generation=m.generation;v.encoded=32w0;}}
 rv=v.encoded;
}}}};
RegisterAction<bucket_t,bit<1>,bit<32>>(bucket_{i}) cas_{i}={{void apply(inout bucket_t v,out bit<32> rv){{
 if(v.generation==m.generation&&v.encoded==hdr.expected.w{i}){{v.encoded=hdr.candidate.w{i};rv=32w0;}}else{{rv=32w1;}}
}}}};
action read_{i}(){{hdr.expected.w{i}=snapshot_{i}.execute(1w0);}}
table read_{i}_t{{actions={{read_{i};}}size=1;const default_action=read_{i}();}}
action write_{i}(){{m.status{i}=cas_{i}.execute(1w0);}}
table write_{i}_t{{actions={{write_{i};}}size=1;const default_action=write_{i}();}}
'''
    return s

def generate():
    words=''.join(f'bit<32> w{i};' for i in range(12))
    statuses=''.join(f'bit<32> status{i};' for i in range(12))
    s='''#include <core.p4>
#include <tna.p4>
// Internal executable bank primitive, not raw network admission or protected publication.
header eth_h{bit<48> dst;bit<48> src;bit<16> type;}
header ref_h{bit<32> epoch;bit<32> generation;bit<32> expected_cell;bit<16> event;bit<16> reserved;}
'''+f'header words_h{{{words}}}\nstruct bucket_t{{bit<32> generation;bit<32> encoded;}}\nstruct headers_t{{eth_h eth;ref_h ref;words_h expected;words_h candidate;}}\nstruct meta_t{{bit<32> generation;{statuses}}}\n'
    s+='''parser IgParser(packet_in pkt,out headers_t hdr,out meta_t m,out ingress_intrinsic_metadata_t ig){
 state start{pkt.extract(ig);pkt.advance(PORT_METADATA_SIZE);transition eth;}
 state eth{pkt.extract(hdr.eth);transition select(hdr.eth.type){16w0x88D4:ref;default:reject;}}
 state ref{pkt.extract(hdr.ref);m.generation=hdr.ref.generation;transition expected;}
 state expected{pkt.extract(hdr.expected);transition candidate;}
 state candidate{pkt.extract(hdr.candidate);transition accept;}}
control Ingress(inout headers_t hdr,inout meta_t m,in ingress_intrinsic_metadata_t ig,in ingress_intrinsic_metadata_from_parser_t p,inout ingress_intrinsic_metadata_for_deparser_t md,inout ingress_intrinsic_metadata_for_tm_t tm){
'''+declarations()+'''action deny(){md.drop_ctl=3w1;}
'''
    key=''.join(f'm.status{i}:exact;' for i in range(12));zero=','.join('32w0' for _ in range(12))
    s+=f'table result{{key={{{key}}}actions={{deny;NoAction;}}size=1;const default_action=deny();const entries={{({zero}):NoAction();}}}}\n'
    s+='apply{tm.ucast_egress_port=ig.ingress_port;tm.bypass_egress=1w1;if(m.generation!=32w0){if(hdr.ref.event==16w1){'
    s+=''.join(f'read_{i}_t.apply();' for i in range(12))+'}else if(hdr.ref.event==16w2){'+''.join(f'write_{i}_t.apply();' for i in range(12))+'result.apply();}else{deny();}}else{deny();}}}\n'
    s+='''control IgDeparser(packet_out pkt,inout headers_t hdr,in meta_t m,in ingress_intrinsic_metadata_for_deparser_t md){apply{pkt.emit(hdr.eth);pkt.emit(hdr.ref);pkt.emit(hdr.expected);pkt.emit(hdr.candidate);}}
parser EgParser(packet_in pkt,out headers_t hdr,out meta_t m,out egress_intrinsic_metadata_t eg){state start{pkt.extract(eg);transition accept;}}
control Egress(inout headers_t hdr,inout meta_t m,in egress_intrinsic_metadata_t eg,in egress_intrinsic_metadata_from_parser_t p,inout egress_intrinsic_metadata_for_deparser_t md,inout egress_intrinsic_metadata_for_output_port_t port){apply{}}
control EgDeparser(packet_out pkt,inout headers_t hdr,in meta_t m,in egress_intrinsic_metadata_for_deparser_t md){apply{}}
Pipeline(IgParser(),Ingress(),IgDeparser(),EgParser(),Egress(),EgDeparser()) pipe;Switch(pipe) main;
'''
    return s
if __name__=='__main__':Path(__file__).with_name('buckets.p4').write_text(generate())

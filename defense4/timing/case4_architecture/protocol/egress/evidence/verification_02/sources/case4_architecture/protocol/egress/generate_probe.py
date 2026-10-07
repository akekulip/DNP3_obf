"""Compiler hypothesis: paired64 shared egress banks with full64 atomic reads."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from generate_images import common

def banks():
 s=''
 for i in range(14):
  data=f'hdr.image.w{i}' if i<13 else 'm.last_word'
  s+=f'''Register<cache_word_t,bit<1>>(2,{{32w0,32w0}}) image_{i};
RegisterAction<cache_word_t,bit<1>,bit<32>>(image_{i}) write_{i}={{void apply(inout cache_word_t v,out bit<32> rv){{
if(v.generation<hdr.descriptor.generation){{v.generation=hdr.descriptor.generation;v.data={data};rv=v.generation;}}
else{{if(v.data!={data}){{rv=32w0;}}else{{rv=v.generation;}}}}
}}}};
RegisterAction<cache_word_t,bit<1>,cache_word_t>(image_{i}) read_{i}={{void apply(inout cache_word_t v,out cache_word_t rv){{rv=v;}}}};
action store_{i}(){{m.tag{i}=write_{i}.execute(hdr.descriptor.slot);}}
table store_{i}_t{{actions={{store_{i};}}size=1;const default_action=store_{i}();}}
action load_{i}(){{m.loaded{i}=read_{i}.execute(hdr.descriptor.slot);}}
table load_{i}_t{{actions={{load_{i};}}size=1;const default_action=load_{i}();}}
action unpack_{i}(){{m.tag{i}=m.loaded{i}.generation;'''+(f'hdr.image.w{i}=m.loaded{i}.data;' if i<13 else 'hdr.image.w13=m.loaded13.data[31:8];')+f'''}}
table unpack_{i}_t{{actions={{unpack_{i};}}size=1;const default_action=unpack_{i}();}}
action difference_{i}(){{m.tag{i}=m.tag{i}^hdr.descriptor.generation;}}
table difference_{i}_t{{actions={{difference_{i};}}size=1;const default_action=difference_{i}();}}
'''
 return s

def generate():
 s=common()+'''header descriptor_h{bit<32> generation;bit<32> wire_start;bit<8> operation;bit<1> slot;bit<7> pad;bit<16> reserved;}
header image_h{'''+''.join(f'bit<32> w{i};' for i in range(13))+'''bit<24> w13;}
header byte_h{bit<8> data;}
struct cache_word_t{bit<32> generation;bit<32> data;}
struct headers_t{descriptor_h descriptor;eth_h eth;ip_h ip;tcp_h tcp;image_h image;byte_h native;}
struct meta_t{bit<32> last_word;bit<16> tcp_length;'''+''.join(f'bit<32> tag{i};cache_word_t loaded{i};' for i in range(14))+'''}
parser IgParser(packet_in pkt,out headers_t hdr,out meta_t m,out ingress_intrinsic_metadata_t ig){state start{pkt.extract(ig);pkt.advance(PORT_METADATA_SIZE);pkt.extract(hdr.descriptor);pkt.extract(hdr.eth);pkt.extract(hdr.ip);pkt.extract(hdr.tcp);transition select(hdr.descriptor.operation){8w2:image;8w1:byte;default:reject;}}state image{pkt.extract(hdr.image);transition accept;}state byte{pkt.extract(hdr.native);transition accept;}}
control Ingress(inout headers_t hdr,inout meta_t m,in ingress_intrinsic_metadata_t ig,in ingress_intrinsic_metadata_from_parser_t p,inout ingress_intrinsic_metadata_for_deparser_t md,inout ingress_intrinsic_metadata_for_tm_t tm){apply{tm.ucast_egress_port=ig.ingress_port;tm.bypass_egress=1w0;}}
control IgDeparser(packet_out pkt,inout headers_t hdr,in meta_t m,in ingress_intrinsic_metadata_for_deparser_t md){apply{pkt.emit(hdr.descriptor);pkt.emit(hdr.eth);pkt.emit(hdr.ip);pkt.emit(hdr.tcp);pkt.emit(hdr.image);pkt.emit(hdr.native);}}
parser EgParser(packet_in pkt,out headers_t hdr,out meta_t m,out egress_intrinsic_metadata_t eg){state start{pkt.extract(eg);pkt.extract(hdr.descriptor);pkt.extract(hdr.eth);pkt.extract(hdr.ip);pkt.extract(hdr.tcp);transition select(hdr.descriptor.operation){8w2:image;8w1:byte;default:reject;}}state image{pkt.extract(hdr.image);transition accept;}state byte{pkt.extract(hdr.native);transition accept;}}
control Egress(inout headers_t hdr,inout meta_t m,in egress_intrinsic_metadata_t eg,in egress_intrinsic_metadata_from_parser_t p,inout egress_intrinsic_metadata_for_deparser_t md,inout egress_intrinsic_metadata_for_output_port_t port){
'''+banks()+'''action deny(){md.drop_ctl=3w1;}
action last_word(){m.last_word=hdr.image.w13++8w0;}
table last_word_t{actions={last_word;}size=1;const default_action=last_word();}
'''
 keys=''.join(f'm.tag{i}:exact;' for i in range(14));zeros=','.join('32w0' for i in range(14))
 s+=f'table valid_tags{{key={{{keys}}}actions={{NoAction;deny;}}size=1;const default_action=deny();const entries={{({zeros}):NoAction();}}}}\n'
 s+='apply{if(hdr.descriptor.generation==32w0){deny();}else{if(hdr.descriptor.operation==8w2){last_word_t.apply();'+''.join(f'store_{i}_t.apply();' for i in range(14))+'}else{'+''.join(f'load_{i}_t.apply();unpack_{i}_t.apply();' for i in range(14))+'hdr.image.setValid();hdr.native.setInvalid();hdr.ip.len=16w95;hdr.tcp.seq=hdr.descriptor.wire_start;}'+''.join(f'difference_{i}_t.apply();' for i in range(14))+'valid_tags.apply();}m.tcp_length=16w75;}\n}\n'
 s+='''control EgDeparser(packet_out pkt,inout headers_t hdr,in meta_t m,in egress_intrinsic_metadata_for_deparser_t md){Checksum() ic;Checksum() tc;apply{hdr.ip.checksum=ic.update({hdr.ip.version,hdr.ip.ihl,hdr.ip.tos,hdr.ip.len,hdr.ip.id,hdr.ip.flags,hdr.ip.frag,hdr.ip.ttl,hdr.ip.proto,hdr.ip.src,hdr.ip.dst});hdr.tcp.checksum=tc.update({hdr.ip.src,hdr.ip.dst,8w0,hdr.ip.proto,m.tcp_length,hdr.tcp.sport,hdr.tcp.dport,hdr.tcp.seq,hdr.tcp.ack,hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.flags,hdr.tcp.window,hdr.tcp.urgent,'''+','.join(f'hdr.image.w{i}' for i in range(14))+'''});pkt.emit(hdr.eth);pkt.emit(hdr.ip);pkt.emit(hdr.tcp);pkt.emit(hdr.image);}}
Pipeline(IgParser(),Ingress(),IgDeparser(),EgParser(),Egress(),EgDeparser()) pipe;Switch(pipe) main;
'''
 return s
if __name__=='__main__':Path(__file__).with_name('tagged_probe.p4').write_text(generate())

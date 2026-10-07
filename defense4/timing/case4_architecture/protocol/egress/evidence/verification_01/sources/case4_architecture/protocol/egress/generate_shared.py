"""Actual raw admission → native validation → shared egress scalar image banks.

A structural primitive: immutable connection/WorkRecord authority is NOT implemented.
The 12-byte descriptor is emitted internally after validation, never parsed from wire.
"""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from generate_padding import generate as padding

def generate():
 s=padding()
 s=s.replace('struct headers_t{','header descriptor_h{bit<32> generation;bit<32> wire_start;bit<8> operation;bit<8> slot;bit<16> reserved;}\nheader image_h{'+''.join(f'bit<32> w{i};' for i in range(13))+'bit<24> w13;}\nheader byte_h{bit<8> data;}\nstruct headers_t{descriptor_h descriptor;image_h image;byte_h replay;')
 s=s.replace('struct meta_t{','struct meta_t{bit<1> replay_parsed;bit<1> replay_allowed;bit<32> generation;bit<32> wire_start;bit<8> native_last;bit<8> slot;bit<32> last_word;')
 s=s.replace('m.parsed=1w0;','m.replay_parsed=1w0;m.replay_allowed=1w0;m.parsed=1w0;')
 s=s.replace('(4w4,4w5,16w75,8w6):ip_flags;','(4w4,4w5,16w75,8w6):ip_flags;(4w4,4w5,16w41,8w6):ip_flags;')
 s=s.replace('16w0):dl;','16w0):payload;')
 s=s.replace(' state dl{',' state payload{transition select(hdr.ip.len){16w75:dl;16w41:replay;default:accept;}}\n state replay{pkt.extract(hdr.replay);tc.subtract(hdr.replay);m.tcp_sum=tc.get();m.replay_parsed=1w1;transition accept;}\n state dl{')
 # Consume IP length before TCP selectors so urgent16 retains one16+two8 PMRs.
 s=s.replace('(4w4,4w5,16w75,8w6):ip_flags;(4w4,4w5,16w41,8w6):ip_flags;', '(4w4,4w5,16w75,8w6):ip_flags_full;(4w4,4w5,16w41,8w6):ip_flags_replay;')
 start=s.index(' state ip_flags{');end=s.index(' state replay{',start)
 s=s[:start]+''' state ip_flags_full{transition select(hdr.ip.frag,hdr.ip.flags){(13w0,3w0):tcp_full;(13w0,3w2):tcp_full;default:accept;}}
 state ip_flags_replay{transition select(hdr.ip.frag,hdr.ip.flags){(13w0,3w0):tcp_replay;(13w0,3w2):tcp_replay;default:accept;}}
 state tcp_full{pkt.extract(hdr.tcp);tc.subtract(hdr.tcp);transition select(hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.flags,hdr.tcp.urgent){(4w5,4w0,8w0x10,16w0):dl;(4w5,4w0,8w0x18,16w0):dl;default:accept;}}
 state tcp_replay{pkt.extract(hdr.tcp);tc.subtract(hdr.tcp);transition select(hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.flags,hdr.tcp.urgent){(4w5,4w0,8w0x10,16w0):replay;(4w5,4w0,8w0x18,16w0):replay;default:accept;}}
'''+s[end:]
 s=s.replace('tm.bypass_egress=1w1;','tm.bypass_egress=1w0;')
 s=s.replace('bit<32> off){m.enabled','bit<32> off,bit<32> generation){m.generation=generation;m.enabled')
 s=s.replace(' apply{forwarding.apply();if(m.parsed',''' action cached(bit<32> generation,bit<32> wire_start,bit<8> native_last,bit<8> slot){m.replay_allowed=1w1;m.generation=generation;m.wire_start=wire_start;m.native_last=native_last;m.slot=slot;}
 table replay_context{key={hdr.ip.src:exact;hdr.ip.dst:exact;hdr.tcp.sport:exact;hdr.tcp.dport:exact;hdr.tcp.seq:exact;}actions={cached;NoAction;}size=2;const default_action=NoAction();}
 action write_descriptor(){hdr.descriptor.setValid();hdr.descriptor.generation=m.generation;hdr.descriptor.wire_start=hdr.tcp.seq;hdr.descriptor.operation=8w2;hdr.descriptor.slot=m.slot;hdr.descriptor.reserved=16w0;}
 table write_descriptor_t{actions={write_descriptor;}size=1;const default_action=write_descriptor();}
 action read_descriptor(){hdr.descriptor.setValid();hdr.descriptor.generation=m.generation;hdr.descriptor.wire_start=m.wire_start;hdr.descriptor.operation=8w1;hdr.descriptor.slot=m.slot;hdr.descriptor.reserved=16w0;}
 table read_descriptor_t{actions={read_descriptor;}size=1;const default_action=read_descriptor();}
 apply{forwarding.apply();if(md.drop_ctl==3w0){if(m.parsed''')
 # exact fixed native profile and all three CRC checks from padding; mutation only after admission.
 end='crc_render_t.apply();}}}}\n}'
 repl='''crc_render_t.apply();m.slot=hdr.native.func-8w3;if(m.generation!=32w0){write_descriptor_t.apply();}}}}
 if(m.replay_parsed==1w1&&!m.ip_error&&m.tcp_sum==16w0xFFEB){replay_context.apply();if(m.replay_allowed==1w1&&m.generation!=32w0&&hdr.replay.data==m.native_last){read_descriptor_t.apply();}}
 }if(!hdr.descriptor.isValid()){deny();}}
}'''
 assert end in s;s=s.replace(end,repl)
 # Avoid isValid in fragment evaluator: validity flag has actual assignment in descriptors.
 s=s.replace('bit<1> replay_parsed;','bit<1> descriptor_valid;bit<1> replay_parsed;').replace('m.replay_parsed=1w0;','m.descriptor_valid=1w0;m.replay_parsed=1w0;').replace('hdr.descriptor.setValid();','m.descriptor_valid=1w1;hdr.descriptor.setValid();').replace('!hdr.descriptor.isValid()','m.descriptor_valid==1w0')
 s=s.replace('pkt.emit(hdr.eth);pkt.emit(hdr.ip);pkt.emit(hdr.tcp);pkt.emit(hdr.dl);','pkt.emit(hdr.descriptor);pkt.emit(hdr.eth);pkt.emit(hdr.ip);pkt.emit(hdr.tcp);pkt.emit(hdr.replay);pkt.emit(hdr.dl);')
 s=s[:s.index('parser EgParser')]
 s+='''parser EgParser(packet_in pkt,out headers_t hdr,out meta_t m,out egress_intrinsic_metadata_t eg){
 state start{pkt.extract(eg);pkt.extract(hdr.descriptor);pkt.extract(hdr.eth);pkt.extract(hdr.ip);pkt.extract(hdr.tcp);transition select(hdr.descriptor.operation,hdr.descriptor.slot){(8w2,8w0):image;(8w2,8w1):image;(8w1,8w0):replay;(8w1,8w1):replay;default:reject;}}
 state image{pkt.extract(hdr.image);transition accept;}
 state replay{pkt.extract(hdr.replay);transition accept;}
}
control Egress(inout headers_t hdr,inout meta_t m,in egress_intrinsic_metadata_t eg,in egress_intrinsic_metadata_from_parser_t p,inout egress_intrinsic_metadata_for_deparser_t md,inout egress_intrinsic_metadata_for_output_port_t port){
'''
 for i in range(14):
  value=f'hdr.image.w{i}' if i<13 else 'm.last_word'
  s+=f'''Register<bit<32>,bit<1>>(2,32w0) image_{i};
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_{i}) write_{i}={{void apply(inout bit<32> v,out bit<32> rv){{v={value};rv=v;}}}};
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_{i}) read_{i}={{void apply(inout bit<32> v,out bit<32> rv){{rv=v;}}}};
 action store_{i}(){{write_{i}.execute(hdr.descriptor.slot[0:0]);}}
 table store_{i}_t{{actions={{store_{i};}}size=1;const default_action=store_{i}();}}
 action load_{i}(){{'''+(f'hdr.image.w{i}=read_{i}.execute(hdr.descriptor.slot[0:0]);' if i<13 else 'm.last_word=read_13.execute(hdr.descriptor.slot[0:0]);')+f'''}}
 table load_{i}_t{{actions={{load_{i};}}size=1;const default_action=load_{i}();}}
'''
 s+='''action deny(){md.drop_ctl=3w1;}
 action form_last(){m.last_word=hdr.image.w13++8w0;}
 table form_last_t{actions={form_last;}size=1;const default_action=form_last();}
 action render(){hdr.image.w13=m.last_word[31:8];hdr.image.setValid();hdr.replay.setInvalid();hdr.ip.len=16w95;hdr.tcp.seq=hdr.descriptor.wire_start;}
 table render_t{actions={render;}size=1;const default_action=render();}
 apply{if(hdr.descriptor.generation==32w0){deny();}else{if(hdr.descriptor.operation==8w2){form_last_t.apply();'''+''.join(f'store_{i}_t.apply();' for i in range(14))+'''}else{if(hdr.descriptor.operation==8w1){'''+''.join(f'load_{i}_t.apply();' for i in range(14))+'''render_t.apply();}else{deny();}}}m.tcp_length=16w75;}
}
control EgDeparser(packet_out pkt,inout headers_t hdr,in meta_t m,in egress_intrinsic_metadata_for_deparser_t md){Checksum() ic;Checksum() tc;
 apply{hdr.ip.checksum=ic.update({hdr.ip.version,hdr.ip.ihl,hdr.ip.tos,hdr.ip.len,hdr.ip.id,hdr.ip.flags,hdr.ip.frag,hdr.ip.ttl,hdr.ip.proto,hdr.ip.src,hdr.ip.dst});hdr.tcp.checksum=tc.update({hdr.ip.src,hdr.ip.dst,8w0,hdr.ip.proto,m.tcp_length,hdr.tcp.sport,hdr.tcp.dport,hdr.tcp.seq,hdr.tcp.ack,hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.flags,hdr.tcp.window,hdr.tcp.urgent,'''+','.join(f'hdr.image.w{i}' for i in range(14))+'''});pkt.emit(hdr.eth);pkt.emit(hdr.ip);pkt.emit(hdr.tcp);pkt.emit(hdr.image);}
}
Pipeline(IgParser(),Ingress(),IgDeparser(),EgParser(),Egress(),EgDeparser()) pipe;Switch(pipe) main;
'''
 return s
if __name__=='__main__':Path(__file__).with_name('shared_egress.p4').write_text(generate())

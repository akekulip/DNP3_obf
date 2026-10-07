"""Small independent exact-image and CRC-materialization target experiments.

Controller-seeded immutable records are a primitive input, not a validation proof.
"""
from pathlib import Path
from generate_mapping import generate

def common():
 s=generate()
 return s[s.index('#include'):s.index('struct headers_t')]

def generate_image(canonical=False):
 s='/* Offline cache render experiment: CP-published record, no admission/lifecycle producer. */\n'+common()
 if canonical:
  fields='bit<32> h0;bit<32> h1;bit<16> hc;'+''.join(''.join(f'bit<32> b{block}_{i};' for i in range(4))+f'bit<16> c{block};' for block in range(2))+ 'bit<32> t0;bit<24> t1;bit<16> tc;'
  words=['h0','h1']+[f'b{b}_{i}' for b in range(2) for i in range(4)]+['t0','t1']
 else:
  fields=''.join(f'bit<32> w{i};' for i in range(13))+'bit<24> w13;'
  words=[f'w{i}' for i in range(14)]
 s+='header image_h {'+fields+'}\nheader byte_h{bit<8> data;}\nstruct headers_t{eth_h eth;ip_h ip;tcp_h tcp;byte_h native;image_h image;}\n'
 s+='''struct meta_t{bit<1> render;bit<1> image_slot;bit<32> loaded_last;bit<16> ip_length;bit<16> tcp_length;bit<32> wire_start;bit<8> expected_byte;bit<16> tcp_sum;bool ip_error;bit<1> parsed;bit<16> hcrc;bit<16> crc0;bit<16> crc1;bit<16> crct;}
parser IgParser(packet_in pkt,out headers_t hdr,out meta_t m,out ingress_intrinsic_metadata_t ig){Checksum() ic;Checksum() tc;
 state start{pkt.extract(ig);pkt.advance(PORT_METADATA_SIZE);m.render=1w0;m.parsed=1w0;transition eth;}
 state eth{pkt.extract(hdr.eth);transition select(hdr.eth.type){16w0x0800:ip;default:accept;}}
 state ip{pkt.extract(hdr.ip);ic.add(hdr.ip);m.ip_error=ic.verify();tc.subtract({hdr.ip.src,hdr.ip.dst,8w0,hdr.ip.proto,hdr.ip.len});transition select(hdr.ip.version,hdr.ip.ihl,hdr.ip.len,hdr.ip.proto){(4w4,4w5,16w41,8w6):ip_flags;default:accept;}}
 state ip_flags{transition select(hdr.ip.frag,hdr.ip.flags){(13w0,3w0):tcp;(13w0,3w2):tcp;default:accept;}}\n state tcp{pkt.extract(hdr.tcp);tc.subtract(hdr.tcp);transition select(hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.flags,hdr.tcp.urgent){(4w5,4w0,8w0x10,16w0):body;(4w5,4w0,8w0x18,16w0):body;default:accept;}}
 state body{pkt.extract(hdr.native);tc.subtract(hdr.native);m.tcp_sum=tc.get();m.parsed=1w1;transition accept;}
}
control Ingress(inout headers_t hdr,inout meta_t m,in ingress_intrinsic_metadata_t ig,in ingress_intrinsic_metadata_from_parser_t p,inout ingress_intrinsic_metadata_for_deparser_t md,inout ingress_intrinsic_metadata_for_tm_t tm){
 action deny(){md.drop_ctl=3w1;}
 action route(PortId_t port){tm.ucast_egress_port=port;tm.bypass_egress=1w1;}
 table forwarding{key={ig.ingress_port:exact;}actions={route;deny;}size=4;default_action=deny();}
 action cached(bit<32> wire_start,bit<8> native_last,bit<1> image_slot){m.image_slot=image_slot;m.render=1w1;m.wire_start=wire_start;m.expected_byte=native_last;}
 table replay{key={hdr.ip.src:exact;hdr.ip.dst:exact;hdr.tcp.sport:exact;hdr.tcp.dport:exact;hdr.tcp.seq:exact;}actions={cached;NoAction;}size=2;default_action=NoAction();}
'''
 for i,name in enumerate(words):
  width=24 if (canonical and name=='t1') or (not canonical and name=='w13') else 32
  s+=f'Register<bit<32>,bit<1>>(2,0) image_{i};\nRegisterAction<bit<32>,bit<1>,bit<32>>(image_{i}) read_{i}={{void apply(inout bit<32> v,out bit<32> rv){{rv=v;}}}};\n'
  # Both image slots need caller-selected index; phase selection comes from exact TCP position.
  s+=f'action load_{i}(){{'+(f'm.loaded_last=read_{i}.execute(m.image_slot);' if width!=32 else f'hdr.image.{name}=read_{i}.execute(m.image_slot);')+f'}}\ntable load_{i}_t{{actions={{load_{i};}}size=1;const default_action=load_{i}();}}\n'
  if width!=32:s+=f'action last_slice(){{hdr.image.{name}=m.loaded_last[31:8];}}\ntable last_slice_t{{actions={{last_slice;}}size=1;const default_action=last_slice();}}\n'
 if canonical:
  s+='CRCPolynomial<bit<16>>(16w0x3D65,true,false,false,16w0,16w0xFFFF) poly;\n'
  for name in ('head','block0','block1','tail'):s+=f'Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_{name};\n'
  
  for name,field,refs in [('head','hc','h0,h1'),('block0','c0','b0_0,b0_1,b0_2,b0_3'),('block1','c1','b1_0,b1_1,b1_2,b1_3'),('tail','tc','t0,t1')]:
   args=','.join('hdr.image.'+f for f in refs.split(','))
   s+=f'action crc_{name}(){{hdr.image.{field}=hash_{name}.get({{{args}}});}}\ntable crc_{name}_t{{actions={{crc_{name};}}size=1;const default_action=crc_{name}();}}\n'
  s+='action crc_swap(){hdr.image.hc=hdr.image.hc[7:0]++hdr.image.hc[15:8];hdr.image.c0=hdr.image.c0[7:0]++hdr.image.c0[15:8];hdr.image.c1=hdr.image.c1[7:0]++hdr.image.c1[15:8];hdr.image.tc=hdr.image.tc[7:0]++hdr.image.tc[15:8];}\ntable swap_t{actions={crc_swap;}size=1;const default_action=crc_swap();}\n'
 s+='action complete(){hdr.image.setValid();hdr.native.setInvalid();hdr.tcp.seq=m.wire_start;hdr.ip.len=16w95;m.ip_length=16w95;m.tcp_length=16w75;}\ntable complete_t{actions={complete;}size=1;const default_action=complete();}\n'
 s+='apply{forwarding.apply();if(m.parsed==1w1&&!m.ip_error&&m.tcp_sum==16w0xFFEB){replay.apply();if(m.render==1w1){if(hdr.native.data!=m.expected_byte){deny();}else{'
 s+=''.join(f'load_{i}_t.apply();' for i in range(len(words)))
 s+='last_slice_t.apply();'
 if canonical:s+=''.join('crc_'+n+'_t.apply();' for n in ('head','block0','block1','tail'))+'swap_t.apply();'
 s+='complete_t.apply();}}}}\n}\n'
 fieldrefs=','.join('hdr.image.'+name for name in __import__('re').findall(r'bit<\d+>\s+(\w+);',fields))
 s+='''control IgDeparser(packet_out pkt,inout headers_t hdr,in meta_t m,in ingress_intrinsic_metadata_for_deparser_t md){Checksum() ic;Checksum() tc;apply{if(m.render==1w1){hdr.ip.checksum=ic.update({hdr.ip.version,hdr.ip.ihl,hdr.ip.tos,hdr.ip.len,hdr.ip.id,hdr.ip.flags,hdr.ip.frag,hdr.ip.ttl,hdr.ip.proto,hdr.ip.src,hdr.ip.dst});hdr.tcp.checksum=tc.update({hdr.ip.src,hdr.ip.dst,8w0,hdr.ip.proto,m.tcp_length,hdr.tcp.sport,hdr.tcp.dport,hdr.tcp.seq,hdr.tcp.ack,hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.flags,hdr.tcp.window,hdr.tcp.urgent,'''+fieldrefs+'''});}pkt.emit(hdr.eth);pkt.emit(hdr.ip);pkt.emit(hdr.tcp);pkt.emit(hdr.native);pkt.emit(hdr.image);}}
parser EgParser(packet_in pkt,out headers_t hdr,out meta_t m,out egress_intrinsic_metadata_t eg){state start{pkt.extract(eg);transition accept;}}
control Egress(inout headers_t hdr,inout meta_t m,in egress_intrinsic_metadata_t eg,in egress_intrinsic_metadata_from_parser_t p,inout egress_intrinsic_metadata_for_deparser_t md,inout egress_intrinsic_metadata_for_output_port_t port){apply{}}
control EgDeparser(packet_out pkt,inout headers_t hdr,in meta_t m,in egress_intrinsic_metadata_for_deparser_t md){apply{}}
Pipeline(IgParser(),Ingress(),IgDeparser(),EgParser(),Egress(),EgDeparser()) pipe;Switch(pipe) main;
'''
 return s
if __name__=='__main__':
 for canonical,name in ((False,'exact_replay.p4'),(True,'canonical_replay.p4')):Path(__file__).with_name(name).write_text(generate_image(canonical))

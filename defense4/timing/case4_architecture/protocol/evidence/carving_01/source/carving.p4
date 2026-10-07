/* Response57 CRC/profile validator + ordered TCP carve primitive; no transaction association/queue order proof. */
#include <core.p4>
#include <tna.p4>
header eth_h {bit<48> dst;bit<48> src;bit<16> type;}
header ip_h {bit<4> version;bit<4> ihl;bit<8> tos;bit<16> len;bit<16> id;bit<3> flags;bit<13> frag;bit<8> ttl;bit<8> proto;bit<16> checksum;bit<32> src;bit<32> dst;}
header tcp_h {bit<16> sport;bit<16> dport;bit<32> seq;bit<32> ack;bit<4> offset;bit<4> reserved;bit<8> flags;bit<16> window;bit<16> checksum;bit<16> urgent;}
header dl_h{bit<16> magic;bit<8> len;bit<8> ctrl;bit<16> dst;bit<16> src;bit<16> crc;}
header block_h{bit<32> w0;bit<32> w1;bit<32> w2;bit<32> w3;bit<16> crc;}
header tail_h{bit<32> w0;bit<32> w1;bit<8> w2;bit<16> crc;}
struct headers_t{eth_h eth;ip_h ip;tcp_h tcp;dl_h dl;block_h first;block_h second;tail_h tail;}
struct meta_t{bit<1> parsed;bit<1> changed;bool ip_error;bit<16> tcp_sum;bit<16> tcp_length;bit<16> hcrc;bit<16> crc0;bit<16> crc1;bit<16> crct;bit<1> badh;bit<1> bad0;bit<1> bad1;bit<1> badt;bit<1> profile;}
parser IgParser(packet_in pkt,out headers_t hdr,out meta_t m,out ingress_intrinsic_metadata_t ig){Checksum() ic;Checksum() tc;
 state start{pkt.extract(ig);pkt.advance(PORT_METADATA_SIZE);m.parsed=1w0;m.changed=1w0;m.badh=1w0;m.bad0=1w0;m.bad1=1w0;m.badt=1w0;m.profile=1w0;transition eth;}
 state eth{pkt.extract(hdr.eth);transition select(hdr.eth.type){16w0x0800:ip;default:accept;}}
 state ip{pkt.extract(hdr.ip);ic.add(hdr.ip);m.ip_error=ic.verify();tc.subtract({hdr.ip.src,hdr.ip.dst,8w0,hdr.ip.proto,hdr.ip.len});transition select(hdr.ip.version,hdr.ip.ihl,hdr.ip.proto,hdr.ip.len){(4w4,4w5,8w6,16w97):ip_flags;default:accept;}}
 state ip_flags{transition select(hdr.ip.frag,hdr.ip.flags){(13w0,3w0):tcp;(13w0,3w2):tcp;default:accept;}}
 state tcp{pkt.extract(hdr.tcp);tc.subtract(hdr.tcp);transition select(hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.flags,hdr.tcp.urgent){(4w5,4w0,8w0x10,16w0):dl;(4w5,4w0,8w0x18,16w0):dl;default:accept;}}
 state dl{pkt.extract(hdr.dl);tc.subtract(hdr.dl);transition first;}
 state first{pkt.extract(hdr.first);tc.subtract(hdr.first);transition second;}
 state second{pkt.extract(hdr.second);tc.subtract(hdr.second);transition tail;}
 state tail{pkt.extract(hdr.tail);tc.subtract(hdr.tail);m.tcp_sum=tc.get();m.parsed=1w1;transition accept;}
}
control Ingress(inout headers_t hdr,inout meta_t m,in ingress_intrinsic_metadata_t ig,in ingress_intrinsic_metadata_from_parser_t p,inout ingress_intrinsic_metadata_for_deparser_t md,inout ingress_intrinsic_metadata_for_tm_t tm){
 action deny(){md.drop_ctl=3w1;}
 action route(PortId_t port){tm.ucast_egress_port=port;}
 table forwarding{key={ig.ingress_port:exact;}actions={route;deny;}size=4;default_action=deny();}
 action split(bit<16> mgid){tm.mcast_grp_a=mgid;}
 table connection{key={hdr.ip.src:exact;hdr.ip.dst:exact;hdr.tcp.sport:exact;hdr.tcp.dport:exact;}actions={split;NoAction;}size=1;default_action=NoAction();}
 action eligible(){m.profile=1w1;}
 table profile{key={hdr.dl.magic:exact;hdr.dl.len:exact;hdr.dl.ctrl:exact;hdr.first.w0[31:24]:ternary;hdr.first.w0[23:16]:ternary;hdr.first.w0[15:8]:exact;hdr.first.w1[23:0]:exact;hdr.first.w2[31:16]:exact;hdr.second.w1[7:0]:exact;hdr.second.w2:exact;}
 actions={eligible;NoAction;}size=1;const default_action=NoAction();const entries={(16w0x0564,8w46,8w0x44,8w0xC0&&&8w0xC0,8w0xC0&&&8w0xF0,8w0x81,24w0x0C0128,16w0x0100,8w12,32w0x01280100):eligible();}}
 CRCPolynomial<bit<16>>(16w0x3D65,true,false,false,16w0,16w0xFFFF) poly;
Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_head;
action crc_head(){m.hcrc=hash_head.get({hdr.dl.magic,hdr.dl.len,hdr.dl.ctrl,hdr.dl.dst,hdr.dl.src});}
table crc_head_t{actions={crc_head;}size=1;const default_action=crc_head();}
Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_first;
action crc_first(){m.crc0=hash_first.get({hdr.first.w0,hdr.first.w1,hdr.first.w2,hdr.first.w3});}
table crc_first_t{actions={crc_first;}size=1;const default_action=crc_first();}
Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_second;
action crc_second(){m.crc1=hash_second.get({hdr.second.w0,hdr.second.w1,hdr.second.w2,hdr.second.w3});}
table crc_second_t{actions={crc_second;}size=1;const default_action=crc_second();}
Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_tail;
action crc_tail(){m.crct=hash_tail.get({hdr.tail.w0,hdr.tail.w1,hdr.tail.w2});}
table crc_tail_t{actions={crc_tail;}size=1;const default_action=crc_tail();}
apply{forwarding.apply();if(m.parsed==1w1&&!m.ip_error&&m.tcp_sum==16w0xFFEB){profile.apply();if(m.profile==1w1){crc_head_t.apply();crc_first_t.apply();crc_second_t.apply();crc_tail_t.apply();if(hdr.dl.crc!=(m.hcrc[7:0]++m.hcrc[15:8])){m.badh=1w1;}if(hdr.first.crc!=(m.crc0[7:0]++m.crc0[15:8])){m.bad0=1w1;}if(hdr.second.crc!=(m.crc1[7:0]++m.crc1[15:8])){m.bad1=1w1;}if(hdr.tail.crc!=(m.crct[7:0]++m.crct[15:8])){m.badt=1w1;}if(m.badh==1w0&&m.bad0==1w0&&m.bad1==1w0&&m.badt==1w0){connection.apply();}}}}
}
control IgDeparser(packet_out pkt,inout headers_t hdr,in meta_t m,in ingress_intrinsic_metadata_for_deparser_t md){apply{pkt.emit(hdr.eth);pkt.emit(hdr.ip);pkt.emit(hdr.tcp);pkt.emit(hdr.dl);pkt.emit(hdr.first);pkt.emit(hdr.second);pkt.emit(hdr.tail);}}
parser EgParser(packet_in pkt,out headers_t hdr,out meta_t m,out egress_intrinsic_metadata_t eg){state start{pkt.extract(eg);m.changed=1w0;transition eth;}state eth{pkt.extract(hdr.eth);transition select(hdr.eth.type){16w0x0800:ip;default:accept;}}state ip{pkt.extract(hdr.ip);transition select(hdr.ip.version,hdr.ip.ihl,hdr.ip.proto,hdr.ip.len){(4w4,4w5,8w6,16w97):tcp;default:accept;}}state tcp{pkt.extract(hdr.tcp);transition dl;}state dl{pkt.extract(hdr.dl);transition first;}state first{pkt.extract(hdr.first);transition second;}state second{pkt.extract(hdr.second);transition tail;}state tail{pkt.extract(hdr.tail);transition accept;}}
control Egress(inout headers_t hdr,inout meta_t m,in egress_intrinsic_metadata_t eg,in egress_intrinsic_metadata_from_parser_t p,inout egress_intrinsic_metadata_for_deparser_t md,inout egress_intrinsic_metadata_for_output_port_t port){
 action render_first(){hdr.second.setInvalid();hdr.tail.setInvalid();hdr.ip.len=16w68;hdr.tcp.flags=hdr.tcp.flags&8w0xF7;m.changed=1w1;}
 action render_second(){hdr.dl.setInvalid();hdr.first.setInvalid();hdr.ip.len=16w69;hdr.tcp.seq=hdr.tcp.seq+32w28;m.changed=1w1;}
 table rendering{key={eg.egress_rid:exact;}actions={render_first;render_second;NoAction;}size=2;const default_action=NoAction();const entries={16w1:render_first();16w2:render_second();}}
 apply{if(hdr.tail.isValid()){rendering.apply();}m.tcp_length=hdr.ip.len-16w20;}
}
control EgDeparser(packet_out pkt,inout headers_t hdr,in meta_t m,in egress_intrinsic_metadata_for_deparser_t md){Checksum() ic;Checksum() tc;apply{if(m.changed==1w1){hdr.ip.checksum=ic.update({hdr.ip.version,hdr.ip.ihl,hdr.ip.tos,hdr.ip.len,hdr.ip.id,hdr.ip.flags,hdr.ip.frag,hdr.ip.ttl,hdr.ip.proto,hdr.ip.src,hdr.ip.dst});hdr.tcp.checksum=tc.update({hdr.ip.src,hdr.ip.dst,8w0,hdr.ip.proto,m.tcp_length,hdr.tcp.sport,hdr.tcp.dport,hdr.tcp.seq,hdr.tcp.ack,hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.flags,hdr.tcp.window,hdr.tcp.urgent,hdr.dl.magic,hdr.dl.len,hdr.dl.ctrl,hdr.dl.dst,hdr.dl.src,hdr.dl.crc,hdr.first.w0,hdr.first.w1,hdr.first.w2,hdr.first.w3,hdr.first.crc,hdr.second.w0,hdr.second.w1,hdr.second.w2,hdr.second.w3,hdr.second.crc,hdr.tail.w0,hdr.tail.w1,hdr.tail.w2,hdr.tail.crc});}pkt.emit(hdr.eth);pkt.emit(hdr.ip);pkt.emit(hdr.tcp);pkt.emit(hdr.dl);pkt.emit(hdr.first);pkt.emit(hdr.second);pkt.emit(hdr.tail);}}
Pipeline(IgParser(),Ingress(),IgDeparser(),EgParser(),Egress(),EgDeparser()) pipe;Switch(pipe) main;

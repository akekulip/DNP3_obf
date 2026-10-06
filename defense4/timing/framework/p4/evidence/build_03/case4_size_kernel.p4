/* Case4 fixed-layout TNA size compile probe. SOFTWARE/OFFLINE ONLY.
 * No deployment authority. Admission defaults OFF. Transport/resegmentation
 * completion is a separate gate; this wire kernel alone is not a safe proxy.
 * Custom DNP3 CRC idiom recovered from historical padnorm kernel at 9ffa9102.
 * The configured index below exists only in the isolated software gate.
 */
#include <core.p4>
#include <tna.p4>
const bit<16> RRC_49 = 16w49;
const bit<16> RRC_57 = 16w57;
header eth_h { bit<48> dst; bit<48> src; bit<16> type; }
header ip_h { bit<4> version; bit<4> ihl; bit<8> tos; bit<16> total_len;
 bit<16> id; bit<3> flags; bit<13> frag; bit<8> ttl; bit<8> proto;
 bit<16> checksum; bit<32> src; bit<32> dst; }
header tcp_h { bit<16> sport; bit<16> dport; bit<32> seq; bit<32> ack;
 bit<4> offset; bit<4> reserved; bit<8> flags; bit<16> win; bit<16> checksum; bit<16> urgent; }
header dl_h { bit<16> magic; bit<8> len; bit<8> ctrl; bit<16> dst; bit<16> src; bit<16> crc; }
header req0_h { bit<8> tp; bit<8> app; bit<8> func; bit<8> group;
 bit<8> variation; bit<8> qualifier; bit<16> count; bit<16> index;
 bit<8> code; bit<8> crob_count; bit<32> on; bit<16> crc; }
header tail_h { bit<32> off; bit<8> status; bit<16> crc; }
header out1_h { bit<32> off; bit<8> status; bit<8> group; bit<8> variation;
 bit<8> qualifier; bit<16> count; bit<16> index; bit<8> code;
 bit<8> crob_count; bit<16> on_first; bit<16> crc; }
header out2_h { bit<16> on_last; bit<32> off; bit<8> status; bit<16> crc; }
header block_h { bit<128> data; bit<16> crc; }
header last49_h { bit<8> data; bit<16> crc; }
header last57_h { bit<72> data; bit<16> crc; }
struct headers_t { eth_h eth; ip_h ip; tcp_h tcp; dl_h dl;
 req0_h req0; tail_h tail; out1_h out1; out2_h out2;
 block_h block0; block_h block1; last49_h last49; last57_h last57; }
struct ig_meta_t { bit<8> profile; bit<8> crc_ok; bit<16> payload_len;
 bit<16> hcrc; bit<16> bcrc; bit<16> tcrc; }
struct eg_meta_t { bit<1> changed; bit<16> tcp_len; bit<8> native;
 bit<8> enable; bit<8> direction; bit<16> decoy_index; bit<8> decoy_code;
 bit<8> decoy_count; bit<32> decoy_on; bit<32> decoy_off;
 bit<16> hcrc; bit<16> bcrc; bit<16> tcrc; bit<16> payload_len; }

parser IgParser(packet_in pkt, out headers_t hdr, out ig_meta_t m,
 out ingress_intrinsic_metadata_t ig) {
 state start { pkt.extract(ig); pkt.advance(PORT_METADATA_SIZE);
  m.profile=8w0; m.crc_ok=8w0;m.payload_len=16w0;m.hcrc=16w0;m.bcrc=16w0;m.tcrc=16w0; transition eth; }
 state eth { pkt.extract(hdr.eth); transition select(hdr.eth.type) {16w0x0800:ip;default:accept;} }
 state ip { pkt.extract(hdr.ip); transition select(hdr.ip.version,hdr.ip.ihl,hdr.ip.proto,hdr.ip.frag,hdr.ip.flags) {
  (4w4,4w5,8w6,13w0,3w0):tcp; (4w4,4w5,8w6,13w0,3w2):tcp;default:accept;} }
 state tcp { pkt.extract(hdr.tcp);
  transition select(hdr.tcp.offset,hdr.ip.total_len) {(4w5,16w89):dl49;(4w5,16w97):dl57;default:accept;} }
 state dl49 {pkt.extract(hdr.dl);m.profile=8w49;transition b0;}
 state dl57 {pkt.extract(hdr.dl);m.profile=8w57;transition b0;}
 state b0 {pkt.extract(hdr.block0);transition b1;}
 state b1 {pkt.extract(hdr.block1);transition select(hdr.ip.total_len) {16w89:last49;default:last57;} }
 state last49 {pkt.extract(hdr.last49);transition accept;}
 state last57 {pkt.extract(hdr.last57);transition accept;}
}
control Ingress(inout headers_t hdr,inout ig_meta_t m,
 in ingress_intrinsic_metadata_t ig,in ingress_intrinsic_metadata_from_parser_t parser_md,
 inout ingress_intrinsic_metadata_for_deparser_t deparser_md,inout ingress_intrinsic_metadata_for_tm_t tm) {
 CRCPolynomial<bit<16>>(16w0x3D65,true,false,false,16w0,16w0xFFFF) poly;
 Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) h_header;
 Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) h_block0;
 Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) h_block1;
 Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) h_tail49;
 Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) h_tail57;
 action forward(PortId_t port) {tm.ucast_egress_port=port;}
 action reject() {deparser_md.drop_ctl=3w1;}
 table forwarding {key={ig.ingress_port:exact;}actions={forward;reject;}size=4;default_action=reject();}
 action split(bit<16> mgid) {tm.mcast_grp_a=mgid;}
 table shape {key={hdr.ip.src:exact;hdr.ip.dst:exact;hdr.tcp.sport:exact;hdr.tcp.dport:exact;m.profile:exact;}
 actions={split;NoAction;}size=4;default_action=NoAction();}
 apply {forwarding.apply();
  if(m.profile!=8w0) {
   m.hcrc=h_header.get({hdr.dl.magic,hdr.dl.len,hdr.dl.ctrl,hdr.dl.dst,hdr.dl.src});
   m.bcrc=h_block0.get({hdr.block0.data});
   m.tcrc=h_block1.get({hdr.block1.data});
   m.crc_ok=8w1;
   if(hdr.dl.crc!=(m.hcrc[7:0]++m.hcrc[15:8])) {m.crc_ok=8w0;}
   if(hdr.block0.crc!=(m.bcrc[7:0]++m.bcrc[15:8])) {m.crc_ok=8w0;}
   if(hdr.block1.crc!=(m.tcrc[7:0]++m.tcrc[15:8])) {m.crc_ok=8w0;}
   if(m.profile==8w49) {m.tcrc=h_tail49.get({hdr.last49.data});
    if(hdr.last49.crc!=(m.tcrc[7:0]++m.tcrc[15:8])) {m.crc_ok=8w0;}
    if(hdr.dl.len!=8w38) {m.crc_ok=8w0;}}
   else {m.tcrc=h_tail57.get({hdr.last57.data});
    if(hdr.last57.crc!=(m.tcrc[7:0]++m.tcrc[15:8])) {m.crc_ok=8w0;}
    if(hdr.dl.len!=8w46) {m.crc_ok=8w0;}}
   if(hdr.dl.magic!=16w0x0564) {m.crc_ok=8w0;}
   if((hdr.tcp.flags&8w0x16)!=8w0x10) {m.crc_ok=8w0;}
   if(m.crc_ok==8w1) {shape.apply();}
  }
 }
}
control IgDeparser(packet_out pkt,inout headers_t hdr,in ig_meta_t m,
 in ingress_intrinsic_metadata_for_deparser_t md) {
 apply {pkt.emit(hdr.eth);pkt.emit(hdr.ip);pkt.emit(hdr.tcp);pkt.emit(hdr.dl);
 pkt.emit(hdr.block0);pkt.emit(hdr.block1);pkt.emit(hdr.last49);pkt.emit(hdr.last57);}
}

parser EgParser(packet_in pkt,out headers_t hdr,out eg_meta_t m,out egress_intrinsic_metadata_t eg) {
 state start {pkt.extract(eg);m.changed=1w0;m.native=8w0;m.enable=8w0;m.direction=8w0;m.tcp_len=16w0;
 m.decoy_index=16w0;m.decoy_code=8w0;m.decoy_count=8w0;m.decoy_on=32w0;m.decoy_off=32w0;
 m.hcrc=16w0;m.bcrc=16w0;m.tcrc=16w0;m.payload_len=16w0;transition eth;}
 state eth {pkt.extract(hdr.eth);transition select(hdr.eth.type) {16w0x0800:ip;default:accept;}}
 state ip {pkt.extract(hdr.ip);transition select(hdr.ip.ihl,hdr.ip.proto,hdr.ip.frag,hdr.ip.flags) {
 (4w5,8w6,13w0,3w0):tcp;(4w5,8w6,13w0,3w2):tcp;default:accept;}}
 state tcp {pkt.extract(hdr.tcp);
  transition select(hdr.tcp.offset,hdr.ip.total_len) {(4w5,16w75):native_dl;(4w5,16w89):response49;(4w5,16w97):response57;default:accept;}}
 state native_dl {pkt.extract(hdr.dl);transition native0;}
 state native0 {pkt.extract(hdr.req0);transition native_tail;}
 state native_tail {pkt.extract(hdr.tail);m.native=8w1;transition accept;}
 state response49 {m.payload_len=RRC_49;transition response_dl;}
 state response57 {m.payload_len=RRC_57;transition response_dl;}
 state response_dl {pkt.extract(hdr.dl);transition response0;}
 state response0 {pkt.extract(hdr.block0);transition response1;}
 state response1 {pkt.extract(hdr.block1);transition select(hdr.ip.total_len) {16w89:last49;default:last57;}}
 state last49 {pkt.extract(hdr.last49);transition accept;}
 state last57 {pkt.extract(hdr.last57);transition accept;}
}
control Egress(inout headers_t hdr,inout eg_meta_t m,in egress_intrinsic_metadata_t eg,
 in egress_intrinsic_metadata_from_parser_t parser_md,inout egress_intrinsic_metadata_for_deparser_t md,
 inout egress_intrinsic_metadata_for_output_port_t port_md) {
 CRCPolynomial<bit<16>>(16w0x3D65,true,false,false,16w0,16w0xFFFF) poly;
 Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) h_native_header;
 Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) h_native0;
 Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) h_native_tail;
 Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) h_new_header;
 Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) h_new1;
 Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) h_new2;
 action configured_decoy(bit<16> index_wire,bit<8> code,bit<8> count,bit<32> on_wire,bit<32> off_wire) {
  m.enable=8w1;m.decoy_index=index_wire;m.decoy_code=code;m.decoy_count=count;m.decoy_on=on_wire;m.decoy_off=off_wire;}
 table insertion_profile {key={hdr.ip.src:exact;hdr.ip.dst:exact;hdr.tcp.sport:exact;hdr.tcp.dport:exact;}
  actions={configured_decoy;NoAction;}size=1;default_action=NoAction();}
 apply {
  insertion_profile.apply();
  if(m.native==8w1&&m.enable==8w1) {
   m.hcrc=h_native_header.get({hdr.dl.magic,hdr.dl.len,hdr.dl.ctrl,hdr.dl.dst,hdr.dl.src});
   m.bcrc=h_native0.get({hdr.req0.tp,hdr.req0.app,hdr.req0.func,hdr.req0.group,hdr.req0.variation,
    hdr.req0.qualifier,hdr.req0.count,hdr.req0.index,hdr.req0.code,hdr.req0.crob_count,hdr.req0.on});
   m.tcrc=h_native_tail.get({hdr.tail.off,hdr.tail.status});
   if(hdr.dl.crc!=(m.hcrc[7:0]++m.hcrc[15:8])) {m.enable=8w0;}
   if(hdr.req0.crc!=(m.bcrc[7:0]++m.bcrc[15:8])) {m.enable=8w0;}
   if(hdr.tail.crc!=(m.tcrc[7:0]++m.tcrc[15:8])) {m.enable=8w0;}
   if(hdr.dl.magic!=16w0x0564||hdr.dl.len!=8w26) {m.enable=8w0;}
   if(hdr.req0.group!=8w12||hdr.req0.variation!=8w1||hdr.req0.qualifier!=8w0x28||hdr.req0.count!=16w0x0100) {m.enable=8w0;}
   if((hdr.req0.tp&8w0xC0)!=8w0xC0||(hdr.req0.app&8w0xF0)!=8w0xC0||hdr.tail.status!=8w0) {m.enable=8w0;}
   if(hdr.req0.func!=8w3&&hdr.req0.func!=8w4) {m.enable=8w0;}
   if(hdr.req0.index==m.decoy_index) {m.enable=8w0;}
   if((hdr.tcp.flags&8w0x37)!=8w0x10) {m.enable=8w0;}
   if(m.enable==8w1) {
    hdr.out1.setValid();hdr.out2.setValid();
    hdr.out1.off=hdr.tail.off;hdr.out1.status=hdr.tail.status;
    hdr.out1.group=8w12;hdr.out1.variation=8w1;hdr.out1.qualifier=8w0x28;
    hdr.out1.count=16w0x0100;hdr.out1.index=m.decoy_index;hdr.out1.code=m.decoy_code;
    hdr.out1.crob_count=m.decoy_count;hdr.out1.on_first=m.decoy_on[31:16];
    hdr.out2.on_last=m.decoy_on[15:0];hdr.out2.off=m.decoy_off;hdr.out2.status=8w0;
    hdr.tail.setInvalid();hdr.dl.len=8w44;hdr.ip.total_len=hdr.ip.total_len + 16w20;
    m.hcrc=h_new_header.get({hdr.dl.magic,hdr.dl.len,hdr.dl.ctrl,hdr.dl.dst,hdr.dl.src});
    hdr.dl.crc=m.hcrc[7:0]++m.hcrc[15:8];
    m.bcrc=h_new1.get({hdr.out1.off,hdr.out1.status,hdr.out1.group,hdr.out1.variation,hdr.out1.qualifier,
     hdr.out1.count,hdr.out1.index,hdr.out1.code,hdr.out1.crob_count,hdr.out1.on_first});
    hdr.out1.crc=m.bcrc[7:0]++m.bcrc[15:8];
    m.tcrc=h_new2.get({hdr.out2.on_last,hdr.out2.off,hdr.out2.status});
    hdr.out2.crc=m.tcrc[7:0]++m.tcrc[15:8];m.changed=1w1;
   }
  }
  if(eg.egress_rid==16w1) {
   hdr.block1.setInvalid();hdr.last49.setInvalid();hdr.last57.setInvalid();
   hdr.ip.total_len=16w68;hdr.tcp.flags=hdr.tcp.flags&8w0xF6;m.changed=1w1;
  } else if(eg.egress_rid==16w2) {
   hdr.dl.setInvalid();hdr.block0.setInvalid();hdr.ip.total_len=hdr.ip.total_len-16w28;
   hdr.tcp.seq=hdr.tcp.seq + 32w28;m.changed=1w1;
  }
  m.tcp_len=hdr.ip.total_len-16w20;
 }
}
control EgDeparser(packet_out pkt,inout headers_t hdr,in eg_meta_t m,in egress_intrinsic_metadata_for_deparser_t md) {
 Checksum() ip_checksum;Checksum() tcp_checksum;
 apply {
  if(m.changed==1w1) {
   hdr.ip.checksum=ip_checksum.update({hdr.ip.version,hdr.ip.ihl,hdr.ip.tos,hdr.ip.total_len,
    hdr.ip.id,hdr.ip.flags,hdr.ip.frag,hdr.ip.ttl,hdr.ip.proto,hdr.ip.src,hdr.ip.dst});
   hdr.tcp.checksum=tcp_checksum.update({hdr.ip.src,hdr.ip.dst,8w0,hdr.ip.proto,m.tcp_len,
    hdr.tcp.sport,hdr.tcp.dport,hdr.tcp.seq,hdr.tcp.ack,hdr.tcp.offset,hdr.tcp.reserved,
    hdr.tcp.flags,hdr.tcp.win,hdr.tcp.urgent,hdr.dl.magic,hdr.dl.len,hdr.dl.ctrl,hdr.dl.dst,hdr.dl.src,hdr.dl.crc,
    hdr.req0.tp,hdr.req0.app,hdr.req0.func,hdr.req0.group,hdr.req0.variation,hdr.req0.qualifier,
    hdr.req0.count,hdr.req0.index,hdr.req0.code,hdr.req0.crob_count,hdr.req0.on,hdr.req0.crc,
    hdr.tail.off,hdr.tail.status,hdr.tail.crc,
    hdr.out1.off,hdr.out1.status,hdr.out1.group,hdr.out1.variation,hdr.out1.qualifier,hdr.out1.count,
    hdr.out1.index,hdr.out1.code,hdr.out1.crob_count,hdr.out1.on_first,hdr.out1.crc,
    hdr.out2.on_last,hdr.out2.off,hdr.out2.status,hdr.out2.crc,
    hdr.block0.data,hdr.block0.crc,hdr.block1.data,hdr.block1.crc,hdr.last49.data,hdr.last49.crc,hdr.last57.data,hdr.last57.crc});
  }
  pkt.emit(hdr.eth);pkt.emit(hdr.ip);pkt.emit(hdr.tcp);pkt.emit(hdr.dl);pkt.emit(hdr.req0);pkt.emit(hdr.tail);
  pkt.emit(hdr.out1);pkt.emit(hdr.out2);pkt.emit(hdr.block0);pkt.emit(hdr.block1);pkt.emit(hdr.last49);pkt.emit(hdr.last57);
 }
}
Pipeline(IgParser(),Ingress(),IgDeparser(),EgParser(),Egress(),EgDeparser()) pipe;
Switch(pipe) main;

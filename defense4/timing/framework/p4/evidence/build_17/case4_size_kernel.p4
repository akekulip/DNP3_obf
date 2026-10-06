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
struct ig_meta_t {bit<16> tcp_sum; bool ip_valid; bool tcp_valid; bit<8> profile; bit<8> crc_ok; bit<16> payload_len;
 bit<16> hcrc; bit<16> bcrc; bit<16> tcrc; }
struct eg_meta_t {bit<8> ack_mode;bit<16> delta_left16;bit<16> delta_right16;bit<16> window16;bit<32> win32;bit<32> reset_mask;bit<16> tcp_sum;bit<32> base_old;bit<32> base;bit<32> op_old;bit<32> op_base;bit<32> cached_on;bit<32> cached_off;bit<32> cached_identity;bit<32> cached_addresses;bit<32> cached_tag;bit<32> cached_op_tag;bit<32> identity;bit<32> addresses;bit<32> tag;bit<32> seq_off;bit<32> seq_op_off;bit<32> ack_off;bit<32> ack_op_off;bit<32> right_ack;bit<32> right_off;bit<32> right_op_off;bit<32> seq_delta;bit<32> ack_delta;bit<32> right_delta;bit<32> window_before;bit<32> window_after;bit<8> fresh_select;bit<8> select_candidate;bit<8> op_candidate;bit<8> fresh_operate;bit<8> pad_committed;bit<8> active;bit<8> has_operate;bit<8> matches_objects;bit<8> reset;bit<8> allow;bit<8> bad0;bit<8> bad1;bit<8> bad2;bit<8> bad3;bit<8> bad4;bit<8> bad5;bit<8> bad6;bit<8> bad7;bit<8> bad8; bool ip_valid; bool tcp_valid; bit<1> changed; bit<16> tcp_len; bit<8> native;
 bit<8> enable; bit<8> direction; bit<16> decoy_index; bit<8> decoy_code;
 bit<8> decoy_count; bit<32> decoy_on; bit<32> decoy_off;
 bit<16> hcrc; bit<16> bcrc; bit<16> tcrc; bit<16> payload_len; }

parser IgParser(packet_in pkt, out headers_t hdr, out ig_meta_t m,
 out ingress_intrinsic_metadata_t ig) {
 Checksum() ip_check;Checksum() tcp_check;
 state start { pkt.extract(ig); pkt.advance(PORT_METADATA_SIZE);
  m.tcp_sum=16w0;m.ip_valid=false;m.tcp_valid=false;m.profile=8w0; m.crc_ok=8w0;m.payload_len=16w0;m.hcrc=16w0;m.bcrc=16w0;m.tcrc=16w0; transition eth; }
 state eth { pkt.extract(hdr.eth); transition select(hdr.eth.type) {16w0x0800:ip;default:accept;} }
 state ip { pkt.extract(hdr.ip);ip_check.add(hdr.ip);m.ip_valid=ip_check.verify();tcp_check.add({hdr.ip.src,hdr.ip.dst,8w0,hdr.ip.proto,hdr.ip.total_len});tcp_check.subtract({10w0,hdr.ip.ihl,2w0}); transition select(hdr.ip.version,hdr.ip.ihl,hdr.ip.proto,hdr.ip.frag,hdr.ip.flags) {
  (4w4,4w5,8w6,13w0,3w0):tcp; (4w4,4w5,8w6,13w0,3w2):tcp;default:accept;} }
 state tcp { pkt.extract(hdr.tcp);tcp_check.add(hdr.tcp);
  transition select(hdr.tcp.offset,hdr.ip.total_len) {(4w5,16w89):dl49;(4w5,16w97):dl57;default:accept;} }
 state dl49 {pkt.extract(hdr.dl);tcp_check.add(hdr.dl);m.profile=8w49;transition b0;}
 state dl57 {pkt.extract(hdr.dl);tcp_check.add(hdr.dl);m.profile=8w57;transition b0;}
 state b0 {pkt.extract(hdr.block0);tcp_check.add(hdr.block0);transition b1;}
 state b1 {pkt.extract(hdr.block1);tcp_check.add(hdr.block1);transition select(hdr.ip.total_len) {16w89:last49;default:last57;} }
 state last49 {pkt.extract(hdr.last49);tcp_check.add(hdr.last49);m.tcp_valid=tcp_check.verify();transition accept;}
 state last57 {pkt.extract(hdr.last57);tcp_check.add(hdr.last57);m.tcp_valid=tcp_check.verify();transition accept;}
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
 action crc_step_0() {m.hcrc=h_header.get({hdr.dl.magic,hdr.dl.len,hdr.dl.ctrl,hdr.dl.dst,hdr.dl.src});}
 table t_crc_step_0 {actions={crc_step_0;}size=1;const default_action=crc_step_0();}
 action crc_step_1() {m.bcrc=h_block0.get({hdr.block0.data});}
 table t_crc_step_1 {actions={crc_step_1;}size=1;const default_action=crc_step_1();}
 action crc_step_2() {m.tcrc=h_block1.get({hdr.block1.data});}
 table t_crc_step_2 {actions={crc_step_2;}size=1;const default_action=crc_step_2();}
 action crc_step_3() {m.tcrc=h_tail49.get({hdr.last49.data});}
 table t_crc_step_3 {actions={crc_step_3;}size=1;const default_action=crc_step_3();}
 action crc_step_4() {m.tcrc=h_tail57.get({hdr.last57.data});}
 table t_crc_step_4 {actions={crc_step_4;}size=1;const default_action=crc_step_4();}
 apply {forwarding.apply();
  // Pseudo length uses extracted IPv4 total_len; valid packet sum is +20.
  
  if(m.profile!=8w0) {
   t_crc_step_0.apply();
   t_crc_step_1.apply();
   t_crc_step_2.apply();
   m.crc_ok=8w1;
   if(hdr.dl.crc!=(m.hcrc[7:0]++m.hcrc[15:8])) {m.crc_ok=8w0;}
   if(hdr.block0.crc!=(m.bcrc[7:0]++m.bcrc[15:8])) {m.crc_ok=8w0;}
   if(hdr.block1.crc!=(m.tcrc[7:0]++m.tcrc[15:8])) {m.crc_ok=8w0;}
   if(m.profile==8w49) {t_crc_step_3.apply();
    if(hdr.last49.crc!=(m.tcrc[7:0]++m.tcrc[15:8])) {m.crc_ok=8w0;}
    if(hdr.dl.len!=8w38) {m.crc_ok=8w0;}}
   else {t_crc_step_4.apply();
    if(hdr.last57.crc!=(m.tcrc[7:0]++m.tcrc[15:8])) {m.crc_ok=8w0;}
    if(hdr.dl.len!=8w46) {m.crc_ok=8w0;}}
   if(hdr.dl.magic!=16w0x0564) {m.crc_ok=8w0;}
   if((hdr.tcp.flags&8w0x16)!=8w0x10) {m.crc_ok=8w0;}
   if(m.crc_ok==8w1&&m.ip_valid&&m.tcp_valid) {shape.apply();}
  }
 }
}
control IgDeparser(packet_out pkt,inout headers_t hdr,in ig_meta_t m,
 in ingress_intrinsic_metadata_for_deparser_t md) {
 apply {pkt.emit(hdr.eth);pkt.emit(hdr.ip);pkt.emit(hdr.tcp);pkt.emit(hdr.dl);
 pkt.emit(hdr.block0);pkt.emit(hdr.block1);pkt.emit(hdr.last49);pkt.emit(hdr.last57);}
}

parser EgParser(packet_in pkt,out headers_t hdr,out eg_meta_t m,out egress_intrinsic_metadata_t eg) {
 Checksum() ip_check;Checksum() tcp_check;
 state start {pkt.extract(eg);m.ack_mode=8w0;m.delta_left16=16w0;m.delta_right16=16w0;m.window16=16w0;m.win32=32w0;m.reset_mask=32w0;m.base_old=32w0;m.base=32w0;m.op_old=32w0;m.op_base=32w0;m.cached_on=32w0;m.cached_off=32w0;m.cached_identity=32w0;m.cached_addresses=32w0;m.cached_tag=32w0;m.cached_op_tag=32w0;m.identity=32w0;m.addresses=32w0;m.tag=32w0;m.seq_off=32w0;m.seq_op_off=32w0;m.ack_off=32w0;m.ack_op_off=32w0;m.right_ack=32w0;m.right_off=32w0;m.right_op_off=32w0;m.seq_delta=32w0;m.ack_delta=32w0;m.right_delta=32w0;m.window_before=32w0;m.window_after=32w0;m.fresh_select=8w0;m.select_candidate=8w0;m.op_candidate=8w0;m.fresh_operate=8w0;m.pad_committed=8w0;m.active=8w0;m.has_operate=8w0;m.matches_objects=8w0;m.reset=8w0;m.allow=8w0;m.bad0=8w0;m.bad1=8w0;m.bad2=8w0;m.bad3=8w0;m.bad4=8w0;m.bad5=8w0;m.bad6=8w0;m.bad7=8w0;m.bad8=8w0;m.tcp_sum=16w0;m.ip_valid=false;m.tcp_valid=false;m.changed=1w0;m.native=8w0;m.enable=8w0;m.direction=8w0;m.tcp_len=16w0;
 m.decoy_index=16w0;m.decoy_code=8w0;m.decoy_count=8w0;m.decoy_on=32w0;m.decoy_off=32w0;
 m.hcrc=16w0;m.bcrc=16w0;m.tcrc=16w0;m.payload_len=16w0;transition eth;}
 state eth {pkt.extract(hdr.eth);transition select(hdr.eth.type) {16w0x0800:ip;default:accept;}}
 state ip {pkt.extract(hdr.ip);ip_check.add(hdr.ip);m.ip_valid=ip_check.verify();tcp_check.add({hdr.ip.src,hdr.ip.dst,8w0,hdr.ip.proto,hdr.ip.total_len});tcp_check.subtract({10w0,hdr.ip.ihl,2w0});transition select(hdr.ip.ihl,hdr.ip.proto,hdr.ip.frag,hdr.ip.flags) {
 (4w5,8w6,13w0,3w0):tcp;(4w5,8w6,13w0,3w2):tcp;default:accept;}}
 state tcp {pkt.extract(hdr.tcp);tcp_check.add(hdr.tcp);
  transition select(hdr.tcp.offset,hdr.ip.total_len) {(4w5,16w40):pure_ack;(4w5,16w75):native_dl;(4w5,16w89):response49;(4w5,16w97):response57;default:accept;}}
 state pure_ack {m.tcp_valid=tcp_check.verify();transition accept;}
 state native_dl {pkt.extract(hdr.dl);tcp_check.add(hdr.dl);transition native0;}
 state native0 {pkt.extract(hdr.req0);tcp_check.add(hdr.req0);transition native_tail;}
 state native_tail {pkt.extract(hdr.tail);tcp_check.add(hdr.tail);m.tcp_valid=tcp_check.verify();m.native=8w1;transition accept;}
 state response49 {m.payload_len=RRC_49;transition response_dl;}
 state response57 {m.payload_len=RRC_57;transition response_dl;}
 state response_dl {pkt.extract(hdr.dl);transition response0;}
 state response0 {pkt.extract(hdr.block0);transition response1;}
 state response1 {pkt.extract(hdr.block1);transition select(hdr.ip.total_len) {16w89:last49;default:last57;}}
 state last49 {pkt.extract(hdr.last49);transition accept;}
 state last57 {pkt.extract(hdr.last57);transition accept;}
}
@pa_container_size("egress", "m.seq_delta", 32)
@pa_container_size("egress", "m.ack_delta", 32)
@pa_container_size("egress", "m.right_delta", 32)
@pa_container_size("egress", "m.window_before", 32)
@pa_container_size("egress", "m.window_after", 32)
@pa_container_size("egress", "m.base_old", 32)
@pa_container_size("egress", "m.op_old", 32)
@pa_container_size("egress", "m.base", 32)
@pa_container_size("egress", "m.op_base", 32)
@pa_container_size("egress", "m.seq_off", 32)
@pa_container_size("egress", "m.seq_op_off", 32)
@pa_container_size("egress", "m.ack_off", 32)
@pa_container_size("egress", "m.ack_op_off", 32)
@pa_container_size("egress", "m.right_ack", 32)
@pa_container_size("egress", "m.right_off", 32)
@pa_container_size("egress", "m.right_op_off", 32)
@pa_container_size("egress", "m.win32", 32)
@pa_container_size("egress", "hdr.tcp.seq", 32)
@pa_container_size("egress", "hdr.tcp.ack", 32)
@pa_atomic("egress", "m.seq_delta")
@pa_atomic("egress", "m.ack_delta")
@pa_atomic("egress", "m.right_delta")
@pa_atomic("egress", "m.window_before")
@pa_atomic("egress", "m.window_after")
@pa_atomic("egress", "m.base_old")
@pa_atomic("egress", "m.op_old")
@pa_atomic("egress", "m.base")
@pa_atomic("egress", "m.op_base")
@pa_atomic("egress", "m.seq_off")
@pa_atomic("egress", "m.seq_op_off")
@pa_atomic("egress", "m.ack_off")
@pa_atomic("egress", "m.ack_op_off")
@pa_atomic("egress", "m.right_ack")
@pa_atomic("egress", "m.right_off")
@pa_atomic("egress", "m.right_op_off")
@pa_atomic("egress", "m.win32")
@pa_atomic("egress", "hdr.tcp.seq")
@pa_atomic("egress", "hdr.tcp.ack")
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
  m.enable=8w1;m.direction=8w1;m.decoy_index=index_wire;m.decoy_code=code;m.decoy_count=count;m.decoy_on=on_wire;m.decoy_off=off_wire;}
 action configured_reverse() {m.direction=8w2;}
 table insertion_profile {key={hdr.ip.src:exact;hdr.ip.dst:exact;hdr.tcp.sport:exact;hdr.tcp.dport:exact;}
  actions={configured_decoy;configured_reverse;NoAction;}size=2;default_action=NoAction();}
 action crc_step_0() {m.hcrc=h_native_header.get({hdr.dl.magic,hdr.dl.len,hdr.dl.ctrl,hdr.dl.dst,hdr.dl.src});}
 table t_crc_step_0 {actions={crc_step_0;}size=1;const default_action=crc_step_0();}
 action crc_step_1() {m.bcrc=h_native0.get({hdr.req0.tp,hdr.req0.app,hdr.req0.func,hdr.req0.group,hdr.req0.variation,
    hdr.req0.qualifier,hdr.req0.count,hdr.req0.index,hdr.req0.code,hdr.req0.crob_count,hdr.req0.on});}
 table t_crc_step_1 {actions={crc_step_1;}size=1;const default_action=crc_step_1();}
 action crc_step_2() {m.tcrc=h_native_tail.get({hdr.tail.off,hdr.tail.status});}
 table t_crc_step_2 {actions={crc_step_2;}size=1;const default_action=crc_step_2();}
 action crc_step_3() {m.hcrc=h_new_header.get({hdr.dl.magic,hdr.dl.len,hdr.dl.ctrl,hdr.dl.dst,hdr.dl.src});}
 table t_crc_step_3 {actions={crc_step_3;}size=1;const default_action=crc_step_3();}
 action crc_step_4() {m.bcrc=h_new1.get({hdr.out1.off,hdr.out1.status,hdr.out1.group,hdr.out1.variation,hdr.out1.qualifier,
     hdr.out1.count,hdr.out1.index,hdr.out1.code,hdr.out1.crob_count,hdr.out1.on_first});}
 table t_crc_step_4 {actions={crc_step_4;}size=1;const default_action=crc_step_4();}
 action crc_step_5() {m.tcrc=h_new2.get({hdr.out2.on_last,hdr.out2.off,hdr.out2.status});}
 table t_crc_step_5 {actions={crc_step_5;}size=1;const default_action=crc_step_5();}
 action allow_padding() {m.allow=8w1;}
 table eligible_native {key={m.bad0:exact;m.bad1:exact;m.bad2:exact;m.bad3:exact;m.bad4:exact;m.bad5:exact;m.bad6:exact;m.bad7:exact;m.bad8:exact;}actions={allow_padding;NoAction;}size=1;const default_action=NoAction();
 const entries={(8w0,8w0,8w0,8w0,8w0,8w0,8w0,8w0,8w0):allow_padding();}}

 // Singleton owner; all cells MUST be explicitly seeded to EMPTY before admission.
 // No tuple reuse/FIN/SACK/resegmentation guarantee. Never enable on hardware.
 Register<bit<32>,bit<8>>(1) first_base;
 Register<bit<32>,bit<8>>(1) second_base;
 Register<bit<32>,bit<8>>(1) selected_on;
 Register<bit<32>,bit<8>>(1) selected_off;
 Register<bit<32>,bit<8>>(1) selected_identity;
 Register<bit<32>,bit<8>>(1) selected_addresses;
 Register<bit<32>,bit<8>>(1) selected_tag;
 Register<bit<32>,bit<8>>(1) operate_tag;
 RegisterAction<bit<32>,bit<8>,bit<32>>(first_base) first_rmw = {
  void apply(inout bit<32> value,out bit<32> old) {
   old=value;
   if(m.select_candidate==8w1&&value==32w0xFFFFFFFF) {value=hdr.tcp.seq;}
   else {value=value|m.reset_mask;}
  }
 };
 RegisterAction<bit<32>,bit<8>,bit<32>>(second_base) second_rmw = {
  void apply(inout bit<32> value,out bit<32> old) {
   old=value;
   if(m.op_candidate==8w1&&value==32w0xFFFFFFFF) {value=hdr.tcp.seq;}
   else {value=value|m.reset_mask;}
  }
 };
 RegisterAction<bit<32>,bit<8>,bit<32>>(selected_on) selected_on_rmw = {
  void apply(inout bit<32> value,out bit<32> result) {
   if(m.fresh_select==8w1) {value=hdr.req0.on;} result=value;
  }
 };
 RegisterAction<bit<32>,bit<8>,bit<32>>(selected_off) selected_off_rmw = {
  void apply(inout bit<32> value,out bit<32> result) {
   if(m.fresh_select==8w1) {value=hdr.tail.off;} result=value;
  }
 };
 RegisterAction<bit<32>,bit<8>,bit<32>>(selected_identity) selected_identity_rmw = {
  void apply(inout bit<32> value,out bit<32> result) {
   if(m.fresh_select==8w1) {value=m.identity;} result=value;
  }
 };
 RegisterAction<bit<32>,bit<8>,bit<32>>(selected_addresses) selected_addresses_rmw = {
  void apply(inout bit<32> value,out bit<32> result) {
   if(m.fresh_select==8w1) {value=m.addresses;} result=value;
  }
 };
 RegisterAction<bit<32>,bit<8>,bit<32>>(selected_tag) selected_tag_rmw = {
  void apply(inout bit<32> value,out bit<32> result) {
   if(m.fresh_select==8w1) {value=m.tag;} result=value;
  }
 };
 RegisterAction<bit<32>,bit<8>,bit<32>>(operate_tag) operate_tag_rmw = {
  void apply(inout bit<32> value,out bit<32> result) {
   if(m.fresh_operate==8w1) {value=m.tag;} result=value;
  }
 };
 action arith_step_0() {m.seq_off=hdr.tcp.seq-m.base;}
 table t_arith_step_0 {actions={arith_step_0;}size=1;const default_action=arith_step_0();}
 action arith_step_1() {m.seq_op_off=hdr.tcp.seq-m.op_base;}
 table t_arith_step_1 {actions={arith_step_1;}size=1;const default_action=arith_step_1();}
 action arith_step_2() {hdr.tcp.seq=hdr.tcp.seq+32w20;}
 action seq_plus40() {hdr.tcp.seq=hdr.tcp.seq+32w40;}
 table t_arith_step_2 {key={m.seq_delta:exact;}actions={arith_step_2;seq_plus40;NoAction;}size=2;const default_action=NoAction();const entries={32w20:arith_step_2();32w40:seq_plus40();}}
 action arith_step_3() {m.ack_off=hdr.tcp.ack-m.base;}
 table t_arith_step_3 {actions={arith_step_3;}size=1;const default_action=arith_step_3();}
 action arith_step_4() {m.ack_op_off=hdr.tcp.ack-m.op_base;}
 table t_arith_step_4 {actions={arith_step_4;}size=1;const default_action=arith_step_4();}
 action arith_step_5() {m.right_ack=hdr.tcp.ack+m.win32;}
 table t_arith_step_5 {actions={arith_step_5;}size=1;const default_action=arith_step_5();}
 action arith_step_6() {m.right_off=m.right_ack-m.base;}
 table t_arith_step_6 {actions={arith_step_6;}size=1;const default_action=arith_step_6();}
 action arith_step_7() {m.right_op_off=m.right_ack-m.op_base;}
 table t_arith_step_7 {actions={arith_step_7;}size=1;const default_action=arith_step_7();}
 action arith_step_8() {hdr.tcp.ack=hdr.tcp.ack-32w20;}
 action ack_minus40() {hdr.tcp.ack=hdr.tcp.ack-32w40;}
 action ack_clamp_first() {hdr.tcp.ack=m.base+32w35;}
 action ack_clamp_second() {hdr.tcp.ack=m.op_base+32w35;}
 table t_arith_step_8 {key={m.ack_mode:exact;}actions={arith_step_8;ack_minus40;ack_clamp_first;ack_clamp_second;NoAction;}size=4;const default_action=NoAction();const entries={8w1:arith_step_8();8w2:ack_minus40();8w3:ack_clamp_first();8w4:ack_clamp_second();}}
 action arith_step_9() {m.window16=hdr.tcp.win+m.delta_left16;}
 table t_arith_step_9 {actions={arith_step_9;}size=1;const default_action=arith_step_9();}
 action arith_step_10() {hdr.tcp.win=m.window16-m.delta_right16;}
 table t_arith_step_10 {actions={arith_step_10;}size=1;const default_action=arith_step_10();}
 action widen_window() {m.win32=16w0++hdr.tcp.win;}
 table t_widen_window {actions={widen_window;}size=1;const default_action=widen_window();}
 apply {
  
  insertion_profile.apply();
  if(m.native==8w1&&m.enable==8w1&&m.ip_valid&&m.tcp_valid) {
   t_crc_step_0.apply();
   t_crc_step_1.apply();
   t_crc_step_2.apply();
   if(hdr.dl.crc!=(m.hcrc[7:0]++m.hcrc[15:8])) {m.bad0=8w1;}
   if(hdr.req0.crc!=(m.bcrc[7:0]++m.bcrc[15:8])) {m.bad1=8w1;}
   if(hdr.tail.crc!=(m.tcrc[7:0]++m.tcrc[15:8])) {m.bad2=8w1;}
   if(hdr.dl.magic!=16w0x0564||hdr.dl.len!=8w26) {m.bad3=8w1;}
   if(hdr.req0.group!=8w12||hdr.req0.variation!=8w1||hdr.req0.qualifier!=8w0x28||hdr.req0.count!=16w0x0100) {m.bad4=8w1;}
   if((hdr.req0.tp&8w0xC0)!=8w0xC0||(hdr.req0.app&8w0xF0)!=8w0xC0||hdr.tail.status!=8w0) {m.bad5=8w1;}
   if(hdr.req0.func!=8w3&&hdr.req0.func!=8w4) {m.bad6=8w1;}
   if(hdr.req0.index==m.decoy_index) {m.bad7=8w1;}
   if((hdr.tcp.flags&8w0x37)!=8w0x10) {m.bad8=8w1;}
   eligible_native.apply();
  }

  if(m.direction!=8w0&&hdr.tcp.isValid()) {
   t_widen_window.apply();
   m.identity=hdr.req0.index++hdr.req0.code++hdr.req0.crob_count;
   m.addresses=hdr.dl.dst++hdr.dl.src;
   m.tag=hdr.dl.ctrl++hdr.req0.tp++hdr.req0.app++hdr.req0.func;
   if((hdr.tcp.flags&8w4)==8w4) {m.reset=8w1;m.reset_mask=32w0xFFFFFFFF;}
   if(m.allow==8w1&&hdr.req0.func==8w3&&hdr.tcp.seq!=32w0xFFFFFFFF) {m.select_candidate=8w1;}
   m.base_old=first_rmw.execute(8w0);
   m.base=m.base_old;
   if(m.base_old==32w0xFFFFFFFF&&m.select_candidate==8w1) {
    m.base=hdr.tcp.seq;m.fresh_select=8w1;
   }
   if(m.base!=32w0xFFFFFFFF) {m.active=8w1;}
   m.cached_on=selected_on_rmw.execute(8w0);
   m.cached_off=selected_off_rmw.execute(8w0);
   m.cached_identity=selected_identity_rmw.execute(8w0);
   m.cached_addresses=selected_addresses_rmw.execute(8w0);
   m.cached_tag=selected_tag_rmw.execute(8w0);
   // Each equality is independent; whole-frame cache fields are exact, not a hash.
   if(m.cached_on==hdr.req0.on&&m.cached_off==hdr.tail.off&&m.cached_identity==m.identity&&m.cached_addresses==m.addresses) {m.matches_objects=8w1;}
   if(m.allow==8w1&&m.active==8w1&&m.matches_objects==8w1&&hdr.req0.func==8w4&&hdr.tcp.seq!=32w0xFFFFFFFF) {m.op_candidate=8w1;}
   m.op_old=second_rmw.execute(8w0);m.op_base=m.op_old;
   if(m.op_old==32w0xFFFFFFFF&&m.op_candidate==8w1) {m.op_base=hdr.tcp.seq;m.fresh_operate=8w1;}
   if(m.op_base!=32w0xFFFFFFFF) {m.has_operate=8w1;}
   m.cached_op_tag=operate_tag_rmw.execute(8w0);
   if(m.allow==8w1&&m.matches_objects==8w1) {
    if(hdr.req0.func==8w3&&hdr.tcp.seq==m.base&&m.tag==m.cached_tag) {m.pad_committed=8w1;}
    if(hdr.req0.func==8w4&&hdr.tcp.seq==m.op_base&&m.tag==m.cached_op_tag) {m.pad_committed=8w1;}
   }
   if(m.active==8w1) {
    if(m.direction==8w1) {
     t_arith_step_0.apply();t_arith_step_1.apply();
     if(m.seq_off[31:31]==1w0&&m.seq_off>=32w35) {m.seq_delta=32w20;}
     if(m.has_operate==8w1&&m.seq_op_off[31:31]==1w0&&m.seq_op_off>=32w35) {m.seq_delta=32w40;}
     t_arith_step_2.apply();
    } else {
     t_arith_step_3.apply();t_arith_step_4.apply();
     t_arith_step_5.apply();
     t_arith_step_6.apply();t_arith_step_7.apply();
     if(m.ack_off[31:31]==1w0&&m.ack_off>32w35) {
      if(m.ack_off<32w55) {m.ack_delta=m.ack_off-32w35;m.ack_mode=8w3;}else {m.ack_delta=32w20;m.ack_mode=8w1;}
     }
     if(m.has_operate==8w1&&m.ack_op_off[31:31]==1w0&&m.ack_op_off>=32w55) {
      if(m.ack_op_off<32w75) {m.ack_delta=m.ack_op_off-32w35;m.ack_mode=8w4;}else {m.ack_delta=32w40;m.ack_mode=8w2;}
     }
     if(m.right_off[31:31]==1w0&&m.right_off>32w35) {
      if(m.right_off<32w55) {m.right_delta=m.right_off-32w35;}else {m.right_delta=32w20;}
     }
     if(m.has_operate==8w1&&m.right_op_off[31:31]==1w0&&m.right_op_off>=32w55) {
      if(m.right_op_off<32w75) {m.right_delta=m.right_op_off-32w35;}else {m.right_delta=32w40;}
     }
     t_arith_step_8.apply();
     m.delta_left16=m.ack_delta[15:0];m.delta_right16=m.right_delta[15:0];
     t_arith_step_9.apply();
     t_arith_step_10.apply();
    }
    m.changed=1w1;
    // A missing byte-image replay path must never silently forward a partial
    // native retransmission into an expanded stream. This is an explicit blocker.
    if(hdr.ip.total_len!=16w40&&m.native==8w0&&m.payload_len==16w0) {md.drop_ctl=3w1;}
   }
  }
   if(m.pad_committed==8w1) {
    hdr.out1.setValid();hdr.out2.setValid();
    hdr.out1.off=hdr.tail.off;hdr.out1.status=hdr.tail.status;
    hdr.out1.group=8w12;hdr.out1.variation=8w1;hdr.out1.qualifier=8w0x28;
    hdr.out1.count=16w0x0100;hdr.out1.index=m.decoy_index;hdr.out1.code=m.decoy_code;
    hdr.out1.crob_count=m.decoy_count;hdr.out1.on_first=m.decoy_on[31:16];
    hdr.out2.on_last=m.decoy_on[15:0];hdr.out2.off=m.decoy_off;hdr.out2.status=8w0;
    hdr.tail.setInvalid();hdr.dl.len=8w44;hdr.ip.total_len=hdr.ip.total_len + 16w20;
    t_crc_step_3.apply();
    hdr.dl.crc=m.hcrc[7:0]++m.hcrc[15:8];
    t_crc_step_4.apply();
    hdr.out1.crc=m.bcrc[7:0]++m.bcrc[15:8];
    t_crc_step_5.apply();
    hdr.out2.crc=m.tcrc[7:0]++m.tcrc[15:8];m.changed=1w1;
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

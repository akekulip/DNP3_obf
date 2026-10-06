/* INGRESS PROCESSING ARITHMETIC COMPONENT; NOT A DEPLOYABLE CASE4 PROGRAM.
 * Read-only two-boundary ledger inputs require controller initialization.
 * No validation proof, connection admission, image cache, or final forwarding.
 * The private completion stays internal and drops until full integration exists.
 */
#include <core.p4>
#include <tna.p4>
const bit<16> WORK_TYPE = 16w0x88CA;
const bit<8> MAX_PASSES = 8w16;
const PortId_t PROCESS_PORT = 9w69;
header eth_h {bit<48> dst;bit<48> src;bit<16> etype;}
header work_h {
 bit<8> version;bit<8> phase;bit<8> passes;bit<8> first_valid;
 bit<8> second_valid;bit<8> complete;bit<16> reserved;
 bit<32> cookie;bit<32> first_start;bit<32> second_start;
 bit<32> seq_native;bit<32> seq_wire;bit<32> ack_wire;
 bit<32> window;bit<32> right_wire;bit<32> left_native;
 bit<32> right_native;bit<32> offset;
}
struct headers_t {eth_h eth;work_h work;}
struct metadata_t {bit<8> allowed;bit<8> valid;bit<32> cookie;bit<32> first;bit<32> second;}
parser IgParser(packet_in pkt,out headers_t hdr,out metadata_t m,out ingress_intrinsic_metadata_t ig) {
 state start {pkt.extract(ig);pkt.advance(PORT_METADATA_SIZE);m.allowed=8w0;m.valid=8w0;m.cookie=32w0;m.first=32w0;m.second=32w0;transition eth;}
 state eth {pkt.extract(hdr.eth);transition select(ig.ingress_port,hdr.eth.etype) {(PROCESS_PORT,WORK_TYPE):work;default:reject;}}
 state work {pkt.extract(hdr.work);transition select(hdr.work.version,hdr.work.reserved) {(8w1,16w0):accept;default:reject;}}
}
@pa_container_size("ingress", "hdr.work.first_start", 32)
@pa_container_size("ingress", "hdr.work.second_start", 32)
@pa_container_size("ingress", "hdr.work.seq_native", 32)
@pa_container_size("ingress", "hdr.work.seq_wire", 32)
@pa_container_size("ingress", "hdr.work.ack_wire", 32)
@pa_container_size("ingress", "hdr.work.window", 32)
@pa_container_size("ingress", "hdr.work.right_wire", 32)
@pa_container_size("ingress", "hdr.work.left_native", 32)
@pa_container_size("ingress", "hdr.work.right_native", 32)
@pa_container_size("ingress", "hdr.work.offset", 32)
control Ingress(inout headers_t hdr,inout metadata_t m,in ingress_intrinsic_metadata_t ig,
 in ingress_intrinsic_metadata_from_parser_t parser_md,
 inout ingress_intrinsic_metadata_for_deparser_t deparser_md,
 inout ingress_intrinsic_metadata_for_tm_t tm) {
 Register<bit<32>, bit<1>>(1,0) first_start;
 Register<bit<32>, bit<1>>(1,0) second_start;
 Register<bit<32>, bit<1>>(1,0) connection_cookie;
 Register<bit<8>, bit<1>>(1,0) boundary_valid;
 RegisterAction<bit<32>,bit<1>,bit<32>>(first_start) first_read={void apply(inout bit<32> v,out bit<32> result){result=v;}};
 RegisterAction<bit<32>,bit<1>,bit<32>>(second_start) second_read={void apply(inout bit<32> v,out bit<32> result){result=v;}};
 RegisterAction<bit<32>,bit<1>,bit<32>>(connection_cookie) cookie_read={void apply(inout bit<32> v,out bit<32> result){result=v;}};
 RegisterAction<bit<8>,bit<1>,bit<8>>(boundary_valid) valid_read={void apply(inout bit<8> v,out bit<8> result){result=v;}};
 action reject(){deparser_md.drop_ctl=3w1;}
 action allow(){m.allowed=8w1;}
 table admitted_cookie {key={hdr.work.cookie:exact;}actions={allow;reject;}size=1;default_action=reject();}
 action first_load(){m.first=first_read.execute(1w0);}
 table first_load_t {actions={first_load;}size=1;const default_action=first_load();}
 action second_load(){m.second=second_read.execute(1w0);}
 table second_load_t {actions={second_load;}size=1;const default_action=second_load();}
 action cookie_load(){m.cookie=cookie_read.execute(1w0);}
 table cookie_load_t {actions={cookie_load;}size=1;const default_action=cookie_load();}
 action valid_load(){m.valid=valid_read.execute(1w0);}
 table valid_load_t {actions={valid_load;}size=1;const default_action=valid_load();}
 action initialize(){hdr.work.first_start=m.first;hdr.work.second_start=m.second;
 hdr.work.first_valid=m.valid&8w1;hdr.work.second_valid=m.valid&8w2;
 hdr.work.seq_wire=hdr.work.seq_native;hdr.work.left_native=hdr.work.ack_wire;
 hdr.work.right_native=hdr.work.ack_wire;hdr.work.complete=8w0;}
 table initialize_t {actions={initialize;}size=1;const default_action=initialize();}
 action right_edge(){hdr.work.right_wire=hdr.work.ack_wire+hdr.work.window;}
 action seq_offset_1(){hdr.work.offset=hdr.work.seq_native-hdr.work.first_start;}
 action seq_offset_2(){hdr.work.offset=hdr.work.seq_native-hdr.work.second_start;}
 action left_offset_1(){hdr.work.offset=hdr.work.ack_wire-hdr.work.first_start;}
 action left_offset_2(){hdr.work.offset=hdr.work.ack_wire-hdr.work.second_start;}
 action right_offset_1(){hdr.work.offset=hdr.work.right_wire-hdr.work.first_start;}
 action right_offset_2(){hdr.work.offset=hdr.work.right_wire-hdr.work.second_start;}
 action right_copy(){hdr.work.right_native=hdr.work.right_wire;}
 action window_difference(){hdr.work.offset=hdr.work.right_native-hdr.work.left_native;}
 action window_growth(){hdr.work.offset=hdr.work.offset-hdr.work.window;}
 action window_finish(){hdr.work.window=hdr.work.right_native-hdr.work.left_native;}
 action finished(){hdr.work.complete=8w1;}
 action seq_plus_20(){hdr.work.seq_wire=hdr.work.seq_native+32w20;}
 action seq_plus_40(){hdr.work.seq_wire=hdr.work.seq_native+32w40;}
 action left_minus_20(){hdr.work.left_native=hdr.work.ack_wire-32w20;}
 action left_minus_40(){hdr.work.left_native=hdr.work.ack_wire-32w40;}
 action right_minus_20(){hdr.work.right_native=hdr.work.right_wire-32w20;}
 action right_minus_40(){hdr.work.right_native=hdr.work.right_wire-32w40;}
 action left_clamp_1(){hdr.work.left_native=hdr.work.first_start+32w34;}
 action left_clamp_2(){hdr.work.left_native=hdr.work.second_start+32w34;}
 action right_clamp_1(){hdr.work.right_native=hdr.work.first_start+32w34;}
 action right_clamp_2(){hdr.work.right_native=hdr.work.second_start+32w34;}
 table right_edge_t {actions={right_edge;}size=1;const default_action=right_edge();}
 table seq_offset_1_t {actions={seq_offset_1;}size=1;const default_action=seq_offset_1();}
 table seq_offset_2_t {actions={seq_offset_2;}size=1;const default_action=seq_offset_2();}
 table left_offset_1_t {actions={left_offset_1;}size=1;const default_action=left_offset_1();}
 table left_offset_2_t {actions={left_offset_2;}size=1;const default_action=left_offset_2();}
 table right_offset_1_t {actions={right_offset_1;}size=1;const default_action=right_offset_1();}
 table right_offset_2_t {actions={right_offset_2;}size=1;const default_action=right_offset_2();}
 table right_copy_t {actions={right_copy;}size=1;const default_action=right_copy();}
 table window_difference_t {actions={window_difference;}size=1;const default_action=window_difference();}
 table window_growth_t {actions={window_growth;}size=1;const default_action=window_growth();}
 // Monotone inverse mapping cannot enlarge an unscaled window. Reject a
 // modular half-range discontinuity instead of advertising invented capacity.
 table window_guard {key={hdr.work.offset[31:31]:exact;hdr.work.offset[30:0]:ternary;}
 actions={reject;NoAction;}size=2;const default_action=NoAction();const entries={
 (1w0,31w0):NoAction();(1w0,31w0&&&31w0):reject();}}
 table window_finish_t {actions={window_finish;}size=1;const default_action=window_finish();}
 table finished_t {actions={finished;}size=1;const default_action=finished();}
 table seq_first {key={hdr.work.first_valid:exact;hdr.work.offset[31:7]:exact;hdr.work.offset[6:0]:range;}
 actions={seq_plus_20;NoAction;}size=2;const default_action=NoAction();
 const entries={(8w1,25w0,7w35..7w127):seq_plus_20();}}
 table seq_first_large {key={hdr.work.first_valid:exact;hdr.work.offset[31:31]:exact;hdr.work.offset[30:7]:ternary;}
 actions={seq_plus_20;NoAction;}size=2;const default_action=NoAction();
 const entries={(8w1,1w0,24w0):NoAction();
 (8w1,1w0,24w0&&&24w0):seq_plus_20();}}
 table seq_second {key={hdr.work.second_valid:exact;hdr.work.offset[31:7]:exact;hdr.work.offset[6:0]:range;}
 actions={seq_plus_40;NoAction;}size=2;const default_action=NoAction();
 const entries={(8w2,25w0,7w35..7w127):seq_plus_40();}}
 table seq_second_large {key={hdr.work.second_valid:exact;hdr.work.offset[31:31]:exact;hdr.work.offset[30:7]:ternary;}
 actions={seq_plus_40;NoAction;}size=2;const default_action=NoAction();
 const entries={(8w2,1w0,24w0):NoAction();
 (8w2,1w0,24w0&&&24w0):seq_plus_40();}}
 table left_map_1 {key={hdr.work.first_valid:exact;hdr.work.offset[31:7]:exact;hdr.work.offset[6:0]:range;}
 actions={left_clamp_1;left_minus_20;NoAction;}size=2;
 const default_action=NoAction();const entries={(8w1,25w0,7w35..7w54):left_clamp_1();
 (8w1,25w0,7w55..7w127):left_minus_20();}}
 table left_map_1_large {key={hdr.work.first_valid:exact;hdr.work.offset[31:31]:exact;hdr.work.offset[30:7]:ternary;}
 actions={left_minus_20;NoAction;}size=2;const default_action=NoAction();const entries={
 (8w1,1w0,24w0):NoAction();
 (8w1,1w0,24w0&&&24w0):left_minus_20();}}
 table left_map_2 {key={hdr.work.second_valid:exact;hdr.work.offset[31:7]:exact;hdr.work.offset[6:0]:range;}
 actions={left_clamp_2;left_minus_40;NoAction;}size=2;
 const default_action=NoAction();const entries={(8w2,25w0,7w55..7w74):left_clamp_2();
 (8w2,25w0,7w75..7w127):left_minus_40();}}
 table left_map_2_large {key={hdr.work.second_valid:exact;hdr.work.offset[31:31]:exact;hdr.work.offset[30:7]:ternary;}
 actions={left_minus_40;NoAction;}size=2;const default_action=NoAction();const entries={
 (8w2,1w0,24w0):NoAction();
 (8w2,1w0,24w0&&&24w0):left_minus_40();}}
 table right_map_1 {key={hdr.work.first_valid:exact;hdr.work.offset[31:7]:exact;hdr.work.offset[6:0]:range;}
 actions={right_clamp_1;right_minus_20;NoAction;}size=2;
 const default_action=NoAction();const entries={(8w1,25w0,7w35..7w54):right_clamp_1();
 (8w1,25w0,7w55..7w127):right_minus_20();}}
 table right_map_1_large {key={hdr.work.first_valid:exact;hdr.work.offset[31:31]:exact;hdr.work.offset[30:7]:ternary;}
 actions={right_minus_20;NoAction;}size=2;const default_action=NoAction();const entries={
 (8w1,1w0,24w0):NoAction();
 (8w1,1w0,24w0&&&24w0):right_minus_20();}}
 table right_map_2 {key={hdr.work.second_valid:exact;hdr.work.offset[31:7]:exact;hdr.work.offset[6:0]:range;}
 actions={right_clamp_2;right_minus_40;NoAction;}size=2;
 const default_action=NoAction();const entries={(8w2,25w0,7w55..7w74):right_clamp_2();
 (8w2,25w0,7w75..7w127):right_minus_40();}}
 table right_map_2_large {key={hdr.work.second_valid:exact;hdr.work.offset[31:31]:exact;hdr.work.offset[30:7]:ternary;}
 actions={right_minus_40;NoAction;}size=2;const default_action=NoAction();const entries={
 (8w2,1w0,24w0):NoAction();
 (8w2,1w0,24w0&&&24w0):right_minus_40();}}
 action next(){hdr.work.phase=hdr.work.phase+8w1;hdr.work.passes=hdr.work.passes+8w1;tm.ucast_egress_port=PROCESS_PORT;tm.qid = 5w0;}
 table next_t {actions={next;}size=1;const default_action=next();}
 apply {admitted_cookie.apply();
 if(m.allowed==8w1){
 if(hdr.work.passes>=MAX_PASSES || hdr.work.phase!=hdr.work.passes || hdr.work.window[31:16]!=16w0){reject();}
 else {
 cookie_load_t.apply();
 if(m.cookie!=hdr.work.cookie){reject();}
 else {
 if(hdr.work.phase==8w0){first_load_t.apply();second_load_t.apply();valid_load_t.apply();
 if(m.valid!=8w0 && m.valid!=8w1 && m.valid!=8w3){reject();}else {initialize_t.apply();}}
 else if(hdr.work.phase==8w1){right_edge_t.apply();right_copy_t.apply();}
 else if(hdr.work.phase==8w2){seq_offset_1_t.apply();}
 else if(hdr.work.phase==8w3){seq_first.apply();seq_first_large.apply();}
 else if(hdr.work.phase==8w4){seq_offset_2_t.apply();}
 else if(hdr.work.phase==8w5){seq_second.apply();seq_second_large.apply();}
 else if(hdr.work.phase==8w6){left_offset_1_t.apply();}
 else if(hdr.work.phase==8w7){left_map_1.apply();left_map_1_large.apply();}
 else if(hdr.work.phase==8w8){left_offset_2_t.apply();}
 else if(hdr.work.phase==8w9){left_map_2.apply();left_map_2_large.apply();}
 else if(hdr.work.phase==8w10){right_offset_1_t.apply();}
 else if(hdr.work.phase==8w11){right_map_1.apply();right_map_1_large.apply();}
 else if(hdr.work.phase==8w12){right_offset_2_t.apply();}
 else if(hdr.work.phase==8w13){right_map_2.apply();right_map_2_large.apply();}
 else if(hdr.work.phase==8w14){window_difference_t.apply();window_growth_t.apply();window_guard.apply();window_finish_t.apply();}
 else if(hdr.work.phase==8w15){finished_t.apply();reject();}
 else {reject();}
 next_t.apply();
 }
 }
 }
 }
}
control IgDeparser(packet_out pkt,inout headers_t hdr,in metadata_t m,in ingress_intrinsic_metadata_for_deparser_t md){apply {pkt.emit(hdr.eth);pkt.emit(hdr.work);}}
parser EgParser(packet_in pkt,out headers_t hdr,out metadata_t m,out egress_intrinsic_metadata_t eg){state start {pkt.extract(eg);transition eth;}state eth {pkt.extract(hdr.eth);transition work;}state work {pkt.extract(hdr.work);transition accept;}}
control Egress(inout headers_t hdr,inout metadata_t m,in egress_intrinsic_metadata_t eg,in egress_intrinsic_metadata_from_parser_t parser_md,inout egress_intrinsic_metadata_for_deparser_t md,inout egress_intrinsic_metadata_for_output_port_t port_md){apply {}}
control EgDeparser(packet_out pkt,inout headers_t hdr,in metadata_t m,in egress_intrinsic_metadata_for_deparser_t md){apply {pkt.emit(hdr.eth);pkt.emit(hdr.work);}}
Pipeline(IgParser(),Ingress(),IgDeparser(),EgParser(),Egress(),EgDeparser()) pipe;
Switch(pipe) main;

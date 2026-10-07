/* Scratch aliasing (PHV): so1 holds seq-35 / ao1 the replay byte / so2 the native last byte / ao2 the ledger generation / ro1 the ledger wire_start on the non-map kinds. */
/* S3-3 resource canary for role M (pipe 1 ingress). NEVER DEPLOY. Not the final M.
 * Envelope parser (N's 16-byte prefix), epoch-tagged geometry and slot-ledger registers,
 * forward mapping arithmetic (two insertion boundaries, +20 per boundary), reverse inverse
 * mapping with clamp and window guard, replay compare. Mapping const tables are copied
 * verbatim from payload_mapping/forward.p4 and reverse.p4 by generate_m_skeleton.py.
 * Excluded on purpose (S3-4): construct and the three output CRC hashes, descriptor, carve. */
#include <core.p4>
#include <tna.p4>
header work_h{bit<32> epoch;bit<32> generation;bit<32> expected_cell;bit<16> event;bit<16> reserved;}
header eth_h{bit<48> dst;bit<48> src;bit<16> type;}
header ip_h{bit<4> version;bit<4> ihl;bit<8> tos;bit<16> len;bit<16> id;bit<3> flags;bit<13> frag;bit<8> ttl;bit<8> proto;bit<16> checksum;bit<32> src;bit<32> dst;}
header tcp_h{bit<16> sport;bit<16> dport;bit<32> seq;bit<32> ack;bit<32> control_window;bit<16> checksum;bit<16> urgent;}
header dl_h{bit<16> magic;bit<8> len;bit<8> ctrl;bit<16> dst;bit<16> src;bit<16> crc;}
header native_h{bit<8> tp;bit<8> app;bit<8> func;bit<8> group;bit<8> variation;bit<8> qualifier;bit<16> count;bit<16> index;bit<8> code;bit<8> repeat;bit<32> on;bit<16> crc;}
header tail_h{bit<32> off;bit<8> status;bit<16> crc;}
header replay_h{bit<8> data;}
struct pair_t{bit<32> lo;bit<32> hi;}
struct headers_t{work_h work;eth_h eth;ip_h ip;tcp_h tcp;dl_h dl;native_h native;tail_h tail;replay_h replay;}
struct meta_t{bit<8> network_allowed;bit<32> repair_sum_pad;bit<16> repair_sum;bit<32> first;bit<32> second;bit<8> valid;bit<8> direction;PortId_t output_port;
 bit<32> right;bit<32> left;bit<32> native_right;bit<32> so1;bit<32> so2;bit<32> ao1;bit<32> ao2;bit<32> ro1;bit<32> ro2;
 bit<32> full_window;bit<32> window_after;bit<16> tcp_len;bool ip_error;bit<8> parsed;bit<1> changed;
 bit<32> native_last;bit<32> replay_byte;bit<8> kind;bit<16> phase;bit<8> contig;bit<8> led_ok;}
parser IgParser(packet_in pkt,out headers_t hdr,out meta_t m,out ingress_intrinsic_metadata_t ig){Checksum() ipcheck;Checksum() repaircheck;
 state start{pkt.extract(ig);pkt.advance(PORT_METADATA_SIZE);m.parsed=8w0;m.changed=1w0;m.direction=8w0;m.valid=8w0;m.network_allowed=8w0;m.kind=8w0;m.phase=16w0;m.contig=8w0;m.led_ok=8w0;m.ro1=32w0;transition select(ig.ingress_port){9w68:work;default:reject;}}
 state work{pkt.extract(hdr.work);m.kind=hdr.work.event[7:0];m.phase=hdr.work.expected_cell[31:16];transition select(hdr.work.reserved){16w0:eth;default:reject;}}
 state eth{pkt.extract(hdr.eth);transition select(hdr.eth.type){16w0x0800:ip;default:reject;}}
 state ip{pkt.extract(hdr.ip);ipcheck.add(hdr.ip);m.ip_error=ipcheck.verify();transition select(hdr.ip.version,hdr.ip.ihl,hdr.ip.proto){(4w4,4w5,8w6):ip_flags;default:reject;}}
 state ip_flags{transition select(hdr.ip.frag,hdr.ip.flags){(13w0,3w0):tcp;(13w0,3w2):tcp;default:reject;}}
 state tcp{pkt.extract(hdr.tcp);repaircheck.subtract({hdr.tcp.seq,hdr.tcp.ack,hdr.tcp.control_window,hdr.tcp.checksum,16w0});m.repair_sum=repaircheck.get();transition select(hdr.tcp.control_window[31:24],hdr.tcp.control_window[23:16],hdr.tcp.urgent){(8w0x50,8w0x10,16w0):payload;(8w0x50,8w0x18,16w0):payload;default:reject;}}
 state payload{transition select(hdr.ip.len){16w75:native_dl;16w41:replay;default:eligible;}}
 state native_dl{pkt.extract(hdr.dl);pkt.extract(hdr.native);pkt.extract(hdr.tail);transition eligible;}
 state replay{pkt.extract(hdr.replay);transition eligible;}
 state eligible{m.parsed=8w1;transition accept;}
}
@pa_container_size("ingress", "hdr.tcp.seq", 32)
@pa_container_size("ingress", "hdr.tcp.ack", 32)
@pa_container_size("ingress", "m.first", 32)
@pa_container_size("ingress", "m.second", 32)
@pa_container_size("ingress", "m.right", 32)
@pa_container_size("ingress", "m.left", 32)
@pa_container_size("ingress", "m.native_right", 32)
@pa_container_size("ingress", "m.so2", 32)
@pa_container_size("ingress", "m.ao1", 32)
@pa_container_size("ingress", "m.ao2", 32)
@pa_container_size("ingress", "m.ro1", 32)
@pa_container_size("ingress", "m.ro2", 32)
@pa_container_size("ingress", "m.full_window", 32)
@pa_container_size("ingress", "m.window_after", 32)
@pa_container_size("ingress", "m.so1", 32)
@pa_container_size("ingress", "hdr.tcp.control_window", 32)
control Ingress(inout headers_t hdr,inout meta_t m,in ingress_intrinsic_metadata_t ig,in ingress_intrinsic_metadata_from_parser_t p,inout ingress_intrinsic_metadata_for_deparser_t md,inout ingress_intrinsic_metadata_for_tm_t tm){
 action deny(){md.drop_ctl=3w1;}
 action route(PortId_t port){m.output_port=port;tm.ucast_egress_port=port;tm.bypass_egress=1w0;}
 table forwarding{key={ig.ingress_port:exact;}actions={route;deny;}size=4;default_action=deny();}
 /* Static tuple to direction only. Geometry no longer lives here: it is in the registers below. */
 action configure(bit<8> direction){m.direction=direction;}
 table connection{key={hdr.ip.src:exact;hdr.ip.dst:exact;hdr.tcp.sport:exact;hdr.tcp.dport:exact;}actions={configure;NoAction;}size=2;default_action=NoAction();}
 action network_allow(){m.network_allowed=8w1;}
 table network_gate{key={m.parsed:exact;m.ip_error:exact;hdr.ip.len:range;hdr.ip.ttl:range;}actions={network_allow;NoAction;}size=1;const default_action=NoAction();const entries={(8w1,false,16w40..16w65535,8w1..8w255):network_allow();}}
 action prep(){m.so1=hdr.tcp.seq-32w35;m.native_last=32w0;m.replay_byte=32w0;}
 table prep_t{actions={prep;}size=1;const default_action=prep();}
 action prep_native(){m.native_last=(bit<32>)hdr.tail.crc[7:0];}
 table prep_native_t{actions={prep_native;}size=1;const default_action=prep_native();}
 action prep_replay(){m.replay_byte=(bit<32>)hdr.replay.data;}
 table prep_replay_t{actions={prep_replay;}size=1;const default_action=prep_replay();}
 /* ---- geometry registers. One table per register. Epoch-tagged: tag cell {epoch,bits}. ---- */
 Register<bit<32>,bit<1>>(1,0) geo_first;
 RegisterAction<bit<32>,bit<1>,bit<32>>(geo_first) first_write={void apply(inout bit<32> v,out bit<32> r){v=hdr.tcp.seq;r=32w0;}};
 RegisterAction<bit<32>,bit<1>,bit<32>>(geo_first) first_read={void apply(inout bit<32> v,out bit<32> r){r=v;}};
 action geo_first_write(){first_write.execute(1w0);}
 action geo_first_read(){m.first=first_read.execute(1w0);}
 table geo_first_t{key={m.kind:exact;m.parsed:exact;m.ip_error:exact;}actions={geo_first_write;geo_first_read;NoAction;}size=4;const default_action=NoAction();const entries={(8w5,8w1,false):geo_first_write();(8w8,8w1,false):geo_first_read();(8w6,8w1,false):geo_first_read();(8w13,8w1,false):geo_first_read();}}
 Register<pair_t,bit<1>>(1,{0,0}) geo_second;
 RegisterAction<pair_t,bit<1>,bit<32>>(geo_second) second_arm={void apply(inout pair_t v,out bit<32> r){v.lo=hdr.tcp.seq;r=32w0;}};
 RegisterAction<pair_t,bit<1>,bit<8>>(geo_second) second_write={void apply(inout pair_t v,out bit<8> r){r=8w0;if(v.lo==m.so1){v.hi=hdr.tcp.seq;r=8w1;}}};
 RegisterAction<pair_t,bit<1>,bit<32>>(geo_second) second_read={void apply(inout pair_t v,out bit<32> r){r=v.hi;}};
 action geo_second_arm(){second_arm.execute(1w0);}
 action geo_second_write(){m.contig=second_write.execute(1w0);}
 action geo_second_read(){m.second=second_read.execute(1w0);}
 table geo_second_t{key={m.kind:exact;m.parsed:exact;m.ip_error:exact;}actions={geo_second_arm;geo_second_write;geo_second_read;NoAction;}size=8;const default_action=NoAction();const entries={(8w5,8w1,false):geo_second_arm();(8w7,8w1,false):geo_second_write();(8w8,8w1,false):geo_second_read();(8w6,8w1,false):geo_second_read();(8w13,8w1,false):geo_second_read();}}
 Register<pair_t,bit<1>>(1,{0,0}) geo_tag;
 RegisterAction<pair_t,bit<1>,bit<8>>(geo_tag) tag_arm={void apply(inout pair_t v,out bit<8> r){if(v.lo!=hdr.work.epoch){v.lo=hdr.work.epoch;v.hi=32w1;}else{v.hi=v.hi|32w1;}r=8w1;}};
 RegisterAction<pair_t,bit<1>,bit<8>>(geo_tag) tag_operate={void apply(inout pair_t v,out bit<8> r){r=8w0;if(v.lo==hdr.work.epoch){v.hi=v.hi|32w2;r=(bit<8>)v.hi;}}};
 RegisterAction<pair_t,bit<1>,bit<8>>(geo_tag) tag_read={void apply(inout pair_t v,out bit<8> r){r=8w0;if(v.lo==hdr.work.epoch){r=(bit<8>)v.hi;}}};
 action geo_tag_arm(){m.valid=tag_arm.execute(1w0);}
 action geo_tag_operate(){m.valid=tag_operate.execute(1w0);}
 action geo_tag_read(){m.valid=tag_read.execute(1w0);}
 table geo_tag_t{key={m.kind:exact;m.parsed:exact;m.ip_error:exact;}actions={geo_tag_arm;geo_tag_operate;geo_tag_read;NoAction;}size=8;const default_action=NoAction();const entries={(8w5,8w1,false):geo_tag_arm();(8w7,8w1,false):geo_tag_operate();(8w8,8w1,false):geo_tag_read();(8w6,8w1,false):geo_tag_read();(8w13,8w1,false):geo_tag_read();}}
 /* ---- slot ledger: two registers of two slots each, written by produce, compared by replay ---- */
 Register<pair_t,bit<1>>(2,{0,0}) led_id;
 RegisterAction<pair_t,bit<1>,bit<8>>(led_id) id_write={void apply(inout pair_t v,out bit<8> r){r=8w0;if(v.lo!=hdr.work.epoch){v.lo=hdr.work.epoch;v.hi=hdr.work.generation;r=8w1;}else{if(v.hi<hdr.work.generation){v.hi=hdr.work.generation;r=8w1;}}}};
 RegisterAction<pair_t,bit<1>,bit<32>>(led_id) id_check={void apply(inout pair_t v,out bit<32> r){r=32w0;if(v.lo==hdr.work.epoch){r=v.hi;}}};
 action led_id_write_0(){m.led_ok=id_write.execute(1w0);}
 action led_id_write_1(){m.led_ok=id_write.execute(1w1);}
 action led_id_check_0(){m.ao2=id_check.execute(1w0);}
 action led_id_check_1(){m.ao2=id_check.execute(1w1);}
 table led_id_t{key={m.kind:exact;m.phase:exact;m.parsed:exact;m.ip_error:exact;}actions={led_id_write_0;led_id_write_1;led_id_check_0;led_id_check_1;NoAction;}size=4;const default_action=NoAction();const entries={(8w5,16w9,8w1,false):led_id_write_0();(8w7,16w12,8w1,false):led_id_write_1();(8w12,16w9,8w1,false):led_id_check_0();(8w12,16w12,8w1,false):led_id_check_1();}}
 Register<pair_t,bit<1>>(2,{0,0}) led_pos;
 RegisterAction<pair_t,bit<1>,bit<32>>(led_pos) pos_write={void apply(inout pair_t v,out bit<32> r){v.lo=hdr.tcp.seq;v.hi=m.native_last;r=32w0;}};
 RegisterAction<pair_t,bit<1>,bit<32>>(led_pos) pos_check={void apply(inout pair_t v,out bit<32> r){r=32w0;if(v.hi==m.replay_byte){r=v.lo;}}};
 action led_pos_write_0(){pos_write.execute(1w0);}
 action led_pos_write_1(){pos_write.execute(1w1);}
 action led_pos_check_0(){m.ro1=pos_check.execute(1w0);}
 action led_pos_check_1(){m.ro1=pos_check.execute(1w1);}
 table led_pos_t{key={m.kind:exact;m.phase:exact;m.parsed:exact;m.ip_error:exact;}actions={led_pos_write_0;led_pos_write_1;led_pos_check_0;led_pos_check_1;NoAction;}size=4;const default_action=NoAction();const entries={(8w5,16w9,8w1,false):led_pos_write_0();(8w7,16w12,8w1,false):led_pos_write_1();(8w12,16w9,8w1,false):led_pos_check_0();(8w12,16w12,8w1,false):led_pos_check_1();}}
 /* constant +20 for the OPERATE produce packet itself (valid bit 0 proven by N and re-read here) */
 action operate_shift(){hdr.tcp.seq=hdr.tcp.seq+32w20;m.changed=1w1;}
 table operate_shift_t{actions={operate_shift;}size=1;const default_action=operate_shift();}
 /* ---- mapping arithmetic (forward.p4 / reverse.p4 as they exist) ---- */
 action snapshot(){m.so1=m.second-m.first;}
 table snapshot_t{actions={snapshot;}size=1;const default_action=snapshot();}
 action prepare_window(){m.full_window=hdr.tcp.control_window&32w0xffff;}
 table prepare_window_t{actions={prepare_window;}size=1;const default_action=prepare_window();}
 action edges(){m.right=hdr.tcp.ack+m.full_window;m.left=hdr.tcp.ack;m.tcp_len=16w20;}
 table edges_t{actions={edges;}size=1;const default_action=edges();}
 action offsets(){m.so1=hdr.tcp.seq-m.first;m.so2=hdr.tcp.seq-m.second;m.ao1=hdr.tcp.ack-m.first;m.ao2=hdr.tcp.ack-m.second;m.ro1=m.right-m.first;m.ro2=m.right-m.second;m.native_right=m.right;}
 table offsets_t{actions={offsets;}size=1;const default_action=offsets();}
action seq1_shift(){hdr.tcp.seq=hdr.tcp.seq+32w20;}
table seq1{key={m.direction:exact;m.valid:ternary;m.so1:ternary;}actions={seq1_shift;NoAction;}size=128;const default_action=NoAction();const entries={
(8w1,8w1&&&8w1,32w0x23&&&32w0xffffffff):seq1_shift();
(8w1,8w1&&&8w1,32w0x24&&&32w0xfffffffc):seq1_shift();
(8w1,8w1&&&8w1,32w0x28&&&32w0xfffffff8):seq1_shift();
(8w1,8w1&&&8w1,32w0x30&&&32w0xfffffff0):seq1_shift();
(8w1,8w1&&&8w1,32w0x40&&&32w0xffffffc0):seq1_shift();
(8w1,8w1&&&8w1,32w0x80&&&32w0xffffff80):seq1_shift();
(8w1,8w1&&&8w1,32w0x100&&&32w0xffffff00):seq1_shift();
(8w1,8w1&&&8w1,32w0x200&&&32w0xfffffe00):seq1_shift();
(8w1,8w1&&&8w1,32w0x400&&&32w0xfffffc00):seq1_shift();
(8w1,8w1&&&8w1,32w0x800&&&32w0xfffff800):seq1_shift();
(8w1,8w1&&&8w1,32w0x1000&&&32w0xfffff000):seq1_shift();
(8w1,8w1&&&8w1,32w0x2000&&&32w0xffffe000):seq1_shift();
(8w1,8w1&&&8w1,32w0x4000&&&32w0xffffc000):seq1_shift();
(8w1,8w1&&&8w1,32w0x8000&&&32w0xffff8000):seq1_shift();
(8w1,8w1&&&8w1,32w0x10000&&&32w0xffff0000):seq1_shift();
(8w1,8w1&&&8w1,32w0x20000&&&32w0xfffe0000):seq1_shift();
(8w1,8w1&&&8w1,32w0x40000&&&32w0xfffc0000):seq1_shift();
(8w1,8w1&&&8w1,32w0x80000&&&32w0xfff80000):seq1_shift();
(8w1,8w1&&&8w1,32w0x100000&&&32w0xfff00000):seq1_shift();
(8w1,8w1&&&8w1,32w0x200000&&&32w0xffe00000):seq1_shift();
(8w1,8w1&&&8w1,32w0x400000&&&32w0xffc00000):seq1_shift();
(8w1,8w1&&&8w1,32w0x800000&&&32w0xff800000):seq1_shift();
(8w1,8w1&&&8w1,32w0x1000000&&&32w0xff000000):seq1_shift();
(8w1,8w1&&&8w1,32w0x2000000&&&32w0xfe000000):seq1_shift();
(8w1,8w1&&&8w1,32w0x4000000&&&32w0xfc000000):seq1_shift();
(8w1,8w1&&&8w1,32w0x8000000&&&32w0xf8000000):seq1_shift();
(8w1,8w1&&&8w1,32w0x10000000&&&32w0xf0000000):seq1_shift();
(8w1,8w1&&&8w1,32w0x20000000&&&32w0xe0000000):seq1_shift();
(8w1,8w1&&&8w1,32w0x40000000&&&32w0xc0000000):seq1_shift();
}}
action seq2_shift(){hdr.tcp.seq=hdr.tcp.seq+32w20;}
table seq2{key={m.direction:exact;m.valid:ternary;m.so2:ternary;}actions={seq2_shift;NoAction;}size=128;const default_action=NoAction();const entries={
(8w1,8w2&&&8w2,32w0x23&&&32w0xffffffff):seq2_shift();
(8w1,8w2&&&8w2,32w0x24&&&32w0xfffffffc):seq2_shift();
(8w1,8w2&&&8w2,32w0x28&&&32w0xfffffff8):seq2_shift();
(8w1,8w2&&&8w2,32w0x30&&&32w0xfffffff0):seq2_shift();
(8w1,8w2&&&8w2,32w0x40&&&32w0xffffffc0):seq2_shift();
(8w1,8w2&&&8w2,32w0x80&&&32w0xffffff80):seq2_shift();
(8w1,8w2&&&8w2,32w0x100&&&32w0xffffff00):seq2_shift();
(8w1,8w2&&&8w2,32w0x200&&&32w0xfffffe00):seq2_shift();
(8w1,8w2&&&8w2,32w0x400&&&32w0xfffffc00):seq2_shift();
(8w1,8w2&&&8w2,32w0x800&&&32w0xfffff800):seq2_shift();
(8w1,8w2&&&8w2,32w0x1000&&&32w0xfffff000):seq2_shift();
(8w1,8w2&&&8w2,32w0x2000&&&32w0xffffe000):seq2_shift();
(8w1,8w2&&&8w2,32w0x4000&&&32w0xffffc000):seq2_shift();
(8w1,8w2&&&8w2,32w0x8000&&&32w0xffff8000):seq2_shift();
(8w1,8w2&&&8w2,32w0x10000&&&32w0xffff0000):seq2_shift();
(8w1,8w2&&&8w2,32w0x20000&&&32w0xfffe0000):seq2_shift();
(8w1,8w2&&&8w2,32w0x40000&&&32w0xfffc0000):seq2_shift();
(8w1,8w2&&&8w2,32w0x80000&&&32w0xfff80000):seq2_shift();
(8w1,8w2&&&8w2,32w0x100000&&&32w0xfff00000):seq2_shift();
(8w1,8w2&&&8w2,32w0x200000&&&32w0xffe00000):seq2_shift();
(8w1,8w2&&&8w2,32w0x400000&&&32w0xffc00000):seq2_shift();
(8w1,8w2&&&8w2,32w0x800000&&&32w0xff800000):seq2_shift();
(8w1,8w2&&&8w2,32w0x1000000&&&32w0xff000000):seq2_shift();
(8w1,8w2&&&8w2,32w0x2000000&&&32w0xfe000000):seq2_shift();
(8w1,8w2&&&8w2,32w0x4000000&&&32w0xfc000000):seq2_shift();
(8w1,8w2&&&8w2,32w0x8000000&&&32w0xf8000000):seq2_shift();
(8w1,8w2&&&8w2,32w0x10000000&&&32w0xf0000000):seq2_shift();
(8w1,8w2&&&8w2,32w0x20000000&&&32w0xe0000000):seq2_shift();
(8w1,8w2&&&8w2,32w0x40000000&&&32w0xc0000000):seq2_shift();
}}
action left1_shift(){m.left=hdr.tcp.ack-32w20;}
action left1_clamp(){m.left=m.first+32w34;}
table left1{key={m.direction:exact;m.valid:ternary;m.ao1:ternary;}actions={left1_shift;NoAction;left1_clamp;}size=128;const default_action=NoAction();const entries={
(8w2,8w1&&&8w1,32w0x23&&&32w0xffffffff):left1_clamp();
(8w2,8w1&&&8w1,32w0x24&&&32w0xfffffffc):left1_clamp();
(8w2,8w1&&&8w1,32w0x28&&&32w0xfffffff8):left1_clamp();
(8w2,8w1&&&8w1,32w0x30&&&32w0xfffffffc):left1_clamp();
(8w2,8w1&&&8w1,32w0x34&&&32w0xfffffffe):left1_clamp();
(8w2,8w1&&&8w1,32w0x36&&&32w0xffffffff):left1_clamp();
(8w2,8w1&&&8w1,32w0x37&&&32w0xffffffff):left1_shift();
(8w2,8w1&&&8w1,32w0x38&&&32w0xfffffff8):left1_shift();
(8w2,8w1&&&8w1,32w0x40&&&32w0xffffffc0):left1_shift();
(8w2,8w1&&&8w1,32w0x80&&&32w0xffffff80):left1_shift();
(8w2,8w1&&&8w1,32w0x100&&&32w0xffffff00):left1_shift();
(8w2,8w1&&&8w1,32w0x200&&&32w0xfffffe00):left1_shift();
(8w2,8w1&&&8w1,32w0x400&&&32w0xfffffc00):left1_shift();
(8w2,8w1&&&8w1,32w0x800&&&32w0xfffff800):left1_shift();
(8w2,8w1&&&8w1,32w0x1000&&&32w0xfffff000):left1_shift();
(8w2,8w1&&&8w1,32w0x2000&&&32w0xffffe000):left1_shift();
(8w2,8w1&&&8w1,32w0x4000&&&32w0xffffc000):left1_shift();
(8w2,8w1&&&8w1,32w0x8000&&&32w0xffff8000):left1_shift();
(8w2,8w1&&&8w1,32w0x10000&&&32w0xffff0000):left1_shift();
(8w2,8w1&&&8w1,32w0x20000&&&32w0xfffe0000):left1_shift();
(8w2,8w1&&&8w1,32w0x40000&&&32w0xfffc0000):left1_shift();
(8w2,8w1&&&8w1,32w0x80000&&&32w0xfff80000):left1_shift();
(8w2,8w1&&&8w1,32w0x100000&&&32w0xfff00000):left1_shift();
(8w2,8w1&&&8w1,32w0x200000&&&32w0xffe00000):left1_shift();
(8w2,8w1&&&8w1,32w0x400000&&&32w0xffc00000):left1_shift();
(8w2,8w1&&&8w1,32w0x800000&&&32w0xff800000):left1_shift();
(8w2,8w1&&&8w1,32w0x1000000&&&32w0xff000000):left1_shift();
(8w2,8w1&&&8w1,32w0x2000000&&&32w0xfe000000):left1_shift();
(8w2,8w1&&&8w1,32w0x4000000&&&32w0xfc000000):left1_shift();
(8w2,8w1&&&8w1,32w0x8000000&&&32w0xf8000000):left1_shift();
(8w2,8w1&&&8w1,32w0x10000000&&&32w0xf0000000):left1_shift();
(8w2,8w1&&&8w1,32w0x20000000&&&32w0xe0000000):left1_shift();
(8w2,8w1&&&8w1,32w0x40000000&&&32w0xc0000000):left1_shift();
}}
action left2_shift(){m.left=hdr.tcp.ack-32w40;}
action left2_clamp(){m.left=m.second+32w34;}
table left2{key={m.direction:exact;m.valid:ternary;m.ao2:ternary;}actions={left2_shift;NoAction;left2_clamp;}size=128;const default_action=NoAction();const entries={
(8w2,8w2&&&8w2,32w0x37&&&32w0xffffffff):left2_clamp();
(8w2,8w2&&&8w2,32w0x38&&&32w0xfffffff8):left2_clamp();
(8w2,8w2&&&8w2,32w0x40&&&32w0xfffffff8):left2_clamp();
(8w2,8w2&&&8w2,32w0x48&&&32w0xfffffffe):left2_clamp();
(8w2,8w2&&&8w2,32w0x4a&&&32w0xffffffff):left2_clamp();
(8w2,8w2&&&8w2,32w0x4b&&&32w0xffffffff):left2_shift();
(8w2,8w2&&&8w2,32w0x4c&&&32w0xfffffffc):left2_shift();
(8w2,8w2&&&8w2,32w0x50&&&32w0xfffffff0):left2_shift();
(8w2,8w2&&&8w2,32w0x60&&&32w0xffffffe0):left2_shift();
(8w2,8w2&&&8w2,32w0x80&&&32w0xffffff80):left2_shift();
(8w2,8w2&&&8w2,32w0x100&&&32w0xffffff00):left2_shift();
(8w2,8w2&&&8w2,32w0x200&&&32w0xfffffe00):left2_shift();
(8w2,8w2&&&8w2,32w0x400&&&32w0xfffffc00):left2_shift();
(8w2,8w2&&&8w2,32w0x800&&&32w0xfffff800):left2_shift();
(8w2,8w2&&&8w2,32w0x1000&&&32w0xfffff000):left2_shift();
(8w2,8w2&&&8w2,32w0x2000&&&32w0xffffe000):left2_shift();
(8w2,8w2&&&8w2,32w0x4000&&&32w0xffffc000):left2_shift();
(8w2,8w2&&&8w2,32w0x8000&&&32w0xffff8000):left2_shift();
(8w2,8w2&&&8w2,32w0x10000&&&32w0xffff0000):left2_shift();
(8w2,8w2&&&8w2,32w0x20000&&&32w0xfffe0000):left2_shift();
(8w2,8w2&&&8w2,32w0x40000&&&32w0xfffc0000):left2_shift();
(8w2,8w2&&&8w2,32w0x80000&&&32w0xfff80000):left2_shift();
(8w2,8w2&&&8w2,32w0x100000&&&32w0xfff00000):left2_shift();
(8w2,8w2&&&8w2,32w0x200000&&&32w0xffe00000):left2_shift();
(8w2,8w2&&&8w2,32w0x400000&&&32w0xffc00000):left2_shift();
(8w2,8w2&&&8w2,32w0x800000&&&32w0xff800000):left2_shift();
(8w2,8w2&&&8w2,32w0x1000000&&&32w0xff000000):left2_shift();
(8w2,8w2&&&8w2,32w0x2000000&&&32w0xfe000000):left2_shift();
(8w2,8w2&&&8w2,32w0x4000000&&&32w0xfc000000):left2_shift();
(8w2,8w2&&&8w2,32w0x8000000&&&32w0xf8000000):left2_shift();
(8w2,8w2&&&8w2,32w0x10000000&&&32w0xf0000000):left2_shift();
(8w2,8w2&&&8w2,32w0x20000000&&&32w0xe0000000):left2_shift();
(8w2,8w2&&&8w2,32w0x40000000&&&32w0xc0000000):left2_shift();
}}
action right1_shift(){m.native_right=m.right-32w20;}
action right1_clamp(){m.native_right=m.first+32w34;}
table right1{key={m.direction:exact;m.valid:ternary;m.ro1:ternary;}actions={right1_shift;NoAction;right1_clamp;}size=128;const default_action=NoAction();const entries={
(8w2,8w1&&&8w1,32w0x23&&&32w0xffffffff):right1_clamp();
(8w2,8w1&&&8w1,32w0x24&&&32w0xfffffffc):right1_clamp();
(8w2,8w1&&&8w1,32w0x28&&&32w0xfffffff8):right1_clamp();
(8w2,8w1&&&8w1,32w0x30&&&32w0xfffffffc):right1_clamp();
(8w2,8w1&&&8w1,32w0x34&&&32w0xfffffffe):right1_clamp();
(8w2,8w1&&&8w1,32w0x36&&&32w0xffffffff):right1_clamp();
(8w2,8w1&&&8w1,32w0x37&&&32w0xffffffff):right1_shift();
(8w2,8w1&&&8w1,32w0x38&&&32w0xfffffff8):right1_shift();
(8w2,8w1&&&8w1,32w0x40&&&32w0xffffffc0):right1_shift();
(8w2,8w1&&&8w1,32w0x80&&&32w0xffffff80):right1_shift();
(8w2,8w1&&&8w1,32w0x100&&&32w0xffffff00):right1_shift();
(8w2,8w1&&&8w1,32w0x200&&&32w0xfffffe00):right1_shift();
(8w2,8w1&&&8w1,32w0x400&&&32w0xfffffc00):right1_shift();
(8w2,8w1&&&8w1,32w0x800&&&32w0xfffff800):right1_shift();
(8w2,8w1&&&8w1,32w0x1000&&&32w0xfffff000):right1_shift();
(8w2,8w1&&&8w1,32w0x2000&&&32w0xffffe000):right1_shift();
(8w2,8w1&&&8w1,32w0x4000&&&32w0xffffc000):right1_shift();
(8w2,8w1&&&8w1,32w0x8000&&&32w0xffff8000):right1_shift();
(8w2,8w1&&&8w1,32w0x10000&&&32w0xffff0000):right1_shift();
(8w2,8w1&&&8w1,32w0x20000&&&32w0xfffe0000):right1_shift();
(8w2,8w1&&&8w1,32w0x40000&&&32w0xfffc0000):right1_shift();
(8w2,8w1&&&8w1,32w0x80000&&&32w0xfff80000):right1_shift();
(8w2,8w1&&&8w1,32w0x100000&&&32w0xfff00000):right1_shift();
(8w2,8w1&&&8w1,32w0x200000&&&32w0xffe00000):right1_shift();
(8w2,8w1&&&8w1,32w0x400000&&&32w0xffc00000):right1_shift();
(8w2,8w1&&&8w1,32w0x800000&&&32w0xff800000):right1_shift();
(8w2,8w1&&&8w1,32w0x1000000&&&32w0xff000000):right1_shift();
(8w2,8w1&&&8w1,32w0x2000000&&&32w0xfe000000):right1_shift();
(8w2,8w1&&&8w1,32w0x4000000&&&32w0xfc000000):right1_shift();
(8w2,8w1&&&8w1,32w0x8000000&&&32w0xf8000000):right1_shift();
(8w2,8w1&&&8w1,32w0x10000000&&&32w0xf0000000):right1_shift();
(8w2,8w1&&&8w1,32w0x20000000&&&32w0xe0000000):right1_shift();
(8w2,8w1&&&8w1,32w0x40000000&&&32w0xc0000000):right1_shift();
}}
action right2_shift(){m.native_right=m.right-32w40;}
action right2_clamp(){m.native_right=m.second+32w34;}
table right2{key={m.direction:exact;m.valid:ternary;m.ro2:ternary;}actions={right2_shift;NoAction;right2_clamp;}size=128;const default_action=NoAction();const entries={
(8w2,8w2&&&8w2,32w0x37&&&32w0xffffffff):right2_clamp();
(8w2,8w2&&&8w2,32w0x38&&&32w0xfffffff8):right2_clamp();
(8w2,8w2&&&8w2,32w0x40&&&32w0xfffffff8):right2_clamp();
(8w2,8w2&&&8w2,32w0x48&&&32w0xfffffffe):right2_clamp();
(8w2,8w2&&&8w2,32w0x4a&&&32w0xffffffff):right2_clamp();
(8w2,8w2&&&8w2,32w0x4b&&&32w0xffffffff):right2_shift();
(8w2,8w2&&&8w2,32w0x4c&&&32w0xfffffffc):right2_shift();
(8w2,8w2&&&8w2,32w0x50&&&32w0xfffffff0):right2_shift();
(8w2,8w2&&&8w2,32w0x60&&&32w0xffffffe0):right2_shift();
(8w2,8w2&&&8w2,32w0x80&&&32w0xffffff80):right2_shift();
(8w2,8w2&&&8w2,32w0x100&&&32w0xffffff00):right2_shift();
(8w2,8w2&&&8w2,32w0x200&&&32w0xfffffe00):right2_shift();
(8w2,8w2&&&8w2,32w0x400&&&32w0xfffffc00):right2_shift();
(8w2,8w2&&&8w2,32w0x800&&&32w0xfffff800):right2_shift();
(8w2,8w2&&&8w2,32w0x1000&&&32w0xfffff000):right2_shift();
(8w2,8w2&&&8w2,32w0x2000&&&32w0xffffe000):right2_shift();
(8w2,8w2&&&8w2,32w0x4000&&&32w0xffffc000):right2_shift();
(8w2,8w2&&&8w2,32w0x8000&&&32w0xffff8000):right2_shift();
(8w2,8w2&&&8w2,32w0x10000&&&32w0xffff0000):right2_shift();
(8w2,8w2&&&8w2,32w0x20000&&&32w0xfffe0000):right2_shift();
(8w2,8w2&&&8w2,32w0x40000&&&32w0xfffc0000):right2_shift();
(8w2,8w2&&&8w2,32w0x80000&&&32w0xfff80000):right2_shift();
(8w2,8w2&&&8w2,32w0x100000&&&32w0xfff00000):right2_shift();
(8w2,8w2&&&8w2,32w0x200000&&&32w0xffe00000):right2_shift();
(8w2,8w2&&&8w2,32w0x400000&&&32w0xffc00000):right2_shift();
(8w2,8w2&&&8w2,32w0x800000&&&32w0xff800000):right2_shift();
(8w2,8w2&&&8w2,32w0x1000000&&&32w0xff000000):right2_shift();
(8w2,8w2&&&8w2,32w0x2000000&&&32w0xfe000000):right2_shift();
(8w2,8w2&&&8w2,32w0x4000000&&&32w0xfc000000):right2_shift();
(8w2,8w2&&&8w2,32w0x8000000&&&32w0xf8000000):right2_shift();
(8w2,8w2&&&8w2,32w0x10000000&&&32w0xf0000000):right2_shift();
(8w2,8w2&&&8w2,32w0x20000000&&&32w0xe0000000):right2_shift();
(8w2,8w2&&&8w2,32w0x40000000&&&32w0xc0000000):right2_shift();
}}
action difference(){m.window_after=m.native_right-m.left;}
 table difference_t{actions={difference;}size=1;const default_action=difference();}
 action growth(){m.native_right=m.window_after-m.full_window;m.window_after=m.window_after&32w0xffff;m.full_window=hdr.tcp.control_window&32w0xffff0000;}
 table growth_t{actions={growth;}size=1;const default_action=growth();}
table window_guard{key={m.native_right:ternary;}actions={deny;NoAction;}size=32;const default_action=NoAction();const entries={
(32w0x1&&&32w0xffffffff):deny();
(32w0x2&&&32w0xfffffffe):deny();
(32w0x4&&&32w0xfffffffc):deny();
(32w0x8&&&32w0xfffffff8):deny();
(32w0x10&&&32w0xfffffff0):deny();
(32w0x20&&&32w0xffffffe0):deny();
(32w0x40&&&32w0xffffffc0):deny();
(32w0x80&&&32w0xffffff80):deny();
(32w0x100&&&32w0xffffff00):deny();
(32w0x200&&&32w0xfffffe00):deny();
(32w0x400&&&32w0xfffffc00):deny();
(32w0x800&&&32w0xfffff800):deny();
(32w0x1000&&&32w0xfffff000):deny();
(32w0x2000&&&32w0xffffe000):deny();
(32w0x4000&&&32w0xffffc000):deny();
(32w0x8000&&&32w0xffff8000):deny();
(32w0x10000&&&32w0xffff0000):deny();
(32w0x20000&&&32w0xfffe0000):deny();
(32w0x40000&&&32w0xfffc0000):deny();
(32w0x80000&&&32w0xfff80000):deny();
(32w0x100000&&&32w0xfff00000):deny();
(32w0x200000&&&32w0xffe00000):deny();
(32w0x400000&&&32w0xffc00000):deny();
(32w0x800000&&&32w0xff800000):deny();
(32w0x1000000&&&32w0xff000000):deny();
(32w0x2000000&&&32w0xfe000000):deny();
(32w0x4000000&&&32w0xfc000000):deny();
(32w0x8000000&&&32w0xf8000000):deny();
(32w0x10000000&&&32w0xf0000000):deny();
(32w0x20000000&&&32w0xe0000000):deny();
(32w0x40000000&&&32w0xc0000000):deny();
}}
 action window_narrow(){m.window_after=m.window_after&32w0xffff;m.full_window=hdr.tcp.control_window&32w0xffff0000;}
 action complete_forward(){m.changed=1w1;}
 table complete_forward_t{actions={complete_forward;}size=1;const default_action=complete_forward();}
 action complete_reverse(){hdr.tcp.ack=m.left;hdr.tcp.control_window=m.full_window|m.window_after;m.changed=1w1;}
 table complete_reverse_t{actions={complete_reverse;}size=1;const default_action=complete_reverse();}
 apply{forwarding.apply();network_gate.apply();connection.apply();prep_t.apply();
  if(hdr.native.isValid()){prep_native_t.apply();}
  if(hdr.replay.isValid()){prep_replay_t.apply();}
  if(ig.ingress_port==9w68&&p.parser_err==16w0&&hdr.work.generation!=32w0){geo_first_t.apply();geo_second_t.apply();geo_tag_t.apply();led_id_t.apply();led_pos_t.apply();}
  if(ig.ingress_port==9w68&&p.parser_err==16w0&&md.drop_ctl==3w0){if(hdr.work.generation!=32w0){
  if(m.network_allowed==8w1&&m.direction!=8w0){
   if(m.kind==8w5||m.kind==8w7){
    if(m.led_ok==8w0){deny();}
    if(m.kind==8w7){if(m.contig==8w0||(m.valid&8w1)==8w0){deny();}else{operate_shift_t.apply();}}
   }else{
    if(m.kind==8w12){if(m.ao2==32w0||m.ro1==32w0){deny();}}
    else{
     if((m.kind==8w8&&m.direction==8w1)||((m.kind==8w13||m.kind==8w6)&&m.direction==8w2)){
      if(m.valid==8w0||m.valid==8w1||m.valid==8w3){snapshot_t.apply();prepare_window_t.apply();if(m.valid!=8w3||m.so1==32w35){edges_t.apply();offsets_t.apply();
       if(m.direction==8w1){seq1.apply();seq2.apply();complete_forward_t.apply();}
       else{left1.apply();left2.apply();right1.apply();right2.apply();difference_t.apply();growth_t.apply();window_guard.apply();if(md.drop_ctl==3w0){complete_reverse_t.apply();}}
      }else{deny();}}else{deny();}
     }else{deny();}
    }
   }
  }else{deny();}
 }else{deny();}}else{deny();}}
}
control IgDeparser(packet_out pkt,inout headers_t hdr,in meta_t m,in ingress_intrinsic_metadata_for_deparser_t md){Checksum() tcpcheck;
 apply{if(m.changed==1w1){hdr.tcp.checksum=tcpcheck.update({hdr.tcp.seq,hdr.tcp.ack,hdr.tcp.control_window,m.repair_sum,16w0});}pkt.emit(hdr.work);pkt.emit(hdr.eth);pkt.emit(hdr.ip);pkt.emit(hdr.tcp);pkt.emit(hdr.dl);pkt.emit(hdr.native);pkt.emit(hdr.tail);pkt.emit(hdr.replay);}}
parser EgParser(packet_in pkt,out headers_t hdr,out meta_t m,out egress_intrinsic_metadata_t eg){state start{pkt.extract(eg);transition accept;}}
control Egress(inout headers_t hdr,inout meta_t m,in egress_intrinsic_metadata_t eg,in egress_intrinsic_metadata_from_parser_t p,inout egress_intrinsic_metadata_for_deparser_t md,inout egress_intrinsic_metadata_for_output_port_t port){apply{}}
control EgDeparser(packet_out pkt,inout headers_t hdr,in meta_t m,in egress_intrinsic_metadata_for_deparser_t md){apply{}}
Pipeline(IgParser(),Ingress(),IgDeparser(),EgParser(),Egress(),EgDeparser()) pipe;Switch(pipe) main;

/* Direction 2 grouped TCP mapping primitive. CP-seeded two-boundary state only; no handshake/producer.
 * One ingress pass completes a real pure-ACK packet; no internal placeholder completion.
 * Default forwarding/profile tables deny. No hardware qualification. */
#include <core.p4>
#include <tna.p4>
header eth_h {bit<48> dst;bit<48> src;bit<16> type;}
header ip_h {bit<4> version;bit<4> ihl;bit<8> tos;bit<16> len;bit<16> id;bit<3> flags;bit<13> frag;bit<8> ttl;bit<8> proto;bit<16> checksum;bit<32> src;bit<32> dst;}
header tcp_h {bit<16> sport;bit<16> dport;bit<32> seq;bit<32> ack;bit<4> offset;bit<4> reserved;bit<8> flags;bit<16> window;bit<16> checksum;bit<16> urgent;}
struct headers_t {eth_h eth;ip_h ip;tcp_h tcp;}
struct meta_t {bit<32> first;bit<32> second;bit<8> valid;bit<8> direction;PortId_t output_port;
 bit<32> right;bit<32> left;bit<32> native_right;bit<32> so1;bit<32> so2;bit<32> ao1;bit<32> ao2;bit<32> ro1;bit<32> ro2;
 bit<32> seq_result;bit<16> output_window;bit<32> full_window;bit<32> window_after;bit<32> original_seq;bit<32> original_ack;bit<32> growth;bit<16> original_window;bit<16> tcp_len;bit<16> tcp_sum;bool ip_error;bit<8> parsed;bit<1> changed;}
parser IgParser(packet_in pkt,out headers_t hdr,out meta_t m,out ingress_intrinsic_metadata_t ig){
 Checksum() ipcheck;Checksum() tcpcheck;
 state start{pkt.extract(ig);pkt.advance(PORT_METADATA_SIZE);m.parsed=8w0;m.changed=1w0;m.direction=8w0;m.valid=8w0;transition eth;}
 state eth{pkt.extract(hdr.eth);transition select(hdr.eth.type){16w0x0800:ip;default:accept;}}
 state ip{pkt.extract(hdr.ip);ipcheck.add(hdr.ip);m.ip_error=ipcheck.verify();tcpcheck.subtract({hdr.ip.src,hdr.ip.dst,8w0,hdr.ip.proto,hdr.ip.len});
 transition select(hdr.ip.version,hdr.ip.ihl,hdr.ip.proto,hdr.ip.len){(4w4,4w5,8w6,16w40):ip_flags;default:accept;}}
 state ip_flags{transition select(hdr.ip.frag,hdr.ip.flags){(13w0,3w0):tcp;(13w0,3w2):tcp;default:accept;}}
 state tcp{pkt.extract(hdr.tcp);tcpcheck.subtract(hdr.tcp);m.tcp_sum=tcpcheck.get();transition select(hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.flags,hdr.tcp.urgent){(4w5,4w0,8w0x10,16w0):eligible;default:accept;} }
 state eligible{m.parsed=8w1;transition accept;}
}
@pa_container_size("ingress", "hdr.tcp.seq", 32)
@pa_container_size("ingress", "hdr.tcp.ack", 32)
@pa_container_size("ingress", "m.first", 32)
@pa_container_size("ingress", "m.second", 32)
@pa_container_size("ingress", "m.right", 32)
@pa_container_size("ingress", "m.left", 32)
@pa_container_size("ingress", "m.native_right", 32)
@pa_container_size("ingress", "m.so1", 32)
@pa_container_size("ingress", "m.so2", 32)
@pa_container_size("ingress", "m.ao1", 32)
@pa_container_size("ingress", "m.ao2", 32)
@pa_container_size("ingress", "m.ro1", 32)
@pa_container_size("ingress", "m.ro2", 32)
@pa_container_size("ingress", "m.original_seq", 32)
@pa_container_size("ingress", "m.original_ack", 32)
@pa_container_size("ingress", "m.growth", 32)
@pa_container_size("ingress", "m.full_window", 32)
@pa_container_size("ingress", "m.window_after", 32)
@pa_container_size("ingress", "m.seq_result", 32)
control Ingress(inout headers_t hdr,inout meta_t m,in ingress_intrinsic_metadata_t ig,in ingress_intrinsic_metadata_from_parser_t p,inout ingress_intrinsic_metadata_for_deparser_t md,inout ingress_intrinsic_metadata_for_tm_t tm){
 action deny(){md.drop_ctl=3w1;}
 action route(PortId_t port){m.output_port=port;tm.ucast_egress_port=port;tm.bypass_egress=1w1;}
 table forwarding{key={ig.ingress_port:exact;}actions={route;deny;}size=4;default_action=deny();}
 action configure(bit<32> first,bit<32> second,bit<8> valid,bit<8> direction){m.first=first;m.second=second;m.valid=valid;m.direction=direction;}
 table connection{key={hdr.ip.src:exact;hdr.ip.dst:exact;hdr.tcp.sport:exact;hdr.tcp.dport:exact;}actions={configure;NoAction;}size=2;default_action=NoAction();}
 action prepare_window(){m.full_window=16w0++hdr.tcp.window;}
 table prepare_window_t{actions={prepare_window;}size=1;const default_action=prepare_window();}
 action edges(){m.right=hdr.tcp.ack+m.full_window;m.left=hdr.tcp.ack;m.original_ack=hdr.tcp.ack;m.original_seq=hdr.tcp.seq;m.seq_result=hdr.tcp.seq;m.original_window=hdr.tcp.window;m.tcp_len=16w20;}
 table edges_t{actions={edges;}size=1;const default_action=edges();}
 action offsets(){m.so1=m.original_seq-m.first;m.so2=m.original_seq-m.second;m.ao1=m.original_ack-m.first;m.ao2=m.original_ack-m.second;m.ro1=m.right-m.first;m.ro2=m.right-m.second;m.native_right=m.right;}
 table offsets_t{actions={offsets;}size=1;const default_action=offsets();}
action seq1_shift(){m.seq_result=m.original_seq+32w20;}
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
action seq2_shift(){m.seq_result=m.original_seq+32w40;}
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
action left1_shift(){m.left=m.original_ack-32w20;}
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
action left2_shift(){m.left=m.original_ack-32w40;}
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
action difference(){m.growth=m.native_right-m.left;m.window_after=m.native_right-m.left;}
 table difference_t{actions={difference;}size=1;const default_action=difference();}
 action growth(){m.growth=m.growth-m.full_window;}
 table growth_t{actions={growth;}size=1;const default_action=growth();}
 table window_guard{key={m.growth:ternary;}actions={deny;NoAction;}size=32;const default_action=NoAction();const entries={
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
 action window_narrow(){m.output_window=(bit<16>)m.window_after;}
 table window_narrow_t{actions={window_narrow;}size=1;const default_action=window_narrow();}
 action complete(){hdr.tcp.ack=m.left;hdr.tcp.window=m.output_window;m.changed=1w1;tm.ucast_egress_port=m.output_port;}
 table complete_t{actions={complete;}size=1;const default_action=complete();}
 apply{forwarding.apply();if(m.parsed==8w1 && !m.ip_error && m.tcp_sum==16w0xFFEB){
 connection.apply();if(m.direction!=8w0){prepare_window_t.apply();edges_t.apply();offsets_t.apply();left1.apply();left2.apply();right1.apply();right2.apply();
 {difference_t.apply();growth_t.apply();window_guard.apply();window_narrow_t.apply();complete_t.apply();}}}}
}
control IgDeparser(packet_out pkt,inout headers_t hdr,in meta_t m,in ingress_intrinsic_metadata_for_deparser_t md){Checksum() tcpcheck;apply{if(m.changed==1w1){hdr.tcp.checksum=tcpcheck.update({hdr.ip.src,hdr.ip.dst,8w0,hdr.ip.proto,m.tcp_len,hdr.tcp.sport,hdr.tcp.dport,hdr.tcp.seq,hdr.tcp.ack,hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.flags,hdr.tcp.window,hdr.tcp.urgent});}pkt.emit(hdr.eth);pkt.emit(hdr.ip);pkt.emit(hdr.tcp);}}
parser EgParser(packet_in pkt,out headers_t hdr,out meta_t m,out egress_intrinsic_metadata_t eg){state start{pkt.extract(eg);transition eth;}state eth{pkt.extract(hdr.eth);transition ip;}state ip{pkt.extract(hdr.ip);transition tcp;}state tcp{pkt.extract(hdr.tcp);transition accept;}}
control Egress(inout headers_t hdr,inout meta_t m,in egress_intrinsic_metadata_t eg,in egress_intrinsic_metadata_from_parser_t p,inout egress_intrinsic_metadata_for_deparser_t md,inout egress_intrinsic_metadata_for_output_port_t port){apply{}}
control EgDeparser(packet_out pkt,inout headers_t hdr,in meta_t m,in egress_intrinsic_metadata_for_deparser_t md){apply{pkt.emit(hdr.eth);pkt.emit(hdr.ip);pkt.emit(hdr.tcp);}}
Pipeline(IgParser(),Ingress(),IgDeparser(),EgParser(),Egress(),EgDeparser()) pipe;Switch(pipe) main;

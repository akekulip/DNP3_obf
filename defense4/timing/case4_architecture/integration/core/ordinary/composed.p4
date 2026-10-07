/* Partial ordinary SELECT, local compiler/model only. */
#include <core.p4>
#include <tna.p4>
#ifndef CASE4_EXPECTED_WORK_RECORD_P4
#define CASE4_EXPECTED_WORK_RECORD_P4
struct n_expected_work_cell_t { bit<32> generation; bit<32> phase; }
// A genuine producer emits expected phase1/2/3 in its private return packet.
// Full generation and full expected phase are compared in one atomic SALU.
// The caller must quarantine lifecycle ownership separately on raw close;
// operation3 uniquely hands SELECT to downstream processing: 3->5 pending,
// 5->7 ready-received/pinned, 7->9 terminal/free. Ready progress is NOT release
// authority: the caller must subsequently commit the current owner atomically.
// Uniform +2 needs only the two identity
// comparisons available in the SALU. Free9 is physical and reported as9;
// the caller's existing selectors must accept both free4 and free9.
// Callers derive each expected phase from an
// actual private return; this helper alone does not prove owner/cache validity.
// Normal handshake operation2 retains its actual phase3->free4 return. Global full32
// generations must not wrap; epoch and final dirty-write lifetime are caller
// authority. No shared bank write may follow a terminal that permits reuse.
control n_ExpectedWorkRecord(in bit<8> operation, in bit<32> generation,
                           in bit<32> expected_phase,
                           inout bit<32> observed_phase) {
    Register<n_expected_work_cell_t, bit<1>>(1, {0, 4}) work;
    RegisterAction<n_expected_work_cell_t, bit<1>, bit<32>>(work) claim = {
        void apply(inout n_expected_work_cell_t value, out bit<32> old_phase) {
            old_phase = value.phase;
            if (value.phase == 4 || value.phase == 9) {
                value.generation = generation; value.phase = 1;
            }
        }
    };
    RegisterAction<n_expected_work_cell_t, bit<1>, bit<32>>(work) advance = {
        void apply(inout n_expected_work_cell_t value, out bit<32> old_phase) {
            old_phase = 0;
            if (value.generation == generation && value.phase == expected_phase) {
                old_phase = value.phase; value.phase = value.phase + 1;
            }
        }
    };
    RegisterAction<n_expected_work_cell_t, bit<1>, bit<32>>(work) downstream = {
        void apply(inout n_expected_work_cell_t value, out bit<32> old_phase) {
            old_phase = 0;
            if (value.generation == generation && value.phase == expected_phase) {
                old_phase = value.phase;
                value.phase = value.phase + 2;
            }
        }
    };
    RegisterAction<n_expected_work_cell_t, bit<1>, bit<32>>(work) read = {
        void apply(inout n_expected_work_cell_t value, out bit<32> old_phase) {
            old_phase = value.phase;
            // Closed dispatch below supplies phase0 for read, never a live
            // phase; phase5 is exclusively the genuine pre-M local abort.
            // Returned raw phase is not a qualified success indication.
            if (value.generation == generation && value.phase == expected_phase) {
                value.phase = 9;
            }
        }
    };
    action claim_work() { observed_phase = claim.execute(0); }
    action return_work() { observed_phase = advance.execute(0); }
    action read_work() { observed_phase = read.execute(0); }
    action abort_read() { observed_phase = read.execute(0); }
    action downstream_work() { observed_phase = downstream.execute(0); }
    action unavailable_work() { observed_phase = 0; }
    table dispatch {
        key = { operation : exact; generation : ternary; expected_phase : ternary; }
        actions = { claim_work; return_work; read_work; abort_read; downstream_work; unavailable_work; }
        const entries = {
            (0, _, 0) : read_work();
            (1, 0, _) : unavailable_work();
            (1, _, _) : claim_work();
            (2, _, 1) : return_work();
            (2, _, 2) : return_work();
            (2, _, 3) : return_work();
            (2, _, _) : unavailable_work();
            (3, _, 3) : downstream_work();
            (3, _, 5) : downstream_work();
            (3, _, 7) : downstream_work();
            (3, _, _) : unavailable_work();
            (4, _, 5) : abort_read();
        }
        const default_action = unavailable_work(); size = 12;
    }
    apply { dispatch.apply(); }
}
#endif

/* Actual native binding structural experiment, not full target qualification.
 * No receipt/reuse qualification or physical deployment.
 * Protected real-packet handshake candidate. No device configuration.
 * Four passes: validate/reserve/snapshot; write/current-owner CAS;
 * current-owner publication; actual WorkRecord terminal return.
 * Fixed stage order WorkRecord -> epoch/client/server banks -> owner.
 * Lost original/producer remains pinned. No verified retirement/reuse.
 * Actual native35 final ACK+SELECT admitted; composed transformation remains blocked.
 * Epoch/work are full32. Owner generation16 is nonwrapping.
 */
const PortId_t n_RETURN_PORT=9w68;
const PortId_t n_READ_HANDOFF_PORT=9w325;
const PortId_t n_STEP3_M_PORT=9w196;
header n_dl_h{bit<16> magic;bit<8> len;bit<8> ctrl;bit<16> dst;bit<16> src;bit<16> crc;}
header n_block_h{bit<32> w0;bit<32> w1;bit<32> w2;bit<32> w3;bit<16> crc;}
header n_tail_h{bit<32> off;bit<8> status;bit<16> crc;}
header n_response_tail_h{bit<32> w0;bit<32> w1;bit<8> w2;bit<16> crc;}
struct n_object_pair_t{bit<32> first;bit<32> second;}
header n_read_req_h{bit<8> tp;bit<8> app;bit<8> func;bit<8> group;bit<8> variation;bit<8> qualifier;bit<8> first;bit<8> last;bit<16> crc;}
header n_read_tail_h{bit<8> value;bit<16> crc;}
header n_t0_h{bit<32> t0q;}
header n_replay_h{bit<8> value;}
header n_eth_h{bit<48> dst;bit<48> src;bit<16> type;}
header n_ip_h{bit<4> version;bit<4> ihl;bit<8> tos;bit<16> len;bit<16> id;bit<3> flags;bit<13> frag;bit<8> ttl;bit<8> proto;bit<16> checksum;bit<32> src;bit<32> dst;}
header n_tcp_h{bit<16> sport;bit<16> dport;bit<32> seq;bit<32> ack;bit<4> offset;bit<4> reserved;bit<8> flags;bit<16> window;bit<16> checksum;bit<16> urgent;}
header n_mss_h{bit<8> kind;bit<8> len;bit<16> value;}
header n_envelope_h{bit<32> epoch;}
header n_work_generation_h{bit<32> generation;}
header n_expected_cell_h{bit<32> expected_cell;}
header n_event_h{bit<16> event;bit<16> reserved;}
header n_captured_decoy_h{bit<16> index;bit<8> code;bit<8> repeat;bit<32> on;bit<32> off;}
header n_cache_reference_h{bit<32> generation;bit<32> expected_owner;}
header n_completion_stamp_h{bit<32> epoch;}
header n_image_h{bit<32> w0;bit<32> w1;bit<32> w2;bit<32> w3;bit<32> w4;bit<32> w5;bit<32> w6;bit<32> w7;bit<32> w8;bit<32> w9;bit<32> w10;bit<32> w11;bit<32> w12;bit<24> w13;}
struct n_headers_t{n_envelope_h envelope;n_work_generation_h work_generation;n_expected_cell_h expected_cell;n_event_h event;n_cache_reference_h cache;n_completion_stamp_h completion;n_captured_decoy_h captured;n_t0_h t0;n_eth_h eth;n_ip_h ip;n_tcp_h tcp;n_mss_h mss;n_dl_h dl;n_block_h first;n_block_h second;n_tail_h tail;n_response_tail_h response_tail;n_read_req_h rd_req;n_read_tail_h rd_tail;n_replay_h rb;n_image_h image;}
struct n_meta_t{bit<32> terminal_diff;bit<32> active_gen_diff;bit<32> cached_owner_diff;bit<8> cache_mode;bit<8> association_allowed;bit<8> response;bit<8> matched;bit<8> operate_qualified;bit<32> prefix_difference;bit<32> accepted_diff;bit<16> crc1;bit<8> bad1;bit<32> compare_real_links;bit<32> diff_real_links;bit<32> compare_real_tcp_src;bit<32> compare_real_tcp_dst;bit<32> diff_real_tcp_dst;bit<32> compare_real_tcp_ports;bit<32> compare_real_object;bit<32> diff_real_object;bit<32> compare_real_on;bit<32> compare_real_off;bit<32> diff_real_off;bit<32> compare_native_start;bit<32> compare_native_end;bit<32> diff_native_end;bit<32> compare_server_start;bit<32> compare_application;bit<32> diff_application;bit<32> compare_frozen_decoy_object;bit<32> diff_frozen_decoy_object;bit<32> compare_frozen_decoy_on;bit<32> compare_frozen_decoy_off;bit<32> diff_frozen_decoy_off;bit<32> context_generation;bit<32> native_end;bit<8> enabled;bit<8> profile;bit<8> changed;bit<16> tcp_length;bit<16> decoy_index;bit<8> decoy_code;bit<8> decoy_repeat;bit<32> decoy_on;bit<32> decoy_off;bit<16> hcrc;bit<16> bcrc;bit<16> tcrc;bit<8> badh;bit<8> badb;bit<8> badt;bit<8> return_abort;bit<8> data_valid;bit<32> ack_native;bit<32> expected_work_phase;bit<8> go;bit<16> link_dst;bit<16> link_src;bit<32> compare_read_app;bit<8> parsed;bit<8> port_valid;bit<8> direction;bit<8> network_valid;bit<8> shape_valid;bit<8> packet_kind;bit<8> stage;bit<8> kind;bit<8> work_op;bit<8> owner_op;bit<8> sequence_valid;bit<8> epoch_valid;bit<8> emit_loop;PortId_t output_port;bool ip_error;bit<16> tcp_sum;bit<32> counter;bit<32> generation;bit<32> work_phase;bit<32> epoch;bit<32> client;bit<32> server;bit<32> new_seq;bit<32> client_diff;bit<32> server_diff;bit<32> epoch_diff;bit<32> expected;bit<32> desired;bit<32> observed;bit<32> owner_diff;}
parser n_IgParser(packet_in pkt,out n_headers_t hdr,out n_meta_t m,out ingress_intrinsic_metadata_t ig){
 Checksum() ic;Checksum() tc;
 state start{pkt.extract(ig);pkt.advance(PORT_METADATA_SIZE);m.parsed=8w0;m.enabled=8w0;m.profile=8w0;m.response=8w0;m.matched=8w0;m.data_valid=8w0;m.cache_mode=8w0;m.badh=8w0;m.badb=8w0;m.bad1=8w0;m.badt=8w0;m.stage=8w0;m.kind=8w0;m.port_valid=8w0;m.direction=8w0;m.network_valid=8w0;m.shape_valid=8w0;m.sequence_valid=8w0;m.epoch_valid=8w0;m.emit_loop=8w0;transition select(ig.ingress_port){n_RETURN_PORT:envelope;default:eth;}}
 state envelope{pkt.extract(hdr.envelope);transition select(hdr.envelope.epoch){32w0:accept;default:envelope_generation;}}
 state envelope_generation{pkt.extract(hdr.work_generation);transition select(hdr.work_generation.generation){32w0:accept;default:envelope_expected;}}
 state envelope_expected{pkt.extract(hdr.expected_cell);pkt.extract(hdr.event);m.stage=hdr.event.event[15:8];m.kind=hdr.event.event[7:0];transition envelope_reserved;}
 state envelope_reserved{transition select(hdr.event.reserved){16w0:envelope_event;16w1:captured_event;16w2:ready_event;16w3:terminal_event;default:accept;}}
 state ready_event{transition select(hdr.event.event){16w0x0514:ready_cache;16w0x0614:ready_cache;16w0x0b14:ready_cache;16w0x0e14:ready_cache;16w0x1014:ready_cache;default:accept;}}
 state terminal_event{transition select(hdr.event.event){16w0x0f14:terminal_cache;16w0x1214:terminal_cache;default:accept;}}
 state terminal_cache{pkt.extract(hdr.cache);pkt.extract(hdr.completion);transition ready_eth;}
 state ready_cache{pkt.extract(hdr.cache);transition ready_eth;}
 state ready_eth{pkt.extract(hdr.eth);transition select(hdr.eth.type){16w0x0800:ready_ip;default:accept;}}
 state ready_ip{pkt.extract(hdr.ip);ic.add(hdr.ip);m.ip_error=ic.verify();tc.subtract({hdr.ip.src,hdr.ip.dst,8w0,hdr.ip.proto,hdr.ip.len});transition select(hdr.ip.version,hdr.ip.ihl,hdr.ip.proto,hdr.ip.len){(4w4,4w5,8w6,16w95):ready_ip_flags;default:accept;}}
 state captured_event{transition select(hdr.event.event){16w0x0105:captured_decoy;16w0x0205:captured_decoy;16w0x0305:captured_decoy;16w0x01ff:captured_decoy;16w0x02ff:captured_decoy;16w0x03ff:captured_decoy;16w0x05ff:captured_decoy;default:accept;}}
 state captured_decoy{pkt.extract(hdr.captured);transition eth;}
 state envelope_event{transition select(hdr.event.event){16w0x0101:eth;16w0x0102:eth;16w0x0103:eth;16w0x0104:eth;16w0x01ff:eth;16w0x0201:eth;16w0x0202:eth;16w0x0203:eth;16w0x02ff:eth;16w0x0301:eth;16w0x0302:eth;16w0x0303:eth;16w0x03ff:eth;16w0x0106:eth;16w0x0107:eth;16w0x0108:eth;16w0x0206:eth;16w0x0207:eth;16w0x0208:eth;16w0x0306:eth;16w0x0307:eth;16w0x0308:eth;16w0x0109:read_t0;16w0x010a:read_t0;16w0x010b:read_t0;16w0x0209:read_t0;16w0x020a:read_t0;16w0x020b:read_t0;16w0x0309:read_t0;16w0x030a:read_t0;16w0x030b:read_t0;16w0x0110:eth;16w0x010c:eth;16w0x0210:eth;16w0x020c:eth;16w0x0310:eth;16w0x030c:eth;default:accept;}}
 state eth{pkt.extract(hdr.eth);transition select(hdr.eth.type){16w0x0800:ip;default:accept;}}
 state ip{pkt.extract(hdr.ip);ic.add(hdr.ip);m.ip_error=ic.verify();tc.subtract({hdr.ip.src,hdr.ip.dst,8w0,hdr.ip.proto,hdr.ip.len});transition select(hdr.ip.version,hdr.ip.ihl,hdr.ip.proto,hdr.ip.len){(4w4,4w5,8w6,16w40):ip_flags;(4w4,4w5,8w6,16w44):ip_flags;(4w4,4w5,8w6,16w75):native_ip_flags;(4w4,4w5,8w6,16w97):response_ip_flags;(4w4,4w5,8w6,16w60):read_ip_flags;(4w4,4w5,8w6,16w89):read_response_ip_flags;(4w4,4w5,8w6,16w41):replay_ip_flags;default:accept;}}
 state ip_flags{transition select(hdr.ip.frag,hdr.ip.flags){(13w0,3w0):tcp;(13w0,3w2):tcp;default:accept;}}
 state tcp{pkt.extract(hdr.tcp);tc.subtract(hdr.tcp);transition select(hdr.tcp.offset,hdr.ip.len,hdr.tcp.flags){(4w6,16w44,8w2):mss_syn;(4w6,16w44,8w18):mss_synack;(4w5,16w40,8w16):ack;(4w5,16w40,8w17):close;(4w5,16w40,8w20):close;(4w5,16w40,8w4):close;default:accept;}}
 state mss_syn{pkt.extract(hdr.mss);tc.subtract(hdr.mss);m.packet_kind=8w1;transition mss_check;}
 state mss_synack{pkt.extract(hdr.mss);tc.subtract(hdr.mss);m.packet_kind=8w2;transition mss_check;}
 state mss_check{transition select(hdr.mss.kind,hdr.mss.len,hdr.mss.value){(8w2,8w4,16w57..16w65535):finish;default:accept;}}
 state ack{m.packet_kind=8w3;transition finish;}
 state close{m.packet_kind=8w4;transition finish;}
 state ready_ip_flags{transition select(hdr.ip.frag,hdr.ip.flags){(13w0,3w0):ready_tcp;(13w0,3w2):ready_tcp;default:accept;}}
 state ready_tcp{pkt.extract(hdr.tcp);tc.subtract(hdr.tcp);transition select(hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.urgent,hdr.tcp.flags){(4w5,4w0,16w0,8w16):ready_image;(4w5,4w0,16w0,8w24):ready_image;default:accept;}}
 state ready_image{pkt.extract(hdr.image);tc.subtract(hdr.image);m.packet_kind=8w20;transition finish;}
 state native_ip_flags{transition select(hdr.ip.frag,hdr.ip.flags){(13w0,3w0):native_tcp;(13w0,3w2):native_tcp;default:accept;}}
 state native_tcp{pkt.extract(hdr.tcp);tc.subtract(hdr.tcp);transition select(hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.urgent,hdr.tcp.flags){(4w5,4w0,16w0,8w16):native_dl;(4w5,4w0,16w0,8w24):native_dl;default:accept;}}
 state native_dl{pkt.extract(hdr.dl);tc.subtract(hdr.dl);transition native_block;}
 state response_ip_flags{transition select(hdr.ip.frag,hdr.ip.flags){(13w0,3w0):response_tcp;(13w0,3w2):response_tcp;default:accept;}}
 state response_tcp{pkt.extract(hdr.tcp);tc.subtract(hdr.tcp);transition select(hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.urgent,hdr.tcp.flags){(4w5,4w0,16w0,8w16):response_dl;(4w5,4w0,16w0,8w24):response_dl;default:accept;}}
 state response_dl{pkt.extract(hdr.dl);tc.subtract(hdr.dl);transition response_block;}
 state read_ip_flags{transition select(hdr.ip.frag,hdr.ip.flags){(13w0,3w0):read_tcp;(13w0,3w2):read_tcp;default:accept;}}
 state read_tcp{pkt.extract(hdr.tcp);tc.subtract(hdr.tcp);transition select(hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.urgent,hdr.tcp.flags){(4w5,4w0,16w0,8w16):read_dl;(4w5,4w0,16w0,8w24):read_dl;default:accept;}}
 state read_dl{pkt.extract(hdr.dl);tc.subtract(hdr.dl);transition read_request;}
 state read_response_ip_flags{transition select(hdr.ip.frag,hdr.ip.flags){(13w0,3w0):read_response_tcp;(13w0,3w2):read_response_tcp;default:accept;}}
 state read_response_tcp{pkt.extract(hdr.tcp);tc.subtract(hdr.tcp);transition select(hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.urgent,hdr.tcp.flags){(4w5,4w0,16w0,8w16):read_response_dl;(4w5,4w0,16w0,8w24):read_response_dl;default:accept;}}
 state read_response_dl{pkt.extract(hdr.dl);tc.subtract(hdr.dl);transition read_response_block;}
 state replay_ip_flags{transition select(hdr.ip.frag,hdr.ip.flags){(13w0,3w0):replay_tcp;(13w0,3w2):replay_tcp;default:accept;}}
 state replay_tcp{pkt.extract(hdr.tcp);tc.subtract(hdr.tcp);transition select(hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.urgent,hdr.tcp.flags){(4w5,4w0,16w0,8w16):replay_byte;default:accept;}}
 state replay_byte{pkt.extract(hdr.rb);tc.subtract(hdr.rb);m.packet_kind=8w12;transition finish;}
 state read_request{pkt.extract(hdr.rd_req);tc.subtract(hdr.rd_req);m.packet_kind=8w9;transition finish;}
 state read_response_block{pkt.extract(hdr.first);tc.subtract(hdr.first);transition read_response_second;}
 state read_response_second{pkt.extract(hdr.second);tc.subtract(hdr.second);transition read_response_tail;}
 state read_response_tail{pkt.extract(hdr.rd_tail);tc.subtract(hdr.rd_tail);m.packet_kind=8w11;transition finish;}
 state read_t0{pkt.extract(hdr.t0);transition eth;}
 state native_block{pkt.extract(hdr.first);tc.subtract(hdr.first);transition native_tail;}
 state native_tail{pkt.extract(hdr.tail);tc.subtract(hdr.tail);transition select(hdr.first.w0[15:8]){8w3:select_finish;8w4:operate_finish;default:accept;}}
 state select_finish{m.packet_kind=8w5;transition finish;}
 state operate_finish{m.packet_kind=8w7;transition finish;}
 state response_block{pkt.extract(hdr.first);tc.subtract(hdr.first);transition response_second;}
 state response_second{pkt.extract(hdr.second);tc.subtract(hdr.second);transition response_tail;}
 state response_tail{pkt.extract(hdr.response_tail);tc.subtract(hdr.response_tail);m.response=8w1;m.packet_kind=8w6;transition finish;}
 state finish{m.tcp_sum=tc.get();m.parsed=8w1;m.shape_valid=8w1;transition accept;}

}
control n_Ingress(inout n_headers_t hdr,inout n_meta_t m,in ingress_intrinsic_metadata_t ig,in ingress_intrinsic_metadata_from_parser_t p,inout ingress_intrinsic_metadata_for_deparser_t md,inout ingress_intrinsic_metadata_for_tm_t tm){
 n_ExpectedWorkRecord() work;
 Register<bit<32>,bit<1>>(1,0) counter;
 RegisterAction<bit<32>,bit<1>,bit<32>>(counter) allocate={void apply(inout bit<32> v,out bit<32> r){r=32w0;if((int<32>)v!=-1){v=v+32w1;r=v;}}};
 Register<bit<32>,bit<1>>(1,0) owner;
 RegisterAction<bit<32>,bit<1>,bit<32>>(owner) check_owner={void apply(inout bit<32> v,out bit<32> r){r=v-m.expected;}};
 RegisterAction<bit<32>,bit<1>,bit<32>>(owner) read_owner={void apply(inout bit<32> v,out bit<32> r){r=v;}};
 RegisterAction<bit<32>,bit<1>,bit<32>>(owner) compare_owner={void apply(inout bit<32> v,out bit<32> r){r=v-m.expected;if(v==m.expected){v=m.desired;}}};
 Register<bit<32>,bit<4>>(4,0) count_first;
RegisterAction<bit<32>,bit<4>,bit<32>>(count_first) count_first_bump={void apply(inout bit<32> v,out bit<32> r){if((int<32>)v!=-1){v=v+32w1;}r=v;}};
Register<bit<32>,bit<4>>(4,0) count_busy;
RegisterAction<bit<32>,bit<4>,bit<32>>(count_busy) count_busy_bump={void apply(inout bit<32> v,out bit<32> r){if((int<32>)v!=-1){v=v+32w1;}r=v;}};
Register<bit<32>,bit<4>>(4,0) count_term;
RegisterAction<bit<32>,bit<4>,bit<32>>(count_term) count_term_bump={void apply(inout bit<32> v,out bit<32> r){if((int<32>)v!=-1){v=v+32w1;}r=v;}};
 action deny(){md.drop_ctl=3w1;}
 action route(PortId_t port){m.port_valid=8w1;tm.ucast_egress_port=port;tm.bypass_egress=1w1;}
 table ports{key={ig.ingress_port:exact;}actions={route;deny;}size=4;default_action=deny();}
 action forward_flow(PortId_t port){m.direction=8w1;m.output_port=port;tm.ucast_egress_port=port;}
 action reverse_flow(PortId_t port){m.direction=8w2;m.output_port=port;tm.ucast_egress_port=port;}
 table connection{key={hdr.ip.src:exact;hdr.ip.dst:exact;hdr.tcp.sport:exact;hdr.tcp.dport:exact;}actions={forward_flow;reverse_flow;NoAction;}size=2;default_action=NoAction();}
 action network_accept(){m.network_valid=8w1;}
 table network{key={m.parsed:exact;m.kind:exact;hdr.tcp.flags:ternary;m.ip_error:exact;m.tcp_sum:exact;hdr.ip.ttl:range;hdr.tcp.reserved:exact;hdr.tcp.urgent:exact;}actions={network_accept;NoAction;}size=32;const default_action=NoAction();const entries={(8w1,8w20,8w16,false,16w0xffeb,8w1..8w255,4w0,16w0):network_accept();(8w1,8w20,8w24,false,16w0xffeb,8w1..8w255,4w0,16w0):network_accept();(8w1,8w0,_,false,16w0xffeb,8w1..8w255,4w0,16w0):network_accept();(8w1,8w1,8w2,false,16w0xffeb,8w1..8w255,4w0,16w0):network_accept();(8w1,8w2,8w18,false,16w0xffeb,8w1..8w255,4w0,16w0):network_accept();(8w1,8w3,8w16,false,16w0xffeb,8w1..8w255,4w0,16w0):network_accept();(8w1,8w4,8w17,false,16w0xffeb,8w1..8w255,4w0,16w0):network_accept();(8w1,8w4,8w20,false,16w0xffeb,8w1..8w255,4w0,16w0):network_accept();(8w1,8w4,8w4,false,16w0xffeb,8w1..8w255,4w0,16w0):network_accept();(8w1,8w255,_,false,16w0xffeb,8w1..8w255,4w0,16w0):network_accept();(8w1,8w5,8w16,false,16w0xffeb,8w1..8w255,4w0,16w0):network_accept();(8w1,8w5,8w24,false,16w0xffeb,8w1..8w255,4w0,16w0):network_accept();(8w1,8w6,8w16,false,16w0xffeb,8w1..8w255,4w0,16w0):network_accept();(8w1,8w6,8w24,false,16w0xffeb,8w1..8w255,4w0,16w0):network_accept();(8w1,8w7,8w16,false,16w0xffeb,8w1..8w255,4w0,16w0):network_accept();(8w1,8w7,8w24,false,16w0xffeb,8w1..8w255,4w0,16w0):network_accept();(8w1,8w8,8w2,false,16w0xffeb,8w1..8w255,4w0,16w0):network_accept();(8w1,8w8,8w18,false,16w0xffeb,8w1..8w255,4w0,16w0):network_accept();(8w1,8w8,8w16,false,16w0xffeb,8w1..8w255,4w0,16w0):network_accept();(8w1,8w9,8w16,false,16w0xffeb,8w1..8w255,4w0,16w0):network_accept();(8w1,8w9,8w24,false,16w0xffeb,8w1..8w255,4w0,16w0):network_accept();(8w1,8w10,8w16,false,16w0xffeb,8w1..8w255,4w0,16w0):network_accept();(8w1,8w11,8w16,false,16w0xffeb,8w1..8w255,4w0,16w0):network_accept();(8w1,8w11,8w24,false,16w0xffeb,8w1..8w255,4w0,16w0):network_accept();(8w1,8w16,8w16,false,16w0xffeb,8w1..8w255,4w0,16w0):network_accept();(8w1,8w16,8w24,false,16w0xffeb,8w1..8w255,4w0,16w0):network_accept();(8w1,8w12,8w16,false,16w0xffeb,8w1..8w255,4w0,16w0):network_accept();}}
 action syn_shape(){m.shape_valid=8w1;m.kind=8w1;}
 action synack_shape(){m.shape_valid=8w1;m.kind=8w2;}
 table syn_shapes{key={m.direction:exact;hdr.tcp.flags:exact;hdr.mss.kind:exact;hdr.mss.len:exact;hdr.mss.value:range;}
 actions={syn_shape;synack_shape;NoAction;}size=2;const default_action=NoAction();const entries={(8w1,8w2,8w2,8w4,16w57..16w65535):syn_shape();(8w2,8w18,8w2,8w4,16w57..16w65535):synack_shape();}}
 action ack_shape(){m.shape_valid=8w1;m.kind=8w3;}
 action close_shape(){m.shape_valid=8w1;m.kind=8w4;}
 table short_shapes{key={m.direction:exact;hdr.tcp.flags:exact;}
 actions={ack_shape;close_shape;NoAction;}size=7;const default_action=NoAction();const entries={(8w1,8w16):ack_shape();(8w1,8w17):close_shape();(8w2,8w17):close_shape();(8w1,8w20):close_shape();(8w2,8w20):close_shape();(8w1,8w4):close_shape();(8w2,8w4):close_shape();}}
 action configure(bit<16> index,bit<8> code,bit<8> repeat,bit<32> on,bit<32> off){m.enabled=8w1;m.decoy_index=index;m.decoy_code=code;m.decoy_repeat=repeat;m.decoy_on=on;m.decoy_off=off;}
 table data_connection{key={hdr.ip.src:exact;hdr.ip.dst:exact;hdr.tcp.sport:exact;hdr.tcp.dport:exact;}actions={configure;NoAction;}size=2;default_action=NoAction();}
 action eligible(){m.profile=8w1;}
 table profile{key={hdr.dl.magic:exact;hdr.dl.len:exact;hdr.dl.ctrl:exact;hdr.first.w0[31:24]:ternary;hdr.first.w0[23:16]:ternary;hdr.first.w0[15:8]:exact;hdr.first.w0[7:0]:exact;hdr.first.w1[31:24]:exact;hdr.first.w1[23:16]:exact;hdr.first.w1[15:0]:exact;hdr.tail.status:exact;}
 actions={eligible;NoAction;}size=2;const default_action=NoAction();const entries={(16w0x0564,8w26,8w0xC4,8w0xC0&&&8w0xC0,8w0xC0&&&8w0xF0,8w3,8w12,8w1,8w0x28,16w0x0100,8w0):eligible();(16w0x0564,8w26,8w0xC4,8w0xC0&&&8w0xC0,8w0xC0&&&8w0xF0,8w4,8w12,8w1,8w0x28,16w0x0100,8w0):eligible();}}
 CRCPolynomial<bit<16>>(16w0x3D65,true,false,false,16w0,16w0xFFFF) poly;
Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_head;
Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_body;
Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_tail;
action input_head(){m.hcrc=hash_head.get({hdr.dl.magic,hdr.dl.len,hdr.dl.ctrl,hdr.dl.dst,hdr.dl.src});}
table input_head_t{actions={input_head;}size=1;const default_action=input_head();}
action input_body(){m.bcrc=hash_body.get({hdr.first.w0[31:24],hdr.first.w0[23:16],hdr.first.w0[15:8],hdr.first.w0[7:0],hdr.first.w1[31:24],hdr.first.w1[23:16],hdr.first.w1[15:0],hdr.first.w2[31:16],hdr.first.w2[15:8],hdr.first.w2[7:0],hdr.first.w3});}
table input_body_t{actions={input_body;}size=1;const default_action=input_body();}
action input_tail(){m.tcrc=hash_tail.get({hdr.tail.off,hdr.tail.status});}
table input_tail_t{actions={input_tail;}size=1;const default_action=input_tail();}
table response_profile{key={hdr.dl.magic:exact;hdr.dl.len:exact;hdr.dl.ctrl:exact;hdr.first.w0[31:24]:ternary;hdr.first.w0[23:16]:ternary;hdr.first.w0[15:0]:exact;hdr.first.w1:exact;hdr.first.w2[31:16]:exact;hdr.second.w1[15:0]:exact;hdr.second.w2:exact;hdr.response_tail.w2:exact;}
 actions={eligible;NoAction;}size=1;const default_action=NoAction();const entries={(16w0x0564,8w46,8w0x44,8w0xc0&&&8w0xc0,8w0xc0&&&8w0xf0,16w0x8100,32w0x000c0128,16w0x0100,16w0x000c,32w0x01280100,8w0):eligible();}}
Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_first;
action response_crc0(){m.bcrc=hash_first.get({hdr.first.w0,hdr.first.w1,hdr.first.w2,hdr.first.w3});}
table response_crc0_t{actions={response_crc0;}size=1;const default_action=response_crc0();}
Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_second;
action response_crc1(){m.crc1=hash_second.get({hdr.second.w0,hdr.second.w1,hdr.second.w2,hdr.second.w3});}
table response_crc1_t{actions={response_crc1;}size=1;const default_action=response_crc1();}
Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_response_tail;
action response_crct(){m.tcrc=hash_response_tail.get({hdr.response_tail.w0,hdr.response_tail.w1,hdr.response_tail.w2});}
table response_crct_t{actions={response_crct;}size=1;const default_action=response_crct();}
 action available(){m.work_op=8w1;}
 table available_t{key={m.generation:exact;}actions={available;NoAction;}size=1;const entries={32w0:NoAction();}const default_action=available();}
 Register<bit<32>,bit<1>>(1,0) epoch;
 RegisterAction<bit<32>,bit<1>,bit<32>>(epoch) read_epoch={void apply(inout bit<32> v,out bit<32> r){r=v;}};
 RegisterAction<bit<32>,bit<1>,bit<32>>(epoch) read_epoch_diff={void apply(inout bit<32> v,out bit<32> r){r=v-hdr.envelope.epoch;}};
 RegisterAction<bit<32>,bit<1>,bit<32>>(epoch) write_epoch={void apply(inout bit<32> v,out bit<32> r){v=hdr.envelope.epoch;r=32w0;}};
 action load_epoch(){m.epoch=read_epoch.execute(1w0);}
 action diff_epoch(){m.epoch_diff=read_epoch_diff.execute(1w0);}
 action store_epoch(){m.epoch_diff=write_epoch.execute(1w0);}
 table epoch_t{key={m.stage:ternary;m.kind:ternary;m.work_phase:ternary;m.work_op:ternary;}actions={load_epoch;diff_epoch;store_epoch;}size=3;
 const entries={(8w1,8w1,32w1,8w2):store_epoch();(8w0,_,_,_):load_epoch();}const default_action=diff_epoch();}
 Register<bit<32>,bit<1>>(1,0) client;
 RegisterAction<bit<32>,bit<1>,bit<32>>(client) read_client={void apply(inout bit<32> v,out bit<32> r){r=v;}};
 RegisterAction<bit<32>,bit<1>,bit<32>>(client) write_client={void apply(inout bit<32> v,out bit<32> r){r=v;v=m.new_seq;}};
 action load_client(){m.client=read_client.execute(1w0);}
 action store_client(){m.client=write_client.execute(1w0);}
 table client_t{key={m.stage:exact;m.kind:exact;m.work_phase:exact;m.work_op:exact;m.epoch_diff:exact;}actions={load_client;store_client;}size=4;
 const entries={(8w1,8w1,32w1,8w2,32w0):store_client();(8w1,8w5,32w1,8w2,32w0):store_client();(8w1,8w7,32w1,8w2,32w0):store_client();(8w1,8w9,32w1,8w2,32w0):store_client();}const default_action=load_client();}
 Register<bit<32>,bit<1>>(1,0) server;
 RegisterAction<bit<32>,bit<1>,bit<32>>(server) read_server={void apply(inout bit<32> v,out bit<32> r){r=v;}};
 RegisterAction<bit<32>,bit<1>,bit<32>>(server) write_server={void apply(inout bit<32> v,out bit<32> r){r=v;v=m.new_seq;}};
 action load_server(){m.server=read_server.execute(1w0);}
 action store_server(){m.server=write_server.execute(1w0);}
 table server_t{key={m.stage:exact;m.kind:exact;m.work_phase:exact;m.work_op:exact;m.epoch_diff:exact;}actions={load_server;store_server;}size=4;
 const entries={(8w1,8w2,32w1,8w2,32w0):store_server();(8w1,8w6,32w1,8w2,32w0):store_server();(8w1,8w11,32w1,8w2,32w0):store_server();(8w1,8w16,32w1,8w2,32w0):store_server();}const default_action=load_server();}
 action next_seq(){m.new_seq=hdr.tcp.seq+32w1;}
 action next_control(){m.new_seq=hdr.tcp.seq+32w35;}
 action next_response(){m.new_seq=hdr.tcp.seq+32w57;}
 action next_read_request(){m.new_seq=hdr.tcp.seq+32w20;}
 action next_read_response(){m.new_seq=hdr.tcp.seq+32w49;}
 table next_seq_t{key={m.packet_kind:exact;}actions={next_seq;next_control;next_response;next_read_request;next_read_response;}size=5;const entries={8w5:next_control();8w7:next_control();8w6:next_response();8w9:next_read_request();8w11:next_read_response();}const default_action=next_seq();}
 action diff_syn(){m.client_diff=hdr.tcp.ack;m.server_diff=32w0;}
 action diff_synack(){m.client_diff=hdr.tcp.ack-m.client;m.server_diff=32w0;}
 action diff_forward(){m.client_diff=hdr.tcp.seq-m.client;m.server_diff=hdr.tcp.ack-m.server;}
 action diff_reverse(){m.client_diff=hdr.tcp.seq-m.server;m.server_diff=hdr.tcp.ack-m.client;}
 action diff_reset_forward(){m.client_diff=hdr.tcp.seq-m.client;m.server_diff=32w0;}
 action diff_reset_reverse(){m.client_diff=hdr.tcp.seq-m.server;m.server_diff=32w0;}
 action ack_native(){m.ack_native=hdr.tcp.ack-32w20;}
 table ack_native_t{actions={ack_native;}size=1;const default_action=ack_native();}
 action diff_response(){m.client_diff=m.ack_native-m.client;m.server_diff=hdr.tcp.seq-m.server;}
 action diff_read_response(){m.client_diff=hdr.tcp.ack-m.client;m.server_diff=hdr.tcp.seq-m.server;}
 table sequence_diff{key={m.packet_kind:ternary;m.direction:ternary;hdr.tcp.flags:ternary;}
 actions={diff_syn;diff_synack;diff_forward;diff_reverse;diff_reset_forward;diff_reset_reverse;diff_response;diff_read_response;NoAction;}size=20;const default_action=NoAction();
 const entries={(8w5,_,_):diff_forward();(8w6,_,_):diff_response();(8w7,_,_):diff_forward();(8w9,_,_):diff_forward();(8w11,_,_):diff_read_response();(_,8w1,8w2):diff_syn();(_,8w2,8w18):diff_synack();(_,8w1,8w16):diff_forward();(_,8w1,8w17):diff_forward();(_,8w2,8w17):diff_reverse();(_,8w1,8w20):diff_forward();(_,8w2,8w20):diff_reverse();(_,8w1,8w4):diff_reset_forward();(_,8w2,8w4):diff_reset_reverse();(8w3,8w2,8w16):diff_reverse();}}
 action seq_ok(){m.sequence_valid=8w1;}
 action seq_ok_second(){m.sequence_valid=8w2;}
 action seq_resent(){m.sequence_valid=8w3;}
 action seq_replay(){m.sequence_valid=8w4;}
 table sequence_guard{key={m.client_diff:exact;m.server_diff:exact;}actions={seq_ok;seq_ok_second;seq_resent;seq_replay;NoAction;}size=4;const entries={(32w0,32w0):seq_ok();(32w20,32w0):seq_ok_second();(32w0xffffffdd,32w0):seq_resent();(32w0xffffffff,32w0):seq_replay();}const default_action=NoAction();}
 action epoch_ok(){m.epoch_valid=8w1;}
 table epoch_guard{key={m.epoch_diff:exact;}actions={epoch_ok;NoAction;}size=1;const entries={32w0:epoch_ok();}const default_action=NoAction();}
 action claim_syn(){m.expected=hdr.expected_cell.expected_cell;m.desired=hdr.expected_cell.expected_cell+32w0x10001;m.owner_op=8w1;}
 action claim_synack(){m.expected=hdr.expected_cell.expected_cell;m.desired=hdr.expected_cell.expected_cell+32w0x10000;m.owner_op=8w1;}
 action claim_ack(){m.expected=hdr.expected_cell.expected_cell;m.desired=hdr.expected_cell.expected_cell+32w0x10000;m.owner_op=8w1;}
 action publish_syn(){m.expected=hdr.expected_cell.expected_cell;m.desired=hdr.expected_cell.expected_cell+32w0x10000;m.owner_op=8w1;}
 action publish_synack(){m.expected=hdr.expected_cell.expected_cell;m.desired=hdr.expected_cell.expected_cell+32w0x10000;m.owner_op=8w1;}
 action publish_ack(){m.expected=hdr.expected_cell.expected_cell;m.desired=hdr.expected_cell.expected_cell;m.owner_op=8w1;}
 action close_pending(){m.expected=hdr.expected_cell.expected_cell;m.desired=16w6++hdr.expected_cell.expected_cell[15:0];m.owner_op=8w1;}
 action close_free(){m.expected=hdr.expected_cell.expected_cell;m.desired=16w7++hdr.expected_cell.expected_cell[15:0];m.owner_op=8w1;}
action quarantine_abort(){m.expected=hdr.expected_cell.expected_cell;m.desired=16w6++hdr.expected_cell.expected_cell[15:0];m.owner_op=8w1;}
action drain_completed_select(){m.expected=hdr.expected_cell.expected_cell;m.desired=16w18++hdr.expected_cell.expected_cell[15:0];m.owner_op=8w1;}
action commit_prepared_select(){m.expected=hdr.expected_cell.expected_cell;m.desired=16w17++hdr.expected_cell.expected_cell[15:0];m.owner_op=8w1;}
action claim_select(){m.expected=hdr.expected_cell.expected_cell;m.desired=16w8++hdr.expected_cell.expected_cell[15:0];m.owner_op=8w1;}
action publish_select(){m.expected=hdr.expected_cell.expected_cell;m.desired=16w9++hdr.expected_cell.expected_cell[15:0];m.owner_op=8w1;}
action claim_response(){m.expected=hdr.expected_cell.expected_cell;m.desired=16w10++hdr.expected_cell.expected_cell[15:0];m.owner_op=8w1;}
action publish_response(){m.expected=hdr.expected_cell.expected_cell;m.desired=16w10++hdr.expected_cell.expected_cell[15:0];m.owner_op=8w1;}
action claim_operate(){m.expected=hdr.expected_cell.expected_cell;m.desired=16w11++hdr.expected_cell.expected_cell[15:0];m.owner_op=8w1;}
action publish_operate(){m.expected=hdr.expected_cell.expected_cell;m.desired=16w12++hdr.expected_cell.expected_cell[15:0];m.owner_op=8w1;}
action claim_read(){m.expected=hdr.expected_cell.expected_cell;m.desired=16w13++hdr.expected_cell.expected_cell[15:0];m.owner_op=8w1;}
action publish_read(){m.expected=hdr.expected_cell.expected_cell;m.desired=16w14++hdr.expected_cell.expected_cell[15:0];m.owner_op=8w1;}
action claim_read_rsp(){m.expected=hdr.expected_cell.expected_cell;m.desired=16w15++hdr.expected_cell.expected_cell[15:0];m.owner_op=8w1;}
action publish_read_rsp(){m.expected=hdr.expected_cell.expected_cell;m.desired=16w5++hdr.expected_cell.expected_cell[15:0];m.owner_op=8w1;}
action claim_response_op(){m.expected=hdr.expected_cell.expected_cell;m.desired=16w16++hdr.expected_cell.expected_cell[15:0];m.owner_op=8w1;}
action publish_response_op(){m.expected=hdr.expected_cell.expected_cell;m.desired=16w5++hdr.expected_cell.expected_cell[15:0];m.owner_op=8w1;}
 table owner_command{key={m.stage:exact;m.kind:exact;m.work_phase:exact;m.epoch_diff:exact;m.return_abort:ternary;m.active_gen_diff:ternary;hdr.expected_cell.expected_cell:ternary;}
 actions={claim_syn;claim_synack;claim_ack;publish_syn;publish_synack;publish_ack;close_pending;close_free;quarantine_abort;drain_completed_select;commit_prepared_select;claim_select;publish_select;claim_response;publish_response;claim_operate;publish_operate;claim_read;publish_read;claim_read_rsp;publish_read_rsp;claim_response_op;publish_response_op;NoAction;}size=31;const default_action=NoAction();
 const entries={(8w16,8w20,32w7,32w0,_,32w0,32w0x60000&&&32w0xffff0000):close_free();(8w14,8w20,32w7,32w0,_,32w0,32w0x110000&&&32w0xffff0000):drain_completed_select();(8w1,8w4,32w7,32w0,_,_,32w0x120000&&&32w0xffff0000):close_free();(8w6,8w20,32w5,32w0,_,_,_):commit_prepared_select();(8w1,8w1,32w1,32w0,_,_,_):claim_syn();(8w1,8w2,32w1,32w0,_,_,_):claim_synack();(8w1,8w3,32w1,32w0,_,_,_):claim_ack();(8w2,8w1,32w2,32w0,_,_,_):publish_syn();(8w2,8w2,32w2,32w0,_,_,_):publish_synack();(8w2,8w3,32w2,32w0,_,_,_):publish_ack();(8w1,8w4,32w4,32w0,_,_,_):close_free();(8w1,8w4,32w9,32w0,_,_,_):close_free();(8w1,8w4,32w5,32w0,_,_,_):close_pending();(8w1,8w4,32w7,32w0,_,_,_):close_pending();(8w1,8w4,32w1,32w0,_,_,_):close_pending();(8w1,8w4,32w2,32w0,_,_,_):close_pending();(8w1,8w4,32w3,32w0,_,_,_):close_pending();(8w1,8w5,32w1,32w0,_,_,_):claim_select();(8w2,8w5,32w2,32w0,_,_,_):publish_select();(8w1,8w6,32w1,32w0,_,_,_):claim_response();(8w2,8w6,32w2,32w0,_,_,_):publish_response();(8w1,8w7,32w1,32w0,_,_,_):claim_operate();(8w2,8w7,32w2,32w0,_,_,_):publish_operate();(8w1,8w9,32w1,32w0,_,_,_):claim_read();(8w2,8w9,32w2,32w0,_,_,_):publish_read();(8w1,8w11,32w1,32w0,_,_,_):claim_read_rsp();(8w2,8w11,32w2,32w0,_,_,_):publish_read_rsp();(8w1,8w16,32w1,32w0,_,_,_):claim_response_op();(8w2,8w16,32w2,32w0,_,_,_):publish_response_op();(8w2,8w255,32w2,32w0,8w1,_,_):quarantine_abort();(8w3,8w255,32w3,32w0,8w1,_,_):quarantine_abort();}}
 action owner_read(){m.observed=read_owner.execute(1w0);}
 action owner_cas(){m.owner_diff=compare_owner.execute(1w0);}
 action owner_check(){m.owner_diff=check_owner.execute(1w0);}
 table owner_t{key={m.stage:ternary;m.owner_op:exact;}actions={owner_read;owner_cas;owner_check;}size=2;const entries={(_,8w1):owner_cas();(8w0,8w0):owner_read();}const default_action=owner_check();}
 action snapshot(){hdr.envelope.setValid();hdr.work_generation.setValid();hdr.expected_cell.setValid();hdr.event.setValid();hdr.expected_cell.expected_cell=m.observed;hdr.work_generation.generation=m.generation;hdr.envelope.epoch=m.epoch;hdr.event.event=16w0x01ff;hdr.event.reserved=16w0;m.emit_loop=8w1;tm.ucast_egress_port=n_RETURN_PORT;tm.bypass_egress=1w1;}
 action snapshot_epoch_zero(){hdr.envelope.setValid();hdr.work_generation.setValid();hdr.expected_cell.setValid();hdr.event.setValid();hdr.expected_cell.expected_cell=m.observed;hdr.work_generation.generation=m.generation;hdr.envelope.epoch=32w0xffffffff;hdr.event.event=16w0x01ff;hdr.event.reserved=16w0;m.emit_loop=8w1;tm.ucast_egress_port=n_RETURN_PORT;tm.bypass_egress=1w1;}
 table snapshot_t{key={m.epoch:exact;}actions={snapshot;snapshot_epoch_zero;}size=1;const entries={32w0:snapshot_epoch_zero();}const default_action=snapshot();}
 action first_syn(){hdr.envelope.epoch=m.generation;hdr.event.event=16w0x0101;}
 action first_synack(){hdr.event.event=16w0x0102;}
 action first_ack(){hdr.event.event=16w0x0103;}
 action first_close(){hdr.event.event=16w0x0104;hdr.work_generation.generation=hdr.envelope.epoch;}
action first_select(){hdr.event.event=16w0x0105;hdr.event.reserved=16w1;hdr.captured.setValid();hdr.captured.index=m.decoy_index;hdr.captured.code=m.decoy_code;hdr.captured.repeat=m.decoy_repeat;hdr.captured.on=m.decoy_on;hdr.captured.off=m.decoy_off;}
action first_response(){hdr.event.event=16w0x0106;}
action first_operate(){hdr.event.event=16w0x0107;}
 action forward_original(){hdr.event.event=16w0x0108;}
 action first_response_op(){hdr.event.event=16w0x0110;}
 action first_replay(){hdr.event.event=16w0x010c;}
 action count_refused(){count_first_bump.execute(4w0);}
 action count_resent(){count_first_bump.execute(4w1);}
 action count_replay_refused(){count_first_bump.execute(4w2);}
 action first_read_request(){hdr.event.event=16w0x0109;hdr.t0.setValid();hdr.t0.t0q=p.global_tstamp[31:8]++8w0;}
 action first_read_ack(){hdr.event.event=16w0x010a;hdr.t0.setValid();hdr.t0.t0q=p.global_tstamp[31:8]++8w0;}
 action first_read_response(){hdr.event.event=16w0x010b;hdr.t0.setValid();hdr.t0.t0q=p.global_tstamp[31:8]++8w0;}
 action close_forward(){hdr.envelope.setInvalid();hdr.work_generation.setInvalid();hdr.expected_cell.setInvalid();hdr.event.setInvalid();m.emit_loop=8w0;tm.ucast_egress_port=m.output_port;}
 table first_event{key={m.kind:ternary;m.sequence_valid:ternary;m.matched:ternary;m.observed:ternary;}
 actions={first_syn;first_synack;first_ack;first_close;first_select;first_response;first_operate;first_read_request;first_read_ack;first_read_response;first_response_op;first_replay;count_refused;count_resent;count_replay_refused;forward_original;close_forward;NoAction;}size=64;const default_action=NoAction();
 const entries={(8w1,8w1,8w0,32w0):first_syn();(8w2,8w1,8w0,32w0x20000&&&32w0xffff0000):first_synack();(8w3,8w1,8w0,32w0x40000&&&32w0xffff0000):first_ack();(8w4,8w1,8w0,32w0x20000&&&32w0xffff0000):first_close();(8w4,8w1,8w0,32w0x30000&&&32w0xffff0000):first_close();(8w4,8w1,8w0,32w0x40000&&&32w0xffff0000):first_close();(8w4,8w1,8w0,32w0x50000&&&32w0xffff0000):first_close();(8w5,8w1,8w0,32w0x40000&&&32w0xffff0000):first_select();(8w5,8w1,8w0,32w0x50000&&&32w0xffff0000):first_select();(8w6,8w1,8w1,32w0x90000&&&32w0xffff0000):first_response();(8w7,8w1,8w1,32w0xa0000&&&32w0xffff0000):first_operate();(8w4,8w1,8w0,32w0x80000&&&32w0xffff0000):first_close();(8w4,8w1,8w0,32w0x90000&&&32w0xffff0000):first_close();(8w4,8w1,8w0,32w0x110000&&&32w0xffff0000):first_close();(8w4,8w1,8w0,32w0x120000&&&32w0xffff0000):first_close();(8w4,8w1,8w0,32w0xa0000&&&32w0xffff0000):first_close();(8w4,8w1,8w0,32w0xb0000&&&32w0xffff0000):first_close();(8w4,8w1,8w0,32w0xc0000&&&32w0xffff0000):first_close();(8w4,8w1,8w0,32w0xd0000&&&32w0xffff0000):first_close();(8w4,8w1,8w0,32w0xe0000&&&32w0xffff0000):first_close();(8w4,8w1,8w0,32w0xf0000&&&32w0xffff0000):first_close();(8w1,8w1,8w0,32w0x20000&&&32w0xffff0000):forward_original();(8w1,8w1,8w0,32w0x30000&&&32w0xffff0000):forward_original();(8w2,8w1,8w0,32w0x30000&&&32w0xffff0000):forward_original();(8w2,8w1,8w0,32w0x40000&&&32w0xffff0000):forward_original();(8w2,8w1,8w0,32w0x50000&&&32w0xffff0000):forward_original();(8w3,8w1,8w0,32w0x50000&&&32w0xffff0000):forward_original();(8w3,8w1,8w0,32w0x80000&&&32w0xffff0000):forward_original();(8w3,8w1,8w0,32w0x90000&&&32w0xffff0000):forward_original();(8w3,8w1,8w0,32w0xa0000&&&32w0xffff0000):forward_original();(8w3,8w1,8w0,32w0xb0000&&&32w0xffff0000):forward_original();(8w3,8w1,8w0,32w0xc0000&&&32w0xffff0000):forward_original();(8w4,_,_,_):close_forward();(8w9,8w1,8w0,32w0x50000&&&32w0xffff0000):first_read_request();(8w11,8w1,8w1,32w0xe0000&&&32w0xffff0000):first_read_response();(8w10,8w1,8w0,32w0xe0000&&&32w0xffff0000):first_read_ack();(8w10,_,_,_):forward_original();(8w6,8w2,8w1,32w0xc0000&&&32w0xffff0000):first_response_op();(8w12,8w4,8w0,32w0x90000&&&32w0xffff0000):first_replay();(8w12,8w4,8w0,32w0xc0000&&&32w0xffff0000):first_replay();(8w12,_,_,_):count_replay_refused();(8w5,8w3,_,_):count_resent();(8w7,8w3,_,_):count_resent();(8w5,_,_,_):count_refused();(8w6,_,_,_):count_refused();(8w7,_,_,_):count_refused();(8w9,_,_,_):count_refused();(8w11,_,_,_):count_refused();}}
 action next_stage(){hdr.event.event=hdr.event.event+16w0x100;m.emit_loop=8w1;tm.ucast_egress_port=n_RETURN_PORT;tm.bypass_egress=1w1;}
 table next_stage_t{actions={next_stage;}size=1;const default_action=next_stage();}
 action carry_current(){hdr.expected_cell.expected_cell=m.desired;}
 table carry_t{actions={carry_current;}size=1;const default_action=carry_current();}
 action abort_work(){hdr.event.event[7:0]=8w255;hdr.t0.setInvalid();}
 table abort_t{actions={abort_work;}size=1;const default_action=abort_work();}
Register<bit<32>,bit<1>>(1,0) application;
RegisterAction<bit<32>,bit<1>,bit<32>>(application) write_application={void apply(inout bit<32> v,out bit<32> r){v=m.compare_application;r=v;}};
RegisterAction<bit<32>,bit<1>,bit<32>>(application) read_op_application={void apply(inout bit<32> v,out bit<32> r){r=v-m.compare_application;}};RegisterAction<bit<32>,bit<1>,bit<32>>(application) read_rsp_application={void apply(inout bit<32> v,out bit<32> r){r=v-m.compare_application;}};
action compare_rsp_application(){m.diff_application=read_rsp_application.execute(1w0);}
action compare_application(){m.diff_application=read_op_application.execute(1w0);}
action store_application(){write_application.execute(1w0);}
table application_t{key={m.stage:ternary;m.kind:ternary;m.work_phase:ternary;m.epoch_diff:ternary;}actions={store_application;compare_application;compare_rsp_application;NoAction;}size=6;const entries={(8w1,8w5,32w1,32w0):store_application();(8w1,8w7,32w1,32w0):store_application();(8w0,8w7,32w4,_):compare_application();(8w0,8w7,32w9,_):compare_application();(8w0,8w6,32w4,_):compare_rsp_application();(8w0,8w6,32w9,_):compare_rsp_application();}const default_action=NoAction();}
Register<bit<32>,bit<1>>(1,0) frozen_decoy_off;
RegisterAction<bit<32>,bit<1>,bit<32>>(frozen_decoy_off) write_frozen_decoy_off={void apply(inout bit<32> v,out bit<32> r){v=m.compare_frozen_decoy_off;r=v;}};
RegisterAction<bit<32>,bit<1>,bit<32>>(frozen_decoy_off) read_op_frozen_decoy_off={void apply(inout bit<32> v,out bit<32> r){r=v-m.compare_frozen_decoy_off;}};RegisterAction<bit<32>,bit<1>,bit<32>>(frozen_decoy_off) read_rsp_frozen_decoy_off={void apply(inout bit<32> v,out bit<32> r){r=v-m.compare_frozen_decoy_off;}};
action compare_rsp_frozen_decoy_off(){m.diff_frozen_decoy_off=read_rsp_frozen_decoy_off.execute(1w0);}
action compare_frozen_decoy_off(){m.diff_frozen_decoy_off=read_op_frozen_decoy_off.execute(1w0);}
action store_frozen_decoy_off(){write_frozen_decoy_off.execute(1w0);}
table frozen_decoy_off_t{key={m.stage:ternary;m.kind:ternary;m.work_phase:ternary;m.epoch_diff:ternary;}actions={store_frozen_decoy_off;compare_frozen_decoy_off;compare_rsp_frozen_decoy_off;NoAction;}size=5;const entries={(8w1,8w5,32w1,32w0):store_frozen_decoy_off();(8w0,8w7,32w4,_):compare_frozen_decoy_off();(8w0,8w7,32w9,_):compare_frozen_decoy_off();(8w0,8w6,32w4,_):compare_rsp_frozen_decoy_off();(8w0,8w6,32w9,_):compare_rsp_frozen_decoy_off();}const default_action=NoAction();}
Register<n_object_pair_t,bit<1>>(1,{0,0}) pair_real_links_real_tcp_src;
RegisterAction<n_object_pair_t,bit<1>,bit<32>>(pair_real_links_real_tcp_src) write_real_links={void apply(inout n_object_pair_t v,out bit<32> r){v.first=m.compare_real_links;v.second=m.compare_real_tcp_src;r=32w0;}};
RegisterAction<n_object_pair_t,bit<1>,bit<32>>(pair_real_links_real_tcp_src) read_real_links={void apply(inout n_object_pair_t v,out bit<32> r){if(v.first!=m.compare_real_links||v.second!=m.compare_real_tcp_src){r=32w1;}else{r=32w0;}}};
action store_real_links(){write_real_links.execute(1w0);}
action compare_real_links(){m.diff_real_links=read_real_links.execute(1w0);}
table real_links_t{key={m.stage:ternary;m.kind:ternary;m.work_phase:ternary;m.epoch_diff:ternary;}actions={store_real_links;compare_real_links;NoAction;}size=5;const entries={(8w1,8w5,32w1,32w0):store_real_links();(8w0,8w7,32w4,_):compare_real_links();(8w0,8w7,32w9,_):compare_real_links();(8w0,8w6,32w4,_):compare_real_links();(8w0,8w6,32w9,_):compare_real_links();}const default_action=NoAction();}
Register<n_object_pair_t,bit<1>>(1,{0,0}) pair_real_tcp_dst_real_tcp_ports;
RegisterAction<n_object_pair_t,bit<1>,bit<32>>(pair_real_tcp_dst_real_tcp_ports) write_real_tcp_dst={void apply(inout n_object_pair_t v,out bit<32> r){v.first=m.compare_real_tcp_dst;v.second=m.compare_real_tcp_ports;r=32w0;}};
RegisterAction<n_object_pair_t,bit<1>,bit<32>>(pair_real_tcp_dst_real_tcp_ports) read_real_tcp_dst={void apply(inout n_object_pair_t v,out bit<32> r){if(v.first!=m.compare_real_tcp_dst||v.second!=m.compare_real_tcp_ports){r=32w1;}else{r=32w0;}}};
action store_real_tcp_dst(){write_real_tcp_dst.execute(1w0);}
action compare_real_tcp_dst(){m.diff_real_tcp_dst=read_real_tcp_dst.execute(1w0);}
table real_tcp_dst_t{key={m.stage:ternary;m.kind:ternary;m.work_phase:ternary;m.epoch_diff:ternary;}actions={store_real_tcp_dst;compare_real_tcp_dst;NoAction;}size=5;const entries={(8w1,8w5,32w1,32w0):store_real_tcp_dst();(8w0,8w7,32w4,_):compare_real_tcp_dst();(8w0,8w7,32w9,_):compare_real_tcp_dst();(8w0,8w6,32w4,_):compare_real_tcp_dst();(8w0,8w6,32w9,_):compare_real_tcp_dst();}const default_action=NoAction();}
Register<n_object_pair_t,bit<1>>(1,{0,0}) pair_real_object_real_on;
RegisterAction<n_object_pair_t,bit<1>,bit<32>>(pair_real_object_real_on) write_real_object={void apply(inout n_object_pair_t v,out bit<32> r){v.first=m.compare_real_object;v.second=m.compare_real_on;r=32w0;}};
RegisterAction<n_object_pair_t,bit<1>,bit<32>>(pair_real_object_real_on) read_real_object={void apply(inout n_object_pair_t v,out bit<32> r){if(v.first!=m.compare_real_object||v.second!=m.compare_real_on){r=32w1;}else{r=32w0;}}};
action store_real_object(){write_real_object.execute(1w0);}
action compare_real_object(){m.diff_real_object=read_real_object.execute(1w0);}
table real_object_t{key={m.stage:ternary;m.kind:ternary;m.work_phase:ternary;m.epoch_diff:ternary;}actions={store_real_object;compare_real_object;NoAction;}size=5;const entries={(8w1,8w5,32w1,32w0):store_real_object();(8w0,8w7,32w4,_):compare_real_object();(8w0,8w7,32w9,_):compare_real_object();(8w0,8w6,32w4,_):compare_real_object();(8w0,8w6,32w9,_):compare_real_object();}const default_action=NoAction();}
Register<n_object_pair_t,bit<1>>(1,{0,0}) pair_real_off_native_start;
RegisterAction<n_object_pair_t,bit<1>,bit<32>>(pair_real_off_native_start) write_real_off={void apply(inout n_object_pair_t v,out bit<32> r){v.first=m.compare_real_off;v.second=m.compare_native_start;r=32w0;}};
RegisterAction<n_object_pair_t,bit<1>,bit<32>>(pair_real_off_native_start) read_real_off={void apply(inout n_object_pair_t v,out bit<32> r){if(v.first!=m.compare_real_off||v.second!=m.compare_native_start){r=32w1;}else{r=32w0;}}};
action store_real_off(){write_real_off.execute(1w0);}
action compare_real_off(){m.diff_real_off=read_real_off.execute(1w0);}
table real_off_t{key={m.stage:ternary;m.kind:ternary;m.work_phase:ternary;m.epoch_diff:ternary;}actions={store_real_off;compare_real_off;NoAction;}size=6;const entries={(8w1,8w5,32w1,32w0):store_real_off();(8w1,8w7,32w1,32w0):store_real_off();(8w0,8w7,32w4,_):compare_real_off();(8w0,8w7,32w9,_):compare_real_off();(8w0,8w6,32w4,_):compare_real_off();(8w0,8w6,32w9,_):compare_real_off();}const default_action=NoAction();}
Register<n_object_pair_t,bit<1>>(1,{0,0}) pair_native_end_server_start;
RegisterAction<n_object_pair_t,bit<1>,bit<32>>(pair_native_end_server_start) write_native_end={void apply(inout n_object_pair_t v,out bit<32> r){v.first=m.compare_native_end;v.second=m.compare_server_start;r=32w0;}};
RegisterAction<n_object_pair_t,bit<1>,bit<32>>(pair_native_end_server_start) read_native_end={void apply(inout n_object_pair_t v,out bit<32> r){if(v.first!=m.compare_native_end||v.second!=m.compare_server_start){r=32w1;}else{r=32w0;}}};
action store_native_end(){write_native_end.execute(1w0);}
action compare_native_end(){m.diff_native_end=read_native_end.execute(1w0);}
table native_end_t{key={m.stage:ternary;m.kind:ternary;m.work_phase:ternary;m.epoch_diff:ternary;}actions={store_native_end;compare_native_end;NoAction;}size=6;const entries={(8w1,8w5,32w1,32w0):store_native_end();(8w1,8w7,32w1,32w0):store_native_end();(8w0,8w7,32w4,_):compare_native_end();(8w0,8w7,32w9,_):compare_native_end();(8w0,8w6,32w4,_):compare_native_end();(8w0,8w6,32w9,_):compare_native_end();}const default_action=NoAction();}
Register<n_object_pair_t,bit<1>>(1,{0,0}) pair_frozen_decoy_object_frozen_decoy_on;
RegisterAction<n_object_pair_t,bit<1>,bit<32>>(pair_frozen_decoy_object_frozen_decoy_on) write_frozen_decoy_object={void apply(inout n_object_pair_t v,out bit<32> r){v.first=m.compare_frozen_decoy_object;v.second=m.compare_frozen_decoy_on;r=32w0;}};
RegisterAction<n_object_pair_t,bit<1>,bit<32>>(pair_frozen_decoy_object_frozen_decoy_on) read_frozen_decoy_object={void apply(inout n_object_pair_t v,out bit<32> r){if(v.first!=m.compare_frozen_decoy_object||v.second!=m.compare_frozen_decoy_on){r=32w1;}else{r=32w0;}}};
action store_frozen_decoy_object(){write_frozen_decoy_object.execute(1w0);}
action compare_frozen_decoy_object(){m.diff_frozen_decoy_object=read_frozen_decoy_object.execute(1w0);}
table frozen_decoy_object_t{key={m.stage:ternary;m.kind:ternary;m.work_phase:ternary;m.epoch_diff:ternary;}actions={store_frozen_decoy_object;compare_frozen_decoy_object;NoAction;}size=5;const entries={(8w1,8w5,32w1,32w0):store_frozen_decoy_object();(8w0,8w7,32w4,_):compare_frozen_decoy_object();(8w0,8w7,32w9,_):compare_frozen_decoy_object();(8w0,8w6,32w4,_):compare_frozen_decoy_object();(8w0,8w6,32w9,_):compare_frozen_decoy_object();}const default_action=NoAction();}
action compare_response_inputs(){m.compare_real_links=(bit<32>)(hdr.dl.src++hdr.dl.dst);m.compare_real_tcp_src=(bit<32>)(hdr.ip.dst);m.compare_real_tcp_dst=(bit<32>)(hdr.ip.src);m.compare_real_tcp_ports=(bit<32>)(hdr.tcp.dport++hdr.tcp.sport);m.compare_real_object=(bit<32>)(hdr.first.w2[15:0]++hdr.first.w3[31:16]);m.compare_real_on=(bit<32>)(hdr.first.w3[15:0]++hdr.second.w0[31:16]);m.compare_real_off=(bit<32>)(hdr.second.w0[15:0]++hdr.second.w1[31:16]);m.compare_native_start=(bit<32>)(hdr.tcp.ack-32w55);m.compare_native_end=(bit<32>)(hdr.tcp.ack);m.compare_server_start=(bit<32>)(hdr.tcp.seq);m.compare_application=(bit<32>)(hdr.first.w0[23:16]);m.compare_frozen_decoy_object=(bit<32>)(hdr.second.w3);m.compare_frozen_decoy_on=(bit<32>)(hdr.response_tail.w0);m.compare_frozen_decoy_off=(bit<32>)(hdr.response_tail.w1);}
table compare_response_inputs_t{actions={compare_response_inputs;}size=1;const default_action=compare_response_inputs();}
action compare_operate_inputs(){m.compare_real_links=(bit<32>)(hdr.dl.dst++hdr.dl.src);m.compare_real_tcp_src=(bit<32>)(hdr.ip.src);m.compare_real_tcp_dst=(bit<32>)(hdr.ip.dst);m.compare_real_tcp_ports=(bit<32>)(hdr.tcp.sport++hdr.tcp.dport);m.compare_real_object=(bit<32>)(hdr.first.w2[31:16]++hdr.first.w2[15:8]++hdr.first.w2[7:0]);m.compare_real_on=(bit<32>)(hdr.first.w3);m.compare_real_off=(bit<32>)(hdr.tail.off);m.compare_native_start=(bit<32>)(hdr.tcp.seq-32w35);m.compare_native_end=(bit<32>)(hdr.tcp.seq+32w20);m.compare_server_start=(bit<32>)(hdr.tcp.ack-32w57);m.compare_application=(bit<32>)(hdr.first.w0[23:16]);m.compare_frozen_decoy_object=(bit<32>)(m.decoy_index++m.decoy_code++m.decoy_repeat);m.compare_frozen_decoy_on=(bit<32>)(m.decoy_on);m.compare_frozen_decoy_off=(bit<32>)(m.decoy_off);}
action compare_operate_store_inputs(){m.compare_real_links=(bit<32>)(hdr.dl.dst++hdr.dl.src);m.compare_real_tcp_src=(bit<32>)(hdr.ip.src);m.compare_real_tcp_dst=(bit<32>)(hdr.ip.dst);m.compare_real_tcp_ports=(bit<32>)(hdr.tcp.sport++hdr.tcp.dport);m.compare_real_object=(bit<32>)(hdr.first.w2[31:16]++hdr.first.w2[15:8]++hdr.first.w2[7:0]);m.compare_real_on=(bit<32>)(hdr.first.w3);m.compare_real_off=(bit<32>)(hdr.tail.off);m.compare_native_start=(bit<32>)(hdr.tcp.seq+32w20);m.compare_native_end=(bit<32>)(hdr.tcp.seq+32w75);m.compare_server_start=(bit<32>)(hdr.tcp.ack);m.compare_application=(bit<32>)(hdr.first.w0[23:16]);m.compare_frozen_decoy_object=(bit<32>)(m.decoy_index++m.decoy_code++m.decoy_repeat);m.compare_frozen_decoy_on=(bit<32>)(m.decoy_on);m.compare_frozen_decoy_off=(bit<32>)(m.decoy_off);}
table compare_operate_inputs_t{key={m.stage:exact;}actions={compare_operate_inputs;compare_operate_store_inputs;}size=2;const entries={8w1:compare_operate_store_inputs();}const default_action=compare_operate_inputs();}
action compare_select_inputs(){m.compare_real_links=(bit<32>)(hdr.dl.dst++hdr.dl.src);m.compare_real_tcp_src=(bit<32>)(hdr.ip.src);m.compare_real_tcp_dst=(bit<32>)(hdr.ip.dst);m.compare_real_tcp_ports=(bit<32>)(hdr.tcp.sport++hdr.tcp.dport);m.compare_real_object=(bit<32>)(hdr.first.w2[31:16]++hdr.first.w2[15:8]++hdr.first.w2[7:0]);m.compare_real_on=(bit<32>)(hdr.first.w3);m.compare_real_off=(bit<32>)(hdr.tail.off);m.compare_native_start=(bit<32>)(hdr.tcp.seq);m.compare_native_end=hdr.tcp.seq+32w55;m.compare_server_start=(bit<32>)(hdr.tcp.ack);m.compare_application=(bit<32>)(hdr.first.w0[23:16]);m.compare_frozen_decoy_object=(bit<32>)(hdr.captured.index++hdr.captured.code++hdr.captured.repeat);m.compare_frozen_decoy_on=(bit<32>)(hdr.captured.on);m.compare_frozen_decoy_off=(bit<32>)(hdr.captured.off);}
table compare_select_inputs_t{actions={compare_select_inputs;}size=1;const default_action=compare_select_inputs();}
action matched(){m.matched=8w1;}
table object_match{key={m.response:exact;m.diff_real_links:exact;m.diff_real_tcp_dst:exact;m.diff_real_object:exact;m.diff_real_off:exact;m.diff_native_end:exact;m.diff_application:exact;m.diff_frozen_decoy_object:exact;m.diff_frozen_decoy_off:exact;}actions={matched;NoAction;}size=3;const default_action=NoAction();const entries={(8w1,32w0,32w0,32w0,32w0,32w0,32w0,32w0,32w0):matched();(8w0,32w0,32w0,32w0,32w0,32w0,32w4294967295,32w0,32w0):matched();(8w0,32w0,32w0,32w0,32w0,32w0,32w15,32w0,32w0):matched();}}
action read_configure(bit<16> dst,bit<16> src){m.enabled=8w1;m.link_dst=dst;m.link_src=src;}
table read_connection{key={hdr.ip.src:exact;hdr.ip.dst:exact;hdr.tcp.sport:exact;hdr.tcp.dport:exact;}actions={read_configure;NoAction;}size=2;default_action=NoAction();}
table read_request_profile{key={hdr.dl.magic:exact;hdr.dl.len:exact;hdr.dl.ctrl:exact;hdr.rd_req.tp:ternary;hdr.rd_req.app:ternary;hdr.rd_req.func:exact;hdr.rd_req.group:exact;hdr.rd_req.variation:exact;hdr.rd_req.qualifier:exact;hdr.rd_req.first:exact;hdr.rd_req.last:exact;}
 actions={eligible;NoAction;}size=1;const default_action=NoAction();const entries={(16w0x0564,8w13,8w0xc4,8w0xc0&&&8w0xc0,8w0xc0&&&8w0xf0,8w1,8w10,8w2,8w0,8w0,8w22):eligible();}}
table read_response_profile{key={hdr.dl.magic:exact;hdr.dl.len:exact;hdr.dl.ctrl:exact;hdr.first.w0[31:24]:ternary;hdr.first.w0[23:16]:ternary;hdr.first.w0[15:8]:exact;hdr.first.w1[23:16]:exact;hdr.first.w1[15:8]:exact;hdr.first.w1[7:0]:exact;hdr.first.w2[31:24]:exact;hdr.first.w2[23:16]:exact;}
 actions={eligible;NoAction;}size=1;const default_action=NoAction();const entries={(16w0x0564,8w38,8w0x44,8w0xc0&&&8w0xc0,8w0xc0&&&8w0xf0,8w0x81,8w10,8w2,8w0,8w0,8w22):eligible();}}
Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_rd_head;
action rd_head_crc(){m.hcrc=hash_rd_head.get({hdr.dl.magic,hdr.dl.len,hdr.dl.ctrl,hdr.dl.dst,hdr.dl.src});}
table rd_head_t{actions={rd_head_crc;}size=1;const default_action=rd_head_crc();}
Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_rd_first;
action rd_first_crc(){m.bcrc=hash_rd_first.get({hdr.first.w0,hdr.first.w1,hdr.first.w2,hdr.first.w3});}
table rd_first_crc_t{actions={rd_first_crc;}size=1;const default_action=rd_first_crc();}
Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_rd_second;
action rd_second_crc(){m.crc1=hash_rd_second.get({hdr.second.w0,hdr.second.w1,hdr.second.w2,hdr.second.w3});}
table rd_second_crc_t{actions={rd_second_crc;}size=1;const default_action=rd_second_crc();}
Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_rd_request;
action rd_request_crc(){m.bcrc=hash_rd_request.get({hdr.rd_req.tp,hdr.rd_req.app,hdr.rd_req.func,hdr.rd_req.group,hdr.rd_req.variation,hdr.rd_req.qualifier,hdr.rd_req.first,hdr.rd_req.last});}
table rd_request_crc_t{actions={rd_request_crc;}size=1;const default_action=rd_request_crc();}
Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_rd_tail;
action rd_tail_crc(){m.tcrc=hash_rd_tail.get({hdr.rd_tail.value});}
table rd_tail_crc_t{actions={rd_tail_crc;}size=1;const default_action=rd_tail_crc();}
action read_request_input(){m.compare_read_app=(bit<32>)(hdr.rd_req.app[3:0]);}
action read_response_input(){m.compare_read_app=(bit<32>)(hdr.first.w0[19:16]);}
table read_input_t{key={m.packet_kind:exact;}actions={read_request_input;read_response_input;NoAction;}size=2;const entries={8w9:read_request_input();8w11:read_response_input();}const default_action=NoAction();}
Register<bit<32>,bit<1>>(1,0) read_app;
RegisterAction<bit<32>,bit<1>,bit<32>>(read_app) write_read_app={void apply(inout bit<32> v,out bit<32> r){v=m.compare_read_app;r=v;}};
RegisterAction<bit<32>,bit<1>,bit<8>>(read_app) check_read_app={void apply(inout bit<32> v,out bit<8> r){r=8w0;if(v==m.compare_read_app){r=8w1;}}};
action store_read_app(){write_read_app.execute(1w0);}
action match_read_app(){m.matched=check_read_app.execute(1w0);}
table read_app_t{key={m.stage:ternary;m.kind:ternary;m.work_phase:ternary;m.epoch_diff:ternary;}actions={store_read_app;match_read_app;NoAction;}size=3;const entries={(8w1,8w9,32w1,32w0):store_read_app();(8w0,8w11,32w4,_):match_read_app();(8w0,8w11,32w9,_):match_read_app();}const default_action=NoAction();}
action emit_tev(bit<16> event){hdr.expected_cell.expected_cell=hdr.t0.t0q;hdr.event.event=event;hdr.t0.setInvalid();tm.ucast_egress_port=n_READ_HANDOFF_PORT;m.emit_loop=8w0;}
action terminal_strip(){hdr.captured.setInvalid();hdr.envelope.setInvalid();hdr.work_generation.setInvalid();hdr.expected_cell.setInvalid();hdr.event.setInvalid();}
action terminal_abort(){hdr.captured.setInvalid();hdr.envelope.setInvalid();hdr.work_generation.setInvalid();hdr.expected_cell.setInvalid();hdr.event.setInvalid();md.drop_ctl=3w1;}
action emit_reset(){hdr.event.event=8w4++m.direction;hdr.expected_cell.expected_cell=32w0;tm.ucast_egress_port=n_READ_HANDOFF_PORT;m.emit_loop=8w0;}
table reset_boundary{key={m.owner_op:exact;m.owner_diff:exact;m.epoch_diff:exact;}actions={emit_reset;terminal_abort;}size=1;const entries={(8w1,32w0,32w0):emit_reset();}const default_action=terminal_abort();}
action emit_replay(){tm.ucast_egress_port=n_STEP3_M_PORT;m.emit_loop=8w0;count_term_bump.execute(4w0);}
action emit_select(){tm.ucast_egress_port=n_STEP3_M_PORT;m.emit_loop=8w0;}
action emit_local_abort(){hdr.expected_cell.expected_cell=hdr.envelope.epoch;hdr.event.event=16w0x05ff;tm.ucast_egress_port=n_RETURN_PORT;tm.bypass_egress=1w1;m.emit_loop=8w1;}
table read_terminal_t{key={m.kind:ternary;m.owner_diff:ternary;m.epoch_diff:ternary;}actions={emit_tev;emit_replay;emit_select;emit_local_abort;terminal_strip;terminal_abort;}size=8;const entries={(8w5,32w0,32w0):emit_select();(8w5,_,32w0):emit_local_abort();(8w9,32w0,32w0):emit_tev(16w0x0900);(8w10,32w0,32w0):emit_tev(16w0x0a00);(8w11,32w0,32w0):emit_tev(16w0x0b00);(8w12,32w0,32w0):emit_replay();(8w255,32w0,32w0):terminal_abort();(_,32w0,32w0):terminal_strip();}const default_action=terminal_abort();}
action busy_drop(){md.drop_ctl=3w1;count_busy_bump.execute(4w0);}
action busy_pass(){count_busy_bump.execute(4w1);}
table busy_t{key={m.kind:exact;}actions={busy_drop;busy_pass;}size=6;const entries={8w5:busy_drop();8w6:busy_drop();8w7:busy_drop();8w9:busy_drop();8w11:busy_drop();8w12:busy_drop();}const default_action=busy_pass();}
 Register<bit<32>,bit<1>>(1,0) active_work_generation;
 RegisterAction<bit<32>,bit<1>,bit<32>>(active_work_generation) active_generation_write={void apply(inout bit<32> value,out bit<32> result){value=m.generation;result=32w0;}};
 RegisterAction<bit<32>,bit<1>,bit<32>>(active_work_generation) active_generation_check={void apply(inout bit<32> value,out bit<32> result){result=value-hdr.work_generation.generation;}};
 action store_active_generation(){m.active_gen_diff=active_generation_write.execute(1w0);}
 action check_active_generation(){m.active_gen_diff=active_generation_check.execute(1w0);}
 table active_generation_t{key={m.work_op:ternary;m.work_phase:ternary;m.kind:ternary;}actions={store_active_generation;check_active_generation;NoAction;}size=3;const default_action=NoAction();const entries={(8w1,32w4,_):store_active_generation();(8w1,32w9,_):store_active_generation();(_,_,8w20):check_active_generation();}}
 action ready_qualified(){hdr.event.event=16w0x0614;tm.ucast_egress_port=n_RETURN_PORT;tm.bypass_egress=1w1;}
 action activate_select(){hdr.expected_cell.expected_cell=m.desired;hdr.event.event=16w0x0714;tm.ucast_egress_port=n_STEP3_M_PORT;tm.bypass_egress=1w1;}
 action qualify_quarantine_cleanup(){hdr.expected_cell.expected_cell=16w6++hdr.expected_cell.expected_cell[15:0];hdr.event.event=16w0x1014;tm.ucast_egress_port=n_RETURN_PORT;tm.bypass_egress=1w1;}
 action emit_completed_terminal(){hdr.expected_cell.expected_cell=m.desired;hdr.completion.setValid();hdr.completion.epoch=hdr.envelope.epoch;hdr.event.event=16w0x0f14;hdr.event.reserved=16w3;tm.ucast_egress_port=n_RETURN_PORT;tm.bypass_egress=1w1;}
 action cache_terminal_egress(){tm.ucast_egress_port=n_RETURN_PORT;tm.bypass_egress=1w0;}
 action endpoint_egress(){tm.ucast_egress_port=9w2;tm.bypass_egress=1w0;}
 table ready_result_t{key={m.stage:exact;m.work_phase:exact;m.active_gen_diff:exact;m.cached_owner_diff:exact;m.epoch_diff:exact;m.owner_diff:exact;hdr.expected_cell.expected_cell:ternary;}actions={ready_qualified;activate_select;endpoint_egress;cache_terminal_egress;emit_completed_terminal;qualify_quarantine_cleanup;deny;}size=8;const default_action=deny();const entries={(8w16,32w7,32w0,32w0xfffd0000,32w0,32w0,32w0x60000&&&32w0xffff0000):emit_completed_terminal();(8w14,32w7,32w0,32w0x80000,32w0,32w0xfff50000,32w0x110000&&&32w0xffff0000):qualify_quarantine_cleanup();(8w18,32w7,32w0,32w0x80000,32w0,32w0xfff50000,32w0x110000&&&32w0xffff0000):cache_terminal_egress();(8w18,32w7,32w0,32w0x80000,32w0,32w0,32w0x110000&&&32w0xffff0000):cache_terminal_egress();(8w14,32w7,32w0,32w0x80000,32w0,32w0,32w0x110000&&&32w0xffff0000):emit_completed_terminal();(8w11,32w7,32w0,32w0x80000,32w0,32w0,32w0x110000&&&32w0xffff0000):endpoint_egress();(8w5,32w5,32w0,32w0,32w0,32w0,32w0x90000&&&32w0xffff0000):ready_qualified();(8w6,32w5,32w0,32w0,32w0,32w0,32w0x90000&&&32w0xffff0000):activate_select();}}
action go_new(bit<8> k){m.go=8w1;m.kind=k;m.generation=allocate.execute(1w0);m.work_op=8w1;}
action go_keep(bit<8> k){m.go=8w1;m.kind=k;}
action go_ret_completed_terminal(){m.go=8w1;m.generation=hdr.work_generation.generation;m.expected_work_phase=32w7;m.work_op=8w3;}
action go_ret_ready(){m.go=8w1;m.generation=hdr.work_generation.generation;m.expected_work_phase=32w5;m.work_op=8w3;}
action go_ret_select_pending(){m.go=8w1;m.generation=hdr.work_generation.generation;m.work_op=8w3;}
action go_ret_work(){m.go=8w1;m.generation=hdr.work_generation.generation;m.work_op=8w2;}
action go_ret_nowork(){m.go=8w1;m.generation=hdr.work_generation.generation;m.expected_work_phase=32w0;}
action go_ret_local_terminal(){m.go=8w1;m.generation=hdr.work_generation.generation;m.work_op=8w4;}
action go_ret_abort(){m.go=8w1;m.kind=8w255;m.return_abort=8w1;m.generation=hdr.work_generation.generation;m.work_op=8w2;hdr.event.event[7:0]=8w255;hdr.t0.setInvalid();}
table guard{key={m.stage:ternary;m.packet_kind:ternary;m.kind:ternary;m.direction:ternary;m.shape_valid:ternary;m.enabled:ternary;m.profile:ternary;m.badh:ternary;m.badb:ternary;m.bad1:ternary;m.badt:ternary;m.prefix_difference:ternary;m.cached_owner_diff:ternary;m.terminal_diff:ternary;}
actions={go_new;go_keep;go_ret_work;go_ret_select_pending;go_ret_ready;go_ret_completed_terminal;go_ret_nowork;go_ret_local_terminal;go_ret_abort;NoAction;}size=56;const default_action=NoAction();const entries={(8w16,8w20,8w20,8w1,8w1,_,_,_,_,_,_,32w0,32w0xfffd0000,_):go_ret_nowork();(8w15,8w20,8w20,8w1,8w1,_,_,_,_,_,_,32w0,32w0xfffe0000,32w0):go_ret_completed_terminal();(8w18,8w20,8w20,8w1,8w1,_,_,_,_,_,_,32w0,32w0x80000,32w0):go_ret_nowork();(8w15,8w20,8w20,8w1,8w1,_,_,_,_,_,_,32w0,32w0x90000,32w0):go_ret_completed_terminal();(8w14,8w20,8w20,8w1,8w1,_,_,_,_,_,_,32w0,32w0x80000,_):go_ret_nowork();(8w11,8w20,8w20,8w1,8w1,_,_,_,_,_,_,32w0,32w0x80000,_):go_ret_nowork();(8w5,8w20,8w20,8w1,8w1,_,_,_,_,_,_,32w0,32w0,_):go_ret_nowork();(8w6,8w20,8w20,8w1,8w1,_,_,_,_,_,_,32w0,32w0,_):go_ret_ready();(8w1,_,_,8w0,_,_,_,_,_,_,_,_,_,_):go_ret_abort();(8w2,_,_,8w0,_,_,_,_,_,_,_,_,_,_):go_ret_abort();(8w3,_,_,8w0,_,_,_,_,_,_,_,_,_,_):go_ret_abort();(8w0,8w1,8w0,8w1,8w1,_,_,_,_,_,_,_,_,_):go_new(8w1);(8w0,8w2,8w0,8w2,8w1,_,_,_,_,_,_,_,_,_):go_new(8w2);(8w0,8w3,8w0,8w1,8w1,_,_,_,_,_,_,_,_,_):go_new(8w3);(8w0,8w4,8w0,8w1,8w1,_,_,_,_,_,_,_,_,_):go_keep(8w4);(8w0,8w4,8w0,8w2,8w1,_,_,_,_,_,_,_,_,_):go_keep(8w4);(8w0,8w5,8w0,8w1,8w1,8w1,8w1,8w0,8w0,8w0,8w0,_,_,_):go_new(8w5);(8w0,8w6,8w0,8w2,8w1,8w1,8w1,8w0,8w0,8w0,8w0,_,_,_):go_new(8w6);(8w0,8w7,8w0,8w1,8w1,8w1,8w1,8w0,8w0,8w0,8w0,_,_,_):go_new(8w7);(8w0,8w9,8w0,8w1,8w1,8w1,8w1,8w0,8w0,8w0,8w0,_,_,_):go_new(8w9);(8w0,8w11,8w0,8w2,8w1,8w1,8w1,8w0,8w0,8w0,8w0,_,_,_):go_new(8w11);(8w0,8w3,8w0,8w2,8w1,_,_,_,_,_,_,_,_,_):go_new(8w10);(8w0,8w12,8w0,8w1,8w1,_,_,_,_,_,_,_,_,_):go_new(8w12);(_,8w1,8w1,_,_,_,_,_,_,_,_,_,_,_):go_ret_work();(_,8w2,8w2,_,_,_,_,_,_,_,_,_,_,_):go_ret_work();(_,8w3,8w3,_,_,_,_,_,_,_,_,_,_,_):go_ret_work();(_,8w4,8w4,_,_,_,_,_,_,_,_,_,_,_):go_ret_nowork();(8w3,8w5,8w5,_,_,8w1,8w1,8w0,8w0,8w0,8w0,_,_,_):go_ret_select_pending();(_,8w5,8w5,_,_,8w1,8w1,8w0,8w0,8w0,8w0,_,_,_):go_ret_work();(_,8w6,8w6,_,_,8w1,8w1,8w0,8w0,8w0,8w0,_,_,_):go_ret_work();(_,8w7,8w7,_,_,8w1,8w1,8w0,8w0,8w0,8w0,_,_,_):go_ret_work();(_,8w1,8w8,_,_,_,_,_,_,_,_,_,_,_):go_ret_work();(_,8w2,8w8,_,_,_,_,_,_,_,_,_,_,_):go_ret_work();(_,8w3,8w8,_,_,_,_,_,_,_,_,_,_,_):go_ret_work();(_,8w9,8w9,_,_,8w1,8w1,8w0,8w0,8w0,8w0,_,_,_):go_ret_work();(_,8w3,8w10,_,_,_,_,_,_,_,_,_,_,_):go_ret_work();(_,8w11,8w11,_,_,8w1,8w1,8w0,8w0,8w0,8w0,_,_,_):go_ret_work();(_,8w6,8w16,_,_,8w1,8w1,8w0,8w0,8w0,8w0,_,_,_):go_ret_work();(_,8w12,8w12,_,_,_,_,_,_,_,_,_,_,_):go_ret_work();(8w5,8w5,8w255,8w1,8w1,_,8w1,8w0,8w0,8w0,8w0,32w0,_,_):go_ret_local_terminal();(_,_,8w255,_,_,_,_,_,_,_,_,_,_,_):go_ret_work();(8w1,_,_,_,_,_,_,_,_,_,_,_,_,_):go_ret_abort();(8w2,_,_,_,_,_,_,_,_,_,_,_,_,_):go_ret_abort();(8w3,_,_,_,_,_,_,_,_,_,_,_,_,_):go_ret_abort();}}
 apply{
  m.return_abort=8w0;m.work_op=8w0;m.owner_op=8w0;m.generation=32w0;m.expected=hdr.expected_cell.expected_cell;m.desired=32w0;m.go=8w0;m.owner_diff=32w1;m.expected_work_phase=(bit<32>)m.stage;
  // Full packet identity echo for the genuine, epoch-qualified pre-M abort.
  if(m.kind==8w20){m.prefix_difference=hdr.work_generation.generation-hdr.cache.generation;m.cached_owner_diff=hdr.expected_cell.expected_cell-hdr.cache.expected_owner;}else{m.prefix_difference=hdr.envelope.epoch-hdr.expected_cell.expected_cell;}
  m.terminal_diff=hdr.envelope.epoch-hdr.completion.epoch;
  ports.apply();network.apply();
  // Parsed network validity includes the parser's exact private format/event gate.
  if(m.port_valid==8w1&&m.network_valid==8w1){
   connection.apply();
   if(m.packet_kind==8w5||m.packet_kind==8w6||m.packet_kind==8w7){
    data_connection.apply();
    if(m.response==8w1){response_profile.apply();}else{profile.apply();}
    input_head_t.apply();if(m.response==8w1){response_crc0_t.apply();response_crc1_t.apply();response_crct_t.apply();}else{input_body_t.apply();input_tail_t.apply();}
    if(hdr.dl.crc!=(m.hcrc[7:0]++m.hcrc[15:8])){m.badh=8w1;}
    if(hdr.first.crc!=(m.bcrc[7:0]++m.bcrc[15:8])){m.badb=8w1;}
    if(m.response==8w1){if(hdr.second.crc!=(m.crc1[7:0]++m.crc1[15:8])){m.bad1=8w1;}if(hdr.response_tail.crc!=(m.tcrc[7:0]++m.tcrc[15:8])){m.badt=8w1;}}
    else{if(hdr.tail.crc!=(m.tcrc[7:0]++m.tcrc[15:8])){m.badt=8w1;}}
   }else if(m.packet_kind==8w9||m.packet_kind==8w11){
    read_connection.apply();rd_head_t.apply();
    if(m.packet_kind==8w9){read_request_profile.apply();rd_request_crc_t.apply();}else{read_response_profile.apply();rd_first_crc_t.apply();rd_second_crc_t.apply();rd_tail_crc_t.apply();}
    if(hdr.dl.dst!=m.link_dst||hdr.dl.src!=m.link_src){m.badh=8w1;}
    if(hdr.dl.crc!=(m.hcrc[7:0]++m.hcrc[15:8])){m.badh=8w1;}
    if(m.packet_kind==8w9){if(hdr.rd_req.crc!=(m.bcrc[7:0]++m.bcrc[15:8])){m.badb=8w1;}}
    else{if(hdr.first.crc!=(m.bcrc[7:0]++m.bcrc[15:8])){m.badb=8w1;}if(hdr.second.crc!=(m.crc1[7:0]++m.crc1[15:8])){m.bad1=8w1;}if(hdr.rd_tail.crc!=(m.tcrc[7:0]++m.tcrc[15:8])){m.badt=8w1;}}
   }
   guard.apply();
   if(m.go==8w1){
    if(m.packet_kind==8w5||m.packet_kind==8w6||m.packet_kind==8w7){
     if(m.response==8w1){compare_response_inputs_t.apply();}else{if(m.packet_kind==8w5){compare_select_inputs_t.apply();}else{compare_operate_inputs_t.apply();}}
    }
    ack_native_t.apply();read_input_t.apply();
    work.apply(m.work_op,m.generation,m.expected_work_phase,m.work_phase);
    // Genuine stamped final returns are terminal: no bank access follows free.
    if(m.work_op==8w4||m.stage==8w15){deny();}else{
    active_generation_t.apply();
    next_seq_t.apply();epoch_t.apply();client_t.apply();server_t.apply();
    sequence_diff.apply();sequence_guard.apply();
    owner_command.apply();owner_t.apply();
    if(m.packet_kind==8w5||m.packet_kind==8w6||m.packet_kind==8w7){
     real_links_t.apply();real_tcp_dst_t.apply();real_object_t.apply();real_off_t.apply();native_end_t.apply();application_t.apply();frozen_decoy_object_t.apply();frozen_decoy_off_t.apply();
    }
    read_app_t.apply();
    if(m.kind==8w20){ready_result_t.apply();}else if(m.stage==8w0){
     if(m.packet_kind==8w6||m.packet_kind==8w7){object_match.apply();}
     if((m.work_op==8w1&&(m.work_phase==32w4||m.work_phase==32w9))||(m.kind==8w4&&m.shape_valid==8w1)){
      snapshot_t.apply();first_event.apply();
     }else if(m.work_op==8w1){busy_t.apply();}
    }else if(m.kind==8w4){reset_boundary.apply();}
    else if(m.work_phase==32w1||m.work_phase==32w2){
     if(m.epoch_diff!=32w0){abort_t.apply();}
     else if(m.kind==8w8||m.kind==8w10||m.kind==8w12){if(m.owner_diff!=32w0){abort_t.apply();}}
     else{if(m.owner_op==8w1&&m.owner_diff==32w0){carry_t.apply();}else{abort_t.apply();}}
     next_stage_t.apply();
    }else if(m.work_phase==32w3){read_terminal_t.apply();}
    else{deny();}
    }
   }else if(m.stage!=8w0){deny();}
  }else if(m.stage!=8w0){deny();}
 }
}
control n_IgDeparser(packet_out pkt,inout n_headers_t hdr,in n_meta_t m,in ingress_intrinsic_metadata_for_deparser_t md){apply{pkt.emit(hdr);}}
parser n_EgParser(packet_in pkt,out n_headers_t hdr,out n_meta_t m,out egress_intrinsic_metadata_t eg){state start{pkt.extract(eg);transition accept;}}
control n_Egress(inout n_headers_t hdr,inout n_meta_t m,in egress_intrinsic_metadata_t eg,in egress_intrinsic_metadata_from_parser_t p,inout egress_intrinsic_metadata_for_deparser_t md,inout egress_intrinsic_metadata_for_output_port_t port){apply{}}
control n_EgDeparser(packet_out pkt,inout n_headers_t hdr,in n_meta_t m,in egress_intrinsic_metadata_for_deparser_t md){apply{}}

/* Partial ordinary SELECT M prepare: actual N28 handoff, full native35 validation,
 * captured decoy construction and persistent producer reservation. No release
 * authority: E must finish all image stores before ready; N commits afterward. */
header m_eth_h {bit<48> dst;bit<48> src;bit<16> type;}
header m_ip_h {bit<4> version;bit<4> ihl;bit<8> tos;bit<16> len;bit<16> id;bit<3> flags;bit<13> frag;bit<8> ttl;bit<8> proto;bit<16> checksum;bit<32> src;bit<32> dst;}
header m_tcp_h {bit<16> sport;bit<16> dport;bit<32> seq;bit<32> ack;bit<4> offset;bit<4> reserved;bit<8> flags;bit<16> window;bit<16> checksum;bit<16> urgent;}
header m_dl_h{bit<16> magic;bit<8> len;bit<8> ctrl;bit<16> dst;bit<16> src;bit<16> crc;}
header m_native_h{bit<8> tp;bit<8> app;bit<8> func;bit<8> group;bit<8> variation;bit<8> qualifier;bit<16> count;bit<16> index;bit<8> code;bit<8> repeat;bit<32> on;bit<16> crc;}
header m_tail_h{bit<32> off;bit<8> status;bit<16> crc;}
header m_appended_h{bit<32> off;bit<8> status;bit<8> group;bit<8> variation;bit<8> qualifier;bit<16> count;bit<16> index;bit<8> code;bit<8> repeat;bit<16> on_first;bit<16> crc;}
header m_final_h{bit<16> on_last;bit<32> off;bit<8> status;bit<16> crc;}
header m_reference_h{bit<32> epoch;bit<32> generation;bit<32> expected_owner;bit<16> event;bit<16> format;}
header m_captured_decoy_h{bit<16> index;bit<8> code;bit<8> repeat;bit<32> on;bit<32> off;}
header m_cache_reference_h{bit<32> generation;bit<32> expected_owner;}
header m_image_h{bit<32> w0;bit<32> w1;bit<32> w2;bit<32> w3;bit<32> w4;bit<32> w5;bit<32> w6;bit<32> w7;bit<32> w8;bit<32> w9;bit<32> w10;bit<32> w11;bit<32> w12;bit<24> w13;}
struct m_context_t{bit<32> epoch;bit<32> owner;}
struct m_ledger_tag_t{bit<32> epoch;bit<32> generation;}
struct m_producer_cell_t{bit<32> generation;bit<32> phase;}
header m_completion_epoch_h{bit<32> epoch;}
struct m_headers_t{m_reference_h reference;m_captured_decoy_h captured;m_cache_reference_h cache;m_completion_epoch_h completion;m_eth_h eth;m_ip_h ip;m_tcp_h tcp;m_dl_h dl;m_native_h native;m_tail_h tail;m_appended_h appended;m_final_h last;m_image_h image;}
struct m_meta_t{bit<8> role;bit<32> stamp_diff;bit<32> context_owner;bit<32> context_grant;bit<32> ref_gen_diff;bit<32> ref_owner_diff;bit<32> activation_grant;bit<1> geometry_done;bit<1> position_done;bit<1> ledger_done;bit<32> reservation_grant;bit<1> parsed;bit<1> enabled;bit<1> profile;bit<1> changed;bool ip_error;bit<16> tcp_sum;bit<16> tcp_length;bit<16> decoy_index;bit<8> decoy_code;bit<8> decoy_repeat;bit<32> decoy_on;bit<32> decoy_off;bit<16> hcrc;bit<16> bcrc;bit<16> tcrc;bit<1> badh;bit<1> badb;bit<1> badt;}
parser m_IgParser(packet_in pkt,out m_headers_t hdr,out m_meta_t m,out ingress_intrinsic_metadata_t ig){Checksum() ic;Checksum() tc;
 state start{pkt.extract(ig);pkt.advance(PORT_METADATA_SIZE);m.role=8w0;m.geometry_done=1w0;m.position_done=1w0;m.ledger_done=1w0;m.parsed=1w0;m.enabled=1w0;m.profile=1w0;m.changed=1w0;m.badh=1w0;m.badb=1w0;m.badt=1w0;transition select(ig.ingress_port){9w196:reference;9w198:terminal_reference;default:accept;}}
 state terminal_reference{pkt.extract(hdr.reference);transition select(hdr.reference.epoch){32w0:accept;default:terminal_generation;}}
 state terminal_generation{transition select(hdr.reference.generation){32w0:accept;default:terminal_owner;}}
 state terminal_owner{transition select(hdr.reference.expected_owner[31:16]){16w17:terminal_cookie;default:accept;}}
 state terminal_cookie{transition select(hdr.reference.expected_owner[15:0]){16w0:accept;default:terminal_event;}}
 state terminal_event{transition select(hdr.reference.event,hdr.reference.format){(16w0x0814,16w3):terminal_cache;default:accept;}}
 state reference{pkt.extract(hdr.reference);transition select(hdr.reference.epoch){32w0:accept;default:reference_generation;}}
 state reference_generation{transition select(hdr.reference.generation){32w0:accept;default:reference_owner;}}
 state reference_owner{transition select(hdr.reference.expected_owner[31:16]){16w9:reference_cookie;16w17:activation_cookie;default:accept;}}
 state activation_cookie{transition select(hdr.reference.expected_owner[15:0]){16w0:accept;default:activation_event;}}
 state activation_event{transition select(hdr.reference.event,hdr.reference.format){(16w0x0714,16w2):activation_cache;default:accept;}}
 state activation_cache{m.role=8w1;pkt.extract(hdr.cache);transition activation_eth;}
 state terminal_cache{m.role=8w2;pkt.extract(hdr.cache);pkt.extract(hdr.completion);transition activation_eth;}
 state activation_eth{pkt.extract(hdr.eth);transition select(hdr.eth.type){16w0x0800:activation_ip;default:accept;}}
 state activation_ip{pkt.extract(hdr.ip);ic.add(hdr.ip);m.ip_error=ic.verify();tc.subtract({hdr.ip.src,hdr.ip.dst,8w0,hdr.ip.proto,hdr.ip.len});transition select(hdr.ip.version,hdr.ip.ihl,hdr.ip.len,hdr.ip.proto){(4w4,4w5,16w95,8w6):activation_ip_flags;default:accept;}}
 state activation_ip_flags{transition select(hdr.ip.frag,hdr.ip.flags){(13w0,3w0):activation_tcp;(13w0,3w2):activation_tcp;default:accept;}}
 state activation_tcp{pkt.extract(hdr.tcp);tc.subtract(hdr.tcp);transition select(hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.flags,hdr.tcp.urgent){(4w5,4w0,8w0x10,16w0):activation_image;(4w5,4w0,8w0x18,16w0):activation_image;default:accept;}}
 state activation_image{pkt.extract(hdr.image);tc.subtract(hdr.image);m.tcp_sum=tc.get();m.parsed=1w1;transition accept;}
 state reference_cookie{transition select(hdr.reference.expected_owner[15:0]){16w0:accept;default:reference_event;}}
 state reference_event{transition select(hdr.reference.event,hdr.reference.format){(16w0x0305,16w1):captured;default:accept;}}
 state captured{pkt.extract(hdr.captured);transition eth;}
 state eth{pkt.extract(hdr.eth);transition select(hdr.eth.type){16w0x0800:ip;default:accept;}}
 state ip{pkt.extract(hdr.ip);ic.add(hdr.ip);m.ip_error=ic.verify();tc.subtract({hdr.ip.src,hdr.ip.dst,8w0,hdr.ip.proto,hdr.ip.len});transition select(hdr.ip.version,hdr.ip.ihl,hdr.ip.len,hdr.ip.proto){(4w4,4w5,16w75,8w6):ip_flags;default:accept;}}
 state ip_flags{transition select(hdr.ip.frag,hdr.ip.flags){(13w0,3w0):tcp;(13w0,3w2):tcp;default:accept;}}
 state tcp{pkt.extract(hdr.tcp);tc.subtract(hdr.tcp);transition select(hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.flags,hdr.tcp.urgent){(4w5,4w0,8w0x10,16w0):dl;(4w5,4w0,8w0x18,16w0):dl;default:accept;}}
 state dl{pkt.extract(hdr.dl);tc.subtract(hdr.dl);transition native;}
 state native{pkt.extract(hdr.native);tc.subtract(hdr.native);transition tail;}
 state tail{pkt.extract(hdr.tail);tc.subtract(hdr.tail);m.tcp_sum=tc.get();m.parsed=1w1;transition accept;}
}
control m_Ingress(inout m_headers_t hdr,inout m_meta_t m,in ingress_intrinsic_metadata_t ig,in ingress_intrinsic_metadata_from_parser_t p,inout ingress_intrinsic_metadata_for_deparser_t md,inout ingress_intrinsic_metadata_for_tm_t tm){
 action deny(){md.drop_ctl=3w1;}
 action route(PortId_t port){tm.ucast_egress_port=port;tm.bypass_egress=1w0;}
 table forwarding{key={ig.ingress_port:exact;}actions={route;deny;}size=4;default_action=deny();}
 action allow_connection(){m.enabled=1w1;}
 table connection{key={hdr.ip.src:exact;hdr.ip.dst:exact;hdr.tcp.sport:exact;hdr.tcp.dport:exact;}actions={allow_connection;NoAction;}size=1;default_action=NoAction();}
 Register<m_producer_cell_t,bit<1>>(1,{0,4}) reservation;
 RegisterAction<m_producer_cell_t,bit<1>,bit<32>>(reservation) reserve={
  void apply(inout m_producer_cell_t value,out bit<32> granted){
   granted=32w0;
   if(value.phase==32w4&&value.generation<hdr.reference.generation){
    value.generation=hdr.reference.generation;value.phase=32w1;granted=32w1;
   }
  }
 };
 action reserve_producer(){m.reservation_grant=reserve.execute(1w0);}
 table reserve_t{actions={reserve_producer;}size=1;const default_action=reserve_producer();}

 Register<m_context_t,bit<1>>(1,{0,0}) producer_context;
 RegisterAction<m_context_t,bit<1>,bit<32>>(producer_context) context_write={void apply(inout m_context_t value,out bit<32> result){value.epoch=hdr.reference.epoch;value.owner=m.context_owner;result=32w0;}};
 RegisterAction<m_context_t,bit<1>,bit<32>>(producer_context) context_check={void apply(inout m_context_t value,out bit<32> result){result=32w0;if(value.epoch!=hdr.reference.epoch||value.owner!=m.context_owner){result=32w1;}}};
 action qualify_context(){m.context_grant=context_check.execute(1w0);}
 table qualify_context_t{actions={qualify_context;}size=1;const default_action=qualify_context();}
 RegisterAction<m_producer_cell_t,bit<1>,bit<32>>(reservation) inspect={void apply(inout m_producer_cell_t value,out bit<32> result){result=32w0;if(value.generation==hdr.reference.generation&&value.phase==32w1){result=32w1;}}};
 RegisterAction<m_producer_cell_t,bit<1>,bit<32>>(reservation) retire={void apply(inout m_producer_cell_t value,out bit<32> result){result=32w0;if(value.generation==hdr.reference.generation&&value.phase==32w1){value.phase=32w4;result=32w1;}}};
 action inspect_reservation(){m.reservation_grant=inspect.execute(1w0);}
 action retire_reservation(){m.reservation_grant=retire.execute(1w0);}
 table activation_reservation_t{key={m.role:exact;}actions={inspect_reservation;retire_reservation;NoAction;}size=2;const default_action=NoAction();const entries={8w1:inspect_reservation();8w2:retire_reservation();}}
 Register<bit<32>,bit<1>>(1,0) activation_receipt;
 RegisterAction<bit<32>,bit<1>,bit<32>>(activation_receipt) claim_activation={void apply(inout bit<32> value,out bit<32> result){result=32w0;if(value<hdr.reference.generation){value=hdr.reference.generation;result=32w1;}}};
 action claim_once(){m.activation_grant=claim_activation.execute(1w0);}
 table claim_once_t{actions={claim_once;}size=1;const default_action=claim_once();}
 Register<bit<32>,bit<1>>(1,0) geo_first;
 RegisterAction<bit<32>,bit<1>,bit<1>>(geo_first) write_geometry={void apply(inout bit<32> value,out bit<1> done){value=hdr.tcp.seq+32w35;done=1w1;}};
 action activate_geometry(){m.geometry_done=write_geometry.execute(1w0);}
 table activate_geometry_t{actions={activate_geometry;}size=1;const default_action=activate_geometry();}
 Register<bit<32>,bit<1>>(1,0) ledger_position;
 RegisterAction<bit<32>,bit<1>,bit<1>>(ledger_position) write_position={void apply(inout bit<32> value,out bit<1> done){value=hdr.tcp.seq;done=1w1;}};
 action activate_position(){m.position_done=write_position.execute(1w0);}
 table activate_position_t{actions={activate_position;}size=1;const default_action=activate_position();}
 Register<m_ledger_tag_t,bit<1>>(1,{0,0}) ledger_tag;
 RegisterAction<m_ledger_tag_t,bit<1>,bit<1>>(ledger_tag) write_ledger={void apply(inout m_ledger_tag_t value,out bit<1> done){value.epoch=hdr.reference.epoch;value.generation=hdr.cache.generation;done=1w1;}};
 action activate_ledger(){m.ledger_done=write_ledger.execute(1w0);}
 table activate_ledger_t{key={m.geometry_done:exact;m.position_done:exact;}actions={activate_ledger;NoAction;}size=1;const default_action=NoAction();const entries={(1w1,1w1):activate_ledger();}}
 action dirty_return(){hdr.completion.setValid();hdr.completion.epoch=hdr.reference.epoch;hdr.reference.format=16w3;hdr.reference.event=16w0x0814;tm.ucast_egress_port=9w198;tm.bypass_egress=1w1;}
 table dirty_return_t{key={m.ledger_done:exact;}actions={dirty_return;deny;}size=1;const default_action=deny();const entries={1w1:dirty_return();}}
 action to_endpoint_egress(){hdr.completion.setInvalid();hdr.reference.format=16w2;hdr.reference.event=16w0x0914;tm.ucast_egress_port=9w68;tm.bypass_egress=1w0;}
 table terminal_result_t{key={m.reservation_grant:exact;}actions={to_endpoint_egress;deny;}size=1;const default_action=deny();const entries={32w1:to_endpoint_egress();}}
 action reference_differences(){m.ref_gen_diff=hdr.reference.generation-hdr.cache.generation;m.ref_owner_diff=hdr.reference.expected_owner-hdr.cache.expected_owner;}
 table reference_differences_t{actions={reference_differences;}size=1;const default_action=reference_differences();}
 action no_stamp(){m.stamp_diff=32w0;}
 action compare_stamp(){m.stamp_diff=hdr.reference.epoch-hdr.completion.epoch;}
 table stamp_t{key={m.role:exact;}actions={no_stamp;compare_stamp;}size=1;const default_action=no_stamp();const entries={8w2:compare_stamp();}}
 action activate_allowed(){m.profile=1w1;}
 table activation_identity_t{key={m.ref_gen_diff:exact;m.ref_owner_diff:exact;m.stamp_diff:exact;}actions={activate_allowed;NoAction;}size=1;const default_action=NoAction();const entries={(32w0,32w0x80000,32w0):activate_allowed();}}
 action prepare_context_owner(){m.context_owner=hdr.reference.expected_owner;}
 action activation_context_owner(){m.context_owner=hdr.cache.expected_owner;}
 table context_owner_t{key={m.role:exact;}actions={prepare_context_owner;activation_context_owner;}size=2;const entries={8w1:activation_context_owner();8w2:activation_context_owner();}const default_action=prepare_context_owner();}
 action eligible(){m.profile=1w1;}
 table profile{key={hdr.dl.magic:exact;hdr.dl.len:exact;hdr.dl.ctrl:exact;hdr.native.tp:ternary;hdr.native.app:ternary;hdr.native.func:exact;hdr.native.group:exact;hdr.native.variation:exact;hdr.native.qualifier:exact;hdr.native.count:exact;hdr.tail.status:exact;}
 actions={eligible;NoAction;}size=1;const default_action=NoAction();const entries={(16w0x0564,8w26,8w0xC4,8w0xC0&&&8w0xC0,8w0xC0&&&8w0xF0,8w3,8w12,8w1,8w0x28,16w0x0100,8w0):eligible();}}
 CRCPolynomial<bit<16>>(16w0x3D65,true,false,false,16w0,16w0xFFFF) poly;
Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_head;
Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_body;
Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_tail;
Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_newhead;
Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_newbody;
Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_newtail;
action input_head(){m.hcrc=hash_head.get({hdr.dl.magic,hdr.dl.len,hdr.dl.ctrl,hdr.dl.dst,hdr.dl.src});}
table input_head_t{actions={input_head;}size=1;const default_action=input_head();}
action input_body(){m.bcrc=hash_body.get({hdr.native.tp,hdr.native.app,hdr.native.func,hdr.native.group,hdr.native.variation,hdr.native.qualifier,hdr.native.count,hdr.native.index,hdr.native.code,hdr.native.repeat,hdr.native.on});}
table input_body_t{actions={input_body;}size=1;const default_action=input_body();}
action input_tail(){m.tcrc=hash_tail.get({hdr.tail.off,hdr.tail.status});}
table input_tail_t{actions={input_tail;}size=1;const default_action=input_tail();}
action construct(){context_write.execute(1w0);hdr.appended.setValid();hdr.last.setValid();hdr.appended.off=hdr.tail.off;hdr.appended.status=hdr.tail.status;hdr.appended.group=8w12;hdr.appended.variation=8w1;hdr.appended.qualifier=8w0x28;hdr.appended.count=16w0x0100;hdr.appended.index=hdr.captured.index;hdr.appended.code=hdr.captured.code;hdr.appended.repeat=hdr.captured.repeat;hdr.appended.on_first=hdr.captured.on[31:16];hdr.last.on_last=hdr.captured.on[15:0];hdr.last.off=hdr.captured.off;hdr.last.status=8w0;hdr.tail.setInvalid();hdr.dl.len=8w44;hdr.ip.len=16w95;m.tcp_length=16w75;m.changed=1w1;hdr.cache.setValid();hdr.cache.generation=hdr.reference.generation;hdr.cache.expected_owner=hdr.reference.expected_owner;hdr.reference.event=16w0x0405;hdr.reference.format=16w2;}
 table construct_t{actions={construct;}size=1;const default_action=construct();}
action output_newhead(){m.hcrc=hash_newhead.get({hdr.dl.magic,hdr.dl.len,hdr.dl.ctrl,hdr.dl.dst,hdr.dl.src});}
table output_newhead_t{actions={output_newhead;}size=1;const default_action=output_newhead();}
action output_newbody(){m.bcrc=hash_newbody.get({hdr.appended.off,hdr.appended.status,hdr.appended.group,hdr.appended.variation,hdr.appended.qualifier,hdr.appended.count,hdr.appended.index,hdr.appended.code,hdr.appended.repeat,hdr.appended.on_first});}
table output_newbody_t{actions={output_newbody;}size=1;const default_action=output_newbody();}
action output_newtail(){m.tcrc=hash_newtail.get({hdr.last.on_last,hdr.last.off,hdr.last.status});}
table output_newtail_t{actions={output_newtail;}size=1;const default_action=output_newtail();}
action crc_render(){hdr.dl.crc=m.hcrc[7:0]++m.hcrc[15:8];hdr.appended.crc=m.bcrc[7:0]++m.bcrc[15:8];hdr.last.crc=m.tcrc[7:0]++m.tcrc[15:8];}
 table crc_render_t{actions={crc_render;}size=1;const default_action=crc_render();}
 table crc_gate{key={m.badh:exact;m.badb:exact;m.badt:exact;}actions={NoAction;}size=1;const default_action=NoAction();}
 apply{
 stamp_t.apply();context_owner_t.apply();forwarding.apply();
 if(md.drop_ctl==3w0&&m.parsed==1w1&&!m.ip_error&&m.tcp_sum==16w0xFFEB&&hdr.ip.ttl!=8w0){
  connection.apply();
  if(m.role==8w1||m.role==8w2){
   reference_differences_t.apply();activation_identity_t.apply();
   if(m.enabled==1w1&&m.profile==1w1){
    activation_reservation_t.apply();
    if(m.role==8w2){terminal_result_t.apply();}else if(m.reservation_grant==32w1){
     qualify_context_t.apply();
     if(m.context_grant==32w0){
      claim_once_t.apply();
      if(m.activation_grant==32w1){activate_geometry_t.apply();activate_position_t.apply();activate_ledger_t.apply();dirty_return_t.apply();}else{deny();}
     }else{deny();}
    }else{deny();}
   }else{deny();}
  }else{profile.apply();
  if(m.enabled==1w1&&m.profile==1w1){
   input_head_t.apply();input_body_t.apply();input_tail_t.apply();
   if(hdr.dl.crc!=(m.hcrc[7:0]++m.hcrc[15:8])){m.badh=1w1;}
   if(hdr.native.crc!=(m.bcrc[7:0]++m.bcrc[15:8])){m.badb=1w1;}
   if(hdr.tail.crc!=(m.tcrc[7:0]++m.tcrc[15:8])){m.badt=1w1;}
   if(m.badh==1w0&&m.badb==1w0&&m.badt==1w0&&hdr.native.index!=hdr.captured.index){
    reserve_t.apply();
    if(m.reservation_grant==32w1){
     construct_t.apply();output_newhead_t.apply();output_newbody_t.apply();output_newtail_t.apply();crc_render_t.apply();
    }else{deny();}
   }else{deny();}
  }else{deny();}
 }
 }else{deny();}
 }
}
control m_IgDeparser(packet_out pkt,inout m_headers_t hdr,in m_meta_t m,in ingress_intrinsic_metadata_for_deparser_t md){Checksum() ic;Checksum() tc;apply{if(m.changed==1w1){hdr.ip.checksum=ic.update({hdr.ip.version,hdr.ip.ihl,hdr.ip.tos,hdr.ip.len,hdr.ip.id,hdr.ip.flags,hdr.ip.frag,hdr.ip.ttl,hdr.ip.proto,hdr.ip.src,hdr.ip.dst});hdr.tcp.checksum=tc.update({hdr.ip.src,hdr.ip.dst,8w0,hdr.ip.proto,m.tcp_length,hdr.tcp.sport,hdr.tcp.dport,hdr.tcp.seq,hdr.tcp.ack,hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.flags,hdr.tcp.window,hdr.tcp.urgent,hdr.dl.magic,hdr.dl.len,hdr.dl.ctrl,hdr.dl.dst,hdr.dl.src,hdr.dl.crc,hdr.native.tp,hdr.native.app,hdr.native.func,hdr.native.group,hdr.native.variation,hdr.native.qualifier,hdr.native.count,hdr.native.index,hdr.native.code,hdr.native.repeat,hdr.native.on,hdr.native.crc,hdr.appended.off,hdr.appended.status,hdr.appended.group,hdr.appended.variation,hdr.appended.qualifier,hdr.appended.count,hdr.appended.index,hdr.appended.code,hdr.appended.repeat,hdr.appended.on_first,hdr.appended.crc,hdr.last.on_last,hdr.last.off,hdr.last.status,hdr.last.crc});}pkt.emit(hdr.reference);pkt.emit(hdr.cache);pkt.emit(hdr.completion);pkt.emit(hdr.eth);pkt.emit(hdr.ip);pkt.emit(hdr.tcp);pkt.emit(hdr.dl);pkt.emit(hdr.native);pkt.emit(hdr.tail);pkt.emit(hdr.appended);pkt.emit(hdr.last);pkt.emit(hdr.image);}}
parser m_EgParser(packet_in pkt,out m_headers_t hdr,out m_meta_t m,out egress_intrinsic_metadata_t eg){state start{pkt.extract(eg);transition accept;}}
control m_Egress(inout m_headers_t hdr,inout m_meta_t m,in egress_intrinsic_metadata_t eg,in egress_intrinsic_metadata_from_parser_t p,inout egress_intrinsic_metadata_for_deparser_t md,inout egress_intrinsic_metadata_for_output_port_t port){apply{}}
control m_EgDeparser(packet_out pkt,inout m_headers_t hdr,in m_meta_t m,in egress_intrinsic_metadata_for_deparser_t md){apply{}}

/* Partial protected E prepare. Typed24B interface; no endpoint release authority. */
header e_eth_h {bit<48> dst;bit<48> src;bit<16> type;}
header e_ip_h {bit<4> version;bit<4> ihl;bit<8> tos;bit<16> len;bit<16> id;bit<3> flags;bit<13> frag;bit<8> ttl;bit<8> proto;bit<16> checksum;bit<32> src;bit<32> dst;}
header e_tcp_h {bit<16> sport;bit<16> dport;bit<32> seq;bit<32> ack;bit<4> offset;bit<4> reserved;bit<8> flags;bit<16> window;bit<16> checksum;bit<16> urgent;}
header e_reference_h{bit<32> epoch;bit<32> generation;bit<32> expected_owner;bit<16> event;bit<16> format;}
header e_captured_decoy_h{bit<16> index;bit<8> code;bit<8> repeat;bit<32> on;bit<32> off;}
header e_cache_reference_h{bit<32> generation;bit<32> expected_owner;}
header e_completion_h{bit<32> epoch;bit<32> generation;bit<32> expected_owner;bit<16> event;bit<16> format;bit<32> cached_generation;bit<32> cached_owner;}
header e_completion_stamp_h{bit<32> epoch;}
header e_image_h{bit<32> w0;bit<32> w1;bit<32> w2;bit<32> w3;bit<32> w4;bit<32> w5;bit<32> w6;bit<32> w7;bit<32> w8;bit<32> w9;bit<32> w10;bit<32> w11;bit<32> w12;bit<24> w13;}
struct e_producer_cell_t{bit<32> generation;bit<32> phase;}
struct e_cache_tag_t{bit<32> epoch;bit<32> generation;}
struct e_headers_t{e_reference_h reference;e_cache_reference_h cache;e_completion_stamp_h completion;e_eth_h eth;e_ip_h ip;e_tcp_h tcp;e_image_h image;}
struct e_meta_t{bit<32> pin_generation;bit<16> tcp_length;bit<32> completion_epoch;bit<32> completion_generation;bit<32> completion_owner;bit<32> completion_cache_generation;bit<32> completion_cache_owner;bit<16> completion_event;bit<16> completion_format;bit<32> expected_phase;bit<32> completion_diff;bit<10> mirror_sid;bit<1> emit_ready;bit<8> role;bit<32> tag_match;bit<32> stored_owner_diff;bit<32> stored_position_diff;bit<1> parsed;bit<1> enabled;bool ip_error;bit<16> tcp_sum;bit<32> grant;bit<32> gen_diff;bit<32> owner_diff;bit<1> done0;bit<1> done1;bit<1> done2;bit<1> done3;bit<1> done4;bit<1> done5;bit<1> done6;bit<1> done7;bit<1> done8;bit<1> done9;bit<1> done10;bit<1> done11;bit<1> done12;bit<1> done13;bit<1> position_done;bit<1> tag_done;bit<1> owner_done;bit<1> identity_grant;}
parser e_EgParser(packet_in pkt,out e_headers_t hdr,out e_meta_t m,out egress_intrinsic_metadata_t eg){Checksum() ic;Checksum() tc;
 state start{pkt.extract(eg);m.grant=32w0;m.emit_ready=1w0;m.role=8w0;m.parsed=1w0;m.enabled=1w0;m.identity_grant=1w0;m.position_done=1w0;m.tag_done=1w0;m.owner_done=1w0;m.done0=1w0;m.done1=1w0;m.done2=1w0;m.done3=1w0;m.done4=1w0;m.done5=1w0;m.done6=1w0;m.done7=1w0;m.done8=1w0;m.done9=1w0;m.done10=1w0;m.done11=1w0;m.done12=1w0;m.done13=1w0;transition select(eg.egress_port){9w68:reference;9w2:emit_reference;default:reject;}}
 state emit_reference{m.role=8w2;pkt.extract(hdr.reference);transition select(hdr.reference.epoch){32w0:reject;default:emit_generation;}}
 state emit_generation{transition select(hdr.reference.generation){32w0:reject;default:emit_owner;}}
 state emit_owner{transition select(hdr.reference.expected_owner[31:16]){16w17:emit_cookie;default:reject;}}
 state emit_cookie{transition select(hdr.reference.expected_owner[15:0]){16w0:reject;default:emit_event;}}
 state emit_event{transition select(hdr.reference.event,hdr.reference.format){(16w0x0b14,16w2):emit_cache;default:reject;}}
 state reference{pkt.extract(hdr.reference);transition select(hdr.reference.epoch){32w0:reject;default:generation;}}
 state generation{transition select(hdr.reference.generation){32w0:reject;default:owner;}}
 state owner{transition select(hdr.reference.expected_owner[31:16]){16w9:cookie;16w17:query_cookie;default:reject;}}
 state query_cookie{transition select(hdr.reference.expected_owner[15:0]){16w0:reject;default:query_event;}}
 state query_event{transition select(hdr.reference.event,hdr.reference.format){(16w0x0914,16w2):query_cache;(16w0x0e14,16w2):completion_cache;(16w0x1214,16w3):terminal_cache;default:reject;}}
 state terminal_cache{m.role=8w4;pkt.extract(hdr.cache);pkt.extract(hdr.completion);m.parsed=1w1;transition accept;}
 state emit_cache{pkt.extract(hdr.cache);transition eth;}
 state completion_cache{m.role=8w3;m.expected_phase=32w2;pkt.extract(hdr.cache);transition eth;}
 state query_cache{m.role=8w1;m.expected_phase=32w1;pkt.extract(hdr.cache);transition eth;}
 state cookie{transition select(hdr.reference.expected_owner[15:0]){16w0:reject;default:event;}}
 state event{transition select(hdr.reference.event,hdr.reference.format){(16w0x0405,16w2):cache;default:reject;}}
 state cache{pkt.extract(hdr.cache);transition eth;}
 state eth{pkt.extract(hdr.eth);transition select(hdr.eth.type){16w0x0800:ip;default:reject;}}
 state ip{pkt.extract(hdr.ip);ic.add(hdr.ip);m.ip_error=ic.verify();tc.subtract({hdr.ip.src,hdr.ip.dst,8w0,hdr.ip.proto,hdr.ip.len});transition select(hdr.ip.version,hdr.ip.ihl,hdr.ip.len,hdr.ip.proto){(4w4,4w5,16w95,8w6):ip_flags;default:reject;}}
 state ip_flags{transition select(hdr.ip.frag,hdr.ip.flags){(13w0,3w0):tcp;(13w0,3w2):tcp;default:reject;}}
 state tcp{pkt.extract(hdr.tcp);tc.subtract(hdr.tcp);transition select(hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.flags,hdr.tcp.urgent){(4w5,4w0,8w0x10,16w0):image;(4w5,4w0,8w0x18,16w0):image;default:reject;}}
 state image{pkt.extract(hdr.image);tc.subtract(hdr.image);m.tcp_sum=tc.get();m.parsed=1w1;transition accept;}
}
control e_Egress(inout e_headers_t hdr,inout e_meta_t m,in egress_intrinsic_metadata_t eg,in egress_intrinsic_metadata_from_parser_t p,inout egress_intrinsic_metadata_for_deparser_t md,inout egress_intrinsic_metadata_for_output_port_t port){
 action deny(){md.drop_ctl=3w1;}
 action allow_connection(){m.enabled=1w1;}
 table connection{key={hdr.ip.src:exact;hdr.ip.dst:exact;hdr.tcp.sport:exact;hdr.tcp.dport:exact;}actions={allow_connection;NoAction;}size=1;default_action=NoAction();}

 action compare_reference(){m.gen_diff=hdr.reference.generation-hdr.cache.generation;m.owner_diff=hdr.reference.expected_owner-hdr.cache.expected_owner;}
 table compare_reference_t{actions={compare_reference;}size=1;const default_action=compare_reference();}
 action identity_admitted(){m.identity_grant=1w1;}
 table identity_t{key={m.role:exact;m.gen_diff:ternary;m.owner_diff:exact;}actions={identity_admitted;NoAction;}size=5;const default_action=NoAction();const entries={(8w4,32w0,32w0x80000):identity_admitted();(8w0,32w0,32w0):identity_admitted();(8w1,_,32w0x80000):identity_admitted();(8w2,32w0,32w0x80000):identity_admitted();(8w3,32w0,32w0x80000):identity_admitted();}}
 action cache_pin_identity(){m.pin_generation=hdr.cache.generation;}
 action current_pin_identity(){m.pin_generation=hdr.reference.generation;}
 table pin_identity_t{key={m.role:exact;}actions={cache_pin_identity;current_pin_identity;deny;}size=5;const default_action=deny();const entries={8w0:cache_pin_identity();8w1:cache_pin_identity();8w2:cache_pin_identity();8w3:current_pin_identity();8w4:current_pin_identity();}}
 Register<e_producer_cell_t,bit<1>>(1,{0,4}) reservation;
 RegisterAction<e_producer_cell_t,bit<1>,bit<32>>(reservation) reserve={void apply(inout e_producer_cell_t value,out bit<32> granted){granted=32w0;if(value.phase==32w4&&value.generation<m.pin_generation){value.generation=m.pin_generation;value.phase=32w1;granted=32w1;}}};
 action reserve_image(){m.grant=reserve.execute(1w0);}
 table reserve_t{actions={reserve_image;}size=1;const default_action=reserve_image();}
 RegisterAction<e_producer_cell_t,bit<1>,bit<32>>(reservation) claim_emit={void apply(inout e_producer_cell_t value,out bit<32> granted){granted=32w0;if(value.generation==m.pin_generation&&value.phase==32w1){value.generation=m.pin_generation;value.phase=32w2;granted=32w1;}}};
 RegisterAction<e_producer_cell_t,bit<1>,bit<32>>(reservation) terminal={void apply(inout e_producer_cell_t value,out bit<32> granted){granted=32w0;if(value.generation==m.pin_generation&&value.phase==32w2){value.phase=32w4;granted=32w1;}}};
 action claim_endpoint(){m.grant=claim_emit.execute(1w0);}
 table claim_endpoint_t{actions={claim_endpoint;}size=1;const default_action=claim_endpoint();}
 action retire_emit(){m.grant=terminal.execute(1w0);}
 table retire_emit_t{actions={retire_emit;}size=1;const default_action=retire_emit();}
 Register<bit<32>,bit<1>>(1,0) image_0;
 RegisterAction<bit<32>,bit<1>,bit<1>>(image_0) write_0={void apply(inout bit<32> value,out bit<1> completed){value=hdr.image.w0;completed=1w1;}};
 action store_0(){m.done0=write_0.execute(1w0);}
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_0) read_0={void apply(inout bit<32> value,out bit<32> result){result=value;}};
 action load_0(){hdr.image.w0=read_0.execute(1w0);m.done0=1w1;}
 table load_0_t{actions={load_0;}size=1;const default_action=load_0();}
 table store_0_t{actions={store_0;}size=1;const default_action=store_0();}
 Register<bit<32>,bit<1>>(1,0) image_1;
 RegisterAction<bit<32>,bit<1>,bit<1>>(image_1) write_1={void apply(inout bit<32> value,out bit<1> completed){value=hdr.image.w1;completed=1w1;}};
 action store_1(){m.done1=write_1.execute(1w0);}
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_1) read_1={void apply(inout bit<32> value,out bit<32> result){result=value;}};
 action load_1(){hdr.image.w1=read_1.execute(1w0);m.done1=1w1;}
 table load_1_t{actions={load_1;}size=1;const default_action=load_1();}
 table store_1_t{actions={store_1;}size=1;const default_action=store_1();}
 Register<bit<32>,bit<1>>(1,0) image_2;
 RegisterAction<bit<32>,bit<1>,bit<1>>(image_2) write_2={void apply(inout bit<32> value,out bit<1> completed){value=hdr.image.w2;completed=1w1;}};
 action store_2(){m.done2=write_2.execute(1w0);}
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_2) read_2={void apply(inout bit<32> value,out bit<32> result){result=value;}};
 action load_2(){hdr.image.w2=read_2.execute(1w0);m.done2=1w1;}
 table load_2_t{actions={load_2;}size=1;const default_action=load_2();}
 table store_2_t{actions={store_2;}size=1;const default_action=store_2();}
 Register<bit<32>,bit<1>>(1,0) image_3;
 RegisterAction<bit<32>,bit<1>,bit<1>>(image_3) write_3={void apply(inout bit<32> value,out bit<1> completed){value=hdr.image.w3;completed=1w1;}};
 action store_3(){m.done3=write_3.execute(1w0);}
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_3) read_3={void apply(inout bit<32> value,out bit<32> result){result=value;}};
 action load_3(){hdr.image.w3=read_3.execute(1w0);m.done3=1w1;}
 table load_3_t{actions={load_3;}size=1;const default_action=load_3();}
 table store_3_t{actions={store_3;}size=1;const default_action=store_3();}
 Register<bit<32>,bit<1>>(1,0) image_4;
 RegisterAction<bit<32>,bit<1>,bit<1>>(image_4) write_4={void apply(inout bit<32> value,out bit<1> completed){value=hdr.image.w4;completed=1w1;}};
 action store_4(){m.done4=write_4.execute(1w0);}
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_4) read_4={void apply(inout bit<32> value,out bit<32> result){result=value;}};
 action load_4(){hdr.image.w4=read_4.execute(1w0);m.done4=1w1;}
 table load_4_t{actions={load_4;}size=1;const default_action=load_4();}
 table store_4_t{actions={store_4;}size=1;const default_action=store_4();}
 Register<bit<32>,bit<1>>(1,0) image_5;
 RegisterAction<bit<32>,bit<1>,bit<1>>(image_5) write_5={void apply(inout bit<32> value,out bit<1> completed){value=hdr.image.w5;completed=1w1;}};
 action store_5(){m.done5=write_5.execute(1w0);}
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_5) read_5={void apply(inout bit<32> value,out bit<32> result){result=value;}};
 action load_5(){hdr.image.w5=read_5.execute(1w0);m.done5=1w1;}
 table load_5_t{actions={load_5;}size=1;const default_action=load_5();}
 table store_5_t{actions={store_5;}size=1;const default_action=store_5();}
 Register<bit<32>,bit<1>>(1,0) image_6;
 RegisterAction<bit<32>,bit<1>,bit<1>>(image_6) write_6={void apply(inout bit<32> value,out bit<1> completed){value=hdr.image.w6;completed=1w1;}};
 action store_6(){m.done6=write_6.execute(1w0);}
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_6) read_6={void apply(inout bit<32> value,out bit<32> result){result=value;}};
 action load_6(){hdr.image.w6=read_6.execute(1w0);m.done6=1w1;}
 table load_6_t{actions={load_6;}size=1;const default_action=load_6();}
 table store_6_t{actions={store_6;}size=1;const default_action=store_6();}
 Register<bit<32>,bit<1>>(1,0) image_7;
 RegisterAction<bit<32>,bit<1>,bit<1>>(image_7) write_7={void apply(inout bit<32> value,out bit<1> completed){value=hdr.image.w7;completed=1w1;}};
 action store_7(){m.done7=write_7.execute(1w0);}
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_7) read_7={void apply(inout bit<32> value,out bit<32> result){result=value;}};
 action load_7(){hdr.image.w7=read_7.execute(1w0);m.done7=1w1;}
 table load_7_t{actions={load_7;}size=1;const default_action=load_7();}
 table store_7_t{actions={store_7;}size=1;const default_action=store_7();}
 Register<bit<32>,bit<1>>(1,0) image_8;
 RegisterAction<bit<32>,bit<1>,bit<1>>(image_8) write_8={void apply(inout bit<32> value,out bit<1> completed){value=hdr.image.w8;completed=1w1;}};
 action store_8(){m.done8=write_8.execute(1w0);}
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_8) read_8={void apply(inout bit<32> value,out bit<32> result){result=value;}};
 action load_8(){hdr.image.w8=read_8.execute(1w0);m.done8=1w1;}
 table load_8_t{actions={load_8;}size=1;const default_action=load_8();}
 table store_8_t{actions={store_8;}size=1;const default_action=store_8();}
 Register<bit<32>,bit<1>>(1,0) image_9;
 RegisterAction<bit<32>,bit<1>,bit<1>>(image_9) write_9={void apply(inout bit<32> value,out bit<1> completed){value=hdr.image.w9;completed=1w1;}};
 action store_9(){m.done9=write_9.execute(1w0);}
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_9) read_9={void apply(inout bit<32> value,out bit<32> result){result=value;}};
 action load_9(){hdr.image.w9=read_9.execute(1w0);m.done9=1w1;}
 table load_9_t{actions={load_9;}size=1;const default_action=load_9();}
 table store_9_t{actions={store_9;}size=1;const default_action=store_9();}
 Register<bit<32>,bit<1>>(1,0) image_10;
 RegisterAction<bit<32>,bit<1>,bit<1>>(image_10) write_10={void apply(inout bit<32> value,out bit<1> completed){value=hdr.image.w10;completed=1w1;}};
 action store_10(){m.done10=write_10.execute(1w0);}
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_10) read_10={void apply(inout bit<32> value,out bit<32> result){result=value;}};
 action load_10(){hdr.image.w10=read_10.execute(1w0);m.done10=1w1;}
 table load_10_t{actions={load_10;}size=1;const default_action=load_10();}
 table store_10_t{actions={store_10;}size=1;const default_action=store_10();}
 Register<bit<32>,bit<1>>(1,0) image_11;
 RegisterAction<bit<32>,bit<1>,bit<1>>(image_11) write_11={void apply(inout bit<32> value,out bit<1> completed){value=hdr.image.w11;completed=1w1;}};
 action store_11(){m.done11=write_11.execute(1w0);}
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_11) read_11={void apply(inout bit<32> value,out bit<32> result){result=value;}};
 action load_11(){hdr.image.w11=read_11.execute(1w0);m.done11=1w1;}
 table load_11_t{actions={load_11;}size=1;const default_action=load_11();}
 table store_11_t{actions={store_11;}size=1;const default_action=store_11();}
 Register<bit<32>,bit<1>>(1,0) image_12;
 RegisterAction<bit<32>,bit<1>,bit<1>>(image_12) write_12={void apply(inout bit<32> value,out bit<1> completed){value=hdr.image.w12;completed=1w1;}};
 action store_12(){m.done12=write_12.execute(1w0);}
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_12) read_12={void apply(inout bit<32> value,out bit<32> result){result=value;}};
 action load_12(){hdr.image.w12=read_12.execute(1w0);m.done12=1w1;}
 table load_12_t{actions={load_12;}size=1;const default_action=load_12();}
 table store_12_t{actions={store_12;}size=1;const default_action=store_12();}
 Register<bit<32>,bit<1>>(1,0) image_13;
 RegisterAction<bit<32>,bit<1>,bit<1>>(image_13) write_13={void apply(inout bit<32> value,out bit<1> completed){value=8w0++hdr.image.w13;completed=1w1;}};
 action store_13(){m.done13=write_13.execute(1w0);}
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_13) read_13={void apply(inout bit<32> value,out bit<32> result){result=value;}};
 action load_13(){hdr.image.w13=read_13.execute(1w0)[23:0];m.done13=1w1;}
 table load_13_t{actions={load_13;}size=1;const default_action=load_13();}
 table store_13_t{actions={store_13;}size=1;const default_action=store_13();}
 Register<e_cache_tag_t,bit<1>>(1,{0,0}) cache_tag;
 RegisterAction<e_cache_tag_t,bit<1>,bit<1>>(cache_tag) tag_write={void apply(inout e_cache_tag_t value,out bit<1> completed){value.epoch=hdr.reference.epoch;value.generation=hdr.cache.generation;completed=1w1;}};
 Register<bit<32>,bit<1>>(1,0) cache_owner;
 RegisterAction<bit<32>,bit<1>,bit<1>>(cache_owner) owner_write={void apply(inout bit<32> value,out bit<1> completed){value=hdr.cache.expected_owner;completed=1w1;}};
 action publish_tag(){m.tag_done=tag_write.execute(1w0);}
 action publish_owner(){m.owner_done=owner_write.execute(1w0);}
 table publish_tag_t{key={m.done0:exact;m.done1:exact;m.done2:exact;m.done3:exact;m.done4:exact;m.done5:exact;m.done6:exact;m.done7:exact;m.done8:exact;m.done9:exact;m.done10:exact;m.done11:exact;m.done12:exact;m.done13:exact;}actions={publish_tag;NoAction;}size=1;const default_action=NoAction();const entries={(1w1,1w1,1w1,1w1,1w1,1w1,1w1,1w1,1w1,1w1,1w1,1w1,1w1,1w1):publish_tag();}}
 table publish_owner_t{key={m.done0:exact;m.done1:exact;m.done2:exact;m.done3:exact;m.done4:exact;m.done5:exact;m.done6:exact;m.done7:exact;m.done8:exact;m.done9:exact;m.done10:exact;m.done11:exact;m.done12:exact;m.done13:exact;}actions={publish_owner;NoAction;}size=1;const default_action=NoAction();const entries={(1w1,1w1,1w1,1w1,1w1,1w1,1w1,1w1,1w1,1w1,1w1,1w1,1w1,1w1):publish_owner();}}
 Register<bit<32>,bit<1>>(1,0) wire_position;
 RegisterAction<bit<32>,bit<1>,bit<1>>(wire_position) position_write={void apply(inout bit<32> value,out bit<1> completed){value=hdr.tcp.seq;completed=1w1;}};
 action publish_position(){m.position_done=position_write.execute(1w0);}
 table publish_position_t{key={m.done0:exact;m.done1:exact;m.done2:exact;m.done3:exact;m.done4:exact;m.done5:exact;m.done6:exact;m.done7:exact;m.done8:exact;m.done9:exact;m.done10:exact;m.done11:exact;m.done12:exact;m.done13:exact;}actions={publish_position;NoAction;}size=1;const default_action=NoAction();const entries={(1w1,1w1,1w1,1w1,1w1,1w1,1w1,1w1,1w1,1w1,1w1,1w1,1w1,1w1):publish_position();}}
 action endpoint_ready(){m.emit_ready=1w1;m.tcp_length=16w75;m.mirror_sid=10w1;md.mirror_type=3w2;m.completion_epoch=hdr.reference.epoch;m.completion_generation=hdr.reference.generation;m.completion_owner=hdr.reference.expected_owner;m.completion_cache_generation=hdr.cache.generation;m.completion_cache_owner=hdr.cache.expected_owner;m.completion_event=16w0x0e14;m.completion_format=16w2;hdr.reference.setInvalid();hdr.cache.setInvalid();}
 table endpoint_ready_t{key={m.done0:exact;m.done1:exact;m.done2:exact;m.done3:exact;m.done4:exact;m.done5:exact;m.done6:exact;m.done7:exact;m.done8:exact;m.done9:exact;m.done10:exact;m.done11:exact;m.done12:exact;m.done13:exact;}actions={endpoint_ready;deny;}size=1;const default_action=deny();const entries={(1w1,1w1,1w1,1w1,1w1,1w1,1w1,1w1,1w1,1w1,1w1,1w1,1w1,1w1):endpoint_ready();}}
 action ready(){hdr.reference.event=16w0x0514;}
 table ready_t{key={m.tag_done:exact;m.owner_done:exact;m.position_done:exact;}actions={ready;deny;}size=1;const default_action=deny();const entries={(1w1,1w1,1w1):ready();}}

 RegisterAction<e_producer_cell_t,bit<1>,bit<32>>(reservation) inspect={void apply(inout e_producer_cell_t value,out bit<32> granted){granted=32w0;if(value.generation==m.pin_generation&&value.phase==m.expected_phase){granted=32w1;}}};
 action inspect_cache_pin(){m.grant=inspect.execute(1w0);}
 table inspect_cache_pin_t{actions={inspect_cache_pin;}size=1;const default_action=inspect_cache_pin();}
 RegisterAction<e_cache_tag_t,bit<1>,bit<32>>(cache_tag) tag_check={void apply(inout e_cache_tag_t value,out bit<32> result){result=32w0;if(value.epoch!=hdr.reference.epoch||value.generation!=hdr.cache.generation){result=32w1;}}};
 RegisterAction<bit<32>,bit<1>,bit<32>>(cache_owner) owner_check={void apply(inout bit<32> value,out bit<32> result){result=value-hdr.cache.expected_owner;}};
 RegisterAction<bit<32>,bit<1>,bit<32>>(wire_position) position_check={void apply(inout bit<32> value,out bit<32> result){result=value-hdr.tcp.seq;}};
 action check_tag(){m.tag_match=tag_check.execute(1w0);}
 table check_tag_t{actions={check_tag;}size=1;const default_action=check_tag();}
 action check_owner(){m.stored_owner_diff=owner_check.execute(1w0);}
 table check_owner_t{actions={check_owner;}size=1;const default_action=check_owner();}
 action check_position(){m.stored_position_diff=position_check.execute(1w0);}
 table check_position_t{actions={check_position;}size=1;const default_action=check_position();}
 action query_qualified(){hdr.reference.event=16w0x0b14;}
 action completion_qualified(){hdr.completion.setValid();hdr.completion.epoch=hdr.reference.epoch;hdr.reference.event=16w0x1214;hdr.reference.format=16w3;}
 table query_result_t{key={m.role:exact;m.tag_match:exact;m.stored_owner_diff:exact;m.stored_position_diff:exact;}actions={query_qualified;completion_qualified;deny;}size=2;const default_action=deny();const entries={(8w1,32w0,32w0,32w0):query_qualified();(8w3,32w0,32w0,32w0):completion_qualified();}}
 table terminal_gate_t{key={m.identity_grant:exact;m.completion_diff:exact;}actions={retire_emit;deny;}size=1;const default_action=deny();const entries={(1w1,32w0):retire_emit();}}
 action strip_completion(){hdr.reference.event=16w0x0e14;hdr.reference.format=16w2;hdr.completion.setInvalid();}
 table completion_result_t{key={m.grant:exact;}actions={strip_completion;deny;}size=1;const default_action=deny();const entries={32w1:strip_completion();}}
 apply{
  compare_reference_t.apply();identity_t.apply();pin_identity_t.apply();
  if(m.role==8w4&&m.parsed==1w1){
   m.completion_diff=hdr.reference.epoch-hdr.completion.epoch;
   terminal_gate_t.apply();completion_result_t.apply();
  }else if(m.parsed==1w1&&!m.ip_error&&m.tcp_sum==16w0xFFEB&&hdr.ip.ttl!=8w0){
   connection.apply();
   if(m.enabled==1w1&&m.identity_grant==1w1){
    if(m.role==8w2){
     claim_endpoint_t.apply();
     if(m.grant==32w1){load_0_t.apply();load_1_t.apply();load_2_t.apply();load_3_t.apply();load_4_t.apply();load_5_t.apply();load_6_t.apply();load_7_t.apply();load_8_t.apply();load_9_t.apply();load_10_t.apply();load_11_t.apply();load_12_t.apply();load_13_t.apply();endpoint_ready_t.apply();}else{deny();}
    }else if(m.role==8w1||m.role==8w3){
     inspect_cache_pin_t.apply();
     if(m.grant==32w1){check_tag_t.apply();check_owner_t.apply();check_position_t.apply();query_result_t.apply();}else{deny();}
    }else{reserve_t.apply();
    if(m.grant==32w1){
store_0_t.apply();store_1_t.apply();store_2_t.apply();store_3_t.apply();store_4_t.apply();store_5_t.apply();store_6_t.apply();store_7_t.apply();store_8_t.apply();store_9_t.apply();store_10_t.apply();store_11_t.apply();store_12_t.apply();store_13_t.apply();
     publish_tag_t.apply();publish_owner_t.apply();publish_position_t.apply();ready_t.apply();
    }else{deny();}
    }
   }else{deny();}
  }else{deny();}
 }

}
control e_EgDeparser(packet_out pkt,inout e_headers_t hdr,in e_meta_t m,in egress_intrinsic_metadata_for_deparser_t md){
 Checksum() tc;
 Mirror() mirror;
 apply{
  if(m.emit_ready==1w1){
   hdr.tcp.checksum=tc.update({hdr.ip.src,hdr.ip.dst,8w0,hdr.ip.proto,m.tcp_length,hdr.tcp.sport,hdr.tcp.dport,hdr.tcp.seq,hdr.tcp.ack,hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.flags,hdr.tcp.window,hdr.tcp.urgent,hdr.image.w0,hdr.image.w1,hdr.image.w2,hdr.image.w3,hdr.image.w4,hdr.image.w5,hdr.image.w6,hdr.image.w7,hdr.image.w8,hdr.image.w9,hdr.image.w10,hdr.image.w11,hdr.image.w12,hdr.image.w13});
   mirror.emit<e_completion_h>(m.mirror_sid,{m.completion_epoch,m.completion_generation,m.completion_owner,m.completion_event,m.completion_format,m.completion_cache_generation,m.completion_cache_owner});
  }
  pkt.emit(hdr);
 }
}
parser e_IgParser(packet_in pkt,out e_headers_t hdr,out e_meta_t m,out ingress_intrinsic_metadata_t ig){state start{pkt.extract(ig);pkt.advance(PORT_METADATA_SIZE);transition accept;}}
control e_Ingress(inout e_headers_t hdr,inout e_meta_t m,in ingress_intrinsic_metadata_t ig,in ingress_intrinsic_metadata_from_parser_t p,inout ingress_intrinsic_metadata_for_deparser_t md,inout ingress_intrinsic_metadata_for_tm_t tm){apply{md.drop_ctl=3w1;}}
control e_IgDeparser(packet_out pkt,inout e_headers_t hdr,in e_meta_t m,in ingress_intrinsic_metadata_for_deparser_t md){apply{}}

Pipeline(n_IgParser(),n_Ingress(),n_IgDeparser(),e_EgParser(),e_Egress(),e_EgDeparser()) p0;
Pipeline(m_IgParser(),m_Ingress(),m_IgDeparser(),m_EgParser(),m_Egress(),m_EgDeparser()) p1;
Switch(p0,p1) main;

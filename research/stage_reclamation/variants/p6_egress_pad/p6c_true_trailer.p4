/* ============================================================================
 * p6c_true_trailer.p4 — VARIANT P6c: does MECHANISM A actually compile on TF1?
 *
 * THE PROBLEM P6 LEAVES OPEN.  A TNA deparser emits its emitted headers and then
 * whatever the parser did not consume (the residual).  There is no way to emit a
 * header AFTER the residual.  So if a live IPv4/TCP/DNP3 frame's payload is the
 * residual, any pad header lands BETWEEN the TCP header and the DNP3 payload —
 * inside the IP datagram.  That construction is REJECTED outright: it corrupts
 * DNP3 application bytes, breaks the DNP3 CRC, and makes IP total_length and the
 * TCP checksum inconsistent with the bytes on the wire.
 *
 * THE FIX TESTED HERE.  Make the residual EMPTY, by having the egress parser
 * consume the entire TCP payload into a shared power-of-2 header set.  Then the
 * pad headers, emitted last, are genuinely AFTER the end of the IP datagram —
 * i.e. an Ethernet trailer in the RFC 894 §2 sense ("padding ... is not part of
 * the IP packet and is not included in the total length field of the IP header").
 *
 * WHAT IS AND IS NOT MODIFIED (the rejection checklist, item by item):
 *   - DNP3 application bytes : extracted and re-emitted in the SAME order, never
 *                              read or written by any MAU action.  Untouched.
 *   - DNP3 CRC               : rides inside those payload bytes.  Untouched.
 *   - TCP sequence space     : no payload byte is added or removed.  Untouched.
 *   - IP total_length        : never written, and still exactly delimits
 *                              ip(20) + tcp(20) + payload.  Consistent.
 *   - TCP checksum           : covers the pseudo-header + TCP header + payload,
 *                              none of which changed.  Still valid.
 *   - endpoint modification  : none required; the trailer is below IP.
 *   - Ethernet FCS           : recomputed by the egress MAC over the padded
 *                              frame, so the frame is a well-formed Ethernet
 *                              frame, not a frame with a stale FCS.
 *
 * REMAINING RISK (honest, and NOT resolved by this compile): no RFC *requires*
 * a receiver to accept trailer octets.  RFC 894 §2 / RFC 1042 §3.2 establish
 * that they are not part of the IP packet; Linux ip_rcv_core() demonstrably
 * trims to ntohs(iph->tot_len) via pskb_trim_rcsum().  A specific IED's stack
 * (e.g. the SEL-751) is [OPEN] until measured.  See SIZE_PRIMITIVE_REUSE_AUDIT.md §7.
 *
 * PAYLOAD DECOMPOSITION.  ihl=5, data_offset=5 => payload = total_len - 40.
 *   wire  total_len  payload  payload = sum of 2^i chunks     pad delta to 128
 *    60      46         6     4+2                                   68
 *    62      48         8     8                                     66
 *    66      52        12     8+4                                   62
 *    74      60        20     16+4                                  54
 *    76      62        22     16+4+2                                52
 *    88      74        34     32+2                                  40
 *    89      75        35     32+2+1                                39
 *    91      77        37     32+4+1                                37
 *   101      87        47     32+8+4+2+1                            27
 *   103      89        49     32+16+1                               25
 *   108      94        54     32+16+4+2                             20
 *   115     101        61     32+16+8+4+1                           13
 *   120     106        66     64+2                                   8
 * The payload chunk headers are SHARED across all 13 classes (127 B of header
 * definitions total, not 13 x 66 B), and are never touched by the MAU, so they
 * are eligible for tagalong (deparser-only) storage.
 * Extraction order and emission order are both DESCENDING, so the payload is
 * reconstructed byte-identically for every subset.
 *
 * Ingress is again P0 VERBATIM.  Target: Tofino 1 (TNA), bf-p4c 9.13.1.
 * Compile-only; never loaded.
 * ==========================================================================*/
#include <core.p4>
#include <tna.p4>

const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<8>  IP_PROTO_TCP   = 8w6;

const bit<16> ETHERTYPE_IBSPG_REAL  = 0x88C0;
const bit<16> ETHERTYPE_IBSPG_TOKEN = 0x88C1;

const bit<8> ROLE_BLOCK = 1;
const bit<8> ROLE_RESP  = 2;
const bit<8> ROLE_ARM   = 6;
const bit<8> ROLE_ACK   = 7;

const PortId_t PORT_L      = 9w8;
const PortId_t PORT_VISION = 9w9;
const PortId_t PORT_HULK   = 9w11;

const bit<5> QID_BLOCK = 5w7;
const bit<5> QID_RESP  = 5w1;
const bit<8> SLOT0     = 8w0;

/* ============================ headers ==================================== */
header ethernet_h { bit<48> dst; bit<48> src; bit<16> etype; }
header ibspg_h    { bit<8> role; bit<8> slot; bit<8> gen; bit<32> seq; }

header ipv4_h {
    bit<4>  version;  bit<4>  ihl;      bit<8>  diffserv;  bit<16> total_len;
    bit<16> id;       bit<3>  flags;    bit<13> frag_off;
    bit<8>  ttl;      bit<8>  protocol; bit<16> hdr_checksum;
    bit<32> src_addr; bit<32> dst_addr;
}
header tcp_h {
    bit<16> src_port; bit<16> dst_port; bit<32> seq_no; bit<32> ack_no;
    bit<4>  data_offset; bit<4> res; bit<8> flags; bit<16> window;
    bit<16> checksum; bit<16> urgent_ptr;
}

/* Shared power-of-2 PAYLOAD chunks: consume the whole DNP3 payload so the
 * deparser residual is empty.  Never read/written by the MAU. */
header pay1_h  { bit<8>   f; }
header pay2_h  { bit<16>  f; }
header pay4_h  { bit<32>  f; }
header pay8_h  { bit<64>  f; }
header pay16_h { bit<128> f; }
header pay32_h { bit<256> f; }
header pay64_h { bit<512> f; }

/* Shared power-of-2 PAD chunks: emitted AFTER the payload = Ethernet trailer. */
header pad1_h  { bit<8>   f; }
header pad2_h  { bit<16>  f; }
header pad4_h  { bit<32>  f; }
header pad8_h  { bit<64>  f; }
header pad16_h { bit<128> f; }
header pad32_h { bit<256> f; }
header pad64_h { bit<512> f; }

struct headers_t { ethernet_h eth; ibspg_h ib; }

struct eg_headers_t {
    ethernet_h eth;
    ipv4_h     ipv4;
    tcp_h      tcp;
    pay64_h pay64; pay32_h pay32; pay16_h pay16; pay8_h pay8;
    pay4_h  pay4;  pay2_h  pay2;  pay1_h  pay1;
    pad64_h pad64; pad32_h pad32; pad16_h pad16; pad8_h pad8;
    pad4_h  pad4;  pad2_h  pad2;  pad1_h  pad1;
}

struct ig_meta_t {
    bit<8>  dequeued;   bit<32> ts32;       bit<8>  budget_zero;
    bit<8>  gen_we;     bit<8>  gen_val;
    bit<8>  active_we;  bit<8>  active_val;
    bit<8>  dl_we;      bit<32> dl_val;
    bit<8>  gen_now;    bit<8>  active_now; bit<32> dl_now;
    bit<8>  gen_mismatch; bit<8> ack_ok;    bit<8>  dl_armed;
    bit<32> age;        bit<8>  expired;
    bit<8>  ev_first_block; bit<8> ev_ack_arm;
    bit<8>  ev_block_term;  bit<8> ev_resp_release;
}
struct eg_meta_t { bit<8> normalized; }

/* =================== ingress parser (P0 VERBATIM) ======================== */
parser IgParser(packet_in pkt, out headers_t hdr, out ig_meta_t meta,
                out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        meta.dequeued = 8w0; meta.ts32 = 32w0; meta.budget_zero = 8w0;
        meta.gen_we = 8w0; meta.gen_val = 8w0;
        meta.active_we = 8w0; meta.active_val = 8w0;
        meta.dl_we = 8w0; meta.dl_val = 32w0;
        meta.gen_now = 8w0; meta.active_now = 8w0; meta.dl_now = 32w0;
        meta.gen_mismatch = 8w0; meta.ack_ok = 8w0; meta.dl_armed = 8w0;
        meta.age = 32w0; meta.expired = 8w0;
        meta.ev_first_block = 8w0; meta.ev_ack_arm = 8w0;
        meta.ev_block_term = 8w0; meta.ev_resp_release = 8w0;
        transition parse_eth;
    }
    state parse_eth {
        pkt.extract(hdr.eth);
        transition select(hdr.eth.etype) {
            ETHERTYPE_IBSPG_REAL  : parse_ib;
            ETHERTYPE_IBSPG_TOKEN : parse_ib;
            default               : accept;
        }
    }
    state parse_ib { pkt.extract(hdr.ib); transition accept; }
}

/* =================== ingress control (P0 VERBATIM) ======================= */
control Ingress(inout headers_t hdr, inout ig_meta_t meta,
                in    ingress_intrinsic_metadata_t              ig_intr_md,
                in    ingress_intrinsic_metadata_from_parser_t  ig_prsr_md,
                inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                inout ingress_intrinsic_metadata_for_tm_t       ig_tm_md) {

    Register<bit<8>, bit<1>>(1, 0) reg_gen;
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_gen) gen_rmw = {
        void apply(inout bit<8> v, out bit<8> rv) {
            rv = v; if (meta.gen_we == 8w1) { v = meta.gen_val; } } };
    Register<bit<8>, bit<1>>(1, 0) reg_active;
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_active) active_rmw = {
        void apply(inout bit<8> v, out bit<8> rv) {
            rv = v; if (meta.active_we == 8w1) { v = meta.active_val; } } };
    Register<bit<32>, bit<1>>(1, 0) reg_deadline;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_deadline) deadline_rmw = {
        void apply(inout bit<32> v, out bit<32> rv) {
            rv = v; if (meta.dl_we == 8w1) { v = meta.dl_val; } } };

    Register<bit<32>, bit<1>>(1, 0) reg_ts_first_block;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_ts_first_block) ts_first_block_w = {
        void apply(inout bit<32> v) { if (v == 32w0) { v = meta.ts32; } } };
    Register<bit<32>, bit<1>>(1, 0) reg_ts_ack_arm;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_ts_ack_arm) ts_ack_arm_w = {
        void apply(inout bit<32> v) { if (v == 32w0) { v = meta.ts32; } } };
    Register<bit<32>, bit<1>>(1, 0) reg_ts_block_term;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_ts_block_term) ts_block_term_w = {
        void apply(inout bit<32> v) { if (v == 32w0) { v = meta.ts32; } } };
    Register<bit<32>, bit<1>>(1, 0) reg_ts_first_resp_release;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_ts_first_resp_release) ts_first_resp_w = {
        void apply(inout bit<32> v) { if (v == 32w0) { v = meta.ts32; } } };

    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_arm;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_block_enq;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_block_loop;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_block_term_deadline;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_block_term_timeout;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_block_term_stale;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_ack_arm;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_ack_bypass;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_resp_enq;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_resp_release;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_nonibspg;

    action to_block() { ig_tm_md.ucast_egress_port = PORT_L; ig_tm_md.qid = QID_BLOCK; ig_tm_md.bypass_egress = 1w1; }
    action to_resp()  { ig_tm_md.ucast_egress_port = PORT_L; ig_tm_md.qid = QID_RESP;  ig_tm_md.bypass_egress = 1w1; }
    action to_host()  { ig_tm_md.ucast_egress_port = PORT_VISION; ig_tm_md.qid = 5w0;  ig_tm_md.bypass_egress = 1w0; }
    action drop_pkt() { ig_dprsr_md.drop_ctl = 3w1; }

    action mark_expired()     { meta.expired = 8w1; }
    action mark_not_expired() { meta.expired = 8w0; }
    table tbl_deadline_expiry {
        key = { meta.dl_armed : exact; meta.age : ternary; }
        actions = { mark_expired; mark_not_expired; }
        const default_action = mark_not_expired();
        const entries = { (8w1, 32w0 &&& 32w0x80000000) : mark_expired(); }
        size = 2;
    }

    apply {
        if (!hdr.ib.isValid()) {
            ctr_nonibspg.count(0);
            drop_pkt();
        } else {
            if (ig_intr_md.ingress_port == PORT_L) { meta.dequeued = 8w1; }
            meta.ts32 = ig_intr_md.ingress_mac_tstamp[31:0];
            if (hdr.ib.seq == 32w0) { meta.budget_zero = 8w1; }

            if (meta.dequeued == 8w0 && hdr.ib.role == ROLE_ARM) {
                meta.gen_we = 8w1; meta.gen_val = hdr.ib.gen;
                meta.active_we = 8w1; meta.active_val = 8w1;
                meta.dl_we = 8w1; meta.dl_val = 32w0;
            }
            meta.gen_now = gen_rmw.execute(0);
            if (meta.gen_now != hdr.ib.gen) { meta.gen_mismatch = 8w1; }

            if (meta.dequeued == 8w1 && hdr.ib.role == ROLE_BLOCK) {
                if (meta.gen_mismatch == 8w1 || meta.budget_zero == 8w1) {
                    meta.active_we = 8w1; meta.active_val = 8w0;
                }
            }
            meta.active_now = active_rmw.execute(0);

            if (meta.dequeued == 8w0 && hdr.ib.role == ROLE_ACK
                && hdr.ib.slot == SLOT0 && meta.gen_mismatch == 8w0
                && meta.active_now == 8w1) {
                meta.ack_ok = 8w1; meta.dl_we = 8w1;
                meta.dl_val = meta.ts32 + hdr.ib.seq;
            }
            meta.dl_now = deadline_rmw.execute(0);

            if (meta.dl_now != 32w0) { meta.dl_armed = 8w1; }
            meta.age = meta.ts32 - meta.dl_now;
            tbl_deadline_expiry.apply();

            if (meta.dequeued == 8w0) {
                if (hdr.ib.role == ROLE_BLOCK) {
                    to_block(); ctr_block_enq.count(0); meta.ev_first_block = 8w1;
                } else if (hdr.ib.role == ROLE_RESP) {
                    to_resp(); ctr_resp_enq.count(0);
                } else if (hdr.ib.role == ROLE_ACK) {
                    to_host();
                    if (meta.ack_ok == 8w1) { ctr_ack_arm.count(0); meta.ev_ack_arm = 8w1; }
                    else { ctr_ack_bypass.count(0); }
                } else if (hdr.ib.role == ROLE_ARM) {
                    ctr_arm.count(0); drop_pkt();
                } else { drop_pkt(); }
            } else {
                if (hdr.ib.role == ROLE_BLOCK) {
                    if (meta.active_now == 8w0 || meta.gen_mismatch == 8w1) {
                        drop_pkt(); ctr_block_term_stale.count(0); meta.ev_block_term = 8w1;
                    } else if (meta.expired == 8w1) {
                        drop_pkt(); ctr_block_term_deadline.count(0); meta.ev_block_term = 8w1;
                    } else if (meta.budget_zero == 8w1) {
                        drop_pkt(); ctr_block_term_timeout.count(0); meta.ev_block_term = 8w1;
                    } else {
                        hdr.ib.seq = hdr.ib.seq - 32w1;
                        to_block(); ctr_block_loop.count(0);
                    }
                } else if (hdr.ib.role == ROLE_RESP) {
                    to_host(); ctr_resp_release.count(0); meta.ev_resp_release = 8w1;
                } else { drop_pkt(); }
            }

            if (meta.ev_first_block  == 8w1) { ts_first_block_w.execute(0); }
            if (meta.ev_ack_arm      == 8w1) { ts_ack_arm_w.execute(0); }
            if (meta.ev_block_term   == 8w1) { ts_block_term_w.execute(0); }
            if (meta.ev_resp_release == 8w1) { ts_first_resp_w.execute(0); }
        }
    }
}

control IgDeparser(packet_out pkt, inout headers_t hdr, in ig_meta_t meta,
                   in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    apply { pkt.emit(hdr.eth); pkt.emit(hdr.ib); }
}

/* ========================= EGRESS — the P6c mechanism ===================
 * Fully consume ip + tcp + payload so the residual is empty.  Any frame that is
 * not ihl=5 / doff=5 / a known total_len falls through to `accept` with the
 * payload still in the residual and NO pad valid => forwarded unchanged. */
parser EgParser(packet_in pkt, out eg_headers_t hdr, out eg_meta_t meta,
                out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        pkt.extract(eg_intr_md);
        transition parse_eth;
    }
    state parse_eth {
        pkt.extract(hdr.eth);
        transition select(hdr.eth.etype) {
            ETHERTYPE_IPV4 : parse_ipv4;
            default        : accept;
        }
    }
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.ihl, hdr.ipv4.protocol) {
            (4w5, IP_PROTO_TCP) : parse_tcp;
            default             : accept;      /* options / non-TCP: fail open */
        }
    }
    /* The total_len select lives IN the tcp-extract state: a select on
     * ipv4.total_len in a state placed AFTER the tcp extract is a known
     * bf-p4c 9.13.x failure mode on this toolchain. */
    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition select(hdr.tcp.data_offset, hdr.ipv4.total_len) {
            (4w5, 16w46 ) : pl_6;
            (4w5, 16w48 ) : pl_8;
            (4w5, 16w52 ) : pl_12;
            (4w5, 16w60 ) : pl_20;
            (4w5, 16w62 ) : pl_22;
            (4w5, 16w74 ) : pl_34;
            (4w5, 16w75 ) : pl_35;
            (4w5, 16w77 ) : pl_37;
            (4w5, 16w87 ) : pl_47;
            (4w5, 16w89 ) : pl_49;
            (4w5, 16w94 ) : pl_54;
            (4w5, 16w101) : pl_61;
            (4w5, 16w106) : pl_66;
            default       : accept;            /* unknown length: fail open */
        }
    }
    /* Payload chunks extracted DESCENDING; the deparser emits DESCENDING too,
     * so every subset reconstructs the payload byte-identically. */
    state pl_6  { pkt.extract(hdr.pay4);  pkt.extract(hdr.pay2); transition accept; }
    state pl_8  { pkt.extract(hdr.pay8);  transition accept; }
    state pl_12 { pkt.extract(hdr.pay8);  pkt.extract(hdr.pay4); transition accept; }
    state pl_20 { pkt.extract(hdr.pay16); pkt.extract(hdr.pay4); transition accept; }
    state pl_22 { pkt.extract(hdr.pay16); pkt.extract(hdr.pay4); pkt.extract(hdr.pay2); transition accept; }
    state pl_34 { pkt.extract(hdr.pay32); pkt.extract(hdr.pay2); transition accept; }
    state pl_35 { pkt.extract(hdr.pay32); pkt.extract(hdr.pay2); pkt.extract(hdr.pay1); transition accept; }
    state pl_37 { pkt.extract(hdr.pay32); pkt.extract(hdr.pay4); pkt.extract(hdr.pay1); transition accept; }
    state pl_47 { pkt.extract(hdr.pay32); pkt.extract(hdr.pay8); pkt.extract(hdr.pay4); pkt.extract(hdr.pay2); pkt.extract(hdr.pay1); transition accept; }
    state pl_49 { pkt.extract(hdr.pay32); pkt.extract(hdr.pay16); pkt.extract(hdr.pay1); transition accept; }
    state pl_54 { pkt.extract(hdr.pay32); pkt.extract(hdr.pay16); pkt.extract(hdr.pay4); pkt.extract(hdr.pay2); transition accept; }
    state pl_61 { pkt.extract(hdr.pay32); pkt.extract(hdr.pay16); pkt.extract(hdr.pay8); pkt.extract(hdr.pay4); pkt.extract(hdr.pay1); transition accept; }
    state pl_66 { pkt.extract(hdr.pay64); pkt.extract(hdr.pay2); transition accept; }
}

control Egress(inout eg_headers_t hdr, inout eg_meta_t meta,
               in    egress_intrinsic_metadata_t                 eg_intr_md,
               in    egress_intrinsic_metadata_from_parser_t     eg_prsr_md,
               inout egress_intrinsic_metadata_for_deparser_t    eg_dprsr_md,
               inout egress_intrinsic_metadata_for_output_port_t eg_oport_md) {

    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_size_normalized;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_size_failopen;

    action pad_none() { meta.normalized = 8w0; }
    action pad_d8()  { meta.normalized = 8w1; hdr.pad8.setValid();  hdr.pad8.f  = 0; }
    action pad_d13() { meta.normalized = 8w1; hdr.pad8.setValid();  hdr.pad8.f  = 0; hdr.pad4.setValid();  hdr.pad4.f  = 0; hdr.pad1.setValid(); hdr.pad1.f = 0; }
    action pad_d20() { meta.normalized = 8w1; hdr.pad16.setValid(); hdr.pad16.f = 0; hdr.pad4.setValid();  hdr.pad4.f  = 0; }
    action pad_d25() { meta.normalized = 8w1; hdr.pad16.setValid(); hdr.pad16.f = 0; hdr.pad8.setValid();  hdr.pad8.f  = 0; hdr.pad1.setValid(); hdr.pad1.f = 0; }
    action pad_d27() { meta.normalized = 8w1; hdr.pad16.setValid(); hdr.pad16.f = 0; hdr.pad8.setValid();  hdr.pad8.f  = 0; hdr.pad2.setValid(); hdr.pad2.f = 0; hdr.pad1.setValid(); hdr.pad1.f = 0; }
    action pad_d37() { meta.normalized = 8w1; hdr.pad32.setValid(); hdr.pad32.f = 0; hdr.pad4.setValid();  hdr.pad4.f  = 0; hdr.pad1.setValid(); hdr.pad1.f = 0; }
    action pad_d39() { meta.normalized = 8w1; hdr.pad32.setValid(); hdr.pad32.f = 0; hdr.pad4.setValid();  hdr.pad4.f  = 0; hdr.pad2.setValid(); hdr.pad2.f = 0; hdr.pad1.setValid(); hdr.pad1.f = 0; }
    action pad_d40() { meta.normalized = 8w1; hdr.pad32.setValid(); hdr.pad32.f = 0; hdr.pad8.setValid();  hdr.pad8.f  = 0; }
    action pad_d52() { meta.normalized = 8w1; hdr.pad32.setValid(); hdr.pad32.f = 0; hdr.pad16.setValid(); hdr.pad16.f = 0; hdr.pad4.setValid(); hdr.pad4.f = 0; }
    action pad_d54() { meta.normalized = 8w1; hdr.pad32.setValid(); hdr.pad32.f = 0; hdr.pad16.setValid(); hdr.pad16.f = 0; hdr.pad4.setValid(); hdr.pad4.f = 0; hdr.pad2.setValid(); hdr.pad2.f = 0; }
    action pad_d62() { meta.normalized = 8w1; hdr.pad32.setValid(); hdr.pad32.f = 0; hdr.pad16.setValid(); hdr.pad16.f = 0; hdr.pad8.setValid(); hdr.pad8.f = 0; hdr.pad4.setValid(); hdr.pad4.f = 0; hdr.pad2.setValid(); hdr.pad2.f = 0; }
    action pad_d66() { meta.normalized = 8w1; hdr.pad64.setValid(); hdr.pad64.f = 0; hdr.pad2.setValid();  hdr.pad2.f  = 0; }
    action pad_d68() { meta.normalized = 8w1; hdr.pad64.setValid(); hdr.pad64.f = 0; hdr.pad4.setValid();  hdr.pad4.f  = 0; }

    /* Keyed on the MEASURED egress frame length.  Only frames whose payload the
     * parser fully consumed can match, because the 13 lengths correspond exactly
     * to the 13 parsed classes; anything else takes the default and is unchanged. */
    table size_norm {
        key     = { eg_intr_md.pkt_length : exact; }
        actions = { pad_none; pad_d8; pad_d13; pad_d20; pad_d25; pad_d27; pad_d37;
                    pad_d39; pad_d40; pad_d52; pad_d54; pad_d62; pad_d66; pad_d68; }
        const entries = {
            16w60  : pad_d68();  16w62  : pad_d66();  16w66  : pad_d62();
            16w74  : pad_d54();  16w76  : pad_d52();  16w88  : pad_d40();
            16w89  : pad_d39();  16w91  : pad_d37();  16w101 : pad_d27();
            16w103 : pad_d25();  16w108 : pad_d20();  16w115 : pad_d13();
            16w120 : pad_d8();
        }
        const default_action = pad_none();
        size = 16;
    }

    apply {
        size_norm.apply();
        if (meta.normalized == 8w1) { ctr_size_normalized.count(0); }
        else                        { ctr_size_failopen.count(0); }
    }
}

/* THE POINT: pads are emitted after the LAST payload chunk.  When the parser
 * consumed the whole payload the residual is empty, so the pad bytes are the
 * last bytes before the FCS -> a true Ethernet trailer, outside the IP datagram
 * that ipv4.total_len delimits. */
control EgDeparser(packet_out pkt, inout eg_headers_t hdr, in eg_meta_t meta,
                   in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {
    apply {
        pkt.emit(hdr.eth);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.pay64); pkt.emit(hdr.pay32); pkt.emit(hdr.pay16);
        pkt.emit(hdr.pay8);  pkt.emit(hdr.pay4);  pkt.emit(hdr.pay2); pkt.emit(hdr.pay1);
        pkt.emit(hdr.pad64); pkt.emit(hdr.pad32); pkt.emit(hdr.pad16);
        pkt.emit(hdr.pad8);  pkt.emit(hdr.pad4);  pkt.emit(hdr.pad2); pkt.emit(hdr.pad1);
    }
}

Pipeline(IgParser(), Ingress(), IgDeparser(),
         EgParser(), Egress(), EgDeparser()) pipe;

Switch(pipe) main;

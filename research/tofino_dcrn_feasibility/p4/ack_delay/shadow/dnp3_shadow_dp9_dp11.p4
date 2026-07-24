/*******************************************************************************
 * dnp3_shadow_dp9_dp11.p4  —  MEASURED-TOPOLOGY DEPLOYMENT VARIANT of the FROZEN dnp3_shadow.p4.
 * NOT a replacement for the frozen file. ONLY difference: the two role->port constants, set from the
 * MEASURED host<->dev_port mapping (per-port RX-counter test 2026-07-24): Vision(master)=dp9,
 * Hulk(outstation)=dp11. (This is the OPPOSITE of the initially-assumed dp11/dp9; the cable swap put
 * Vision on dp9 and Hulk on dp11 — see PORT_ROLE_AUDIT_20260724.md.) Role contract unchanged: master
 * ingress = dir 0 (dp9), outstation ingress = dir 1 (dp11). All logic derives from the two constants.
 *
 * dnp3_shadow.p4  —  PASSIVE DNP3 shadow classifier (Tofino 1 / TNA)
 *
 * Phase 1 of research/END_TO_END_IMPLEMENTATION_PLAN.md (charter §G, gap row 2).
 * Tofino 1 (TNA), BF-SDE 9.13.1 local / 9.13.2 switch.
 *
 * WHAT IT DOES:
 *   A transparent bump-in-the-wire between Vision (dp9, master) and Hulk (dp11, outstation).
 *   It PARSES and CLASSIFIES every packet of the DNP3 session and emits a measurement Digest,
 *   but it changes NOTHING on the wire: no recirculation, no hold, no header push/pop, no size
 *   change, no field/seq/CRC edit. IP-and-above is bit-identical; packet ORDER is preserved
 *   (single unicast forward, no queue steering). It is the read-only "shadow" that observes the
 *   NATIVE transaction (native CLRT, ACK mode, sizes) so the offline collector can characterize
 *   the flow before any defense is applied.
 *
 * FORWARDING (shadow invariant): a frame that arrives on PORT_VISION egresses PORT_HULK and vice
 *   versa. Nothing is ever dropped (a MALFORMED frame is CLASSIFIED, not dropped). No qid steering,
 *   no recirc, no bridge, no deparser header change beyond re-emitting exactly what was parsed.
 *
 * CLASSIFICATION (one result per packet, ingress; see CLASS_* enum below):
 *   NON_DNP3/UNRELATED, DNP3_READ, PURE_ACK, DNP3_RESPONSE, TCP_FIN, TCP_RST,
 *   LINK_STATUS_OR_OTHER_DNP3, MALFORMED.
 *
 * RETRANSMISSION: intentionally NO per-flow seq/ack state is kept (it would cost a SALU stage for
 *   no dataplane benefit here). Instead the digest carries tcp.seq and tcp.ack verbatim and the
 *   OFFLINE collector detects retransmissions by observing a repeated (flow,seq) or a seq that
 *   moves backwards. This keeps the shadow strictly smaller than a defense variant.
 *
 * DIGEST: one learn digest per packet (40 B, well under the 48 B TNA learn quantum), A/B-gated by
 *   the reg_shadow_enable register (default 1). Forwarding is UNCONDITIONAL and identical whether
 *   the digest is on or off — the register only gates measurement export, never the wire.
 *   Digests are emitted only for TCP frames so the deparser packs valid hdr.tcp.* directly; the
 *   per-class Counter still counts every packet including non-TCP.
 *
 * REUSE (lifted verbatim from dcrn_defense1.p4, minus the recirc/hold machinery): the parser chain
 *   Eth->IPv4(ihl==5)->TCP->length-gated DNP3 including the zero-payload-ACK gate and SYN exclusion;
 *   the tcp payload_len negate-and-add overhead table; the canonical bidirectional CRC16 flow hash
 *   over {client_ip, server_ip, client_port}; the DNP3 link/app header extraction.
 *
 * Author: Philip
 ******************************************************************************/

#include <core.p4>
#include <tna.p4>

/*==============================================================================
 * CONSTANTS
 *============================================================================*/

const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<8>  IP_PROTO_TCP    = 6;
const bit<16> DNP3_PORT       = 20000;
const bit<8>  DNP3_START_0     = 0x05;
const bit<8>  DNP3_START_1     = 0x64;

const PortId_t PORT_VISION = 9w9;    // master / dir 0 = Vision, MEASURED on dp9
const PortId_t PORT_HULK   = 9w11;   // outstation / dir 1 = Hulk, MEASURED on dp11

// ---- classification result enum (bit<8>). 0 is the natural NON_DNP3 catch-all. ----
const bit<8> CLASS_NON_DNP3   = 0;   // not TCP, or TCP not on the DNP3 flow, or 0-payload control
const bit<8> CLASS_DNP3_READ  = 1;   // dir==req, dst 20000, DNP3 app func_code==1
const bit<8> CLASS_PURE_ACK   = 2;   // payload_len==0, ACK set, SYN/FIN/RST clear
const bit<8> CLASS_DNP3_RESP  = 3;   // dir==resp, src 20000, DNP3 app func_code==129
const bit<8> CLASS_TCP_FIN    = 4;   // FIN set (RST clear)
const bit<8> CLASS_TCP_RST    = 5;   // RST set
const bit<8> CLASS_LINK_OTHER = 6;   // 0x0564 present but func_code not 1/129 (link status / other FC / wrong dir)
const bit<8>  CLASS_MALFORMED = 7;   // to/from 20000 with payload>0 but 0x0564 magic mismatch
const bit<32> NUM_CLASSES     = 8;   // enum span 0..7 -> per-class Counter size (bit<32>: Counter ctor arg)

// ---- notes / parse-detail code (bit<8>) — disambiguates the catch-all buckets for the collector ----
const bit<8> NOTE_OK           = 0;
const bit<8> NOTE_NON_TCP      = 1;  // frame is not IPv4/TCP (ARP, ICMP, ...)
const bit<8> NOTE_NOT_DNP3_FLOW= 2;  // TCP but neither port is 20000
const bit<8> NOTE_TCP_CONTROL  = 3;  // 0-payload, not a pure ACK (SYN / SYN-ACK / handshake) on the DNP3 flow
const bit<8> NOTE_NO_MAGIC     = 4;  // payload>0 on DNP3 flow but 0x0564 did not match -> MALFORMED
const bit<8> NOTE_OTHER_FC     = 5;  // 0x0564 valid, func_code not 1/129
const bit<8> NOTE_WRONG_DIR    = 6;  // func_code 1/129 but the direction/port does not match a READ/RESPONSE

// digest_type selector (ig_dprsr_md.digest_type is bit<3>; a CONSTANT selects the struct, TNA rule)
const bit<3> DIGEST_SHADOW = 1;

/*==============================================================================
 * HEADERS
 *============================================================================*/

header ethernet_h {
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16> ether_type;
}

header ipv4_h {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<3>  flags;
    bit<13> frag_offset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdr_checksum;
    bit<32> src_addr;
    bit<32> dst_addr;
}

header tcp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4>  data_offset;
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

// TCP options carried verbatim (byte-identical forward). One fixed-size header per data_offset;
// exactly one valid. NEVER read in the MAU — extracted only to be re-emitted unchanged.
header tcp_opt4_h  { bit<32>  data; }
header tcp_opt8_h  { bit<64>  data; }
header tcp_opt12_h { bit<96>  data; }   // Linux timestamps, the common case
header tcp_opt16_h { bit<128> data; }
header tcp_opt20_h { bit<160> data; }
header tcp_opt24_h { bit<192> data; }
header tcp_opt28_h { bit<224> data; }
header tcp_opt32_h { bit<256> data; }
header tcp_opt36_h { bit<288> data; }
header tcp_opt40_h { bit<320> data; }

// DNP3 data-link header (10 B). Extracted whenever a payload-bearing frame passes the length gate.
header dnp3_dl_h {
    bit<8>  start_0;
    bit<8>  start_1;
    bit<8>  length;
    bit<8>  ctrl;
    bit<16> dst_addr;
    bit<16> src_addr;
    bit<16> crc;
}
header dnp3_tp_h  { bit<1> fin; bit<1> fir; bit<6> seq; }
header dnp3_app_h {
    bit<8> app_control;
    bit<8> func_code;
    bit<8> obj_group;
    bit<8> obj_variation;
}

/*==============================================================================
 * METADATA  (all fields byte-aligned per constraint Class 3 — no sub-byte metadata)
 *============================================================================*/

struct metadata_t {
    bit<32> ts;             // ingress_tstamp: low 32 bits of global_tstamp (ns; wrap handled offline)
    bit<16> payload_len;    // total_len + (0x10000 - overhead)  (negate-and-add)
    bit<16> flow_id;        // canonical bidirectional CRC16 hash (same for req/resp)
    bit<16> orig_len;       // original frame length = ipv4.total_len + 14 (Eth II hdr); 0 if not IPv4
    bit<16> d_dnp3_dst;     // DNP3 link dst_addr for the digest (0 if no DNP3 header)
    bit<16> d_dnp3_src;     // DNP3 link src_addr for the digest (0 if no DNP3 header)
    bit<8>  ig_port;        // ingress dev_port, low 8 bits (dp8/dp9)
    bit<8>  eg_port;        // egress dev_port, low 8 bits (dp8/dp9)
    bit<8>  dir;            // 0 = from Vision (request), 1 = from Hulk (response)
    bit<8>  flags_ok;       // pure ACK: (flags & 0x17)==0x10
    bit<8>  is_fin;         // FIN bit set
    bit<8>  is_rst;         // RST bit set
    bit<8>  d_func;         // DNP3 app func_code for the digest (0 if no DNP3 header)
    bit<8>  d_appseq;       // DNP3 app_control & 0x0f for the digest (0 if no DNP3 header)
    bit<8>  classification; // CLASS_* result
    bit<8>  notes;          // NOTE_* parse/classification detail
}

struct headers_t {
    ethernet_h  ethernet;
    ipv4_h      ipv4;
    tcp_h       tcp;
    tcp_opt4_h  tcp_opt4;
    tcp_opt8_h  tcp_opt8;
    tcp_opt12_h tcp_opt12;
    tcp_opt16_h tcp_opt16;
    tcp_opt20_h tcp_opt20;
    tcp_opt24_h tcp_opt24;
    tcp_opt28_h tcp_opt28;
    tcp_opt32_h tcp_opt32;
    tcp_opt36_h tcp_opt36;
    tcp_opt40_h tcp_opt40;
    dnp3_dl_h   dnp3_dl;
    dnp3_tp_h   dnp3_tp;
    dnp3_app_h  dnp3_app;
}

// ---- measurement digest. Field order == pack() order, and GROUPED BY WIDTH (32b, then 16b, then
// 8b) so the learn engine packs them with minimal alignment padding — a flat 48 B learn-quantum cap
// (constraint Class 4) is on the container-aligned physical layout, not the logical bit sum, and an
// ungrouped ordering fragmented this to ~51 B. Grouped, the 34 logical bytes fit with margin. ----
struct shadow_dg_t {
    // ---- 32-bit group ----
    bit<32> ingress_tstamp;   // low 32 bits of global_tstamp
    bit<32> tcp_seq;
    bit<32> tcp_ack;
    // ---- 16-bit group ----
    bit<16> flow_hash;
    bit<16> tcp_src_port;
    bit<16> tcp_dst_port;
    bit<16> payload_len;
    bit<16> dnp3_dst_addr;
    bit<16> dnp3_src_addr;
    bit<16> orig_len;
    // ---- 8-bit group ----
    bit<8>  ingress_port;     // dev_port low 8 bits (dp8/dp9)
    bit<8>  egress_port;      // dev_port low 8 bits (dp8/dp9)
    bit<8>  direction;
    bit<8>  tcp_flags;
    bit<8>  dnp3_func_code;
    bit<8>  dnp3_app_seq;
    bit<8>  classification;
    bit<8>  notes;
}

/*==============================================================================
 * INGRESS PARSER  (identical classification structure to dcrn_defense1.p4, MINUS the recirc
 *                  bridge: Ethernet branches on IPv4 only; no ETHERTYPE_DCRN, no parse_bridge)
 *============================================================================*/

parser ShadowIngressParser(
        packet_in pkt,
        out headers_t hdr,
        out metadata_t meta,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        meta.ts             = 0;
        meta.ig_port        = 0;
        meta.eg_port        = 0;
        meta.payload_len    = 0;
        meta.flow_id        = 0;
        meta.orig_len       = 0;
        meta.d_dnp3_dst     = 0;
        meta.d_dnp3_src     = 0;
        meta.dir            = 0;
        meta.flags_ok       = 0;
        meta.is_fin         = 0;
        meta.is_rst         = 0;
        meta.d_func         = 0;
        meta.d_appseq       = 0;
        meta.classification = 0;
        meta.notes          = 0;
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            default        : accept;          // ARP / other -> transparent forward, classified NON_DNP3
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.ihl) {
            4w5    : parse_tcp;               // only no-option IPv4
            default: accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        // L4-PAYLOAD LENGTH GATE (verbatim from dcrn_defense1.p4): descend into DNP3 parsing ONLY
        // when the frame is long enough to hold a DNP3 link header, else extract(dnp3_dl) reads past
        // end-of-packet -> parser error -> the frame is DROPPED (this crashed every pure TCP ACK to
        // dst 20000). IP header = 20B (ihl==5), TCP header = 4*data_offset, DNP3 needs
        // total_len >= 20 + 4*data_offset + 10 = 30 + 4*data_offset. The parser cannot do arithmetic,
        // so range-match total_len per data_offset in THIS state (only 1 16b parser match register),
        // and exclude SYN (flags[1:1]==0). dst_port is intentionally NOT in the select (16b register
        // is full); the MAU re-checks dst_port==20000 for the READ classification.
        transition select(hdr.tcp.flags[1:1], hdr.tcp.data_offset, hdr.ipv4.total_len) {
            (1w0, 4w5,  16w50 .. 16w65535) : parse_tcp_options;   // no options
            (1w0, 4w6,  16w54 .. 16w65535) : parse_tcp_options;
            (1w0, 4w7,  16w58 .. 16w65535) : parse_tcp_options;
            (1w0, 4w8,  16w62 .. 16w65535) : parse_tcp_options;   // Linux TCP timestamps — common case
            (1w0, 4w9,  16w66 .. 16w65535) : parse_tcp_options;
            (1w0, 4w10, 16w70 .. 16w65535) : parse_tcp_options;
            (1w0, 4w11, 16w74 .. 16w65535) : parse_tcp_options;
            (1w0, 4w12, 16w78 .. 16w65535) : parse_tcp_options;
            (1w0, 4w13, 16w82 .. 16w65535) : parse_tcp_options;
            (1w0, 4w14, 16w86 .. 16w65535) : parse_tcp_options;
            (1w0, 4w15, 16w90 .. 16w65535) : parse_tcp_options;
            default                        : accept;             // pure ACK / short / SYN -> forward
        }
    }

    state parse_tcp_options {
        transition select(hdr.tcp.data_offset) {
            5  : parse_dnp3_dl;      // no options
            6  : opt4;
            7  : opt8;
            8  : opt12;              // Linux TCP timestamps — the common case
            9  : opt16;
            10 : opt20;
            11 : opt24;
            12 : opt28;
            13 : opt32;
            14 : opt36;
            15 : opt40;
            default : accept;
        }
    }
    state opt4  { pkt.extract(hdr.tcp_opt4);  transition parse_dnp3_dl; }
    state opt8  { pkt.extract(hdr.tcp_opt8);  transition parse_dnp3_dl; }
    state opt12 { pkt.extract(hdr.tcp_opt12); transition parse_dnp3_dl; }
    state opt16 { pkt.extract(hdr.tcp_opt16); transition parse_dnp3_dl; }
    state opt20 { pkt.extract(hdr.tcp_opt20); transition parse_dnp3_dl; }
    state opt24 { pkt.extract(hdr.tcp_opt24); transition parse_dnp3_dl; }
    state opt28 { pkt.extract(hdr.tcp_opt28); transition parse_dnp3_dl; }
    state opt32 { pkt.extract(hdr.tcp_opt32); transition parse_dnp3_dl; }
    state opt36 { pkt.extract(hdr.tcp_opt36); transition parse_dnp3_dl; }
    state opt40 { pkt.extract(hdr.tcp_opt40); transition parse_dnp3_dl; }

    state parse_dnp3_dl {
        pkt.extract(hdr.dnp3_dl);
        transition select(hdr.dnp3_dl.start_0, hdr.dnp3_dl.start_1) {
            (DNP3_START_0, DNP3_START_1) : parse_dnp3_tp;
            default                      : accept;   // 0x0564 mismatch -> MALFORMED in the MAU
        }
    }
    state parse_dnp3_tp  { pkt.extract(hdr.dnp3_tp);  transition parse_dnp3_app; }
    state parse_dnp3_app { pkt.extract(hdr.dnp3_app); transition accept; }
}

/*==============================================================================
 * INGRESS CONTROL — classify, forward unchanged, emit measurement digest
 *============================================================================*/

control ShadowIngress(
        inout headers_t hdr,
        inout metadata_t meta,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    // per-class packet Counter (Stats ALU). Read via bfrt with a SyncCounters op.
    Counter<bit<64>, bit<8>>(NUM_CLASSES, CounterType_t.PACKETS) class_ctr;

    // canonical bidirectional flow hash — ONE instance, ONE tuple shape (no Class-7 reuse hazard)
    Hash<bit<16>>(HashAlgorithm_t.CRC16) flow_hash;

    // A/B measurement gate (default 1 => digests on). Read-only; NOT an in-SALU ==0 sentinel
    // (Class 8) — the controller can flip it to 0 for the "off" arm. Forwarding ignores it.
    Register<bit<8>, bit<8>>(1, 1) reg_shadow_enable;
    RegisterAction<bit<8>, bit<8>, bit<8>>(reg_shadow_enable) shadow_enable_read = {
        void apply(inout bit<8> v, out bit<8> rv) { rv = v; }
    };

    // ---- payload-length overhead table (negate-and-add; Class 5), verbatim from defense1 ----
    action set_overhead(bit<16> neg_ov) { meta.payload_len = hdr.ipv4.total_len + neg_ov; }
    table tcp_overhead {
        key     = { hdr.tcp.data_offset : exact; }
        actions = { set_overhead; }
        const entries = {
            (4w5)  : set_overhead(16w0xFFD8);   // -40
            (4w6)  : set_overhead(16w0xFFD4);   // -44
            (4w7)  : set_overhead(16w0xFFD0);   // -48
            (4w8)  : set_overhead(16w0xFFCC);   // -52  (TCP timestamps)
            (4w9)  : set_overhead(16w0xFFC8);   // -56
            (4w10) : set_overhead(16w0xFFC4);   // -60
            (4w11) : set_overhead(16w0xFFC0);   // -64
            (4w12) : set_overhead(16w0xFFBC);   // -68
            (4w13) : set_overhead(16w0xFFB8);   // -72
            (4w14) : set_overhead(16w0xFFB4);   // -76
            (4w15) : set_overhead(16w0xFFB0);   // -80
        }
        default_action = set_overhead(16w0xFFD8);   // -40
        size = 16;
    }

    apply {
        // ===== PROLOGUE (parallel; shared by every path) =====
        meta.ts      = ig_prsr_md.global_tstamp[31:0];           // low 32b ingress tstamp
        meta.ig_port = (bit<8>)ig_intr_md.ingress_port;
        if (ig_intr_md.ingress_port == PORT_VISION) { meta.dir = 0; } else { meta.dir = 1; }

        tcp_overhead.apply();                                    // meta.payload_len (meaningful when TCP valid)

        // canonical bidirectional flow key (server = the :20000 side). IDENTICAL for req and resp.
        bit<32> client_ip;
        bit<16> client_port;
        bit<32> server_ip;
        if (meta.dir == 0) {
            client_ip = hdr.ipv4.src_addr; client_port = hdr.tcp.src_port; server_ip = hdr.ipv4.dst_addr;
        } else {
            client_ip = hdr.ipv4.dst_addr; client_port = hdr.tcp.dst_port; server_ip = hdr.ipv4.src_addr;
        }
        meta.flow_id = flow_hash.get({ client_ip, server_ip, client_port });

        // TCP flag classification, computed shallow (bit<8> per Class 3). Harmless when TCP invalid.
        if ((hdr.tcp.flags & 8w0x17) == 8w0x10) { meta.flags_ok = 1; }   // pure ACK: ACK=1,SYN=RST=FIN=0
        if ((hdr.tcp.flags & 8w0x01) != 0)      { meta.is_fin   = 1; }   // FIN
        if ((hdr.tcp.flags & 8w0x04) != 0)      { meta.is_rst   = 1; }   // RST

        // original frame length = IP total_len + 14 (Ethernet II header). Excludes the 4B FCS and
        // any L2 padding; TNA ingress has no direct packet-length field, so this is the standard proxy.
        if (hdr.ipv4.isValid()) { meta.orig_len = hdr.ipv4.total_len + 16w14; }

        // marshal DNP3 fields into metadata for the digest (headers may be invalid -> default 0),
        // so the deparser never reads a conditionally-valid header.
        if (hdr.dnp3_dl.isValid())  { meta.d_dnp3_dst = hdr.dnp3_dl.dst_addr; meta.d_dnp3_src = hdr.dnp3_dl.src_addr; }
        if (hdr.dnp3_app.isValid()) { meta.d_func = hdr.dnp3_app.func_code; meta.d_appseq = hdr.dnp3_app.app_control & 8w0x0f; }

        // ===== CLASSIFY (mutually exclusive; first match wins) =====
        // on_dnp3 as a guarded bit<8> flag (isValid() stays inside if-conditions; assigning it into
        // a bool local trips bf-p4c "source of modify_field invalid").
        bit<8> on_dnp3 = 0;
        if (hdr.tcp.isValid() && hdr.tcp.dst_port == DNP3_PORT) { on_dnp3 = 1; }
        if (hdr.tcp.isValid() && hdr.tcp.src_port == DNP3_PORT) { on_dnp3 = 1; }
        if (!hdr.tcp.isValid()) {
            meta.classification = CLASS_NON_DNP3;   meta.notes = NOTE_NON_TCP;
        }
        else if (on_dnp3 == 0) {
            meta.classification = CLASS_NON_DNP3;   meta.notes = NOTE_NOT_DNP3_FLOW;
        }
        else if (meta.is_rst == 1) {
            meta.classification = CLASS_TCP_RST;    meta.notes = NOTE_OK;
        }
        else if (meta.is_fin == 1) {
            meta.classification = CLASS_TCP_FIN;    meta.notes = NOTE_OK;
        }
        else if (meta.payload_len == 0) {
            if (meta.flags_ok == 1) { meta.classification = CLASS_PURE_ACK; meta.notes = NOTE_OK; }
            else                    { meta.classification = CLASS_NON_DNP3; meta.notes = NOTE_TCP_CONTROL; }  // SYN / handshake
        }
        else if (hdr.dnp3_app.isValid()) {
            // payload>0 on the DNP3 flow with the 0x0564 magic matched
            if (meta.d_func == 8w1 && meta.dir == 0 && hdr.tcp.dst_port == DNP3_PORT) {
                meta.classification = CLASS_DNP3_READ;  meta.notes = NOTE_OK;
            }
            else if (meta.d_func == 8w129 && meta.dir == 1 && hdr.tcp.src_port == DNP3_PORT) {
                meta.classification = CLASS_DNP3_RESP;  meta.notes = NOTE_OK;
            }
            else if (meta.d_func == 8w1 || meta.d_func == 8w129) {
                meta.classification = CLASS_LINK_OTHER; meta.notes = NOTE_WRONG_DIR;   // right FC, wrong direction
            }
            else {
                meta.classification = CLASS_LINK_OTHER; meta.notes = NOTE_OTHER_FC;    // link status / other FC
            }
        }
        else {
            // payload>0 on the DNP3 flow but 0x0564 did NOT match
            meta.classification = CLASS_MALFORMED;  meta.notes = NOTE_NO_MAGIC;
        }

        // ===== SHADOW FORWARD — bump-in-the-wire, byte + order identical, never dropped =====
        if (ig_intr_md.ingress_port == PORT_VISION) {
            ig_tm_md.ucast_egress_port = PORT_HULK;   meta.eg_port = (bit<8>)PORT_HULK;
        } else {
            ig_tm_md.ucast_egress_port = PORT_VISION; meta.eg_port = (bit<8>)PORT_VISION;
        }

        // per-class Counter (counts EVERY packet, TCP or not)
        class_ctr.count(meta.classification);

        // ===== MEASUREMENT DIGEST (A/B-gated; NEVER affects the wire) =====
        // Only for TCP frames, so the deparser packs valid hdr.tcp.* directly (TCP valid => IPv4 valid).
        if (hdr.tcp.isValid()) {
            bit<8> en = shadow_enable_read.execute(0);
            if (en == 1) { ig_dprsr_md.digest_type = DIGEST_SHADOW; }
        }
    }
}

/*==============================================================================
 * INGRESS DEPARSER — emit exactly what was parsed (byte identity), pack the digest.
 * No Checksum extern: no IP/TCP/DNP3 byte is modified anywhere in this program.
 *============================================================================*/

control ShadowIngressDeparser(
        packet_out pkt,
        inout headers_t hdr,
        in metadata_t meta,
        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    Digest<shadow_dg_t>() shadow_digest;
    apply {
        // one learn-digest per packet, gated by the CONSTANT digest_type (TNA rule). hdr.tcp is
        // guaranteed valid here (digest_type is only set when hdr.tcp.isValid()); DNP3 fields ride
        // in metadata (0 when absent), so nothing conditionally-valid is read in pack().
        if (ig_dprsr_md.digest_type == DIGEST_SHADOW) {
            // pack order MUST match shadow_dg_t field order (width-grouped: 32b, 16b, 8b)
            shadow_digest.pack({ meta.ts, hdr.tcp.seq_no, hdr.tcp.ack_no,
                                 meta.flow_id, hdr.tcp.src_port, hdr.tcp.dst_port, meta.payload_len,
                                 meta.d_dnp3_dst, meta.d_dnp3_src, meta.orig_len,
                                 meta.ig_port, meta.eg_port, meta.dir, hdr.tcp.flags,
                                 meta.d_func, meta.d_appseq, meta.classification, meta.notes });
        }
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.tcp_opt4);
        pkt.emit(hdr.tcp_opt8);
        pkt.emit(hdr.tcp_opt12);
        pkt.emit(hdr.tcp_opt16);
        pkt.emit(hdr.tcp_opt20);
        pkt.emit(hdr.tcp_opt24);
        pkt.emit(hdr.tcp_opt28);
        pkt.emit(hdr.tcp_opt32);
        pkt.emit(hdr.tcp_opt36);
        pkt.emit(hdr.tcp_opt40);
        pkt.emit(hdr.dnp3_dl);
        pkt.emit(hdr.dnp3_tp);
        pkt.emit(hdr.dnp3_app);
    }
}

/*==============================================================================
 * EGRESS — minimal pass-through. The shadow does no egress work (no bridge, no clock, no rewrite).
 * Ethernet is re-emitted verbatim; IPv4-and-beyond ride as unparsed residual -> byte identical.
 *============================================================================*/

struct eg_headers_t  { ethernet_h ethernet; }
struct eg_metadata_t { bit<8> unused_; }

parser ShadowEgressParser(
        packet_in pkt,
        out eg_headers_t hdr,
        out eg_metadata_t meta,
        out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        pkt.extract(eg_intr_md);
        meta.unused_ = 0;
        pkt.extract(hdr.ethernet);
        transition accept;
    }
}

control ShadowEgress(
        inout eg_headers_t hdr,
        inout eg_metadata_t meta,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_prsr_md,
        inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_oport_md) {
    apply { }   // no-op: pass through unchanged
}

control ShadowEgressDeparser(
        packet_out pkt,
        inout eg_headers_t hdr,
        in eg_metadata_t meta,
        in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {
    apply {
        pkt.emit(hdr.ethernet);   // residual (ipv4 + ...) auto-appended -> byte identical
    }
}

/*==============================================================================
 * PIPELINE ASSEMBLY
 *============================================================================*/

Pipeline(
    ShadowIngressParser(),
    ShadowIngress(),
    ShadowIngressDeparser(),
    ShadowEgressParser(),
    ShadowEgress(),
    ShadowEgressDeparser()
) pipe;

Switch(pipe) main;

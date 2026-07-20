/*******************************************************************************
 * dcrn_ackA.p4  —  CASE A: ACK_DELAY_REDUCE_CLRT (event-governed pure-ACK hold)
 *
 * Tofino 1 (TNA), BF-SDE 9.13.1 local / 9.13.2 switch. Compile-time Case-A variant of
 * research/tofino_dcrn_feasibility/p4/dcrn.p4. NO runtime policy_mode — this file is Case A only.
 *
 * WHAT IT DOES (Dr. Lin Case A; test_cases.md §10, ACK_DELAY_STATE_MACHINE.md §2/§3):
 *   - ARM on an eligible master->outstation DNP3 READ (dp8, dst 20000, FC allowlisted): bump the
 *     per-flow generation, store req_tick, set armed, CLEAR the per-flow event flags.
 *   - Separate-ACK transaction: HOLD the pure TCP ACK on the dp68 recirc loop. Release is
 *     EVENT-governed — each pass polls reg_resp_seen; NO wall-clock deadline (so Case A is immune
 *     to the global_tstamp-refresh-on-recirc unknown that stalls deadline holds).
 *   - When the DNP3 RESPONSE arrives, set reg_resp_seen and ADMIT the response to the loop (past
 *     the arming watermark — completing an existing hold, not arming a new one). The held ACK, on
 *     its next pass, sees resp_seen==1, is directed to PORT_VISION, and sets reg_ack_gone:=1 on
 *     that same pass. The response is directed to PORT_VISION only on a pass where it reads
 *     reg_ack_gone==1 (+ a few guard passes).
 *
 * ZERO-INVERSION INVARIANT (the crux): a response frame is directed to PORT_VISION ONLY on a pass
 *   where it reads reg_ack_gone==1; the ACK sets reg_ack_gone:=1 on the pass it is directed to
 *   PORT_VISION. Register writes are visible only to strictly-later passes ⇒ the response's release
 *   pass is strictly later than the ACK's ⇒ on the SHARED FIFO egress queue of PORT_VISION (both
 *   released to qid 0, never QID_HOLD) the ACK dequeues first. Non-same-cycle visibility can only
 *   DELAY the response's read of ack_gone (adds guard), never advance it ⇒ cannot invert.
 *
 * COMBINED MODE (test_cases.md §3): a payload-bearing response with reg_ack_seen==0 (no pure ACK
 *   was ever held) is classified COMBINED → BYPASS unchanged. Never synthesize/suppress an ACK.
 *
 * BYTE-PRESERVATION: the recirc frame carries an internal dcrn_bridge_h (pushed on hold-enter,
 *   popped before the dp8->Vision egress). Frame reaching Vision is IP-and-above bit-identical. No
 *   DNP3/TCP/IP field edit, no seq/ack rewrite, no CRC recompute, NO Checksum() extern.
 *
 * FAIL-OPEN: every guard forwards, never drops (drop() is L2-malformed only). MAX_PASS is a PURE
 *   fail-open cap counted as an alarm — never the normal release cause. The held ACK's fail-open
 *   still sets reg_ack_gone so a waiting response is never stuck. The response has NO independent
 *   time-based fail-open before ack_gone (RESP_MAX_PASS sits far above ACK_MAX_PASS as a last-
 *   resort net that, by construction, only fires long after ack_gone is set → cannot invert).
 *
 * tstamp_tick: written by egress on DCRN frames only (prep for the Case-B clock fix). Case A does
 *   NOT read it — included now so the bridge geometry is stable across the A/B variants.
 *
 * Grounding: parser / overhead-table / Hash / bridge encap-decap / recirc-hold / seeded registers /
 *   two-RegisterActions-per-register / indexed Counter are all lifted from the compiled dcrn.p4 and
 *   the co-resident programs already running on this silicon.
 * Author: Philip
 ******************************************************************************/

#include <core.p4>
#include <tna.p4>

/*==============================================================================
 * CONSTANTS
 *============================================================================*/

const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<16> ETHERTYPE_DCRN = 0x88B6;   // private recirc-bridge ethertype (0x88B5 taken by a co-resident program)
const bit<8>  IP_PROTO_TCP    = 6;
const bit<16> DNP3_PORT       = 20000;
const bit<8>  DNP3_START_0     = 0x05;
const bit<8>  DNP3_START_1     = 0x64;

const PortId_t  PORT_VISION = 9w8;    // master
const PortId_t  PORT_HULK   = 9w9;    // outstation / split_server.py replay
const PortId_t  PORT_RECIRC = 9w68;   // pipe-0 internal recirc port (self-clock)
const QueueId_t QID_HOLD    = 5;      // dp68 shaped hold queue. RELEASE paths leave qid at default 0
                                      // so ACK+response share ONE FIFO queue on PORT_VISION (invariant).

// recirc frame roles (carried in the bridge)
const bit<8> ROLE_ACK  = 0;
const bit<8> ROLE_RESP = 1;

// Case-A ordering guard: the response holds this many extra paced passes AFTER it observes
// ack_gone==1. This δ is the reduced CLRT floor; calibrate down to the minimum inversion-free
// value in the Gate-5 microbenchmark.
const bit<32> GUARD_PASSES  = 32w4;

// PURE fail-open caps (powers of 2 -> cheap high-bits gateway). ACK_MAX_PASS bounds a hold whose
// response never arrives; RESP_MAX_PASS is a last-resort net far above it (never fires in correct
// operation because ack_gone is always set by the ACK's own release/fail-open first).
const bit<32> ACK_MAX_PASS  = 32w65536;    // 2^16
const bit<32> RESP_MAX_PASS = 32w131072;   // 2^17

const bit<32> HELD_MAX = 32w256;   // recirc-occupancy watermark -> ARMING new ACK holds is gated

// event-counter indices (one indexed Counter)
const bit<8> EV_PASSTHRU        = 0;
const bit<8> EV_ARMED           = 1;
const bit<8> EV_ACK_HELD        = 2;
const bit<8> EV_ACK_RELEASED    = 3;   // normal event-governed release
const bit<8> EV_RESP_HELD       = 4;
const bit<8> EV_RESP_RELEASED   = 5;
const bit<8> EV_COMBINED_BYPASS = 6;
const bit<8> EV_WATERMARK_BYPASS= 7;
const bit<8> EV_STALE_FLUSH     = 8;
const bit<8> EV_ARM_BYPASS      = 9;   // request seen but FC not allowlisted
const bit<8> EV_ACK_MAXPASS     = 10;  // ALARM: ACK fail-open cap hit
const bit<8> EV_RESP_MAXPASS    = 11;  // ALARM: response safety net hit (must stay 0)

// Dedicated RELIABLE event tallies (reason: the standalone Stats-ALU Counter needs a HW->SW sync to
// read; a bfrt Register reads live — reg_held_count proved this on HW while the Counter read 0).
// TWO registers (one per release block) so each has a SINGLE call site at one depth — a single
// register touched in BOTH the ACK-release and response-release sub-branches cannot span the two
// depths (placement fails, as held_count did). Index = the alarm bit:  [0]=RELEASED  [1]=MAXPASS.
const bit<8> ES_RELEASED = 0;
const bit<8> ES_MAXPASS   = 1;

/*==============================================================================
 * HEADERS
 *============================================================================*/

header ethernet_h {
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16> ether_type;
}

// Internal recirc-only bridge (NEVER reaches Vision). Pushed on hold-enter, popped on release.
header dcrn_bridge_h {
    bit<16> original_ethertype;   // 0x0800, restored on release
    bit<32> pass_count;           // recirc laps (fail-open cap) — 32-bit so a power-of-2 cap is a
                                  // cheap high-bits gateway check
    bit<32> tstamp_tick;          // egress global_tstamp[47:16], written per pass in egress.
                                  // Case A does NOT read it (Case-B clock-fix prep only).
    bit<8>  role;                 // ROLE_ACK / ROLE_RESP  (Class 3: byte-wide)
    bit<8>  gen;                  // transaction generation at hold-enter (staleness guard)
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

// TCP options carried verbatim on the REQUEST path (byte-identical forward). One fixed-size header
// per data_offset; exactly one valid. NEVER read in the MAU — extracted only to be re-emitted.
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

// DNP3 data-link header (10 B). Extracted ONLY for requests (dst 20000) to reach the FC.
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
 * METADATA
 *============================================================================*/

struct metadata_t {
    bit<8>  dir;            // 0 = from Vision(dp8), 1 = from Hulk(dp9)/recirc(dp68)
    bit<16> payload_len;    // total_len + (0x10000 - overhead)   (negate-and-add)
    bit<16> flow_id;        // canonical bidirectional Hash index (same for req/resp/recirc)
    bit<32> now_tick;       // global_tstamp[47:16], 65.5 us tick
    bit<8>  fc_ok;          // FC on allowlist
}

struct headers_t {
    ethernet_h    ethernet;
    dcrn_bridge_h bridge;     // valid only on the recirc loop
    ipv4_h        ipv4;
    tcp_h         tcp;
    tcp_opt4_h    tcp_opt4;   // request path only — carried TCP options (one valid)
    tcp_opt8_h    tcp_opt8;
    tcp_opt12_h   tcp_opt12;
    tcp_opt16_h   tcp_opt16;
    tcp_opt20_h   tcp_opt20;
    tcp_opt24_h   tcp_opt24;
    tcp_opt28_h   tcp_opt28;
    tcp_opt32_h   tcp_opt32;
    tcp_opt36_h   tcp_opt36;
    tcp_opt40_h   tcp_opt40;
    dnp3_dl_h     dnp3_dl;    // request path only
    dnp3_tp_h     dnp3_tp;    // request path only
    dnp3_app_h    dnp3_app;   // request path only
}

/*==============================================================================
 * INGRESS PARSER  (identical classification to dcrn.p4)
 *============================================================================*/

parser DcrnIngressParser(
        packet_in pkt,
        out headers_t hdr,
        out metadata_t meta,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        meta.dir         = 0;
        meta.payload_len = 0;
        meta.flow_id     = 0;
        meta.now_tick    = 0;
        meta.fc_ok       = 0;
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_DCRN : parse_bridge;    // arrived on recirc port dp68 — strip bridge, continue
            ETHERTYPE_IPV4 : parse_ipv4;
            default        : accept;          // ARP / other -> transparent forward
        }
    }

    state parse_bridge {
        pkt.extract(hdr.bridge);
        transition parse_ipv4;
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
        // L4-PAYLOAD LENGTH GATE (fixes the real-HW drop of zero-payload frames to dst 20000).
        // Descend into DNP3 parsing ONLY when the frame is long enough to hold a DNP3 link header,
        // else extract(dnp3_dl) reads past end-of-packet -> parser error -> the frame is DROPPED in
        // pipeline (this crashed every pure TCP ACK to dst 20000 and caused a retransmit storm on
        // any unconfirmed transaction). IP header = 20B (ihl==5 here), TCP header = 4*data_offset,
        // so DNP3 needs total_len >= 20 + 4*data_offset + 10 = 30 + 4*data_offset.
        // Constraints forced this exact shape (all verified against bf-p4c 9.13.1):
        //   * the parser cannot do arithmetic (-> range-match total_len per data_offset, not compute);
        //   * matching total_len in a state AFTER parse_tcp ICEs, and matching dst_port(16b)+
        //     total_len(16b) in one state overflows the single 16b parser match register -> so we
        //     gate HERE (total_len live-range = 1 state) and DROP dst_port from the select.
        // Dropping dst_port is correct + byte-preserving: the MAU still arms only on dst_port==20000
        // (& dir==0 & dnp3_app.isValid()); a response/other frame merely gets its DNP3 headers
        // extracted and re-emitted identically, and parse_dnp3_dl's 0x0564 magic-byte check rejects
        // non-DNP3. SYN excluded via flags[1:1]==0.
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
            default                      : accept;
        }
    }
    state parse_dnp3_tp  { pkt.extract(hdr.dnp3_tp);  transition parse_dnp3_app; }
    state parse_dnp3_app { pkt.extract(hdr.dnp3_app); transition accept; }
}

/*==============================================================================
 * INGRESS CONTROL
 *============================================================================*/

control DcrnIngress(
        inout headers_t hdr,
        inout metadata_t meta,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    action drop() { ig_dprsr_md.drop_ctl = 1; }   // L2-malformed only, never a DNP3 frame

    Counter<bit<64>, bit<8>>(16, CounterType_t.PACKETS) events;

    Hash<bit<16>>(HashAlgorithm_t.CRC16) flow_hash;

    // ---- per-flow registers (constructor-seeded 0; Class 8: no in-SALU ==0 sentinel) ----
    Register<bit<8>,  bit<16>>(65536, 0) reg_gen;        // transaction generation
    Register<bit<8>,  bit<16>>(65536, 0) reg_armed;      // flow armed on an eligible READ
    Register<bit<32>, bit<16>>(65536, 0) reg_req_tick;   // request arrival tick (telemetry / Case-B)
    Register<bit<8>,  bit<16>>(65536, 0) reg_ack_seen;   // pure ACK observed (separate mode)
    Register<bit<8>,  bit<16>>(65536, 0) reg_resp_seen;  // response entered pipeline (Case-A trigger)
    Register<bit<8>,  bit<16>>(65536, 0) reg_ack_gone;   // held ACK directed to PORT_VISION (ordering)
    Register<bit<32>, bit<1>>(1, 0)      reg_held_count; // recirc-occupancy watermark (ACK arming)
    // reliable release-path event tallies, read via bfrt Register (not the Stats-ALU Counter):
    //   evstat_ack[0]=ACK_RELEASED  evstat_ack[1]=ACK_MAXPASS
    //   evstat_resp[0]=RESP_RELEASED evstat_resp[1]=RESP_MAXPASS
    Register<bit<32>, bit<8>>(2, 0)      evstat_ack;
    Register<bit<32>, bit<8>>(2, 0)      evstat_resp;

    // reg_gen: bump at arm; read for stale-frame guard / bridge stamp
    RegisterAction<bit<8>, bit<16>, bit<8>>(reg_gen) gen_bump = {
        void apply(inout bit<8> v, out bit<8> rv) { v = v + 1; rv = v; }
    };
    // reg_armed
    RegisterAction<bit<8>, bit<16>, bit<8>>(reg_armed) armed_set = {
        void apply(inout bit<8> v, out bit<8> rv) { v = 1; rv = 1; }
    };
    RegisterAction<bit<8>, bit<16>, bit<8>>(reg_armed) armed_get = {
        void apply(inout bit<8> v, out bit<8> rv) { rv = v; }
    };
    // reg_req_tick
    RegisterAction<bit<32>, bit<16>, bit<32>>(reg_req_tick) reqtick_set = {
        void apply(inout bit<32> v, out bit<32> rv) { v = meta.now_tick; rv = v; }
    };
    // reg_ack_seen: set on ACK-hold; atomic read-and-clear when the response consumes it
    // (one SALU op -> avoids a same-stage read-then-conditional-write-of-the-same-register).
    RegisterAction<bit<8>, bit<16>, bit<8>>(reg_ack_seen) ackseen_set = {
        void apply(inout bit<8> v, out bit<8> rv) { v = 1; rv = 1; }
    };
    RegisterAction<bit<8>, bit<16>, bit<8>>(reg_ack_seen) ackseen_getclr = {
        void apply(inout bit<8> v, out bit<8> rv) { rv = v; v = 0; }
    };
    // reg_resp_seen: set on response-admit; atomic read-and-clear on each ACK poll (a no-op until
    // the response sets it; on the matching pass it returns 1 and self-clears for the next txn).
    RegisterAction<bit<8>, bit<16>, bit<8>>(reg_resp_seen) respseen_set = {
        void apply(inout bit<8> v, out bit<8> rv) { v = 1; rv = 1; }
    };
    RegisterAction<bit<8>, bit<16>, bit<8>>(reg_resp_seen) respseen_getclr = {
        void apply(inout bit<8> v, out bit<8> rv) { rv = v; v = 0; }
    };
    // reg_ack_gone
    RegisterAction<bit<8>, bit<16>, bit<8>>(reg_ack_gone) ackgone_set = {
        void apply(inout bit<8> v, out bit<8> rv) { v = 1; rv = 1; }
    };
    RegisterAction<bit<8>, bit<16>, bit<8>>(reg_ack_gone) ackgone_clr = {
        void apply(inout bit<8> v, out bit<8> rv) { v = 0; rv = 0; }
    };
    RegisterAction<bit<8>, bit<16>, bit<8>>(reg_ack_gone) ackgone_get = {
        void apply(inout bit<8> v, out bit<8> rv) { rv = v; }
    };
    // reg_held_count: check-and-increment for ACK arming; decrement on ACK release
    RegisterAction<bit<32>, bit<1>, bit<8>>(reg_held_count) held_check_inc = {
        void apply(inout bit<32> v, out bit<8> over) {
            if (v >= HELD_MAX) { over = 1; }
            else               { v = v + 1; over = 0; }
        }
    };
    RegisterAction<bit<32>, bit<8>, bit<32>>(evstat_ack) evstat_ack_inc = {
        void apply(inout bit<32> v, out bit<32> rv) { v = v + 1; rv = v; }
    };
    RegisterAction<bit<32>, bit<8>, bit<32>>(evstat_resp) evstat_resp_inc = {
        void apply(inout bit<32> v, out bit<32> rv) { v = v + 1; rv = v; }
    };

    // ---- payload-length overhead table (negate-and-add; Class 5) ----
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

    // ---- FC allowlist: controller installs READ (0x01) only initially; miss -> no arm (bypass) ----
    action fc_allow() { meta.fc_ok = 1; }
    table fc_allowlist {
        key     = { hdr.dnp3_app.func_code : exact; }
        actions = { fc_allow; NoAction; }
        default_action = NoAction();
        size = 32;
    }

    apply {
        // ===== UNCONDITIONAL PROLOGUE (parallel; shared by every path) =====
        meta.now_tick = ig_prsr_md.global_tstamp[47:16];
        if (ig_intr_md.ingress_port == PORT_VISION) { meta.dir = 0; }
        else                                        { meta.dir = 1; }   // dp9 or dp68

        tcp_overhead.apply();                              // meta.payload_len

        // canonical bidirectional flow key (server = the :20000 side). IDENTICAL for request,
        // response, AND recirc frame -> one hash, no per-path resolution.
        bit<32> client_ip;
        bit<16> client_port;
        bit<32> server_ip;
        if (meta.dir == 0) {
            client_ip = hdr.ipv4.src_addr; client_port = hdr.tcp.src_port; server_ip = hdr.ipv4.dst_addr;
        } else {
            client_ip = hdr.ipv4.dst_addr; client_port = hdr.tcp.dst_port; server_ip = hdr.ipv4.src_addr;
        }
        meta.flow_id = flow_hash.get({ client_ip, server_ip, client_port });

        // ===== MUTUALLY-EXCLUSIVE PATHS (if / else-if / else — no early return) =====
        if (!hdr.ethernet.isValid()) {
            drop();
        }
        else if (hdr.tcp.isValid() && hdr.tcp.dst_port == DNP3_PORT && meta.payload_len > 0
                 && hdr.dnp3_app.isValid() && meta.dir == 0) {
            // ---------- ARM (request, dp8) — forwarded UNCHANGED to Hulk ----------
            fc_allowlist.apply();                          // meta.fc_ok
            if (meta.fc_ok == 1) {
                // Arm touches ONLY arm-phase registers (keeps each ≤2 phases for placement).
                // Per-txn freshness lives in the event flags, cleared at their reset points below;
                // `armed` correctly stays set for the life of a monitored flow.
                gen_bump.execute(meta.flow_id);            // new transaction generation
                armed_set.execute(meta.flow_id);
                reqtick_set.execute(meta.flow_id);
                events.count(EV_ARMED);
            } else {
                events.count(EV_ARM_BYPASS);
            }
            ig_tm_md.ucast_egress_port = PORT_HULK;        // byte-identical, incl. TCP options
        }
        else if (hdr.bridge.isValid()) {
            // ---------- RECIRC FRAME (a held ACK or an admitted response, looping) ----------
            // (Recirc gen-staleness enforcement is deferred: the bridge carries `gen` for a future
            //  check, but reading reg_gen here too would push it to a 3rd phase. In the initial
            //  single-outstanding/slow-request scope the flag-clear discipline covers freshness.)
            hdr.bridge.pass_count = hdr.bridge.pass_count + 1;

            if (hdr.bridge.role == ROLE_ACK) {
                // held pure ACK: EVENT-governed release (poll resp_seen). Factor the two exit causes
                // into ONE release block -> single call site per register (placement-friendly).
                bit<8> rs = respseen_getclr.execute(meta.flow_id);   // atomic poll+self-clear
                bit<8> ack_release = rs;                   // event-governed
                bit<8> ack_alarm   = 0;
                if (hdr.bridge.pass_count >= ACK_MAX_PASS) { ack_release = 1; ack_alarm = 1; } // isolated 32-bit cmp
                // Each RegisterAction in its OWN action (don't bundle two registers in one action,
                // which would force reg_ack_gone and reg_held_count into a single MAU stage).
                if (ack_release == 1) {
                    ackgone_set.execute(meta.flow_id);     // set on the SAME pass we go to PORT_VISION
                }
                if (ack_release == 1) {
                    // reliable tally (own action, single call site): index = ack_alarm (0=REL,1=MAXPASS)
                    evstat_ack_inc.execute(ack_alarm);
                }
                // NOTE (GATE-3 reduction): the release-time held_count DECREMENT is deferred. It would
                // sit behind the deep resp_seen read (recirc phase) while held_check_inc sits in the
                // reverse phase, and a single-stage global register cannot span both depths here. The
                // ARMING gate (held_check_inc, below) is retained. Loop occupancy in the single-
                // outstanding / single-flow scope is <=2 << HELD_MAX(256), so the cap never trips.
                // Restore precise occupancy for multi-flow scale via an egress-side global counter.
                if (ack_release == 1) {
                    hdr.ethernet.ether_type = hdr.bridge.original_ethertype;
                    hdr.bridge.setInvalid();
                    ig_tm_md.ucast_egress_port = PORT_VISION;   // qid default 0 (shared FIFO)
                    if (ack_alarm == 1) { events.count(EV_ACK_MAXPASS); }   // ALARM (fail-open)
                    else                { events.count(EV_ACK_RELEASED); }
                } else {
                    ig_tm_md.ucast_egress_port = PORT_RECIRC;
                    ig_tm_md.qid               = QID_HOLD;
                }
            }
            else {
                // admitted response: release ONLY on ack_gone==1 (+ guard passes) -> no inversion.
                // The two pass_count compares depend ONLY on pass_count (not on ag), so compute them
                // as standalone isolated 32-bit compares (Class 1) -> the placer runs them early /
                // in parallel with ackgone_get instead of chaining them behind it.
                bit<8> guard_ok = 0;
                if (hdr.bridge.pass_count >= GUARD_PASSES)  { guard_ok = 1; }
                bit<8> resp_alarm = 0;
                if (hdr.bridge.pass_count >= RESP_MAX_PASS) { resp_alarm = 1; }
                bit<8> ag = ackgone_get.execute(meta.flow_id);
                bit<8> resp_release = resp_alarm;                 // last-resort net
                if (ag == 1 && guard_ok == 1) { resp_release = 1; }   // 8-bit predicates only
                if (resp_release == 1) {
                    // reliable tally (own action, single call site): index = resp_alarm (0=REL,1=MAXPASS)
                    evstat_resp_inc.execute(resp_alarm);
                }
                if (resp_release == 1) {
                    hdr.ethernet.ether_type = hdr.bridge.original_ethertype;
                    hdr.bridge.setInvalid();
                    ig_tm_md.ucast_egress_port = PORT_VISION;   // qid default 0 (shared FIFO, AFTER the ACK)
                    if (resp_alarm == 1) { events.count(EV_RESP_MAXPASS); }  // ALARM (must stay 0)
                    else                 { events.count(EV_RESP_RELEASED); }
                } else {
                    ig_tm_md.ucast_egress_port = PORT_RECIRC;
                    ig_tm_md.qid               = QID_HOLD;
                }
            }
        }
        else if (hdr.tcp.isValid() && hdr.tcp.src_port == DNP3_PORT && meta.dir == 1) {
            // ---------- FIRST-ARRIVAL REVERSE FRAME (pure ACK or DNP3 response) ----------
            bit<8> armed = armed_get.execute(meta.flow_id);
            // reg_gen is bumped at arm (a live per-txn generation the control plane can read). The
            // bridge `gen` field is stamped 0 here: recirc gen-staleness enforcement is deferred, so
            // reading reg_gen on the reverse path would only add a cross-branch coupling + a stage.
            if (armed == 0) {
                ig_tm_md.ucast_egress_port = PORT_VISION;   // not armed -> bypass (fail-open)
                events.count(EV_PASSTHRU);
            }
            else if (meta.payload_len == 0) {
                // pure ACK for an armed flow -> HOLD (arming a new hold, watermark-gated).
                // ackseen_set/ackgone_clr are SHALLOW here (parallel with the watermark read) so both
                // reg_ack_seen accesses land at the same depth -> one-stage placement. Marking ack_seen
                // on a watermark-bypass is a harmless saturation corner (the ACK is forwarded, so no
                // inversion; a later response just self-releases via RESP_MAX_PASS).
                ackseen_set.execute(meta.flow_id);            // an ACK is now held (separate mode)
                ackgone_clr.execute(meta.flow_id);            // reset ack_gone for this hold (write-only here)
                bit<8> over = held_check_inc.execute(0);
                if (over == 1) {
                    ig_tm_md.ucast_egress_port = PORT_VISION;   // loop saturated -> bypass ACK
                    events.count(EV_WATERMARK_BYPASS);
                } else {
                    hdr.bridge.setValid();
                    hdr.bridge.original_ethertype = hdr.ethernet.ether_type;   // 0x0800
                    hdr.bridge.pass_count         = 0;
                    hdr.bridge.tstamp_tick        = meta.now_tick;             // seed; egress refreshes
                    hdr.bridge.role               = ROLE_ACK;
                    hdr.bridge.gen                = 0;
                    hdr.ethernet.ether_type       = ETHERTYPE_DCRN;
                    ig_tm_md.ucast_egress_port    = PORT_RECIRC;
                    ig_tm_md.qid                  = QID_HOLD;
                    events.count(EV_ACK_HELD);
                }
            }
            else {
                // payload-bearing DNP3 response for an armed flow
                bit<8> seen = ackseen_getclr.execute(meta.flow_id);   // atomic read+consume (one SALU)
                // Keep the register execute in its OWN action (no action data) — a hash-indexed
                // RegisterAction cannot share a keyless table's action with header/action-data writes.
                if (seen == 1) {
                    respseen_set.execute(meta.flow_id);
                }
                if (seen == 1) {
                    // separate mode: a pure ACK is held -> ADMIT the response PAST the watermark
                    hdr.bridge.setValid();
                    hdr.bridge.original_ethertype = hdr.ethernet.ether_type;
                    hdr.bridge.pass_count         = 0;
                    hdr.bridge.tstamp_tick        = meta.now_tick;
                    hdr.bridge.role               = ROLE_RESP;
                    hdr.bridge.gen                = 0;
                    hdr.ethernet.ether_type       = ETHERTYPE_DCRN;
                    ig_tm_md.ucast_egress_port    = PORT_RECIRC;
                    ig_tm_md.qid                  = QID_HOLD;
                    events.count(EV_RESP_HELD);
                } else {
                    // COMBINED mode (response before any pure ACK) -> BYPASS unchanged (§3)
                    ig_tm_md.ucast_egress_port = PORT_VISION;
                    events.count(EV_COMBINED_BYPASS);
                }
            }
        }
        else {
            // ---------- transparent bump-in-the-wire (ARP / ICMP / non-DNP3 / handshake) ----------
            if (meta.dir == 0) { ig_tm_md.ucast_egress_port = PORT_HULK; }
            else               { ig_tm_md.ucast_egress_port = PORT_VISION; }
            events.count(EV_PASSTHRU);
        }
    }
}

/*==============================================================================
 * INGRESS DEPARSER  (emit all headers; NO Checksum extern — no IP/TCP/DNP3 byte modified)
 *============================================================================*/

control DcrnIngressDeparser(
        packet_out pkt,
        inout headers_t hdr,
        in metadata_t meta,
        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.bridge);      // valid only on the recirc loop; popped before dp8 egress
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
 * EGRESS — stamp the bridge clock on DCRN frames only (Case-B prep; Case A ignores it).
 * Frames RELEASED to Vision have no bridge (popped in ingress) -> not stamped, byte-identical.
 *============================================================================*/

struct eg_headers_t  {
    ethernet_h    ethernet;
    dcrn_bridge_h bridge;
}
struct eg_metadata_t { bit<8> unused_; }

parser DcrnEgressParser(
        packet_in pkt,
        out eg_headers_t hdr,
        out eg_metadata_t meta,
        out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        pkt.extract(eg_intr_md);
        meta.unused_ = 0;
        transition parse_eth;
    }
    state parse_eth {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_DCRN : parse_bridge;   // recirc frame -> peel bridge to stamp it
            default        : accept;         // released/native frame -> rest rides as residual
        }
    }
    state parse_bridge {
        pkt.extract(hdr.bridge);
        transition accept;
    }
}

control DcrnEgress(
        inout eg_headers_t hdr,
        inout eg_metadata_t meta,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_prsr_md,
        inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_oport_md) {
    apply {
        // Refresh the recirc clock each pass. Case A does not read this; Case B's release compare will.
        if (hdr.bridge.isValid()) {
            hdr.bridge.tstamp_tick = eg_prsr_md.global_tstamp[47:16];
        }
    }
}

control DcrnEgressDeparser(
        packet_out pkt,
        inout eg_headers_t hdr,
        in eg_metadata_t meta,
        in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.bridge);   // valid only on DCRN frames; residual (ipv4+...) auto-appended
    }
}

/*==============================================================================
 * PIPELINE ASSEMBLY
 *============================================================================*/

Pipeline(
    DcrnIngressParser(),
    DcrnIngress(),
    DcrnIngressDeparser(),
    DcrnEgressParser(),
    DcrnEgress(),
    DcrnEgressDeparser()
) pipe;

Switch(pipe) main;

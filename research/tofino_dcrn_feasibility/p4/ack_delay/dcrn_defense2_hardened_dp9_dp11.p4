/*******************************************************************************
 * dcrn_ackB.p4  —  CASE B: RESPONSE_DELAY_INCREASE_CLRT (ACK-anchored deadline hold)
 *
 * Tofino 1 (TNA), BF-SDE 9.13.1 local / 9.13.2 switch. Compile-time Case-B variant.
 * SEPARATE program from dcrn_ackA.p4 (Case A) — this file is Case B ONLY, no runtime mode.
 *
 * WHAT IT DOES  (the OPPOSITE of Case A: A holds the ACK; B forwards the ACK and holds the response):
 *   request -> pure ACK (FORWARDED IMMEDIATELY) -> RESPONSE HELD to an ACK-RELATIVE deadline.
 *
 *   Release equation (ACK-relative, NOT request-relative):
 *       t_response_out = max(t_response_ready, t_ACK + G_i)
 *   where G_i is a common, device-independent target gap. Effect: request->ACK is unchanged;
 *   ACK->response is increased to ~G_i; request->response is increased.
 *
 *   The deadline base is recorded AT THE PURE ACK (t_ACK), never at the request. This is the
 *   load-bearing Case-B property — a request-relative t0 (the old dcrn.p4 policy) would be wrong.
 *
 * PER-TRANSACTION DATA PATH:
 *   1. REQUEST  (dp8/dir0, dst 20000, payload>0, DNP3, FC-allowlisted): ARM — set armed, store the
 *      request end-seq (reg_expected_ack = seq + payload_len via the exp_addend prologue-widen trick
 *      to dodge the BIT_COLLISION add). Forward UNCHANGED to Hulk.
 *   2. PURE ACK (dir1, src 20000, payload==0, EXACT-qualified: armed && (flags&0x17)==0x10 &&
 *      reg_expected_ack==tcp.ack_no): record the ACK-anchored deadline reg_deadline = now_tick + G_i
 *      (the ONLY place the deadline is written), mark reg_ack_seen (separate mode), then FORWARD THE
 *      ACK IMMEDIATELY to Vision (no recirc, no hold). This is the Case-A/Case-B difference.
 *   3. RESPONSE (dir1, src 20000, payload>0, armed, a separate pure ACK was seen): if now < deadline
 *      HOLD on the dp68 recirc loop (ROLE_RESP bridge, QID_HOLD), refreshing now from the egress-
 *      bridged global_tstamp each pass and re-checking; release to Vision on the first pass at/after
 *      the deadline and CLEAR the per-txn marker. max(ready,deadline) falls out naturally: a response
 *      cannot be held before it arrives, and it releases the first pass at/after the deadline.
 *   4. COMBINED response (no separate pure ACK seen for the txn): BYPASS unchanged — not held, not
 *      treated as CLRT.
 *   5. FAIL-OPEN: MAX_PASS is a PURE fail-open net only (a held response looping past it is forwarded);
 *      it must NOT be the normal release path (the deadline is). Also fail open on watermark overload,
 *      stale/past deadline (seeded 0), policy-absent (Di=0), and abort (FIN/RST) frames.
 *
 * G_i LOADABILITY (control-plane, NOT hard-compiled): G_i is action data on the bounded_target table
 *   walked by a global txn counter at the ACK. B1_FIXED = controller installs one G_i in every entry
 *   (or the default action); B2_COMMON_BOUNDED = controller installs a device-independent bounded
 *   distribution across the 256 entries (must NOT depend on IP/size/pcap/native-CLRT/ACK-mode). Same
 *   dataplane; the controller fills the table. Calibrate the value separately.
 *
 * BYTE-PRESERVATION: the recirc frame carries an internal dcrn_bridge_h (pushed on hold-enter, POPPED
 *   in ingress before the dp8->Vision egress). The frame reaching Vision is IP-and-above bit-identical.
 *   No DNP3/TCP/IP field edit, no seq/ack rewrite, no CRC recompute, NO Checksum() extern. The request
 *   forwards to Hulk bit-identical INCLUDING its TCP options.
 *
 * CLOCK (deadline holds need a refreshing wall clock; ig_prsr_md.global_tstamp does NOT refresh on
 *   recirc): the ARM/deadline anchor uses ig_prsr_md.global_tstamp at the real ACK arrival (trusted).
 *   The recirc release compares against hdr.bridge.tstamp_tick, which egress rewrites from
 *   eg_prsr_md.global_tstamp[47:16] every pass. First-arrival responses compare against their real
 *   arrival tick. Same clock fix flagged in Case A's bridge; Case B is the case that actually reads it.
 *
 * Grounding: parser/overhead-table/Hash/bridge encap-decap/carried-option ladder are lifted verbatim
 *   from the compiled dcrn_ackA.p4; reg_deadline + the runtime-operand check_deadline SALU +
 *   bounded_target/next_txn + recirc-hold + held-count watermark are lifted from the compiled dcrn.p4
 *   (M1 local fit PASS, 9/12 ingress stages). Only the deadline ANCHOR moves request->ACK.
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

const PortId_t  PORT_MASTER      = 9w9;    // master/dir0=Vision MEASURED dp9 (parser-hardened dp9/dp11 variant)
const PortId_t  PORT_OUTSTATION  = 9w11;   // outstation/dir1=Hulk MEASURED dp11
const PortId_t  PORT_RECIRC = 9w68;   // pipe-0 internal recirc port (self-clock hold loop)
const QueueId_t QID_HOLD    = 5;      // dp68 shaped hold queue — max_rate shaper paces the recirc loop

// recirc frame role (Case B holds ONLY responses; kept byte-wide for bridge-layout parity with Case A)
const bit<8> ROLE_RESP = 1;

// tick = global_tstamp[47:16] = 65.536 us. MAX_PASS is a PURE fail-open cap (power of 2 -> the compare
// reduces to a cheap high-bits gateway). At a paced recirc loop it sits ABOVE the largest installed
// deadline, so the DEADLINE governs release and MAX_PASS only catches a stuck frame.
const bit<32> MAX_PASS = 32w65536;    // 2^16
const bit<32> HELD_MAX = 32w256;      // recirc-occupancy watermark -> new holds bypass

// event-counter indices (one indexed telemetry Counter). NOTE: a Stats-ALU Counter reads 0 on HW
// without operations_execute("SyncCounters"); for a MUST-READ alarm, sync before reading (or promote
// EV_RESP_MAXPASS to a dedicated Register). Off-switch compile-fit does not read HW, so a Counter here.
const bit<8> EV_PASSTHRU         = 0;
const bit<8> EV_ARMED            = 1;   // request armed
const bit<8> EV_ARM_BYPASS       = 2;   // request seen but FC not allowlisted
const bit<8> EV_ACK_DEADLINE     = 3;   // pure ACK qualified -> deadline recorded, ACK forwarded
const bit<8> EV_ACK_PASSTHRU     = 4;   // pure ACK not qualified -> forwarded
const bit<8> EV_RESP_HELD        = 5;   // response entered the recirc hold
const bit<8> EV_RESP_RELEASED    = 6;   // recirc release AT the deadline (normal path)
const bit<8> EV_RESP_RELEASE_NOW = 7;   // first-arrival response, deadline already matured -> release now
const bit<8> EV_COMBINED_BYPASS  = 8;   // response with no separate pure ACK -> bypass (not CLRT)
const bit<8> EV_WATERMARK_BYPASS = 9;   // recirc saturated -> response bypassed
const bit<8> EV_RESP_MAXPASS     = 10;  // ALARM: fail-open cap hit (must stay ~0 in correct operation)

/*==============================================================================
 * HEADERS
 *============================================================================*/

header ethernet_h {
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16> ether_type;
}

// Internal recirc-only bridge (NEVER reaches Vision). Pushed on hold-enter, popped on release.
// Byte layout kept IDENTICAL to dcrn_ackA.p4 so the encap/decap geometry is stable across A/B.
header dcrn_bridge_h {
    bit<16> original_ethertype;   // 0x0800, restored on release
    bit<32> pass_count;           // recirc laps (MAX_PASS fail-open) — 32-bit so a power-of-2 cap is a
                                  // cheap high-bits gateway check
    bit<32> tstamp_tick;          // egress global_tstamp[47:16], rewritten per pass in egress. Case B
                                  // READS this on the recirc release compare (the clock fix).
    bit<8>  role;                 // always ROLE_RESP in Case B (byte-wide; Class 3)
    bit<8>  gen;                  // reserved (staleness guard; unused in the single-outstanding scope)
    bit<8>  event;                // reserved (Case B strips in ingress, so egress needs no event signal)
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

// DNP3 data-link header (10 B). Extracted ONLY for payload-bearing frames past the length gate.
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
    bit<32> now_tick;       // global_tstamp[47:16], 65.5 us tick (real port arrival)
    bit<32> now_eff;        // clock for the deadline compare: now_tick (first-arrival) or bridge tick (recirc)
    bit<8>  bkt_idx;        // bounded_target index (low 8 bits of the txn counter)
    bit<32> deadline;       // now_tick(ACK) + G_i  (single-stage add, ACK-anchored)
    bit<8>  fc_ok;          // FC on allowlist
    bit<8>  released;       // deadline compare result (now_eff >= deadline)
    bit<32> exp_ack;        // request end-seq (= req.seq_no + payload_len), stored at arm
    bit<32> exp_addend;     // payload_len widened to 32b in the prologue (clean 32+32 add; no BIT_COLLISION)
    bit<8>  flags_ok;       // TCP flags == pure ACK ((flags & 0x17)==0x10) — prologue
    bit<8>  not_abort;      // TCP flags have no FIN and no RST ((flags & 0x05)==0) — prologue
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
    dnp3_dl_h     dnp3_dl;
    dnp3_tp_h     dnp3_tp;
    dnp3_app_h    dnp3_app;
}

/*==============================================================================
 * INGRESS PARSER  (VERBATIM from dcrn_ackA.p4 — the payload-length DNP3 gate)
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
        meta.now_eff     = 0;
        meta.bkt_idx     = 0;
        meta.deadline    = 0;
        meta.fc_ok       = 0;
        meta.released    = 0;
        meta.exp_ack     = 0;
        meta.exp_addend  = 0;
        meta.flags_ok    = 0;
        meta.not_abort   = 0;
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
        // pipeline (this crashed every pure TCP ACK to dst 20000 and caused a retransmit storm).
        // IP header = 20B (ihl==5 here), TCP header = 4*data_offset, so DNP3 needs
        // total_len >= 20 + 4*data_offset + 10 = 30 + 4*data_offset.
        // Constraints forced this exact shape: the parser cannot do arithmetic (-> range-match
        // total_len per data_offset), matching total_len in a state AFTER parse_tcp ICEs, and
        // dst_port(16b)+total_len(16b) in one state overflows the single 16b parser match register ->
        // so we gate HERE and drop dst_port from the select (the MAU still arms only on dst_port==20000).
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
        // PARSER HARDENING: descend to transport/app only when link length>=10 (full app header);
        // 0x0564 link-only/short frames pass through to accept (no extract-past-end drop). See
        // shadow/PARSER_HARDENING_ROOTCAUSE_20260724.md. Link-only frames are non-transaction -> the
        // defense forwards them unchanged (they never arm/hold).
        transition select(hdr.dnp3_dl.start_0, hdr.dnp3_dl.start_1, hdr.dnp3_dl.length) {
            (DNP3_START_0, DNP3_START_1, 8w10 .. 8w255) : parse_dnp3_tp;
            (DNP3_START_0, DNP3_START_1, _)             : accept;
            default                                      : accept;
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

    Hash<bit<16>>(HashAlgorithm_t.CRC16) flow_hash;   // ONE instance, ONE tuple shape (Class 7)

    // ---- per-flow registers (constructor-seeded 0; Class 8: no in-SALU ==0 sentinel) ----
    // Every register touches at most 2 pipeline phases (arm / reverse-first-arrival / recirc).
    Register<bit<8>,  bit<16>>(65536, 0) reg_armed;          // active txn: set@arm, read(+abort-clear)@ACK
    Register<bit<32>, bit<16>>(65536, 0) reg_expected_ack;   // request end-seq; match-in-SALU @pure-ACK
    Register<bit<32>, bit<16>>(65536, 0) reg_deadline;       // ACK-anchored absolute deadline (0 = past -> release now)
    Register<bit<8>,  bit<16>>(65536, 0) reg_ack_seen;       // separate-mode marker: set@ACK, read+clear@response
    Register<bit<32>, bit<1>>(1, 0)      reg_txn;            // global txn counter -> bounded_target index
    Register<bit<32>, bit<1>>(1, 0)      reg_held_count;     // global recirc-occupancy watermark

    // reg_armed: set@arm; read@ACK (also clears if the reverse frame is an abort FIN/RST). No response-
    // side clear needed — reg_ack_seen (cleared at the response) is the per-txn reset; armed is re-set
    // by the next request. Keeping armed off the recirc/response phases holds it to 2 phases.
    RegisterAction<bit<8>, bit<16>, bit<8>>(reg_armed) armed_set = {
        void apply(inout bit<8> v, out bit<8> rv) { v = 1; rv = 1; }
    };
    RegisterAction<bit<8>, bit<16>, bit<8>>(reg_armed) armed_get_absclr = {
        void apply(inout bit<8> v, out bit<8> rv) { rv = v; if (meta.not_abort == 0) { v = 0; } }
    };
    // reg_expected_ack: set@arm; compare-in-SALU vs hdr.tcp.ack_no @pure-ACK -> 1-bit match
    RegisterAction<bit<32>, bit<16>, bit<32>>(reg_expected_ack) expack_set = {
        void apply(inout bit<32> v, out bit<32> rv) { v = meta.exp_ack; rv = v; }
    };
    RegisterAction<bit<32>, bit<16>, bit<8>>(reg_expected_ack) expack_match = {
        void apply(inout bit<32> v, out bit<8> matched) {
            if (v == hdr.tcp.ack_no) { matched = 1; } else { matched = 0; }
        }
    };
    // reg_deadline: write @pure-ACK (the ONLY deadline write, ACK-anchored); read via a SINGLE shared
    // check_deadline site (recirc + first-arrival response) -> 2 accesses, mutually exclusive (the
    // dcrn.p4 pattern). NEVER cleared: a stale past deadline reads released=1 -> immediate fail-open.
    RegisterAction<bit<32>, bit<16>, bit<32>>(reg_deadline) arm_deadline = {
        void apply(inout bit<32> dl, out bit<32> rv) { dl = meta.deadline; rv = dl; }
    };
    // Runtime PHV operand (meta.now_eff) compared against the stored word — LOWERED CLEANLY on
    // bf-p4c 9.13.1 (dcrn.p4 M1). `>=` is a magnitude compare, NOT a Class-8 ==0 sentinel.
    RegisterAction<bit<32>, bit<16>, bit<8>>(reg_deadline) check_deadline = {
        void apply(inout bit<32> dl, out bit<8> released) {
            if (meta.now_eff >= dl) { released = 1; }
            else                    { released = 0; }
        }
    };
    // reg_ack_seen: set @pure-ACK (separate mode); atomic read-and-clear @response (per-txn reset)
    RegisterAction<bit<8>, bit<16>, bit<8>>(reg_ack_seen) set_ack_seen = {
        void apply(inout bit<8> v, out bit<8> rv) { v = 1; rv = 1; }
    };
    RegisterAction<bit<8>, bit<16>, bit<8>>(reg_ack_seen) ackseen_getclr = {
        void apply(inout bit<8> v, out bit<8> rv) { rv = v; v = 0; }
    };
    // reg_txn: walk the bounded distribution (global counter)
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_txn) next_txn = {
        void apply(inout bit<32> v, out bit<32> rv) { v = v + 1; rv = v; }
    };
    // reg_held_count: check-and-increment @hold (only if under cap); decrement @recirc-release
    RegisterAction<bit<32>, bit<1>, bit<8>>(reg_held_count) held_check_inc = {
        void apply(inout bit<32> v, out bit<8> over) {
            if (v >= HELD_MAX) { over = 1; }
            else               { v = v + 1; over = 0; }
        }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_held_count) held_dec = {
        void apply(inout bit<32> v, out bit<32> rv) { if (v > 0) { v = v - 1; } rv = v; }
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

    // ---- BOUNDED distribution: controller pre-samples 256 device-independent G_i, installs them ----
    // set_deadline folds t_ACK + G_i: G_i = action data (per-entry const) -> single-stage add (Class 5).
    // B1_FIXED = every entry the same G_i; B2_COMMON_BOUNDED = a device-independent distribution.
    action set_deadline(bit<32> gi) { meta.deadline = meta.now_tick + gi; }
    table bounded_target {
        key     = { meta.bkt_idx : exact; }
        actions = { set_deadline; }
        default_action = set_deadline(32w0);   // policy-absent -> deadline in the past -> immediate release
        size = 256;
    }

    apply {
        // ===== UNCONDITIONAL PROLOGUE (parallel; shared by every path) =====
        meta.now_tick = ig_prsr_md.global_tstamp[47:16];
        if (ig_intr_md.ingress_port == PORT_MASTER) { meta.dir = 0; }
        else                                        { meta.dir = 1; }   // dp9 or dp68

        tcp_overhead.apply();                              // meta.payload_len
        meta.exp_addend = (bit<32>)meta.payload_len;       // widen HERE (SET) so the arm-time exp_ack
                                                           // add is a clean 32+32 (no BIT_COLLISION)

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

        // TCP-flag classification, computed SHALLOW here so the reverse paths stay flat.
        if ((hdr.tcp.flags & 8w0x17) == 8w0x10) { meta.flags_ok  = 1; }   // pure ACK: ACK=1,SYN=RST=FIN=0
        if ((hdr.tcp.flags & 8w0x05) == 0)      { meta.not_abort = 1; }   // no FIN, no RST

        // ===== MUTUALLY-EXCLUSIVE PATHS (if / else-if / else — no early return) =====
        if (!hdr.ethernet.isValid()) {
            drop();
        }
        else if (hdr.tcp.isValid() && hdr.tcp.dst_port == DNP3_PORT && meta.payload_len > 0
                 && hdr.dnp3_app.isValid() && meta.dir == 0) {
            // ---------- ARM (request, dp8) — forwarded UNCHANGED to Hulk ----------
            fc_allowlist.apply();                          // meta.fc_ok
            meta.exp_ack = hdr.tcp.seq_no + meta.exp_addend;   // request end-seq (clean 32+32)
            if (meta.fc_ok == 1) {
                armed_set.execute(meta.flow_id);           // active txn
                expack_set.execute(meta.flow_id);          // store request end-seq (for the ACK match)
                events.count(EV_ARMED);
            } else {
                events.count(EV_ARM_BYPASS);
            }
            ig_tm_md.ucast_egress_port = PORT_OUTSTATION;        // byte-identical, incl. TCP options
        }
        else if (hdr.tcp.isValid() && hdr.tcp.src_port == DNP3_PORT && meta.dir == 1
                 && meta.payload_len == 0) {
            // ---------- PURE ACK (reverse, dp9): FORWARD IMMEDIATELY + record ACK-anchored deadline ----------
            // Walk the device-independent target distribution in parallel with the qual reads; only the
            // deadline WRITE is gated by qualification (dcrn.p4 pattern: walk ungated, gate the write).
            bit<32> txn  = next_txn.execute(0);
            meta.bkt_idx = txn[7:0];
            bounded_target.apply();                        // meta.deadline = now_tick(ACK) + G_i  (ANCHORED HERE)

            bit<8> armed  = armed_get_absclr.execute(meta.flow_id);   // clears armed if abort (FIN/RST)
            bit<8> amatch = expack_match.execute(meta.flow_id);       // reg_expected_ack == ack_no?
            bit<8> qual = 0;
            if (armed == 1 && meta.flags_ok == 1 && amatch == 1) { qual = 1; }   // EXACT pure-ACK qualification
            if (qual == 1) {
                set_ack_seen.execute(meta.flow_id);        // separate-mode marker (read by the response)
                arm_deadline.execute(meta.flow_id);        // reg_deadline = meta.deadline (ONLY deadline write)
                events.count(EV_ACK_DEADLINE);
            } else {
                events.count(EV_ACK_PASSTHRU);
            }
            ig_tm_md.ucast_egress_port = PORT_MASTER;       // ACK ALWAYS forwarded now (no hold) — core Case B
        }
        else if (hdr.bridge.isValid() ||
                 (hdr.tcp.isValid() && hdr.tcp.src_port == DNP3_PORT && meta.dir == 1)) {
            // ---------- HOLD / RELEASE (recirc frames + first-arrival responses) ----------
            // A pure ACK (payload==0) was caught above, so a first-arrival frame here has payload>0.
            bit<8> is_recirc = 0;
            if (hdr.bridge.isValid()) { is_recirc = 1; }

            // CLOCK: recirc reads the egress-refreshed bridge tick; first-arrival uses its real arrival.
            if (is_recirc == 1) { meta.now_eff = hdr.bridge.tstamp_tick; }
            else                { meta.now_eff = meta.now_tick; }

            // first-arrival response: separate-vs-combined classification + per-txn reset (getclr)
            bit<8> seen = 0;
            if (is_recirc == 0) { seen = ackseen_getclr.execute(meta.flow_id); }

            // THE single deadline compare (shared recirc + first-arrival) -> reg_deadline stays 2-access
            meta.released = check_deadline.execute(meta.flow_id);   // 1 = now_eff >= deadline

            if (is_recirc == 1) {
                // recirc frame: release when now>=deadline OR max-pass fail-open, else keep looping
                hdr.bridge.pass_count = hdr.bridge.pass_count + 1;
                // isolate the 32-bit magnitude compare (Class 1: one magnitude compare per gateway,
                // no second predicate) so the placer runs it parallel to check_deadline.
                bit<8> do_release = meta.released;
                bit<8> alarm      = 0;
                if (hdr.bridge.pass_count >= MAX_PASS) { do_release = 1; alarm = 1; }
                if (do_release == 1) {
                    hdr.ethernet.ether_type = hdr.bridge.original_ethertype;   // restore 0x0800
                    hdr.bridge.setInvalid();                                   // POP bridge (byte-preserved)
                    held_dec.execute(0);                                       // release occupancy
                    ig_tm_md.ucast_egress_port = PORT_MASTER;
                    if (alarm == 1) { events.count(EV_RESP_MAXPASS); }         // ALARM (must stay ~0)
                    else            { events.count(EV_RESP_RELEASED); }        // normal: released AT deadline
                } else {
                    ig_tm_md.ucast_egress_port = PORT_RECIRC;
                    ig_tm_md.qid               = QID_HOLD;
                }
            } else {
                // first-arrival response
                bit<8> sep = 0;
                if (seen == 1 && meta.not_abort == 1) { sep = 1; }   // separate mode + genuine (not FIN/RST-data)
                if (sep == 0) {
                    // COMBINED (no separate ACK) / unmonitored / abort-with-data -> BYPASS unchanged
                    ig_tm_md.ucast_egress_port = PORT_MASTER;
                    events.count(EV_COMBINED_BYPASS);
                } else if (meta.released == 1) {
                    // deadline already matured (t_resp_ready >= t_ACK + G_i) -> release NOW (max() lower arm)
                    ig_tm_md.ucast_egress_port = PORT_MASTER;
                    events.count(EV_RESP_RELEASE_NOW);
                } else {
                    // HOLD to the ACK-anchored deadline on the recirc loop
                    bit<8> over = held_check_inc.execute(0);   // occupancy arming gate (fail-open guard)
                    if (over == 1) {
                        ig_tm_md.ucast_egress_port = PORT_MASTER;   // recirc saturated -> bypass
                        events.count(EV_WATERMARK_BYPASS);
                    } else {
                        // header-only block (no reg.execute) so the hash-indexed SALUs above don't
                        // share an action with header writes (placement rule #4).
                        hdr.bridge.setValid();
                        hdr.bridge.original_ethertype = hdr.ethernet.ether_type;   // 0x0800
                        hdr.bridge.pass_count         = 0;
                        hdr.bridge.tstamp_tick        = meta.now_tick;   // seed; egress refreshes each pass
                        hdr.bridge.role               = ROLE_RESP;
                        hdr.bridge.gen                = 0;
                        hdr.bridge.event              = 0;
                        hdr.ethernet.ether_type       = ETHERTYPE_DCRN;
                        ig_tm_md.ucast_egress_port    = PORT_RECIRC;
                        ig_tm_md.qid                  = QID_HOLD;
                        events.count(EV_RESP_HELD);
                    }
                }
            }
        }
        else {
            // ---------- transparent bump-in-the-wire (ARP / ICMP / non-DNP3 / handshake) ----------
            if (meta.dir == 0) { ig_tm_md.ucast_egress_port = PORT_OUTSTATION; }
            else               { ig_tm_md.ucast_egress_port = PORT_MASTER; }
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
 * EGRESS — refresh the bridge clock on recirc frames only (the Case-B clock fix).
 * Released frames had their bridge popped in ingress -> not stamped, byte-identical.
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
            ETHERTYPE_DCRN : parse_bridge;   // recirc frame -> peel bridge to refresh its tick
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
        if (hdr.bridge.isValid()) {
            // recirc frame (still DCRN): refresh the clock so the ingress deadline compare advances.
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
        pkt.emit(hdr.bridge);   // valid only on DCRN recirc frames; residual (ipv4+...) auto-appended
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

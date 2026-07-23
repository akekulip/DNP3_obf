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
 *
 * ---------------------------------------------------------------------------
 * TELEMETRY GRAFT (dcrn_defense2_telem.p4) — Track 1 instrumentation of the cover-OFF,
 * DEADLINE-governed Case-A Defense 2 ("delay the response"). NON-INVASIVE, measurement-only:
 * it changes NOTHING on the release path. The four frozen exits keep byte-identical predicates —
 * recirc deadline release (now_eff>=deadline via check_deadline), recirc MAX_PASS fail-open,
 * first-arrival deadline-already-matured immediate release, and the combined/ineligible BYPASS.
 * The graft only (1) stamps a measurement tick into the recirc bridge at the response hold-ENTER
 * (admit), (2) STAGES release-edge measurement values into metadata (read-only copies of bridge
 * fields, taken BEFORE the frozen ingress bridge-pop), and (3) emits control-plane learning
 * DIGESTS, A/B-gated by a telemetry_enable register (default 0 => byte- and timing-identical to the
 * frozen original). Every global_tstamp / bridge / deadline read here is MEASUREMENT ONLY and never
 * appears in a release/fail-open/ambiguity/bypass/cleanup predicate.
 *
 * TWO digests (register-free), joined by the collector on (run_id, flow_id, txn_ack):
 *   - d2_ack_dg_t   @ qualified pure-ACK  : exports deadline_tick = meta.deadline (= t_ACK + G_i).
 *   - d2_resp_dg_t  @ response-release/exit: exports t_in, release_tick, pass_count, release_reason.
 *   PRIMARY METRIC  E_D2 = (RESP).release_tick - (ACK).deadline_tick  (overshoot past the deadline).
 *
 * WHY the deadline is exported at the ACK (not read into the response digest): the frozen
 * check_deadline SALU consumes reg_deadline's SINGLE per-packet stateful access on EVERY hold/release
 * pass, so reg_deadline cannot be read a second time at admit; and the deadline value does not exist
 * on the response packet before that (locked in reg_deadline). Rather than add a redundant per-flow
 * deadline-mirror register (explicitly disallowed; the Defense-1 review's reg_resp_tick lesson), the
 * deadline is captured register-free at the ACK where meta.deadline already exists, exactly mirroring
 * Defense 1's two-digest + (run_id,flow_id,txn_ack) join idiom. Not per-pass work (one-time ACK event).
 *
 * CLOCK: ig_prsr_md.global_tstamp does NOT refresh on recirc (the frozen Defense-2 property), so the
 * recirc release_tick is the egress-refreshed hdr.bridge.tstamp_tick — the SAME clock the frozen
 * check_deadline compares. All exported ticks are global_tstamp[47:16] (65.536 us) in ONE free-running
 * timebase (ig-parser ticks for deadline/ack/first-arrival, egress-refreshed bridge tick for recirc
 * release) => directly subtractable. A negative E_D2 with release_reason==MAXPASS is the diagnostic
 * signature of a stuck recirc clock (the "MAX_PASS-not-deadline" pathology).
 * ---------------------------------------------------------------------------
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

// ---- TELEMETRY (measurement-only) constants — Track 1 learning-digest graft ----
// release_reason enum carried in the RESPONSE digest so a collector separates ALL FOUR release exits.
const bit<8> REL_TIMESTAMP_DEADLINE  = 8w1;   // normal: now_eff >= reg_deadline  (recirc RESP_RELEASED)
const bit<8> REL_FAIL_OPEN_MAXPASS   = 8w2;   // pass_count >= MAX_PASS           (recirc RESP_MAXPASS)
const bit<8> REL_AMBIGUITY_FAIL_OPEN = 8w3;   // first-arrival deadline-already-matured/stale immediate
                                              // release (RESP_RELEASE_NOW) — NOT a clean held-to-deadline
                                              // release (ambiguous: genuine-late vs stale/absent deadline)
const bit<8> REL_BYPASS              = 8w4;   // combined/ineligible frame forwarded unchanged (COMBINED_BYPASS)
// ig_dprsr_md.digest_type (bit<3>) selects which learn-digest struct the deparser packs (CONSTANT gate).
#define DIGEST_ACK  1
#define DIGEST_RESP 2

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
    // --- TELEMETRY (measurement-only; recirc-internal, stripped before Vision egress) ---
    bit<32> t_in;                 // response arrival tick (global_tstamp[47:16]) stamped at hold-enter (admit)
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
    // ---- TELEMETRY (measurement-only; NONE read by any release/fail-open/ambiguity/bypass/cleanup predicate) ----
    bit<8>  telem_on;       // A/B gate value, read once in the prologue
    bit<16> run_id;         // run epoch, read once in the prologue
    bit<32> d_tin;          // RESP digest: response arrival tick (bridge.t_in on recirc; now_tick first-arrival)
    bit<32> d_rel;          // RESP digest: release tick (bridge.tstamp_tick recirc; now_tick first-arrival)
    bit<32> d_pass;         // RESP digest: recirc pass_count at release (0 if never held)
    bit<8>  d_reason;       // RESP digest: release_reason (1 DEADLINE | 2 MAXPASS | 3 AMBIGUITY | 4 BYPASS)
    bit<32> d_txn;          // BOTH digests: tcp.ack_no (stable txn key = acknowledged request end-seq)
    bit<32> d_ack_tick;     // ACK  digest: pure-ACK arrival tick
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
 * TELEMETRY DIGESTS (measurement-only) — Track 1 learning-digest graft.
 * Two learn-digests, joined by the collector on (run_id, flow_id, txn_ack) — the Defense-1-verified
 * stable key: the pure ACK and its response acknowledge the SAME master request end-sequence, so both
 * carry the same tcp.ack_no. Both are well within the TNA learn-quantum (<= 48 B).
 *   PRIMARY METRIC   E_D2 = (RESP).release_tick - (ACK).deadline_tick   [ticks, one global timebase]
 *   on-chip hold        = (RESP).release_tick - (RESP).t_in
 *   internal recirc cost= (RESP).pass_count
 *============================================================================*/
struct d2_ack_dg_t {          // digest_type == DIGEST_ACK ; 128 bits / 16 B
    bit<16> run_id;
    bit<16> flow_id;
    bit<32> txn_ack;          // tcp.ack_no @ pure ACK = acknowledged request end-seq (join key)
    bit<32> deadline_tick;    // reg_deadline value = meta.deadline = ack_tick + G_i  (ACK-anchored)
    bit<32> ack_tick;         // pure-ACK arrival tick (global_tstamp[47:16]); G_i = deadline_tick - ack_tick
}
struct d2_resp_dg_t {         // digest_type == DIGEST_RESP ; 168 bits / 21 B
    bit<16> run_id;
    bit<16> flow_id;
    bit<32> txn_ack;          // tcp.ack_no @ release (same key as the ACK digest)
    bit<32> t_in;             // response arrival tick (@ admit / @ first-arrival)
    bit<32> release_tick;     // response release tick;  E_D2 = release_tick - (ACK).deadline_tick
    bit<32> pass_count;       // recirc laps at release (0 if not held)
    bit<8>  release_reason;   // 1 DEADLINE | 2 MAXPASS | 3 AMBIGUITY | 4 BYPASS
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
        meta.telem_on    = 0;
        meta.run_id      = 0;
        meta.d_tin       = 0;
        meta.d_rel       = 0;
        meta.d_pass      = 0;
        meta.d_reason    = 0;
        meta.d_txn       = 0;
        meta.d_ack_tick  = 0;
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
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_digest_emit;   // TELEM: digest records emitted (A/B-gated)

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

    // ---- TELEMETRY (measurement-only) registers — read ONCE each in the PROLOGUE (single call site,
    // side-effect-free, off the critical path; never touches a release/fail-open/bypass predicate). With
    // telemetry_enable[0]==0 (default) no digest_type is ever set => byte- and timing-identical to frozen. ----
    Register<bit<8>,  bit<1>>(1, 0) telemetry_enable;   // A/B gate, default 0
    RegisterAction<bit<8>, bit<1>, bit<8>>(telemetry_enable) telemetry_enable_read = {
        void apply(inout bit<8> v, out bit<8> rv) { rv = v; }
    };
    Register<bit<16>, bit<1>>(1, 0) run_id_reg;         // control-plane run epoch
    RegisterAction<bit<16>, bit<1>, bit<16>>(run_id_reg) run_id_read = {
        void apply(inout bit<16> v, out bit<16> rv) { rv = v; }
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
        meta.telem_on = telemetry_enable_read.execute(0);   // TELEM: A/B gate (single prologue call site)
        meta.run_id   = run_id_read.execute(0);             // TELEM: run epoch (single prologue call site)
        if (ig_intr_md.ingress_port == PORT_VISION) { meta.dir = 0; }
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
            ig_tm_md.ucast_egress_port = PORT_HULK;        // byte-identical, incl. TCP options
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
                // ===== TELEMETRY (measurement-only): ACK-side deadline digest =====
                // Exports the ACK-anchored deadline register-free from meta.deadline (already computed by
                // bounded_target above); the pure ACK is still FORWARDED UNCHANGED below. One-time ACK
                // event (NOT per-pass recirc work). Gates NOTHING; sets no packet byte.
                meta.d_txn      = hdr.tcp.ack_no;           // txn key = acknowledged request end-seq
                meta.d_ack_tick = meta.now_tick;            // pure-ACK arrival tick
                if (meta.telem_on == 1) {                   // A/B gate (prologue read)
                    ig_dprsr_md.digest_type = DIGEST_ACK;
                    ctr_digest_emit.count(0);
                }
            } else {
                events.count(EV_ACK_PASSTHRU);
            }
            ig_tm_md.ucast_egress_port = PORT_VISION;       // ACK ALWAYS forwarded now (no hold) — core Case B
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
                    // ===== TELEMETRY (measurement-only): stage the recirc-release digest BEFORE the frozen
                    // bridge-pop below. release_tick = the egress-refreshed hdr.bridge.tstamp_tick (the SAME
                    // fresh clock the frozen check_deadline uses on recirc). Pure PHV copies; gate NOTHING. =====
                    meta.d_tin  = hdr.bridge.t_in;
                    meta.d_rel  = hdr.bridge.tstamp_tick;
                    meta.d_pass = hdr.bridge.pass_count;
                    meta.d_txn  = hdr.tcp.ack_no;
                    if (alarm == 1) { meta.d_reason = REL_FAIL_OPEN_MAXPASS; }   // stuck-clock diagnostic
                    else            { meta.d_reason = REL_TIMESTAMP_DEADLINE; }  // clean deadline
                    if (meta.telem_on == 1) { ig_dprsr_md.digest_type = DIGEST_RESP; ctr_digest_emit.count(0); }
                    hdr.ethernet.ether_type = hdr.bridge.original_ethertype;   // restore 0x0800
                    hdr.bridge.setInvalid();                                   // POP bridge (byte-preserved)
                    held_dec.execute(0);                                       // release occupancy
                    ig_tm_md.ucast_egress_port = PORT_VISION;
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
                    ig_tm_md.ucast_egress_port = PORT_VISION;
                    events.count(EV_COMBINED_BYPASS);
                    // ===== TELEMETRY (measurement-only): BYPASS digest (combined/ineligible, never held) =====
                    meta.d_tin    = meta.now_tick;   // first-arrival: arrival tick (fresh ig clock)
                    meta.d_rel    = meta.now_tick;   // forwarded now (no hold) -> release_tick == arrival
                    meta.d_pass   = 0;
                    meta.d_txn    = hdr.tcp.ack_no;
                    meta.d_reason = REL_BYPASS;
                    if (meta.telem_on == 1) { ig_dprsr_md.digest_type = DIGEST_RESP; ctr_digest_emit.count(0); }
                } else if (meta.released == 1) {
                    // deadline already matured (t_resp_ready >= t_ACK + G_i) -> release NOW (max() lower arm)
                    ig_tm_md.ucast_egress_port = PORT_VISION;
                    events.count(EV_RESP_RELEASE_NOW);
                    // ===== TELEMETRY (measurement-only): AMBIGUITY digest — first-arrival deadline already
                    // matured/stale => immediate release, NOT a clean held-to-deadline release. =====
                    meta.d_tin    = meta.now_tick;
                    meta.d_rel    = meta.now_tick;   // released at arrival (no hold)
                    meta.d_pass   = 0;
                    meta.d_txn    = hdr.tcp.ack_no;
                    meta.d_reason = REL_AMBIGUITY_FAIL_OPEN;
                    if (meta.telem_on == 1) { ig_dprsr_md.digest_type = DIGEST_RESP; ctr_digest_emit.count(0); }
                } else {
                    // HOLD to the ACK-anchored deadline on the recirc loop
                    bit<8> over = held_check_inc.execute(0);   // occupancy arming gate (fail-open guard)
                    if (over == 1) {
                        ig_tm_md.ucast_egress_port = PORT_VISION;   // recirc saturated -> bypass
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
                        hdr.bridge.t_in               = meta.now_tick;   // TELEM: response arrival tick (measurement-only)
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
    Digest<d2_ack_dg_t>()  ack_digest;    // TELEM: emitted at qualified pure-ACK    (digest_type==DIGEST_ACK)
    Digest<d2_resp_dg_t>() resp_digest;   // TELEM: emitted at response release/exit  (digest_type==DIGEST_RESP)
    apply {
        // TELEM: one learn-digest per gated edge, each on a CONSTANT digest_type (TNA rule). A digest is a
        // control-plane metadata export, not a packet edit -> frames stay byte-clean. digest_type defaults 0
        // (no digest) and is set only when meta.telem_on==1, so telemetry is A/B-gated off by default.
        if (ig_dprsr_md.digest_type == DIGEST_ACK) {
            ack_digest.pack({meta.run_id, meta.flow_id, meta.d_txn, meta.deadline, meta.d_ack_tick});
        }
        if (ig_dprsr_md.digest_type == DIGEST_RESP) {
            resp_digest.pack({meta.run_id, meta.flow_id, meta.d_txn, meta.d_tin, meta.d_rel, meta.d_pass, meta.d_reason});
        }
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

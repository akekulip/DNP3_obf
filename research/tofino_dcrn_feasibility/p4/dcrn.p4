/*******************************************************************************
 * dcrn.p4  —  DNP3 Dual-Case Release-Time Normalizer (on-switch ACK-delay)
 *
 * Tofino 1 (TNA), BF-SDE 9.13.2, Hulk/Vision testbed (pipe 0):
 *   dp8 = Vision (master / run_master.py)   dp9 = Hulk (outstation / split_server.py)
 *   dp68 = pipe-0 internal recirculation port (self-clock hold loop)
 *
 * WHAT IT DOES (see research/tofino_dcrn_feasibility/ build spec + corrective.md):
 *   - ARM: on a payload-bearing master->outstation DNP3 READ (dp8, dst 20000, FC on
 *     allowlist) record t0 = global_tstamp tick, select a class-independent delay Di
 *     from the controller-installed BOUNDED table, store absolute deadline t0+Di.
 *   - CLASSIFY the reverse frame (dp9, src 20000): pure TCP ACK (payload_len==0) vs
 *     ACK-bearing DNP3 RESPONSE (payload_len>0).
 *   - HOLD to the absolute deadline via a self-clocked recirc loop on dp68; RELEASE to
 *     Vision when now >= deadline.  Dual-case FIFO: the separate-case response gets a
 *     common guard-delta so the pure ACK egresses first.
 *
 * BYTE-PRESERVATION (invariant): the recirc frame carries an internal dcrn_bridge_h
 *   (a proven internal-bridge encap/decap geometry). It is PUSHED on hold-enter and POPPED before the
 *   dp8->Vision egress, so the frame reaching Vision is IP-and-above bit-identical to the
 *   native response. No DNP3/TCP/IP field edit, no CRC recompute, NO Checksum() extern.
 *   The REQUEST is forwarded to Hulk bit-identical INCLUDING its TCP options.
 *
 * FAIL-OPEN (invariant): every guard forwards, never drops, never holds past the RTO cap.
 *   RTO cap = controller guarantees every installed Di <= rto_cap_ticks (zero dataplane
 *   cost). Watermark, max-pass, policy-absent, unarmed-flow all resolve to immediate
 *   forward. drop() is used ONLY for malformed L2, never for a DNP3 frame.
 *
 * ---------------------------------------------------------------------------------------
 * UNCOMPILED semantics-fit note — the M1 bf-p4c compile drives an iterative fit loop.
 *
 *   FIXED (wire correctness): request-path TCP options are EXTRACTED into fixed per-
 *     data_offset headers (tcp_opt4_h..tcp_opt40_h) and re-emitted by the deparser (exactly
 *     one valid) so the request forwards byte-identical. Do NOT pkt.advance() over them
 *     (advanced bytes are lost). Constant-extract ladder = a proven constant-advance pad-ladder; a
 *     runtime varbit extract is what a reference DNP3 parser's "Tofino 1 requires constant advance
 *     amounts" warns
 *     against. Response path stops at TCP -> its options+payload ride as byte-preserved
 *     residual (a zero-payload pure ACK never short-extracts).
 *
 *   FIXED (action-data operand): payload_len = total_len - overhead is done as an ADD of the
 *     NEGATED overhead (total_len + (0x10000 - overhead)); Tofino forbids action data as the
 *     SECOND operand of a subtraction. set_deadline's `now_tick + Di` is an ADD with an
 *     action-data addend (allowed). All SALU bodies and the now_eff/pass_count arithmetic use
 *     CONSTANT second operands only (GUARD_TICKS, 1).
 *
 *   FIXED (fit: 17-deep dependency chain > 12 MAU stages): the apply block was a nested
 *     if/return cascade that serialized the mutually-exclusive recirc / request / response
 *     paths into one 17-long control chain, and reg_deadline was accessed 3x. Restructured:
 *       (a) mutually-exclusive if / else-if / else (no early `return` -> no hasReturned
 *           serialization; the fitter overlaps the exclusive branches in the same stages);
 *       (b) an unconditional PROLOGUE computes now_tick, dir, payload_len, flow_id ONCE, in
 *           parallel, shared by all paths (flow_id's canonical key is identical for request,
 *           response, AND recirc frame, so the recirc path re-derives it -> flow_id no longer
 *           carried in the bridge);
 *       (c) a SINGLE check_deadline call site serves BOTH recirc and first-arrival response
 *           -> reg_deadline down to 2 accesses (arm write + check read), mutually exclusive;
 *       (d) store_t0 / reg_req_tstamp (telemetry only) DROPPED;
 *       (e) next_txn + bounded_target no longer gated by fc_ok (only the arm_deadline WRITE
 *           is) -> the arm chain is next_txn -> bounded_target -> arm_deadline, ~3 deep, with
 *           fc_allowlist parallel. Semantic note: the txn counter advances on every payload-
 *           bearing dst:20000 request even if its FC is non-allowlisted; the BOUNDED walk stays
 *           deterministic and device-independent, and in the READ-only rig campaign every
 *           request is allowlisted so the sequences are identical;
 *       (f) one indexed events Counter replaces the six per-branch counters.
 *     MEASURED ingress depth (bf-p4c 9.13.1, 2026-07-20): 9 of 12 stages, 0 errors — fits the wall
 *     with 3 stages headroom (the earlier ~5-7 estimate was optimistic; 9 is the real number).
 *     Evidence: M1_local_compile_result.md + build_local_9.13.1/logs/. On-switch 9.13.2 = final confirm.
 *
 *   REMAINING semantic-fit risk (the one shape not proven in lab code):
 *     check_deadline compares a runtime PHV operand (meta.now_eff) against the stored register
 *     word. Lab SALUs only compare against constants (reference SALUs use e.g. `val > 4`). If it will not
 *     lower, fall back to the constant-biased two-RegisterAction form or the pass-count
 *     self-clock (build spec Part 4/10). Not a compile item: global_tstamp refresh-on-recirc
 *     is an M2 hardware probe.
 *
 * Grounding: every construct below is adapted from working, compiled P4 already running on this
 *   shared switch — DNP3 parse / overhead-table / Hash, Register / RegisterAction / constructor-seed
 *   / runtime-index, and recirc-hold / bridge encap-decap / carried-header ladder / counters — so the
 *   patterns are proven on this silicon, not invented here.
 * Author: Philip
 ******************************************************************************/

#include <core.p4>
#include <tna.p4>

/*==============================================================================
 * CONSTANTS
 *============================================================================*/

const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<16> ETHERTYPE_DCRN = 0x88B6;   // private recirc-bridge ethertype (0x88B5 is taken by a co-resident program — avoid)
const bit<8>  IP_PROTO_TCP    = 6;
const bit<16> DNP3_PORT       = 20000;
const bit<8>  DNP3_START_0     = 0x05;
const bit<8>  DNP3_START_1     = 0x64;

const PortId_t PORT_VISION = 9w8;    // master
const PortId_t PORT_HULK   = 9w9;    // outstation / split_server.py replay
const PortId_t PORT_RECIRC = 9w68;   // pipe-0 internal recirc port (self-clock)
const QueueId_t QID_HOLD   = 5;      // dp68 shaped hold queue — max_rate shaper here paces the recirc loop

// tick = global_tstamp[47:16] = 65.536 us. GUARD >= one recirc pass and >= host ~0.19 ms.
const bit<32> GUARD_TICKS = 32w4;      // ~0.26 ms
const bit<32> MAX_PASS    = 32w65536;  // hard loop cap (=2^16) -> fail-open release. Power of 2 so the
                                       // compare reduces to a cheap high-bits gateway check. At bare-speed
                                       // recirc (~0.72 us/pass) that is ~47 ms, ABOVE the 33 ms deadline,
                                       // so the deadline governs release IF global_tstamp refreshes on
                                       // recirc; else the cap fail-opens at ~47 ms (disambiguates Q1).
const bit<32> HELD_MAX    = 32w256;    // recirc-occupancy watermark -> new responses bypass

// event-counter indices (one indexed Counter instead of six)
const bit<8> EV_PASSTHRU = 0;
const bit<8> EV_ARMED    = 1;
const bit<8> EV_HELD     = 2;
const bit<8> EV_RELEASED = 3;
const bit<8> EV_MISS     = 4;
const bit<8> EV_BYPASS   = 5;

/*==============================================================================
 * HEADERS
 *============================================================================*/

header ethernet_h {
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16> ether_type;
}

// Internal recirc-only bridge (NEVER reaches Vision). Pushed on hold-enter, popped on
// release. Mirrors a proven internal-bridge encap/decap role. flow_id is NOT carried — the
// prologue re-derives the identical canonical key for a recirc frame.
header dcrn_bridge_h {
    bit<16> original_ethertype;   // 0x0800, restored on release
    bit<32> pass_count;           // recirc laps (max-pass fail-open guard) — 32-bit so a power-of-2
                                  // cap (2^16) reduces to a cheap high-bits gateway check
    bit<8>  guard_apply;          // 1 = separate-case response (subtract GUARD); else 0  (Class 3: byte-wide)
    bit<8>  pad_;
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

// TCP options carried verbatim on the REQUEST path so the request forwards byte-identical.
// One fixed-size header per data_offset (options length = (data_offset-5)*4 bytes); exactly
// one is valid per request. NEVER read in the MAU — extracted only to be re-emitted.
header tcp_opt4_h  { bit<32>  data; }   // data_offset 6  (4 B)
header tcp_opt8_h  { bit<64>  data; }   // data_offset 7  (8 B)
header tcp_opt12_h { bit<96>  data; }   // data_offset 8  (12 B) — Linux timestamps, the common case
header tcp_opt16_h { bit<128> data; }   // data_offset 9  (16 B)
header tcp_opt20_h { bit<160> data; }   // data_offset 10 (20 B)
header tcp_opt24_h { bit<192> data; }   // data_offset 11 (24 B)
header tcp_opt28_h { bit<224> data; }   // data_offset 12 (28 B)
header tcp_opt32_h { bit<256> data; }   // data_offset 13 (32 B)
header tcp_opt36_h { bit<288> data; }   // data_offset 14 (36 B)
header tcp_opt40_h { bit<320> data; }   // data_offset 15 (40 B)

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
    bit<32> now_eff;        // now_tick, or now_tick - GUARD_TICKS for separate-case responses
    bit<8>  bkt_idx;        // bounded_target index (low 8 bits of txn counter)
    bit<32> deadline;       // now_tick + Di  (single-stage add)
    bit<8>  fc_ok;          // FC on allowlist
    bit<8>  released;       // deadline compare result
    bit<8>  guard_apply;    // staged into the bridge on hold-enter
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
 * INGRESS PARSER
 *============================================================================*/

parser DcrnIngressParser(
        packet_in pkt,
        out headers_t hdr,
        out metadata_t meta,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        // initialize every metadata field (no uninitialized reads) — standard TNA idiom
        meta.dir         = 0;
        meta.payload_len = 0;
        meta.flow_id     = 0;
        meta.now_tick    = 0;
        meta.now_eff     = 0;
        meta.bkt_idx     = 0;
        meta.deadline    = 0;
        meta.fc_ok       = 0;
        meta.released    = 0;
        meta.guard_apply = 0;
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

    // decap pattern: peel the internal bridge, then parse the carried frame.
    state parse_bridge {
        pkt.extract(hdr.bridge);
        transition parse_ipv4;
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.ihl) {
            4w5    : parse_tcp;               // only no-option IPv4 (matches the reference parsers)
            default: accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        // Parse DNP3 ONLY for requests (dst 20000, non-SYN). Responses/pure-ACKs (src 20000)
        // and recirc frames fall to accept -> options+DNP3 payload stay as byte-preserved
        // residual, and a zero-payload pure ACK never short-extracts. (reference-parser gate)
        transition select(hdr.tcp.dst_port, hdr.tcp.flags[1:1]) {
            (DNP3_PORT, 1w0) : parse_tcp_options;
            default          : accept;
        }
    }

    // Carry the TCP options (do NOT advance). One fixed-size header per data_offset; exactly
    // one becomes valid, re-emitted by the deparser so the request forwards byte-identical.
    state parse_tcp_options {
        transition select(hdr.tcp.data_offset) {
            5  : parse_dnp3_dl;      // no options
            6  : opt4;
            7  : opt8;
            8  : opt12;              // Linux TCP timestamps — the common run_master.py case
            9  : opt16;
            10 : opt20;
            11 : opt24;
            12 : opt28;
            13 : opt32;
            14 : opt36;
            15 : opt40;
            default : accept;        // impossible data_offset -> stop; frame stays intact as residual
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
            default                      : accept;   // not DNP3 -> leave residual
        }
    }
    state parse_dnp3_tp  { pkt.extract(hdr.dnp3_tp);  transition parse_dnp3_app; }
    state parse_dnp3_app { pkt.extract(hdr.dnp3_app); transition accept; }   // FC at fixed offset; body is residual
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

    // used ONLY for malformed L2 — never for a DNP3 frame (fail-open)
    action drop() { ig_dprsr_md.drop_ctl = 1; }

    // one indexed telemetry counter (leaf; not on the dependency chain)
    Counter<bit<64>, bit<8>>(16, CounterType_t.PACKETS) events;

    // ---- flow-key hash: ONE instance, ONE tuple shape (Class 7) ----   (single-hash idiom)
    Hash<bit<16>>(HashAlgorithm_t.CRC16) flow_hash;

    // ---- registers (constructor-seeded to 0; Class 8 dodged: never an in-SALU ==0 sentinel) ----
    Register<bit<32>, bit<16>>(65536, 0) reg_deadline;    // absolute deadline tick per flow (0 = unarmed/past -> release now)
    Register<bit<8>,  bit<16>>(65536, 0) reg_ack_seen;    // separate-case: pure ACK observed for this flow
    Register<bit<32>, bit<1>>(1, 0)      reg_txn;         // global transaction counter -> BOUNDED index
    Register<bit<32>, bit<1>>(1, 0)      reg_held_count;  // global recirc-occupancy watermark

    // ARM: write absolute deadline (meta.deadline = now_tick + Di precomputed in set_deadline).
    RegisterAction<bit<32>, bit<16>, bit<32>>(reg_deadline) arm_deadline = {
        void apply(inout bit<32> dl, out bit<32> rv) { dl = meta.deadline; rv = dl; }
    };
    // DEADLINE COMPARE (read + predicate): compares runtime PHV operand meta.now_eff against the
    // stored word — the one SALU shape not seen in lab code. LOWERED CLEANLY on bf-p4c 9.13.1
    // (M1, 2026-07-20, 0 errors) -> constant-biased fallback not needed; 9.13.2 is the final confirm.
    RegisterAction<bit<32>, bit<16>, bit<8>>(reg_deadline) check_deadline = {
        void apply(inout bit<32> dl, out bit<8> released) {
            if (meta.now_eff >= dl) { released = 1; }
            else                    { released = 0; }
        }
    };
    RegisterAction<bit<8>, bit<16>, bit<8>>(reg_ack_seen) set_ack_seen = {
        void apply(inout bit<8> v, out bit<8> rv) { v = 1; rv = 1; }
    };
    RegisterAction<bit<8>, bit<16>, bit<8>>(reg_ack_seen) get_ack_seen = {
        void apply(inout bit<8> v, out bit<8> rv) { rv = v; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_txn) next_txn = {
        void apply(inout bit<32> v, out bit<32> rv) { v = v + 1; rv = v; }
    };
    // watermark: check-and-increment atomically (increments only if under cap).
    RegisterAction<bit<32>, bit<1>, bit<8>>(reg_held_count) held_check_inc = {
        void apply(inout bit<32> v, out bit<8> over) {
            if (v >= HELD_MAX) { over = 1; }
            else               { v = v + 1; over = 0; }
        }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_held_count) held_dec = {
        void apply(inout bit<32> v, out bit<32> rv) { if (v > 0) { v = v - 1; } rv = v; }
    };

    // ---- payload-length overhead table ----
    // Tofino forbids action data as the SECOND operand of a subtraction, so compute
    // payload_len = total_len - overhead as an ADD of the NEGATED overhead (16-bit two's
    // complement): payload_len = total_len + (0x10000 - overhead). Action-data ADDEND is ok.
    action set_overhead(bit<16> neg_ov) { meta.payload_len = hdr.ipv4.total_len + neg_ov; }
    table tcp_overhead {
        key     = { hdr.tcp.data_offset : exact; }
        actions = { set_overhead; }
        const entries = {
            (4w5)  : set_overhead(16w0xFFD8);   // -40  (IP20 + TCP20, no options)
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

    // ---- FC allowlist: controller installs READ (0x01) only initially; miss -> bypass ----
    action fc_allow() { meta.fc_ok = 1; }
    table fc_allowlist {
        key     = { hdr.dnp3_app.func_code : exact; }
        actions = { fc_allow; NoAction; }
        default_action = NoAction();          // not allowlisted -> fc_ok stays 0 -> no arm (fail-open)
        size = 32;
    }

    // ---- BOUNDED distribution: controller pre-samples 256 Di (deterministic seed), installs ----
    // set_deadline folds t0 + Di: Di = action data (per-entry const) -> single-stage add (Class 5)
    action set_deadline(bit<32> di) { meta.deadline = meta.now_tick + di; }
    table bounded_target {
        key     = { meta.bkt_idx : exact; }
        actions = { set_deadline; }
        default_action = set_deadline(32w0);   // policy-absent -> deadline in the past -> immediate release
        size = 256;
    }

    apply {
        // ===== UNCONDITIONAL PROLOGUE (parallel; shared by every path) =====
        meta.now_tick = ig_prsr_md.global_tstamp[47:16];   // [tna.p4] refresh-on-recirc is M2 probe (a)
        if (ig_intr_md.ingress_port == PORT_VISION) { meta.dir = 0; }
        else                                        { meta.dir = 1; }   // dp9 or dp68; dp10/11 never enabled

        tcp_overhead.apply();                              // meta.payload_len (leaf for non-DNP3)

        // canonical bidirectional flow key (server = the :20000 side). IDENTICAL for the
        // request, the response, AND the recirc frame -> one hash, no per-path resolution.
        bit<32> client_ip;
        bit<16> client_port;
        bit<32> server_ip;
        if (meta.dir == 0) {
            client_ip = hdr.ipv4.src_addr; client_port = hdr.tcp.src_port; server_ip = hdr.ipv4.dst_addr;
        } else {
            client_ip = hdr.ipv4.dst_addr; client_port = hdr.tcp.dst_port; server_ip = hdr.ipv4.src_addr;
        }
        meta.flow_id = flow_hash.get({ client_ip, server_ip, client_port });   // ONE tuple shape (Class 7)

        // ===== MUTUALLY-EXCLUSIVE PATHS (if / else-if / else — no early return) =====
        if (!hdr.ethernet.isValid()) {
            drop();
        }
        else if (hdr.tcp.isValid() && hdr.tcp.dst_port == DNP3_PORT && meta.payload_len > 0
                 && hdr.dnp3_app.isValid() && meta.dir == 0) {
            // ---------- ARM (request, dp8) — forwarded UNCHANGED to Hulk ----------
            bit<32> txn  = next_txn.execute(0);            // walk the BOUNDED distribution
            meta.bkt_idx = txn[7:0];
            bounded_target.apply();                        // meta.deadline = now_tick + Di
            fc_allowlist.apply();                          // meta.fc_ok (parallel to next_txn/bounded_target)
            if (meta.fc_ok == 1) {
                arm_deadline.execute(meta.flow_id);        // reg_deadline write (gated by FC)
                events.count(EV_ARMED);
            } else {
                events.count(EV_BYPASS);
            }
            ig_tm_md.ucast_egress_port = PORT_HULK;        // byte-identical, incl. TCP options
        }
        else if (hdr.bridge.isValid() ||
                 (hdr.tcp.isValid() && hdr.tcp.src_port == DNP3_PORT && meta.dir == 1)) {
            // ---------- HOLD / RELEASE (recirc frames + first-arrival responses/ACKs) ----------
            bit<8> is_recirc = 0;
            if (hdr.bridge.isValid()) { is_recirc = 1; }

            // resolve guard_apply per path (recirc: carried; response: from ack_seen)
            if (is_recirc == 1) {
                meta.guard_apply = hdr.bridge.guard_apply;
            } else if (meta.payload_len == 0) {
                set_ack_seen.execute(meta.flow_id);        // pure ACK (separate): record, hold to T
                meta.guard_apply = 0;
            } else {
                bit<8> seen = get_ack_seen.execute(meta.flow_id);   // response: separate? -> guard
                if (seen == 1) { meta.guard_apply = 1; }
                else           { meta.guard_apply = 0; }
            }

            // shared guard bias + THE single deadline compare
            if (meta.guard_apply == 1) { meta.now_eff = meta.now_tick - GUARD_TICKS; }
            else                       { meta.now_eff = meta.now_tick; }
            meta.released = check_deadline.execute(meta.flow_id);

            if (is_recirc == 1) {
                // recirc frame: release when now>=deadline OR max-pass, else keep looping
                hdr.bridge.pass_count = hdr.bridge.pass_count + 1;
                // split the OR into two simple gateways (Class 1: a 16-bit magnitude compare + the
                // released predicate in one gateway exceeds the 44-bit gateway input limit).
                bit<8> do_release = meta.released;
                if (hdr.bridge.pass_count >= MAX_PASS) { do_release = 1; }   // fail-open cap
                if (do_release == 1) {
                    hdr.ethernet.ether_type = hdr.bridge.original_ethertype;   // restore + pop
                    hdr.bridge.setInvalid();
                    held_dec.execute(0);
                    ig_tm_md.ucast_egress_port = PORT_VISION;
                    events.count(EV_RELEASED);
                } else {
                    ig_tm_md.ucast_egress_port = PORT_RECIRC;
                    ig_tm_md.qid               = QID_HOLD;   // shaped queue -> shaper paces the loop
                }
            } else {
                // first-arrival response / pure ACK
                if (meta.released == 1) {
                    // deadline already passed OR unarmed (deadline seeded 0) -> release now (no held change)
                    ig_tm_md.ucast_egress_port = PORT_VISION;
                    events.count(EV_MISS);
                } else {
                    bit<8> over = held_check_inc.execute(0);   // increments only if under cap
                    if (over == 1) {
                        ig_tm_md.ucast_egress_port = PORT_VISION;   // recirc saturated -> bypass
                        events.count(EV_BYPASS);
                    } else {
                        hdr.bridge.setValid();
                        hdr.bridge.original_ethertype = hdr.ethernet.ether_type;   // 0x0800
                        hdr.bridge.pass_count         = 0;
                        hdr.bridge.guard_apply        = meta.guard_apply;
                        hdr.bridge.pad_               = 0;
                        hdr.ethernet.ether_type       = ETHERTYPE_DCRN;            // 0x88B6 (recirc-only)
                        ig_tm_md.ucast_egress_port    = PORT_RECIRC;
                        ig_tm_md.qid                  = QID_HOLD;                   // shaped queue
                        events.count(EV_HELD);
                    }
                }
            }
        }
        else {
            // ---------- transparent bump-in-the-wire (ARP / ICMP / non-DNP3 / handshake ACK) ----------
            if (meta.dir == 0) { ig_tm_md.ucast_egress_port = PORT_HULK; }
            else               { ig_tm_md.ucast_egress_port = PORT_VISION; }
            events.count(EV_PASSTHRU);
        }
    }
}

/*==============================================================================
 * INGRESS DEPARSER  (emit all headers; NO Checksum extern — we modify no IP/TCP/DNP3 byte)
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
        // carried TCP options — exactly one valid on a request; none on responses/recirc
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
        pkt.emit(hdr.dnp3_dl);     // valid on the request path only
        pkt.emit(hdr.dnp3_tp);
        pkt.emit(hdr.dnp3_app);
    }
}

/*==============================================================================
 * EGRESS — pure pass-through (minimal egress: unparsed body carries)
 *============================================================================*/

struct eg_headers_t  { ethernet_h ethernet; }
struct eg_metadata_t { bit<8> unused_; }

parser DcrnEgressParser(
        packet_in pkt,
        out eg_headers_t hdr,
        out eg_metadata_t meta,
        out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        pkt.extract(eg_intr_md);
        meta.unused_ = 0;
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
    apply { }
}

control DcrnEgressDeparser(
        packet_out pkt,
        inout eg_headers_t hdr,
        in eg_metadata_t meta,
        in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {
    apply { }
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

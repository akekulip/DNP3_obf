/* ============================================================================
 * dnp3_timing_normalizer.p4 — THE CANONICAL TIMING-ONLY REFERENCE for the meeting
 *                 deliverable. It is p12_combined.p4 with (a) the egress size
 *                 normalization removed and replaced by a byte-preserving
 *                 pass-through, and (b) a G-selection guard added that measures the
 *                 native CLRT of each response and records whether the configured
 *                 guard interval G actually applied any hold.
 *                 (Tofino 1, TNA, bf-p4c 9.13.1, compile-only, never loaded)
 *
 * PROVENANCE (nothing here is invented):
 *   - INGRESS is p12_combined.p4's ingress, VERBATIM: parser DNP3 classification,
 *     packed transaction state (reg_tag = generation+active, armed-bit in the low
 *     byte of reg_deadline), HOLD_RESPONSE deadline logic, blocker reservoir,
 *     pass-budget fail-open, internal-token isolation (0x88C1 forced to ROLE_BLOCK),
 *     data_offset 5-15 classification. The timing mechanism is UNCHANGED except for one
 *     deliberate correctness fix (finding B-D1): the deadline and its shadow t_ack are
 *     now armed/captured on the FIRST qualifying ACK and are idempotent to duplicate
 *     ACKs (see reg_deadline / reg_t_ack below). No other behavior changes.
 *   - EGRESS is ibspg_dnp3.p4's egress, VERBATIM: a byte-preserving pass-through
 *     (extract only ethernet; the rest is residual and re-emitted automatically), so
 *     a released ACK or RESPONSE (bypass_egress=0) egresses byte-identical.
 *   - The G-SELECTION GUARD is the only new logic, and it is ADDITIVE to the ingress
 *     (new registers/tables/counters; no existing register, table, action, gateway,
 *     counter, or metadata field of the timing mechanism is changed).
 *
 * WHAT WAS REMOVED vs p12_combined.p4 (all EGRESS-only, out of scope this week and a
 * corruption hazard):
 *   - the pay.. and pad.. payload-chunk headers and the eg_headers_t that held them,
 *   - the EgParser payload-chunking + total_len select,
 *   - the size_norm table and its 14 pad_* actions,
 *   - ctr_size_normalized / ctr_size_failopen and the meta.normalized logic,
 *   - the pad emission in EgDeparser.
 *   None of these touched any ingress construct, so removing them cannot change the
 *   ingress stage count; it only shrinks the egress.
 *
 * WHAT WAS ADDED — the G-selection guard (directive §3). The mechanism already does
 * zero-hold when the native CLRT is >= G (if the response arrives after the deadline,
 * the blockers have already terminated so Q_RESP is not starved). Rather than let
 * that pass silently as though normalization happened, the guard DETECTS and COUNTS
 * it. At the point a fresh RESPONSE from the outstation (dir OUT) is admitted and
 * enqueued to Q_RESP, using values already present in the pipeline:
 *       native_clrt      = t_response_arrival - t_ack           (reg_native_clrt, 32b ns)
 *       clrt_diff        = native_clrt - G                      (sign bit = the decision)
 *       protection       = 1 iff native_clrt <  G  (a hold WAS applied)  (reg_protection)
 *                        = 0 iff native_clrt >= G  (zero hold; G too low, low_G_warning)
 *   Semantics (directive §3): if native_clrt <  G  -> effective_hold = G - native_clrt,
 *   protection_applied = true; else effective_hold = 0, protection_applied = false and
 *   low_G_warning = true.
 *
 * TWO INDEPENDENT COMPARES (deliberate cross-check for the meeting deliverable —
 * they are mathematically equal because deadline = t_ack + G, so
 * now >= deadline  <=>  native_clrt >= G):
 *   (1) now vs deadline — reuses the EXISTING deadline sign-bit ternary (meta.expired
 *       from tbl_deadline_expiry, already computed for every packet including this
 *       response). Drives ctr_response_before_deadline / _at_or_after_deadline.
 *   (2) native_clrt vs G — a fresh sign-bit ternary (tbl_clrt_guard on clrt_diff),
 *       computed FROM the measured native_clrt for the readout register and flag.
 *       Drives ctr_response_actually_held / _zero_hold. NO bit-slice is used
 *       anywhere: the sign bit is tested by a ternary TCAM mask (0x80000000), exactly
 *       as the deadline expiry tests 0x800000FF — a slice of a 32-bit arithmetic
 *       field in a gateway/assignment breaks PHV allocation (measured on 9.13.1).
 * If run (1) and run (2) ever disagree the guard is inconsistent — that is the point
 * of keeping both.
 *
 * WHY t_ack COMES FROM A DEDICATED SHADOW REGISTER (reg_t_ack). The existing
 * reg_ts_ack_arm (write-if-zero) is part of the frozen timing mechanism and is left
 * untouched. reg_t_ack is a NEW register that returns `now - v` (= native_clrt when v
 * holds t_ack). To measure the native CLRT from the FIRST ACK (finding B-D1), t_ack is
 * captured with FIRST-ACK idempotency, mirroring the deadline: the ARM resets it to 0
 * (t_ack_reset), the first qualifying ACK captures ts32 only while v == 0
 * (t_ack_capture), a duplicate ACK leaves it, and every other packet reads it
 * (t_ack_read). The three RegisterActions are mutually exclusive (one access per
 * packet); each is the "rv = phv - v [, conditional write]" shape with ts32 as the only
 * PHV input, so no new constraint class.
 *
 * RELEASE-CAUSE COUNTERS (directive §3). ctr_release_deadline / ctr_release_fail_open
 * are added at the EXISTING response-release site (the dequeued ROLE_RESP branch),
 * attributed by the already-computed meta.expired of the dequeued response: if the
 * deadline has passed by the time the response is dequeued (Q_BLOCK drained on the
 * deadline) it was released by the deadline; otherwise the blockers drained early on
 * their pass budget (fail-open). This is a clean 1:1-with-release attribution, which
 * the per-blocker ctr_block_term_* counters (K increments per drain) are not — so
 * these two are ADDED rather than derived from ctr_block_term_deadline/_timeout,
 * which remain available for the per-token view.
 *
 * SAFETY PROPERTIES — each one, and where it lives in this file (all carried from
 * p12_combined UNCHANGED by the guard):
 *   generation safety      : reg_tag holds the generation; the blocker decode entry
 *                            (CLASS_BLOCK_DEQ, 0x00 &&& 0xFF) fires only on an exact
 *                            tag match, so only a token of the CURRENT generation is
 *                            ever tag_ok. The ACK path keeps out of this (JOIN B).
 *   pass-budget fail-open  : meta.budget_zero -> TAG_INACTIVE at the tag write and
 *                            ctr_block_term_timeout at the act; every later token then
 *                            reads a stale tag and terminates.
 *   blocker isolation      : ethertype 0x88C1 is FORCED to ROLE_BLOCK in the parser,
 *                            so a token can only reach to_block() or drop_pkt(), never
 *                            a host port.
 *   byte preservation      : no MAU action reads or writes any byte of any host frame
 *                            in ingress OR egress. The single field written anywhere
 *                            is hdr.ib.seq, the internal token's own pass counter.
 *                            Ingress emits in extraction order; egress extracts only
 *                            ethernet and re-emits the rest as residual.
 *
 * NOT CLAIMED: nothing here has been loaded or run. This file answers a compile-fit
 * question only.
 * ==========================================================================*/
#include <core.p4>
#include <tna.p4>

/* ---- ethertypes ---- */
const bit<16> ETHERTYPE_IBSPG_TOKEN = 0x88C1;  /* BLOCK(1) private marker, internal only */
const bit<16> ETHERTYPE_IPV4        = 0x0800;
const bit<8>  IP_PROTO_TCP          = 8w6;

/* ---- DNP3 ---- */
const bit<16> DNP3_START       = 0x0564;   /* link-layer start magic                      */
const bit<8>  DNP3_FC_READ     = 8w1;      /* master -> outstation : arms the transaction */
const bit<8>  DNP3_FC_RESPONSE = 8w129;    /* outstation -> master : the held frame       */

/* ---- roles ---- */
const bit<8> ROLE_BYPASS = 0;  /* forwarded unchanged, never held, never arms        */
const bit<8> ROLE_BLOCK  = 1;  /* 0x88C1 : enqueue Q_BLOCK (qid7); deadline-checking  */
const bit<8> ROLE_RESP   = 2;  /* DNP3 RESPONSE : enqueue Q_RESP (qid1); released     */
const bit<8> ROLE_ARM    = 6;  /* DNP3 READ     : takes the tag, clears the deadline  */
const bit<8> ROLE_ACK    = 7;  /* pure TCP ACK  : forwarded NOW; arms the deadline    */

/* ---- direction ---- */
const bit<8> DIR_MASTER = 0;   /* arrived from the master side (dp9)                  */
const bit<8> DIR_OUT    = 1;   /* arrived from the outstation side (dp11) or loopback */

/* ---- ports ---- */
const PortId_t PORT_L      = 9w8;   /* internal loopback L (dev_port 8, pipe 0)           */
const PortId_t PORT_VISION = 9w9;   /* master side (dp9)                                  */
const PortId_t PORT_HULK   = 9w11;  /* outstation side (dp11)                             */

/* ---- queues on PORT_L ---- */
const bit<5> QID_BLOCK = 5w7;   /* HIGH (max_priority=7) : blocker reservoir   */
const bit<5> QID_RESP  = 5w1;   /* LOW  (max_priority=0) : response held queue */

/* ---- packed-state constants (piece 2) ---- */
const bit<32> TICK_MASK    = 32w0xFFFFFF00;  /* keep 24 tick bits, clear the marker byte */
const bit<32> ARMED_MARK   = 32w0x00000001;  /* bit 0 of the deadline word = armed       */
const bit<32> UNARMED_WORD = 32w0x00000002;  /* explicit "armed nothing" (marker clear)  */
const bit<32> DL_NO_WRITE  = 32w0;           /* SALU sentinel: leave the deadline be     */
const bit<8>  TAG_INACTIVE = 8w0xFF;         /* explicit "no transaction"                */
const bit<8>  TAG_NO_WRITE = 8w0;            /* SALU sentinel: leave the tag be          */

/* Guard interval G, ALREADY EXPRESSED IN 256 ns TICKS (low byte MUST be zero — see
 * JOIN C). 0x017D7800 = 24 999 936 ns = 25 ms rounded down to one tick, which sits
 * above the SEL-751 corpus CLRT p95 of 16.5 ms (median 12.9 ms). The control plane
 * rewrites tbl_guard's default action parameter for a G sweep — no recompile. */
const bit<32> G_DEFAULT_TICKS = 32w0x017D7800;

/* ---- packet classes (drive the one decode table) ---- */
const bit<8> CLASS_OTHER     = 8w0;
const bit<8> CLASS_ARM       = 8w1;   /* fresh DNP3 READ from the master     */
const bit<8> CLASS_ACK       = 8w2;   /* fresh pure TCP ACK from outstation  */
const bit<8> CLASS_BLOCK_DEQ = 8w3;   /* blocker token back from loopback    */

/* ============================ headers ==================================== */
header ethernet_h { bit<48> dst; bit<48> src; bit<16> etype; }

/* internal blocker token: seq = pass budget, gen = transaction generation.
 * role/slot are kept for wire compatibility with the Part 9/11/12 injector but are
 * NOT read — an 0x88C1 frame is FORCED to ROLE_BLOCK in the parser. */
header ibspg_h { bit<8> role; bit<8> slot; bit<8> gen; bit<32> seq; }

header ipv4_h {
    bit<4>  version; bit<4>  ihl;      bit<8>  diffserv;    bit<16> total_len;
    bit<16> identification; bit<3> flags; bit<13> frag_offset;
    bit<8>  ttl;     bit<8>  protocol; bit<16> hdr_checksum;
    bit<32> src_addr; bit<32> dst_addr;
}

header tcp_h {
    bit<16> src_port; bit<16> dst_port; bit<32> seq_no; bit<32> ack_no;
    bit<4>  data_offset; bit<4> res; bit<8> flags;
    bit<16> window; bit<16> checksum; bit<16> urgent_ptr;
}

/* TCP options carried verbatim; one fixed-size header per data_offset (the TNA
 * parser cannot advance by a runtime amount). NEVER read in the MAU. */
header tcp_opt4_h  { bit<32> data; }
header tcp_opt8_h  { bit<64> data; }
header tcp_opt12_h { bit<96> data; }

/* DNP3 data-link header, 10 B. `start` is the two magic bytes as ONE 16-bit field so
 * the magic and the LEN gate fit one 16-bit + one 8-bit parser match register in a
 * single select. */
header dnp3_dl_h {
    bit<16> start; bit<8> length; bit<8> ctrl;
    bit<16> dst_addr; bit<16> src_addr; bit<16> crc;
}
header dnp3_tp_h  { bit<8> tp_ctrl; }                      /* transport header, 1 B */
header dnp3_app_h { bit<8> app_control; bit<8> func_code; } /* classification only   */

struct headers_t {
    ethernet_h  eth;
    ibspg_h     ib;
    ipv4_h      ipv4;
    tcp_h       tcp;
    tcp_opt4_h  tcp_opt4;
    tcp_opt8_h  tcp_opt8;
    tcp_opt12_h tcp_opt12;
    dnp3_dl_h   dnp3_dl;
    dnp3_tp_h   dnp3_tp;
    dnp3_app_h  dnp3_app;
}

struct ig_meta_t {
    /* ---- piece 1: parser-computed classification ---- */
    bit<8>  role;          /* ROLE_*                                              */
    bit<8>  dir;           /* DIR_MASTER / DIR_OUT                                */
    bit<9>  fwd_port;      /* transparent-forward peer port for this ingress port */
    bit<8>  port_ok;       /* 1 if the ingress port is dp8 / dp9 / dp11           */
    bit<8>  gen_in;        /* generation carried by this frame (PHV input 1 of reg_tag) */
    bit<8>  dequeued;      /* 1 if ingress_port == PORT_L                         */

    bit<32> ts32;          /* full-resolution ns, for the timestamp bank only     */
    bit<8>  budget_zero;   /* 1 if hdr.ib.seq == 0 as dequeued (fail-open watchdog)*/

    /* ---- piece 2: packed transaction state ---- */
    /* level 0 — packet-derived */
    bit<32> ts_m;          /* ts32 & TICK_MASK                                    */
    bit<32> seq_m;         /* G in ticks, from tbl_guard (low byte zero)          */

    /* level 1 */
    bit<32> now_word;      /* ts_m | ARMED_MARK — the deadline-aligned "now"      */
    bit<8>  pkt_class;
    bit<8>  tag_val;       /* PHV input 2 of reg_tag: 0 = do not write            */

    /* level 2 */
    bit<32> dl_cand;       /* now_word + seq_m = the armed word for this ACK      */
    bit<8>  tag_diff;      /* SALU result: gen_in - stored_tag                    */

    /* level 3 */
    bit<32> dl_val;        /* PHV input 2 of reg_deadline: 0 = do not write       */
    bit<8>  tag_ok;        /* 1 = state is live AND is this generation            */
    bit<8>  ack_ok;        /* 1 = this ACK qualified and armed the deadline       */

    /* level 4 */
    bit<32> age;           /* now_word - deadline_word, straight out of the SALU  */
    bit<8>  expired;       /* 1 = armed AND due                                   */

    /* timestamp event flags (each guards ONE ts-register call site) */
    bit<8>  ev_first_block;
    bit<8>  ev_ack_arm;
    bit<8>  ev_block_term;
    bit<8>  ev_resp_release;

    /* ---- G-selection guard (the only new fields) ---- */
    bit<8>  is_fresh_resp;  /* 1 = a fresh RESPONSE from the outstation, being admitted */
    bit<32> native_clrt;    /* t_response_arrival - t_ack, straight out of reg_t_ack    */
    bit<32> clrt_diff;      /* native_clrt - G : the sign bit is the protection decision */
    bit<8>  protection;     /* 1 = native_clrt <  G (a hold applied); 0 = zero hold      */
}

/* ============================ ingress parser =============================
 * PIECE 1, carried over VERBATIM from p12_combined. Every role decision is taken
 * here; the MAU sees only meta.role / meta.dir / meta.dequeued / meta.fwd_port /
 * meta.port_ok / meta.gen_in. */
parser IgParser(packet_in pkt,
                out headers_t hdr,
                out ig_meta_t meta,
                out ingress_intrinsic_metadata_t ig_intr_md) {

    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        /* NOTE — role, dir, fwd_port, port_ok, gen_in and dequeued are deliberately
         * NOT initialized here. Tofino's parser has no clear-on-write: assigning a
         * field in `start` and again in a later state on the same path is a hard
         * compile error. Each is assigned exactly ONCE per path and every default is
         * the all-zero encoding the compiler's own metadata init supplies:
         * ROLE_BYPASS=0, DIR_MASTER=0, port_ok=0, gen_in=0, dequeued=0. fwd_port is
         * written on every path that sets port_ok=1, and a frame from any other port
         * is dropped before it is read. */
        meta.ts32            = 32w0;
        meta.budget_zero     = 8w0;
        meta.ts_m            = 32w0;
        meta.seq_m           = 32w0;
        meta.now_word        = 32w0;
        meta.pkt_class       = CLASS_OTHER;
        meta.tag_val         = TAG_NO_WRITE;
        meta.dl_cand         = 32w0;
        meta.tag_diff        = 8w0;
        meta.dl_val          = DL_NO_WRITE;
        meta.tag_ok          = 8w0;
        meta.ack_ok          = 8w0;
        meta.age             = 32w0;
        meta.expired         = 8w0;
        meta.ev_first_block  = 8w0;
        meta.ev_ack_arm      = 8w0;
        meta.ev_block_term   = 8w0;
        meta.ev_resp_release = 8w0;
        /* G-selection guard scratch — all-zero defaults, assigned once in start,
         * (re)computed in the apply; never touched again in the parser. */
        meta.is_fresh_resp   = 8w0;
        meta.native_clrt     = 32w0;
        meta.clrt_diff       = 32w0;
        meta.protection      = 8w0;
        transition select(ig_intr_md.ingress_port) {
            PORT_L      : from_loopback;
            PORT_HULK   : from_outstation;
            PORT_VISION : from_master;
            default     : accept;      /* port_ok stays 0 -> dropped in the MAU */
        }
    }

    /* the loopback carries only outstation-origin frames (held responses) and
     * blocker tokens, so its direction is the outstation side and its transparent
     * forward target is the master. */
    state from_loopback   { meta.dequeued = 8w1; meta.dir = DIR_OUT;    meta.fwd_port = PORT_VISION;
                            meta.port_ok  = 8w1; transition parse_eth; }
    state from_outstation { meta.dir      = DIR_OUT;    meta.fwd_port = PORT_VISION;
                            meta.port_ok  = 8w1; transition parse_eth; }
    state from_master     { meta.dir      = DIR_MASTER; meta.fwd_port = PORT_HULK;
                            meta.port_ok  = 8w1; transition parse_eth; }

    state parse_eth {
        pkt.extract(hdr.eth);
        transition select(hdr.eth.etype) {
            ETHERTYPE_IBSPG_TOKEN : parse_token;
            ETHERTYPE_IPV4        : parse_ipv4;
            default               : accept;    /* ARP / IPv6 / ... -> ROLE_BYPASS */
        }
    }

    /* 0x88C1 is internal and can only ever be a blocker token: the role is FORCED
     * here, so no injected frame can talk its way onto a host port. */
    state parse_token {
        pkt.extract(hdr.ib);
        meta.role   = ROLE_BLOCK;
        meta.gen_in = hdr.ib.gen;
        transition accept;
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol, hdr.ipv4.ihl) {
            (IP_PROTO_TCP, 4w5) : parse_tcp;   /* TCP with no IP options only */
            default             : accept;
        }
    }

    /* GATE 1 — TCP payload length. Range-matched HERE (total_len live-range = one
     * state) because the TNA parser cannot compute, and matching total_len in a
     * downstream state ICEs.
     *   pure ACK      : total_len == 20 + 4*data_offset, ACK=1, SYN=FIN=RST=0
     *   DNP3-capable  : total_len >= 20 + 4*data_offset + 13, SYN=FIN=RST=0
     * Anything else falls through to `accept` and is forwarded as ROLE_BYPASS. */
    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition select(hdr.tcp.flags, hdr.tcp.data_offset, hdr.ipv4.total_len) {
            (8w0x10 &&& 8w0x17, 4w5,  16w40) : set_role_ack;
            (8w0x10 &&& 8w0x17, 4w6,  16w44) : set_role_ack;
            (8w0x10 &&& 8w0x17, 4w7,  16w48) : set_role_ack;
            (8w0x10 &&& 8w0x17, 4w8,  16w52) : set_role_ack;   /* Linux TS — the corpus case */
            (8w0x10 &&& 8w0x17, 4w9,  16w56) : set_role_ack;
            (8w0x10 &&& 8w0x17, 4w10, 16w60) : set_role_ack;
            (8w0x10 &&& 8w0x17, 4w11, 16w64) : set_role_ack;
            (8w0x10 &&& 8w0x17, 4w12, 16w68) : set_role_ack;
            (8w0x10 &&& 8w0x17, 4w13, 16w72) : set_role_ack;
            (8w0x10 &&& 8w0x17, 4w14, 16w76) : set_role_ack;
            (8w0x10 &&& 8w0x17, 4w15, 16w80) : set_role_ack;
            (8w0x00 &&& 8w0x07, 4w5,  16w53 .. 16w65535) : parse_dnp3_dl;
            (8w0x00 &&& 8w0x07, 4w6,  16w57 .. 16w65535) : opt4;
            (8w0x00 &&& 8w0x07, 4w7,  16w61 .. 16w65535) : opt8;
            (8w0x00 &&& 8w0x07, 4w8,  16w65 .. 16w65535) : opt12;
            default                                      : accept;
        }
    }

    state opt4  { pkt.extract(hdr.tcp_opt4);  transition parse_dnp3_dl; }
    state opt8  { pkt.extract(hdr.tcp_opt8);  transition parse_dnp3_dl; }
    state opt12 { pkt.extract(hdr.tcp_opt12); transition parse_dnp3_dl; }

    state set_role_ack { meta.role = ROLE_ACK; transition accept; }

    /* GATE 2 — DNP3 link LEN. LEN counts ctrl+dst+src+user data, so LEN == 5 is a
     * well-formed LINK-ONLY frame: valid, forwarded transparently, never dropped.
     * Transport(1) + application(2) need LEN >= 8. */
    state parse_dnp3_dl {
        pkt.extract(hdr.dnp3_dl);
        transition select(hdr.dnp3_dl.start, hdr.dnp3_dl.length) {
            (DNP3_START, 8w8 .. 8w255) : parse_dnp3_tp;
            default                    : accept;   /* LINK_OTHER or not DNP3 */
        }
    }

    state parse_dnp3_tp { pkt.extract(hdr.dnp3_tp); transition parse_dnp3_app; }

    state parse_dnp3_app {
        pkt.extract(hdr.dnp3_app);
        /* the DNP3 application control byte (FIR/FIN/CON/UNS + the 4-bit application
         * sequence, which increments per poll) is this transaction's generation. */
        meta.gen_in = hdr.dnp3_app.app_control;
        /* JOIN B: the ARM leaf additionally requires app_control == 0xCn, i.e.
         * FIR = FIN = 1 and CON = UNS = 0 — which IEEE 1815 mandates for a request,
         * requests being single-fragment. This costs nothing (the select already
         * holds both bytes) and it is what makes the tag domain provably
         * {0x00, 0xC0..0xCF, 0xFF}: never the SALU no-write sentinel 0x00, never
         * TAG_INACTIVE 0xFF. A READ outside that range simply does not arm and is
         * forwarded as ROLE_BYPASS. */
        transition select(hdr.dnp3_app.app_control, hdr.dnp3_app.func_code) {
            (8w0x00 &&& 8w0x00, DNP3_FC_RESPONSE) : set_role_resp;
            (8w0xC0 &&& 8w0xF0, DNP3_FC_READ)     : set_role_arm;
            default                               : accept;  /* DIRECT_OPERATE etc. */
        }
    }
    state set_role_resp { meta.role = ROLE_RESP; transition accept; }
    state set_role_arm  { meta.role = ROLE_ARM;  transition accept; }
}

/* ============================ ingress control =========================== */
control Ingress(inout headers_t hdr,
                inout ig_meta_t meta,
                in    ingress_intrinsic_metadata_t              ig_intr_md,
                in    ingress_intrinsic_metadata_from_parser_t  ig_prsr_md,
                inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                inout ingress_intrinsic_metadata_for_tm_t       ig_tm_md) {

    /* ================= state register 1 of 2: the TAG =====================
     * Packs generation and "active" into one byte. The SALU returns the DIFFERENCE
     * against this frame's generation, so the comparison happens inside the stateful
     * ALU:  tag_diff == 0  <=>  a transaction is active AND it is this generation.
     * PHV inputs: meta.gen_in, meta.tag_val — exactly 2. */
    Register<bit<8>, bit<1>>(1, 0) reg_tag;
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_tag) tag_rmw = {
        void apply(inout bit<8> v, out bit<8> rv) {
            rv = meta.gen_in - v;
            if (meta.tag_val != TAG_NO_WRITE) { v = meta.tag_val; }
        }
    };

    /* ================= state register 2 of 2: the DEADLINE ================
     * 24 bits of 256 ns ticks in [31:8]; bit 0 is the ARMED MARKER. The SALU returns
     * the age directly, so the separate `age = now - deadline` level is gone, and
     * because the marker rides in the same word the separate `dl_armed` test is gone.
     * PHV inputs: meta.now_word, meta.dl_val — exactly 2.
     *
     * TWO RegisterActions, mutually exclusive per packet (one access):
     *   deadline_rmw       — every non-arming packet, INCLUDING the ARM (which disarms
     *                        with dl_val = UNARMED_WORD). Unchanged. dl_val == 0 for
     *                        blockers/responses/bypass => read-only.
     *   deadline_arm_once  — ONLY the qualifying ACK (meta.ack_ok == 1). Arms FIRST-ACK
     *                        idempotently: writes dl_cand ONLY if the stored word is
     *                        still the unarmed sentinel (v == UNARMED_WORD, the state
     *                        the ARM leaves behind). A duplicate/retransmitted ACK for
     *                        the same armed transaction reads v == dl_cand (marker set,
     *                        != UNARMED_WORD) and leaves the deadline untouched — so it
     *                        can no longer push t_ack+G out. Both return the age
     *                        rv = now_word - v identically. */
    Register<bit<32>, bit<1>>(1, 0) reg_deadline;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_deadline) deadline_rmw = {
        void apply(inout bit<32> v, out bit<32> rv) {
            rv = meta.now_word - v;
            if (meta.dl_val != DL_NO_WRITE) { v = meta.dl_val; }
        }
    };
    /* FIRST-ACK idempotency (finding B-D1). Compare-and-arm-once inside the SALU: the
     * armed word is written atomically only when the current stored word is the unarmed
     * sentinel. `v == UNARMED_WORD` is a memory-vs-constant compare (same shape the ts
     * registers use, and the FULL 32-bit word is compared — no bit-slice, no gateway
     * slice). PHV inputs: meta.now_word, meta.dl_val — exactly 2. */
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_deadline) deadline_arm_once = {
        void apply(inout bit<32> v, out bit<32> rv) {
            rv = meta.now_word - v;
            if (v == UNARMED_WORD) { v = meta.dl_val; }
        }
    };

    /* ================= fixed-slot timestamp registers (4) =================
     * SPARSE latency capture, write-if-zero = first occurrence. UNCHANGED from
     * p12_combined; part of the frozen timing mechanism.
     *   G_observed     = reg_ts_first_resp_release - reg_ts_ack_arm
     *   deadline error = G_observed - G
     *   release tail   = reg_ts_first_resp_release - reg_ts_block_term */
    Register<bit<32>, bit<1>>(1, 0) reg_ts_first_block;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_ts_first_block) ts_first_block_w = {
        void apply(inout bit<32> v) { if (v == 32w0) { v = meta.ts32; } }
    };
    Register<bit<32>, bit<1>>(1, 0) reg_ts_ack_arm;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_ts_ack_arm) ts_ack_arm_w = {
        void apply(inout bit<32> v) { if (v == 32w0) { v = meta.ts32; } }
    };
    Register<bit<32>, bit<1>>(1, 0) reg_ts_block_term;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_ts_block_term) ts_block_term_w = {
        void apply(inout bit<32> v) { if (v == 32w0) { v = meta.ts32; } }
    };
    Register<bit<32>, bit<1>>(1, 0) reg_ts_first_resp_release;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_ts_first_resp_release) ts_first_resp_w = {
        void apply(inout bit<32> v) { if (v == 32w0) { v = meta.ts32; } }
    };

    /* ================= G-selection guard: shadow t_ack register ============
     * NEW, additive. Always returns `now - v`; when v holds the FIRST ACK's timestamp
     * that is the native CLRT measured from the first ACK (finding B-D1). Three
     * RegisterActions, mutually exclusive per packet (one access), mirroring the
     * deadline's reset/arm-once so t_ack tracks the SAME transaction boundary:
     *   t_ack_reset   — the ARM (new transaction): clear to 0, forgetting the old t_ack
     *                   so the next transaction's first ACK captures fresh. This is the
     *                   t_ack analogue of the deadline's disarm-on-ARM.
     *   t_ack_capture — the qualifying ACK: capture ts32 ONLY if v == 0 (first ACK of
     *                   this transaction). A duplicate ACK reads v != 0 and leaves it,
     *                   so t_ack stays anchored to the first ACK.
     *   t_ack_read    — every other packet (incl. the RESPONSE, which reads native_clrt
     *                   = now - t_ack): read-only.
     * All are the "rv = phv - v [, conditional/unconditional write]" shape; PHV input
     * is ts32 only (write values are ts32 or the constant 0) — within the 2-input
     * budget with room to spare. */
    Register<bit<32>, bit<1>>(1, 0) reg_t_ack;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_t_ack) t_ack_reset = {
        void apply(inout bit<32> v, out bit<32> rv) {
            rv = meta.ts32 - v;
            v  = 32w0;
        }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_t_ack) t_ack_capture = {
        void apply(inout bit<32> v, out bit<32> rv) {
            rv = meta.ts32 - v;
            if (v == 32w0) { v = meta.ts32; }
        }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_t_ack) t_ack_read = {
        void apply(inout bit<32> v, out bit<32> rv) {
            rv = meta.ts32 - v;
        }
    };

    /* ================= G-selection guard: readout registers (2) ============
     * NEW, additive. Each ONE RegisterAction, ONE unconditional execute() call site,
     * write-enabled by meta.is_fresh_resp. Read live by the control plane. */
    Register<bit<32>, bit<1>>(1, 0) reg_native_clrt;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_native_clrt) native_clrt_w = {
        void apply(inout bit<32> v) { if (meta.is_fresh_resp == 8w1) { v = meta.native_clrt; } }
    };
    Register<bit<8>, bit<1>>(1, 0) reg_protection;
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_protection) protection_w = {
        void apply(inout bit<8> v) { if (meta.is_fresh_resp == 8w1) { v = meta.protection; } }
    };

    /* ================= counters (Stats ALU — multi-site OK) ================ */
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_arm;               /* DNP3 READ forwarded */
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_block_enq;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_block_loop;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_block_term_deadline;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_block_term_timeout;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_block_term_stale;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_ack_arm;      /* qualifying ACK     */
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_ack_bypass;   /* non-qualifying ACK */
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_resp_enq;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_resp_release;
    /* index 0 = ROLE_BYPASS forwarded transparently, index 1 = dropped (bad port) */
    Counter<bit<64>, bit<8>>(2, CounterType_t.PACKETS) ctr_bypass;

    /* ---- G-selection guard counters (NEW, additive; directive §3) ---- */
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_response_before_deadline;      /* now <  deadline */
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_response_at_or_after_deadline; /* now >= deadline */
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_response_actually_held;        /* native_clrt <  G */
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_response_zero_hold;            /* native_clrt >= G */
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_release_deadline;             /* released by deadline */
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_release_fail_open;            /* released by fail-open */

    /* ================= TM actions ================= */
    action to_block() {                       /* enqueue Q_BLOCK on loopback dp8 */
        ig_tm_md.ucast_egress_port = PORT_L;
        ig_tm_md.qid               = QID_BLOCK;
        ig_tm_md.bypass_egress     = 1w1;
    }
    action to_resp() {                        /* enqueue Q_RESP on loopback dp8  */
        ig_tm_md.ucast_egress_port = PORT_L;
        ig_tm_md.qid               = QID_RESP;
        ig_tm_md.bypass_egress     = 1w1;
    }
    /* transparent forward to this frame's peer port: the immediate ACK, the released
     * RESPONSE, the forwarded READ, and all bypass traffic. bypass_egress = 0, so
     * these — and only these — traverse egress (a byte-preserving pass-through). */
    action to_fwd() {
        ig_tm_md.ucast_egress_port = meta.fwd_port;
        ig_tm_md.qid               = 5w0;
        ig_tm_md.bypass_egress     = 1w0;
    }
    action drop_pkt() { ig_dprsr_md.drop_ctl = 3w1; }

    /* ================= guard interval G (JOIN C) =================
     * G already in 256 ns ticks; the low byte MUST be zero. No dependencies, so this
     * lands at or before the level that builds now_word and costs no depth. */
    action set_guard(bit<32> g_ticks) { meta.seq_m = g_ticks; }
    table tbl_guard {
        actions = { set_guard; }
        default_action = set_guard(G_DEFAULT_TICKS);
        size = 1;
    }

    /* ---- level 1: build the deadline-aligned "now" ----
     * Constants only on the packing side. This must be an explicit table rather than
     * a plain statement beside the level-0 assignments: bf-p4c merges consecutive
     * unconditional statements into ONE action and then rejects the intra-action
     * dependency with "action spanning multiple stages" (measured on 9.13.1). */
    action build_now() { meta.now_word = meta.ts_m | ARMED_MARK; }
    table tbl_build_now {
        actions = { build_now; }
        const default_action = build_now();
        size = 1;
    }

    /* ---- level 2: the candidate armed word for an ACK ----
     * dl_cand = now_word + G_ticks: the low byte of the addend is zero, so the ARMED
     * marker survives the addition untouched and the tick fields add. */
    action build_cand() { meta.dl_cand = meta.now_word + meta.seq_m; }
    table tbl_build_cand {
        actions = { build_cand; }
        const default_action = build_cand();
        size = 1;
    }

    /* ================= the ONE decode table ==============================
     * Replaces the gen_mismatch compare level, the active-clear driver level and the
     * ACK-qualify / deadline-driver level with a single lookup on the packet class
     * and the tag difference. The match unit reads the whole container under a TCAM
     * mask, so nothing is sliced.
     *
     *   BLOCK : tag_diff == 0                <=> active AND my generation.
     *   ACK   : tag_diff NOT IN {0x00,0x01}  <=> a transaction is live (JOIN B).
     * Entry order IS priority: the CLASS_ACK reject pattern precedes the CLASS_ACK
     * accept-any pattern. A non-qualifying ACK writes NOTHING, so it cannot move any
     * release time. */
    action dec_arm()     { meta.dl_val = UNARMED_WORD; }                       /* ARM disarms  */
    action dec_ack_arm() { meta.dl_val = meta.dl_cand; meta.ack_ok = 8w1; }    /* ACK arms     */
    action dec_live()    { meta.dl_val = DL_NO_WRITE;  meta.tag_ok = 8w1; }    /* live blocker */
    action dec_none()    { meta.dl_val = DL_NO_WRITE; }
    table tbl_state_decode {
        key = {
            meta.pkt_class : exact;
            meta.tag_diff  : ternary;
        }
        actions = { dec_arm; dec_ack_arm; dec_live; dec_none; }
        const default_action = dec_none();
        const entries = {
            (CLASS_ARM,       8w0x00 &&& 8w0x00) : dec_arm();      /* any tag: ARM takes over  */
            (CLASS_ACK,       8w0x00 &&& 8w0xFE) : dec_none();     /* no live transaction      */
            (CLASS_ACK,       8w0x00 &&& 8w0x00) : dec_ack_arm();  /* live: qualified, arm     */
            (CLASS_BLOCK_DEQ, 8w0x00 &&& 8w0xFF) : dec_live();     /* my generation, still live */
        }
        size = 8;
    }

    /* ================= deadline expiry =================================
     * expired <=> the deadline word is ARMED (low byte of the age is 0x00, which
     * happens only when the stored marker 0x01 cancelled the now-word marker with no
     * borrow) AND the 24-bit tick difference is non-negative (bit 31 clear). ONE
     * ternary entry tests both; unarmed words can never read as expired. */
    action mark_expired()     { meta.expired = 8w1; }
    action mark_not_expired() { meta.expired = 8w0; }
    table tbl_deadline_expiry {
        key = { meta.age : ternary; }
        actions = { mark_expired; mark_not_expired; }
        const default_action = mark_not_expired();
        const entries = {
            (32w0x00000000 &&& 32w0x800000FF) : mark_expired();
        }
        size = 2;
    }

    /* ================= G-selection guard: native_clrt vs G ================
     * NEW. clrt_diff = native_clrt - G is built in its OWN table (a plain statement
     * would merge with the level-0 assignments and trip "action spanning multiple
     * stages", the same reason tbl_build_now / tbl_build_cand exist). */
    action build_clrt_diff() { meta.clrt_diff = meta.native_clrt - meta.seq_m; }
    table tbl_build_clrt_diff {
        actions = { build_clrt_diff; }
        const default_action = build_clrt_diff();
        size = 1;
    }

    /* protection <=> native_clrt < G <=> (native_clrt - G) is negative <=> sign bit
     * set. Tested by a ternary TCAM mask on the whole 32-bit container — NOT a bit
     * slice — exactly as tbl_deadline_expiry tests its sign byte. */
    action mark_held()      { meta.protection = 8w1; }
    action mark_zero_hold() { meta.protection = 8w0; }
    table tbl_clrt_guard {
        key = { meta.clrt_diff : ternary; }
        actions = { mark_held; mark_zero_hold; }
        const default_action = mark_zero_hold();
        const entries = {
            (32w0x80000000 &&& 32w0x80000000) : mark_held();   /* sign set: native_clrt < G */
        }
        size = 2;
    }

    apply {
        if (meta.port_ok == 8w0) {
            /* isolate the pipeline: only dp8 / dp9 / dp11 are in the topology */
            ctr_bypass.count(8w1);
            drop_pkt();
        } else {
            /* ---------- level 0: packet-derived only ----------
             * role / dir / dequeued / fwd_port / gen_in already came from the parser. */
            meta.ts32 = ig_intr_md.ingress_mac_tstamp[31:0];
            meta.ts_m = ig_intr_md.ingress_mac_tstamp[31:0] & TICK_MASK;
            /* hdr.ib is valid ONLY on blocker tokens, so on every other frame this
             * compares a stale tagalong container and budget_zero is MEANINGLESS.
             * Safe because budget_zero has exactly two consumers and both sit inside
             * a ROLE_BLOCK branch, and ROLE_BLOCK implies the token header is valid.
             * Do not read budget_zero outside a ROLE_BLOCK branch. */
            if (hdr.ib.seq == 32w0) { meta.budget_zero = 8w1; }  /* isolated 32b compare */
            tbl_guard.apply();                                   /* meta.seq_m = G ticks */

            /* ---------- level 1: now-word, class, tag write driver ---------- */
            tbl_build_now.apply();
            if (meta.dequeued == 8w0) {
                if (meta.role == ROLE_ARM && meta.dir == DIR_MASTER) {
                    meta.pkt_class = CLASS_ARM;
                    meta.tag_val   = meta.gen_in;      /* ARM takes ownership; 0xCn by gate */
                } else if (meta.role == ROLE_ACK && meta.dir == DIR_OUT) {
                    meta.pkt_class = CLASS_ACK;
                }
            } else if (meta.role == ROLE_BLOCK) {
                meta.pkt_class = CLASS_BLOCK_DEQ;
                if (meta.budget_zero == 8w1) {
                    meta.tag_val = TAG_INACTIVE;       /* fail-open: retire the txn */
                }
            }

            /* ---------- level 2: tag access (+ ACK candidate in parallel) ------ */
            meta.tag_diff = tag_rmw.execute(0);
            tbl_build_cand.apply();

            /* ---------- level 3: one decode for stale / qualify / disarm ------- */
            tbl_state_decode.apply();

            /* ---------- level 4: deadline access, returning the age ------------
             * The qualifying ACK arms first-ACK idempotently (deadline_arm_once writes
             * only if v is still UNARMED_WORD); every other packet — including the ARM,
             * which disarms via dl_val = UNARMED_WORD — uses the unchanged deadline_rmw.
             * ack_ok == 1 <=> dec_ack_arm fired <=> dl_val == dl_cand, so arm_once always
             * sees a valid armed word. Both return the same age; only one runs per pkt. */
            if (meta.ack_ok == 8w1) {
                meta.age = deadline_arm_once.execute(0);
            } else {
                meta.age = deadline_rmw.execute(0);
            }

            /* ---------- level 5: expiry ---------- */
            tbl_deadline_expiry.apply();

            /* ================= ACT (flat, no early returns) ================= */
            if (meta.dequeued == 8w0) {
                /* ----- FRESH from a host port ----- */
                if (meta.role == ROLE_BLOCK) {
                    to_block();
                    ctr_block_enq.count(0);
                    meta.ev_first_block = 8w1;
                } else if (meta.role == ROLE_RESP && meta.dir == DIR_OUT) {
                    to_resp();                        /* held on Q_RESP (qid1, LOW) */
                    ctr_resp_enq.count(0);
                    meta.is_fresh_resp = 8w1;         /* NEW: arm the G-selection guard */
                } else if (meta.role == ROLE_ACK) {
                    /* HOLD_RESPONSE: the ACK is NEVER held — forward it now. */
                    to_fwd();
                    if (meta.ack_ok == 8w1) {
                        ctr_ack_arm.count(0);
                        meta.ev_ack_arm = 8w1;
                    } else {
                        ctr_ack_bypass.count(0);
                    }
                } else if (meta.role == ROLE_ARM) {
                    /* a real DNP3 READ: it took the tag above and must reach the
                     * outstation, so it is forwarded, not consumed. */
                    to_fwd();
                    ctr_arm.count(0);
                } else {
                    to_fwd();                         /* ROLE_BYPASS: transparent */
                    ctr_bypass.count(8w0);
                }
            } else {
                /* ----- DEQUEUED (looped back from dp8) ----- */
                if (meta.role == ROLE_BLOCK) {
                    /* terminate causes, priority: stale > deadline > budget */
                    if (meta.tag_ok == 8w0) {
                        drop_pkt();
                        ctr_block_term_stale.count(0);
                        meta.ev_block_term = 8w1;
                    } else if (meta.expired == 8w1) {
                        drop_pkt();
                        ctr_block_term_deadline.count(0);
                        meta.ev_block_term = 8w1;
                    } else if (meta.budget_zero == 8w1) {
                        drop_pkt();
                        ctr_block_term_timeout.count(0);
                        meta.ev_block_term = 8w1;
                    } else {
                        /* LOOP: consume one budget unit, re-enqueue Q_BLOCK */
                        hdr.ib.seq = hdr.ib.seq - 32w1;
                        to_block();
                        ctr_block_loop.count(0);
                    }
                } else if (meta.role == ROLE_RESP) {
                    /* RELEASED RESPONSE: forward to the master, byte-identical.
                     * NEW: attribute the release cause by the deadline state at
                     * dequeue — expired => the reservoir drained on the deadline;
                     * not-expired => it drained early on its pass budget (fail-open).
                     * meta.expired is already computed above for this packet; this
                     * adds only two Stats-ALU count() calls, no new stage. */
                    to_fwd();
                    ctr_resp_release.count(0);
                    meta.ev_resp_release = 8w1;
                    if (meta.expired == 8w1) { ctr_release_deadline.count(0); }
                    else                     { ctr_release_fail_open.count(0); }
                } else {
                    drop_pkt();   /* nothing else may loop back */
                }
            }

            /* ================= G-selection guard (NEW; directive §3) =============
             * Applies only to a freshly admitted RESPONSE. reg_t_ack is executed
             * unconditionally (single call site) and returns now - t_ack; the value
             * is only stored/counted when meta.is_fresh_resp. tbl_build_clrt_diff and
             * tbl_clrt_guard also run unconditionally (they compute on scratch for
             * non-responses, which is never read). */
            /* reg_t_ack tracks the SAME transaction boundary as the deadline: the ARM
             * resets it, the FIRST qualifying ACK captures ts32 (v==0), a duplicate ACK
             * leaves it, and the RESPONSE (else) reads native_clrt = now - t_firstACK.
             * Exactly one RegisterAction runs per packet (one access). */
            if (meta.pkt_class == CLASS_ARM) {
                meta.native_clrt = t_ack_reset.execute(0);    /* new txn: forget old t_ack   */
            } else if (meta.ack_ok == 8w1) {
                meta.native_clrt = t_ack_capture.execute(0);  /* first ACK only (v==0)       */
            } else {
                meta.native_clrt = t_ack_read.execute(0);     /* response & others: read     */
            }
            tbl_build_clrt_diff.apply();               /* clrt_diff = native_clrt - G       */
            tbl_clrt_guard.apply();                    /* protection = sign(clrt_diff)      */
            native_clrt_w.execute(0);                  /* store native CLRT for CP readout  */
            protection_w.execute(0);                   /* store protection flag for CP      */
            if (meta.is_fresh_resp == 8w1) {
                /* compare (1): now vs deadline, via the EXISTING deadline sign-bit
                 * ternary (meta.expired). */
                if (meta.expired == 8w1) { ctr_response_at_or_after_deadline.count(0); }
                else                     { ctr_response_before_deadline.count(0); }
                /* compare (2): native_clrt vs G, via tbl_clrt_guard (meta.protection). */
                if (meta.protection == 8w1) { ctr_response_actually_held.count(0); }
                else                        { ctr_response_zero_hold.count(0); }
            }

            /* ================= SPARSE latency capture (single call site each) ===
             * UNCHANGED from p12_combined. */
            if (meta.ev_first_block  == 8w1) { ts_first_block_w.execute(0); }
            if (meta.ev_ack_arm      == 8w1) { ts_ack_arm_w.execute(0); }
            if (meta.ev_block_term   == 8w1) { ts_block_term_w.execute(0); }
            if (meta.ev_resp_release == 8w1) { ts_first_resp_w.execute(0); }
        }
    }
}

/* ============================ ingress deparser ==========================
 * Emission order == extraction order, so every forwarded frame is byte-identical.
 * Exactly one of {ib} / {ipv4 ...} is valid; unextracted bytes stay residual and are
 * emitted automatically. UNCHANGED from p12_combined. */
control IgDeparser(packet_out pkt,
                   inout headers_t hdr,
                   in    ig_meta_t meta,
                   in    ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    apply {
        pkt.emit(hdr.eth);
        pkt.emit(hdr.ib);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.tcp_opt4);
        pkt.emit(hdr.tcp_opt8);
        pkt.emit(hdr.tcp_opt12);
        pkt.emit(hdr.dnp3_dl);
        pkt.emit(hdr.dnp3_tp);
        pkt.emit(hdr.dnp3_app);
    }
}

/* ============================ egress ====================================
 * BYTE-PRESERVING PASS-THROUGH, carried over VERBATIM from ibspg_dnp3.p4 (which
 * carried it from Part 12). The immediately-forwarded ACK, the forwarded READ, the
 * released RESPONSE and all bypass traffic traverse egress (bypass_egress=0). Egress
 * extracts only ethernet: everything after it is residual and is re-emitted verbatim,
 * so the frame is byte-identical to what the ingress deparser produced. No field is
 * modified anywhere in egress. Blocker tokens and held responses set bypass_egress=1
 * and never arrive here, so the hold mechanism cannot be perturbed by this gress. */
struct eg_meta_t { }

parser EgParser(packet_in pkt,
                out headers_t hdr,
                out eg_meta_t meta,
                out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        pkt.extract(eg_intr_md);
        transition parse_eth;
    }
    state parse_eth {
        pkt.extract(hdr.eth);
        transition accept;
    }
}
control Egress(inout headers_t hdr,
               inout eg_meta_t meta,
               in    egress_intrinsic_metadata_t                 eg_intr_md,
               in    egress_intrinsic_metadata_from_parser_t     eg_prsr_md,
               inout egress_intrinsic_metadata_for_deparser_t    eg_dprsr_md,
               inout egress_intrinsic_metadata_for_output_port_t eg_oport_md) {
    apply { }
}
control EgDeparser(packet_out pkt,
                   inout headers_t hdr,
                   in    eg_meta_t meta,
                   in    egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {
    apply {
        pkt.emit(hdr.eth);
    }
}

/* ============================ pipeline ================================== */
Pipeline(IgParser(), Ingress(), IgDeparser(),
         EgParser(), Egress(), EgDeparser()) pipe;

Switch(pipe) main;

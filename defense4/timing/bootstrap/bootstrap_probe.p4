/* ============================================================================
 * bootstrap_probe.p4 — Defense 4 directive §3: RESERVOIR-BOOTSTRAP FEASIBILITY PROBE
 *
 * PURPOSE (feasibility only). Answer, OFFLINE, the R11 kill-question: can the two
 * blocker reservoirs (ACK + RESPONSE) be ESTABLISHED and MAINTAINED with ONE-TIME
 * control-plane configuration only — no per-transaction host, controller, ARM,
 * blocker injection, or TM action — as an autonomous data-plane bootstrap?
 *
 * This is an ISOLATED probe. It is NOT the Defense 4 timing core and does NOT patch
 * defense4_timing.p4. It deliberately omits the full deadline/release machinery (that
 * is directive §4, gated): it models ONLY the bootstrap mechanisms and their gates, so
 * each can be shown placeable on Tofino-1. NOTHING here is loaded or run; this answers a
 * local bf-p4c 9.13.1 compile-fit question only. Silicon behaviour (continuity, timing,
 * ordering, and the periodic-top-up RATE below) is OUT OF SCOPE and UNVERIFIED.
 *
 * THE CONSTRUCTION UNDER TEST — a residency-tracked, self-healing reservoir.
 *   Source:    a pktgen TIMER app configured ONCE (trigger_timer_*), firing the K
 *              packet_ids (0..K-1, app_id -> domain) PERIODICALLY. A period fire that
 *              hits a still-live token is de-duplicated in the data plane; a fire that
 *              hits a FREED slot re-admits it. So a single one-time app both seeds and
 *              tops up the pool — no per-transaction action seeds it. (Directive R11
 *              permits a continuously-configured pktgen source iff configured once and
 *              the data plane controls admission/stamping/readiness — this is that.)
 *   Residency: reg_present is a per-(domain,packet_id) OCCUPANCY cell (admit sets it,
 *              termination CLEARS it) and reg_pop is the per-domain live count (++ on a
 *              distinct admit, -- on a termination). readiness == (pop == K). Because pop
 *              tracks live residency, it FALLS when tokens terminate — so an emptied ring
 *              can never read "ready" (no silent protection loss), and a freed slot can
 *              be re-seeded by the periodic source (termination and re-seed are
 *              reconciled, not mutually exclusive).
 *   Distinct:  distinctness is structural + residency-gated. A token is counted only on
 *              the timer-parse path AND only when its occupancy cell was empty
 *              (present_old==0). Every recirculation pass re-enters on the recirc-parse
 *              path and is NEVER counted; a periodic re-fire of a still-live id reads
 *              present_old!=0 and is dropped. So pop == number of DISTINCT LIVE tokens,
 *              never the number of passes or re-fires.
 *   Persist:   a recirc token is simply re-enqueued each pass (persistence is NOT a
 *              finite budget — there is no self-draining counter). If the epoch advanced
 *              it ADOPTS the current epoch (re-stamps hdr.token.gen), so live tokens
 *              track the active transaction.
 *   Terminate: a token is terminated ONLY when its domain is RETIRED (reg_retire set by
 *              the control plane for a deliberate drain/reprovision — an admin action,
 *              NOT per-transaction). Retirement drops the token, clears its occupancy
 *              cell, and decrements its domain's count, touching NOTHING else; the
 *              periodic source then re-seeds the freed slots. Per-transaction end (P8) is
 *              a different, non-draining event (see below).
 *
 * PROPERTY -> SITE MAP (directive §3; grep the tags)
 *   [P1] authenticated internal origin ...... parser from_pgen/from_loop + value_set
 *                                             pgen_timer; a ROLE_TOKEN with is_first==0 &&
 *                                             is_loop==0 (i.e. a 0x88C1 frame from a host
 *                                             port) is dropped (ctr_seed_badorigin).
 *   [P2] distinct id, no double-count ....... reg_present occupancy (admit sets, retire
 *                                             clears); pop ++ only on present_old==0;
 *                                             recirc passes and live re-fires never count.
 *   [P3] ACK + RESP reservoir readiness ..... reg_pop indexed by domain (2 reservoirs);
 *                                             ready <=> pop == K; pop tracks LIVE residency
 *                                             (++admit / --terminate) so it is truthful.
 *   [P4] data-plane gen/role/domain stamp ... admit_token(): marker/domain/gen/tokid
 *                                             written in the MAU from reg_gen + the pktgen
 *                                             header (NOT the CP template); loop adopt
 *                                             re-stamps gen from reg_gen (hdr.token.gen is
 *                                             read by the adopt compare — it is live state).
 *   [P5] ACK-before-ready fail-open ......... host ACK/RESP: ready && active && from_out
 *                                             -> to_hold; else to_fwd (forwarded, never
 *                                             enqueued behind an unready reservoir =>
 *                                             un-stranded).
 *   [P6] stale-token termination ............ recirc token with reg_retire set -> drop +
 *                                             present_clear(own cell) + pop_decr(own
 *                                             domain) ONLY; writes no other token and not
 *                                             reg_gen => touches no newer generation.
 *   [P7] inactive nonblocking ............... reg_active==0 => host ACK/RESP forwarded,
 *                                             never held; tokens persist irrespective of
 *                                             active (the token loop never reads
 *                                             reg_active) so they keep looping harmlessly.
 *   [P8] bounded cleanup + restoration ...... FIN/RST -> active_clear (ONE write); the
 *                                             pool is NOT drained (per-transaction end is
 *                                             not retirement), so restoration on the next
 *                                             ARM is O(1) (active_set). The heavier
 *                                             retire+re-seed drain (P6 + periodic source)
 *                                             is admin-only, not per-transaction.
 *
 * WHY NOT THE FROZEN defense2_pktgen PKTGEN. That variant is REQUEST-TRIGGERED: a fresh
 * READ mirrors a clone whose recirculation fires a per-READ batch of K tokens — a
 * per-transaction data-plane action, which §3 forbids. This probe replaces it with a
 * one-time timer source + residency-tracked recirculation, so establishment is one-time.
 *
 * NOT CLAIMED. No silicon result. No dual-reservoir continuity, no deadline correctness,
 * no ordering, and NOT that the periodic top-up RATE keeps pop==K across a retire/refill
 * gap — those are Gate 3 / hardware obligations (R2/R11). Reservoir SIZING and whether
 * per-generation isolation must be terminate-based or adopt-based are §4 decisions; this
 * probe demonstrates BOTH the adopt (persist) and terminate (retire) paths are placeable.
 * ==========================================================================*/
#include <core.p4>
#include <tna.p4>

/* ---- ethertypes ---- */
const bit<16> ETHERTYPE_TOKEN = 0x88C1;   /* internal blocker token, never on a host port */
const bit<16> ETHERTYPE_IPV4  = 0x0800;
const bit<8>  IP_PROTO_TCP     = 8w6;

/* ---- DNP3 (compact subset, host classification only) ---- */
const bit<16> DNP3_START       = 0x0564;
const bit<8>  DNP3_FC_READ      = 8w1;
const bit<8>  DNP3_FC_RESPONSE  = 8w129;

/* ---- ports (mirror the frozen topology; dp8 loopback, dp68 pktgen source) ---- */
const PortId_t PORT_L      = 9w8;    /* internal loopback: recirculating tokens */
const PortId_t PORT_MASTER = 9w9;    /* master side (host)                      */
const PortId_t PORT_RELAY  = 9w64;   /* outstation side (host)                  */
const PortId_t PORT_PGEN   = 9w68;   /* pktgen source: one-time timer app       */

/* ---- queues on PORT_L ---- */
const bit<5> QID_BLOCK = 5w7;   /* HIGH: the blocker reservoir           */
const bit<5> QID_HOLD  = 5w1;   /* LOW : held ACK/RESPONSE (behind block) */

/* ---- reservoirs / domains ---- */
const bit<8>  DOMAIN_ACK  = 8w0;   /* app_id 0 */
const bit<8>  DOMAIN_RESP = 8w1;   /* app_id 1 */
const bit<16> K_TOKENS    = 16w64; /* tokens per reservoir; ready <=> pop == K */

/* ---- token identity / lifecycle ---- */
const bit<8> TOKEN_MARKER = 8w0xE1;   /* internal marker byte in the token header */
const bit<8> RETIRE_ON    = 8w1;      /* reg_retire value that drains a domain (admin) */

/* ---- roles (assigned in the parser) ---- */
const bit<8> ROLE_BYPASS  = 8w0;   /* forwarded unchanged                */
const bit<8> ROLE_TOKEN   = 8w1;   /* 0x88C1 internal blocker token      */
const bit<8> ROLE_ACK     = 8w2;   /* pure TCP ACK                       */
const bit<8> ROLE_RESP    = 8w3;   /* DNP3 RESPONSE                      */
const bit<8> ROLE_ARM     = 8w6;   /* DNP3 READ from the master          */
const bit<8> ROLE_CLEANUP = 8w7;   /* TCP FIN/RST: end of transaction    */

/* ============================ headers ==================================== */
header ethernet_h { bit<48> dst; bit<48> src; bit<16> etype; }

/* the recirculating blocker token, stamped entirely in the data plane on admission.
 * No budget field: persistence is by recirculation + periodic top-up, not a finite,
 * self-draining counter (that was the refuted design). */
header token_h {
    bit<8>  marker;   /* TOKEN_MARKER 0xE1                          */
    bit<8>  domain;   /* reservoir id (DOMAIN_ACK / DOMAIN_RESP)    */
    bit<8>  gen;      /* stamped epoch (adopted when it changes)    */
    bit<16> tokid;    /* token identity = pktgen packet_id, for life*/
}

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
/* the corpus SEL-751 case is Linux TCP timestamps = data_offset 8 (12 option bytes).
 * options are carried verbatim and NEVER read; offsets other than 5/8 are BYPASS. */
header tcp_opt12_h { bit<96> data; }

header dnp3_dl_h {
    bit<16> start; bit<8> length; bit<8> ctrl;
    bit<16> dst_addr; bit<16> src_addr; bit<16> crc;
}
header dnp3_tp_h  { bit<8> tp_ctrl; }
header dnp3_app_h { bit<8> app_control; bit<8> func_code; }

struct headers_t {
    pktgen_timer_header_t timer;   /* 6B prefix on every timer-app packet */
    ethernet_h  eth;
    token_h     token;
    ipv4_h      ipv4;
    tcp_h       tcp;
    tcp_opt12_h tcp_opt12;
    dnp3_dl_h   dnp3_dl;
    dnp3_tp_h   dnp3_tp;
    dnp3_app_h  dnp3_app;
}

struct ig_meta_t {
    /* parser-set classification (assigned once per path; default-0 elsewhere) */
    bit<8>  role;
    bit<8>  port_ok;    /* 1 if the ingress port is in the topology */
    bit<9>  fwd_port;   /* transparent-forward peer                 */
    bit<8>  is_first;   /* 1 = arrived on the pktgen source (first appearance) */
    bit<8>  is_loop;    /* 1 = arrived on the loopback (a recirc pass)         */
    bit<8>  from_out;   /* 1 = arrived from the outstation side (ACK/RESP dir) */

    /* MAU-derived identity (from hdr.timer on admit, hdr.token on loop) */
    bit<8>  domain;
    bit<1>  dom_idx;    /* domain[0:0], the reg_pop / reservoir index */
    bit<7>  pres_idx;   /* (domain,tokid) occupancy-cell index       */
    bit<16> tokid;

    /* MAU scratch (zero-init in start) */
    bit<8>  present_old;/* reg_present read: 0 => an empty slot            */
    bit<8>  pres_cleared;/* reg_present old on a retire clear (1 => was live)*/
    bit<16> pop_val;    /* reg_pop read/updated                     */
    bit<8>  ready;      /* 1 = this domain's reservoir is at K      */
    bit<8>  gen_cur;    /* reg_gen raw read (current epoch)         */
    bit<8>  retire_val; /* reg_retire read                          */
    bit<8>  active_val; /* reg_active read                          */
}

/* ============================ ingress parser ============================ */
parser IgParser(packet_in pkt,
                out headers_t hdr,
                out ig_meta_t meta,
                out ingress_intrinsic_metadata_t ig_intr_md) {

    /* [P1] the control plane loads this with each reservoir app's leading byte:
     * pktgen_timer_header_t byte0 = 000 ++ pipe_id(2) ++ app_id(3) = 0x00 (app 0, pipe 0)
     * and 0x01 (app 1, pipe 0). Consulted ONLY for dp68 traffic. */
    value_set<bit<8>>(2) pgen_timer;

    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        /* role/port_ok/fwd_port/is_first/is_loop/from_out/domain/dom_idx/pres_idx/tokid
         * are assigned once per path and default to their all-zero encoding elsewhere. */
        meta.present_old  = 8w0;
        meta.pres_cleared = 8w0;
        meta.pop_val      = 16w0;
        meta.ready        = 8w0;
        meta.gen_cur      = 8w0;
        meta.retire_val   = 8w0;
        meta.active_val   = 8w0;
        transition select(ig_intr_md.ingress_port) {
            PORT_PGEN   : from_pgen;
            PORT_L      : from_loop;
            PORT_MASTER : from_master;
            PORT_RELAY  : from_relay;
            default     : accept;      /* port_ok stays 0 -> dropped in the MAU */
        }
    }

    /* [P1] dp68 carries only timer-app packets. A packet whose leading byte matches a
     * configured reservoir app is admitted as a first-appearance token; anything else on
     * dp68 falls through with port_ok=0 and is dropped. */
    state from_pgen {
        transition select(pkt.lookahead<bit<8>>()) {
            pgen_timer : parse_timer;
            default    : accept;
        }
    }
    state parse_timer {
        pkt.extract(hdr.timer);
        meta.is_first = 8w1;
        meta.port_ok  = 8w1;
        /* domain/dom_idx/tokid/pres_idx are derived from hdr.timer in the MAU: Tofino's
         * parser rejects the sliced/multi-path re-assignment of these fields. */
        transition parse_eth;
    }

    /* the loopback carries recirculating tokens (outstation-direction). */
    state from_loop     { meta.is_loop = 8w1; meta.port_ok = 8w1; meta.fwd_port = PORT_MASTER;
                          transition parse_eth; }
    state from_master   { meta.port_ok = 8w1; meta.fwd_port = PORT_RELAY;  transition parse_eth; }
    state from_relay    { meta.port_ok = 8w1; meta.fwd_port = PORT_MASTER; meta.from_out = 8w1;
                          transition parse_eth; }

    state parse_eth {
        pkt.extract(hdr.eth);
        transition select(hdr.eth.etype) {
            ETHERTYPE_TOKEN : parse_token;
            ETHERTYPE_IPV4  : parse_ipv4;
            default         : accept;      /* ROLE_BYPASS */
        }
    }
    state parse_token {
        pkt.extract(hdr.token);
        meta.role = ROLE_TOKEN;
        transition accept;
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol, hdr.ipv4.ihl) {
            (IP_PROTO_TCP, 4w5) : parse_tcp;
            default             : accept;
        }
    }
    /* host classification (compact). FIN/RST -> CLEANUP; pure ACK -> ACK; DNP3-capable
     * -> parse the app header for READ/RESPONSE. data_offset 5 (no opts) and 8 (TS opts)
     * only; every other offset is BYPASS. FIN/RST precede ACK so a FIN-ACK is CLEANUP. */
    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition select(hdr.tcp.flags, hdr.tcp.data_offset, hdr.ipv4.total_len) {
            (8w0x01 &&& 8w0x01, 4w0 &&& 4w0, 16w0 &&& 16w0) : set_role_cleanup; /* FIN */
            (8w0x04 &&& 8w0x04, 4w0 &&& 4w0, 16w0 &&& 16w0) : set_role_cleanup; /* RST */
            (8w0x10 &&& 8w0x17, 4w5, 16w40)                 : set_role_ack;
            (8w0x10 &&& 8w0x17, 4w8, 16w52)                 : set_role_ack;
            (8w0x00 &&& 8w0x07, 4w5, 16w53 .. 16w65535)     : parse_dnp3_dl;
            (8w0x00 &&& 8w0x07, 4w8, 16w65 .. 16w65535)     : opt12_dnp3;
            default                                         : accept;
        }
    }
    state opt12_dnp3 { pkt.extract(hdr.tcp_opt12); transition parse_dnp3_dl; }

    state set_role_ack     { meta.role = ROLE_ACK;     transition accept; }
    state set_role_cleanup { meta.role = ROLE_CLEANUP; transition accept; }

    state parse_dnp3_dl {
        pkt.extract(hdr.dnp3_dl);
        transition select(hdr.dnp3_dl.start, hdr.dnp3_dl.length) {
            (DNP3_START, 8w8 .. 8w255) : parse_dnp3_tp;
            default                    : accept;
        }
    }
    state parse_dnp3_tp { pkt.extract(hdr.dnp3_tp); transition parse_dnp3_app; }
    state parse_dnp3_app {
        pkt.extract(hdr.dnp3_app);
        transition select(hdr.dnp3_app.app_control, hdr.dnp3_app.func_code) {
            (8w0x00 &&& 8w0x00, DNP3_FC_RESPONSE) : set_role_resp;
            (8w0xC0 &&& 8w0xF0, DNP3_FC_READ)     : set_role_arm;
            default                               : accept;
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

    /* ---- [P2] occupancy: one cell per (domain, packet_id) ----
     * 2 domains * 64 tokens = 128 cells. present_admit returns the OLD value (0 => empty
     * slot => a distinct token to admit; 1 => still live => a periodic re-fire, dropped)
     * and fills it. present_clear empties it on retirement, returning the OLD value so
     * pop is decremented exactly once. A recirc pass reaches NEITHER (it is not on the
     * first-appearance or retire path), so pop reflects DISTINCT LIVE tokens, not passes.*/
    Register<bit<8>, bit<7>>(128, 0) reg_present;
    RegisterAction<bit<8>, bit<7>, bit<8>>(reg_present) present_admit = {
        void apply(inout bit<8> v, out bit<8> rv) {
            rv = v;
            if (v == 8w0) { v = 8w1; }
        }
    };
    RegisterAction<bit<8>, bit<7>, bit<8>>(reg_present) present_clear = {
        void apply(inout bit<8> v, out bit<8> rv) {
            rv = v;
            v  = 8w0;
        }
    };

    /* ---- [P3] LIVE population per reservoir; ready <=> pop == K ----
     * pop_incr on a distinct admit, pop_decr on a retirement, pop_read on host admission.
     * Because pop tracks residency it can only be K when K tokens are genuinely live, so
     * an emptied ring can never read "ready". */
    Register<bit<16>, bit<1>>(2, 0) reg_pop;
    RegisterAction<bit<16>, bit<1>, bit<16>>(reg_pop) pop_incr = {
        void apply(inout bit<16> v, out bit<16> rv) { v = v + 16w1; rv = v; }
    };
    RegisterAction<bit<16>, bit<1>, bit<16>>(reg_pop) pop_decr = {
        void apply(inout bit<16> v, out bit<16> rv) { v = v - 16w1; rv = v; }
    };
    RegisterAction<bit<16>, bit<1>, bit<16>>(reg_pop) pop_read = {
        void apply(inout bit<16> v, out bit<16> rv) { rv = v; }
    };

    /* ---- [P4] current epoch. gen_read stamps/adopts; gen_bump advances on a READ.
     * gen is bit<8> and wraps naturally; the wrap is BENIGN because gen is only used to
     * decide whether to re-stamp (both branches persist) — termination is driven by
     * reg_retire, NOT by any gen sentinel, so there is no wrap-to-drain hazard. */
    Register<bit<8>, bit<1>>(1, 0) reg_gen;
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_gen) gen_read = {
        void apply(inout bit<8> v, out bit<8> rv) { rv = v; }
    };
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_gen) gen_bump = {
        void apply(inout bit<8> v, out bit<8> rv) { v = v + 8w1; rv = v; }
    };

    /* ---- [P6] per-domain retire flag: control-plane set for a deliberate drain /
     * reprovision (an ADMIN action, not per-transaction). Data plane reads it on the
     * token loop. Indexed by domain. */
    Register<bit<8>, bit<1>>(2, 0) reg_retire;
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_retire) retire_read = {
        void apply(inout bit<8> v, out bit<8> rv) { rv = v; }
    };

    /* ---- [P7/P8] domain active flag (single domain in this probe) ---- */
    Register<bit<8>, bit<1>>(1, 0) reg_active;
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_active) active_set   = {
        void apply(inout bit<8> v, out bit<8> rv) { v = 8w1; rv = v; }
    };
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_active) active_clear = {
        void apply(inout bit<8> v, out bit<8> rv) { v = 8w0; rv = v; }
    };
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_active) active_read  = {
        void apply(inout bit<8> v, out bit<8> rv) { rv = v; }
    };

    /* ---- counters (Stats ALU; multi-site OK) ---- */
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_seed_new;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_seed_dup;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_seed_badorigin;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_loop_persist;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_loop_adopt;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_term_retire;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_ack_hold;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_ack_failopen;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_resp_hold;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_resp_failopen;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_arm;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_cleanup;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_bypass;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_drop_badport;

    /* ---- TM actions ---- */
    action to_block() {                       /* enqueue Q_BLOCK (reservoir) on dp8 */
        ig_tm_md.ucast_egress_port = PORT_L;
        ig_tm_md.qid               = QID_BLOCK;
        ig_tm_md.bypass_egress     = 1w1;
    }
    action to_hold() {                        /* enqueue Q_HOLD (behind the reservoir) */
        ig_tm_md.ucast_egress_port = PORT_L;
        ig_tm_md.qid               = QID_HOLD;
        ig_tm_md.bypass_egress     = 1w1;
    }
    action to_fwd() {                         /* transparent forward to the peer port */
        ig_tm_md.ucast_egress_port = meta.fwd_port;
        ig_tm_md.qid               = 5w0;
        ig_tm_md.bypass_egress     = 1w0;
    }
    action drop_pkt() { ig_dprsr_md.drop_ctl = 3w1; }

    /* [P4] STAMP a freshly admitted token in the DATA PLANE: identity from the pktgen
     * header (domain, tokid) and epoch from reg_gen (gen_cur), plus the marker.
     * Independent field writes -> one action. */
    action admit_token() {
        hdr.token.setValid();
        hdr.token.marker = TOKEN_MARKER;
        hdr.token.domain = meta.domain;
        hdr.token.gen    = meta.gen_cur;
        hdr.token.tokid  = meta.tokid;
        hdr.timer.setInvalid();               /* strip the pktgen prefix before recirc */
    }
    action adopt_epoch() { hdr.token.gen = meta.gen_cur; }  /* re-stamp on epoch change */

    apply {
        if (meta.port_ok == 8w0) {
            ctr_drop_badport.count(1w0);
            drop_pkt();
        } else if (meta.role == ROLE_TOKEN) {
            /* ================= reservoir token ================= */
            if (meta.is_first == 8w1) {
                /* ---- [P1] first appearance: from the pktgen source ---- */
                /* identity derived in the MAU (independent single-ops from the header) */
                meta.domain   = (bit<8>)hdr.timer.app_id;
                meta.tokid    = hdr.timer.packet_id;
                meta.dom_idx  = hdr.timer.app_id[0:0];
                meta.pres_idx = hdr.timer.app_id[0:0] ++ hdr.timer.packet_id[5:0];
                meta.present_old = present_admit.execute(meta.pres_idx);
                meta.gen_cur     = gen_read.execute(1w0);
                if (meta.present_old == 8w0) {
                    /* [P2] an empty slot: a distinct token. count once, [P4] stamp, admit */
                    meta.pop_val = pop_incr.execute(meta.dom_idx);
                    admit_token();
                    to_block();
                    ctr_seed_new.count(1w0);
                } else {
                    /* a periodic re-fire of a still-live id: dedup, do not double-count */
                    drop_pkt();
                    ctr_seed_dup.count(1w0);
                }
            } else if (meta.is_loop == 8w1) {
                /* ---- recirculation pass (NEVER counted here) ---- */
                meta.domain     = hdr.token.domain;
                meta.dom_idx    = hdr.token.domain[0:0];
                meta.pres_idx   = hdr.token.domain[0:0] ++ hdr.token.tokid[5:0];
                meta.gen_cur    = gen_read.execute(1w0);
                meta.retire_val = retire_read.execute(meta.dom_idx);
                if (meta.retire_val == RETIRE_ON) {
                    /* [P6] domain retired: terminate. clear own cell + decrement own
                     * domain's count ONLY; touch no other token and not reg_gen. The
                     * periodic source re-seeds the freed slot. */
                    meta.pres_cleared = present_clear.execute(meta.pres_idx);
                    if (meta.pres_cleared == 8w1) { meta.pop_val = pop_decr.execute(meta.dom_idx); }
                    drop_pkt();
                    ctr_term_retire.count(1w0);
                } else if (hdr.token.gen == meta.gen_cur) {
                    /* persist: still the current epoch, re-enqueue (no self-draining budget) */
                    to_block();
                    ctr_loop_persist.count(1w0);
                } else {
                    /* [P4] persist + ADOPT: the epoch advanced; re-stamp and re-enqueue */
                    adopt_epoch();
                    to_block();
                    ctr_loop_adopt.count(1w0);
                }
            } else {
                /* [P1] a 0x88C1 frame from a HOST port: reject (bad origin) */
                drop_pkt();
                ctr_seed_badorigin.count(1w0);
            }
        } else if (meta.role == ROLE_ARM) {
            /* ================= host READ: open/advance a transaction ================= */
            meta.gen_cur    = gen_bump.execute(1w0);      /* new epoch (benign wrap)  */
            meta.active_val = active_set.execute(1w0);    /* [P8] restoration is O(1) */
            to_fwd();
            ctr_arm.count(1w0);
        } else if (meta.role == ROLE_CLEANUP) {
            /* ================= host FIN/RST: bounded, NON-draining cleanup ================= */
            meta.active_val = active_clear.execute(1w0);  /* [P8] one write; pool persists */
            to_fwd();
            ctr_cleanup.count(1w0);
        } else if (meta.role == ROLE_ACK) {
            /* ================= host ACK: readiness-gated admission ================= */
            meta.pop_val    = pop_read.execute(1w0);      /* DOMAIN_ACK reservoir */
            meta.active_val = active_read.execute(1w0);
            if (meta.pop_val == K_TOKENS) { meta.ready = 8w1; }   /* [P3] */
            if (meta.ready == 8w1 && meta.active_val == 8w1 && meta.from_out == 8w1) {
                to_hold();                                        /* protected admission */
                ctr_ack_hold.count(1w0);
            } else {
                /* [P5/P7] not ready / inactive / wrong direction: forward (fail open),
                 * never enqueue behind an unready reservoir => the ACK is not stranded. */
                to_fwd();
                ctr_ack_failopen.count(1w0);
            }
        } else if (meta.role == ROLE_RESP) {
            /* ================= host RESPONSE: readiness-gated admission ================= */
            meta.pop_val    = pop_read.execute(1w1);      /* DOMAIN_RESP reservoir */
            meta.active_val = active_read.execute(1w0);
            if (meta.pop_val == K_TOKENS) { meta.ready = 8w1; }   /* [P3] */
            if (meta.ready == 8w1 && meta.active_val == 8w1 && meta.from_out == 8w1) {
                to_hold();
                ctr_resp_hold.count(1w0);
            } else {
                to_fwd();
                ctr_resp_failopen.count(1w0);
            }
        } else {
            /* ================= ROLE_BYPASS ================= */
            to_fwd();
            ctr_bypass.count(1w0);
        }
    }
}

/* ============================ ingress deparser ========================== */
control IgDeparser(packet_out pkt,
                   inout headers_t hdr,
                   in    ig_meta_t meta,
                   in    ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    apply {
        /* emission order == extraction order (byte-preserving for host frames). The
         * pktgen timer prefix is invalidated on admission, so it never egresses. Exactly
         * one of {token} / {ipv4 ...} is valid on any frame. */
        pkt.emit(hdr.eth);
        pkt.emit(hdr.token);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.tcp_opt12);
        pkt.emit(hdr.dnp3_dl);
        pkt.emit(hdr.dnp3_tp);
        pkt.emit(hdr.dnp3_app);
    }
}

/* ============================ egress (byte-preserving pass-through) ====== */
struct eg_meta_t { }
parser EgParser(packet_in pkt,
                out headers_t hdr,
                out eg_meta_t meta,
                out egress_intrinsic_metadata_t eg_intr_md) {
    state start { pkt.extract(eg_intr_md); transition parse_eth; }
    state parse_eth { pkt.extract(hdr.eth); transition accept; }
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
    apply { pkt.emit(hdr.eth); }
}

/* ============================ pipeline ================================== */
Pipeline(IgParser(), Ingress(), IgDeparser(),
         EgParser(), Egress(), EgDeparser()) pipe;

Switch(pipe) main;

/* ============================================================================
 * bootstrap_probe_v5.p4 — Defense 4 §3 reservoir bootstrap, v5
 *   SINGLE-PASS SHADOW STAGING (v4) + a PACKED ATOMIC {active,generation} word,
 *   loopback-shim held-RESP generation, and a full retirement lifecycle.
 *
 * v5 is v4 (bootstrap_probe_v4.p4) with five additions. v4 already PLACES at 12/12
 * ingress stages; v5's structural goal is to shorten the register chain (target ~10).
 *
 * === A. LOOPBACK-GENERATION SHIM (reg_resp_gen DELETED) ===
 *   The held-RESP's generation is carried on the loopback copy in a prepended shim
 *   (header shim_h, etype ETHERTYPE_HELD_RESP=0x88C3, field gen). Gen-qualified cleanup
 *   at completion compares the shim's gen to the stored generation (done ATOMICALLY inside
 *   reg_txn's SALU: v == (CONF|shim.gen)) instead of reading a reg_resp_gen register.
 *   The shim is STRIPPED (setInvalid) before forwarding, so the frame the master sees is
 *   byte-identical to the original RESPONSE. Each held RESP carries its OWN generation, so
 *   overlapping transactions cannot mis-clear each other.
 *
 * === B. EARLY ATOMIC READ-ADMISSION GUARD (reg_gen + reg_active MERGED -> reg_txn) ===
 *   reg_txn (bit<32>) = { active(bit31), generation(bits[30:0]) }, generation in
 *   [1,0x7FFFFFFF] so bit31 is free for active. Read ONCE at the top of apply on every
 *   path. cur_gen/active are METADATA SLICES of the read word (legal in the MAU; the
 *   bf-asm slice/mask ban is only INSIDE a stateful compare).
 *   A READ (ROLE_ARM) does an ATOMIC open RMW (txn_open): if NOT active -> next(gen),
 *   skip 0, set active; if ALREADY active -> NO-OP (gen+active unchanged) and count
 *   ctr_overlap. The in-SALU active test is the UNSIGNED MAGNITUDE compare (v < 0x80000000
 *   == active bit clear); the open advance+set is ONE add (v += 0x80000001), wrap at
 *   GEN_MAX -> 0x80000001. PROBED and PROVEN to assemble on bf-p4c 9.13.1 (tofino.bin);
 *   no fallback needed. Because active is read at the SAME early stage as gen, the
 *   READ-path resets (stage/pop/failopen) are GATED on the pre-open active, so an
 *   OVERLAPPING READ leaves generation, counts, identities, shadow, fail-open and active
 *   ALL unchanged.
 *
 * === C/D. RETIREMENT LIFECYCLE + INACTIVE BEHAVIOR ===
 *   Retirement = clearing reg_txn's active bit (generation preserved). It happens on:
 *   (1) a HELD RESP's authenticated loopback completion (gen-qualified via the shim), and
 *   (2) a FORWARDED (fail-open / bypass) RESP — which is routed onto the SAME loopback-shim
 *       path so its retire is a single gen-qualified reg_txn access on a FRESH pass. This
 *       is the key structural move: the native pass makes the hold/forward decision LATE
 *       (after the pop pivot), which cannot write the EARLY single-stage reg_txn; deferring
 *       the retire to the shim'd loopback pass keeps reg_txn at ONE depth and <=1 access per
 *       packet-path (READ=open; loopback-RESP=complete/retire; CLEANUP=clear; else=read).
 *   An early ACK/RESP (unready) latches generation-qualified fail-open (kept from v4). A
 *   fail-open RESP forwards AND retires; a HELD RESP retires ONLY at completion. After
 *   retirement active==0, so a duplicate/late native ACK/RESP fails open (never re-holds);
 *   only a READ re-opens. Loopback tokens and pktgen seeds are DROPPED while active==0
 *   (no re-enqueue, no re-seed) -> the <=2K resident blockers drain within one loop period.
 *   Stale (gen-mismatch) loopback tokens are dropped BEFORE any ident/pop access.
 *
 *   ►► LOAD-BEARING §4 DEPENDENCY (adversarially reviewed; do NOT read C/D as self-contained):
 *   a genuinely-HELD RESP is enqueued to qid4 (LOWEST strict priority), and the reservoir is
 *   sized (K=64, Little's law) precisely to keep qid7/qid5 CONTINUOUSLY queue-resident — so by
 *   strict priority qid4 STARVES. Its completion (hence retire) therefore happens ONLY when the
 *   §4 DEADLINE release drains the reservoir and dequeues qid4. The retire is correctly WIRED to
 *   that release (the held packet is already queued with its shim + PORT_L egress, so on qid4
 *   dequeue it loops, runs txn_complete, retires, strips the shim, and reaches the master
 *   byte-identical). BUT:
 *     - IN §3 (no deadline modeled) a held RESP NEVER completes, so after the FIRST successful
 *       hold, active stays set and the overlap guard no-ops every subsequent READ -> further
 *       transactions re-hold on the starved qid4 and the master receives nothing = FAIL-CLOSED
 *       (worse than the missing-RESP case, which is fail-open). §3-in-isolation is correct only
 *       for a SINGLE transaction and for the fail-open paths.
 *     - HARD §4 REQUIREMENT: the deadline release must fire, and DEADLINE < POLL INTERVAL (the
 *       held RESP must retire before the next READ). If violated (or on a READ retransmit
 *       mid-transaction), the overlap guard degrades to a fail-CLOSED held pileup, NOT fail-open.
 *       A §4 bounded-transaction watchdog is also needed to clear a stranded active on a
 *       never-answered poll (the MISSING-RESP case: fail-open, self-heals only if the next RESP
 *       takes the qid7 retire path — a ready next txn instead re-enters the qid4 wedge).
 *   v4's unconditional re-open MASKED all of this (it reset every transaction on every READ, at
 *   the cost of clobbering an in-flight transaction — the very thing B's guard correctly fixes).
 *   So v5's guard is a genuine correctness improvement that EXPOSED this latent §4 dependency.
 *   (Minor: a FORWARDED RESP's qid7 retire adds one loop-RTT of latency before the master hop.)
 *
 * === E. v4 CONTRACT PRESERVED ===
 *   RESP-only shadow reg_resp_stage gates ONLY ACK seeding; reg_pop_packed is the
 *   authoritative packed K/K (atomic == 0x00400040), read once by native admission. Per-role
 *   generation-qualified identity cells reg_ident_resp/reg_ident_ack (two-comparator seed
 *   dedup, load-bearing). Four queues qid 7/6/5/4. Token identity validated before any cell
 *   access; host-origin 0x88C1 dropped. Every metadata field initialized on every parser
 *   path. Native ACK holds only at pop==K/K && active && !fail-open-latched.
 *
 * SCOPE / NOT CLAIMED. §3 feasibility probe: NOT the timing core, does NOT patch
 * defense4_timing.p4, NOT loaded, NOT run. Shows the contract PLACES and is self-consistent;
 * NOT that it works on silicon. R11 (staged establishment reaches/holds K/K within CLRT)
 * stays OPEN.
 * ==========================================================================*/
#include <core.p4>
#include <tna.p4>

const bit<16> ETHERTYPE_TOKEN     = 0x88C1;
const bit<16> ETHERTYPE_HELD_RESP = 0x88C3;   /* v5: loopback held-RESP / retire shim */
const bit<16> ETHERTYPE_IPV4      = 0x0800;
const bit<8>  IP_PROTO_TCP         = 8w6;

const bit<16> DNP3_START       = 0x0564;
const bit<8>  DNP3_FC_READ      = 8w1;
const bit<8>  DNP3_FC_RESPONSE  = 8w129;

const PortId_t PORT_L      = 9w8;
const PortId_t PORT_MASTER = 9w9;
const PortId_t PORT_RELAY  = 9w64;
const PortId_t PORT_PGEN   = 9w68;

/* static strict-priority ladder 7 > 6 > 5 > 4 */
const bit<5> Q_ACK_BLOCK  = 5w7;
const bit<5> Q_ACK_HOLD    = 5w6;
const bit<5> Q_RESP_BLOCK = 5w5;
const bit<5> Q_RESP_HOLD    = 5w4;

const bit<16> K_TOKENS   = 16w64;
const bit<32> BOTH_READY = 32w0x00400040;   /* authoritative packed K/K */
const bit<32> DELTA_ACK_UP  = 32w0x00010000;
const bit<32> DELTA_RESP_UP = 32w0x00000001;

const bit<8> TOKEN_MARKER = 8w0xE1;
const bit<8> SD_LOOP      = 8w0x5A;
const bit<8> TOK_ACK      = 8w0xA1;
const bit<8> TOK_RESP     = 8w0xA2;

/* reg_txn packing: bit31 = active, bits[30:0] = generation in [1, 0x7FFFFFFF] */
const bit<32> GEN_MAX     = 32w0x7FFFFFFF;   /* max generation (bit31 clear) */
const bit<32> CONF_BIT    = 32w0x80000000;   /* active bit (also CONFIRMED marker on ident) */
const bit<32> GEN_MASK    = 32w0x7FFFFFFF;   /* clear active, keep generation */
const bit<32> OPEN_ADD    = 32w0x80000001;   /* +1 generation AND set active, in one SALU add */

const bit<8> R_SEEDED = 8w1;
const bit<8> R_DEDUP  = 8w0;
const bit<8> R_FIRST  = 8w1;
const bit<8> R_AGAIN  = 8w0;

const bit<8> ROLE_BYPASS  = 8w0;
const bit<8> ROLE_TOKEN   = 8w1;
const bit<8> ROLE_ACK     = 8w2;
const bit<8> ROLE_RESP    = 8w3;
const bit<8> ROLE_ARM     = 8w6;
const bit<8> ROLE_CLEANUP = 8w7;

/* ============================ headers ==================================== */
header shim_h { bit<48> dst; bit<48> src; bit<16> etype; bit<32> gen; }  /* v5 prepended */
header ethernet_h { bit<48> dst; bit<48> src; bit<16> etype; }
header token_h {
    bit<8>  marker;
    bit<8>  sdomain;
    bit<8>  role;
    bit<32> generation;
    bit<16> token_id;
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
header tcp_opt12_h { bit<96> data; }
header dnp3_dl_h {
    bit<16> start; bit<8> length; bit<8> ctrl;
    bit<16> dst_addr; bit<16> src_addr; bit<16> crc;
}
header dnp3_tp_h  { bit<8> tp_ctrl; }
header dnp3_app_h { bit<8> app_control; bit<8> func_code; }

struct headers_t {
    pktgen_timer_header_t timer;
    shim_h      shim;         /* v5: valid only on held-RESP / retire loopback copies */
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
    /* origin/classification — written on EVERY parser path */
    bit<8>  role;
    bit<8>  port_ok;
    bit<9>  fwd_port;
    bit<8>  is_first;
    bit<8>  is_loop;
    bit<8>  from_out;

    /* MAU-derived (also init in start) */
    bit<8>  tok_valid;
    bit<1>  role_bit;
    bit<8>  tok_role;
    bit<16> token_id;
    bit<32> txn_old;         /* reg_txn read/old word { active, generation } */
    bit<32> cur_gen;         /* txn_old[30:0]  (generation, bit31=0) */
    bit<32> cur_gen_conf;    /* cur_gen | CONF_BIT — CONFIRMED(cur_gen) for seed dedup */
    bit<8>  active;          /* txn_old[31:31] — 1 = transaction active */
    bit<16> stage_val;       /* reg_resp_stage read (shadow) */
    bit<8>  ident_res;
    bit<32> pop_packed;
    bit<32> pop_delta;
    bit<8>  ready;           /* 1 = (pop_packed == BOTH_READY) && active */
    bit<1>  fo_eq;           /* 1 = (failopen_old == cur_gen) */
    bit<32> shim_gen_active; /* shim.gen (= CONF|cur_gen, stamped) — completion clear key */
}

/* ============================ ingress parser ============================ */
parser IgParser(packet_in pkt,
                out headers_t hdr,
                out ig_meta_t meta,
                out ingress_intrinsic_metadata_t ig_intr_md) {

    value_set<bit<8>>(2) pgen_timer;

    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        meta.tok_valid       = 8w0;
        meta.role_bit        = 1w0;
        meta.tok_role        = 8w0;
        meta.token_id        = 16w0;
        meta.txn_old         = 32w0;
        meta.cur_gen         = 32w0;
        meta.cur_gen_conf    = 32w0;
        meta.active          = 8w0;
        meta.stage_val       = 16w0;
        meta.ident_res       = 8w0;
        meta.pop_packed      = 32w0;
        meta.pop_delta       = 32w0;
        meta.ready           = 8w0;
        meta.fo_eq           = 1w0;
        meta.shim_gen_active = 32w0;
        transition select(ig_intr_md.ingress_port) {
            PORT_PGEN   : from_pgen;
            PORT_L      : from_loop;
            PORT_MASTER : from_master;
            PORT_RELAY  : from_relay;
            default     : bad_port;
        }
    }

    state bad_port {
        meta.role = ROLE_BYPASS; meta.port_ok = 8w0; meta.fwd_port = 9w0;
        meta.is_first = 8w0; meta.is_loop = 8w0; meta.from_out = 8w0;
        transition accept;
    }
    state from_loop {
        meta.port_ok = 8w1; meta.fwd_port = PORT_MASTER;
        meta.is_first = 8w0; meta.is_loop = 8w1; meta.from_out = 8w0;
        /* first ethernet-shaped etype selects: 0x88C3 -> shim (held-RESP/retire),
         * else (0x88C1 token / 0x0800 held-ACK) -> parse_eth directly. */
        transition select(pkt.lookahead<ethernet_h>().etype) {
            ETHERTYPE_HELD_RESP : parse_shim;
            default             : parse_eth;
        }
    }
    state parse_shim {
        pkt.extract(hdr.shim);
        /* shim.gen is stamped as the CONFIRMED form (CONF | cur_gen) at admission, so this is
         * exactly the completion clear key with NO parser/MAU OR (parser OR-const ICEs 9.13.1;
         * an MAU OR costs reg_txn a stage). gen-qualification shim.gen[30:0]==cur_gen holds. */
        meta.shim_gen_active = hdr.shim.gen;
        transition parse_eth;            /* inner real eth follows */
    }
    state from_master {
        meta.port_ok = 8w1; meta.fwd_port = PORT_RELAY;
        meta.is_first = 8w0; meta.is_loop = 8w0; meta.from_out = 8w0;
        transition parse_eth;
    }
    state from_relay {
        meta.port_ok = 8w1; meta.fwd_port = PORT_MASTER;
        meta.is_first = 8w0; meta.is_loop = 8w0; meta.from_out = 8w1;
        transition parse_eth;
    }
    state from_pgen {
        transition select(pkt.lookahead<bit<8>>()) {
            pgen_timer : parse_timer;
            default    : pgen_bad;
        }
    }
    state pgen_bad {
        meta.role = ROLE_BYPASS; meta.port_ok = 8w0; meta.fwd_port = 9w0;
        meta.is_first = 8w1; meta.is_loop = 8w0; meta.from_out = 8w0;
        transition accept;
    }
    state parse_timer {
        pkt.extract(hdr.timer);
        meta.port_ok = 8w1; meta.fwd_port = PORT_MASTER;
        meta.is_first = 8w1; meta.is_loop = 8w0; meta.from_out = 8w0;
        transition parse_eth;
    }

    state parse_eth {
        pkt.extract(hdr.eth);
        transition select(hdr.eth.etype) {
            ETHERTYPE_TOKEN : parse_token;
            ETHERTYPE_IPV4  : parse_ipv4;
            default         : set_bypass;
        }
    }
    state parse_token { pkt.extract(hdr.token); meta.role = ROLE_TOKEN; transition accept; }
    state set_bypass  { meta.role = ROLE_BYPASS; transition accept; }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol, hdr.ipv4.ihl) {
            (IP_PROTO_TCP, 4w5) : parse_tcp;
            default             : set_bypass;
        }
    }
    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition select(hdr.tcp.flags, hdr.tcp.data_offset, hdr.ipv4.total_len) {
            (8w0x01 &&& 8w0x01, 4w0 &&& 4w0, 16w0 &&& 16w0) : set_role_cleanup;
            (8w0x04 &&& 8w0x04, 4w0 &&& 4w0, 16w0 &&& 16w0) : set_role_cleanup;
            (8w0x10 &&& 8w0x17, 4w5, 16w40)                 : set_role_ack;
            (8w0x10 &&& 8w0x17, 4w8, 16w52)                 : set_role_ack;
            (8w0x00 &&& 8w0x07, 4w5, 16w53 .. 16w65535)     : parse_dnp3_dl;
            (8w0x00 &&& 8w0x07, 4w8, 16w65 .. 16w65535)     : opt12_dnp3;
            default                                         : set_bypass;
        }
    }
    state opt12_dnp3 { pkt.extract(hdr.tcp_opt12); transition parse_dnp3_dl; }
    state set_role_ack     { meta.role = ROLE_ACK;     transition accept; }
    state set_role_cleanup { meta.role = ROLE_CLEANUP; transition accept; }
    state parse_dnp3_dl {
        pkt.extract(hdr.dnp3_dl);
        transition select(hdr.dnp3_dl.start, hdr.dnp3_dl.length) {
            (DNP3_START, 8w8 .. 8w255) : parse_dnp3_tp;
            default                    : set_bypass;
        }
    }
    state parse_dnp3_tp { pkt.extract(hdr.dnp3_tp); transition parse_dnp3_app; }
    state parse_dnp3_app {
        pkt.extract(hdr.dnp3_app);
        transition select(hdr.dnp3_app.app_control, hdr.dnp3_app.func_code) {
            (8w0x00 &&& 8w0x00, DNP3_FC_RESPONSE) : set_role_resp;
            (8w0xC0 &&& 8w0xF0, DNP3_FC_READ)     : set_role_arm;
            default                               : set_bypass;
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

    /* ==== state order: txn < ident_resp < resp_stage < ident_ack < pop < failopen ==== */

    /* B: PACKED ATOMIC {active(bit31), generation(bits[30:0])}. Read once per path. */
    Register<bit<32>, bit<1>>(1, 0) reg_txn;
    /* READ: atomic conditional open. NOT active (v < CONF_BIT) -> next(gen) skip 0, set
     * active (v += OPEN_ADD, wrap GEN_MAX -> 0x80000001). Already active -> NO-OP. Returns
     * OLD word so the caller sees pre-open active for overlap gating. PROBED to assemble. */
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_txn) txn_open = {
        void apply(inout bit<32> v, out bit<32> rv) {
            rv = v;
            if (v < CONF_BIT) {
                if (v == GEN_MAX) { v = CONF_BIT | 32w1; }
                else              { v = v + OPEN_ADD; }
            }
        }
    };
    /* establishment + native: plain read (gives active + generation) */
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_txn) txn_read = {
        void apply(inout bit<32> v, out bit<32> rv) { rv = v; }
    };
    /* completion / fail-open-retire: gen-qualified atomic clear. Clears active iff the word
     * is active AND its generation == shim.gen (v == CONF|shim.gen), keeping the generation
     * (v & GEN_MASK). Full-word mem-vs-PHV compare -> no masked/slice compare. Idempotent. */
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_txn) txn_complete = {
        void apply(inout bit<32> v, out bit<32> rv) {
            rv = v;
            if (v == meta.shim_gen_active) { v = v & GEN_MASK; }
        }
    };
    /* FIN/RST teardown: unconditional active clear, generation preserved (v & GEN_MASK). */
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_txn) txn_clear_fin = {
        void apply(inout bit<32> v, out bit<32> rv) { v = v & GEN_MASK; rv = v; }
    };

    /* per-role identity cells (generation, bit31 = confirmed; EMPTY=0) */
    Register<bit<32>, bit<6>>(64, 0) reg_ident_resp;
    RegisterAction<bit<32>, bit<6>, bit<8>>(reg_ident_resp) ident_resp_seed = {
        void apply(inout bit<32> v, out bit<8> rv) {
            /* two full-word comparators (SEEDED or CONFIRMED of cur_gen) — bit-identical to
             * the masked compare (v & GEN_MASK)==cur_gen, which bf-asm cannot assemble. */
            if (v == meta.cur_gen)           { rv = R_DEDUP; }
            else if (v == meta.cur_gen_conf) { rv = R_DEDUP; }
            else { v = meta.cur_gen; rv = R_SEEDED; }
        }
    };
    RegisterAction<bit<32>, bit<6>, bit<8>>(reg_ident_resp) ident_resp_confirm = {
        void apply(inout bit<32> v, out bit<8> rv) {
            if (v == meta.cur_gen) { v = meta.cur_gen | CONF_BIT; rv = R_FIRST; }
            else { rv = R_AGAIN; }
        }
    };

    /* RESP-only SHADOW count — opens ACK seeding ONLY (never authorizes a native packet) */
    Register<bit<16>, bit<1>>(1, 0) reg_resp_stage;
    RegisterAction<bit<16>, bit<1>, bit<16>>(reg_resp_stage) stage_incr = {
        void apply(inout bit<16> v, out bit<16> rv) { v = v + 16w1; rv = v; }
    };
    RegisterAction<bit<16>, bit<1>, bit<16>>(reg_resp_stage) stage_read = {
        void apply(inout bit<16> v, out bit<16> rv) { rv = v; }
    };
    RegisterAction<bit<16>, bit<1>, bit<16>>(reg_resp_stage) stage_reset = {
        void apply(inout bit<16> v, out bit<16> rv) { v = 16w0; rv = v; }
    };

    Register<bit<32>, bit<6>>(64, 0) reg_ident_ack;
    RegisterAction<bit<32>, bit<6>, bit<8>>(reg_ident_ack) ident_ack_seed = {
        void apply(inout bit<32> v, out bit<8> rv) {
            if (v == meta.cur_gen)           { rv = R_DEDUP; }
            else if (v == meta.cur_gen_conf) { rv = R_DEDUP; }
            else { v = meta.cur_gen; rv = R_SEEDED; }
        }
    };
    RegisterAction<bit<32>, bit<6>, bit<8>>(reg_ident_ack) ident_ack_confirm = {
        void apply(inout bit<32> v, out bit<8> rv) {
            if (v == meta.cur_gen) { v = meta.cur_gen | CONF_BIT; rv = R_FIRST; }
            else { rv = R_AGAIN; }
        }
    };

    /* AUTHORITATIVE packed population {ack(hi16), resp(lo16)} */
    Register<bit<32>, bit<1>>(1, 0) reg_pop_packed;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_pop_packed) pop_incr = {
        void apply(inout bit<32> v, out bit<32> rv) { v = v + meta.pop_delta; rv = v; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_pop_packed) pop_read = {
        void apply(inout bit<32> v, out bit<32> rv) { rv = v; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_pop_packed) pop_reset = {
        void apply(inout bit<32> v, out bit<32> rv) { v = 32w0; rv = v; }
    };

    /* generation-qualified fail-open latch (kept from v4 FIX-ACK/FIX-RESP) */
    Register<bit<32>, bit<1>>(1, 0) reg_failopen;
    RegisterAction<bit<32>, bit<1>, bit<8>>(reg_failopen) failopen_rmw = {
        void apply(inout bit<32> v, out bit<8> rv) {
            if (v == meta.cur_gen) { rv = 8w1; } else { rv = 8w0; }
            if (meta.ready == 8w0) { v = meta.cur_gen; }
        }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_failopen) failopen_reset = {
        void apply(inout bit<32> v, out bit<32> rv) { v = 32w0; rv = v; }
    };

    /* ---- counters (load-bearing observability set, as v4) ---- */
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_seed_new;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_confirm_resp;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_confirm_ack;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_term_stale;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_resp_complete_stale;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_overlap;

    /* ---- TM actions ---- */
    action to_ack_block()  { ig_tm_md.ucast_egress_port = PORT_L; ig_tm_md.qid = Q_ACK_BLOCK;  ig_tm_md.bypass_egress = 1w1; }
    action to_ack_hold()   { ig_tm_md.ucast_egress_port = PORT_L; ig_tm_md.qid = Q_ACK_HOLD;   ig_tm_md.bypass_egress = 1w1; }
    action to_resp_block() { ig_tm_md.ucast_egress_port = PORT_L; ig_tm_md.qid = Q_RESP_BLOCK; ig_tm_md.bypass_egress = 1w1; }
    action to_fwd()        { ig_tm_md.ucast_egress_port = meta.fwd_port; ig_tm_md.qid = 5w0; ig_tm_md.bypass_egress = 1w0; }
    action drop_pkt()      { ig_dprsr_md.drop_ctl = 3w1; }

    action admit_stamp() {
        hdr.token.setValid();
        hdr.token.marker     = TOKEN_MARKER;
        hdr.token.sdomain    = SD_LOOP;
        hdr.token.role       = meta.tok_role;
        hdr.token.generation = meta.cur_gen;
        hdr.token.token_id   = meta.token_id;
        hdr.timer.setInvalid();
    }

    action app_ack()  { meta.tok_role = TOK_ACK;  meta.role_bit = 1w0; }
    action app_resp() { meta.tok_role = TOK_RESP; meta.role_bit = 1w1; }
    table tbl_app_role {
        key = { hdr.timer.app_id : exact; }
        actions = { app_ack; app_resp; }
        const default_action = app_ack();
        const entries = { (3w0) : app_ack(); (3w1) : app_resp(); }
        size = 2;
    }

    action mark_tokid_ok()  { meta.tok_valid = 8w1; }
    action mark_tokid_bad() { meta.tok_valid = 8w0; }
    table tbl_tokid_valid {
        key = { hdr.timer.packet_id : ternary; }
        actions = { mark_tokid_ok; mark_tokid_bad; }
        const default_action = mark_tokid_bad();
        const entries = { (16w0 &&& 16w0xFFC0) : mark_tokid_ok(); }
        size = 2;
    }

    action valid_ack()  { meta.tok_valid = 8w1; meta.role_bit = 1w0; }
    action valid_resp() { meta.tok_valid = 8w1; meta.role_bit = 1w1; }
    action valid_bad()  { meta.tok_valid = 8w0; }
    table tbl_token_valid {
        key = {
            hdr.token.marker   : exact;
            hdr.token.sdomain  : exact;
            hdr.token.role     : exact;
            hdr.token.token_id : ternary;
        }
        actions = { valid_ack; valid_resp; valid_bad; }
        const default_action = valid_bad();
        const entries = {
            (TOKEN_MARKER, SD_LOOP, TOK_ACK,  16w0 &&& 16w0xFFC0) : valid_ack();
            (TOKEN_MARKER, SD_LOOP, TOK_RESP, 16w0 &&& 16w0xFFC0) : valid_resp();
        }
        size = 4;
    }

    /* Native ACK/RESPONSE decision, keyed on {role, ready, fo_eq}.
     *   ACK  : ready && !fo -> hold; else fwd (fail-open).
     *   RESP : ready && !fo -> HOLD (shim, PORT_L, retire at completion);
     *          else (forwarded: fail-open or already-failed) -> shim + loopback RETIRE. */
    DirectCounter<bit<64>>(CounterType_t.PACKETS) ctr_native;
    action nd_hold_ack()  { to_ack_hold(); ctr_native.count(); }
    action nd_fwd_ack()   { to_fwd();       ctr_native.count(); }
    action nd_hold_resp() {                 /* held: shim + Q_RESP_HOLD; retire on completion */
        hdr.shim.setValid();
        hdr.shim.dst = 48w0; hdr.shim.src = 48w0;
        hdr.shim.etype = ETHERTYPE_HELD_RESP; hdr.shim.gen = meta.cur_gen_conf;
        ig_tm_md.ucast_egress_port = PORT_L; ig_tm_md.qid = Q_RESP_HOLD; ig_tm_md.bypass_egress = 1w1;
        ctr_native.count();
    }
    action nd_retire_resp() {               /* forwarded RESP: shim + fast loopback -> retire */
        hdr.shim.setValid();
        hdr.shim.dst = 48w0; hdr.shim.src = 48w0;
        hdr.shim.etype = ETHERTYPE_HELD_RESP; hdr.shim.gen = meta.cur_gen_conf;
        ig_tm_md.ucast_egress_port = PORT_L; ig_tm_md.qid = Q_ACK_BLOCK; ig_tm_md.bypass_egress = 1w1;
        ctr_native.count();
    }
    table tbl_native_decide {
        key = { meta.role : exact; meta.ready : exact; meta.fo_eq : exact; }
        actions = { nd_hold_ack; nd_fwd_ack; nd_hold_resp; nd_retire_resp; }
        counters = ctr_native;
        const default_action = nd_fwd_ack();
        const entries = {
            (ROLE_ACK,  8w1, 1w0) : nd_hold_ack();
            (ROLE_ACK,  8w1, 1w1) : nd_fwd_ack();
            (ROLE_ACK,  8w0, 1w0) : nd_fwd_ack();
            (ROLE_ACK,  8w0, 1w1) : nd_fwd_ack();
            (ROLE_RESP, 8w1, 1w0) : nd_hold_resp();
            (ROLE_RESP, 8w1, 1w1) : nd_retire_resp();
            (ROLE_RESP, 8w0, 1w0) : nd_retire_resp();
            (ROLE_RESP, 8w0, 1w1) : nd_retire_resp();
        }
        size = 8;
    }

    apply {
        if (meta.port_ok == 8w0) {
            drop_pkt();
        } else {
          /* ===== single reg_txn access per path, at the TOP ===== */
          /* only a MASTER-side READ (from_out==0) opens a transaction; a DNP3 READ arriving
           * from the relay side is anomalous and must NOT open (else it spuriously activates
           * and the overlap guard would then block real master READs). */
          if (meta.role == ROLE_ARM && meta.from_out == 8w0) {
              meta.txn_old = txn_open.execute(1w0);      /* atomic conditional open */
          } else if (meta.role == ROLE_RESP && meta.is_loop == 8w1) {
              meta.txn_old = txn_complete.execute(1w0);  /* gen-qualified atomic clear (retire) */
          } else if (meta.role == ROLE_CLEANUP) {
              meta.txn_old = txn_clear_fin.execute(1w0); /* unconditional active clear */
          } else {
              meta.txn_old = txn_read.execute(1w0);      /* establishment + native: read */
          }
          /* cur_gen (slice) and cur_gen_conf (OR) both derive DIRECTLY from txn_old, so they
           * compute in PARALLEL in one stage: txn_old|CONF == cur_gen|CONF (bit31 either way). */
          meta.cur_gen      = (bit<32>)meta.txn_old[30:0];
          meta.cur_gen_conf = meta.txn_old | CONF_BIT;
          meta.active       = (bit<8>)meta.txn_old[31:31];

          if (meta.role == ROLE_TOKEN) {
            if (meta.is_first == 8w1) {
                /* ===== PKTGEN ADMIT (staged, role-split) ===== */
                /* stateless validation runs BEFORE the active gate (parallel, early) so only
                 * the stateful seed access is gated on active — shortens the front chain. */
                meta.token_id = (bit<16>)hdr.timer.packet_id;
                tbl_app_role.apply();
                tbl_tokid_valid.apply();
                if (meta.active == 8w0) {
                    drop_pkt();                          /* D: no seeding while inactive */
                } else if (meta.tok_valid == 8w1) {
                    if (meta.role_bit == 1w1) {
                        meta.ident_res = ident_resp_seed.execute(meta.token_id[5:0]);
                        if (meta.ident_res == R_SEEDED) {
                            admit_stamp(); to_resp_block(); ctr_seed_new.count(1w0);
                        } else { drop_pkt(); }
                    } else {
                        meta.stage_val = stage_read.execute(1w0);
                        if (meta.stage_val == K_TOKENS) {
                            meta.ident_res = ident_ack_seed.execute(meta.token_id[5:0]);
                            if (meta.ident_res == R_SEEDED) {
                                admit_stamp(); to_ack_block(); ctr_seed_new.count(1w0);
                            } else { drop_pkt(); }
                        } else {
                            drop_pkt();
                        }
                    }
                } else {
                    drop_pkt();
                }
            } else if (meta.is_loop == 8w1) {
                /* ===== LOOPBACK TOKEN ===== */
                tbl_token_valid.apply();                 /* stateless: run before active gate */
                if (meta.active == 8w0) {
                    drop_pkt();                          /* D: inactive -> drain (no re-enqueue) */
                } else if (meta.tok_valid == 8w1) {
                    if (hdr.token.generation == meta.cur_gen) {
                        if (meta.role_bit == 1w1) {
                            meta.ident_res = ident_resp_confirm.execute(hdr.token.token_id[5:0]);
                            if (meta.ident_res == R_FIRST) {
                                meta.stage_val = stage_incr.execute(1w0);
                                meta.pop_delta = DELTA_RESP_UP;
                                meta.pop_packed = pop_incr.execute(1w0);
                                ctr_confirm_resp.count(1w0);
                            }
                            to_resp_block();
                        } else {
                            meta.ident_res = ident_ack_confirm.execute(hdr.token.token_id[5:0]);
                            if (meta.ident_res == R_FIRST) {
                                meta.pop_delta = DELTA_ACK_UP;
                                meta.pop_packed = pop_incr.execute(1w0);
                                ctr_confirm_ack.count(1w0);
                            }
                            to_ack_block();
                        }
                    } else {
                        drop_pkt(); ctr_term_stale.count(1w0);   /* stale gen: no cell touch */
                    }
                } else {
                    drop_pkt();
                }
            } else {
                drop_pkt();
            }
          } else if (meta.role == ROLE_ARM && meta.from_out == 8w0) {
            /* ===== master-side READ: open handled above; reset state ONLY on a fresh open ===== */
            if (meta.active == 8w0) {                    /* pre-open active (txn_old bit31) */
                stage_reset.execute(1w0);
                pop_reset.execute(1w0);
                failopen_reset.execute(1w0);
            } else {
                ctr_overlap.count(1w0);                  /* overlap: leave ALL state unchanged */
            }
            to_fwd();
          } else if (meta.role == ROLE_CLEANUP) {
            /* FIN/RST teardown: active cleared above (txn_clear_fin). */
            to_fwd();
          } else if (meta.role == ROLE_RESP && meta.is_loop == 8w1) {
            /* ===== held-RESP completion OR fail-open-retire (loopback): cleared above ===== */
            if (meta.txn_old == meta.shim_gen_active) {
                /* active AND stored gen == shim.gen -> retired (cleared above) */
            } else {
                ctr_resp_complete_stale.count(1w0);
            }
            hdr.shim.setInvalid();                       /* STRIP shim -> byte-identical RESP */
            to_fwd();
          } else if (meta.role == ROLE_ACK && meta.is_loop == 8w1) {
            to_fwd();                                     /* held ACK release (no retire) */
          } else if ((meta.role == ROLE_ACK || meta.role == ROLE_RESP) && meta.from_out == 8w1) {
            /* ===== native ACK / RESPONSE (shared reads: pop, failopen) ===== */
            meta.pop_packed = pop_read.execute(1w0);
            if (meta.pop_packed == BOTH_READY && meta.active == 8w1) { meta.ready = 8w1; }
            meta.fo_eq = (bit<1>)failopen_rmw.execute(1w0);   /* latch if !ready; gen-qualified */
            tbl_native_decide.apply();
          } else if (meta.is_first == 8w1) {
            drop_pkt();
          } else {
            to_fwd();
          }
        }
    }
}

/* ============================ ingress deparser ========================== */
control IgDeparser(packet_out pkt,
                   inout headers_t hdr,
                   in    ig_meta_t meta,
                   in    ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    apply {
        pkt.emit(hdr.shim);      /* v5: valid only on held-RESP / retire loopback copies */
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

/* ============================ egress pass-through ======================= */
struct eg_meta_t { }
parser EgParser(packet_in pkt, out headers_t hdr, out eg_meta_t meta,
                out egress_intrinsic_metadata_t eg_intr_md) {
    state start { pkt.extract(eg_intr_md); transition parse_eth; }
    state parse_eth { pkt.extract(hdr.eth); transition accept; }
}
control Egress(inout headers_t hdr, inout eg_meta_t meta,
               in    egress_intrinsic_metadata_t                 eg_intr_md,
               in    egress_intrinsic_metadata_from_parser_t     eg_prsr_md,
               inout egress_intrinsic_metadata_for_deparser_t    eg_dprsr_md,
               inout egress_intrinsic_metadata_for_output_port_t eg_oport_md) {
    apply { }
}
control EgDeparser(packet_out pkt, inout headers_t hdr, in eg_meta_t meta,
                   in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {
    apply { pkt.emit(hdr.eth); }
}

Pipeline(IgParser(), Ingress(), IgDeparser(),
         EgParser(), Egress(), EgDeparser()) pipe;
Switch(pipe) main;

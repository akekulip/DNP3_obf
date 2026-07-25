/* ============================================================================
 * p5_parser_padcode.p4 — VARIANT P5 of the stage-reclamation study.
 *
 * ONE ARCHITECTURAL VARIABLE vs P0 (ibspg_hold_response.p4):
 *   the ingress PRODUCES and CARRIES a size-normalization decision, but performs
 *   NO padding whatsoever.  Nothing else changes: the whole Part-12 HOLD_RESPONSE
 *   state machine below is byte-for-byte the P0 text.
 *
 * QUESTION THIS ANSWERS: does merely *deciding* to normalize — exporting a
 * normalize_size flag, a target-size code, and an oversize/fail-open flag —
 * cost an ingress MAU stage on a pipeline that is already at 12/12?
 *
 * MECHANISM: the decision is made ENTIRELY IN THE INGRESS PARSER and carried in
 * a 3-byte `padctl_h` bridge header.  The Part-13 finding (moving classification
 * into the parser shortened the ingress critical path) is the lever being tested
 * here.  The parser select on hdr.ib.role is the classifier; each leaf state
 * assigns each padctl field EXACTLY ONCE (Tofino parsers have no clear-on-write,
 * so a second assignment on the same path is a hard error — hence no init of
 * these fields in `start`, and one terminal state per decision).
 *
 * The header is emitted by the ingress deparser so the fields are live and
 * cannot be dead-code-eliminated; a deployment would strip it at the far edge.
 * It is NOT a claim about wire format — it is the cheapest way to keep the
 * exported decision observable to the compiler.
 *
 * Target: Tofino 1 (TNA), bf-p4c 9.13.1.  Compile-only; never loaded.
 * ==========================================================================*/
#include <core.p4>
#include <tna.p4>

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

const bit<8> SLOT0 = 8w0;

/* size-normalization decision codes (P5 carries them; it never acts on them) */
const bit<8> TCODE_NONE = 8w0;
const bit<8> TCODE_128  = 8w1;   /* the ONE fixed target state */

/* ============================ headers ==================================== */
header ethernet_h { bit<48> dst; bit<48> src; bit<16> etype; }
header ibspg_h    { bit<8> role; bit<8> slot; bit<8> gen; bit<32> seq; }

/* THE P5 ADDITION: parser-produced size-normalization decision. */
header padctl_h {
    bit<8> normalize;   /* 1 = this frame is a normalization candidate */
    bit<8> tcode;       /* target-size code (TCODE_128 = the one state) */
    bit<8> oversize;    /* 1 = fail open, frame already >= target       */
}

struct headers_t {
    ethernet_h eth;
    ibspg_h    ib;
    padctl_h   padctl;
}

struct ig_meta_t {
    bit<8>  dequeued;
    bit<32> ts32;
    bit<8>  budget_zero;

    bit<8>  gen_we;    bit<8>  gen_val;
    bit<8>  active_we; bit<8>  active_val;
    bit<8>  dl_we;     bit<32> dl_val;

    bit<8>  gen_now;
    bit<8>  active_now;
    bit<32> dl_now;

    bit<8>  gen_mismatch;
    bit<8>  ack_ok;
    bit<8>  dl_armed;
    bit<32> age;
    bit<8>  expired;

    bit<8>  ev_first_block;
    bit<8>  ev_ack_arm;
    bit<8>  ev_block_term;
    bit<8>  ev_resp_release;
}

/* ============================ ingress parser =============================
 * P0's parser plus THREE terminal states that produce the padctl decision.
 * Each padctl field is written exactly once on every path that reaches accept
 * through them; padctl is left INVALID on the non-IBSPG path (no write at all). */
parser IgParser(packet_in pkt,
                out headers_t hdr,
                out ig_meta_t meta,
                out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        meta.dequeued        = 8w0;
        meta.ts32            = 32w0;
        meta.budget_zero     = 8w0;
        meta.gen_we          = 8w0; meta.gen_val    = 8w0;
        meta.active_we       = 8w0; meta.active_val = 8w0;
        meta.dl_we           = 8w0; meta.dl_val     = 32w0;
        meta.gen_now         = 8w0;
        meta.active_now      = 8w0;
        meta.dl_now          = 32w0;
        meta.gen_mismatch    = 8w0;
        meta.ack_ok          = 8w0;
        meta.dl_armed        = 8w0;
        meta.age             = 32w0;
        meta.expired         = 8w0;
        meta.ev_first_block  = 8w0;
        meta.ev_ack_arm      = 8w0;
        meta.ev_block_term   = 8w0;
        meta.ev_resp_release = 8w0;
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
    /* PARSER CLASSIFICATION: the role select is the size-normalization decision. */
    state parse_ib {
        pkt.extract(hdr.ib);
        transition select(hdr.ib.role) {
            ROLE_RESP : padctl_normalize;   /* the held response is the target  */
            ROLE_ACK  : padctl_passthrough; /* ACK forwarded as-is, not resized */
            default   : padctl_passthrough;
        }
    }
    state padctl_normalize {
        hdr.padctl.setValid();
        hdr.padctl.normalize = 8w1;
        hdr.padctl.tcode     = TCODE_128;
        hdr.padctl.oversize  = 8w0;
        transition accept;
    }
    state padctl_passthrough {
        hdr.padctl.setValid();
        hdr.padctl.normalize = 8w0;
        hdr.padctl.tcode     = TCODE_NONE;
        hdr.padctl.oversize  = 8w0;
        transition accept;
    }
}

/* ====================== ingress control (P0 VERBATIM) ==================== */
control Ingress(inout headers_t hdr,
                inout ig_meta_t meta,
                in    ingress_intrinsic_metadata_t              ig_intr_md,
                in    ingress_intrinsic_metadata_from_parser_t  ig_prsr_md,
                inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                inout ingress_intrinsic_metadata_for_tm_t       ig_tm_md) {

    Register<bit<8>, bit<1>>(1, 0) reg_gen;
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_gen) gen_rmw = {
        void apply(inout bit<8> v, out bit<8> rv) {
            rv = v;
            if (meta.gen_we == 8w1) { v = meta.gen_val; }
        }
    };

    Register<bit<8>, bit<1>>(1, 0) reg_active;
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_active) active_rmw = {
        void apply(inout bit<8> v, out bit<8> rv) {
            rv = v;
            if (meta.active_we == 8w1) { v = meta.active_val; }
        }
    };

    Register<bit<32>, bit<1>>(1, 0) reg_deadline;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_deadline) deadline_rmw = {
        void apply(inout bit<32> v, out bit<32> rv) {
            rv = v;
            if (meta.dl_we == 8w1) { v = meta.dl_val; }
        }
    };

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

    action to_block() {
        ig_tm_md.ucast_egress_port = PORT_L;
        ig_tm_md.qid               = QID_BLOCK;
        ig_tm_md.bypass_egress     = 1w1;
    }
    action to_resp() {
        ig_tm_md.ucast_egress_port = PORT_L;
        ig_tm_md.qid               = QID_RESP;
        ig_tm_md.bypass_egress     = 1w1;
    }
    action to_host() {
        ig_tm_md.ucast_egress_port = PORT_VISION;
        ig_tm_md.qid               = 5w0;
        ig_tm_md.bypass_egress     = 1w0;
    }
    action drop_pkt() { ig_dprsr_md.drop_ctl = 3w1; }

    action mark_expired()     { meta.expired = 8w1; }
    action mark_not_expired() { meta.expired = 8w0; }
    table tbl_deadline_expiry {
        key = {
            meta.dl_armed : exact;
            meta.age      : ternary;
        }
        actions = { mark_expired; mark_not_expired; }
        const default_action = mark_not_expired();
        const entries = {
            (8w1, 32w0 &&& 32w0x80000000) : mark_expired();
        }
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
                meta.gen_we    = 8w1; meta.gen_val    = hdr.ib.gen;
                meta.active_we = 8w1; meta.active_val = 8w1;
                meta.dl_we     = 8w1; meta.dl_val     = 32w0;
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
                meta.ack_ok = 8w1;
                meta.dl_we  = 8w1;
                meta.dl_val = meta.ts32 + hdr.ib.seq;
            }

            meta.dl_now = deadline_rmw.execute(0);

            if (meta.dl_now != 32w0) { meta.dl_armed = 8w1; }
            meta.age = meta.ts32 - meta.dl_now;
            tbl_deadline_expiry.apply();

            if (meta.dequeued == 8w0) {
                if (hdr.ib.role == ROLE_BLOCK) {
                    to_block();
                    ctr_block_enq.count(0);
                    meta.ev_first_block = 8w1;
                } else if (hdr.ib.role == ROLE_RESP) {
                    to_resp();
                    ctr_resp_enq.count(0);
                } else if (hdr.ib.role == ROLE_ACK) {
                    to_host();
                    if (meta.ack_ok == 8w1) {
                        ctr_ack_arm.count(0);
                        meta.ev_ack_arm = 8w1;
                    } else {
                        ctr_ack_bypass.count(0);
                    }
                } else if (hdr.ib.role == ROLE_ARM) {
                    ctr_arm.count(0);
                    drop_pkt();
                } else {
                    drop_pkt();
                }
            } else {
                if (hdr.ib.role == ROLE_BLOCK) {
                    if (meta.active_now == 8w0 || meta.gen_mismatch == 8w1) {
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
                        hdr.ib.seq = hdr.ib.seq - 32w1;
                        to_block();
                        ctr_block_loop.count(0);
                    }
                } else if (hdr.ib.role == ROLE_RESP) {
                    to_host();
                    ctr_resp_release.count(0);
                    meta.ev_resp_release = 8w1;
                } else {
                    drop_pkt();
                }
            }

            if (meta.ev_first_block  == 8w1) { ts_first_block_w.execute(0); }
            if (meta.ev_ack_arm      == 8w1) { ts_ack_arm_w.execute(0); }
            if (meta.ev_block_term   == 8w1) { ts_block_term_w.execute(0); }
            if (meta.ev_resp_release == 8w1) { ts_first_resp_w.execute(0); }
        }
    }
}

/* ==== ingress deparser: P0 + the exported padctl (keeps the decision live) === */
control IgDeparser(packet_out pkt,
                   inout headers_t hdr,
                   in    ig_meta_t meta,
                   in    ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    apply {
        pkt.emit(hdr.eth);
        pkt.emit(hdr.ib);
        pkt.emit(hdr.padctl);
    }
}

/* ============================ egress (P0 shape) ========================== */
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
        transition select(hdr.eth.etype) {
            ETHERTYPE_IBSPG_REAL  : parse_ib;
            ETHERTYPE_IBSPG_TOKEN : parse_ib;
            default               : accept;
        }
    }
    state parse_ib {
        pkt.extract(hdr.ib);
        pkt.extract(hdr.padctl);
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
        pkt.emit(hdr.ib);
        pkt.emit(hdr.padctl);
    }
}

Pipeline(IgParser(), Ingress(), IgDeparser(),
         EgParser(), Egress(), EgDeparser()) pipe;

Switch(pipe) main;

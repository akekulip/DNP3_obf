/* ============================================================================
 * p6_egress_pad.p4 — VARIANT P6 of the stage-reclamation study.  THE CANDIDATE.
 *
 * ONE ARCHITECTURAL VARIABLE vs P0 (ibspg_hold_response.p4):
 *   the size decision AND the padding both live entirely in EGRESS.  The ingress
 *   control block, ingress parser and ingress deparser are byte-for-byte the P0
 *   text — not one table, action, register, counter or metadata field is added.
 *
 * WHY THIS CAN WORK AT ALL — the asymmetry that makes egress the right home:
 *   Tofino-1's `ingress_intrinsic_metadata_t` has NO packet-length field
 *   (tofino1_base.p4:108-121 — resubmit_flag, packet_version, ingress_port,
 *   ingress_mac_tstamp, and nothing else).  `egress_intrinsic_metadata_t` DOES:
 *   `bit<16> pkt_length` (tofino1_base.p4:281).  So egress can size a frame with
 *   no help from ingress at all — no bridge header, no exported flag, no shared
 *   metadata.  The ingress "export" the brief anticipated turns out to be
 *   unnecessary: egress already has strictly more size information than ingress.
 *
 *   The second half of the asymmetry is the budget.  P0 is at 12/12 ingress
 *   stages and 0/12 egress stages.  Every egress stage this costs is free.
 *
 * WHAT REACHES EGRESS.  P0's `to_host()` sets bypass_egress = 0, so exactly the
 * two frames we want normalized — the immediately-forwarded ACK and the released
 * RESPONSE — traverse egress.  The queued blocker/response loopback paths set
 * bypass_egress = 1 and are untouched, so the hold mechanism cannot be perturbed.
 *
 * WHAT IT DOES: one egress table, exact match on eg_intr_md.pkt_length over the
 * 13 base-corpus sizes, selecting the compile-time power-of-2 pad subset that
 * brings the frame to ONE fixed 128 B state.  Fail open (no pads) on any other
 * length, including oversize — never truncate.
 *
 * EMISSION-POSITION CAVEAT (do not skip — see SIZE_PRIMITIVE_REUSE_AUDIT.md §7).
 *   The pads are emitted after the last PARSED header and before the unparsed
 *   residual, because a TNA deparser cannot emit a header after the residual.
 *   For the synthetic IBSPG frame (eth + ib, no residual of consequence) that is
 *   exactly a trailer.  For a live IPv4/TCP/DNP3 frame whose payload is the
 *   residual it is NOT a trailer and NOT protocol-valid.  P6 measures the STAGE
 *   COST question only; the protocol-validity question is answered separately
 *   by p6c_true_trailer.p4, which empties the residual first.
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

/* ============================ headers ==================================== */
header ethernet_h { bit<48> dst; bit<48> src; bit<16> etype; }
header ibspg_h    { bit<8> role; bit<8> slot; bit<8> gen; bit<32> seq; }

/* Finite POWER-OF-2 pad-header set (egress-only; the ingress never sees these). */
header pad1_h  { bit<8>   f; }
header pad2_h  { bit<16>  f; }
header pad4_h  { bit<32>  f; }
header pad8_h  { bit<64>  f; }
header pad16_h { bit<128> f; }
header pad32_h { bit<256> f; }
header pad64_h { bit<512> f; }

/* Ingress header set: EXACTLY P0's. */
struct headers_t {
    ethernet_h eth;
    ibspg_h    ib;
}

/* Egress header set: P0's plus the pads. */
struct eg_headers_t {
    ethernet_h eth;
    ibspg_h    ib;
    pad64_h    pad64;
    pad32_h    pad32;
    pad16_h    pad16;
    pad8_h     pad8;
    pad4_h     pad4;
    pad2_h     pad2;
    pad1_h     pad1;
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

struct eg_meta_t { bit<8> normalized; }

/* =================== ingress parser (P0 VERBATIM) ======================== */
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
    state parse_ib {
        pkt.extract(hdr.ib);
        transition accept;
    }
}

/* =================== ingress control (P0 VERBATIM) ======================= */
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

/* ================== ingress deparser (P0 VERBATIM) ====================== */
control IgDeparser(packet_out pkt,
                   inout headers_t hdr,
                   in    ig_meta_t meta,
                   in    ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    apply {
        pkt.emit(hdr.eth);
        pkt.emit(hdr.ib);
    }
}

/* ========================= EGRESS — ALL of P6 lives here ================= */
parser EgParser(packet_in pkt,
                out eg_headers_t hdr,
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
        transition accept;
    }
}

control Egress(inout eg_headers_t hdr,
               inout eg_meta_t meta,
               in    egress_intrinsic_metadata_t                 eg_intr_md,
               in    egress_intrinsic_metadata_from_parser_t     eg_prsr_md,
               inout egress_intrinsic_metadata_for_deparser_t    eg_dprsr_md,
               inout egress_intrinsic_metadata_for_output_port_t eg_oport_md) {

    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_size_normalized;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_size_failopen;

    /* Compile-time power-of-2 pad decode -> ONE 128 B state.
     * Key is the MEASURED frame length from the TM, not a declared label:
     * this is a Level-2 (self-validating) key, unlike the trace_v1 primitive. */
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
        const default_action = pad_none();   /* fail open, incl. oversize */
        size = 16;
    }

    apply {
        size_norm.apply();
        if (meta.normalized == 8w1) { ctr_size_normalized.count(0); }
        else                        { ctr_size_failopen.count(0); }
    }
}

control EgDeparser(packet_out pkt,
                   inout eg_headers_t hdr,
                   in    eg_meta_t meta,
                   in    egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {
    apply {
        pkt.emit(hdr.eth);
        pkt.emit(hdr.ib);
        pkt.emit(hdr.pad64);
        pkt.emit(hdr.pad32);
        pkt.emit(hdr.pad16);
        pkt.emit(hdr.pad8);
        pkt.emit(hdr.pad4);
        pkt.emit(hdr.pad2);
        pkt.emit(hdr.pad1);
    }
}

Pipeline(IgParser(), Ingress(), IgDeparser(),
         EgParser(), Egress(), EgDeparser()) pipe;

Switch(pipe) main;

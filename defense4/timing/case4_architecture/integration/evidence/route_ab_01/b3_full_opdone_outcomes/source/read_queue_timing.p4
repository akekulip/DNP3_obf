// T's READ timing role, queue-resident design (not the heartbeat/recirculation design in
// read_timing.p4). Real ACK/response/OPERATE originals stay resident in their hold queues
// (LADDER qid6/qid4, OP_LADDER qid2); only blocker tokens (qid7/qid5/qid3) repeat the timing
// circulation, matching defense4_rrc_bor_unified12.p4's qid7/6/5/4/3/2 ladder
// (integration/INTEGRATION_CONTRACT.md section 1; the heartbeat design is a correctness
// reference only, never the base). Invariants (a)-(g): see
// integration/read/tests/test_t_queue_invariants.py and
// DNP3_Timing_Size_Integration_Prompt.md section 4, Phase C. The whole file still does not compile
// (unresolved bf-p4c crash); what has been compiled and model-run is listed in
// read/TIMING_QUEUE_MIGRATION_STATUS.md.
#include <core.p4>
#include <tna.p4>
#include "ports.p4"
// New port, local to this file only (not added to ports.p4): where the mirror clone of a
// request admission recirculates (pipe 2 local 68; queue_sim.py PKTGEN_PORT = 324).
const PortId_t PKTGEN_RETURN = 9w324;
// The clone itself (F1): mirror_type 1 requests it; IngressDeparser emits it to the mirror session the
// control plane binds to PKTGEN_RETURN ($mirror.cfg). The session id travels in metadata because
// bf-p4c rejects a constant session selector (defense4_rrc_bor_unified12.p4, same pattern).
const bit<3> MIRROR_TYPE_CLONE = 1;
const MirrorId_t CLONE_SESSION_ID = 10w7;

// Ladder roles (queue_sim.py ROLE dict): 11 ACK blocker, 12 response blocker, 13 OPERATE
// blocker, 14 held ACK, 15 held response, 16 held OPERATE.
const bit<8> ROLE_ACK_BLK  = 11; const bit<8> ROLE_RESP_BLK = 12; const bit<8> ROLE_OP_BLK  = 13;
const bit<8> ROLE_ACK_HELD = 14; const bit<8> ROLE_RESP_HELD = 15; const bit<8> ROLE_OP_HELD = 16;

// tev.kind wire values, identical to read_timing.p4's own T_IN convention.
const bit<8> KIND_REQUEST = 9; const bit<8> KIND_ACK = 10; const bit<8> KIND_RESPONSE = 11;
const bit<8> KIND_OPERATE = 12; const bit<8> KIND_RESET = 4;

// Outcome counters (outcomes register index), named to match test_t_queue_invariants.py's
// out(sim, 'OUT_*') lookups via sim.consts().
const bit<32> OUT_UNMATCHED = 0; const bit<32> OUT_HELD_REWAIT = 1; const bit<32> OUT_ACK_COMMIT = 2;
const bit<32> OUT_RESP_RELEASE = 3; const bit<32> OUT_RESP_DUP_DROP = 4; const bit<32> OUT_OP_RELEASE = 5;
const bit<32> OUT_TOKEN_STALE = 6; const bit<32> OUT_HELD_STALE_FLUSH = 7; const bit<32> OUT_ACK_FALLBACK = 8;
const bit<32> OUT_RESP_FALLBACK = 9; const bit<32> OUT_TOKEN_TMO = 10; const bit<32> OUT_HELD_OFF_FLUSH = 11;
const bit<32> OUT_TOKEN_OFF = 12; const bit<32> OUT_REQ_BYPASS = 13;
// No outcome recorded on this pass (md.outcome_code's initial value; outcome_count has no entry for it).
const bit<8> OUT_NONE = 0xff;

header tev_t { bit<32> epoch; bit<32> wgen; bit<32> t0q; bit<8> kind; bit<8> stage; bit<16> reserved; }
header ladder_t { bit<8> role; bit<8> child; bit<16> generation; bit<32> budget; }
header clone_hdr_t { bit<32> tag; }
header ethernet_t { bit<48> dst; bit<48> src; bit<16> type; }
struct header_t { pktgen_timer_header_t timer; clone_hdr_t clone; tev_t tev; ladder_t ladder; ethernet_t eth; }
struct gen_mask_t { bit<32> gen; bit<32> mask; }

struct metadata_t {
    // da/readiness/gap/op_j are config action-data (set_params); cap is accepted (the test always
    // passes it) but not stored -- nothing in this design uses it as a deadline.
    bit<32> da; bit<32> readiness; bit<32> gap; bit<32> op_j; bit<32> budget_cap; bit<32> enabled;
    bit<32> now;
    bit<32> in_epoch; bit<32> cur_epoch; bit<32> quarantine;
    bit<32> cur_gen; bit<32> new_gen; bit<32> commit_gen; bit<32> t0_v;
    bit<32> ack_done_g; bit<32> resp_done_g;
    bit<32> ack_commit_at_v; bit<32> resp_deadline_v; bit<32> resp_target;
    // Narrow: these only ever hold a 3-bit child mask or a 0/1 flag -- bit<32> would occupy 4x the
    // PHV this design doesn't have to spare (see TIMING_QUEUE_MIGRATION_STATUS.md's PHV finding).
    bit<8> resp_seen_mask; bit<8> dup;
    // Tofino's conditional-execution gateway cannot evaluate a live comparison between two fully
    // dynamic values (bf-p4c: "condition too complex ... one operand must be constant"), so every
    // now-vs-deadline check here is precomputed as delta = now - deadline, then its sign bit is
    // extracted with a plain bit-slice assignment into a 1-bit ready flag -- read_timing.p4's own
    // deadline_deltas/heartbeat_eligibility pattern, adapted to avoid a table per check. The
    // deltas/deadlines need the full dynamic range; the *_ready outputs are 0/1 flags and are
    // narrowed accordingly.
    bit<32> deadline_da; bit<32> da_delta; bit<8> da_ready;
    bit<32> deadline_readiness; bit<32> readiness_delta; bit<8> readiness_ready;
    bit<32> gap_delta; bit<8> gap_ready;
    bit<32> op_t0_masked; bit<32> op_deadline; bit<32> op_delta; bit<8> op_ready;
    bit<32> op_gen; bit<32> op_done_g; bit<32> op_t0_v;
    bit<32> clone_tag; bit<32> token_gen; bit<32> token_domain;
    MirrorId_t clone_ses;
    // The one outcome this pass records; bumped by the single outcome_count table at the end of apply.
    bit<8> outcome_code;
}

parser IngressParser(packet_in pkt, out header_t hdr, out metadata_t md,
                     out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        pkt.extract(ig_intr_md); pkt.advance(PORT_METADATA_SIZE);
        transition select(ig_intr_md.ingress_port) {
            T_IN : parse_tev;
            HELD_RETURN : parse_ladder;
            HB_RETURN : parse_ladder;
            PKTGEN_RETURN : parse_clone;
            default : parse_timer;
        }
    }
    state parse_tev {
        pkt.extract(hdr.tev);
        transition select(hdr.tev.kind, hdr.tev.reserved) {
            (9, 0) : opaque_ethernet;
            (10, 0) : opaque_ethernet;
            (11, 0) : opaque_ethernet;
            (12, 0) : opaque_ethernet;
            (4, 0) : opaque_ethernet;
            default : reject;
        }
    }
    state parse_ladder {
        pkt.extract(hdr.ladder);
        transition select(hdr.ladder.role) {
            11 : accept;
            12 : accept;
            13 : accept;
            14 : opaque_ethernet;
            15 : opaque_ethernet;
            16 : opaque_ethernet;
            default : reject;
        }
    }
    // The clone always carries this pass's pristine original bytes (tag + the T_IN wire format it
    // mirrored). Only an OPERATE-admission clone (tev.kind 12) is used for anything; a
    // request-admission clone (kind 9, READ's ACK/response blockers never need this) is parsed the
    // same way and then simply dropped in the apply block.
    state parse_clone {
        pkt.extract(hdr.clone); pkt.extract(hdr.tev);
        transition select(hdr.tev.kind, hdr.tev.reserved) {
            (9, 0) : opaque_ethernet;
            (12, 0) : opaque_ethernet;
            default : reject;
        }
    }
    state parse_timer { pkt.extract(hdr.timer); transition accept; }
    state opaque_ethernet { pkt.extract(hdr.eth); transition accept; }
}

control Ingress(inout header_t hdr, inout metadata_t md,
                in ingress_intrinsic_metadata_t ig_intr_md,
                in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
                inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {
    // ---- configuration (per-pass action data, not registers) --------------------------------
    action set_params(bit<32> da, bit<32> readiness, bit<32> cap, bit<32> gap, bit<32> op_j,
                      bit<32> budget, bit<32> enabled) {
        md.da = da; md.readiness = readiness; md.gap = gap; md.op_j = op_j;
        md.budget_cap = budget; md.enabled = enabled;
    }
    table params {
        actions = { set_params; }
        default_action = set_params(2000000, 12000000, 16000000, 800000, 2400000, 240000, 1); size = 1;
    }
    action clock_sample() { md.now = ((bit<32>)ig_prsr_md.global_tstamp) & 32w0xffffff00; }
    table clock { actions = { clock_sample; } default_action = clock_sample(); size = 1; }

    // ---- epoch / generation state -------------------------------------------------------------
    Register<bit<32>, bit<1>>(1, 0) cur_epoch_reg;
    RegisterAction<bit<32>, bit<1>, bit<32>>(cur_epoch_reg) epoch_read = {
        void apply(inout bit<32> value, out bit<32> out_value) { out_value = value; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(cur_epoch_reg) epoch_write = {
        void apply(inout bit<32> value, out bit<32> out_value) { value = md.in_epoch; out_value = value; }
    };
    Register<bit<32>, bit<1>>(1, 0xffffffff) quarantine_reg;
    RegisterAction<bit<32>, bit<1>, bit<32>>(quarantine_reg) quarantine_read = {
        void apply(inout bit<32> value, out bit<32> out_value) { out_value = value; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(quarantine_reg) quarantine_write = {
        void apply(inout bit<32> value, out bit<32> out_value) { value = md.in_epoch; out_value = value; }
    };
    Register<bit<32>, bit<1>>(1, 0) gen_alloc_reg;
    RegisterAction<bit<32>, bit<1>, bit<32>>(gen_alloc_reg) gen_peek = {
        void apply(inout bit<32> value, out bit<32> out_value) { out_value = value; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(gen_alloc_reg) gen_bump = {
        void apply(inout bit<32> value, out bit<32> out_value) { value = value + 1; out_value = value; }
    };
    // Request-anchored t0 (NOTATION_MAPPING.md convention): the quantized arrival time of the
    // request that opened the current generation. da/readiness/cap are offsets from THIS, not
    // from the epoch. Written once per generation at admission (admit_request never fires twice
    // for the same generation, so no lazy-arm guard is needed here).
    Register<bit<32>, bit<1>>(1, 0) t0_reg;
    RegisterAction<bit<32>, bit<1>, bit<32>>(t0_reg) t0_read = {
        void apply(inout bit<32> value, out bit<32> out_value) { out_value = value; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(t0_reg) t0_write = {
        void apply(inout bit<32> value, out bit<32> out_value) { value = md.now; out_value = value; }
    };
    // Tofino requires every table (and every bare action call becomes one) to address at most one
    // indirect extern, so reads/writes spanning multiple registers are always split into separate
    // single-register actions called as separate statements, never bundled into one action body.
    action read_cur_epoch() { md.cur_epoch = epoch_read.execute(0); }
    action read_quarantine() { md.quarantine = quarantine_read.execute(0); }
    action peek_gen() { md.cur_gen = gen_peek.execute(0); }
    table gen_snapshot { actions = { peek_gen; } default_action = peek_gen(); size = 1; }

    // ---- ACK domain -----------------------------------------------------------------------
    Register<bit<32>, bit<1>>(1, 0) ack_done_reg;
    RegisterAction<bit<32>, bit<1>, bit<32>>(ack_done_reg) ack_done_read = {
        void apply(inout bit<32> value, out bit<32> out_value) { out_value = value; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(ack_done_reg) ack_done_write = {
        void apply(inout bit<32> value, out bit<32> out_value) { value = md.commit_gen; out_value = value; }
    };
    Register<bit<32>, bit<1>>(1, 0) ack_commit_at_reg;
    RegisterAction<bit<32>, bit<1>, bit<32>>(ack_commit_at_reg) commit_at_read = {
        void apply(inout bit<32> value, out bit<32> out_value) { out_value = value; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(ack_commit_at_reg) commit_at_write = {
        void apply(inout bit<32> value, out bit<32> out_value) { value = md.now; out_value = value; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(ack_commit_at_reg) commit_at_clear = {
        void apply(inout bit<32> value, out bit<32> out_value) { value = 0; out_value = 0; }
    };

    // ---- response domain --------------------------------------------------------------------
    Register<bit<32>, bit<1>>(1, 0) resp_done_reg;
    RegisterAction<bit<32>, bit<1>, bit<32>>(resp_done_reg) resp_done_read = {
        void apply(inout bit<32> value, out bit<32> out_value) { out_value = value; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(resp_done_reg) resp_done_write = {
        void apply(inout bit<32> value, out bit<32> out_value) { value = md.commit_gen; out_value = value; }
    };
    Register<bit<32>, bit<1>>(1, 0) resp_deadline;
    RegisterAction<bit<32>, bit<1>, bit<32>>(resp_deadline) deadline_arm = {
        void apply(inout bit<32> value, out bit<32> out_value) {
            if (value == 0) { value = md.resp_target | 32w1; }
            out_value = value;
        }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(resp_deadline) deadline_clear = {
        void apply(inout bit<32> value, out bit<32> out_value) { value = 0; out_value = 0; }
    };
    Register<gen_mask_t, bit<1>>(1, {0, 0}) resp_mask_reg;
    RegisterAction<gen_mask_t, bit<1>, bit<32>>(resp_mask_reg) mask_read = {
        void apply(inout gen_mask_t value, out bit<32> out_value) {
            out_value = 0;
            if (value.gen == md.cur_gen) { out_value = value.mask; }
        }
    };
    // Tofino stateful ALUs require an AND-mask operand to be a compile-time constant, so each
    // supported child index (0, 1, 2 -- the only values tev.stage carries for a response, see
    // queue_sim.py's response() helper) gets its own fixed-bit action instead of one action
    // taking a runtime mask.
    RegisterAction<gen_mask_t, bit<1>, bit<32>>(resp_mask_reg) mask_try_admit0 = {
        void apply(inout gen_mask_t value, out bit<32> out_value) {
            out_value = 0;
            if (value.gen != md.cur_gen) { value.gen = md.cur_gen; value.mask = 0; }
            if ((value.mask & 32w1) != 0) { out_value = 1; }
            else { value.mask = value.mask | 32w1; }
        }
    };
    RegisterAction<gen_mask_t, bit<1>, bit<32>>(resp_mask_reg) mask_try_admit1 = {
        void apply(inout gen_mask_t value, out bit<32> out_value) {
            out_value = 0;
            if (value.gen != md.cur_gen) { value.gen = md.cur_gen; value.mask = 0; }
            if ((value.mask & 32w2) != 0) { out_value = 1; }
            else { value.mask = value.mask | 32w2; }
        }
    };
    RegisterAction<gen_mask_t, bit<1>, bit<32>>(resp_mask_reg) mask_try_admit2 = {
        void apply(inout gen_mask_t value, out bit<32> out_value) {
            out_value = 0;
            if (value.gen != md.cur_gen) { value.gen = md.cur_gen; value.mask = 0; }
            if ((value.mask & 32w4) != 0) { out_value = 1; }
            else { value.mask = value.mask | 32w4; }
        }
    };

    // ---- OPERATE domain ---------------------------------------------------------------------
    Register<bit<32>, bit<1>>(1, 0) op_gen_alloc_reg;
    RegisterAction<bit<32>, bit<1>, bit<32>>(op_gen_alloc_reg) op_gen_peek = {
        void apply(inout bit<32> value, out bit<32> out_value) { out_value = value; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(op_gen_alloc_reg) op_gen_bump = {
        void apply(inout bit<32> value, out bit<32> out_value) { value = value + 1; out_value = value; }
    };
    Register<bit<32>, bit<1>>(1, 0) op_done_reg;
    RegisterAction<bit<32>, bit<1>, bit<32>>(op_done_reg) op_done_read = {
        void apply(inout bit<32> value, out bit<32> out_value) { out_value = value; }
    };
    // Atomic compare-and-commit for a held OPERATE: returns the generation recorded BEFORE this pass
    // and records md.op_gen when the deadline has passed. A Tofino register lives in one stage, so the
    // old read-then-compare-then-dependent-write (op_done_read, gateway, op_done_write in a later
    // table) could not place; the caller now decides release from the returned old value instead.
    // Writing op_gen over an equal op_gen is a no-op, so the result matches the old three-step path.
    RegisterAction<bit<32>, bit<1>, bit<32>>(op_done_reg) op_done_try = {
        void apply(inout bit<32> value, out bit<32> out_value) {
            out_value = value;
            if (md.op_ready == 1) { value = md.op_gen; }
        }
    };
    Register<bit<32>, bit<1>>(1, 0) op_t0_reg;
    RegisterAction<bit<32>, bit<1>, bit<32>>(op_t0_reg) op_t0_read = {
        void apply(inout bit<32> value, out bit<32> out_value) { out_value = value; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(op_t0_reg) op_t0_arm = {
        void apply(inout bit<32> value, out bit<32> out_value) {
            value = md.now | 32w1;
            out_value = value;
        }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(op_t0_reg) op_t0_clear = {
        void apply(inout bit<32> value, out bit<32> out_value) { value = 0; out_value = 0; }
    };

    // ---- outcomes -----------------------------------------------------------------------------
    Register<bit<32>, bit<4>>(16, 0) outcomes;
    RegisterAction<bit<32>, bit<4>, bit<32>>(outcomes) bump_outcome = {
        void apply(inout bit<32> value, out bit<32> out_value) { value = value + 1; out_value = value; }
    };
    // Every path records at most one outcome. A Tofino register lives in one stage, and the ~dozen
    // tables that used to bump `outcomes` directly sat at different dependency depths, so they could
    // not share its stage (bf-p4c: "Table placement was not able to allocate ... in the same stage
    // along with Register Ingress.outcomes"). count() now only names the outcome; outcome_count, the
    // register's single call site, bumps it once at the end of the pass. Same index, same +1.
    action count(bit<32> code) { md.outcome_code = (bit<8>)code; }
    action bump(bit<4> idx) { bump_outcome.execute(idx); }
    table outcome_count {
        key = { md.outcome_code : exact; }
        actions = { bump; NoAction; }
        const entries = {
            0 : bump(0); 1 : bump(1); 2 : bump(2); 3 : bump(3); 4 : bump(4); 5 : bump(5); 6 : bump(6);
            7 : bump(7); 8 : bump(8); 9 : bump(9); 10 : bump(10); 11 : bump(11); 12 : bump(12); 13 : bump(13);
        }
        default_action = NoAction(); size = 16;
    }

    // ---- request admission ---------------------------------------------------------------------
    action admit_request_gen() {
        md.in_epoch = hdr.tev.epoch; md.new_gen = gen_bump.execute(0);
        hdr.tev.setInvalid();
        ig_tm_md.ucast_egress_port = RELAY_PORT;
        ig_dprsr_md.mirror_type = 1; md.clone_tag = md.new_gen & 32w0xffff;
        md.clone_ses = CLONE_SESSION_ID;
    }
    action admit_request_epoch() { epoch_write.execute(0); }
    action admit_request_t0() { t0_write.execute(0); }
    action bypass_request() {
        hdr.tev.setInvalid();
        ig_tm_md.ucast_egress_port = RELAY_PORT;
        count(OUT_REQ_BYPASS);
    }
    action reset_mark_epoch() { md.in_epoch = hdr.tev.epoch; quarantine_write.execute(0); }
    action reset_bump_gen() { md.new_gen = gen_bump.execute(0); }
    action reset_clear_deadline() { deadline_clear.execute(0); }
    action reset_clear_commit_at() { commit_at_clear.execute(0); }
    action reset_clear_op_t0() { op_t0_clear.execute(0); }

    // ---- hold admission (ACK / response) --------------------------------------------------------
    action hold_ack() {
        hdr.tev.setInvalid();
        hdr.ladder.setValid();
        hdr.ladder.role = ROLE_ACK_HELD; hdr.ladder.child = 0;
        hdr.ladder.generation = (bit<16>)md.cur_gen; hdr.ladder.budget = 0;
        ig_tm_md.ucast_egress_port = HELD_RETURN; ig_tm_md.qid = 6;
    }
    action admit_response() {
        hdr.ladder.setValid();
        hdr.ladder.role = ROLE_RESP_HELD; hdr.ladder.child = (bit<8>)hdr.tev.stage;
        hdr.ladder.generation = (bit<16>)md.cur_gen; hdr.ladder.budget = 0;
        hdr.tev.setInvalid();
        ig_tm_md.ucast_egress_port = HELD_RETURN; ig_tm_md.qid = 4;
    }
    action drop_duplicate_response() { ig_dprsr_md.drop_ctl = 1; count(OUT_RESP_DUP_DROP); }
    action passthrough_tev_forward() { hdr.tev.setInvalid(); ig_tm_md.ucast_egress_port = FORWARD_PORT; }
    // The admitting T_IN pass becomes OP_LADDER's first blocker directly (qid3, immediate) instead
    // of the real admission: a generated blocker token cannot carry the original (it has no
    // payload), so the only way to admit the real original without racing the generator's delay is
    // to admit it from the mirror CLONE instead (see parse_clone_tev / admit_operate_held below) --
    // the clone always carries the pass's pristine original bytes, and by construction the direct
    // blocker here is already in qid3 before the clone (pktgen_ns/2) or any generated token
    // (pktgen_ns) can arrive, so qid3 is never empty when the real original's first item shows up.
    action hold_operate() {
        hdr.tev.setInvalid(); hdr.eth.setInvalid();
        hdr.ladder.setValid();
        hdr.ladder.role = ROLE_OP_BLK; hdr.ladder.child = 0;
        hdr.ladder.generation = (bit<16>)md.op_gen; hdr.ladder.budget = md.budget_cap;
        ig_tm_md.ucast_egress_port = HB_RETURN; ig_tm_md.qid = 3;
        // A single Tofino action stage supports one ALU op per field; a mask-then-OR is two, so
        // this relies on one plain OR instead (op_gen is expected well under 0x10000 in any one
        // generation-counter lifetime exercised here -- an actual wraparound-safe generation-tag
        // encoding is a follow-up, not needed for this evidence). Not an add: once the Mirror emit
        // made clone_tag live, bf-p4c split op_gen over two 16-bit containers and rejected the
        // carrying add (2 PHV sources + a constant); a bitwise OR splits per container.
        ig_dprsr_md.mirror_type = 1; md.clone_tag = md.op_gen | 32w0x10000;
        md.clone_ses = CLONE_SESSION_ID;
    }
    action admit_operate_held() {
        md.op_gen = op_gen_peek.execute(0);
        hdr.clone.setInvalid(); hdr.tev.setInvalid();
        hdr.ladder.setValid();
        hdr.ladder.role = ROLE_OP_HELD; hdr.ladder.child = 0;
        hdr.ladder.generation = (bit<16>)md.op_gen; hdr.ladder.budget = 0;
        ig_tm_md.ucast_egress_port = HB_RETURN; ig_tm_md.qid = 2;
    }
    action drop_clone() { ig_dprsr_md.drop_ctl = 1; }
    action passthrough_tev_relay() { hdr.tev.setInvalid(); ig_tm_md.ucast_egress_port = RELAY_PORT; }

    // ---- generator token -> blocker (ports 0, generator app) -----------------------------------
    action seed_ack_blocker() {
        hdr.timer.setInvalid(); hdr.ladder.setValid();
        hdr.ladder.role = ROLE_ACK_BLK; hdr.ladder.child = 0;
        hdr.ladder.generation = (bit<16>)md.token_gen; hdr.ladder.budget = md.budget_cap;
        ig_tm_md.ucast_egress_port = HELD_RETURN; ig_tm_md.qid = 7;
    }
    action seed_resp_blocker() {
        hdr.timer.setInvalid(); hdr.ladder.setValid();
        hdr.ladder.role = ROLE_RESP_BLK; hdr.ladder.child = 0;
        hdr.ladder.generation = (bit<16>)md.token_gen; hdr.ladder.budget = md.budget_cap;
        ig_tm_md.ucast_egress_port = HELD_RETURN; ig_tm_md.qid = 5;
    }
    action seed_op_blocker() {
        hdr.timer.setInvalid(); hdr.ladder.setValid();
        hdr.ladder.role = ROLE_OP_BLK; hdr.ladder.child = 0;
        hdr.ladder.generation = (bit<16>)md.token_gen; hdr.ladder.budget = md.budget_cap;
        ig_tm_md.ucast_egress_port = HB_RETURN; ig_tm_md.qid = 3;
    }
    action drop_timer() { hdr.timer.setInvalid(); ig_dprsr_md.drop_ctl = 1; }
    action drop_timer_stale() { hdr.timer.setInvalid(); ig_dprsr_md.drop_ctl = 1; count(OUT_TOKEN_STALE); }

    // ---- ladder dispatch: blockers re-circulate or die ------------------------------------------
    action keep_blocking(PortId_t port, bit<5> qid) {
        hdr.ladder.budget = hdr.ladder.budget - 1;
        ig_tm_md.ucast_egress_port = port; ig_tm_md.qid = qid;
    }
    action stop_blocking() { ig_dprsr_md.drop_ctl = 1; }
    action stop_blocking_stale() { ig_dprsr_md.drop_ctl = 1; count(OUT_TOKEN_STALE); }
    action stop_blocking_tmo() { ig_dprsr_md.drop_ctl = 1; count(OUT_TOKEN_TMO); }
    action stop_blocking_off() { ig_dprsr_md.drop_ctl = 1; count(OUT_TOKEN_OFF); }

    // ---- deadline readiness: delta-then-sign-bit, read_timing.p4's own proven pattern -----------
    // A live "now >= deadline" comparison is a gateway/conditional operation Tofino caps tightly
    // (bf-p4c: "condition too complex ... one operand must be constant"). Computing delta = now -
    // deadline and then testing its sign bit is still the fix, but the sign bit is extracted with a
    // plain bit-slice assignment (pure data-plane ALU op, not a conditional) instead of a
    // ternary-match table -- this removes five single-row tables entirely, which is a more direct
    // way to relieve both gateway pressure and the table-dependency-graph complexity than narrowing
    // field widths alone (see TIMING_QUEUE_MIGRATION_STATUS.md).
    action compute_deadline_da() { md.deadline_da = md.t0_v + md.da; }
    action compute_da_delta() { md.da_delta = md.now - md.deadline_da; }
    action extract_da_ready() { md.da_ready = (bit<8>)(~md.da_delta[31:31]); }
    action compute_deadline_readiness() { md.deadline_readiness = md.t0_v + md.readiness; }
    action compute_readiness_delta() { md.readiness_delta = md.now - md.deadline_readiness; }
    action extract_readiness_ready() { md.readiness_ready = (bit<8>)(~md.readiness_delta[31:31]); }
    action compute_gap_delta() { md.gap_delta = md.now - md.resp_target; }
    action extract_gap_ready() { md.gap_ready = (bit<8>)(~md.gap_delta[31:31]); }
    action compute_op_t0_masked() { md.op_t0_masked = md.op_t0_v & 32w0xfffffffe; }
    action compute_op_deadline() { md.op_deadline = md.op_t0_masked + md.op_j; }
    action compute_op_delta() { md.op_delta = md.now - md.op_deadline; }
    action extract_op_ready() { md.op_ready = (bit<8>)(~md.op_delta[31:31]); }
    // resp_seen_mask != 0 compares one dynamic field against the constant 0 -- already legal for a
    // gateway (unlike the deadline sums above, this was never the "two dynamic operands" problem),
    // so it needs no delta/sign-bit treatment at all; used directly in conditions below.

    // ---- ladder dispatch: held originals release or rewait --------------------------------------
    // mark_ack_done touches only ack_done_reg; arming resp_deadline and bumping outcomes are
    // separate single-register actions called as separate statements at each call site (Tofino:
    // one table/action may address at most one indirect extern).
    action mark_ack_done() {
        hdr.ladder.setInvalid();
        ig_tm_md.ucast_egress_port = FORWARD_PORT;
        md.commit_gen = md.cur_gen; ack_done_write.execute(0);
    }
    action mark_ack_commit_at() { md.ack_commit_at_v = commit_at_write.execute(0); }
    // Arm resp_deadline now: response_eligibility = a_commit + configured CLRT_new is fixed the
    // instant a_commit happens (INTEGRATION_CONTRACT.md section 4), not deferred until the
    // response's own pass happens to check it.
    action compute_resp_target() { md.resp_target = md.ack_commit_at_v + md.gap; }
    action arm_resp_deadline() { md.resp_deadline_v = deadline_arm.execute(0); }
    action rewait_ack() {
        ig_tm_md.ucast_egress_port = HELD_RETURN; ig_tm_md.qid = 6;
        count(OUT_HELD_REWAIT);
    }
    action flush_ack_stale() {
        hdr.ladder.setInvalid(); ig_tm_md.ucast_egress_port = FORWARD_PORT;
        count(OUT_HELD_STALE_FLUSH);
    }
    action flush_ack_off() {
        hdr.ladder.setInvalid(); ig_tm_md.ucast_egress_port = FORWARD_PORT;
        count(OUT_HELD_OFF_FLUSH);
    }

    action mark_resp_done() {
        hdr.ladder.setInvalid();
        ig_tm_md.ucast_egress_port = FORWARD_PORT;
        md.commit_gen = md.cur_gen; resp_done_write.execute(0);
    }
    action rewait_response() {
        ig_tm_md.ucast_egress_port = HELD_RETURN; ig_tm_md.qid = 4;
        count(OUT_HELD_REWAIT);
    }
    action flush_response_stale() {
        hdr.ladder.setInvalid(); ig_tm_md.ucast_egress_port = FORWARD_PORT;
        count(OUT_HELD_STALE_FLUSH);
    }
    action flush_response_off() {
        hdr.ladder.setInvalid(); ig_tm_md.ucast_egress_port = FORWARD_PORT;
        count(OUT_HELD_OFF_FLUSH);
    }

    // Release only; op_done_reg was already committed by op_done_try on this same pass.
    action release_operate() {
        hdr.ladder.setInvalid();
        ig_tm_md.ucast_egress_port = RELAY_PORT;
    }
    action rewait_operate() {
        ig_tm_md.ucast_egress_port = HB_RETURN; ig_tm_md.qid = 2;
        count(OUT_HELD_REWAIT);
    }
    action flush_operate_stale() {
        hdr.ladder.setInvalid(); ig_tm_md.ucast_egress_port = RELAY_PORT;
        count(OUT_HELD_STALE_FLUSH);
    }
    action flush_operate_off() {
        hdr.ladder.setInvalid(); ig_tm_md.ucast_egress_port = RELAY_PORT;
        count(OUT_HELD_OFF_FLUSH);
    }

    action unmatched() { ig_dprsr_md.drop_ctl = 1; count(OUT_UNMATCHED); }

    apply {
        ig_tm_md.bypass_egress = 0;
        md.outcome_code = OUT_NONE;
        params.apply(); clock.apply();
        // gen_snapshot stays global: T_IN (ACK/response epoch checks), port 0 (token staleness) and
        // HELD_RETURN (every role's staleness check) all need md.cur_gen. Everything else that used
        // to run unconditionally here moved into the one branch that actually needs it (HELD_RETURN
        // or HB_RETURN, below) -- narrowing each field's live range to its own branch lets the PHV
        // allocator reuse containers across mutually exclusive branches instead of holding every
        // domain's deltas/deadlines live for the whole pipeline on every packet type.
        gen_snapshot.apply();

        if (ig_intr_md.ingress_port == PKTGEN_RETURN) {
            if (hdr.tev.kind == KIND_OPERATE && md.enabled != 0) { admit_operate_held(); }
            else { drop_clone(); }
        } else if (ig_intr_md.ingress_port == T_IN) {
            read_cur_epoch(); read_quarantine();
            if (md.enabled == 0) {
                if (hdr.tev.kind == KIND_REQUEST) { passthrough_tev_relay(); }
                else if (hdr.tev.kind == KIND_OPERATE) { passthrough_tev_relay(); }
                else if (hdr.tev.kind == KIND_RESET) { ig_dprsr_md.drop_ctl = 1; }
                else { passthrough_tev_forward(); }
            } else if (hdr.tev.kind == KIND_REQUEST) {
                if (hdr.tev.epoch == md.quarantine) { bypass_request(); }
                else { admit_request_gen(); admit_request_epoch(); admit_request_t0(); }
            } else if (hdr.tev.kind == KIND_RESET) {
                reset_mark_epoch(); reset_bump_gen();
                reset_clear_deadline(); reset_clear_commit_at(); reset_clear_op_t0();
                ig_dprsr_md.drop_ctl = 1;
            } else if (hdr.tev.kind == KIND_ACK) {
                if (hdr.tev.epoch != md.cur_epoch || hdr.tev.epoch == md.quarantine) { passthrough_tev_forward(); }
                else { hold_ack(); }
            } else if (hdr.tev.kind == KIND_RESPONSE) {
                if (hdr.tev.epoch != md.cur_epoch || hdr.tev.epoch == md.quarantine) { passthrough_tev_forward(); }
                else {
                    md.resp_done_g = resp_done_read.execute(0);
                    if (md.resp_done_g == md.cur_gen) { passthrough_tev_forward(); }
                    else {
                        if (hdr.tev.stage == 0) { md.dup = (bit<8>)mask_try_admit0.execute(0); }
                        else if (hdr.tev.stage == 1) { md.dup = (bit<8>)mask_try_admit1.execute(0); }
                        else { md.dup = (bit<8>)mask_try_admit2.execute(0); }
                        if (md.dup == 1) { drop_duplicate_response(); }
                        else { admit_response(); }
                    }
                }
            } else if (hdr.tev.kind == KIND_OPERATE) {
                md.op_gen = op_gen_bump.execute(0);
                op_t0_arm.execute(0);
                hold_operate();
            } else { unmatched(); }
        } else if (ig_intr_md.ingress_port == 0) {
            md.token_domain = (bit<32>)hdr.timer.app_id;
            md.token_gen = (bit<32>)hdr.timer.batch_id;
            if (md.token_domain == 1) {
                // OPERATE domain token (app_id == 1)
                md.op_gen = op_gen_peek.execute(0);
                if (md.token_gen != (md.op_gen & 32w0xffff)) { drop_timer_stale(); }
                else { seed_op_blocker(); }
            } else if (((bit<32>)hdr.timer.packet_id & 32w1) == 0) {
                // READ domain token (app_id == 0); even packet_id -> ACK reservoir
                if (md.token_gen != (md.cur_gen & 32w0xffff)) { drop_timer_stale(); }
                else { seed_ack_blocker(); }
            } else {
                // READ domain token; odd packet_id -> response reservoir
                if (md.token_gen != (md.cur_gen & 32w0xffff)) { drop_timer_stale(); }
                else { seed_resp_blocker(); }
            }
        } else if (ig_intr_md.ingress_port == HELD_RETURN) {
            md.t0_v = t0_read.execute(0);
            md.ack_commit_at_v = commit_at_read.execute(0);
            md.resp_seen_mask = (bit<8>)mask_read.execute(0);
            compute_deadline_da(); compute_da_delta(); extract_da_ready();
            compute_deadline_readiness(); compute_readiness_delta(); extract_readiness_ready();
            compute_resp_target(); compute_gap_delta(); extract_gap_ready();
            if (hdr.ladder.role == ROLE_ACK_BLK) {
                md.ack_done_g = ack_done_read.execute(0);
                if ((bit<32>)hdr.ladder.generation != (md.cur_gen & 32w0xffff)) { stop_blocking_stale(); }
                else if (md.enabled == 0) { stop_blocking_off(); }
                else if (md.ack_done_g == md.cur_gen) { stop_blocking(); }
                else {
                    if ((md.da_ready == 1 && md.resp_seen_mask != 8w0) || md.readiness_ready == 1) { stop_blocking(); }
                    else if (hdr.ladder.budget == 0) { stop_blocking_tmo(); }
                    else { keep_blocking(HELD_RETURN, 7); }
                }
            } else if (hdr.ladder.role == ROLE_RESP_BLK) {
                md.resp_done_g = resp_done_read.execute(0);
                if ((bit<32>)hdr.ladder.generation != (md.cur_gen & 32w0xffff)) { stop_blocking_stale(); }
                else if (md.enabled == 0) { stop_blocking_off(); }
                else if (md.resp_done_g == md.cur_gen) { stop_blocking(); }
                else {
                    md.ack_done_g = ack_done_read.execute(0);
                    if ((md.ack_done_g == md.cur_gen && md.gap_ready == 1) || md.readiness_ready == 1) { stop_blocking(); }
                    else if (hdr.ladder.budget == 0) { stop_blocking_tmo(); }
                    else { keep_blocking(HELD_RETURN, 5); }
                }
            } else if (hdr.ladder.role == ROLE_ACK_HELD) {
                md.ack_done_g = ack_done_read.execute(0);
                if ((bit<32>)hdr.ladder.generation != (md.cur_gen & 32w0xffff)) { flush_ack_stale(); }
                else if (md.enabled == 0) { flush_ack_off(); }
                else if (md.ack_done_g == md.cur_gen) { mark_ack_done(); count(OUT_ACK_COMMIT); }
                else {
                    if (md.da_ready == 1 && md.resp_seen_mask != 8w0) {
                        mark_ack_commit_at(); compute_resp_target(); arm_resp_deadline(); mark_ack_done(); count(OUT_ACK_COMMIT);
                    } else if (md.readiness_ready == 1) { mark_ack_done(); count(OUT_ACK_FALLBACK); }
                    else { rewait_ack(); }
                }
            } else if (hdr.ladder.role == ROLE_RESP_HELD) {
                md.resp_done_g = resp_done_read.execute(0);
                if ((bit<32>)hdr.ladder.generation != (md.cur_gen & 32w0xffff)) { flush_response_stale(); }
                else if (md.enabled == 0) { flush_response_off(); }
                else if (md.resp_done_g == md.cur_gen) { mark_resp_done(); count(OUT_RESP_RELEASE); }
                else {
                    md.ack_done_g = ack_done_read.execute(0);
                    if (md.ack_done_g == md.cur_gen && md.gap_ready == 1) {
                        md.resp_deadline_v = deadline_arm.execute(0);
                        mark_resp_done(); count(OUT_RESP_RELEASE);
                    } else if (md.readiness_ready == 1) { mark_resp_done(); count(OUT_RESP_FALLBACK); }
                    else { rewait_response(); }
                }
            } else { unmatched(); }
        } else if (ig_intr_md.ingress_port == HB_RETURN) {
            md.op_gen = op_gen_peek.execute(0);
            md.op_t0_v = op_t0_read.execute(0);
            compute_op_t0_masked(); compute_op_deadline(); compute_op_delta(); extract_op_ready();
            if (hdr.ladder.role == ROLE_OP_BLK) {
                md.op_done_g = op_done_read.execute(0);
                if ((bit<32>)hdr.ladder.generation != (md.op_gen & 32w0xffff)) { stop_blocking_stale(); }
                else if (md.enabled == 0) { stop_blocking_off(); }
                else if (md.op_done_g == md.op_gen) { stop_blocking(); }
                else {
                    if (md.op_ready == 1) { stop_blocking(); }
                    else if (hdr.ladder.budget == 0) { stop_blocking_tmo(); }
                    else { keep_blocking(HB_RETURN, 3); }
                }
            } else if (hdr.ladder.role == ROLE_OP_HELD) {
                if ((bit<32>)hdr.ladder.generation != (md.op_gen & 32w0xffff)) { flush_operate_stale(); }
                else if (md.enabled == 0) { flush_operate_off(); }
                else {
                    md.op_done_g = op_done_try.execute(0);
                    if (md.op_done_g == md.op_gen) { rewait_operate(); }
                    else if (md.op_ready == 1) { release_operate(); count(OUT_OP_RELEASE); }
                    else { rewait_operate(); }
                }
            } else { unmatched(); }
        } else { unmatched(); }
        outcome_count.apply();
    }
}

control IngressDeparser(packet_out pkt, inout header_t hdr, in metadata_t md,
                       in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    // No-arg Mirror(): the typed Mirror(mirror_type) constructor errors "Inconsistent mirror
    // selectors" on Tofino-1 (defense4_rrc_bor_unified12.p4, IgDeparser).
    Mirror() clone_mirror;
    apply {
        if (ig_dprsr_md.mirror_type == MIRROR_TYPE_CLONE) {
            clone_mirror.emit<clone_hdr_t>(md.clone_ses, { md.clone_tag });
        }
        pkt.emit(hdr);
    }
}
#include "probe_shell.p4"

Pipeline(IngressParser(), Ingress(), IngressDeparser(), EmptyEgressParser(),
         EmptyEgress(), EmptyEgressDeparser()) pipe;
Switch(pipe) main;

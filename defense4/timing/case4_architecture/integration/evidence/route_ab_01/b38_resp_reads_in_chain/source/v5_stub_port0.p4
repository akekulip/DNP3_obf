// T's READ timing role, queue-resident design (not the heartbeat/recirculation design in
// read_timing.p4). Real ACK/response/OPERATE originals stay resident in their hold queues
// (LADDER qid6/qid4, OP_LADDER qid2); only blocker tokens (qid7/qid5/qid3) repeat the timing
// circulation, matching defense4_rrc_bor_unified12.p4's qid7/6/5/4/3/2 ladder
// (integration/INTEGRATION_CONTRACT.md section 1; the heartbeat design is a correctness
// reference only, never the base). Invariants (a)-(g): see
// integration/read/tests/test_t_queue_invariants.py and
// DNP3_Timing_Size_Integration_Prompt.md section 4, Phase C. The whole file still does not compile:
// table placement fails with zero slack on the ACK-commit->response chain (no longer a compiler crash);
// what has been compiled and model-run is listed in read/TIMING_QUEUE_MIGRATION_STATUS.md.
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
    // hdr.tev.epoch XOR the quarantined epoch, from quarantine_read: 0 exactly when this event's epoch is
    // quarantined. One value, so register actions that need the condition take one input (see t0_admit).
    // e_bad: 0 exactly when the event's epoch is the current epoch and not quarantined (epoch_check).
    bit<32> e_bad; bit<32> q_diff;
    bit<32> cur_gen; bit<32> new_gen; bit<32> t0_v;
    // done_diff: the role's done register XOR its live generation (ack/resp: cur_gen, OPERATE: op_gen),
    // before any write on this pass. 0 exactly when that domain already completed in this generation.
    bit<32> done_diff;
    // lgen_diff: the ladder record's 16-bit generation XOR the live generation's low 16 bits; 0 = current.
    bit<16> lgen_diff;
    // Narrow: these only ever hold a 3-bit child mask or a 0/1 flag -- bit<32> would occupy 4x the
    // PHV this design doesn't have to spare (see TIMING_QUEUE_MIGRATION_STATUS.md's PHV finding).
    bit<8> resp_seen_mask; bit<8> dup;
    bit<32> commit_diff;   // ack_commit_gen_reg XOR cur_gen: 0 = genuine ACK commit in this generation
    // 1 when this held ACK / held response may commit on this pass; the input to ack_done_try /
    // resp_done_try, computed before the register so the register needs no later dependent write.
    bit<8> ack_go; bit<8> resp_go; bit<8> commit_ok; bit<8> op_go;
    // Tofino's conditional-execution gateway cannot evaluate a live comparison between two fully
    // dynamic values (bf-p4c: "condition too complex ... one operand must be constant"), so every
    // now-vs-deadline check here is precomputed as delta = now - deadline, then its sign bit is
    // matched by a one-entry ternary table into a 0/1 ready flag -- read_timing.p4's own
    // deadline_deltas/heartbeat_eligibility pattern (see the *_sign tables). The
    // deltas/deadlines need the full dynamic range; the *_ready outputs are 0/1 flags and are
    // narrowed accordingly.
    // now_m_X = now - X: delta = now - (t0 + X) is computed as now_m_X - t0, the same value mod 2^32
    // in one subtraction after the register read instead of two (stage budget, see the *_sign tables).
    bit<32> now_m_da; bit<32> da_delta;
    bit<32> now_m_readiness; bit<32> readiness_delta;
    bit<32> now_m_gap; bit<32> gap_delta;
    bit<32> op_t0_masked; bit<32> now_m_opj; bit<32> op_delta;
    bit<32> op_gen; bit<32> op_t0_v;
    bit<32> clone_tag;
    // Generator token's batch_id XOR each domain's live generation (low 16 bits); 0 = current.
    bit<16> op_tok_diff; bit<16> rd_tok_diff;
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
    // The ACK/response epoch gate `epoch != cur_epoch || epoch == quarantine` as one value: a gateway
    // over three 32-bit fields exceeds the gateway width, bf-p4c split it across stages (cond-81$split),
    // and that pushed mask_try_admit* past mask_read's stage (route_ab_01/b26_qdiff_t0_access/pins2).
    // Quarantined (q_diff == 0) -> q_diff | 1, never 0; otherwise value XOR epoch, 0 iff current.
    RegisterAction<bit<32>, bit<1>, bit<32>>(cur_epoch_reg) epoch_check = {
        void apply(inout bit<32> value, out bit<32> out_value) {
            if (md.q_diff == 0) { out_value = md.q_diff | 32w1; }
            else { out_value = value ^ hdr.tev.epoch; }
        }
    };
    // An enabled REQUEST pass: returns the epoch as it was, and records the request's epoch unless that
    // epoch is quarantined (the quarantine comparison is done here, inside the register action, rather
    // than by a gateway in front of a separate write). Every register below that a request admission
    // writes follows this shape, so each one is accessed by one gateway-selected set of actions in one
    // stage just after quarantine_reg; a read at the top of the pass plus a write behind the quarantine
    // gateway could not share the register's stage ("Table placement was not able to allocate
    // tbl_read_cur_epoch, tbl_admit_request_epoch in the same stage", route_ab_01/b15_tin_flat).
    RegisterAction<bit<32>, bit<1>, bit<32>>(cur_epoch_reg) epoch_admit = {
        void apply(inout bit<32> value, out bit<32> out_value) {
            out_value = value;
            if (md.q_diff != 0) { value = hdr.tev.epoch; }
        }
    };
    Register<bit<32>, bit<1>>(1, 0xffffffff) quarantine_reg;
    // quarantine_reg on T_IN: every pass returns the quarantined epoch as it was before this pass; a
    // RESET pass (selected by hdr.tev.kind, a parser field) also records its epoch when the policy is
    // enabled. Two actions in exclusive branches of one gateway on a parser field share the register's
    // stage; a read at the top plus a write in the RESET arm did not (b8_req_tag_split/v5_stub_port0), and
    // a computed enable flag in front of the read cost the stage budget (b13_chain_shortening).
    RegisterAction<bit<32>, bit<1>, bit<32>>(quarantine_reg) quarantine_read = {
        void apply(inout bit<32> value, out bit<32> out_value) { out_value = value ^ hdr.tev.epoch; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(quarantine_reg) quarantine_reset = {
        void apply(inout bit<32> value, out bit<32> out_value) {
            out_value = value;
            if (md.enabled != 0) { value = hdr.tev.epoch; }
        }
    };
    Register<bit<32>, bit<1>>(1, 0) gen_alloc_reg;
    RegisterAction<bit<32>, bit<1>, bit<32>>(gen_alloc_reg) gen_peek = {
        void apply(inout bit<32> value, out bit<32> out_value) { out_value = value; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(gen_alloc_reg) gen_bump = {
        void apply(inout bit<32> value, out bit<32> out_value) { value = value + 1; out_value = value; }
    };
    // An enabled REQUEST pass: opens a new generation unless the request's epoch is quarantined.
    RegisterAction<bit<32>, bit<1>, bit<32>>(gen_alloc_reg) gen_admit = {
        void apply(inout bit<32> value, out bit<32> out_value) {
            if (md.q_diff != 0) { value = value + 1; }
            out_value = value;
        }
    };
    // Request-anchored t0 (NOTATION_MAPPING.md convention): the quantized arrival time of the
    // request that opened the current generation. da/readiness/cap are offsets from THIS, not
    // from the epoch. Written once per generation at admission (admit_request never fires twice
    // for the same generation, so no lazy-arm guard is needed here).
    Register<bit<32>, bit<1>>(1, 0) t0_reg;
    RegisterAction<bit<32>, bit<1>, bit<32>>(t0_reg) t0_read = {
        void apply(inout bit<32> value, out bit<32> out_value) { out_value = value; }
    };
    // An enabled REQUEST pass records its arrival time unless its epoch is quarantined; the condition is
    // decided here (q_diff) so t0_reg is accessed by one table, t0_access, in the prologue stage with the
    // generation and epoch registers. Behind the request arm's quarantine gateway the write landed a stage
    // later and pushed the whole ACK->response chain past stage 11 (route_ab_01/b24_pin_probe).
    RegisterAction<bit<32>, bit<1>, bit<32>>(t0_reg) t0_admit = {
        void apply(inout bit<32> value, out bit<32> out_value) {
            if (md.q_diff != 0) { value = md.now; }
            out_value = value;
        }
    };
    // Tofino requires every table (and every bare action call becomes one) to address at most one
    // indirect extern, so reads/writes spanning multiple registers are always split into separate
    // single-register actions called as separate statements, never bundled into one action body.
    action check_epoch() { md.e_bad = epoch_check.execute(0); }
    // Policy off: never "current epoch", so nothing gated on e_bad == 0 (the response mask) runs.
    action epoch_off() { md.e_bad = 1; }
    action read_quarantine() { md.q_diff = quarantine_read.execute(0); }
    // A RESET's output is not used; the RESET arm reads nothing that depends on the quarantine.
    action reset_quarantine() { quarantine_reset.execute(0); }
    action peek_gen() { md.cur_gen = gen_peek.execute(0); }
    action admit_gen() { md.new_gen = gen_admit.execute(0); }
    action reset_bump_gen() { md.new_gen = gen_bump.execute(0); }
    action admit_epoch() { epoch_admit.execute(0); }
    // gen_alloc_reg and cur_epoch_reg are each accessed by ONE table, applied once after quarantine_reg:
    // an enabled REQUEST on T_IN admits (bump / record, unless its epoch is quarantined, decided inside
    // the register action), an enabled RESET bumps the generation, every other pass reads. Entries are
    // matched in order, so the `enabled == 0` rows make the rest mean `enabled != 0` exactly. Separate
    // reads at the top of the pass plus writes behind the quarantine gateway did not place
    // (route_ab_01/b14..b16: cur_epoch_reg and gen_alloc_reg "not able to allocate ... in the same
    // stage", then "no more tables are placeable").
    table gen_access {
        key = { ig_intr_md.ingress_port : exact; hdr.tev.kind : ternary; md.enabled : ternary; }
        actions = { peek_gen; admit_gen; reset_bump_gen; }
        const entries = {
            (T_IN, KIND_REQUEST, 0) : peek_gen();
            (T_IN, KIND_REQUEST, _) : admit_gen();
            (T_IN, KIND_RESET, 0) : peek_gen();
            (T_IN, KIND_RESET, _) : reset_bump_gen();
        }
        default_action = peek_gen(); size = 4;
    }
    action read_t0() { md.t0_v = t0_read.execute(0); }
    action admit_t0() { md.t0_v = t0_admit.execute(0); }
    table t0_access {
        key = { ig_intr_md.ingress_port : exact; hdr.tev.kind : ternary; md.enabled : ternary; }
        actions = { read_t0; admit_t0; }
        const entries = {
            (T_IN, KIND_REQUEST, 0) : read_t0();
            (T_IN, KIND_REQUEST, _) : admit_t0();
        }
        default_action = read_t0(); size = 2;
    }
    table epoch_access {
        key = { ig_intr_md.ingress_port : exact; hdr.tev.kind : ternary; md.enabled : ternary; }
        actions = { check_epoch; admit_epoch; epoch_off; }
        const entries = {
            (T_IN, KIND_REQUEST, 0) : epoch_off();
            (T_IN, KIND_REQUEST, _) : admit_epoch();
            (T_IN, _, 0) : epoch_off();
        }
        default_action = check_epoch(); size = 3;
    }

    // ---- ACK domain -----------------------------------------------------------------------
    Register<bit<32>, bit<1>>(1, 0) ack_done_reg;
    // Pure read, returned as value XOR cur_gen: zero exactly when value == cur_gen. A table can match
    // "equals 0" on one field but cannot match two runtime fields for equality, so this lets the
    // response's go flag be one ternary table (resp_go_check) instead of a sign table, a gateway and an
    // assignment (stage budget, route_ab_01/b23).
    RegisterAction<bit<32>, bit<1>, bit<32>>(ack_done_reg) ack_done_read = {
        void apply(inout bit<32> value, out bit<32> out_value) { out_value = value ^ md.cur_gen; }
    };
    // Same atomic compare-and-commit shape as op_done_try: returns the old value, records cur_gen
    // when md.ack_go is set (rewriting an equal cur_gen is a no-op).
    RegisterAction<bit<32>, bit<1>, bit<32>>(ack_done_reg) ack_done_try = {
        void apply(inout bit<32> value, out bit<32> out_value) {
            out_value = value ^ md.cur_gen;
            if (md.ack_go == 1) { value = md.cur_gen; }
        }
    };
    // Generation-scoped a_commit (2026-10-09, route_ab_01/b30). Both registers are written only by a
    // genuine ACK commit (da passed with a response child seen): ack_commit_at_reg the time, and
    // ack_commit_gen_reg the READ generation it belongs to. A response may use a_commit only when
    // ack_commit_gen_reg is the current generation (commit_diff == 0, gating every gap_ready use). A RESET
    // (which bumps the generation) or an ACK that finished by readiness fallback (which records no
    // a_commit) leaves a non-matching generation, so a zero or stale time is never taken as a_commit in
    // the signed gap comparison; no RESET-time clear is needed. Two single-word registers rather than one
    // {gen, at} pair: a two-field stateful ALU may not return a computed value (bf-p4c "subtraction can
    // only be used when the result is written to the register", route_ab_01/b29).
    Register<bit<32>, bit<1>>(1, 0) ack_commit_at_reg;
    // Returns the response gap delta directly: (now - gap) - a_commit = now - (a_commit + gap).
    RegisterAction<bit<32>, bit<1>, bit<32>>(ack_commit_at_reg) commit_at_gap = {
        void apply(inout bit<32> value, out bit<32> out_value) { out_value = md.now_m_gap - value; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(ack_commit_at_reg) commit_at_write = {
        void apply(inout bit<32> value, out bit<32> out_value) { value = md.now; out_value = value; }
    };
    // Initial value 0xffffffff, not 0: generation 0 is the live READ generation before the first request,
    // so a register holding 0 would read as "a genuine commit in generation 0" (commit_diff == 0). Any
    // control-plane or hardware clear of this register must restore 0xffffffff, not 0.
    Register<bit<32>, bit<1>>(1, 0xffffffff) ack_commit_gen_reg;
    // value XOR cur_gen: 0 exactly when a genuine ACK commit happened in the current generation.
    RegisterAction<bit<32>, bit<1>, bit<32>>(ack_commit_gen_reg) commit_gen_read = {
        void apply(inout bit<32> value, out bit<32> out_value) { out_value = value ^ md.cur_gen; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(ack_commit_gen_reg) commit_gen_write = {
        void apply(inout bit<32> value, out bit<32> out_value) { value = md.cur_gen; out_value = value; }
    };

    // ---- response domain --------------------------------------------------------------------
    Register<bit<32>, bit<1>>(1, 0) resp_done_reg;
    RegisterAction<bit<32>, bit<1>, bit<32>>(resp_done_reg) resp_done_read = {
        void apply(inout bit<32> value, out bit<32> out_value) { out_value = value ^ md.cur_gen; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(resp_done_reg) resp_done_try = {
        void apply(inout bit<32> value, out bit<32> out_value) {
            out_value = value ^ md.cur_gen;
            if (md.resp_go == 1) { value = md.cur_gen; }
        }
    };
    // No resp_deadline register (removed 2026-10-09, route_ab_01/b28). It was armed (once per RESET, only
    // while 0) and cleared, but no decision ever read it: response release is decided from
    // ack_commit_at_reg (commit_at_gap) and the configured gap. Its value, a_commit + gap, is derivable
    // from ack_commit_at_reg + gap; the tests now check ack_commit_at_reg directly.
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
        void apply(inout bit<32> value, out bit<32> out_value) { out_value = value ^ md.op_gen; }
    };
    // Atomic compare-and-commit for a held OPERATE: returns the generation recorded BEFORE this pass
    // and records md.op_gen when the deadline has passed. A Tofino register lives in one stage, so the
    // old read-then-compare-then-dependent-write (op_done_read, gateway, op_done_write in a later
    // table) could not place; the caller now decides release from the returned old value instead.
    // Writing op_gen over an equal op_gen is a no-op, so the result matches the old three-step path.
    RegisterAction<bit<32>, bit<1>, bit<32>>(op_done_reg) op_done_try = {
        void apply(inout bit<32> value, out bit<32> out_value) {
            out_value = value ^ md.op_gen;
            if (md.op_go == 1) { value = md.op_gen; }
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
    // No RESET-time clear (2026-10-09, route_ab_01/b32). RESET invalidates OPERATE by bumping its
    // generation (reset_bump_op_gen): a held OPERATE and its blockers then fail the generation check and
    // are flushed / dropped as stale, without op_t0_reg's zero being read as "overdue" in the signed
    // deadline comparison (which was late by up to ~2.1 s in the upper half of the clock).

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
    // new_gen is gen_access's output from an earlier stage, so masking it here is an ordinary ALU op
    // (masking a stateful ALU's output in the action that receives it was IMPOSSIBLE_ALIGNMENT, b7).
    action admit_request() {
        hdr.tev.setInvalid();
        ig_tm_md.ucast_egress_port = RELAY_PORT;
        ig_dprsr_md.mirror_type = 1;
        md.clone_ses = CLONE_SESSION_ID;
        md.clone_tag = md.new_gen & 32w0xffff;
    }
    action bypass_request() {
        hdr.tev.setInvalid();
        ig_tm_md.ucast_egress_port = RELAY_PORT;
        count(OUT_REQ_BYPASS);
    }
    // The RESET pass never reads md.op_gen, so the bump's output is not written: writing it here and in
    // the OPERATE arm made a write-after-write order between two call sites of one register (b35).
    action reset_bump_op_gen() { op_gen_bump.execute(0); }

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
    // The held original carries the generation of the OPERATE that was admitted: the clone's own tag
    // (hold_operate wrote op_gen | 0x10000, so its low 16 bits are that generation's ladder value), not a
    // fresh read of op_gen_alloc_reg. Since RESET bumps the OPERATE generation, a fresh read could pick up
    // a RESET that landed between the admission and the clone's return, and the superseded OPERATE was
    // then released on its old deadline instead of flushed as stale (code review, 2026-10-09: RESET 1..5
    // us after the OPERATE; route_ab_01/b34_clone_tag_generation).
    action admit_operate_held() {
        hdr.ladder.setValid();
        hdr.ladder.role = ROLE_OP_HELD; hdr.ladder.child = 0;
        hdr.ladder.generation = (bit<16>)hdr.clone.tag; hdr.ladder.budget = 0;
        hdr.clone.setInvalid(); hdr.tev.setInvalid();
        ig_tm_md.ucast_egress_port = HB_RETURN; ig_tm_md.qid = 2;
    }
    action drop_clone() { ig_dprsr_md.drop_ctl = 1; }
    action passthrough_tev_relay() { hdr.tev.setInvalid(); ig_tm_md.ucast_egress_port = RELAY_PORT; }

    // ---- generator token -> blocker (ports 0, generator app) -----------------------------------
    action seed_ack_blocker() {
        hdr.timer.setInvalid(); hdr.ladder.setValid();
        hdr.ladder.role = ROLE_ACK_BLK; hdr.ladder.child = 0;
        hdr.ladder.generation = hdr.timer.batch_id; hdr.ladder.budget = md.budget_cap;
        ig_tm_md.ucast_egress_port = HELD_RETURN; ig_tm_md.qid = 7;
    }
    action seed_resp_blocker() {
        hdr.timer.setInvalid(); hdr.ladder.setValid();
        hdr.ladder.role = ROLE_RESP_BLK; hdr.ladder.child = 0;
        hdr.ladder.generation = hdr.timer.batch_id; hdr.ladder.budget = md.budget_cap;
        ig_tm_md.ucast_egress_port = HELD_RETURN; ig_tm_md.qid = 5;
    }
    action seed_op_blocker() {
        hdr.timer.setInvalid(); hdr.ladder.setValid();
        hdr.ladder.role = ROLE_OP_BLK; hdr.ladder.child = 0;
        hdr.ladder.generation = hdr.timer.batch_id; hdr.ladder.budget = md.budget_cap;
        ig_tm_md.ucast_egress_port = HB_RETURN; ig_tm_md.qid = 3;
    }
    // Token staleness without a gateway comparing two runtime fields: `token_gen != (gen & 0xffff)` in a
    // gateway (token_gen is the zero-extended 16-bit batch_id) was what turned this program's placement
    // errors into bf-p4c's bare "Internal compiler error" (route_ab_01/b19_port0_bisect: removing both such
    // comparisons, p3, gives readable errors; removing either alone, p1/p2, still crashes). The XOR is
    // zero exactly when batch_id equals the generation's low 16 bits, so `tok_diff != 0` is the same test.
    action token_diffs() {
        md.op_tok_diff = hdr.timer.batch_id ^ (bit<16>)md.op_gen;
        md.rd_tok_diff = hdr.timer.batch_id ^ (bit<16>)md.cur_gen;
    }
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
    // deadline and then testing its sign bit is still the fix. The sign bit is read by a one-entry
    // ternary table (*_sign), not by a `delta[31:31]` slice: the slice forced every field in the
    // now/t0/deadline/delta add chain, and global_tstamp itself, to split at bit 31, which no 32-bit
    // container can hold across an add ("PHV allocation was not successful", 40 slices [30:0]/[31:31],
    // evidence/route_ab_01/b6_branch_probes/v5_stub_port0.log). A TCAM key needs no such split.
    action held_offsets() {
        md.now_m_da = md.now - md.da; md.now_m_readiness = md.now - md.readiness; md.now_m_gap = md.now - md.gap;
    }
    action compute_da_delta() { md.da_delta = md.now_m_da - md.t0_v; }
    action compute_readiness_delta() { md.readiness_delta = md.now_m_readiness - md.t0_v; }
    action read_gap_delta() { md.gap_delta = commit_at_gap.execute(0); }
    action read_lgen_diff() { md.lgen_diff = hdr.ladder.generation ^ (bit<16>)md.cur_gen; }
    action op_lgen_diff() { md.lgen_diff = hdr.ladder.generation ^ (bit<16>)md.op_gen; }
    action read_ack_done() { md.done_diff = ack_done_read.execute(0); }
    action try_ack_done() { md.done_diff = ack_done_try.execute(0); }
    action read_resp_done() { md.done_diff = resp_done_read.execute(0); }
    action try_resp_done() { md.done_diff = resp_done_try.execute(0); }
    action read_op_done() { md.done_diff = op_done_read.execute(0); }
    action try_op_done() { md.done_diff = op_done_try.execute(0); }
    action compute_op_t0_masked() { md.op_t0_masked = md.op_t0_v & 32w0xfffffffe; }
    action op_offset() { md.now_m_opj = md.now - md.op_j; }
    action compute_op_delta() { md.op_delta = md.now_m_opj - md.op_t0_masked; }
    // resp_seen_mask != 0 compares one dynamic field against the constant 0 -- already legal for a
    // gateway (unlike the deadline sums above, this was never the "two dynamic operands" problem),
    // so it needs no delta/sign-bit treatment at all; used directly in conditions below.

    // ---- ladder dispatch: held originals release or rewait --------------------------------------
    // release_ack touches no register (ack_done_try commits); recording a_commit and outcomes are
    // separate single-register actions called as separate statements at each call site (Tofino:
    // one table/action may address at most one indirect extern).
    // Release only; ack_done_reg was already committed by ack_done_try on this same pass.
    // ack_go = (da passed AND a response child seen) OR readiness passed, read straight from the two
    // deltas' sign bits and the child mask by one ternary table instead of the *_sign tables followed by
    // a gateway and an assignment: that saves the stage the response commit chain needs to fit in 12
    // (route_ab_01/b17_gen_epoch_tables). resp_seen_mask != 0 is exact as three one-bit rows because the
    // mask_try_admit actions only ever set bits 0..2. Rows match in order; no row -> 0.
    // ack_go: this pass may commit the ACK domain (live, and da passed with a child seen, or readiness
    // passed). commit_ok: the genuine-commit case (live, da passed, child seen), which alone records
    // a_commit. Liveness is in the rows, so ack_done_try may run on every held-ACK pass and still writes
    // only on a live one. Rows match in order; the first row makes "_" mean enabled != 0 below it.
    action set_ack_go(bit<8> go, bit<8> ok) { md.ack_go = go; md.commit_ok = ok; }
    table ack_go_check {
        key = { md.enabled : ternary; md.lgen_diff : ternary; md.readiness_delta : ternary;
                md.da_delta : ternary; md.resp_seen_mask : ternary; }
        actions = { set_ack_go; }
        const entries = {
            (0, _, _, _, _) : set_ack_go(0, 0);
            (_, 0, _, 32w0 &&& 32w0x80000000, 8w1 &&& 8w1) : set_ack_go(1, 1);
            (_, 0, _, 32w0 &&& 32w0x80000000, 8w2 &&& 8w2) : set_ack_go(1, 1);
            (_, 0, _, 32w0 &&& 32w0x80000000, 8w4 &&& 8w4) : set_ack_go(1, 1);
            (_, 0, 32w0 &&& 32w0x80000000, _, _) : set_ack_go(1, 0);
        }
        default_action = set_ack_go(0, 0); size = 5;
    }
    action release_ack() {
        hdr.ladder.setInvalid();
        ig_tm_md.ucast_egress_port = FORWARD_PORT;
    }
    action mark_ack_commit_at() { commit_at_write.execute(0); }
    action mark_ack_commit_gen() { commit_gen_write.execute(0); }
    action read_commit_gen() { md.commit_diff = commit_gen_read.execute(0); }
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

    // resp_go = (genuine ACK commit in cur_gen AND a_commit + gap passed) OR readiness passed, as one ternary
    // table (rows match in order; no row -> 0). commit_diff == 0 is "a_commit belongs to this generation"
    // (see ack_commit_gen_reg); the deltas' sign bits stand for gap_ready / readiness_ready. An ACK that
    // finished by readiness fallback has no a_commit, so its response opens by readiness (OUT_RESP_FALLBACK).
    action set_resp_go(bit<8> v) { md.resp_go = v; }
    table resp_go_check {
        key = { md.enabled : ternary; md.lgen_diff : ternary; md.readiness_delta : ternary;
                md.gap_delta : ternary; md.commit_diff : ternary; }
        actions = { set_resp_go; }
        const entries = {
            (0, _, _, _, _) : set_resp_go(0);
            (_, 0, 32w0 &&& 32w0x80000000, _, _) : set_resp_go(1);
            (_, 0, _, 32w0 &&& 32w0x80000000, 0) : set_resp_go(1);
        }
        default_action = set_resp_go(0); size = 3;
    }
    // Release only; resp_done_reg was already committed by resp_done_try on this same pass.
    action release_response() {
        hdr.ladder.setInvalid();
        ig_tm_md.ucast_egress_port = FORWARD_PORT;
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

    action release_ack_commit() { release_ack(); count(OUT_ACK_COMMIT); }
    action release_ack_fallback() { release_ack(); count(OUT_ACK_FALLBACK); }
    action release_response_counted() { release_response(); count(OUT_RESP_RELEASE); }
    action release_response_fallback() { release_response(); count(OUT_RESP_FALLBACK); }
    action release_operate_counted() { release_operate(); count(OUT_OP_RELEASE); }
    action drop_tin() { ig_dprsr_md.drop_ctl = 1; }
    // op_go: a held OPERATE may commit (live and its deadline passed); op_done_try writes only then.
    action set_op_go(bit<8> v) { md.op_go = v; }
    table op_go_check {
        key = { md.enabled : ternary; md.lgen_diff : ternary; md.op_delta : ternary; }
        actions = { set_op_go; }
        const entries = {
            (0, _, _) : set_op_go(0);
            (_, 0, 32w0 &&& 32w0x80000000) : set_op_go(1);
        }
        default_action = set_op_go(0); size = 2;
    }
    action unmatched() { ig_dprsr_md.drop_ctl = 1; count(OUT_UNMATCHED); }

    // ---- verdict tables (route_ab_01/b35) ---------------------------------------------------------
    // Each port's terminal decision is one const-entries ternary table instead of a chain of gateways and
    // one-action tables: bf-p4c ran out of logical tables per stage ("too many tables total", b30..b33).
    // Rows are in the original if/else priority order and the first matching row wins. A row matching
    // 0 on a key makes "_" on that key mean "!= 0" in every later row of the same role/kind. Keys:
    // lgen_diff == 0 (ladder generation is current), done_diff == 0 (domain already completed in this
    // generation), 32w0 &&& 32w0x80000000 on a delta (that deadline has passed), commit_diff == 0
    // (genuine a_commit in this generation), one bit of resp_seen_mask (a response child seen; only bits
    // 0..2 are ever set), budget == 0 (blocker budget exhausted).
    table tin_verdict {
        key = { hdr.tev.kind : ternary; md.enabled : ternary; md.q_diff : ternary; md.e_bad : ternary;
                md.done_diff : ternary; md.dup : ternary; }
        actions = { passthrough_tev_relay; passthrough_tev_forward; drop_tin; bypass_request; admit_request;
                    hold_ack; drop_duplicate_response; admit_response; hold_operate; unmatched; }
        const entries = {
            (KIND_REQUEST, 0, _, _, _, _) : passthrough_tev_relay();
            (KIND_OPERATE, 0, _, _, _, _) : passthrough_tev_relay();
            (KIND_RESET, 0, _, _, _, _) : drop_tin();
            (_, 0, _, _, _, _) : passthrough_tev_forward();
            (KIND_REQUEST, _, 0, _, _, _) : bypass_request();
            (KIND_REQUEST, _, _, _, _, _) : admit_request();
            (KIND_RESET, _, _, _, _, _) : drop_tin();
            (KIND_ACK, _, _, 0, _, _) : hold_ack();
            (KIND_ACK, _, _, _, _, _) : passthrough_tev_forward();
            (KIND_RESPONSE, _, _, 0, 0, _) : passthrough_tev_forward();
            (KIND_RESPONSE, _, _, 0, _, 1) : drop_duplicate_response();
            (KIND_RESPONSE, _, _, 0, _, _) : admit_response();
            (KIND_RESPONSE, _, _, _, _, _) : passthrough_tev_forward();
            (KIND_OPERATE, _, _, _, _, _) : hold_operate();
        }
        default_action = unmatched(); size = 14;
    }
    table token_verdict {
        key = { hdr.timer.app_id : ternary; hdr.timer.packet_id : ternary; md.op_tok_diff : ternary;
                md.rd_tok_diff : ternary; }
        actions = { seed_op_blocker; seed_ack_blocker; seed_resp_blocker; drop_timer_stale; }
        const entries = {
            (1, _, 0, _) : seed_op_blocker();
            (1, _, _, _) : drop_timer_stale();
            (_, 16w0 &&& 16w1, _, 0) : seed_ack_blocker();
            (_, 16w0 &&& 16w1, _, _) : drop_timer_stale();
            (_, _, _, 0) : seed_resp_blocker();
        }
        default_action = drop_timer_stale(); size = 5;
    }
    table held_verdict {
        key = { hdr.ladder.role : ternary; md.lgen_diff : ternary; md.enabled : ternary; md.done_diff : ternary;
                md.da_delta : ternary; md.readiness_delta : ternary; md.gap_delta : ternary;
                md.commit_diff : ternary; md.resp_seen_mask : ternary; hdr.ladder.budget : ternary; }
        actions = { stop_blocking; stop_blocking_stale; stop_blocking_tmo; stop_blocking_off; keep_blocking;
                    release_ack_commit; release_ack_fallback; rewait_ack; flush_ack_stale; flush_ack_off;
                    release_response_counted; release_response_fallback; rewait_response;
                    flush_response_stale; flush_response_off; unmatched; }
        const entries = {
            (ROLE_ACK_BLK, 0, 0, _, _, _, _, _, _, _) : stop_blocking_off();
            (ROLE_ACK_BLK, 0, _, 0, _, _, _, _, _, _) : stop_blocking();
            (ROLE_ACK_BLK, 0, _, _, 32w0 &&& 32w0x80000000, _, _, _, 8w1 &&& 8w1, _) : stop_blocking();
            (ROLE_ACK_BLK, 0, _, _, 32w0 &&& 32w0x80000000, _, _, _, 8w2 &&& 8w2, _) : stop_blocking();
            (ROLE_ACK_BLK, 0, _, _, 32w0 &&& 32w0x80000000, _, _, _, 8w4 &&& 8w4, _) : stop_blocking();
            (ROLE_ACK_BLK, 0, _, _, _, 32w0 &&& 32w0x80000000, _, _, _, _) : stop_blocking();
            (ROLE_ACK_BLK, 0, _, _, _, _, _, _, _, 0) : stop_blocking_tmo();
            (ROLE_ACK_BLK, 0, _, _, _, _, _, _, _, _) : keep_blocking(HELD_RETURN, 7);
            (ROLE_ACK_BLK, _, _, _, _, _, _, _, _, _) : stop_blocking_stale();
            (ROLE_RESP_BLK, 0, 0, _, _, _, _, _, _, _) : stop_blocking_off();
            (ROLE_RESP_BLK, 0, _, 0, _, _, _, _, _, _) : stop_blocking();
            (ROLE_RESP_BLK, 0, _, _, _, _, 32w0 &&& 32w0x80000000, 0, _, _) : stop_blocking();
            (ROLE_RESP_BLK, 0, _, _, _, 32w0 &&& 32w0x80000000, _, _, _, _) : stop_blocking();
            (ROLE_RESP_BLK, 0, _, _, _, _, _, _, _, 0) : stop_blocking_tmo();
            (ROLE_RESP_BLK, 0, _, _, _, _, _, _, _, _) : keep_blocking(HELD_RETURN, 5);
            (ROLE_RESP_BLK, _, _, _, _, _, _, _, _, _) : stop_blocking_stale();
            (ROLE_ACK_HELD, 0, 0, _, _, _, _, _, _, _) : flush_ack_off();
            (ROLE_ACK_HELD, 0, _, 0, _, _, _, _, _, _) : release_ack_commit();
            (ROLE_ACK_HELD, 0, _, _, 32w0 &&& 32w0x80000000, _, _, _, 8w1 &&& 8w1, _) : release_ack_commit();
            (ROLE_ACK_HELD, 0, _, _, 32w0 &&& 32w0x80000000, _, _, _, 8w2 &&& 8w2, _) : release_ack_commit();
            (ROLE_ACK_HELD, 0, _, _, 32w0 &&& 32w0x80000000, _, _, _, 8w4 &&& 8w4, _) : release_ack_commit();
            (ROLE_ACK_HELD, 0, _, _, _, 32w0 &&& 32w0x80000000, _, _, _, _) : release_ack_fallback();
            (ROLE_ACK_HELD, 0, _, _, _, _, _, _, _, _) : rewait_ack();
            (ROLE_ACK_HELD, _, _, _, _, _, _, _, _, _) : flush_ack_stale();
            (ROLE_RESP_HELD, 0, 0, _, _, _, _, _, _, _) : flush_response_off();
            (ROLE_RESP_HELD, 0, _, 0, _, _, _, _, _, _) : release_response_counted();
            (ROLE_RESP_HELD, 0, _, _, _, _, 32w0 &&& 32w0x80000000, 0, _, _) : release_response_counted();
            (ROLE_RESP_HELD, 0, _, _, _, 32w0 &&& 32w0x80000000, _, _, _, _) : release_response_fallback();
            (ROLE_RESP_HELD, 0, _, _, _, _, _, _, _, _) : rewait_response();
            (ROLE_RESP_HELD, _, _, _, _, _, _, _, _, _) : flush_response_stale();
        }
        default_action = unmatched(); size = 30;
    }
    table hb_verdict {
        key = { hdr.ladder.role : ternary; md.lgen_diff : ternary; md.enabled : ternary; md.done_diff : ternary;
                md.op_delta : ternary; hdr.ladder.budget : ternary; }
        actions = { stop_blocking; stop_blocking_stale; stop_blocking_tmo; stop_blocking_off; keep_blocking;
                    release_operate_counted; rewait_operate; flush_operate_stale; flush_operate_off; unmatched; }
        const entries = {
            (ROLE_OP_BLK, 0, 0, _, _, _) : stop_blocking_off();
            (ROLE_OP_BLK, 0, _, 0, _, _) : stop_blocking();
            (ROLE_OP_BLK, 0, _, _, 32w0 &&& 32w0x80000000, _) : stop_blocking();
            (ROLE_OP_BLK, 0, _, _, _, 0) : stop_blocking_tmo();
            (ROLE_OP_BLK, 0, _, _, _, _) : keep_blocking(HB_RETURN, 3);
            (ROLE_OP_BLK, _, _, _, _, _) : stop_blocking_stale();
            (ROLE_OP_HELD, 0, 0, _, _, _) : flush_operate_off();
            (ROLE_OP_HELD, 0, _, 0, _, _) : rewait_operate();
            (ROLE_OP_HELD, 0, _, _, 32w0 &&& 32w0x80000000, _) : release_operate_counted();
            (ROLE_OP_HELD, 0, _, _, _, _) : rewait_operate();
            (ROLE_OP_HELD, _, _, _, _, _) : flush_operate_stale();
        }
        default_action = unmatched(); size = 11;
    }

    apply {
        ig_tm_md.bypass_egress = 0;
        md.outcome_code = OUT_NONE;
        params.apply(); clock.apply();
        // Prologue: quarantine (T_IN only), then the generation and epoch tables (see gen_access). On a
        // REQUEST or RESET pass md.cur_gen / md.e_bad are not read afterwards (those arms use new_gen).
        if (ig_intr_md.ingress_port == T_IN) {
            if (hdr.tev.kind == KIND_RESET) { reset_quarantine(); } else { read_quarantine(); }
        }
        gen_access.apply();
        epoch_access.apply();
        t0_access.apply();

        if (ig_intr_md.ingress_port == PKTGEN_RETURN) {
            if (hdr.tev.kind == KIND_OPERATE && md.enabled != 0) { admit_operate_held(); }
            else { drop_clone(); }
        } else if (ig_intr_md.ingress_port == T_IN) {
            // Register work first, each under a gateway of at most 40 bits; then one verdict. e_bad is
            // nonzero whenever the policy is off (epoch_access), so the mask is never touched then. The
            // child is marked before resp_done_reg is read (stage-ordering loop, b11): the mask's only
            // other consumer is the ACK gate (mask_read -> resp_seen_mask in ack_go_check and the
            // ACK roles' verdict rows), which tests only "some child seen", already true once a response
            // has been released in this generation.
            if (hdr.tev.kind == KIND_RESPONSE && md.e_bad == 0) {
                if (hdr.tev.stage == 0) { md.dup = (bit<8>)mask_try_admit0.execute(0); }
                else if (hdr.tev.stage == 1) { md.dup = (bit<8>)mask_try_admit1.execute(0); }
                else { md.dup = (bit<8>)mask_try_admit2.execute(0); }
            }
            if (hdr.tev.kind == KIND_OPERATE && md.enabled != 0) {
                md.op_gen = op_gen_bump.execute(0);
                op_t0_arm.execute(0);
            } else if (hdr.tev.kind == KIND_RESET && md.enabled != 0) { reset_bump_op_gen(); }
            // Its own gateway: resp_done_reg sits in a late stage (resp_done_try on the held response), and
            // bf-p4c places a gateway with the first table it guards, so sharing the mask's gateway held
            // everything after it back to that late stage (b36).
            if (hdr.tev.kind == KIND_RESPONSE && md.e_bad == 0) { read_resp_done(); }
            tin_verdict.apply();
        } else if (ig_intr_md.ingress_port == 0) { unmatched(); } else if (ig_intr_md.ingress_port == HELD_RETURN) {
            md.resp_seen_mask = (bit<8>)mask_read.execute(0);
            held_offsets();
            compute_da_delta(); compute_readiness_delta(); read_lgen_diff();
            // An else-if chain (the roles are exclusive, so the done_diff writes do not order each other),
            // ordered by the stage its first table needs: bf-p4c places each gateway with the first table
            // it guards, and a later gateway in the chain cannot precede an earlier one, so a late branch
            // first (read_resp_done) held every branch after it back to that stage (b36).
            if (hdr.ladder.role == ROLE_ACK_HELD) {
                ack_go_check.apply();
                try_ack_done();
                // Genuine commit: live, not already committed in this generation, da passed, child seen.
                if (md.done_diff != 0 && md.commit_ok == 1) { mark_ack_commit_at(); mark_ack_commit_gen(); }
            } else if (hdr.ladder.role == ROLE_ACK_BLK) { read_ack_done(); }
            // Only the response roles read the gap delta and the genuine-commit tag (a held ACK's commit pass
            // must not access ack_commit_at_reg twice, b25). Inside the chain, after the ACK-commit branch,
            // these reads land in the stage of the commit writes they share registers with (b37).
            else if (hdr.ladder.role == ROLE_RESP_HELD) {
                read_gap_delta(); read_commit_gen();
                resp_go_check.apply();
                try_resp_done();
            } else if (hdr.ladder.role == ROLE_RESP_BLK) { read_gap_delta(); read_commit_gen(); read_resp_done(); }
            held_verdict.apply();
        } else if (ig_intr_md.ingress_port == HB_RETURN) {
            md.op_gen = op_gen_peek.execute(0);
            md.op_t0_v = op_t0_read.execute(0);
            op_offset(); compute_op_t0_masked(); compute_op_delta(); op_lgen_diff();
            if (hdr.ladder.role == ROLE_OP_HELD) { op_go_check.apply(); try_op_done(); }
            else if (hdr.ladder.role == ROLE_OP_BLK) { read_op_done(); }
            hb_verdict.apply();
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

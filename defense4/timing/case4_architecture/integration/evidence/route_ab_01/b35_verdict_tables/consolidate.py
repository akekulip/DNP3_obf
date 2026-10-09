"""Consolidate read_queue_timing.p4's decision logic into per-port verdict tables (route_ab_01/b35).

Behavior-preserving restructuring: every terminal decision that used to be a chain of gateways and
one-action tables becomes one row of a const-entries ternary table, in the original priority order.
Two-field equalities become "== 0" keys through XOR diffs; "!= 0" is expressed by an earlier row that
matches 0. Register actions keep their own (narrow) gateways.

usage: consolidate.py <read_queue_timing.p4>   (edits in place; every replacement must match once)
"""
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
t = path.read_text()


def rep(a, b, n=1):
    global t
    k = t.count(a)
    assert k == n, (k, a[:100])
    t = t.replace(a, b)


def cut(start, end_marker, repl=''):
    """Replace from `start` (inclusive) to the end of `end_marker` (inclusive) found after it."""
    global t
    s = t.index(start)
    e = t.index(end_marker, s) + len(end_marker)
    t = t[:s] + repl + t[e:]


POS = '32w0 &&& 32w0x80000000'   # sign bit clear: "deadline passed"

# ---- metadata ---------------------------------------------------------------------------------
rep("""    bit<32> ack_done_g; bit<32> resp_done_g;
    bit<32> ack_diff;   // ack_done_reg XOR cur_gen from ack_done_read: 0 exactly when the ACK committed in cur_gen
""", """    // done_diff: the role's done register XOR its live generation (ack/resp: cur_gen, OPERATE: op_gen),
    // before any write on this pass. 0 exactly when that domain already completed in this generation.
    bit<32> done_diff;
    // lgen_diff: the ladder record's 16-bit generation XOR the live generation's low 16 bits; 0 = current.
    bit<16> lgen_diff;
""")
rep("    bit<8> ack_go; bit<8> resp_go;", "    bit<8> ack_go; bit<8> resp_go; bit<8> commit_ok; bit<8> op_go;")
rep("    bit<32> now_m_da; bit<32> da_delta; bit<8> da_ready;", "    bit<32> now_m_da; bit<32> da_delta;")
rep("    bit<32> now_m_readiness; bit<32> readiness_delta; bit<8> readiness_ready;", "    bit<32> now_m_readiness; bit<32> readiness_delta;")
rep("    bit<32> now_m_gap; bit<32> gap_delta; bit<8> gap_ready;", "    bit<32> now_m_gap; bit<32> gap_delta;")
rep("    bit<32> op_t0_masked; bit<32> now_m_opj; bit<32> op_delta; bit<8> op_ready;", "    bit<32> op_t0_masked; bit<32> now_m_opj; bit<32> op_delta;")
rep("    bit<32> op_gen; bit<32> op_done_g; bit<32> op_t0_v;", "    bit<32> op_gen; bit<32> op_t0_v;")
rep("""    bit<32> clone_tag; bit<32> token_gen; bit<32> token_domain;
    bit<16> tok_diff;   // generator token's batch_id XOR the live generation's low 16 bits; 0 = current""",
    """    bit<32> clone_tag;
    // Generator token's batch_id XOR each domain's live generation (low 16 bits); 0 = current.
    bit<16> op_tok_diff; bit<16> rd_tok_diff;""")

# ---- epoch_access: e_bad is nonzero whenever the policy is off ------------------------------------
rep("    action check_epoch() { md.e_bad = epoch_check.execute(0); }",
    "    action check_epoch() { md.e_bad = epoch_check.execute(0); }\n"
    "    // Policy off: never \"current epoch\", so nothing gated on e_bad == 0 (the response mask) runs.\n"
    "    action epoch_off() { md.e_bad = 1; }")
rep("        actions = { check_epoch; admit_epoch; }", "        actions = { check_epoch; admit_epoch; epoch_off; }")
rep("            (T_IN, KIND_REQUEST, 0) : check_epoch();\n            (T_IN, KIND_REQUEST, _) : admit_epoch();",
    "            (T_IN, KIND_REQUEST, 0) : epoch_off();\n            (T_IN, KIND_REQUEST, _) : admit_epoch();\n"
    "            (T_IN, _, 0) : epoch_off();")
rep("        default_action = check_epoch(); size = 2;", "        default_action = check_epoch(); size = 3;")

# ---- done registers return value XOR live generation (old value, before any write) ---------------
rep("""    RegisterAction<bit<32>, bit<1>, bit<32>>(ack_done_reg) ack_done_try = {
        void apply(inout bit<32> value, out bit<32> out_value) {
            out_value = value;
            if (md.ack_go == 1) { value = md.cur_gen; }
        }
    };""", """    RegisterAction<bit<32>, bit<1>, bit<32>>(ack_done_reg) ack_done_try = {
        void apply(inout bit<32> value, out bit<32> out_value) {
            out_value = value ^ md.cur_gen;
            if (md.ack_go == 1) { value = md.cur_gen; }
        }
    };""")
rep("""    RegisterAction<bit<32>, bit<1>, bit<32>>(resp_done_reg) resp_done_read = {
        void apply(inout bit<32> value, out bit<32> out_value) { out_value = value; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(resp_done_reg) resp_done_try = {
        void apply(inout bit<32> value, out bit<32> out_value) {
            out_value = value;
            if (md.resp_go == 1) { value = md.cur_gen; }
        }
    };""", """    RegisterAction<bit<32>, bit<1>, bit<32>>(resp_done_reg) resp_done_read = {
        void apply(inout bit<32> value, out bit<32> out_value) { out_value = value ^ md.cur_gen; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(resp_done_reg) resp_done_try = {
        void apply(inout bit<32> value, out bit<32> out_value) {
            out_value = value ^ md.cur_gen;
            if (md.resp_go == 1) { value = md.cur_gen; }
        }
    };""")
rep("""    RegisterAction<bit<32>, bit<1>, bit<32>>(op_done_reg) op_done_read = {
        void apply(inout bit<32> value, out bit<32> out_value) { out_value = value; }
    };""", """    RegisterAction<bit<32>, bit<1>, bit<32>>(op_done_reg) op_done_read = {
        void apply(inout bit<32> value, out bit<32> out_value) { out_value = value ^ md.op_gen; }
    };""")
rep("""            out_value = value;
            if (md.op_ready == 1) { value = md.op_gen; }""", """            out_value = value ^ md.op_gen;
            if (md.op_go == 1) { value = md.op_gen; }""")

# ---- request admission: one action (new_gen comes from gen_access, an earlier stage) --------------
cut("    action admit_request_gen() {", "    action make_request_tag() { md.clone_tag = md.new_gen & 32w0xffff; }\n",
    """    // new_gen is gen_access's output from an earlier stage, so masking it here is an ordinary ALU op
    // (masking a stateful ALU's output in the action that receives it was IMPOSSIBLE_ALIGNMENT, b7).
    action admit_request() {
        hdr.tev.setInvalid();
        ig_tm_md.ucast_egress_port = RELAY_PORT;
        ig_dprsr_md.mirror_type = 1;
        md.clone_ses = CLONE_SESSION_ID;
        md.clone_tag = md.new_gen & 32w0xffff;
    }
""")

# ---- generator tokens: generation straight from the token's batch_id ------------------------------
rep("hdr.ladder.generation = (bit<16>)md.token_gen; hdr.ladder.budget = md.budget_cap;",
    "hdr.ladder.generation = hdr.timer.batch_id; hdr.ladder.budget = md.budget_cap;", 3)
rep("""    action op_token_diff() { md.tok_diff = hdr.timer.batch_id ^ (bit<16>)md.op_gen; }
    action read_token_diff() { md.tok_diff = hdr.timer.batch_id ^ (bit<16>)md.cur_gen; }
    action drop_timer() { hdr.timer.setInvalid(); ig_dprsr_md.drop_ctl = 1; }
""", """    action token_diffs() {
        md.op_tok_diff = hdr.timer.batch_id ^ (bit<16>)md.op_gen;
        md.rd_tok_diff = hdr.timer.batch_id ^ (bit<16>)md.cur_gen;
    }
""")

# ---- remove the sign tables (verdict and go tables key on the deltas' sign bits directly) ----------
cut("    action set_da_ready(bit<8> v) { md.da_ready = v; }", "default_action = set_da_ready(0); size = 1;\n    }\n")
cut("    action set_readiness_ready(bit<8> v) { md.readiness_ready = v; }", "default_action = set_readiness_ready(0); size = 1;\n    }\n")
cut("    action set_gap_ready(bit<8> v) { md.gap_ready = v; }", "default_action = set_gap_ready(0); size = 1;\n    }\n")
cut("    action set_op_ready(bit<8> v) { md.op_ready = v; }", "default_action = set_op_ready(0); size = 1;\n    }\n")
rep("    action read_gap_delta() { md.gap_delta = commit_at_gap.execute(0); }\n",
    """    action read_gap_delta() { md.gap_delta = commit_at_gap.execute(0); }
    action read_lgen_diff() { md.lgen_diff = hdr.ladder.generation ^ (bit<16>)md.cur_gen; }
    action op_lgen_diff() { md.lgen_diff = hdr.ladder.generation ^ (bit<16>)md.op_gen; }
    action read_ack_done() { md.done_diff = ack_done_read.execute(0); }
    action try_ack_done() { md.done_diff = ack_done_try.execute(0); }
    action read_resp_done() { md.done_diff = resp_done_read.execute(0); }
    action try_resp_done() { md.done_diff = resp_done_try.execute(0); }
    action read_op_done() { md.done_diff = op_done_read.execute(0); }
    action try_op_done() { md.done_diff = op_done_try.execute(0); }
""")

# ---- go tables include liveness (current generation AND policy on) -------------------------------
s = t.index("    action set_ack_go(bit<8> v) { md.ack_go = v; }")
e = t.index("        default_action = set_ack_go(0); size = 4;\n    }\n", s) + len("        default_action = set_ack_go(0); size = 4;\n    }\n")
t = t[:s] + """    // ack_go: this pass may commit the ACK domain (live, and da passed with a child seen, or readiness
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
            (_, 0, _, %(P)s, 8w1 &&& 8w1) : set_ack_go(1, 1);
            (_, 0, _, %(P)s, 8w2 &&& 8w2) : set_ack_go(1, 1);
            (_, 0, _, %(P)s, 8w4 &&& 8w4) : set_ack_go(1, 1);
            (_, 0, %(P)s, _, _) : set_ack_go(1, 0);
        }
        default_action = set_ack_go(0, 0); size = 5;
    }
""" % {'P': POS} + t[e:]
s = t.index("    action set_resp_go(bit<8> v) { md.resp_go = v; }")
e = t.index("        default_action = set_resp_go(0); size = 2;\n    }\n", s) + len("        default_action = set_resp_go(0); size = 2;\n    }\n")
t = t[:s] + """    action set_resp_go(bit<8> v) { md.resp_go = v; }
    table resp_go_check {
        key = { md.enabled : ternary; md.lgen_diff : ternary; md.readiness_delta : ternary;
                md.gap_delta : ternary; md.commit_diff : ternary; }
        actions = { set_resp_go; }
        const entries = {
            (0, _, _, _, _) : set_resp_go(0);
            (_, 0, %(P)s, _, _) : set_resp_go(1);
            (_, 0, _, %(P)s, 0) : set_resp_go(1);
        }
        default_action = set_resp_go(0); size = 3;
    }
""" % {'P': POS} + t[e:]

# ---- released-and-counted actions + verdict tables --------------------------------------------------
anchor = "    action unmatched() { ig_dprsr_md.drop_ctl = 1; count(OUT_UNMATCHED); }\n"
verdicts = """    action release_ack_commit() { release_ack(); count(OUT_ACK_COMMIT); }
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
            (_, 0, %(P)s) : set_op_go(1);
        }
        default_action = set_op_go(0); size = 2;
    }
""" % {'P': POS} + anchor + """
    // ---- verdict tables (route_ab_01/b35) ---------------------------------------------------------
    // Each port's terminal decision is one const-entries ternary table instead of a chain of gateways and
    // one-action tables: bf-p4c ran out of logical tables per stage ("too many tables total", b30..b33).
    // Rows are in the original if/else priority order and the first matching row wins. A row matching
    // 0 on a key makes "_" on that key mean "!= 0" in every later row of the same role/kind. Keys:
    // lgen_diff == 0 (ladder generation is current), done_diff == 0 (domain already completed in this
    // generation), %(P)s on a delta (that deadline has passed), commit_diff == 0
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
            (ROLE_ACK_BLK, 0, _, _, %(P)s, _, _, _, 8w1 &&& 8w1, _) : stop_blocking();
            (ROLE_ACK_BLK, 0, _, _, %(P)s, _, _, _, 8w2 &&& 8w2, _) : stop_blocking();
            (ROLE_ACK_BLK, 0, _, _, %(P)s, _, _, _, 8w4 &&& 8w4, _) : stop_blocking();
            (ROLE_ACK_BLK, 0, _, _, _, %(P)s, _, _, _, _) : stop_blocking();
            (ROLE_ACK_BLK, 0, _, _, _, _, _, _, _, 0) : stop_blocking_tmo();
            (ROLE_ACK_BLK, 0, _, _, _, _, _, _, _, _) : keep_blocking(HELD_RETURN, 7);
            (ROLE_ACK_BLK, _, _, _, _, _, _, _, _, _) : stop_blocking_stale();
            (ROLE_RESP_BLK, 0, 0, _, _, _, _, _, _, _) : stop_blocking_off();
            (ROLE_RESP_BLK, 0, _, 0, _, _, _, _, _, _) : stop_blocking();
            (ROLE_RESP_BLK, 0, _, _, _, _, %(P)s, 0, _, _) : stop_blocking();
            (ROLE_RESP_BLK, 0, _, _, _, %(P)s, _, _, _, _) : stop_blocking();
            (ROLE_RESP_BLK, 0, _, _, _, _, _, _, _, 0) : stop_blocking_tmo();
            (ROLE_RESP_BLK, 0, _, _, _, _, _, _, _, _) : keep_blocking(HELD_RETURN, 5);
            (ROLE_RESP_BLK, _, _, _, _, _, _, _, _, _) : stop_blocking_stale();
            (ROLE_ACK_HELD, 0, 0, _, _, _, _, _, _, _) : flush_ack_off();
            (ROLE_ACK_HELD, 0, _, 0, _, _, _, _, _, _) : release_ack_commit();
            (ROLE_ACK_HELD, 0, _, _, %(P)s, _, _, _, 8w1 &&& 8w1, _) : release_ack_commit();
            (ROLE_ACK_HELD, 0, _, _, %(P)s, _, _, _, 8w2 &&& 8w2, _) : release_ack_commit();
            (ROLE_ACK_HELD, 0, _, _, %(P)s, _, _, _, 8w4 &&& 8w4, _) : release_ack_commit();
            (ROLE_ACK_HELD, 0, _, _, _, %(P)s, _, _, _, _) : release_ack_fallback();
            (ROLE_ACK_HELD, 0, _, _, _, _, _, _, _, _) : rewait_ack();
            (ROLE_ACK_HELD, _, _, _, _, _, _, _, _, _) : flush_ack_stale();
            (ROLE_RESP_HELD, 0, 0, _, _, _, _, _, _, _) : flush_response_off();
            (ROLE_RESP_HELD, 0, _, 0, _, _, _, _, _, _) : release_response_counted();
            (ROLE_RESP_HELD, 0, _, _, _, _, %(P)s, 0, _, _) : release_response_counted();
            (ROLE_RESP_HELD, 0, _, _, _, %(P)s, _, _, _, _) : release_response_fallback();
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
            (ROLE_OP_BLK, 0, _, _, %(P)s, _) : stop_blocking();
            (ROLE_OP_BLK, 0, _, _, _, 0) : stop_blocking_tmo();
            (ROLE_OP_BLK, 0, _, _, _, _) : keep_blocking(HB_RETURN, 3);
            (ROLE_OP_BLK, _, _, _, _, _) : stop_blocking_stale();
            (ROLE_OP_HELD, 0, 0, _, _, _) : flush_operate_off();
            (ROLE_OP_HELD, 0, _, 0, _, _) : rewait_operate();
            (ROLE_OP_HELD, 0, _, _, %(P)s, _) : release_operate_counted();
            (ROLE_OP_HELD, 0, _, _, _, _) : rewait_operate();
            (ROLE_OP_HELD, _, _, _, _, _) : flush_operate_stale();
        }
        default_action = unmatched(); size = 11;
    }
""" % {'P': POS}
rep(anchor, verdicts)

# ---- the apply block ----------------------------------------------------------------------------------
s = t.index("        if (ig_intr_md.ingress_port == PKTGEN_RETURN) {")
e = t.index("        outcome_count.apply();", s)
t = t[:s] + """        if (ig_intr_md.ingress_port == PKTGEN_RETURN) {
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
                read_resp_done();
            }
            if (hdr.tev.kind == KIND_OPERATE && md.enabled != 0) {
                md.op_gen = op_gen_bump.execute(0);
                op_t0_arm.execute(0);
            }
            if (hdr.tev.kind == KIND_RESET && md.enabled != 0) { reset_bump_op_gen(); }
            tin_verdict.apply();
        } else if (ig_intr_md.ingress_port == 0) {
            md.op_gen = op_gen_peek.execute(0);
            token_diffs();
            token_verdict.apply();
        } else if (ig_intr_md.ingress_port == HELD_RETURN) {
            md.resp_seen_mask = (bit<8>)mask_read.execute(0);
            held_offsets();
            compute_da_delta(); compute_readiness_delta(); read_lgen_diff();
            // Only the response roles use the gap delta and the genuine-commit tag (a held ACK's commit
            // pass must not access ack_commit_at_reg twice, b25).
            if (hdr.ladder.role == ROLE_RESP_BLK || hdr.ladder.role == ROLE_RESP_HELD) {
                read_gap_delta(); read_commit_gen();
            }
            if (hdr.ladder.role == ROLE_ACK_BLK) { read_ack_done(); }
            else if (hdr.ladder.role == ROLE_RESP_BLK) { read_resp_done(); }
            else if (hdr.ladder.role == ROLE_ACK_HELD) {
                ack_go_check.apply();
                try_ack_done();
                // Genuine commit: live, not already committed in this generation, da passed, child seen.
                if (md.done_diff != 0 && md.commit_ok == 1) { mark_ack_commit_at(); mark_ack_commit_gen(); }
            } else if (hdr.ladder.role == ROLE_RESP_HELD) {
                resp_go_check.apply();
                try_resp_done();
            }
            held_verdict.apply();
        } else if (ig_intr_md.ingress_port == HB_RETURN) {
            md.op_gen = op_gen_peek.execute(0);
            md.op_t0_v = op_t0_read.execute(0);
            op_offset(); compute_op_t0_masked(); compute_op_delta(); op_lgen_diff();
            if (hdr.ladder.role == ROLE_OP_BLK) { read_op_done(); }
            else if (hdr.ladder.role == ROLE_OP_HELD) { op_go_check.apply(); try_op_done(); }
            hb_verdict.apply();
        } else { unmatched(); }
""" + t[e:]
path.write_text(t)
print('ok')

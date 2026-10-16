"""Generate the control-timing candidate from the qualified candidate61 source (Gate 3; see DESIGN.md).

Milestone 1 (this generator's `m1`): the SELECT transaction joins T's READ lane. N only:
  - read_terminal_t: SELECT (kind 5) commits to T as a REQUEST (commit_before_t(9)) instead of leaving through
    terminal_ack; the control response in owner state 9 (kind 6) is emitted to T as a RESPONSE (0x0b00).
  - first_event: the outstation's bare ACK in owner state 9 is a lane ACK (first_read_ack) instead of
    forward_original.
  - no t0 stamp for SELECT/response events (the loop parser reads them without hdr.t0; T ignores t0q).
The OPERATE transaction (owner state 0xc) is untouched in m1. E and T are byte-identical; the generator asserts
both, and that putting the original N back reconstructs the input.
"""
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parent / 'seg61_02/evidence/full_04/response_only.p4'
SOURCE_SHA256 = '1b2d62d16d40427d8b7e5d4b93f9e57b75e721e6a6c7e4c184fb84a1dc3665aa'

spec = importlib.util.spec_from_file_location('ctl_timing_combined', HERE.parent / 'combined_nt_01/generate.py')
combined = importlib.util.module_from_spec(spec)
spec.loader.exec_module(combined)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def frozen():
    raw = SOURCE.read_bytes()
    assert digest(raw) == SOURCE_SHA256, 'qualified candidate61 input changed'
    return raw.decode()


def once(text, old, new):
    count = text.count(old)
    assert count == 1, ('anchor not found exactly once', count, old[:120])
    return text.replace(old, new, 1)


def transform_n_m1(n):
    # No t0 stamp on first_select/first_response: N's loop parser (envelope_event) reads events 0x0105/0x0106
    # without hdr.t0, so stamping it shifts the loop packet (model_control_timing_m1_01_02: SELECT reparsed as
    # packet_kind 0 and lost). T never reads t0q, so commit_before_t/emit_tev may carry an unset value.
    n = once(n, '(8w10,3w1,_,32w0x90000&&&32w0xffff0000,_,_,_,_,_,_):forward_original();',
             '(8w10,3w1,_,32w0x90000&&&32w0xffff0000,_,_,_,_,_,_):first_read_ack();')
    # read_terminal_t: SELECT before the direction-1 terminal_ack row, the state-9 response before terminal_strip.
    n = once(n, 'actions={terminal_open;terminal_synack;terminal_ack;commit_before_t;emit_tev;terminal_strip;'
                'terminal_abort;}size=10;',
             'actions={terminal_open;terminal_synack;terminal_ack;commit_before_t;emit_tev;terminal_strip;'
             'terminal_abort;}size=12;')
    n = once(n, '(8w11,32w0,32w0,_):emit_tev(16w0x0b00);',
             '(8w11,32w0,32w0,_):emit_tev(16w0x0b00);(8w5,32w0,32w0,_):commit_before_t(8w9);'
             '(8w6,32w0,32w0,_):emit_tev(16w0x0b00);')
    return n


def transform_n_m2(n):
    """m1, plus the OPERATE transaction: ACK in owner state 0xc is a lane ACK; its response (kind 16) is a RESPONSE."""
    n = transform_n_m1(n)
    n = once(n, '(8w10,3w1,_,32w0xc0000&&&32w0xffff0000,_,_,_,_,_,_):forward_original();',
             '(8w10,3w1,_,32w0xc0000&&&32w0xffff0000,_,_,_,_,_,_):first_read_ack();')
    n = once(n, 'terminal_abort;}size=12;', 'terminal_abort;}size=13;')
    n = once(n, '(8w6,32w0,32w0,_):emit_tev(16w0x0b00);',
             '(8w6,32w0,32w0,_):emit_tev(16w0x0b00);(8w16,32w0,32w0,_):emit_tev(16w0x0b00);')
    return n


def transform_t_m2(t):
    """An admitted OPERATE also opens a READ-lane generation and t0 (its J hold rows are unchanged). Kind 15
    (OPERATE duplicate) gets no lane rows. No READ-lane blocker clone for OPERATE (DESIGN.md, change 4)."""
    t = once(t, """            (t_T_IN, t_KIND_REQUEST, _, _, 0) : live_admit_gen();
            (_, _, _, _, 0) : live_gen();
        }
        default_action = bad_gen(); size = 9;""", """            (t_T_IN, t_KIND_REQUEST, _, _, 0) : live_admit_gen();
            (t_T_IN, t_KIND_OPERATE, 0, _, 0) : live_gen();
            (t_T_IN, t_KIND_OPERATE, _, _, 0) : live_admit_gen();
            (_, _, _, _, 0) : live_gen();
        }
        default_action = bad_gen(); size = 11;""")
    t = once(t, """            (t_T_IN, t_KIND_REQUEST, _, _) : admit_t0();
        }
        default_action = read_t0(); size = 3;""", """            (t_T_IN, t_KIND_REQUEST, _, _) : admit_t0();
            (t_T_IN, t_KIND_OPERATE, _, 32w0xffff) : read_t0();
            (t_T_IN, t_KIND_OPERATE, 0, _) : read_t0();
            (t_T_IN, t_KIND_OPERATE, _, _) : admit_t0();
        }
        default_action = read_t0(); size = 6;""")
    return t


def transform_t_m3(t):
    """m2, plus a per-response piggyback bound (DESIGN.md, change 5 as revised): ack_seen_reg records the lane
    generation of the last standalone ACK; a held response whose generation saw no ACK (piggybacked) may go at
    t0 + pb. Separate-ACK responses keep a_commit + gap and the readiness fallback. pb is set_params' last
    argument; its default equals the readiness default, so an unset pb changes nothing."""
    t = transform_t_m2(t)
    t = once(t, """    action set_params(bit<32> da, bit<32> readiness, bit<32> cap, bit<32> gap, bit<32> op_j,
                      bit<32> budget, bit<32> enabled) {
        md.da = da; md.readiness = readiness; md.gap = gap; md.op_j = op_j;
        md.budget_cap = budget; md.enabled = enabled;
    }""", """    action set_params(bit<32> da, bit<32> readiness, bit<32> cap, bit<32> gap, bit<32> op_j,
                      bit<32> budget, bit<32> enabled, bit<32> pb) {
        md.da = da; md.readiness = readiness; md.gap = gap; md.op_j = op_j;
        md.budget_cap = budget; md.enabled = enabled; md.pb_bound = pb;
    }""")
    t = once(t, "default_action = set_params(2000000, 12000000, 16000000, 800000, 2400000, 240000, 1); size = 1;",
             "default_action = set_params(2000000, 12000000, 16000000, 800000, 2400000, 240000, 1, 12000000); size = 1;")
    t = once(t, "    bit<32> now_m_readiness; bit<32> readiness_delta;",
             "    bit<32> now_m_readiness; bit<32> readiness_delta;\n"
             "    bit<32> pb_bound; bit<32> now_m_pb; bit<32> pb_delta; bit<32> ack_seen_diff;")
    t = once(t, "        md.now_m_da = md.now - md.da; md.now_m_readiness = md.now - md.readiness; md.now_m_gap = md.now - md.gap;\n    }",
             "        md.now_m_da = md.now - md.da; md.now_m_readiness = md.now - md.readiness; md.now_m_gap = md.now - md.gap;\n"
             "        md.now_m_pb = md.now - md.pb_bound;\n    }\n"
             "    action compute_pb_delta() { md.pb_delta = md.now_m_pb - md.t0_v; }")
    t = once(t, """    table child_seen0_access {""", """    // Piggyback detection: the last lane generation a standalone ACK was seen in. A response held in a
    // generation with no ACK (TCP piggybacked the ACK on it) reads a non-zero diff.
    Register<bit<32>, bit<1>>(1, 0xffffffff) ack_seen_reg;
    RegisterAction<bit<32>, bit<1>, bit<32>>(ack_seen_reg) ack_seen_mark = {
        void apply(inout bit<32> value, out bit<32> out_value) { out_value = 0; value = md.cur_gen; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(ack_seen_reg) ack_seen_read = {
        void apply(inout bit<32> value, out bit<32> out_value) { out_value = value ^ md.cur_gen; }
    };
    action mark_ack_seen() { md.ack_seen_diff = ack_seen_mark.execute(0); }
    action read_ack_seen() { md.ack_seen_diff = ack_seen_read.execute(0); }
    table ack_seen_access {
        key = { ig_intr_md.ingress_port : ternary; md.event_kind : ternary; hdr.ladder.role : ternary;
                md.e_bad : ternary; }
        actions = { mark_ack_seen; read_ack_seen; NoAction; }
        const entries = {
            (t_T_IN, t_KIND_ACK, _, 0) : mark_ack_seen();
            (t_HELD_RETURN, _, t_ROLE_RESP_HELD, _) : read_ack_seen();
        }
        default_action = NoAction(); size = 2;
    }
    table child_seen0_access {""")
    t = once(t, """        key = { md.e_bad : ternary; md.enabled : ternary; md.lgen_diff : ternary; md.readiness_delta : ternary;
                md.gap_delta : ternary; md.commit_diff : ternary; }
        actions = { set_resp_go; }
        const entries = {
            (0, 0, _, _, _, _) : set_resp_go(0);
            (0, _, 0, 32w0 &&& 32w0x80000000, _, _) : set_resp_go(1);
            (0, _, 0, _, 32w0 &&& 32w0x80000000, 0) : set_resp_go(1);
        }
        default_action = set_resp_go(0); size = 3;""", """        key = { md.e_bad : ternary; md.enabled : ternary; md.lgen_diff : ternary; md.readiness_delta : ternary;
                md.gap_delta : ternary; md.commit_diff : ternary; md.ack_seen_diff : ternary; md.pb_delta : ternary; }
        actions = { set_resp_go; }
        const entries = {
            (0, 0, _, _, _, _, _, _) : set_resp_go(0);
            (0, _, 0, 32w0 &&& 32w0x80000000, _, _, _, _) : set_resp_go(1);
            (0, _, 0, _, 32w0 &&& 32w0x80000000, 0, _, _) : set_resp_go(1);
            (0, _, 0, _, _, _, 0, _) : set_resp_go(0);                          // a standalone ACK was seen
            (0, _, 0, _, _, _, _, 32w0 &&& 32w0x80000000) : set_resp_go(1);     // piggybacked: t0 + pb passed
        }
        default_action = set_resp_go(0); size = 5;""")
    t = once(t, "        child_seen0_access.apply(); child_seen1_access.apply(); child_seen2_access.apply();\n",
             "        child_seen0_access.apply(); child_seen1_access.apply(); child_seen2_access.apply();\n"
             "        ack_seen_access.apply();\n")
    t = once(t, "            compute_da_delta(); compute_readiness_delta(); read_lgen_diff();",
             "            compute_da_delta(); compute_readiness_delta(); compute_pb_delta(); read_lgen_diff();")
    return t


def transform_n_m4(n):
    """m2, plus IEEE 1815-2012 section 4.4.4.3 Rule 4 / Table 4-9 while a selection is in effect (owner state 0xa,
    the SELECT response already delivered): a READ ("neither select nor operate") terminates the selection and is
    admitted as an ordinary READ; a new SELECT (a replacement, or an identical retry) is admitted as a SELECT and
    re-stores the selection. Both rows precede the kind-5/kind-9 count_refused catch-alls. The owner CAS rows
    (claim_read/claim_select) key on stage/kind/phase, not on the prior owner state, so they apply from 0xa.
    first_operate still requires owner 0xa and a matching object, so an OPERATE after cancellation cannot match.
    T (transform_t_m4) also drops and counts an OPERATE on an exhausted read lane.
    Owner state 9 (SELECT response outstanding) is unchanged: admitting a request there would let the late
    response arrive in another state and be refused, which a TCP byte stream cannot survive."""
    n = transform_n_m2(n)
    n = once(n, '(8w7,3w1,1w1,32w0xa0000&&&32w0xffff0000,_,_,_,_,_,_):first_operate();',
             '(8w7,3w1,1w1,32w0xa0000&&&32w0xffff0000,_,_,_,_,_,_):first_operate();'
             '(8w9,3w1,1w0,32w0xa0000&&&32w0xffff0000,_,_,_,_,_,_):first_read_request();'
             '(8w5,3w1,1w0,32w0xa0000&&&32w0xffff0000,_,_,_,_,_,_):first_select();')
    return n


def transform_t_m4(t):
    """m3, plus fail-closed lane exhaustion for OPERATE: an OPERATE admitted on an exhausted read lane
    (new_gen 0xffff) is dropped and counted (GEN_EXHAUSTED) like a REQUEST, instead of keeping its J hold while
    its ACK/response go untimed. The generation precheck keeps this unreachable in a budgeted run."""
    t = transform_t_m3(t)
    t = once(t, "            (t_KIND_OPERATE, _, 0, _, _, _, _, 32w0xffff) : drop_exhausted();\n",
             "            (t_KIND_OPERATE, _, 0, _, _, _, _, 32w0xffff) : drop_exhausted();\n"
             "            (t_KIND_OPERATE, _, 0, _, _, _, 32w0xffff, _) : drop_exhausted();\n")
    t = once(t, "        default_action = drop_old_epoch(); size = 22;", "        default_action = drop_old_epoch(); size = 23;")
    return t


RETRY_BUDGET = 32                      # retry laps per busy response (PLAN_m5.md amendment 3; DESIGN.md m5)
assert RETRY_BUDGET == 32, 'retry_valid_t encodes the budget 1..32 as ternary rows'
RETRY_EVENT = '16w0x0400'              # loop event: stage (bit<2>)0x04 = 0, kind 0, reserved 0


def transform_n_m5(n):
    """m4, plus a bounded, validated busy-retry for responses (PLAN_m5.md; DESIGN.md m5). N only.

    A response (kind 6 control, kind 11 READ) that finds N's single work cell busy -- the outstation's standalone
    ACK still in its four passes -- is no longer dropped: it becomes a retry frame on RETURN_PORT (egress bypassed,
    so E never sees it) carrying the current epoch, the generation already allocated for it, and a lap budget.
      - Generation accounting: the retry claims with the generation carried from its first busy pass (go_retry);
        a retry pass never calls allocate.
      - Strict validation: RETURN_PORT at stage 0 stays denied except for the exact retry form (event 0x0400,
        reserved 0, nonzero epoch and generation, parsed only on RETURN_PORT); a retry whose budget is out of
        range, whose connection direction is not outstation->master, or whose epoch is not the current
        incarnation's (retry_epoch) is a stale retry: it reads the work cell without claiming it and is dropped
        and counted (count_busy[4]).
      - Incarnation: retry_epoch holds the epoch of the open connection; it is written on the SYN lifecycle's
        stage-2 pass (only reached once stage 1 stored the epoch) and cleared on every stage-1 close pass (FIN or
        RST), so a retry from a reset or replaced connection is refused before it can claim the cell. It sits
        before the work cell, so the check precedes the claim.
      - Budget: a retry that is still busy with budget 1 is dropped and counted (count_busy[3], exhaustion).
        count_busy[2] counts retry laps. count_busy grows to 8 cells.
    Requests keep busy_drop, so request admission and the OPERATE hold are unchanged."""
    n = transform_n_m4(n)
    n = once(n, 'bit<32> observed;bit<32> owner_diff;}', 'bit<32> observed;bit<32> owner_diff;bit<2> retry;}')
    n = once(n, 'pkt.advance(PORT_METADATA_SIZE);m.wire_ack=32w0;', 'pkt.advance(PORT_METADATA_SIZE);m.retry=2w0;m.wire_ack=32w0;')
    n = once(n, '16w0x030c:origin;default:accept;}}',
             '16w0x030c:origin;%s:retry_input;default:accept;}}\n state retry_input{m.retry=2w1;transition eth;}' % RETRY_EVENT)
    n = once(n, 'const PortId_t n_READ_HANDOFF_PORT=9w180;',
             'const bit<32> n_RETRY_BUDGET=%d;\nconst PortId_t n_READ_HANDOFF_PORT=9w180;' % RETRY_BUDGET)
    n = once(n, 'table epoch_t{',
             'Register<bit<32>,bit<1>>(1,0) retry_epoch;\n'
             ' RegisterAction<bit<32>,bit<1>,bit<2>>(retry_epoch) check_retry_epoch={void apply(inout bit<32> v,out bit<2> r){if(v==hdr.envelope.epoch){r=2w1;}else{r=2w2;}}};\n'
             ' RegisterAction<bit<32>,bit<1>,bit<2>>(retry_epoch) note_retry_epoch={void apply(inout bit<32> v,out bit<2> r){v=hdr.envelope.epoch;r=2w0;}};\n'
             ' RegisterAction<bit<32>,bit<1>,bit<2>>(retry_epoch) clear_retry_epoch={void apply(inout bit<32> v,out bit<2> r){v=32w0;r=2w0;}};\n'
             ' action retry_epoch_check(){m.retry=check_retry_epoch.execute(1w0);}\n'
             ' action retry_epoch_note(){note_retry_epoch.execute(1w0);}\n'
             ' action retry_epoch_clear(){clear_retry_epoch.execute(1w0);}\n'
             ' table retry_epoch_t{key={m.stage:exact;m.kind:exact;m.retry:exact;}actions={retry_epoch_check;retry_epoch_note;retry_epoch_clear;NoAction;}size=4;const default_action=NoAction();\n'
             ' const entries={(2w0,8w0,2w1):retry_epoch_check();(2w2,8w1,2w0):retry_epoch_note();(2w1,8w4,2w0):retry_epoch_clear();(2w1,8w17,2w0):retry_epoch_clear();}}\n'
             ' table epoch_t{')
    n = once(n, 'Register<bit<32>,bit<4>>(4,0) count_busy;', 'Register<bit<32>,bit<4>>(8,0) count_busy;')
    retry_form = ('hdr.envelope.epoch=m.epoch;hdr.work_generation.generation=m.generation;hdr.event.event=%s;'
                  'hdr.event.reserved=16w0;tm.ucast_egress_port=n_RETURN_PORT;tm.bypass_egress=1w1;' % RETRY_EVENT)
    n = once(n, "table busy_t{key={m.kind:exact;}actions={busy_drop;busy_pass;}size=8;const entries={8w1:busy_drop();8w2:busy_drop();8w5:busy_drop();8w6:busy_drop();8w7:busy_drop();8w9:busy_drop();8w11:busy_drop();8w12:busy_drop();}const default_action=busy_pass();}",
             "action busy_retry(){" + retry_form + "hdr.expected_cell.expected_cell=n_RETRY_BUDGET;count_busy_bump.execute(4w2);}\n"
             # a waiting retry keeps the epoch and generation it carries (never re-stamped with the current epoch, so
             # isolation rests on the retry's own incarnation, not on owner gating; m5_09 review)
             "action busy_retry_next(){hdr.expected_cell.expected_cell=hdr.expected_cell.expected_cell-32w1;"
             "tm.ucast_egress_port=n_RETURN_PORT;tm.bypass_egress=1w1;count_busy_bump.execute(4w2);}\n"
             "action busy_exhausted(){md.drop_ctl=3w1;count_busy_bump.execute(4w3);}\n"
             "action retry_stale(){md.drop_ctl=3w1;count_busy_bump.execute(4w4);}\n"

             "table busy_t{key={m.kind:ternary;m.retry:ternary;hdr.expected_cell.expected_cell[5:0]:ternary;}"
             "actions={busy_drop;busy_pass;busy_retry;busy_retry_next;busy_exhausted;retry_stale;}size=16;"
             "const entries={(_,2w2,_):retry_stale();"
             "(8w6,2w0,_):busy_retry();(8w11,2w0,_):busy_retry();"
             # a retry's budget is 1..32 (retry_valid_t), so its low six bits decide budget 1
             "(8w6,2w1,6w1):busy_exhausted();(8w11,2w1,6w1):busy_exhausted();"
             "(8w6,2w1,_):busy_retry_next();(8w11,2w1,_):busy_retry_next();"
             "(8w1,_,_):busy_drop();(8w2,_,_):busy_drop();(8w5,_,_):busy_drop();(8w7,_,_):busy_drop();"
             "(8w9,_,_):busy_drop();(8w12,_,_):busy_drop();}const default_action=busy_pass();}")
    n = once(n, "action refuse_n_ack_return(){md.drop_ctl=3w1;}",
             "action go_retry(bit<8> k){m.go=(bit<1>)(8w1);m.kind=k;m.generation=hdr.work_generation.generation;m.work_op=8w1;}\n"
             "action go_stale(){m.go=(bit<1>)(8w1);m.kind=8w0;m.work_op=8w0;m.retry=2w2;}\n"
             "action refuse_n_ack_return(){md.drop_ctl=3w1;}")
    # guard: one more key (m.retry, wildcard on every existing row); the retry rows come first
    head = n.index('table guard{')
    body_start = n.index('const entries={', head) + len('const entries={')
    body_end = n.index('}}', body_start)
    rows = n[body_start:body_end]
    assert rows.count('):') == 42
    rows = rows.replace('):', ',_):')
    retry_rows = ('(2w0,8w6,8w0,2w2,1w1,1w1,8w1,1w0,16w0x993a,16w0x993a,_,16w0x993a,_,2w1):go_retry(8w6);'
                  '(2w0,8w11,8w0,2w2,1w1,1w1,8w1,1w0,16w0x993a,16w0x993a,16w0x993a,16w0x993a,_,2w1):go_retry(8w11);'
                  '(_,_,_,_,_,_,_,_,_,_,_,_,_,2w1):go_stale();(_,_,_,_,_,_,_,_,_,_,_,_,_,2w2):go_stale();')
    n = n[:body_start] + retry_rows + rows + n[body_end:]
    n = once(n, 'm.tcrc:ternary;m.output_port:ternary;}', 'm.tcrc:ternary;m.output_port:ternary;m.retry:ternary;}')
    n = once(n, "actions={go_new;go_keep;go_ret_work;go_ret_nowork;go_ret_abort;refuse_n_ack_return;NoAction;}size=48;",
             "actions={go_new;go_keep;go_ret_work;go_ret_nowork;go_ret_abort;go_retry;go_stale;refuse_n_ack_return;NoAction;}size=48;")
    # apply: incarnation check before anything that touches state; strict validation; the busy branch
    n = once(n, 'connection.apply();crc_t.apply();', 'connection.apply();retry_epoch_t.apply();crc_t.apply();')
    # a retry frame is stale unless it is current, on its connection, in budget and passes N's network check;
    # every retry frame (stale or not) takes the guarded branch, so none can recirculate unaccounted
    # (one table, not a gateway: the combined condition exceeds a gateway's PHV input, bf-p4c m5_01 compile)
    n = once(n, 'table epoch_t{',
             'action retry_mark_stale(){m.retry=2w2;}\n'
             ' table retry_valid_t{key={m.retry:exact;m.direction:ternary;hdr.expected_cell.expected_cell:ternary;}'
             'actions={retry_mark_stale;NoAction;}size=5;const default_action=retry_mark_stale();\n'
             # budget 1..32 as ternary rows (bf-p4c: no range match on a 32-bit key): 0 stale, 0..31 masked, 32 exact
             ' const entries={(2w0,_,_):NoAction();(2w2,_,_):NoAction();(2w1,_,32w0):retry_mark_stale();'
             '(2w1,2w2,32w0&&&32w0xffffffe0):NoAction();(2w1,2w2,32w32):NoAction();}}\n'
             ' table epoch_t{')
    n = once(n, 'ports.apply();network.apply();', 'ports.apply();network.apply();retry_valid_t.apply();')
    # a retry that fails N's port or network check never reaches the guard: denied on its single pass (uncounted;
    # a genuine retry is byte-identical to a packet that passed them). Widening the main branch condition instead
    # made PHV allocation fail (bf-p4c, m5_07 and bisect).
    n = once(n, '  }else if((bit<8>)m.stage!=8w0){deny();}\n }\n}',
             '  }else if((bit<8>)m.stage!=8w0||m.retry!=2w0){deny();}\n }\n}')
    n = once(n, 'else if((ig.ingress_port==n_RETURN_PORT&&(bit<8>)m.stage==8w0)||',
             'else if((ig.ingress_port==n_RETURN_PORT&&(bit<8>)m.stage==8w0&&m.retry==2w0)||')
    # a claimed retry that first_event classes as a retransmission (forward_original) would leave untimed ahead of
    # the timed original: it aborts instead (kind 255 returns the cell, terminal_abort drops it) and is counted
    # counted in count_term[0], a register m4 declares and never uses (counting through busy_t needed a merged
    # branch flag that made PHV allocation fail, bf-p4c bisect)
    term = 'RegisterAction<bit<32>,bit<4>,bit<32>>(count_term) count_term_bump={void apply(inout bit<32> v,out bit<32> r){if((int<32>)v!=-1){v=v+32w1;}r=v;}};'
    n = once(n, term, term + '\naction count_retry_duplicate(){count_term_bump.execute(4w0);}\n'
             'table retry_dup_t{actions={count_retry_duplicate;}size=1;const default_action=count_retry_duplicate();}')
    n = once(n, 'snapshot_t.apply();first_event.apply();\n     }else if(m.work_op==8w1){busy_t.apply();}else if(m.kind==8w4){deny();}',
             'snapshot_t.apply();first_event.apply();\n'
             '      if(m.retry==2w1&&hdr.event.event==16w0x0108){hdr.event.event[7:0]=8w255;hdr.t0.setInvalid();'
             'retry_dup_t.apply();}\n'
             '     }else if(m.work_op==8w1||m.retry==2w2){busy_t.apply();}else if(m.kind==8w4){deny();}')
    return n


def transform_n_m6(n):
    """m5 plus three N lifecycle corrections (PLAN_m5.md "m6 continuation"; DESIGN.md m6). N only; E and T
    byte-identical to m5.

    R  Reset while a response is held. A master RST|ACK is checked like any ACK-bearing segment, so N required its
       ACK to equal the server register, which already counts the response T is still holding; a master that has
       not received that response acks the pre-response sequence and was refused. RFC 9293 3.10.7.4 validates a
       reset by its SEQ. New first_event rows accept, with SEQ exact (client_diff 0), an ACK one response behind
       the server register in N's native coordinates (-49 or -37 in owner state 5; -37 in state 0xa). The reset is
       therefore validated by its exact SEQ, as a bare RST (flags 4) already was on m4/m5; the ACK restriction is
       in native coordinates only, so in master-visible coordinates several ACKs pass (an ACK inside the padded
       61-octet image normalizes to the native response start; tests/test_m6_lifecycle.py pins the exact sets).
       Every SEQ mismatch is refused (review of m6_01, H2).
    E  Retry incarnation cleared only at a proven close. m5 cleared retry_epoch on every stage-1 close pass, before
       the owner CAS, so a refused close disabled live retries. A successful close now takes one more pass
       (reset_boundary keyed on stage: stage-1 CAS success -> reset_continue -> stage 2 -> emit_reset), and
       retry_epoch is cleared on that stage-2 pass, as it is for the kind-17 close, whose stage-2 pass already
       follows its CAS.
    D  Response retransmission through T's release gate. A seq_retx copy of the response in an owner state with no
       newer transaction open (READ: 5; control: 0xa, 5) becomes event 0x0119 (kind 25): the kind-8 lifecycle, but
       handed to T as a RESPONSE, so T drops it while the original is held (RESP_DUP_DROP) and passes it after
       release (loss recovery beyond the switch). States 0xe/0xc keep forward_original: a newer transaction is
       open there and T would take an old copy as the new response."""
    n = transform_n_m5(n)
    # R: three acceptance rows (first_event size 163 holds them: 159 -> 162)
    anchor = '(8w4,3w1,1w0,32w0x50000&&&32w0xffff0000,_,_,_,_,_,_):first_close();'
    n = once(n, anchor, anchor +
             '(8w4,3w2,1w0,32w0x50000&&&32w0xffff0000,32w0,32w0xffffffcf,2w1,8w20,_,_):first_close();'
             '(8w4,3w2,1w0,32w0x50000&&&32w0xffff0000,32w0,32w0xffffffdb,2w1,8w20,_,_):first_close();'
             '(8w4,3w2,1w0,32w0xa0000&&&32w0xffff0000,32w0,32w0xffffffdb,2w1,8w20,_,_):first_close();')
    # E: the stage-2 close pass, and retry_epoch cleared there
    n = once(n, '16w0x0104:origin;', '16w0x0104:origin;16w0x0204:origin;')
    n = once(n, 'table reset_boundary{key={m.owner_op:exact;m.owner_diff:exact;m.epoch_diff:exact;}'
                'actions={emit_reset;terminal_abort;}size=1;const entries={(1w1,32w0,32w0):emit_reset();}'
                'const default_action=terminal_abort();}',
             'action reset_continue(){hdr.expected_cell.expected_cell=m.desired;hdr.event.event=hdr.event.event+16w0x100;'
             'm.emit_loop=(bit<1>)(8w1);tm.ucast_egress_port=n_RETURN_PORT;tm.bypass_egress=1w1;}\n'
             'table reset_boundary{key={m.stage:exact;m.owner_op:exact;m.owner_diff:exact;m.epoch_diff:exact;}'
             'actions={reset_continue;emit_reset;terminal_abort;}size=2;const entries={'
             '(2w1,1w1,32w0,32w0):reset_continue();(2w2,1w0,32w0,32w0):emit_reset();}'
             'const default_action=terminal_abort();}')
    n = once(n, '(2w1,8w4,2w0):retry_epoch_clear();(2w1,8w17,2w0):retry_epoch_clear();',
             '(2w2,8w4,2w0):retry_epoch_clear();(2w2,8w17,2w0):retry_epoch_clear();')
    # ...and only the incarnation that closed: the clear is conditional on the stored epoch being the close pass's
    # own envelope epoch, so a delayed close pass of an older incarnation cannot clear a newer one's retry
    # authority (m6 test-matrix finding: replaying an old 0x0204 after a fresh handshake cleared it, and the next
    # contended READ was refused as stale; m5's stage-1 clear had the same gap)
    n = once(n, 'clear_retry_epoch={void apply(inout bit<32> v,out bit<2> r){v=32w0;r=2w0;}}',
             'clear_retry_epoch={void apply(inout bit<32> v,out bit<2> r){if(v==hdr.envelope.epoch){v=32w0;}r=2w0;}}')
    # D: the response-retransmission event 0x0119 (kind 25)
    n = once(n, 'action forward_original(){hdr.event.event=16w0x0108;}',
             'action forward_original(){hdr.event.event=16w0x0108;}\n action first_response_dup(){hdr.event.event=16w0x0119;}')
    n = once(n, 'forward_original;first_operate_dup;close_forward;NoAction;}size=163;',
             'forward_original;first_operate_dup;first_response_dup;close_forward;NoAction;}size=163;')
    for row in ('(8w11,3w2,_,32w0x50000&&&32w0xffff0000,_,32w0xffffffcf,_,_,_,_):',
                '(8w6,3w2,_,32w0xa0000&&&32w0xffff0000,_,32w0xffffffdb,_,_,_,_):',
                '(8w6,3w2,_,32w0x50000&&&32w0xffff0000,_,32w0xffffffdb,_,_,_,_):'):
        n = once(n, row + 'forward_original();', row + 'first_response_dup();')
    n = once(n, '16w0x0108:origin;', '16w0x0108:origin;16w0x0119:origin;16w0x0219:origin;16w0x0319:origin;')
    for packet_kind in ('8w6', '8w11'):
        tail = ('16w0x993a,16w0x993a,_,16w0x993a' if packet_kind == '8w6' else
                '16w0x993a,16w0x993a,16w0x993a,16w0x993a')
        row = '(_,%s,8w8,_,_,1w1,8w1,1w0,%s,_,_):go_ret_work();' % (packet_kind, tail)
        n = once(n, row, row + row.replace(',8w8,', ',8w25,'))
    row = '(1w1,8w8,8w24,false,16w0xffeb,8w1..8w255,4w0,16w0):network_accept();'      # network size 32 holds 30+2
    n = once(n, row, row + row.replace(',8w8,', ',8w25,') + row.replace(',8w8,8w24,', ',8w25,8w16,'))
    n = once(n, 'else if(m.kind==8w8||m.kind==8w24||', 'else if(m.kind==8w8||m.kind==8w25||m.kind==8w24||')
    n = once(n, '(8w16,32w0,32w0,_):emit_tev(16w0x0b00);',
             '(8w16,32w0,32w0,_):emit_tev(16w0x0b00);(8w25,32w0,32w0,_):emit_tev(16w0x0b00);')
    n = once(n, 'terminal_strip;terminal_abort;}size=13;', 'terminal_strip;terminal_abort;}size=14;')
    # R (busy cell): an RST whose stage-0 pass finds the work cell busy was denied. It now retries like a response,
    # as event 0x0800 (stage 0, kind 0) carrying the origin header so the master's normalize-lap values (wire ack,
    # normalized epoch) survive; m5's validation applies (current epoch, budget), any direction (RSTs come from both
    # ends). go_keep re-enters the native RST path; no generation is allocated (generation 1 = marker only). The
    # retried pass must take the snapshot path its first pass took. Every master segment (direction 1) reaches N
    # after its normalize lap and every outstation segment (direction 2) natively, so snapshot_t keys retry frames
    # on m.direction (recomputed on each pass): the master's RST retry takes snapshot_lap, exactly as its first
    # pass did, including a lap whose normalized epoch is 0 (E's unbound slot), which dies on both passes alike;
    # the outstation's takes snapshot. Review of m6_01 (H1): forcing m.lap 1 gave a native RST envelope epoch 0, so
    # it was lost. Carrying the lap in the generation field failed to compile (m6_02 parser match registers, m6_03
    # PARDE alignment, m6_04 PHV); keying on normalized_epoch (m6_05, m6_06) let a busy master RST with normalized
    # epoch 0 succeed where the same RST with the cell free is denied (review of m6_06). The busy retry covers every
    # kind-4 segment that close_shape admits: RST (flags 4, 20) and FIN|ACK (17); a busy FIN|ACK, denied on m5, now
    # retries into the same first_event close rows (tests/test_m6_lifecycle.py).
    n = once(n, 'table snapshot_t{key={m.lap:ternary;m.epoch:ternary;}actions={snapshot;snapshot_lap;snapshot_epoch_zero;}'
                'size=2;const entries={(1w1,_):snapshot_lap();(_,32w0):snapshot_epoch_zero();}',
             'table snapshot_t{key={m.lap:ternary;m.epoch:ternary;m.retry:ternary;m.direction:ternary;}'
             'actions={snapshot;snapshot_lap;snapshot_epoch_zero;}size=4;const entries={(1w1,_,_,_):snapshot_lap();'
             '(_,32w0,_,_):snapshot_epoch_zero();(_,_,2w1,2w1):snapshot_lap();(_,_,2w1,_):snapshot();}')
    n = once(n, '%s:retry_input;' % RETRY_EVENT, '%s:retry_input;16w0x0800:retry_rst_input;' % RETRY_EVENT)
    n = once(n, ' state retry_input{m.retry=2w1;transition eth;}',
             ' state retry_input{m.retry=2w1;transition eth;}\n'
             ' state retry_rst_input{m.retry=2w1;transition origin;}')
    n = once(n, "action busy_exhausted(){",
             "action busy_retry_rst(){hdr.envelope.epoch=m.epoch;hdr.work_generation.generation=32w1;"
             "hdr.event.event=16w0x0800;hdr.event.reserved=16w0;hdr.origin.setValid();hdr.origin.wire_ack=m.wire_ack;"
             "hdr.origin.normalized_epoch=m.normalized_epoch;hdr.expected_cell.expected_cell=n_RETRY_BUDGET;"
             "tm.ucast_egress_port=n_RETURN_PORT;tm.bypass_egress=1w1;count_busy_bump.execute(4w2);}\n"
             "action busy_retry_rst_next(){hdr.expected_cell.expected_cell=hdr.expected_cell.expected_cell-32w1;"
             "tm.ucast_egress_port=n_RETURN_PORT;tm.bypass_egress=1w1;count_busy_bump.execute(4w2);}\n"
             "action busy_exhausted(){")
    n = once(n, "actions={busy_drop;busy_pass;busy_retry;busy_retry_next;busy_exhausted;retry_stale;}size=16;",
             "actions={busy_drop;busy_pass;busy_retry;busy_retry_next;busy_retry_rst;busy_retry_rst_next;busy_exhausted;"
             "retry_stale;}size=16;")
    n = once(n, "(8w11,2w1,_):busy_retry_next();",
             "(8w11,2w1,_):busy_retry_next();(8w4,2w0,_):busy_retry_rst();(8w4,2w1,6w1):busy_exhausted();"
             "(8w4,2w1,_):busy_retry_rst_next();")
    n = once(n, '(2w1,2w2,32w0&&&32w0xffffffe0):NoAction();(2w1,2w2,32w32):NoAction();}}',
             '(2w1,2w2,32w0&&&32w0xffffffe0):NoAction();(2w1,2w2,32w32):NoAction();'
             '(2w1,2w1,32w0&&&32w0xffffffe0):NoAction();(2w1,2w1,32w32):NoAction();}}')
    n = once(n, 'hdr.expected_cell.expected_cell:ternary;}actions={retry_mark_stale;NoAction;}size=5;',
             'hdr.expected_cell.expected_cell:ternary;}actions={retry_mark_stale;NoAction;}size=7;')
    # guard: an RST retry (either direction) re-enters go_keep ahead of the catch-all stale rows; guard size 48 -> 50
    n = once(n, '(_,_,_,_,_,_,_,_,_,_,_,_,_,2w1):go_stale();',
             '(2w0,8w4,8w0,2w1,1w1,_,_,_,_,_,_,_,_,2w1):go_keep(8w4);(2w0,8w4,8w0,2w2,1w1,_,_,_,_,_,_,_,_,2w1):go_keep(8w4);'
             '(_,_,_,_,_,_,_,_,_,_,_,_,_,2w1):go_stale();')
    n = once(n, 'refuse_n_ack_return;NoAction;}size=48;', 'refuse_n_ack_return;NoAction;}size=50;')
    # one busy_t apply site: a shape-valid RST that finds the cell busy retries instead of being denied
    n = once(n, '}else if(m.work_op==8w1||m.retry==2w2){busy_t.apply();}else if(m.kind==8w4){deny();}',
             '}else if(m.work_op==8w1||m.retry==2w2||(m.kind==8w4&&(bit<8>)m.shape_valid==8w1)){busy_t.apply();}'
             'else if(m.kind==8w4){deny();}')
    return n


E_M8_ACTION = ('    action out_drop(bit<8> why) { m.result = why; md.drop_ctl = 3w1; }',
               '    action out_drop(bit<8> why) { m.result = why; md.drop_ctl = 3w1; }\n'
               '    action out_reset_front() { m.qx = m.qf; m.result = r_OUT_RESET_FRONT; m.changed = 1; }')


def transform_e_m8(e):
    """The one E exception of m8 = m7 + this (directive ba50eac69, section 2: abort completion; kept separate from
    m7's T clock so each resource failure has one cause; m7_01/m7_02 combined attempts failed PHV, retained). An outstation RST that N has
    validated and closed while T held its response arrives exactly one held response ahead of E's frontier (front_ret
    49 for READ, 37 for control): the master never received those bytes, so classify_fwd dropped it as
    OUT_DROP_AHEAD and the master's connection stayed open. Measured on Linux 5.15 (scratch rst_linux.py, 2026-10-16):
    an RST at the receiver's RCV.NXT resets; one ahead inside the window only draws a challenge ACK. m7 therefore
    places such an RST at the frontier: qx = q - front_ret is the frontier's offset from the image end, so img_wend_t
    writes the master-visible RCV.NXT. Only RST-bearing segments exactly 49 or 37 octets ahead; every other ahead
    segment still drops. New outcome code 16 (the outcome counter has 32 cells). Nothing else in E changes."""
    e = once(e, 'const bit<8> r_OUT_DROP_MERGED = 15;',
             'const bit<8> r_OUT_DROP_MERGED = 15; const bit<8> r_OUT_RESET_FRONT = 16;')
    e = once(e, *E_M8_ACTION)
    # qf = q - front_ret is computed by its own action after img_end_t (m7_01 did it inside the verdict action and
    # failed bf-p4c's action constraints); out_reset_front then only moves it, as the other verdicts move q or pm
    e = once(e, '    bit<32> front_ret; bit<1> grant;', '    bit<32> front_ret; bit<1> grant; bit<32> qf;')
    e = once(e, '        img_end_t.apply();\n',
             '        img_end_t.apply();\n        front_q_t.apply();\n')
    e = once(e, '    table classify_fwd {',
             '    action front_q() { m.qf = m.q - m.front_ret; }\n'
             '    table front_q_t { actions = { front_q; } size = 1; const default_action = front_q(); }\n'
             '    table classify_fwd {')
    e = once(e, 'actions = { out_commit; out_translate; out_zero; out_replay; out_stale; out_drop; } size = 24;',
             'actions = { out_commit; out_translate; out_zero; out_replay; out_stale; out_drop; out_reset_front; } size = 24;')
    ahead = '(32w0 &&& 32w0x80000000, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _): out_drop(r_OUT_DROP_AHEAD);'
    rows = ''.join('(32w%d, _, _, _, _, _, _, _, _, _, _, _, _, _, _, 8w0x04 &&& 8w0x04): out_reset_front();' % n
                   for n in (49, 37))
    return once(e, ahead, rows + ahead)


T_TIME_M7 = dict(unit_ns=256, grid_ns=512, source='global_tstamp[39:8] & ~1')


def transform_t_m7(t):
    """m7's only change (directive ba50eac69, C1; Philip 2026-10-16). T's clock was the low 32 bits of global_tstamp
    in ns on a 256 ns grid, and every deadline is the sign bit of a 32-bit difference, so an anchor older than
    readiness + 2^31 ns read as "not ready" and one older than 2^32 ns aliased to a fresh exchange
    (evidence/model_contention_m6_07_01/TRACE_sweep_SELECT_000ms.md; the arithmetic is shared by every earlier T
    build, these tests reproduce it on m6, they do not show m6 introduced it). m7's T counts in 256 ns units from the
    byte-aligned slice global_tstamp[39:8] (the [40:9] slice, a shift and a two-word concatenation all failed PHV
    allocation), with bit 0 kept free for the OPERATE anchor flag: a 512 ns sampling grid, a signed horizon of
    2^31 x 256 ns = 9.16 minutes and a full wrap of 18.33 minutes. It widens the supported range; it does not remove
    wrap ambiguity: an anchor must be resolved within 9.16 minutes minus the longest duration (see the rollover
    test). set_params is unchanged: durations arrive in T units, converted from ns by the one shared writer function
    core/response_only/hw/t_config.t_units, which rounds up over both the anchor grid and the unit
    (ceil((D + 512 ns) / 256 ns)) so no deadline resolves before its ns duration (phase-sweep test)."""
    return once(t, 'action clock_sample() { md.now = ((bit<32>)ig_prsr_md.global_tstamp) & 32w0xffffff00; }',
                'action clock_sample() { md.now = ig_prsr_md.global_tstamp[39:8] & 32w0xfffffffe; }')


def full_source(milestone='m1'):
    base = frozen()
    old_n, old_t = combined.segment(base, 'N'), combined.segment(base, 'T')
    new_n = {'m1': transform_n_m1, 'm2': transform_n_m2, 'm3': transform_n_m2, 'm4': transform_n_m4,
             'm5': transform_n_m5, 'm6': transform_n_m6, 'm7': transform_n_m6, 'm8': transform_n_m6}[milestone](old_n)
    new_t = {'m1': lambda t: t, 'm2': transform_t_m2, 'm3': transform_t_m3, 'm4': transform_t_m4,
             'm5': transform_t_m4, 'm6': transform_t_m4, 'm7': transform_t_m4, 'm8': transform_t_m4}[milestone](old_t)
    text = base.replace(old_n, new_n, 1).replace(old_t, new_t, 1)
    assert combined.segment(text, 'E') == combined.segment(base, 'E')
    if milestone in ('m5', 'm6', 'm7', 'm8'):  # N only here; m7/m8 add their named T/E changes below
        m4 = full_source('m4')
        assert combined.segment(text, 'T') == combined.segment(m4, 'T')
        assert combined.segment(text, 'E') == combined.segment(m4, 'E')
    assert text.replace(new_n, old_n, 1).replace(new_t, old_t, 1) == base
    if milestone in ('m7', 'm8'):             # m6's N; m7: T clock (transform_t_m7); m8: m7 + E reset (transform_e_m8)
        old_t7 = combined.segment(text, 'T')
        text = text.replace(old_t7, transform_t_m7(old_t7), 1)
        if milestone == 'm8':
            old_e = combined.segment(text, 'E')
            text = text.replace(old_e, transform_e_m8(old_e), 1)
        assert combined.segment(text, 'N') == combined.segment(full_source('m6'), 'N')
    return text


def write(directory, milestone='m1'):
    directory = Path(directory)
    text = full_source(milestone)
    directory.mkdir(parents=True, exist_ok=False)
    (directory / 'response_only.p4').write_text(text)
    (directory / 'generate.py').write_bytes(Path(__file__).read_bytes())
    metadata = json.loads(SOURCE.with_suffix('.inputs.json').read_text())
    metadata.update(experiment='ctl_timing_01', milestone=milestone,
                    source_sha256=digest(text.encode()),
                    candidate61_source={'path': str(SOURCE), 'sha256': SOURCE_SHA256},
                    generator_sha256=digest(Path(__file__).read_bytes()),
                    changed_roles=['N'] if milestone == 'm1' else ['N', 'T', 'E'] if milestone == 'm8' else ['N', 'T'],
                    t_time=T_TIME_M7 if milestone in ('m7', 'm8') else dict(unit_ns=1, grid_ns=256, source='global_tstamp[31:0] & ~0xff'),
                    segment_sha256={name: digest(combined.segment(text, name).encode()) for name in ('N', 'E', 'T')})
    (directory / 'response_only.inputs.json').write_text(json.dumps(metadata, indent=2) + '\n')
    print(json.dumps({'source_sha256': metadata['source_sha256'], 'segments': metadata['segment_sha256']}, indent=1))


if __name__ == '__main__':
    if len(sys.argv) not in (2, 3):
        raise SystemExit('usage: generate.py OUT_DIR [m1|m2|m3|m4|m5|m6|m7|m8]')
    write(sys.argv[1], *(sys.argv[2:]))

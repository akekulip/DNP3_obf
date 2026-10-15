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
             "action busy_retry_next(){" + retry_form + "hdr.expected_cell.expected_cell=hdr.expected_cell.expected_cell-32w1;count_busy_bump.execute(4w2);}\n"
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


def full_source(milestone='m1'):
    base = frozen()
    old_n, old_t = combined.segment(base, 'N'), combined.segment(base, 'T')
    new_n = {'m1': transform_n_m1, 'm2': transform_n_m2, 'm3': transform_n_m2, 'm4': transform_n_m4,
             'm5': transform_n_m5}[milestone](old_n)
    new_t = {'m1': lambda t: t, 'm2': transform_t_m2, 'm3': transform_t_m3, 'm4': transform_t_m4,
             'm5': transform_t_m4}[milestone](old_t)
    text = base.replace(old_n, new_n, 1).replace(old_t, new_t, 1)
    assert combined.segment(text, 'E') == combined.segment(base, 'E')
    if milestone == 'm5':                     # N only: E and T byte-identical to m4
        m4 = full_source('m4')
        assert combined.segment(text, 'T') == combined.segment(m4, 'T')
        assert combined.segment(text, 'E') == combined.segment(m4, 'E')
    assert text.replace(new_n, old_n, 1).replace(new_t, old_t, 1) == base
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
                    changed_roles=['N'] if milestone == 'm1' else ['N', 'T'],
                    segment_sha256={name: digest(combined.segment(text, name).encode()) for name in ('N', 'E', 'T')})
    (directory / 'response_only.inputs.json').write_text(json.dumps(metadata, indent=2) + '\n')
    print(json.dumps({'source_sha256': metadata['source_sha256'], 'segments': metadata['segment_sha256']}, indent=1))


if __name__ == '__main__':
    if len(sys.argv) not in (2, 3):
        raise SystemExit('usage: generate.py OUT_DIR [m1|m2|m3|m4|m5]')
    write(sys.argv[1], *(sys.argv[2:]))

"""c69: remove the fixed OPERATE-J hold from the telemetry-free response-ready build.

Only T changes. OPERATE opens the existing common response generation and forwards
through admit_request, including the E100/app0 blocker trigger. Its genuine TCP
retries use the same retained-response policy as REQUEST_DUP. All edits require
unique literal anchors, matching the other generator transforms.
"""
from .common import combined, once


def _span(text, start, end, replacement=''):
    """Replace a span bounded by two unique, ordered literal anchors."""
    # Check both anchors with the same fail-closed helper used by literal edits.
    once(text, start, start)
    once(text, end, end)
    a = text.index(start)
    b = text.index(end, a + len(start))
    return once(text, text[a:b], replacement)


def transform(src):
    old = combined.segment(src, 'T')
    t = old
    t = once(t, '// timing_contract: response_ready_ack_d_v2',
             '// timing_contract: response_ready_ack_d_no_j_v3')
    t = _span(t, "// T's READ timing role, queue-resident design", '#ifndef CASE4_READ_PORTS_P4',
              '// Queue-resident ACK/response timing: originals use qid6/qid4 and blockers qid7/qid5.\n'
              '// READ, SELECT and OPERATE share response-ready ACK commit and the configured D release gap.\n')
    t = once(t, 'const PortId_t t_HB_RETURN     = 9w181; /* compose.py port override (was 198) */ // ingress pipe 1 local 70: heartbeat / OPERATE-ladder service return\n', '')
    t = once(t, 'admit_request / hold_operate set t_CLONE_SESSION_ID', 'admit_request sets t_CLONE_SESSION_ID')
    t = _span(t, '// Ladder roles (queue_sim.py ROLE dict)', '// tev.kind wire values.',
              '// Active ladder roles: ACK blocker, response blocker, held ACK and held response.\n'
              'const bit<8> t_ROLE_ACK_BLK  = 11; const bit<8> t_ROLE_RESP_BLK = 12;\n'
              'const bit<8> t_ROLE_ACK_HELD = 14; const bit<8> t_ROLE_RESP_HELD = 15;\n\n')
    t = once(t, '// An identical OPERATE copy (dup_hold_01): held-time drop, post-release forward. Never cloned or held.',
             '// An identical OPERATE TCP retry: suppress while a response is retained; never clone or rearm.')
    t = once(t, 'pipe t_PKTGEN_PIPE, app 0 or 1', 'pipe t_PKTGEN_PIPE, app 0')
    t = _span(t, '    // da/readiness/gap/op_j are config action-data', '    bit<32> now;',
              '    // Per-pass action data: response release gap, blocker lap budget and timing enable.\n'
              '    bit<32> gap; bit<32> budget_cap; bit<32> enabled;\n')
    t = _span(t, "    // done_diff: the role's done register", "    // lgen_diff: the ladder record's", '')
    t = once(t, '    bit<16> lgen_diff; bit<16> op_lgen_diff;', '    bit<16> lgen_diff;')
    t = once(t, '    bit<8> ack_go; bit<8> resp_go; bit<8> op_go;', '    bit<8> ack_go; bit<8> resp_go;')
    t = once(t, '    bit<32> op_t0_masked; bit<32> now_m_opj; bit<32> op_delta;\n'
                '    bit<32> op_gen; bit<32> op_t0_v;\n', '')
    t = once(t, '    bit<16> op_tok_diff; bit<16> rd_tok_diff;', '    bit<16> rd_tok_diff;')
    t = once(t, '            t_HB_RETURN : parse_ladder;\n', '')
    t = once(t, '            13 : accept;\n', '')
    t = once(t, '            16 : opaque_ethernet;\n', '')
    t = _span(t, "    // The clone always carries this pass's pristine original bytes", '    state clone_or_token',
              '    // Common E100 admission clones trigger the app0 blockers; their pristine originals\n'
              '    // have already forwarded and the clone itself is dropped. Legacy command trigger tags reject.\n')
    # Validate the tag before extracting tev: all three selectors together need
    # 40 parser match bits, exceeding Tofino-1's 16+8+8 match registers.
    t = once(t, '''    state parse_clone {
        pkt.extract(hdr.clone); pkt.extract(hdr.tev); md.event_kind = hdr.tev.kind; md.packet_epoch = hdr.tev.epoch;
        md.epoch_delta = 1w1 ++ hdr.tev.epoch[30:0];
        transition select(hdr.tev.kind, hdr.tev.reserved) {
            (9, 0) : opaque_ethernet;
            (12, 0) : opaque_ethernet;
            default : accept;   // an unexpected kind is dropped by drop_clone in the apply block (no reliance t_on reject)
        }
    }
''', '''    state parse_clone {
        pkt.extract(hdr.clone);
        transition select(hdr.clone.tag[31:16]) {
            16w0xE100 : parse_clone_tev;
            default : reject;
        }
    }
    state parse_clone_tev {
        pkt.extract(hdr.tev); md.event_kind = hdr.tev.kind; md.packet_epoch = hdr.tev.epoch;
        md.epoch_delta = 1w1 ++ hdr.tev.epoch[30:0];
        transition select(hdr.tev.kind, hdr.tev.reserved) {
            (9, 0) : opaque_ethernet;
            (12, 0) : opaque_ethernet;
            default : reject;
        }
    }
''')
    t = once(t, "        // Only the expected generator format is a token: T's pipe and its two apps (0 READ, 1 OPERATE).",
             "        // Only the common response-timing app0 format is a token on T's pipe.")
    t = once(t, '            (t_PKTGEN_PIPE, 1) : token_format_ok;\n', '')
    t = once(t, '''    action set_params(bit<32> gap, bit<32> op_j, bit<32> budget, bit<32> enabled) {
        md.gap=gap; md.op_j=op_j; md.budget_cap=budget; md.enabled=enabled;
    }
    table params { actions={set_params;} default_action=set_params(19534,9377,60000,1); size=1; }
''', '''    action set_params(bit<32> gap, bit<32> budget, bit<32> enabled) {
        md.gap=gap; md.budget_cap=budget; md.enabled=enabled;
    }
    table params { actions={set_params;} default_action=set_params(19534,60000,1); size=1; }
''')
    t = once(t, '            (t_PKTGEN_RETURN, t_KIND_OPERATE, _, _) : match_epoch();\n', '')
    t = once(t, '            (t_HB_RETURN, _, t_ROLE_OP_HELD, _) : match_epoch();\n', '')
    t = once(t, '        default_action = read_epoch(); size = 10;', '        default_action = read_epoch(); size = 8;')
    t = _span(t, '    // ---- OPERATE domain', '    // ---- request admission', '')
    t = _span(t, '    // The RESET pass never reads md.op_gen', '    // ---- hold admission', '')
    t = _span(t, "    // The admitting t_T_IN pass becomes OP_LADDER's", '    action drop_clone()', '')
    t = _span(t, '    action seed_op_blocker()', '    // Token staleness', '')
    t = once(t, '        md.op_tok_diff = hdr.timer.batch_id ^ (bit<16>)md.op_gen;\n', '')
    t = once(t, '    action drop_timer_stale_operate() { hdr.timer.setInvalid(); ig_dprsr_md.drop_ctl = 1; }\n', '')
    t = _span(t, '    action op_lgen_diff()', '    // ---- ladder dispatch: held originals', '')
    t = _span(t, '    // Release only; op_done_reg', '    action release_ack_commit()', '')
    t = once(t, '    action release_operate_counted() { release_operate(); }\n', '')
    t = _span(t, '    action drop_operate_dup()', '    action drop_exhausted()', '')
    t = _span(t, 'table operate_completion_access', '    // ---- verdict tables', '')
    # Drop the J completion key/domain and reuse the common retained-response
    # retry policy: completed response -> pass; retained child -> drop; else pass.
    t = _span(t, '    table tin_verdict', '    table token_verdict', '''    table tin_verdict { key = { md.event_kind : ternary; md.enabled : ternary; md.e_bad : ternary; md.ack_diff : ternary; md.resp_diff : ternary; md.dup_diff : ternary; md.seen0_diff : ternary; hdr.tev.stage : ternary; md.cur_gen : ternary; }
        actions = { passthrough_tev_relay; passthrough_tev_forward; drop_tin; admit_request; hold_ack; drop_duplicate_response; admit_response; drop_old_epoch; drop_exhausted; passthrough_request_dup; passthrough_operate_dup; drop_request_duplicate; }
        const entries = {
            (t_KIND_OPEN, _, 0, _, _, _, _, _, _) : passthrough_tev_relay();
            (t_KIND_RESET, _, 32w2, _, _, _, _, 1, _) : passthrough_tev_relay();
            (t_KIND_RESET, _, 32w2, _, _, _, _, 2, _) : passthrough_tev_forward();
            (t_KIND_RESET, _, 0, _, _, _, _, 1, _) : passthrough_tev_relay();
            (t_KIND_RESET, _, 0, _, _, _, _, 2, _) : passthrough_tev_forward();
            (t_KIND_RESET, _, 0, _, _, _, _, _, _) : drop_tin();
            (t_KIND_REQUEST, _, 0, _, _, _, _, _, 32w0xffff) : drop_exhausted();
            (t_KIND_OPERATE, _, 0, _, _, _, _, _, 32w0xffff) : drop_exhausted();
            (t_KIND_REQUEST_DUP, 0, 0, _, _, _, _, _, _) : passthrough_request_dup();
            (t_KIND_OPERATE_DUP, 0, 0, _, _, _, _, _, _) : passthrough_operate_dup();
            (t_KIND_REQUEST_DUP, _, 0, _, 0, _, _, _, _) : passthrough_request_dup();
            (t_KIND_REQUEST_DUP, _, 0, _, _, _, 0, _, _) : drop_request_duplicate();
            (t_KIND_REQUEST_DUP, _, 0, _, _, _, _, _, _) : passthrough_request_dup();
            (t_KIND_OPERATE_DUP, _, 0, _, 0, _, _, _, _) : passthrough_operate_dup();
            (t_KIND_OPERATE_DUP, _, 0, _, _, _, 0, _, _) : drop_request_duplicate();
            (t_KIND_OPERATE_DUP, _, 0, _, _, _, _, _, _) : passthrough_operate_dup();
            (t_KIND_REQUEST, 0, 0, _, _, _, _, _, _) : passthrough_tev_relay();
            (t_KIND_OPERATE, 0, 0, _, _, _, _, _, _) : passthrough_tev_relay();
            (_, 0, 0, _, _, _, _, _, _) : passthrough_tev_forward();
            (t_KIND_REQUEST, _, 0, _, _, _, _, _, _) : admit_request();
            (t_KIND_ACK, _, 0, 0, _, _, _, _, _) : drop_tin();
            (t_KIND_ACK, _, 0, _, _, _, _, _, _) : hold_ack();
            (t_KIND_RESPONSE, _, 0, _, 0, _, _, _, _) : passthrough_tev_forward();
            (t_KIND_RESPONSE, _, 0, _, _, 0, _, _, _) : drop_duplicate_response();
            (t_KIND_RESPONSE, _, 0, _, _, _, _, _, _) : admit_response();
            (t_KIND_OPERATE, _, 0, _, _, _, _, _, _) : admit_request();
        } default_action = drop_old_epoch(); size = 26;
    }
''')
    t = _span(t, '    table token_verdict', '    table held_verdict', '''    table token_verdict {
        key = { md.e_bad : ternary; hdr.timer.app_id : ternary; hdr.timer.packet_id : ternary;
                md.rd_tok_diff : ternary; hdr.timer.batch_id : ternary; }
        actions = { seed_ack_blocker; seed_resp_blocker; drop_timer_stale_read; }
        const entries = {
            (_, _, _, _, 16w0xffff) : drop_timer_stale_read();
            (0, 0, 16w0 &&& 16w1, 0, _) : seed_ack_blocker();
            (0, 0, 16w0 &&& 16w1, _, _) : drop_timer_stale_read();
            (0, 0, _, 0, _) : seed_resp_blocker();
        }
        default_action = drop_timer_stale_read(); size = 4;
    }
''')
    t = _span(t, '    table hb_verdict', '    apply {\n        if ((!hdr.ladder.isValid()', '')
    t = once(t, 'params.apply(); clock.apply(); held_offsets(); op_offset();',
             'params.apply(); clock.apply(); held_offsets();')
    t = once(t, '        operate_generation_access.apply(); operate_anchor_access.apply();\n'
                '        compute_op_t0_masked(); compute_op_delta(); op_lgen_diff();\n', '')
    t = once(t, 'ack_completion_access.apply(); op_go_check.apply(); operate_completion_access.apply();',
             'ack_completion_access.apply();')
    t = once(t, '''            if (md.event_kind == t_KIND_OPERATE && md.enabled != 0 && md.e_bad == 0) { admit_operate_held(); }
            else { drop_clone(); }
''', '            drop_clone();\n')
    t = once(t, '            // Read only: no op_done write, no op_gen bump, no op_t0 arm, no clone (dup_hold_01).\n',
             '            // Genuine retries never allocate a new response generation or emit a clone.\n')
    t = once(t, '''        } else if (ig_intr_md.ingress_port == t_HB_RETURN) {

            hb_verdict.apply();
''', '')
    t = once(t, '// lgen_diff == 0 (ladder generation is current), done_diff == 0 (domain already completed in this\n    // generation),', '// lgen_diff == 0 (ladder generation is current),')
    t = once(t, '// An else-if chain (the roles are exclusive, so the done_diff writes do not order each other),', '// The ACK and response roles are exclusive,')
    for name in ('op_j', 'op_gen', 'op_done', 'op_t0', 'op_go', 'op_delta', 'op_tok_diff', 'op_lgen_diff',
                 'operate_generation_access', 'operate_anchor_access', 'operate_completion_access', 'hb_verdict',
                 't_HB_RETURN', 't_ROLE_OP_', 'hold_operate', 'admit_operate_held', 'seed_op_blocker', 'done_diff'):
        if name in t:
            raise ValueError('strip_operate_hold: %s still present' % name)
    return once(src, old, t)

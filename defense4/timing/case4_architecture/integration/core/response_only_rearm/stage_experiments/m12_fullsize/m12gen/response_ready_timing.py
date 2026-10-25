"""Opt-in response-ready ACK+D contract; frozen relay-ts output is untouched.

ack_done_reg packs status in bits31:16 and generation16 in bits15:0:
WAITING=0, COMMITTED=1, EXPIRED=2. EXPIRED is sticky until OPEN/RESET.
One stateful operation arbitrates expiry against genuine held-ACK commit.
Held-original budget remains the epoch; only blockers decrement a lap budget.
"""
import re

from .common import combined, once


def transform(src):
    # A genuine ACK may arrive after its whole response advanced N's server
    # cursor. Route only the exact old native start/request-end boundary.
    n_old = combined.segment(src, 'N')
    n = n_old
    start = n.index(' table first_event{'); end = n.index(' action next_stage()', start)
    table = n[start:end]
    rows = ''.join('(8w10,3w6,_,32w0x%x0000&&&32w0xffff0000,32w0x%08x,32w0,2w2,8w16,_,_,_):first_read_ack();' %
                   (phase, (-length) & 0xffffffff) for phase, length in ((5,49),(5,91),(5,134),(10,49)))
    table = once(table, 'const entries={', 'const entries={' + rows)
    table = once(table, 'size=184;', 'size=188;')
    n = n[:start] + table + n[end:]
    src = once(src, n_old, n)
    old = combined.segment(src, 'T')
    t = old

    def span(start, end, replacement):
        nonlocal t
        a = t.index(start); b = t.index(end, a)
        t = t[:a] + replacement + t[b:]

    t = once(t, '/* Generated isolated T reconnect candidate. */',
             '/* Generated isolated T reconnect candidate. */\n// timing_contract: response_ready_ack_d_v1')
    t = once(t, 'const bit<32> t_OUT_ACK_FALLBACK = 8;', 'const bit<32> t_OUT_WAIT_EXPIRED = 8;')
    t = once(t, 'const bit<32> t_OUT_RESP_FALLBACK = 9;', 'const bit<32> t_OUT_EXPIRED_DROP = 9;')
    t = once(t, 'bit<32> da; bit<32> readiness; bit<32> gap;', 'bit<32> response_wait_timeout; bit<32> gap;')
    span('    bit<32> now_m_da;', '    bit<32> now_m_gap;', '''    bit<32> now_m_wait; bit<32> wait_delta;
    bit<32> committed_word; bit<32> target_word; bit<32> state_old;
''')
    span('    action set_params(', '    action clock_sample()', '''    action set_params(bit<32> gap, bit<32> op_j, bit<32> response_wait_timeout,
                      bit<32> budget, bit<32> enabled) {
        md.gap = gap; md.op_j = op_j; md.response_wait_timeout = response_wait_timeout;
        md.budget_cap = budget; md.enabled = enabled;
    }
    table params {
        actions = { set_params; }
        default_action = set_params(19534, 9377, 1953127, 60000, 1); size = 1;
    }
''')
    # The admitted generation is also this pass's current generation. All source
    # consumers below the allocation stage therefore use one generation identity.
    t = once(t, 'action live_admit_gen() { md.new_gen = gen_admit.execute(0); md.e_bad = 0; }',
             'action live_admit_gen() { md.cur_gen = gen_admit.execute(0); md.e_bad = 0; }')
    t = once(t, 'action live_reset_gen() { md.new_gen = gen_bump.execute(0); md.e_bad = 0; }',
             'action live_reset_gen() { md.cur_gen = gen_bump.execute(0); md.e_bad = 0; }')
    span('    Register<bit<32>, bit<1>>(1, 0) ack_done_reg;', '    // Generation-scoped a_commit', '''    // Atomic completion state: high16 status (0 waiting,1 committed,2 expired), low16 generation.
    // Expiry wins exactly at t0+timeout; a committed generation keeps its full D.
    Register<bit<32>, bit<1>>(1, 0) ack_done_reg;
    RegisterAction<bit<32>, bit<1>, bit<32>>(ack_done_reg) ack_state_read = {
        void apply(inout bit<32> value, out bit<32> out_value) { out_value = value ^ md.committed_word; }
    };
    // OPEN/RESET seal idle ownership with the protected high1 encoding.
    // No ACK commit timestamp is published. The next REQUEST changes the
    // generation and atomically initializes WAITING before any ACK can commit.
    RegisterAction<bit<32>, bit<1>, bit<32>>(ack_done_reg) ack_state_clear = {
        void apply(inout bit<32> value, out bit<32> out_value) { value = md.committed_word; out_value = 32w0x10000; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(ack_done_reg) ack_state_step = {
        void apply(inout bit<32> value, out bit<32> out_value) {
            out_value = value ^ md.committed_word;
            if (value < 32w0x20000 && value != md.committed_word) { value = md.target_word; }
        }
    };
    action read_ack_state() { md.state_old = ack_state_read.execute(0); }
    action clear_ack_state() { md.state_old = ack_state_clear.execute(0); }
    action step_ack_state() { md.state_old = ack_state_step.execute(0); }
    table ack_status_access {
        key = { md.e_bad : ternary; md.enabled : ternary; md.event_kind : ternary;
                ig_intr_md.ingress_port : ternary; md.token_ok : ternary; }
        actions = { read_ack_state; clear_ack_state; step_ack_state; }
        const entries = {
            (0, _, t_KIND_OPEN, t_T_IN, _) : clear_ack_state();
            (0, _, t_KIND_RESET, t_T_IN, _) : clear_ack_state();
            (0, 0, _, _, _) : read_ack_state();
            (0, _, _, t_T_IN, _) : step_ack_state();
            (0, _, _, t_HELD_RETURN, _) : step_ack_state();
            (0, _, _, t_HB_RETURN, _) : step_ack_state();
            (0, _, _, _, 1) : step_ack_state();
        }
        default_action = read_ack_state(); size = 7;
    }
    action state_words() {
        md.committed_word = md.cur_gen | 32w0x00010000;
    }
''')
    # One PHV output per SALU invocation; the newly admitted generation is
    # canonical throughout T instead of copying the same extern result inside
    # its action (Tofino cannot lower that copy as a second output).
    t = once(t, 'bit<32> cur_gen; bit<32> new_gen;', 'bit<32> cur_gen;')
    t = t.replace('md.new_gen', 'md.cur_gen')
    # No piggyback success path or ACK-seen state in this contract.
    span('    // Piggyback detection:', '    table child_seen0_access', '')
    span('    action held_offsets()', '    action read_gap_delta()', '''    action held_offsets() {
        md.now_m_wait = md.now - md.response_wait_timeout; md.now_m_gap = md.now - md.gap;
    }
    action compute_wait_delta() { md.wait_delta = md.now_m_wait - md.t0_v; }
''')
    t = once(t, '    action read_ack_done() { md.done_diff = ack_done_read.execute(0); }\n', '')
    t = once(t, '    action try_ack_done() { md.done_diff = ack_done_try.execute(0); }\n', '')
    span('    action set_ack_go(', '    action export_held()', '''    action set_ack_go(bit<8> go, bit<32> status) { md.ack_go = go; md.target_word = md.cur_gen | status; }
    table ack_go_check {
        key = { md.e_bad : ternary; md.enabled : ternary; md.wait_delta : ternary;
                ig_intr_md.ingress_port : ternary; hdr.ladder.role : ternary;
                md.lgen_diff : ternary; md.seen0_diff : ternary; md.event_kind : ternary; md.token_ok : ternary; }
        actions = { set_ack_go; }
        const entries = {
            (_, _, _, _, _, _, _, t_KIND_OPEN, _) : set_ack_go(0, 32w0);
            (_, _, _, _, _, _, _, t_KIND_RESET, _) : set_ack_go(0, 32w0);
            (_, _, _, _, _, _, _, t_KIND_REQUEST, _) : set_ack_go(0, 32w0);
            (_, _, _, _, _, _, _, t_KIND_OPERATE, _) : set_ack_go(0, 32w0);
            (0, 0, _, _, _, _, _, _, _) : set_ack_go(0, 32w0);
            (0, _, 32w0 &&& 32w0x80000000, t_T_IN, _, _, _, _, _) : set_ack_go(2, 32w0x20000);
            (0, _, 32w0 &&& 32w0x80000000, t_HELD_RETURN, _, _, _, _, _) : set_ack_go(2, 32w0x20000);
            (0, _, 32w0 &&& 32w0x80000000, t_HB_RETURN, _, _, _, _, _) : set_ack_go(2, 32w0x20000);
            (0, _, 32w0 &&& 32w0x80000000, _, _, _, _, _, 1) : set_ack_go(2, 32w0x20000);
            (0, _, _, t_HELD_RETURN, t_ROLE_ACK_HELD, 0, 0, _, _) : set_ack_go(1, 32w0x10000);
        }
        default_action = set_ack_go(0, 32w0); size = 10;
    }
''')
    # Express consumer predicates as logical status masks here, then lower
    # them to (old completion XOR committed_word, ack_go) at the end. The
    # SALU always returns one ALU expression; it never selects RAM/ALU output.
    for table, writer, reader in (('commit_at_access', 'mark_ack_commit_at', 'read_gap_delta'),
                                  ('commit_generation_access', 'mark_ack_commit_gen', 'read_commit_gen')):
        start = t.index('    table ' + table); end = t.index('\n    }', start) + 6
        replacement = ("    table " + table + " {\n"
            "        key = { hdr.ladder.role : ternary; md.state_old : ternary; }\n"
            "        actions = { " + writer + "; " + reader + "; NoAction; }\n"
            "        const entries = {\n"
            "            (t_ROLE_ACK_HELD, 32w0x50000 &&& 32w0xffff0000) : " + writer + "();\n"
            "            (t_ROLE_RESP_HELD, _) : " + reader + "();\n"
            "            (t_ROLE_RESP_BLK, _) : " + reader + "();\n"
            "        } default_action = NoAction(); size = 3;\n    }")
        t = t[:start] + replacement + t[end:]
    span('    action set_resp_go(', '    // Release only; resp_done_reg', '''    action response_done_wait() { md.resp_go = 0; md.done_diff = resp_done_read.execute(0); }
    action response_done_blocker_ready() { md.resp_go = 1; md.done_diff = resp_done_read.execute(0); }
    action response_done_commit() { md.resp_go = 1; md.done_diff = resp_done_commit.execute(0); }
    table resp_go_check {
        key = { md.e_bad : ternary; md.enabled : ternary; md.lgen_diff : ternary;
                md.gap_delta : ternary; md.commit_diff : ternary; md.state_old : ternary;
                hdr.ladder.role : ternary; }
        actions = { response_done_wait; response_done_blocker_ready; response_done_commit; NoAction; }
        const entries = {
            (0, 0, _, _, _, _, t_ROLE_RESP_HELD) : response_done_wait();
            (0, 0, _, _, _, _, t_ROLE_RESP_BLK) : response_done_wait();
            (0, _, 0, 32w0 &&& 32w0x80000000, 0, 32w0x10000 &&& 32w0x30000, t_ROLE_RESP_HELD) : response_done_commit();
            (0, _, 0, 32w0 &&& 32w0x80000000, 0, 32w0x10000 &&& 32w0x30000, t_ROLE_RESP_BLK) : response_done_blocker_ready();
            (_, _, _, _, _, _, t_ROLE_RESP_HELD) : response_done_wait();
            (_, _, _, _, _, _, t_ROLE_RESP_BLK) : response_done_wait();
        }
        default_action = NoAction(); size = 6;
    }
''')
    # Fuse the response go decision with the one atomic register operation.
    # A blocker only reads completion; it never commits the held original.
    t = once(t, '(resp_done_reg) resp_done_try = {', '(resp_done_reg) resp_done_commit = {')
    t = once(t, '            if (md.resp_go == 1) { value = md.cur_gen; }', '            value = md.cur_gen;')
    t = once(t, '    action try_resp_done() { md.done_diff = resp_done_try.execute(0); }\n', '')
    for name, counter in (('flush_ack_stale','t_OUT_HELD_STALE_FLUSH'), ('flush_response_stale','t_OUT_HELD_STALE_FLUSH'), ('flush_operate_stale','t_OUT_HELD_STALE_FLUSH')):
        start = t.index('    action ' + name + '()'); end = t.index('\n    }', start) + 6
        t = t[:start] + '    action ' + name + '() { ig_dprsr_md.drop_ctl = 1; count(' + counter + '); }' + t[end:]
    t = once(t, '    action release_ack_fallback() { release_ack(); count(t_OUT_ACK_FALLBACK); }',
             '    action drop_expired() { ig_dprsr_md.drop_ctl = 1; count(t_OUT_EXPIRED_DROP); }')
    t = once(t, '    action release_response_fallback() { release_response(); count(t_OUT_RESP_FALLBACK); }\n', '')
    # All T_IN payload admissions respect the sticky failure state. Handshake
    # and close rows remain earlier so normal teardown/new handshake recovers.
    start=t.index('    table tin_verdict'); end=t.index('    table token_verdict',start)
    body=t[start:end]
    body=once(body, 'md.event_kind : ternary; md.enabled : ternary; md.e_bad : ternary;',
              'md.event_kind : ternary; md.enabled : ternary; md.e_bad : ternary; md.state_old : ternary;')
    body=once(body, 'passthrough_operate_dup; drop_operate_dup; }', 'passthrough_operate_dup; drop_operate_dup; drop_expired; }')
    body=re.sub(r'\(([^()\n]+)\) : (\w+)\(', lambda m:'('+','.join(m[1].split(',')[:3])+', _,'+','.join(m[1].split(',')[3:])+') : '+m[2]+'(', body)
    anchor='            (t_KIND_REQUEST, _, 0, _, _, _, _, _, _) : admit_request();'
    body=once(body,anchor,'            (_, _, 0, 32w0x20000 &&& 32w0x30000, _, _, _, _, _) : drop_expired();\n'+anchor)
    # Timed ACK duplicates cannot pass a second genuine commit; response
    # retransmissions after successful release keep the existing passthrough.
    body=once(body, '            (t_KIND_ACK, _, 0, _, _, _, _, _, _) : hold_ack();',
              '            (t_KIND_ACK, _, 0, 32w0x10000 &&& 32w0x30000, _, _, _, _, _) : drop_tin();\n            (t_KIND_ACK, _, 0, _, _, _, _, _, _) : hold_ack();')
    body=once(body, 'size = 23;', 'size = 25;')
    t=t[:start]+body+t[end:]
    span('    table held_verdict', '    table hb_verdict', '''    table held_verdict {
        key = { md.e_bad : ternary; hdr.ladder.role : ternary; md.lgen_diff : ternary;
                md.enabled : ternary; md.state_old : ternary;
                md.resp_go : ternary; md.done_diff : ternary; hdr.ladder.budget : ternary;
                md.seen0_diff : ternary; }
        actions = { stop_blocking; stop_blocking_stale; stop_blocking_tmo; stop_blocking_off; keep_blocking;
                    release_ack_commit; rewait_ack; flush_ack_stale; flush_ack_off;
                    release_response_counted; rewait_response; flush_response_stale; flush_response_off;
                    drop_expired; drop_tin; drop_duplicate_response; drop_old_epoch; unmatched; }
        const entries = {
            (0, t_ROLE_ACK_BLK, _, _, 32w0x20000 &&& 32w0x30000, _, _, _, _) : stop_blocking();
            (0, t_ROLE_RESP_BLK, _, _, 32w0x20000 &&& 32w0x30000, _, _, _, _) : stop_blocking();
            (0, _, _, _, 32w0x20000 &&& 32w0x30000, _, _, _, _) : drop_expired();
            (0, t_ROLE_ACK_BLK, 0, 0, _, _, _, _, _) : stop_blocking_off();
            (0, t_ROLE_ACK_BLK, 0, _, 32w0x10000 &&& 32w0x30000, _, _, _, _) : stop_blocking();
            (0, t_ROLE_ACK_BLK, 0, _, _, _, _, _, 0) : stop_blocking();
            (0, t_ROLE_ACK_BLK, 0, _, _, _, _, 0, _) : stop_blocking_tmo();
            (0, t_ROLE_ACK_BLK, 0, _, _, _, _, _, _) : keep_blocking(t_HELD_RETURN, 7);
            (0, t_ROLE_ACK_BLK, _, _, _, _, _, _, _) : stop_blocking_stale();
            (0, t_ROLE_RESP_BLK, 0, 0, _, _, _, _, _) : stop_blocking_off();
            (0, t_ROLE_RESP_BLK, 0, _, _, 1, _, _, _) : stop_blocking();
            (0, t_ROLE_RESP_BLK, 0, _, _, _, 0, _, _) : stop_blocking();
            (0, t_ROLE_RESP_BLK, 0, _, _, _, _, 0, _) : stop_blocking_tmo();
            (0, t_ROLE_RESP_BLK, 0, _, _, _, _, _, _) : keep_blocking(t_HELD_RETURN, 5);
            (0, t_ROLE_RESP_BLK, _, _, _, _, _, _, _) : stop_blocking_stale();
            (0, t_ROLE_ACK_HELD, 0, 0, _, _, _, _, _) : flush_ack_off();
            (0, t_ROLE_ACK_HELD, 0, _, 32w0x50000 &&& 32w0xffff0000, _, _, _, _) : release_ack_commit();
            (0, t_ROLE_ACK_HELD, 0, _, 32w0x10000 &&& 32w0x30000, _, _, _, _) : drop_tin();
            (0, t_ROLE_ACK_HELD, 0, _, _, _, _, _, _) : rewait_ack();
            (0, t_ROLE_ACK_HELD, _, _, _, _, _, _, _) : flush_ack_stale();
            (0, t_ROLE_RESP_HELD, 0, 0, _, _, _, _, _) : flush_response_off();
            (0, t_ROLE_RESP_HELD, 0, _, _, _, 0, _, _) : drop_duplicate_response();
            (0, t_ROLE_RESP_HELD, 0, _, _, 1, _, _, _) : release_response_counted();
            (0, t_ROLE_RESP_HELD, 0, _, _, _, _, _, _) : rewait_response();
            (0, t_ROLE_RESP_HELD, _, _, _, _, _, _, _) : flush_response_stale();
            (_, _, _, _, _, _, _, _, _) : drop_old_epoch();
        }
        default_action = unmatched(); size = 26;
    }
''')
    # Expired response ownership also retires its still-held OPERATE request.
    # A delayed traffic-manager return must never execute an expired command.
    start = t.index('    table op_go_check'); end = t.index('    action drop_exhausted', start)
    body = t[start:end]
    body = once(body, 'md.op_delta : ternary; }', 'md.op_delta : ternary; md.state_old : ternary; }')
    body = re.sub(r'\(([^()\n]+)\) : set_op_go\(', lambda m: '(' + m[1] + ', _) : set_op_go(', body)
    body = once(body, 'const entries = {',
                'const entries = { (0, _, _, _, 32w0x20000 &&& 32w0x30000) : set_op_go(0);')
    body = once(body, 'size = 2;', 'size = 3;')
    t = t[:start] + body + t[end:]
    start = t.index('    table hb_verdict'); end = t.index('    apply {', start)
    body = t[start:end]
    body = once(body, 'md.op_delta : ternary; hdr.ladder.budget : ternary; }',
                'md.op_delta : ternary; hdr.ladder.budget : ternary; md.state_old : ternary; }')
    body = once(body, 'unmatched; drop_old_epoch; }', 'unmatched; drop_old_epoch; drop_expired; }')
    body = re.sub(r'\(([^()\n]+)\) : (\w+)\(', lambda m: '(' + m[1] + ', _) : ' + m[2] + '(', body)
    body = once(body, 'const entries = {',
                'const entries = {\n'
                '            (0, t_ROLE_OP_BLK, _, _, _, _, _, 32w0x20000 &&& 32w0x30000) : stop_blocking();\n'
                '            (0, t_ROLE_OP_HELD, _, _, _, _, _, 32w0x20000 &&& 32w0x30000) : drop_expired();')
    body = once(body, 'size = 12;', 'size = 14;')
    t = t[:start] + body + t[end:]
    # Finish expiry/commit arbitration once, before any terminal branch. Only
    # actual held ACK/response records interpret budget as an epoch.
    t=once(t, '        ack_seen_access.apply();', '''        compute_wait_delta(); state_words();
        read_lgen_diff(); ack_go_check.apply(); ack_status_access.apply();''')
    t=once(t, '            compute_da_delta(); compute_readiness_delta(); compute_pb_delta(); read_lgen_diff();', '')
    span('            if (hdr.ladder.role == t_ROLE_ACK_HELD) {', '            // Only the response roles', '')
    # Blockers and held originals share the same gap predicate; no response
    # timeout is consulted after a successful commit.
    t=once(t, '            commit_at_access.apply(); commit_generation_access.apply();',
             '            commit_at_access.apply(); commit_generation_access.apply(); resp_go_check.apply();')
    t=once(t, '                resp_go_check.apply();\n', '')
    # Expiry is counted exactly once, including when its first pass also drops
    # an original. Later expired originals get EXPIRED_DROP independently.
    start=t.index('    table outcome_count'); end=t.index('\n    // ---- request admission',start)
    body=t[start:end]
    body=once(body,'key = { md.outcome_code : exact; }','key = { md.state_old : ternary; md.outcome_code : ternary; }')
    body=once(body,'const entries = {','const entries = { (32w0x60000 &&& 32w0xffff0000, _) : bump(8);')
    body=re.sub(r'(?<!\w)(\d+) : bump',r'(_, \1) : bump',body)
    body=once(body,'size = 25;', 'size = 26;')
    t=t[:start]+body+t[end:]
    t = once(t, 'bit<8> ack_go; bit<8> resp_go; bit<8> commit_ok; bit<8> op_go;',
             'bit<8> ack_go; bit<8> resp_go; bit<8> op_go;')
    t = once(t, '        operate_generation_access.apply(); operate_anchor_access.apply();',
             '        operate_generation_access.apply(); operate_anchor_access.apply();\n'
             '        compute_op_t0_masked(); compute_op_delta();')
    t = once(t, '            compute_op_t0_masked(); compute_op_delta(); op_lgen_diff();', '            op_lgen_diff();')
    # Both T_IN reads return into done_diff, but their event kinds are
    # disjoint. Expose that exclusivity so the OP register does not force
    # the response register and every terminal verdict into a later stage.
    op_read = '            if (md.event_kind == t_KIND_OPERATE_DUP && md.e_bad == 0 && md.enabled != 0) { read_op_done(); }'
    rsp_read = '            if (md.event_kind == t_KIND_RESPONSE && md.e_bad == 0 && md.enabled != 0) { read_resp_done(); }'
    t = once(t, op_read + '\n', '')
    t = once(t, rsp_read, op_read + '\n' + rsp_read.replace('            if (', '            else if (', 1))
    t = once(t, '            if (hdr.ladder.role == t_ROLE_RESP_HELD) {\n'
                '                try_resp_done();\n'
                '            } else if (hdr.ladder.role == t_ROLE_RESP_BLK) { read_resp_done(); }\n', '')
    t = direct_state_predicates(t)
    return once(src, old, t)


def direct_state_predicates(t):
    """Fuse logical status classification into each consuming table.

    Proven SALU output: zero=current COMMITTED; high1=old WAITING;
    high3=old EXPIRED. Only WAITING+go1 commits and WAITING+go2 expires.
    Matching these directly removes a full classification-table dependency.
    """
    waiting = '32w0x10000 &&& 32w0xffff0000'
    expired = '32w0x30000 &&& 32w0xffff0000'
    predicates = {
        '_': [('_', '_')],
        '32w0x50000&&&32w0xffff0000': [(waiting, '1')],
        '32w0x60000&&&32w0xffff0000': [(waiting, '2')],
        '32w0x10000&&&32w0x30000': [('32w0', '_')],
        '32w0x20000&&&32w0x30000': [(expired, '_'), (waiting, '2')],
    }
    for name in ('commit_at_access', 'commit_generation_access', 'resp_go_check',
                 'tin_verdict', 'held_verdict', 'op_go_check', 'hb_verdict', 'outcome_count'):
        start = t.index('    table ' + name + ' {')
        end = t.index('\n    }', start) + 6
        body = t[start:end]
        key = re.search(r'key = \{([^}]+)\}', body)
        fields = [field.strip() for field in key[1].split(';') if field.strip()]
        pos = fields.index('md.state_old : ternary')
        fields.insert(pos + 1, 'md.ack_go : ternary')
        body = once(body, key[0], 'key = { ' + '; '.join(fields) + '; }')
        count = 0
        def lower(match):
            nonlocal count
            values = [value.strip() for value in match[1].split(',')]
            cases = predicates[re.sub(r'\s+', '', values[pos])]
            rows = []
            for state, go in cases:
                result = values[:pos] + [state, go] + values[pos + 1:]
                rows.append('(' + ', '.join(result) + ') : ' + match[2] + '(' + match[3] + ');')
            count += len(rows)
            return '\n            '.join(rows)
        body = re.sub(r'\(([^()\n]+)\)\s*:\s*(\w+)\(([^()]*)\);', lower, body)
        body, changed = re.subn(r'size\s*=\s*\d+;', 'size = %d;' % count, body)
        assert changed == 1 and count, name
        t = t[:start] + body + t[end:]
    return t

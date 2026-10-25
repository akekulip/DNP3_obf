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
            "        key = { ig_intr_md.ingress_port : ternary; hdr.ladder.role : ternary; md.state_old : ternary; }\n"
            "        actions = { " + writer + "; " + reader + "; NoAction; }\n"
            "        const entries = {\n"
            "            (t_HELD_RETURN, t_ROLE_ACK_HELD, 32w0x50000 &&& 32w0xffff0000) : " + writer + "();\n"
            "            (t_HELD_RETURN, t_ROLE_RESP_HELD, _) : " + reader + "();\n"
            "            (t_HELD_RETURN, t_ROLE_RESP_BLK, _) : " + reader + "();\n"
            "        } default_action = NoAction(); size = 3;\n    }")
        t = t[:start] + replacement + t[end:]
    span('    action set_resp_go(', '    // Release only; resp_done_reg', '''    action response_done_wait() { md.resp_go = 0; md.done_diff = resp_done_read.execute(0); }
    action response_done_blocker_ready() { md.resp_go = 1; md.done_diff = resp_done_read.execute(0); }
    action response_done_commit() { md.resp_go = 1; md.done_diff = resp_done_commit.execute(0); }
    // One global access point keeps T_IN reads and held commits in one
    // physical stateful bank; separate call sites may be replicated by bf-p4c.
    table response_completion_access {
        key = { ig_intr_md.ingress_port : ternary; md.event_kind : ternary;
                md.e_bad : ternary; md.enabled : ternary; md.lgen_diff : ternary;
                md.gap_delta : ternary; md.commit_diff : ternary; md.state_old : ternary;
                hdr.ladder.role : ternary; }
        actions = { response_done_wait; response_done_blocker_ready; response_done_commit; NoAction; }
        const entries = {
            (t_T_IN, t_KIND_RESPONSE, 0, 0, _, _, _, _, _) : NoAction();
            (t_T_IN, t_KIND_RESPONSE, 0, _, _, _, _, _, _) : response_done_wait();
            (t_HELD_RETURN, _, 0, 0, _, _, _, _, t_ROLE_RESP_HELD) : response_done_wait();
            (t_HELD_RETURN, _, 0, 0, _, _, _, _, t_ROLE_RESP_BLK) : response_done_wait();
            (t_HELD_RETURN, _, 0, _, 0, 32w0 &&& 32w0x80000000, 0, 32w0x10000 &&& 32w0x30000, t_ROLE_RESP_HELD) : response_done_commit();
            (t_HELD_RETURN, _, 0, _, 0, 32w0 &&& 32w0x80000000, 0, 32w0x10000 &&& 32w0x30000, t_ROLE_RESP_BLK) : response_done_blocker_ready();
            (t_HELD_RETURN, _, _, _, _, _, _, _, t_ROLE_RESP_HELD) : response_done_wait();
            (t_HELD_RETURN, _, _, _, _, _, _, _, t_ROLE_RESP_BLK) : response_done_wait();
        }
        default_action = NoAction(); size = 8;
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
             '            commit_at_access.apply(); commit_generation_access.apply(); response_completion_access.apply();')
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
    # T_IN response reads share the single global completion table. Only
    # OPERATE_DUP still reads its separate completion register in this branch.
    rsp_read = '            if (md.event_kind == t_KIND_RESPONSE && md.e_bad == 0 && md.enabled != 0) { read_resp_done(); }'
    t = once(t, rsp_read + '\n', '')
    t = once(t, '    action read_resp_done() { md.done_diff = resp_done_read.execute(0); }\n', '')
    t = once(t, '            if (hdr.ladder.role == t_ROLE_RESP_HELD) {\n'
                '                try_resp_done();\n'
                '            } else if (hdr.ladder.role == t_ROLE_RESP_BLK) { read_resp_done(); }\n', '')
    t = once(t, '            commit_at_access.apply(); commit_generation_access.apply(); response_completion_access.apply();', '')
    t = once(t, '        read_lgen_diff(); ack_go_check.apply(); ack_status_access.apply();',
             '        read_lgen_diff(); ack_go_check.apply(); ack_status_access.apply();\n'
             '        commit_at_access.apply(); commit_generation_access.apply(); response_completion_access.apply();')
    # OPERATE has its own generation domain. Reusing the response lgen_diff
    # PHV field forced its overwrite behind the held-response verdict and
    # serialized the otherwise independent OPERATE deadline path.
    t = once(t, 'bit<16> lgen_diff;', 'bit<16> lgen_diff; bit<16> op_lgen_diff;')
    t = once(t, 'action op_lgen_diff() { md.lgen_diff = hdr.ladder.generation ^ (bit<16>)md.op_gen; }',
             'action op_lgen_diff() { md.op_lgen_diff = hdr.ladder.generation ^ (bit<16>)md.op_gen; }')
    t = once(t, '        compute_op_t0_masked(); compute_op_delta();',
             '        compute_op_t0_masked(); compute_op_delta(); op_lgen_diff();')
    t = once(t, '            op_lgen_diff();\n', '')
    start = t.index('    table op_go_check'); end = t.index('    action drop_exhausted', start)
    body = t[start:end]
    body = once(body, 'key = { ',
                'key = { ig_intr_md.ingress_port : ternary; hdr.ladder.role : ternary; ')
    body = once(body, 'md.lgen_diff : ternary;', 'md.op_lgen_diff : ternary;')
    body = re.sub(r'\(([^()\n]+)\) : set_op_go\(',
                  lambda m: '(t_HB_RETURN, t_ROLE_OP_HELD, ' + m[1] + ') : set_op_go(', body)
    t = t[:start] + body + t[end:]
    start = t.index('    table hb_verdict'); end = t.index('    apply {', start)
    body = once(t[start:end], 'md.lgen_diff : ternary;', 'md.op_lgen_diff : ternary;')
    t = t[:start] + body + t[end:]
    t = once(t, 'ack_go_check.apply(); ack_status_access.apply();',
             'ack_go_check.apply(); ack_status_access.apply(); op_go_check.apply();')
    t = once(t, '{ op_go_check.apply(); try_op_done(); }', '{ try_op_done(); }')
    t = direct_state_predicates(t)
    return request_retry_n(once(src, old, response_ready_v2(t)))


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
    for name in ('commit_at_access', 'commit_generation_access', 'response_completion_access',
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


def replace_block(text, marker, replacement):
    start = text.index(marker)
    at = text.index('{', start)
    depth = 0
    for end in range(at, len(text)):
        if text[end] == '{': depth += 1
        elif text[end] == '}':
            depth -= 1
            if depth == 0:
                stop=end+1
                if not replacement and marker.startswith('RegisterAction') and text[stop:stop+1]==';':stop+=1
                return text[:start] + replacement + text[stop:]
    raise ValueError(marker)


def table_text(name, keys, actions, rows, default='NoAction()'):
    return ('table '+name+' { key = { '+' '.join(k+' : ternary;' for k in keys)+' }\n'
            '        actions = { '+'; '.join(actions)+'; }\n        const entries = {\n            '+
            '\n            '.join('('+', '.join(vals)+') : '+action+';' for vals,action in rows)+
            '\n        } default_action = '+default+'; size = '+str(len(rows))+';\n    }')


def response_ready_v2(t):
    """Lower the selected timing role to unbounded retention with duplicate-request routing."""
    t=t.replace('response_ready_ack_d_v1','response_ready_ack_d_v2')
    t=t.replace('t_OUT_WAIT_EXPIRED','t_OUT_REQ_DUP_DROP').replace('t_OUT_EXPIRED_DROP','t_OUT_REQ_DUP_FORWARD')
    t=once(t,'const bit<8> t_KIND_OPERATE_DUP = 15;','const bit<8> t_KIND_OPERATE_DUP = 15;\nconst bit<8> t_KIND_REQUEST_DUP = 16;')
    t=once(t,'(t_KIND_OPERATE_DUP, 0) : opaque_ethernet;','(t_KIND_OPERATE_DUP, 0) : opaque_ethernet;\n            (t_KIND_REQUEST_DUP, 0) : opaque_ethernet;')
    t=t.replace('bit<32> response_wait_timeout; ','')
    t=t.replace('bit<32> now_m_wait; bit<32> wait_delta;','')
    t=t.replace('bit<32> committed_word; bit<32> target_word; bit<32> state_old;','bit<32> ack_diff; bit<32> resp_diff;')
    t=t.replace('bit<32> t0_v;','')
    t=replace_block(t,'action set_params(','''action set_params(bit<32> gap, bit<32> op_j, bit<32> budget, bit<32> enabled) {
        md.gap=gap; md.op_j=op_j; md.budget_cap=budget; md.enabled=enabled;
    }''')
    t=replace_block(t,'table params {','''table params { actions={set_params;} default_action=set_params(19534,9377,60000,1); size=1; }''')
    # The former request anchor only existed for the removed exchange timeout.
    t=once(t,'Register<bit<32>, bit<1>>(1, 0) t0_reg;','')
    for name in ('t0_read','t0_admit'):
        marker='RegisterAction<bit<32>, bit<1>, bit<32>>(t0_reg) '+name+' = '
        t=replace_block(t,marker,'')
    for name in ('read_t0','admit_t0'):
        t=replace_block(t,'action '+name+'()', '')
    t=replace_block(t,'table t0_access {','')
    t=t.replace('t0_access.apply();','').replace('compute_wait_delta(); state_words();','')
    t=replace_block(t,'action compute_wait_delta()', '')
    t=replace_block(t,'action held_offsets()', 'action held_offsets() { md.now_m_gap=md.now-md.gap; }')
    a=t.index('Register<bit<32>, bit<1>>(1, 0) ack_done_reg;');b=t.index('    // Generation-scoped a_commit',a)
    t=t[:a]+'''Register<bit<32>, bit<1>>(1,0) ack_done_reg;
    RegisterAction<bit<32>,bit<1>,bit<32>>(ack_done_reg) ack_done_read={
        void apply(inout bit<32> v,out bit<32> r){r=v^md.cur_gen;}
    };
    RegisterAction<bit<32>,bit<1>,bit<32>>(ack_done_reg) ack_done_try={
        void apply(inout bit<32> v,out bit<32> r){r=v^md.cur_gen;if(md.ack_go==1){v=md.cur_gen;}}
    };
    action read_ack_completion(){md.ack_diff=ack_done_read.execute(0);}
    action try_ack_completion(){md.ack_diff=ack_done_try.execute(0);}
    table ack_completion_access {
        key={ig_intr_md.ingress_port:ternary;hdr.ladder.role:ternary;}
        actions={read_ack_completion;try_ack_completion;}
        const entries={(t_HELD_RETURN,t_ROLE_ACK_HELD):try_ack_completion();}
        default_action=read_ack_completion();size=1;
    }
'''+t[b:]
    t=t.replace('ack_status_access.apply();','ack_completion_access.apply();')
    t=replace_block(t,'action set_ack_go(', 'action set_ack_go(bit<8> go){md.ack_go=go;}')
    t=replace_block(t,'table ack_go_check {',table_text('ack_go_check',
        ['md.e_bad','ig_intr_md.ingress_port','hdr.ladder.role','md.lgen_diff','md.seen0_diff'],['set_ack_go'],
        [(['0','t_HELD_RETURN','t_ROLE_ACK_HELD','0','0'],'set_ack_go(1)')],'set_ack_go(0)'))
    for name,writer,reader in (('commit_at_access','mark_ack_commit_at','read_gap_delta'),('commit_generation_access','mark_ack_commit_gen','read_commit_gen')):
        rows=[(['t_HELD_RETURN','t_ROLE_ACK_HELD','0','_'],'NoAction()'),
              (['t_HELD_RETURN','t_ROLE_ACK_HELD','_','1'],writer+'()'),
              (['t_HELD_RETURN','t_ROLE_RESP_HELD','_','_'],reader+'()'),
              (['t_HELD_RETURN','t_ROLE_RESP_BLK','_','_'],reader+'()')]
        t=replace_block(t,'table '+name+' {',table_text(name,['ig_intr_md.ingress_port','hdr.ladder.role','md.ack_diff','md.ack_go'],[writer,reader,'NoAction'],rows))
    for name in ('response_done_wait','response_done_blocker_ready','response_done_commit'):
        a=t.index('action '+name+'()');b=t.index('}',a)+1
        t=t[:a]+t[a:b].replace('md.done_diff','md.resp_diff')+t[b:]
    rows=[]
    for kind in ('t_KIND_RESPONSE','t_KIND_REQUEST_DUP','t_KIND_OPERATE_DUP'):
        rows.append((['t_T_IN',kind,'0','_','_','_','_'],'response_done_wait()'))
    for role_,action in (('t_ROLE_RESP_HELD','response_done_commit()'),('t_ROLE_RESP_BLK','response_done_blocker_ready()')):
        rows.append((['t_HELD_RETURN','_','0','0','32w0 &&& 32w0x80000000','0',role_],action))
        rows.append((['t_HELD_RETURN','_','_','_','_','_',role_],'response_done_wait()'))
    t=replace_block(t,'table response_completion_access {',table_text('response_completion_access',
        ['ig_intr_md.ingress_port','md.event_kind','md.e_bad','md.lgen_diff','md.gap_delta','md.commit_diff','hdr.ladder.role'],
        ['response_done_wait','response_done_blocker_ready','response_done_commit','NoAction'],rows))
    # Read the presence marker for request retries; only genuine responses write it.
    marker='            (t_HELD_RETURN, _, _, _, _) : read_seen0();'
    t=once(t,marker,marker+'\n            (t_T_IN,t_KIND_REQUEST_DUP,_,0,_):read_seen0();\n            (t_T_IN,t_KIND_OPERATE_DUP,_,0,_):read_seen0();')
    start=t.index('table child_seen0_access {');end=t.index('\n    }',start)+6
    body=t[start:end];body=once(body,'size = 3;','size = 5;');t=t[:start]+body+t[end:]
    t=replace_block(t,'action drop_expired()', 'action drop_request_duplicate(){ig_dprsr_md.drop_ctl=1;count(t_OUT_REQ_DUP_DROP);}')
    t=once(t,'action passthrough_operate_dup() { hdr.tev.kind = t_KIND_OPERATE; ig_tm_md.ucast_egress_port = t_RELAY_PORT; }',
        'action passthrough_operate_dup(){hdr.tev.kind=t_KIND_OPERATE;ig_tm_md.ucast_egress_port=t_RELAY_PORT;count(t_OUT_REQ_DUP_FORWARD);}\n'
        '    action passthrough_request_dup(){hdr.tev.kind=t_KIND_REQUEST;ig_tm_md.ucast_egress_port=t_RELAY_PORT;count(t_OUT_REQ_DUP_FORWARD);}')
    keys=['md.event_kind','md.enabled','md.e_bad','md.ack_diff','md.resp_diff','md.done_diff','md.dup_diff','md.seen0_diff','hdr.tev.stage','md.cur_gen','md.op_gen']
    def row(kind,action,**kw):
        vals=[kind]+['_']*10
        pos={'en':1,'bad':2,'ack':3,'rsp':4,'op':5,'dup':6,'seen':7,'stage':8,'gen':9,'opgen':10}
        for k,v in kw.items():vals[pos[k]]=v
        return vals,action
    rows=[row('t_KIND_OPEN','passthrough_tev_relay()',bad='0'),
          row('t_KIND_RESET','passthrough_tev_relay()',bad='32w2',stage='1'),row('t_KIND_RESET','passthrough_tev_forward()',bad='32w2',stage='2'),
          row('t_KIND_RESET','passthrough_tev_relay()',bad='0',stage='1'),row('t_KIND_RESET','passthrough_tev_forward()',bad='0',stage='2'),row('t_KIND_RESET','drop_tin()',bad='0'),
          row('t_KIND_REQUEST','drop_exhausted()',bad='0',gen='32w0xffff'),row('t_KIND_OPERATE','drop_exhausted()',bad='0',gen='32w0xffff'),row('t_KIND_OPERATE','drop_exhausted()',bad='0',opgen='32w0xffff')]
    rows += [row('t_KIND_REQUEST_DUP','passthrough_request_dup()',bad='0',en='0'),row('t_KIND_OPERATE_DUP','passthrough_operate_dup()',bad='0',en='0')]
    rows += [row('t_KIND_REQUEST_DUP','passthrough_request_dup()',bad='0',rsp='0'),row('t_KIND_REQUEST_DUP','drop_request_duplicate()',bad='0',seen='0'),row('t_KIND_REQUEST_DUP','passthrough_request_dup()',bad='0'),
             row('t_KIND_OPERATE_DUP','passthrough_operate_dup()',bad='0',rsp='0',op='0'),row('t_KIND_OPERATE_DUP','drop_operate_dup()',bad='0',rsp='0'),row('t_KIND_OPERATE_DUP','drop_request_duplicate()',bad='0',seen='0'),row('t_KIND_OPERATE_DUP','passthrough_operate_dup()',bad='0',op='0'),row('t_KIND_OPERATE_DUP','drop_operate_dup()',bad='0')]
    rows += [row('t_KIND_REQUEST','passthrough_tev_relay()',bad='0',en='0'),row('t_KIND_OPERATE','passthrough_tev_relay()',bad='0',en='0'),row('_','passthrough_tev_forward()',bad='0',en='0'),
             row('t_KIND_REQUEST','admit_request()',bad='0'),row('t_KIND_ACK','drop_tin()',bad='0',ack='0'),row('t_KIND_ACK','hold_ack()',bad='0'),
             row('t_KIND_RESPONSE','passthrough_tev_forward()',bad='0',rsp='0'),row('t_KIND_RESPONSE','drop_duplicate_response()',bad='0',dup='0'),row('t_KIND_RESPONSE','admit_response()',bad='0'),row('t_KIND_OPERATE','hold_operate()',bad='0')]
    acts=['passthrough_tev_relay','passthrough_tev_forward','drop_tin','admit_request','hold_ack','drop_duplicate_response','admit_response','hold_operate','drop_old_epoch','drop_exhausted','passthrough_request_dup','passthrough_operate_dup','drop_request_duplicate','drop_operate_dup']
    t=replace_block(t,'table tin_verdict {',table_text('tin_verdict',keys,acts,rows,'drop_old_epoch()'))
    # All genuine held originals remain gated until release or lifetime cleanup.
    keys=['md.e_bad','hdr.ladder.role','md.lgen_diff','md.ack_diff','md.ack_go','md.resp_go','md.resp_diff','hdr.ladder.budget','md.seen0_diff']
    rows=[]
    def held(role_,action,**kw):
        vals=['0',role_]+['_']*7;pos={'gen':2,'ack':3,'go':4,'rgo':5,'rsp':6,'budget':7,'seen':8}
        for k,v in kw.items():vals[pos[k]]=v
        return vals,action
    rows += [held('t_ROLE_ACK_BLK','stop_blocking()',gen='0',ack='0'),held('t_ROLE_ACK_BLK','stop_blocking()',gen='0',seen='0'),held('t_ROLE_ACK_BLK','stop_blocking_tmo()',gen='0',budget='0'),held('t_ROLE_ACK_BLK','keep_blocking(t_HELD_RETURN,7)',gen='0'),held('t_ROLE_ACK_BLK','stop_blocking_stale()')]
    rows += [held('t_ROLE_RESP_BLK','stop_blocking()',gen='0',rgo='1'),held('t_ROLE_RESP_BLK','stop_blocking()',gen='0',rsp='0'),held('t_ROLE_RESP_BLK','stop_blocking_tmo()',gen='0',budget='0'),held('t_ROLE_RESP_BLK','keep_blocking(t_HELD_RETURN,5)',gen='0'),held('t_ROLE_RESP_BLK','stop_blocking_stale()')]
    rows += [held('t_ROLE_ACK_HELD','drop_tin()',gen='0',ack='0'),held('t_ROLE_ACK_HELD','release_ack_commit()',gen='0',go='1'),held('t_ROLE_ACK_HELD','rewait_ack()',gen='0'),held('t_ROLE_ACK_HELD','flush_ack_stale()')]
    rows += [held('t_ROLE_RESP_HELD','drop_duplicate_response()',gen='0',rsp='0'),held('t_ROLE_RESP_HELD','release_response_counted()',gen='0',rgo='1'),held('t_ROLE_RESP_HELD','rewait_response()',gen='0'),held('t_ROLE_RESP_HELD','flush_response_stale()')]
    acts=['stop_blocking','stop_blocking_tmo','stop_blocking_stale','keep_blocking','drop_tin','release_ack_commit','rewait_ack','flush_ack_stale','drop_duplicate_response','release_response_counted','rewait_response','flush_response_stale','drop_old_epoch']
    t=replace_block(t,'table held_verdict {',table_text('held_verdict',keys,acts,rows,'drop_old_epoch()'))
    t=replace_block(t,'table op_go_check {',table_text('op_go_check',['ig_intr_md.ingress_port','hdr.ladder.role','md.e_bad','md.op_lgen_diff','md.op_delta'],['set_op_go'],
        [(['t_HB_RETURN','t_ROLE_OP_HELD','0','0','32w0 &&& 32w0x80000000'],'set_op_go(1)')],'set_op_go(0)'))
    t=replace_block(t,'table hb_verdict {',table_text('hb_verdict',['md.e_bad','hdr.ladder.role','md.op_lgen_diff','md.done_diff','md.op_go','md.op_delta','hdr.ladder.budget'],
        ['stop_blocking','stop_blocking_stale','stop_blocking_tmo','keep_blocking','release_operate_counted','rewait_operate','flush_operate_stale','drop_old_epoch'],[
        (['0','t_ROLE_OP_BLK','0','0','_','_','_'],'stop_blocking()'),(['0','t_ROLE_OP_BLK','0','_','_','32w0 &&& 32w0x80000000','_'],'stop_blocking()'),(['0','t_ROLE_OP_BLK','0','_','_','_','0'],'stop_blocking_tmo()'),(['0','t_ROLE_OP_BLK','0','_','_','_','_'],'keep_blocking(t_HB_RETURN,3)'),(['0','t_ROLE_OP_BLK','_','_','_','_','_'],'stop_blocking_stale()'),
        (['0','t_ROLE_OP_HELD','0','0','_','_','_'],'rewait_operate()'),(['0','t_ROLE_OP_HELD','0','_','1','_','_'],'release_operate_counted()'),(['0','t_ROLE_OP_HELD','0','_','_','_','_'],'rewait_operate()'),(['0','t_ROLE_OP_HELD','_','_','_','_','_'],'flush_operate_stale()')],'drop_old_epoch()'))
    # Unify all OP completion reads/commits too: one physical bank for both ports.
    t=once(t,'            if (md.event_kind == t_KIND_OPERATE_DUP && md.e_bad == 0 && md.enabled != 0) { read_op_done(); }','')
    t=once(t,'            if (hdr.ladder.role == t_ROLE_OP_HELD) { try_op_done(); }\n            else if (hdr.ladder.role == t_ROLE_OP_BLK) { read_op_done(); }','')
    op=table_text('operate_completion_access',['ig_intr_md.ingress_port','md.event_kind','hdr.ladder.role','md.e_bad'],['read_op_done','try_op_done','NoAction'],[
        (['t_T_IN','t_KIND_OPERATE_DUP','_','0'],'read_op_done()'),(['t_HB_RETURN','_','t_ROLE_OP_HELD','0'],'try_op_done()'),(['t_HB_RETURN','_','t_ROLE_OP_BLK','0'],'read_op_done()')])
    marker='    // ---- verdict tables'
    at=t.index(marker);t=t[:at]+op+'\n'+t[at:]
    t=once(t,'ack_completion_access.apply(); op_go_check.apply();','ack_completion_access.apply(); op_go_check.apply(); operate_completion_access.apply();')
    rows=[([str(i)],'bump('+str(i)+')') for i in list(range(17))+[23,24]]
    t=replace_block(t,'table outcome_count {',table_text('outcome_count',['md.outcome_code'],['bump','NoAction'],rows))
    # No unused successful off flush path survives in the emitted program.
    for name,rewait in (('flush_ack_off','rewait_ack'),('flush_response_off','rewait_response'),('flush_operate_off','rewait_operate')):
        t=replace_block(t,'action '+name+'()', 'action '+name+'(){'+rewait+'();}')
    return t


def request_retry_n(src):
    """Route validated logical request retries through existing kind24 owner checks."""
    old=combined.segment(src,'N');n=old
    n=once(n,'action first_operate_dup(){hdr.event.event=16w0x0118;hdr.t0.setValid();hdr.t0.t0q=32w0;}',
        'action first_operate_dup(){hdr.event.event=16w0x0118;hdr.t0.setValid();hdr.t0.t0q=32w0;}\n'
        'action first_request_dup(){hdr.event.event=16w0x0118;hdr.t0.setValid();hdr.t0.t0q=32w0;}')
    # Existing application banks bind retries to the currently admitted logical
    # request. All fixed object/function bytes were validated by the profiles.
    start=n.index('table read_app_t{');end=n.index('\n',start);body=n[start:end]
    body=once(body,'size=2;','size=3;')
    body=once(body,'const entries={','const entries={(2w0,8w9,32w4,_):match_read_app();')
    n=n[:start]+body+n[end:]
    start=n.index('table application_t{');end=n.index('\n',start);body=n[start:end]
    body=once(body,'size=4;','size=5;')
    body=once(body,'const entries={','const entries={(2w0,8w5,32w4,_):compare_application();')
    n=n[:start]+body+n[end:]
    # Pack logical request type into existing application banks. This binds
    # native TCP end to the original length/function, without a new register.
    n=once(n,'m.compare_read_app=(bit<32>)(hdr.rd_req_full.app[3:0]);',
           'm.compare_read_app=32w0x100 | (bit<32>)(hdr.rd_req_full.app[3:0]);')
    n=once(n,'m.compare_read_app=(bit<32>)(hdr.rd_req_mx.app[3:0]);',
           'm.compare_read_app=32w0x200 | (bit<32>)(hdr.rd_req_mx.app[3:0]);')
    n=replace_block(n,'action read_response_input()',
        'action read_response_input(bit<32> shape){m.compare_read_app=shape | (bit<32>)(hdr.first.w0[19:16]);}')
    n=replace_block(n,'table read_input_t{',
        'table read_input_t{key={m.packet_kind:exact;hdr.rd_req_full.isValid():exact;hdr.rd_req_mx.isValid():exact;hdr.dl.len:ternary;}'
        'actions={read_request_input;read_request_full_input;read_request_mx_input;read_response_input;NoAction;}size=5;'
        'const entries={(8w9,false,false,_):read_request_input();(8w9,true,false,_):read_request_full_input();'
        '(8w9,false,true,_):read_request_mx_input();(8w11,false,false,8w0x4c):read_response_input(32w0x200);'
        '(8w11,false,false,8w0x73):read_response_input(32w0x100);}const default_action=NoAction();}')
    n=once(n,'action store_read_app(){',
        'RegisterAction<bit<32>,bit<1>,bit<32>>(read_app) invalidate_read_app={void apply(inout bit<32> v,out bit<32> r){v=32w0xffffffff;r=v;}};'
        'action forget_read_app(){invalidate_read_app.execute(1w0);}'
        'action store_read_app(){')
    start=n.index('table read_app_t{');end=n.index('\n',start);body=n[start:end]
    body=once(body,'store_read_app;match_read_app;','store_read_app;match_read_app;forget_read_app;')
    body=once(body,'const entries={','const entries={(2w1,8w5,32w1,32w0):forget_read_app();(2w1,8w7,32w1,32w0):forget_read_app();')
    body=once(body,'size=3;','size=5;');n=n[:start]+body+n[end:]
    for name in ('compare_select_inputs','compare_operate_inputs','compare_operate_store_inputs'):
        start=n.index('action '+name+'()');end=n.index('}',start)+1;body=n[start:end]
        body=once(body,'m.compare_application=(bit<32>)(hdr.first.w0[23:16]);',
                  'm.compare_application=(bit<32>)(hdr.first.w0[15:8]++hdr.first.w0[23:16]);')
        n=n[:start]+body+n[end:]
    n=once(n,'action store_application(){',
        'RegisterAction<bit<32>,bit<1>,bit<32>>(application) invalidate_application={void apply(inout bit<32> v,out bit<32> r){v=32w0xffffffff;r=v;}};'
        'action forget_application(){invalidate_application.execute(1w0);}'
        'action store_application(){')
    start=n.index('table application_t{');end=n.index('\n',start);body=n[start:end]
    body=once(body,'store_application;compare_application;','store_application;forget_application;compare_application;')
    body=once(body,'const entries={','const entries={(2w1,8w9,32w1,32w0):forget_application();')
    body=once(body,'size=5;','size=6;');n=n[:start]+body+n[end:]
    start=n.index('table object_match{');end=n.index('\n',start);body=n[start:end]
    body=once(body,'(1w1,32w0,32w0,32w0,32w0,32w0):matched();',
              '(1w1,32w0,32w0,32w0,32w0,32w0x300):matched();(1w1,32w0,32w0,32w0,32w0,32w0x400):matched();')
    body=once(body,'32w4294967295):matched();','32w4294967039):matched();')
    body=once(body,'32w15):matched();','32w4294967055):matched();')
    body=once(body,'size=3;','size=4;');n=n[:start]+body+n[end:]
    start=n.index('table first_event{');end=n.index(' action next_stage()',start);body=n[start:end]
    body=once(body,'m.retry:ternary;}','m.retry:ternary;hdr.dl.len:ternary;m.diff_application:ternary;}')
    body=once(body,'first_operate_dup;','first_operate_dup;first_request_dup;')
    def append_keys(m):
        vals=m[1].split(',')
        if len(vals)!=11:return m[0]
        if vals[0]=='8w9' and vals[1]=='3w1':vals[2]='_'
        extra=['_','0' if m[2]=='first_operate_dup' else '_']
        return '('+','.join(vals+extra)+'):'+m[2]+'('+m[3]+');'
    body=re.sub(r'\(([^()]+)\):(\w+)\(([^()]*)\);',append_keys,body)
    rows=[]
    def add(kind,phase,length,dl,server,matched,app,action):
        vals=[str(kind),'_',matched,'32w0x%x0000&&&32w0xffff0000'%phase,'32w0x%08x'%((-length)&0xffffffff),
              '32w0x%08x'%((-server)&0xffffffff),'2w1','8w24','_','_','_','8w0x%02x'%dl,app]
        rows.append('('+','.join(('8w'+vals[0],)+tuple(vals[1:]))+'):'+action+'();')
    for length,dl in ((25,0x12),(27,0x14)):
        for phase,servers in ((14,(0,)),(5,(0,91,134))):
            for server in servers:add(9,phase,length,dl,server,'1w1','_','first_request_dup')
    for kind,phases,action in ((5,(9,10,5),'first_request_dup'),(7,(12,5),'first_operate_dup')):
        for phase in phases:
            for server in (0,49):add(kind,phase,45,0x24,server,'_','32w0',action)
    body=once(body,'const entries={','const entries={'+''.join(rows))
    body=re.sub(r'size=\d+;', 'size=%d;'%(188+len(rows)),body,count=1)
    n=n[:start]+body+n[end:]
    # Kind24 already has parser states and bounded owner/epoch-check laps.
    # Add its two request shapes to the existing return guard, preserving CRCs.
    start=n.index('table guard{');end=n.index('\n apply{',start);body=n[start:end]
    copies=[]
    for vals,act,args in re.findall(r'\(([^()]+)\):(\w+)\(([^()]*)\);',body):
        v=vals.split(',')
        if len(v)==14 and v[1] in ('8w5','8w9') and v[2]=='8w8':
            v[2]='8w24';copies.append('('+','.join(v)+'):'+act+'('+args+');')
    assert len(copies)==2
    body=once(body,'const entries={','const entries={'+''.join(copies))
    body=once(body,'size=52;','size=54;');n=n[:start]+body+n[end:]
    start=n.index('table read_terminal_t{');end=n.index('\n',start);body=n[start:end]
    body=once(body,'m.direction:ternary;}','m.direction:ternary;m.packet_kind:ternary;}')
    body=re.sub(r'\(([^()]+)\):(\w+)\(([^()]*)\);',lambda m:'('+m[1]+',_):'+m[2]+'('+m[3]+');',body)
    body=once(body,'const entries={','const entries={(8w24,32w0,32w0,2w1,8w5):emit_tev(16w0x1000);(8w24,32w0,32w0,2w1,8w9):emit_tev(16w0x1000);')
    body=once(body,'size=14;','size=16;');n=n[:start]+body+n[end:]
    n=once(n,'control n_Ingress(', '@pa_solitary("ingress","m.diff_real_links")\ncontrol n_Ingress(')
    return once(src,old,n)

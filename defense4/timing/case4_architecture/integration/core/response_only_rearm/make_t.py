"""Derive T's fenced lifetime from the unchanged queue-resident baseline.

The held record's former zero budget carries the complete connection epoch.
Blocker budgets retain their original meaning. A transaction generation is never
reused in a deployment lifetime; 0xffff is an exhausted sentinel.
"""
import re
from baseline import INTEG


def replace(text, old, new):
    assert text.count(old) == 1, old[:100]
    return text.replace(old, new)


LIFETIME = '''    Register<bit<32>, bit<1>>(1, 0) cur_epoch_reg;
    RegisterAction<bit<32>, bit<1>, bit<32>>(cur_epoch_reg) epoch_open = {
        void apply(inout bit<32> value, out bit<32> out_value) {
            if (hdr.tev.epoch > value && hdr.tev.epoch < 32w0x7fffffff) { value = hdr.tev.epoch; out_value = 0; }
            else { out_value = 1; }
        }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(cur_epoch_reg) epoch_read = {
        void apply(inout bit<32> value, out bit<32> out_value) { out_value = value; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(cur_epoch_reg) epoch_match = {
        void apply(inout bit<32> value, out bit<32> out_value) { out_value = value ^ md.packet_epoch; }
    };
    action open_epoch() { md.epoch_delta = epoch_open.execute(0); }
    action read_epoch() { md.packet_epoch = epoch_read.execute(0); md.epoch_delta = 0; }
    action match_epoch() { md.epoch_delta = epoch_match.execute(0); }
    table lifetime_access {
        key = { ig_intr_md.ingress_port : ternary; hdr.tev.kind : ternary; hdr.ladder.role : ternary; }
        actions = { open_epoch; read_epoch; match_epoch; }
        const entries = {
            (T_IN, KIND_OPEN, _) : open_epoch();
            (T_IN, _, _) : match_epoch();
            (PKTGEN_RETURN, KIND_OPERATE, _) : match_epoch();
            (HELD_RETURN, _, ROLE_ACK_HELD) : match_epoch();
            (HELD_RETURN, _, ROLE_RESP_HELD) : match_epoch();
            (HB_RETURN, _, ROLE_OP_HELD) : match_epoch();
        }
        default_action = read_epoch(); size = 6;
    }
    Register<bit<32>, bit<1>>(1, 0xffffffff) quarantine_reg;
    RegisterAction<bit<32>, bit<1>, bit<32>>(quarantine_reg) quarantine_read = {
        void apply(inout bit<32> value, out bit<32> out_value) { out_value = value ^ md.packet_epoch; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(quarantine_reg) quarantine_close = {
        void apply(inout bit<32> value, out bit<32> out_value) {
            out_value = value ^ md.packet_epoch;
            if (md.epoch_delta == 0 && md.packet_epoch != 0) { value = md.packet_epoch; }
        }
    };
    action read_quarantine() { md.q_diff = quarantine_read.execute(0); }
    action close_quarantine() { md.q_diff = quarantine_close.execute(0); }
    table quarantine_access {
        key = { ig_intr_md.ingress_port : ternary; hdr.tev.kind : ternary; }
        actions = { read_quarantine; close_quarantine; }
        const entries = { (T_IN, KIND_RESET) : close_quarantine(); }
        default_action = read_quarantine(); size = 1;
    }
'''



def generate():
    text = (INTEG / 'read' / 'read_queue_timing.p4').read_text()
    text = replace(text, 'bit<32> e_bad; bit<32> q_diff;',
                   'bit<32> e_bad; bit<32> q_diff; bit<32> packet_epoch; bit<32> cur_epoch_val; bit<32> epoch_delta; bit<32> quarantined_epoch; bit<8> event_kind;')
    text = replace(text, '        pkt.extract(ig_intr_md);',
                   '        md.event_kind = 0; md.packet_epoch = 0; pkt.extract(ig_intr_md);')
    text = text.replace('pkt.extract(hdr.tev);',
                        'pkt.extract(hdr.tev); md.event_kind = hdr.tev.kind; md.packet_epoch = hdr.tev.epoch;')
    text = replace(text, 'pkt.extract(hdr.ladder);',
                   'pkt.extract(hdr.ladder); md.packet_epoch = hdr.ladder.budget;')
    text = replace(text, 'const bit<8> KIND_OPERATE = 12; const bit<8> KIND_RESET = 13;',
                   'const bit<8> KIND_OPERATE = 12; const bit<8> KIND_RESET = 13; const bit<8> KIND_OPEN = 14;')
    text = replace(text, '(KIND_RESET, 0) : opaque_ethernet;',
                   '(KIND_RESET, 0) : opaque_ethernet;\n            (KIND_OPEN, 0) : opaque_ethernet;')
    start = text.index('    Register<bit<32>, bit<1>>(1, 0) cur_epoch_reg;')
    end = text.index('    Register<bit<32>, bit<1>>(1, 0) gen_alloc_reg;', start)
    text = text[:start] + LIFETIME + text[end:]
    start = text.index('    action check_epoch()')
    end = text.index('    action peek_gen()', start)
    text = text[:start] + text[end:]
    text = replace(text, '    action admit_epoch() { epoch_admit.execute(0); }\n', '')
    start = text.index('    table epoch_access {')
    end = text.index('    // ---- ACK domain', start)
    text = text[:start] + text[end:]
    # One explicit access table per child bank avoids hidden read/try tables
    # that the backend cannot co-place after the lifecycle prologue. A held
    # return only reads; a current, enabled response writes its own child tag.
    child_tables = []
    for child in range(3):
        skip = ''
        if child == 2:
            skip = ('(T_IN, KIND_RESPONSE, 0, _, _) : NoAction();\n'
                    '            (T_IN, KIND_RESPONSE, 1, _, _) : NoAction();\n')
        stage = '_' if child == 2 else str(child)
        child_tables.append('''    action try_seen%(child)d() { md.seen%(child)d_diff = child_try%(child)d.execute(0); }
    table child_seen%(child)d_access {
        key = { ig_intr_md.ingress_port : ternary; hdr.tev.kind : ternary;
                hdr.tev.stage : ternary; md.e_bad : ternary; md.enabled : ternary; }
        actions = { read_seen%(child)d; try_seen%(child)d; NoAction; }
        const entries = {
            (HELD_RETURN, _, _, _, _) : read_seen%(child)d();
            %(skip)s(T_IN, KIND_RESPONSE, %(stage)s, _, 0) : NoAction();
            (T_IN, KIND_RESPONSE, %(stage)s, 0, _) : try_seen%(child)d();
        }
        default_action = NoAction(); size = %(size)d;
    }
''' % dict(child=child, stage=stage, skip=skip, size=5 if child == 2 else 3))
        text = replace(text, 'md.dup_diff = child_try%d.execute(0);' % child,
                       'md.dup_diff = md.seen%d_diff;' % child)
    text = replace(text, '    // ---- OPERATE domain', ''.join(child_tables) + '    // ---- OPERATE domain')
    text = replace(text, '        t0_access.apply();',
                   '        t0_access.apply();\n'
                   '        child_seen0_access.apply(); child_seen1_access.apply(); child_seen2_access.apply();')
    text = replace(text, '            read_seen0(); read_seen1(); read_seen2();', '')
    # No generation tag is ever repeated. Reset/open can advance to the terminal
    # sentinel, but never wrap; admissions may allocate at most 0xfffe.
    text = text.replace('value = value + 1; out_value = value;',
                        'if (value < 32w0xffff) { value = value + 1; } out_value = value;', 2)
    text = replace(text, 'if (md.q_diff != 0) { value = value + 1; }',
                   'if (value < 32w0xfffe) { value = value + 1; }\n'
                   '            else { value = 32w0xffff; }')
    text = replace(text, 'if (md.q_diff != 0) { value = md.now; }',
                   'if (md.e_bad == 0) { value = md.now; }')
    text = replace(text, 'md.enabled : ternary; }\n        actions = { read_t0; admit_t0; }',
                   'md.enabled : ternary; md.new_gen : ternary; }\n        actions = { read_t0; admit_t0; }')
    text = replace(text, '(T_IN, KIND_REQUEST, 0) : read_t0();',
                   '(T_IN, KIND_REQUEST, _, 32w0xffff) : read_t0();\n'
                   '            (T_IN, KIND_REQUEST, 0, _) : read_t0();')
    text = replace(text, '(T_IN, KIND_REQUEST, _) : admit_t0();', '(T_IN, KIND_REQUEST, _, _) : admit_t0();')
    text = replace(text, 'default_action = read_t0(); size = 2;', 'default_action = read_t0(); size = 3;')
    text = replace(text, '            value = md.now | 32w1;',
                   '            if (md.op_gen < 32w0xffff) { value = md.now | 32w1; }')
    # Guard every allocator call, including RESET, in a single exclusive table.
    start = text.index('    table gen_access {')
    end = text.index('    action read_t0()', start)
    text = text[:start] + '''    action live_gen() { md.cur_gen = gen_peek.execute(0); md.e_bad = 0; }
    action bad_gen() { md.cur_gen = gen_peek.execute(0); md.e_bad = 1; }
    action duplicate_close_gen() { md.cur_gen = gen_peek.execute(0); md.e_bad = 2; }
    action live_admit_gen() { md.new_gen = gen_admit.execute(0); md.e_bad = 0; }
    action live_reset_gen() { md.new_gen = gen_bump.execute(0); md.e_bad = 0; }
    table gen_access {
        key = { ig_intr_md.ingress_port : ternary; hdr.tev.kind : ternary;
                md.enabled : ternary; md.packet_epoch : ternary; md.epoch_delta : ternary; md.q_diff : ternary; }
        actions = { live_gen; bad_gen; duplicate_close_gen; live_admit_gen; live_reset_gen; }
        const entries = {
            (_, _, _, 0, _, _) : bad_gen();
            (_, _, _, 32w0x7fffffff, _, _) : bad_gen();
            (_, _, _, 32w0x80000000 &&& 32w0x80000000, _, _) : bad_gen();
            (T_IN, KIND_OPEN, _, _, 0, _) : live_reset_gen();
            (T_IN, KIND_RESET, _, _, 0, 0) : duplicate_close_gen();
            (_, _, _, _, _, 0) : bad_gen();
            (T_IN, KIND_RESET, _, _, 0, _) : live_reset_gen();
            (T_IN, KIND_REQUEST, 0, _, 0, _) : live_gen();
            (T_IN, KIND_REQUEST, _, _, 0, _) : live_admit_gen();
            (_, _, _, _, 0, _) : live_gen();
        }
        default_action = bad_gen(); size = 10;
    }
''' + text[end:]
    # Epoch mismatch has priority over policy OFF, before any timing write.
    start = text.index('        // Prologue: quarantine')
    end = text.index('        t0_access.apply();', start)
    text = text[:start] + '        lifetime_access.apply(); quarantine_access.apply(); gen_access.apply();\n' + text[end:]
    text = replace(text, 'if (hdr.tev.kind == KIND_OPERATE && md.enabled != 0) { admit_operate_held(); }',
                   'if (hdr.tev.kind == KIND_OPERATE && md.enabled != 0 && md.e_bad == 0) { admit_operate_held(); }')
    text = text.replace('hdr.tev.kind == KIND_RESPONSE && md.e_bad == 0',
                        'hdr.tev.kind == KIND_RESPONSE && md.e_bad == 0 && md.enabled != 0')
    text = replace(text, 'if (hdr.tev.kind == KIND_OPERATE && md.enabled != 0) {',
                   'if (hdr.tev.kind == KIND_OPERATE && md.enabled != 0 && md.e_bad == 0) {')
    text = replace(text, '} else if (hdr.tev.kind == KIND_RESET && md.enabled != 0) { reset_bump_op_gen(); }',
                   '} else if ((hdr.tev.kind == KIND_RESET || hdr.tev.kind == KIND_OPEN) && md.e_bad == 0) { reset_bump_op_gen(); }')
    # Each existing OPERATE bank has one access site. The exclusive table keeps
    # a rejected event read-only and bumps OPEN/CLOSE even when policy is OFF.
    op_access = '''    action peek_operate_generation() { md.op_gen = op_gen_peek.execute(0); }
    action bump_operate_generation() { md.op_gen = op_gen_bump.execute(0); }
    table operate_generation_access {
        key = { ig_intr_md.ingress_port : ternary; hdr.tev.kind : ternary;
                md.enabled : ternary; md.e_bad : ternary; }
        actions = { peek_operate_generation; bump_operate_generation; }
        const entries = {
            (T_IN, KIND_OPEN, _, 0) : bump_operate_generation();
            (T_IN, KIND_RESET, _, 0) : bump_operate_generation();
            (T_IN, KIND_OPERATE, 0, _) : peek_operate_generation();
            (T_IN, KIND_OPERATE, _, 0) : bump_operate_generation();
        }
        default_action = peek_operate_generation(); size = 4;
    }
    action read_operate_anchor() { md.op_t0_v = op_t0_read.execute(0); }
    action arm_operate_anchor() { md.op_t0_v = op_t0_arm.execute(0); }
    table operate_anchor_access {
        key = { ig_intr_md.ingress_port : ternary; hdr.tev.kind : ternary;
                md.enabled : ternary; md.e_bad : ternary; }
        actions = { read_operate_anchor; arm_operate_anchor; }
        const entries = {
            (T_IN, KIND_OPERATE, 0, _) : read_operate_anchor();
            (T_IN, KIND_OPERATE, _, 0) : arm_operate_anchor();
        }
        default_action = read_operate_anchor(); size = 2;
    }
'''
    text = replace(text, '    // ---- ladder dispatch: held originals',
                   op_access + '    // ---- ladder dispatch: held originals')
    text = replace(text, '''            if (hdr.tev.kind == KIND_OPERATE && md.enabled != 0 && md.e_bad == 0) {
                md.op_gen = op_gen_bump.execute(0);
                op_t0_arm.execute(0);
            } else if ((hdr.tev.kind == KIND_RESET || hdr.tev.kind == KIND_OPEN) && md.e_bad == 0) { reset_bump_op_gen(); }
''', '')
    text = text.replace('            md.op_gen = op_gen_peek.execute(0);\n', '')
    text = replace(text, '            md.op_t0_v = op_t0_read.execute(0);\n', '')
    text = replace(text, '        t0_access.apply();',
                   '        operate_generation_access.apply(); operate_anchor_access.apply();\n'
                   '        t0_access.apply();')
    # The two existing ACK commit banks each use one role-qualified access
    # table. Only a newly committed, current ACK writes; response roles read.
    commit_access = '''    table commit_at_access {
        key = { hdr.ladder.role : ternary; md.done_diff : ternary; md.commit_ok : ternary; }
        actions = { mark_ack_commit_at; read_gap_delta; NoAction; }
        const entries = {
            (ROLE_ACK_HELD, 0, _) : NoAction();
            (ROLE_ACK_HELD, _, 1) : mark_ack_commit_at();
            (ROLE_RESP_HELD, _, _) : read_gap_delta();
            (ROLE_RESP_BLK, _, _) : read_gap_delta();
        }
        default_action = NoAction(); size = 4;
    }
    table commit_generation_access {
        key = { hdr.ladder.role : ternary; md.done_diff : ternary; md.commit_ok : ternary; }
        actions = { mark_ack_commit_gen; read_commit_gen; NoAction; }
        const entries = {
            (ROLE_ACK_HELD, 0, _) : NoAction();
            (ROLE_ACK_HELD, _, 1) : mark_ack_commit_gen();
            (ROLE_RESP_HELD, _, _) : read_commit_gen();
            (ROLE_RESP_BLK, _, _) : read_commit_gen();
        }
        default_action = NoAction(); size = 4;
    }
'''
    text = replace(text, '    action rewait_ack() {', commit_access + '    action rewait_ack() {')
    text = replace(text, '''                if (md.done_diff != 0 && md.commit_ok == 1) { mark_ack_commit_at(); mark_ack_commit_gen(); }
''', '')
    text = replace(text, '''            else if (hdr.ladder.role == ROLE_RESP_HELD) {
                read_gap_delta(); read_commit_gen();
                resp_go_check.apply();
                try_resp_done();
            } else if (hdr.ladder.role == ROLE_RESP_BLK) { read_gap_delta(); read_commit_gen(); read_resp_done(); }
''', '''            commit_at_access.apply(); commit_generation_access.apply();
            if (hdr.ladder.role == ROLE_RESP_HELD) {
                resp_go_check.apply();
                try_resp_done();
            } else if (hdr.ladder.role == ROLE_RESP_BLK) { read_resp_done(); }
''')
    # Clock-derived offsets do not depend on lifecycle state. Prepare them
    # alongside qualification so the later ACK/response chain saves one stage.
    text = replace(text, '        params.apply(); clock.apply();',
                   '        params.apply(); clock.apply(); held_offsets(); op_offset();')
    text = replace(text, '            held_offsets();\n', '')
    text = replace(text, '            op_offset(); compute_op_t0_masked();',
                   '            compute_op_t0_masked();')
    # Held original's unused budget is a full epoch. The blocker retains budget.
    text = text.replace('hdr.ladder.generation = (bit<16>)md.cur_gen; hdr.ladder.budget = 0;',
                        'hdr.ladder.generation = (bit<16>)md.cur_gen; hdr.ladder.budget = md.packet_epoch;')
    text = replace(text, 'hdr.ladder.generation = (bit<16>)hdr.clone.tag; hdr.ladder.budget = 0;',
                   'hdr.ladder.generation = (bit<16>)hdr.clone.tag; hdr.ladder.budget = md.packet_epoch;')
    # Gate completion flags inside their existing tables, preventing old held
    # originals from modifying new-generation commits before terminal drop.
    for name in ('ack_go_check', 'resp_go_check', 'op_go_check'):
        start = text.index('    table ' + name + ' {')
        end = text.index('\n    }', start) + 6
        block = text[start:end]
        block = block.replace('key = {', 'key = { md.e_bad : ternary;', 1)
        block = re.sub(r'^(\s*)\((.*)\) :', r'\1(0, \2) :', block, flags=re.M)
        text = text[:start] + block + text[end:]
    text = replace(text, '    action drop_tin() { ig_dprsr_md.drop_ctl = 1; }',
                   '    action drop_tin() { ig_dprsr_md.drop_ctl = 1; }\n'
                   '    action drop_old_epoch() { ig_dprsr_md.drop_ctl = 1; count(OUT_OLD_EPOCH_DROP); }')
    text = replace(text, 'const bit<32> OUT_TOKEN_OFF = 12; const bit<32> OUT_REQ_BYPASS = 13;',
                   'const bit<32> OUT_TOKEN_OFF = 12; const bit<32> OUT_REQ_BYPASS = 13;\n'
                   'const bit<32> OUT_OLD_EPOCH_DROP = 14; const bit<32> OUT_GEN_EXHAUSTED = 15;')
    text = replace(text, '13 : bump(13);', '13 : bump(13); 14 : bump(14); 15 : bump(15);')
    text = replace(text, '    action unmatched() {',
                   '    action drop_exhausted() { ig_dprsr_md.drop_ctl = 1; count(OUT_GEN_EXHAUSTED); }\n    action unmatched() {')
    # Existing verdict tables keep the baseline's current-owner OFF behavior.
    for name, count, first in (('held_verdict', 30, None), ('hb_verdict', 11, None)):
        start = text.index('    table ' + name + ' {')
        end = text.index('\n    }', start) + 6
        block = text[start:end]
        block = block.replace('key = {', 'key = { md.e_bad : ternary;', 1)
        block = block.replace('unmatched; }', 'unmatched; drop_old_epoch; }')
        block = re.sub(r'^(\s*)\((.*)\) :', r'\1(0, \2) :', block, flags=re.M)
        nkeys = 13 if name == 'held_verdict' else 7
        row = '(' + ', '.join(['_', *(['_'] * (nkeys - 1))]) + ') : drop_old_epoch();'
        block = block.replace('        }\n        default_action', '            ' + row + '\n        }\n        default_action')
        block = block.replace('size = %d;' % count, 'size = %d;' % (count + 1))
        text = text[:start] + block + text[end:]
    start = text.index('    table tin_verdict {')
    end = text.index('\n    table token_verdict', start)
    block = text[start:end]
    block = block.replace('unmatched; }', 'unmatched; drop_old_epoch; drop_exhausted; }')
    block = block.replace('hdr.tev.stage : ternary;',
                          'hdr.tev.stage : ternary; md.new_gen : ternary; md.op_gen : ternary;')
    block = re.sub(r'^(\s*)\((.*)\) :', r'\1(\2, _, _) :', block, flags=re.M)
    opening = '''            (KIND_OPEN, _, _, 0, _, _, _, _, _) : passthrough_tev_relay();
            (KIND_RESET, _, _, 32w2, _, _, 1, _, _) : passthrough_tev_relay();
            (KIND_RESET, _, _, 32w2, _, _, 2, _, _) : passthrough_tev_forward();
            (KIND_REQUEST, _, _, _, _, _, _, 32w0xffff, _) : drop_exhausted();
            (KIND_OPERATE, _, _, _, _, _, _, _, 32w0xffff) : drop_exhausted();
'''
    block = block.replace('        const entries = {\n', '        const entries = {\n' + opening)
    # Give every live verdict exact epoch validity. The duplicate CLOSE rows
    # above are the sole closed-epoch forwarding exception.
    block = re.sub(r'(\(KIND_\w+,\s*[^,]+,\s*[^,]+),\s*_(,)', r'\1, 0\2', block)
    block = block.replace('(_, 0, _, _, _, _, _, _, _)', '(_, 0, _, 0, _, _, _, _, _)')
    block = block.replace('default_action = unmatched(); size = 15;', 'default_action = drop_old_epoch(); size = 20;')
    text = text[:start] + block + text[end:]
    # Tokens have no epoch; nonaliasing generations plus sealed lifetime fence
    # are authoritative. A token never unseals or reinitializes a connection.
    start = text.index('    table token_verdict {')
    end = text.index('\n    table held_verdict', start)
    block = text[start:end].replace('key = {', 'key = { md.e_bad : ternary;', 1)
    block = block.replace('md.rd_tok_diff : ternary;', 'md.rd_tok_diff : ternary; hdr.timer.batch_id : ternary;')
    block = re.sub(r'^(\s*)\((.*)\) :', r'\1(0, \2) :', block, flags=re.M)
    block = re.sub(r'^(\s*)\((.*)\) :', r'\1(\2, _) :', block, flags=re.M)
    block = block.replace('const entries = {', 'const entries = {\n            (_, _, _, _, _, 16w0xffff) : drop_timer_stale();')
    block = block.replace('size = 5;', 'size = 6;')
    text = text[:start] + block + text[end:]
    # Final departures cross pipe 0's E. Preserve a fully initialized private
    # envelope until E strips it; held originals carry the epoch in budget.
    for action in ('admit_request', 'bypass_request', 'passthrough_tev_forward', 'passthrough_tev_relay'):
        start = text.index('    action ' + action + '(')
        end = text.index('}', start)
        block = text[start:end].replace('hdr.tev.setInvalid();', '')
        text = text[:start] + block + text[end:]
    export = '''    action export_held() {
        hdr.tev.setValid(); hdr.tev.epoch = hdr.ladder.budget;
        hdr.tev.wgen = 0; hdr.tev.t0q = 0; hdr.tev.kind = 8w0xe3;
        hdr.tev.stage = 0; hdr.tev.reserved = 0; hdr.ladder.setInvalid();
    }
'''
    text = replace(text, '    action release_ack() {', export + '    action release_ack() {')
    for action in ('release_ack', 'release_response', 'release_operate', 'flush_ack_stale', 'flush_ack_off',
                   'flush_response_stale', 'flush_response_off', 'flush_operate_stale', 'flush_operate_off'):
        start = text.index('    action ' + action + '(')
        end = text.index('}', start)
        block = text[start:end].replace('hdr.ladder.setInvalid();', 'export_held();')
        text = text[:start] + block + text[end:]
    # Timers and held records have no tev header. Their event discriminator is
    # explicitly initialized parser metadata, so arbitrary invalid-header bits
    # cannot select OPEN/CLOSE/OPERATE handling or reject a valid timer.
    start = text.index('control Ingress(')
    body = re.sub(r'hdr\.tev\.kind\b(?!\s*=(?!=))', 'md.event_kind', text[start:])
    text = text[:start] + body
    return '/* Generated isolated T reconnect candidate. */\n' + text

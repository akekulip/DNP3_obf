"""E uses a private provenance envelope and read-only normalization.

Only N-qualified terminal envelopes commit wire ACK accounting. A new epoch
arrives via T on the original SYN before E can arm its FIRST_SYNACK mapping.
"""
import re
from baseline import e
from transforms import narrow_metadata


def replace(text, old, new):
    assert text.count(old) == 1, old[:100]
    return text.replace(old, new)


LIFECYCLE = '''    Register<bit<32>, slot_t>(16, 0) epoch;
    RegisterAction<bit<32>, slot_t, bit<32>>(epoch) epoch_normalize = {
        void apply(inout bit<32> v, out bit<32> rv) { rv = v & 32w0x7fffffff; }
    };
    RegisterAction<bit<32>, slot_t, bit<32>>(epoch) epoch_check = {
        void apply(inout bit<32> v, out bit<32> rv) { rv = v ^ hdr.prov.epoch; }
    };
    RegisterAction<bit<32>, slot_t, bit<32>>(epoch) epoch_open = {
        void apply(inout bit<32> v, out bit<32> rv) {
            // Bounded incoming epochs have MSB zero. The unsigned comparison
            // handles unlatched v; the signed, MSB-set input handles latched v.
            // The irrelevant comparison is false in each case, using two CUs.
            if (hdr.prov.epoch > v || (int<32>)m.open_bound > (int<32>)v) { v = hdr.prov.epoch; rv = 0; }
            else { rv = 1; }
        }
    };
    RegisterAction<bit<32>, slot_t, bit<32>>(epoch) epoch_first = {
        void apply(inout bit<32> v, out bit<32> rv) {
            rv = v ^ hdr.prov.epoch;
            if (v == hdr.prov.epoch && v != 0) { v = v | 32w0x80000000; }
        }
    };
    action normalize_epoch() { hdr.prov.epoch = epoch_normalize.execute(m.idx); m.life_bad = 0; m.normalize = 1; }
    Hash<bit<32>>(HashAlgorithm_t.IDENTITY) original_wire_ack;
    action capture_normalization_ack() { hdr.prov.wgen = original_wire_ack.get({hdr.tcp.ack}); }
    table normalization_ack_t {
        key = { hdr.prov.kind : exact; }
        actions = { capture_normalization_ack; NoAction; }
        const entries = { 8w0xe0 : capture_normalization_ack(); }
        default_action = NoAction(); size = 1;
    }
    action check_epoch() { m.life_bad = epoch_check.execute(m.idx); }
    action open_epoch() { m.life_bad = epoch_open.execute(m.idx); }
    action first_epoch() { m.life_bad = epoch_first.execute(m.idx); m.first_synack = 1; }
    action reject_lifetime() { m.life_bad = 1; }
    Hash<bit<32>>(HashAlgorithm_t.IDENTITY) open_epoch_bound;
    action prepare_open() { m.open_bound = open_epoch_bound.get({1w1, hdr.prov.epoch[30:0]}); }
    table prepare_open_t {
        key = { hdr.prov.kind : exact; }
        actions = { prepare_open; NoAction; }
        const entries = { 8w14 : prepare_open(); }
        default_action = NoAction(); size = 1;
    }
    table lifecycle_access {
        key = { hdr.tcp.isValid() : exact; m.dir : ternary; hdr.prov.kind : ternary; hdr.prov.epoch : ternary; }
        actions = { normalize_epoch; check_epoch; open_epoch; first_epoch; reject_lifetime; NoAction; }
        const entries = {
            (false, _, _, _) : NoAction(); (true, 0, _, _) : NoAction();
            (true, _, _, 32w0x80000000 &&& 32w0x80000000) : reject_lifetime();
            (true, _, _, 32w0x7fffffff) : reject_lifetime();
            (true, _, 8w0xe7, 0) : reject_lifetime();
            (true, _, 8w0xe0, _) : normalize_epoch(); (true, _, 8w14, _) : open_epoch();
            (true, _, 8w0xe3, _) : check_epoch(); (true, _, 8w0xe4, _) : check_epoch();
            (true, _, 8w0xe5, _) : check_epoch(); (true, _, 8w0xe7, _) : first_epoch();
            (true, _, 8w9, _) : check_epoch(); (true, _, 8w10, _) : check_epoch();
            (true, _, 8w11, _) : check_epoch(); (true, _, 8w12, _) : check_epoch(); (true, _, 8w13, _) : check_epoch();
            (true, _, _, _) : reject_lifetime();
        }
        default_action = NoAction(); size = 17;
    }
    Register<bit<32>, slot_t>(16, 0) master_isn;
    RegisterAction<bit<32>, slot_t, bit<32>>(master_isn) isn_open = {
        void apply(inout bit<32> v, out bit<32> rv) { v = hdr.tcp.seq; rv = v; }
    };
    RegisterAction<bit<32>, slot_t, bit<32>>(master_isn) isn_read = {
        void apply(inout bit<32> v, out bit<32> rv) { rv = v ^ hdr.tcp.seq; }
    };
    action open_isn() { isn_open.execute(m.idx); }
    action check_isn() { m.life_bad = isn_read.execute(m.idx); }
    table isn_access {
        key = { hdr.prov.kind : exact; m.life_bad : exact; }
        actions = { open_isn; check_isn; NoAction; }
        const entries = { (14, 0) : open_isn(); (8w0xe0, 0) : check_isn(); }
        default_action = NoAction(); size = 2;
    }
    action normalization_stamp(bit<32> same) {
        hdr.prov.aux = same;
    }
    table normalization_result {
        key = { m.life_bad : exact; }
        actions = { normalization_stamp; }
        const entries = { 32w0 : normalization_stamp(32w1); }
        default_action = normalization_stamp(32w0); size = 1;
    }
    action commit_return() { hdr.prov.kind = 8w0xe6; }
    action unbound_normalization() { hdr.prov.epoch = 0; hdr.prov.aux = 0; hdr.prov.kind = 8w0xe1; }
    action normalization_return() { hdr.prov.kind = 8w0xe1; }
    action strip_provenance() { hdr.prov.setInvalid(); }
    action drop_lifetime() { md.drop_ctl = 3w1; }
    table envelope_result {
        key = { hdr.prov.kind : exact; }
        actions = { commit_return; strip_provenance; normalization_return; NoAction; }
        const entries = { 8w0xe0 : normalization_return(); 8w0xe1 : NoAction(); 8w0xe5 : commit_return(); }
        default_action = strip_provenance(); size = 3;
    }
'''


def generate():
    text = e.generate()
    text = replace(text, 'header eth_h {',
                   'header provenance_h { bit<32> epoch; bit<32> wgen; bit<32> aux; bit<8> kind; bit<8> stage; bit<16> reserved; }\nheader eth_h {')
    text = replace(text, 'struct headers_t { eth_h eth;', 'struct headers_t { provenance_h prov; eth_h eth;')
    text = replace(text, 'struct meta_t {',
                   'struct meta_t { bit<32> life_bad; bit<32> open_bound; bit<1> normalize; bit<1> first_synack;')
    text = replace(text, 'm.dir = 0;', 'm.normalize = 0; m.first_synack = 0; m.dir = 0;')
    text = replace(text, '9w9: eth; 9w70: eth; default: accept;',
                   '9w9: provenance; 9w70: provenance; 9w64: provenance; default: accept;')
    text = replace(text, '    state eth {',
                   '    state provenance { pkt.extract(hdr.prov); transition select(hdr.prov.reserved) { 16w0: eth; default: reject; } }\n    state eth {')
    text = replace(text, '    /* ============ mapper registers ============ */',
                   LIFECYCLE + '\n    /* ============ mapper registers ============ */')
    text = replace(text, 'mode_arm_map = { void apply(inout bit<8> v) { v = 1; } };',
                   'mode_arm_map = { void apply(inout bit<8> v, out bit<8> rv) { rv = v; if (v == 2) { v = 1; } } };')
    text = replace(text, 'v = 0; } };\n    RegisterAction<bit<8>, slot_t, bit<8>>(mode) mode_read',
                   'v = 2; } };\n    RegisterAction<bit<8>, slot_t, bit<8>>(mode) mode_read')
    text = replace(text, 'action do_mode_arm_map() { mode_arm_map.execute(m.idx); }',
                   'action do_mode_arm_map() { m.mode = mode_arm_map.execute(m.idx); }')
    start = text.index('    table mode_t {')
    end = text.index('\n\n    Register<bit<32>, slot_t>(16, 0) front;', start)
    text = text[:start] + '''    table mode_t {
        key = { hdr.prov.kind : ternary; }
        actions = { do_mode_arm_map; do_mode_arm_nat; do_mode_read; NoAction; }
        const entries = { 8w14 : do_mode_arm_nat(); 8w0xe7 : do_mode_arm_map(); _ : do_mode_read(); }
        default_action = NoAction(); size = 3;
    }
''' + text[end:]
    # The epoch bank atomically latches FIRST before any image write. Mode can
    # run beside front rather than ordering every mapper bank behind its read.
    for name in ('front_t', 'acct_t', 'img_end_t', 'img_start_t', 'img_wend_t'):
        start = text.index('    table ' + name + ' {')
        end = text.index('\n    }', start) + 6
        block = text[start:end]
        block = block.replace('key = {', 'key = { hdr.prov.kind : ternary;', 1)
        block = re.sub(r'\(([^()]*)\)\s*:',
                       lambda m: '(' + ('8w0xe7, ' if m[1].strip().startswith('1, SH_SYNACK_OK') else '_, ')
                       + m[1] + ') :', block)
        if name == 'acct_t':
            # Readonly normalization does NOT call acct_rev. Every commit
            # receives N's immutable original padded ACK rather than native ACK.
            block = block.replace('(_, 2, SH_ACK,', '(8w0xe4, 2, SH_ACK,', 1)
            row = re.search(r'\(8w0xe4,[^()]*\)\s*: do_acct_rev\(\);', block)[0]
            block = block.replace(row, row + '\n            ' + row.replace('8w0xe4', '8w0xe5')
                                  + '\n            ' + row.replace('8w0xe4', '8w13'))
            block = block.replace('size = 8;', 'size = 10;')
        if name.startswith('img_'):
            block = block.replace('hdr.prov.kind : ternary;', 'm.first_synack : ternary;')
            block = block.replace('8w0xe7,', '1w1,')
        text = text[:start] + block + text[end:]
    # acct's SALU has two PHV inputs across all of its actions: ina and leff.
    # Prepare immutable wire ACK in ina in a preceding MAU table, avoiding a
    # third input and avoiding writes to an input inside the SALU's action.
    text = replace(text, '    action do_acct_arm()',
                   '    Hash<bit<32>>(HashAlgorithm_t.IDENTITY) wire_ack_input;\n'
                   '    action qualified_wire_ack() { m.ina = wire_ack_input.get({hdr.prov.wgen});'
                   ' m.qx = hdr.tcp.ack; m.ack_inv = ~hdr.tcp.ack; }\n'
                   '    table qualified_wire_ack_t { key = { hdr.prov.kind : exact; }'
                   'actions = { qualified_wire_ack; NoAction; }'
                   'const entries = { 8w0xe4 : qualified_wire_ack(); 8w0xe5 : qualified_wire_ack(); 8w13 : qualified_wire_ack(); }'
                   'default_action = NoAction(); size = 3; }\n    action do_acct_arm()')
    # The atomic epoch latch precedes all arm writes. Ordinary duplicate
    # SYNACK uses no arm rows; duplicate FIRST fails the exact unlatched epoch.
    start = text.index('        /* mapper state */')
    end = text.index('        count_t.apply();', start)
    block = text[start:end]
    block = block.replace('        mode_t.apply();', '        qualified_wire_ack_t.apply();')
    block = block.replace('        img_start_t.apply();',
                          '        img_start_t.apply();\n        envelope_result.apply();')
    block = block.replace('else if (m.dir == 2 && m.shape == SH_ACK && m.mode == 1)',
                          'else if (m.dir == 2 && m.shape == SH_ACK && m.mode == 1 && m.normalize == 1)')
    # Qualified ACK commits only touch acct. Normalization reads mode/image
    # banks, while server wire departures execute the original mapper chain.
    wrapped = '''        if (m.dir != 0 && hdr.tcp.isValid()) {
            lifecycle_access.apply();
            if (m.life_bad == 0 || (hdr.prov.kind != 8w0xe7 && m.life_bad == 32w0x80000000)) {
                isn_access.apply();
                if (m.normalize == 1) { normalization_result.apply(); }
                mode_t.apply();
''' + block + '''
            } else { drop_lifetime(); }
        } else {
            if (m.dir != 0) { drop_lifetime(); }
            else if (hdr.prov.kind == 8w0xe0) { unbound_normalization(); }
            else { strip_provenance(); }
        }
'''
    # ACK/accounting-only envelopes must never reverse-map twice. Reading the
    # reverse image banks is harmless, but bypass their classifier/deparser
    # checksum update. Baseline forward arithmetic and padding are unchanged.
    text = text[:start] + wrapped + text[end:]
    # conn is stateless, and every lifecycle access is still qualified by a
    # valid TCP header. Its early lookup removes an avoidable gateway stage.
    text = replace(text, 'if (hdr.tcp.isValid()) { conn.apply();',
                   'conn.apply();\n        if (hdr.tcp.isValid()) { normalization_ack_t.apply();')
    text = replace(text, 'leff_t.apply(); prep_t.apply();',
                   'leff_t.apply(); prepare_open_t.apply(); prep_t.apply();')
    # Immutable ACK selection is packet-only preparation, so perform it in
    # the existing prep lookup. The epoch check still gates acct's write.
    start = text.index('    Hash<bit<32>>(HashAlgorithm_t.IDENTITY) wire_ack_input;')
    end = text.index('    action do_acct_arm()', start)
    ack_prepare = text[start:end]
    action_end = ack_prepare.index('    table qualified_wire_ack_t')
    ack_action = ack_prepare[:action_end]
    text = text[:start] + text[end:]
    text = replace(text, '    action prep_syn()', ack_action + '    action prep_syn()')
    start = text.index('    table prep_t {')
    end = text.index('\n    }', start) + 6
    block = text[start:end]
    block = block.replace('key = {', 'key = { hdr.prov.kind : ternary;', 1)
    block = block.replace('actions = {', 'actions = { qualified_wire_ack;', 1)
    block = block.replace('size = 2;', 'size = 5;')
    block = block.replace('const entries = { 8w0x02',
                          'const entries = { (8w0xe4, _) : qualified_wire_ack();'
                          '(8w0xe5, _) : qualified_wire_ack();(8w13, _) : qualified_wire_ack();'
                          '(_, 8w0x02')
    block = block.replace('&&& 8w0x02 : prep_syn();', '&&& 8w0x02) : prep_syn();')
    text = text[:start] + block + text[end:]
    text = replace(text, '        qualified_wire_ack_t.apply();\n', '')
    # Packet-only preparation need not wait for the invalid-TCP branch or
    # native-CRC verdict gateways. No register action runs without valid TCP
    # and the lifecycle verdict; malformed odd-IP handling remains fail-closed.
    text = replace(text, '''        if (hdr.tcp.isValid()) { normalization_ack_t.apply(); leff_t.apply(); prepare_open_t.apply(); prep_t.apply(); }
        else if (m.ip_odd == 1) { odd_ip_t.apply(); }
''', '''        normalization_ack_t.apply(); prepare_open_t.apply(); leff_t.apply(); prep_t.apply();
''')
    text = replace(text, '            if (m.dir != 0) { drop_lifetime(); }',
                   '            if (m.ip_odd == 1) { odd_ip_t.apply(); drop_lifetime(); }\n'
                   '            else if (m.dir != 0) { drop_lifetime(); }')
    start = text.index('        /* padder native-CRC verdict */')
    end = text.index('        if (m.dir != 0 && hdr.tcp.isValid())', start)
    crc_verdict = text[start:end]
    assert '.execute(' not in crc_verdict
    text = text[:start] + text[end:]
    text = replace(text, '        acct_t.apply();', crc_verdict + '        acct_t.apply();')
    # These packet-only preparations have no input used by the epoch bank.
    # Placing them before lifecycle creates next-table anti dependencies from
    # every hash/profile branch to that bank. Run them after the valid-TCP,
    # connected lifecycle access, outside its result gateway so that its output
    # does not extend every packet-preparation lifetime. Mapper writes still
    # require the same lifetime verdict, and CRC verdicts still precede acct.
    text = replace(text, '        normalization_ack_t.apply(); prepare_open_t.apply(); leff_t.apply(); prep_t.apply();',
                   '        normalization_ack_t.apply(); prepare_open_t.apply();')
    start = text.index('        if (hdr.dl.isValid()) { in_dl_t.apply(); }')
    end = text.index('        if (m.dir != 0 && hdr.tcp.isValid())', start)
    packet_prepare = text[start:end]
    assert '.execute(' not in packet_prepare
    text = text[:start] + text[end:]
    text = replace(text, '''        if (m.dir != 0 && hdr.tcp.isValid()) {
            lifecycle_access.apply();
''', '''        lifecycle_access.apply();
        leff_t.apply(); prep_t.apply();
''' + packet_prepare + '''        if (m.dir != 0 && hdr.tcp.isValid()) {
''')
    # These qualified operand stages have a stage-1 dependency minimum. Prefer
    # them ahead of independent CRC calculations in the greedy allocator.
    text = replace(text, '    table lifecycle_access {',
                   '    @placement_priority(100) table lifecycle_access {')
    text = replace(text, '    table prep_t {',
                   '    @placement_priority(90) table prep_t {')
    # The inverse's decision depends on r and the original window, rather
    # than the late derived y/z. The only negative r values retained by the
    # fixed image are -58..-1. Partition each of their window ranges exactly;
    # positive-halfspace translation and default stale rejection are unchanged.
    # Reuse s_end only after img_end has consumed the forward endpoint. The
    # two pure preparations can run beside the forward classifier before the
    # shared img_wend access; the OPEN action adds r once that access returns.
    start = text.index('    action rev_prep()')
    end = text.index('    action rev_translate()', start)
    text = text[:start] + '''    action reverse_gap() { m.s_end = m.q - m.p; }
    table reverse_gap_t { actions = { reverse_gap; } size = 1; const default_action = reverse_gap(); }
    action reverse_window_base() { m.s_end = m.s_end + widen_win.get({hdr.tcp.window}); }
    table reverse_window_base_t { actions = { reverse_window_base; } size = 1; const default_action = reverse_window_base(); }
''' + text[end:]
    text = replace(text, 'action rev_translate() { hdr.tcp.ack = m.pm;',
                   'action rev_translate() { hdr.tcp.ack = m.q + m.r;')
    text = replace(text, 'm.s_end = m.y + m.t;', 'm.s_end = m.s_end + m.r;')
    start = text.index('    table classify_rev {')
    end = text.index('    Hash<bit<16>>(HashAlgorithm_t.IDENTITY) narrow_win;', start)
    rows = ['(32w0 &&& 32w0x80000000, _) : rev_translate();']
    for distance in range(1, 59):
        offset = '32w0x%08x' % ((1 << 32) - distance)
        rows += ['(%s, 16w0 .. 16w%d) : rev_withhold_zero();' % (offset, distance - 1),
                 '(%s, 16w%d .. 16w65535) : rev_withhold_open();' % (offset, distance)]
    text = text[:start] + '''    table classify_rev {
        key = { m.r : ternary; hdr.tcp.window : range; }
        actions = { rev_translate; rev_withhold_zero; rev_withhold_open; rev_drop; }
        size = 118; const default_action = rev_drop();
        const entries = {
            ''' + '\n            '.join(rows) + '''
        }
    }
''' + text[end:]
    reverse = 'm.dir == 2 && m.shape == SH_ACK && m.mode == 1 && m.normalize == 1'
    text = replace(text, '        envelope_result.apply();',
                   '        envelope_result.apply();\n        if (' + reverse + ') {\n'
                   '            reverse_gap_t.apply(); reverse_window_base_t.apply();\n        }')
    text = replace(text, '            rev_prep_t.apply(); classify_rev.apply();',
                   '            classify_rev.apply();')
    # E captures the untouched wire ACK on N's private normalization opcode,
    # before reverse translation. All qualified N returns preserve that value.
    text = replace(text, '        pkt.emit(hdr.eth);', '        pkt.emit(hdr.prov); pkt.emit(hdr.eth);')
    text = narrow_metadata(text, {'ip_odd': 1, 'tcp_odd': 1, 'has_mss': 1, 'grant': 1, 'wide': 1,
                                 'dir': 2, 'enable': 1, 'shape': 3, 'mode': 2}, '\n/* Same reason')
    return '/* Generated isolated E protected reconnect candidate. */\n' + text

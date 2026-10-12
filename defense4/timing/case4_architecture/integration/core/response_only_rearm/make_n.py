"""Derive protected reconnect N from the unchanged response-only generator.

Owner phases 0x101..0x10f encode {master FIN, server FIN, master ACK of
server FIN, server ACK of master FIN}. 0x10f and qualified-RST 0x200
are retired, but reuse still requires the genuine WorkRecord free result.
"""
import re
from baseline import n, INTEG
from transforms import narrow_metadata


def replace(text, old, new):
    assert text.count(old) == 1, old[:100]
    return text.replace(old, new)


def table(text, name, fn):
    start = re.search(r'\btable\s+' + re.escape(name) + r'\s*\{', text).start()
    opening = text.index('{', start)
    depth, end = 1, opening + 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[:start] + fn(text[start:end]) + text[end:]


def resize(block, delta):
    return re.sub(r'size=(\d+);', lambda m: 'size=%d;' % (int(m[1]) + delta), block, count=1)


def generate():
    text = n.generate()
    # Increment as a complete word before constructing the SYN owner. A
    # 16-bit add splits the owner/timestamp overlay into three PHV fragments.
    text = replace(text, 'struct meta_t{', 'struct meta_t{bit<32> next_owner_gen;')
    text = replace(text, 'action next_seq(){m.new_seq=hdr.tcp.seq+32w1;}',
                   'action next_seq(){m.new_seq=hdr.tcp.seq+32w1;m.next_owner_gen=hdr.expected_cell.expected_cell+32w1;}')
    text = replace(text, 'if((int<32>)v!=-1){v=v+32w1;r=v;}',
                   'if(v<32w0x7ffffffe){v=v+32w1;r=v;}')
    text = replace(text,
                   'm.desired=hdr.expected_cell.expected_cell+32w0x10001;',
                   'm.desired=16w1++m.next_owner_gen[15:0];')
    # Exact pending SYN retries, with a separate fresh-SYN verdict. A changed
    # SYN is never accepted as a retry of the current owner.
    text = replace(text, 'action diff_syn(){m.client_diff=hdr.tcp.ack;m.server_diff=32w0;}',
                   'action diff_syn(){m.client_diff=hdr.tcp.ack;m.server_diff=m.new_seq-m.client;}')
    text = replace(text, 'action diff_synack(){m.client_diff=hdr.tcp.ack-m.client;m.server_diff=32w0;}',
                   'action diff_synack(){m.client_diff=hdr.tcp.ack-m.client;m.server_diff=m.new_seq-m.server;}')
    text = replace(text, 'action seq_ok(){m.sequence_valid=8w1;}',
                   'action seq_ok(){m.sequence_valid=8w1;}\n action seq_fresh(){m.sequence_valid=8w6;}'
                   '\n action seq_forward_fresh(){m.sequence_valid=8w7;}')
    # Default (ACK 0, changed ISN) only means fresh SYN/SYNACK; first_event's
    # packet kind/owner gates give it no authority for normal data or closes.
    text = replace(text, 'actions={seq_ok;seq_resent;seq_replay;seq_fin;NoAction;}size=6;',
                   'actions={seq_ok;seq_fresh;seq_forward_fresh;seq_resent;seq_replay;seq_fin;NoAction;}size=8;')
    text = replace(text, '(32w0xffffffff,32w0):seq_replay();}const default_action=NoAction();',
                   '(32w0xffffffff,32w0):seq_replay();'
                   '(32w0,32w0&&&32w0x80000000):seq_forward_fresh();}const default_action=seq_fresh();')
    text = replace(text, 'key={m.client_diff:exact;m.server_diff:exact;}',
                   'key={m.client_diff:exact;m.server_diff:ternary;}')
    # Exact delta zero/one rows precede the forward-halfspace row. Thus the
    # latter accepts exactly 2..0x7fffffff without a forbidden 32-bit range key.
    # First SYN is accepted with any new ISN and every supported first SYNACK
    # must acknowledge the current client's SYN. Pending repeats require exact
    # server ISN too. Exact SYNACK retries remain qualified while the current
    # frontier still identifies the handshake, including a lost final ACK.
    text = replace(text, '(8w1,8w1,8w0,32w0):first_syn();',
                   '(8w1,_,8w0,32w0):first_syn();')
    text = replace(text, '(8w2,8w1,8w0,32w0x20000&&&32w0xffff0000):first_synack();',
                   '(8w2,_,8w0,32w0x20001):first_synack();'
                   '(8w2,8w7,8w0,32w0x20000&&&32w0xffff0000):first_synack();')
    # Owner command has one stateful CAS call. Add closing rows to that same
    # table, avoiding a second owner access in a later stage.
    text = replace(text, ' action close_pending(){',
                   ' action close_owner(bit<16> phase){m.expected=hdr.expected_cell.expected_cell;'
                   'm.desired=phase++hdr.expected_cell.expected_cell[15:0];m.owner_op=8w1;}\n action close_pending(){')
    def commands(block):
        block = block.replace('m.work_phase:exact;', 'm.work_phase:ternary;')
        block = block.replace('m.return_abort:ternary;',
                              'm.return_abort:ternary;m.direction:ternary;hdr.tcp.flags:ternary;'
                              'm.server_diff:ternary;hdr.expected_cell.expected_cell[31:16]:ternary;')
        block = block.replace('actions={', 'actions={close_owner;', 1)
        block = re.sub(r'\(([^()]*)\):', lambda m: '(' + m[1] + ',_,_,_,_):', block)
        block = re.sub(r'\([^()]*\):close_(?:free|pending)\(\);', '', block)
        rows = []
        for flags in range(16):
            phase = 0x100 | flags
            for direction, finbit, ackbit, peerfin in ((1, 1, 4, 2), (2, 2, 8, 1)):
                for ack_delta in (0, 1):
                    if ack_delta and not (flags & peerfin):
                        continue
                    after = flags | finbit | (ackbit if ack_delta else 0)
                    rows.append('(8w1,8w4,_,32w0,_,8w%d,8w17,32w%d,16w%d):close_owner(16w%d);'
                                % (direction, ack_delta, phase, 0x100 | after))
                    after = flags | (ackbit if ack_delta else 0)
                    rows.append('(8w1,8w17,32w1,32w0,_,8w%d,8w16,32w%d,16w%d):close_owner(16w%d);'
                                % (direction, ack_delta, phase, 0x100 | after))
        # A first FIN has no preceding owner flags. A qualified reset is fully
        # retired independently of bilateral FIN observation.
        for direction in (1, 2):
            rows.append('(8w1,8w4,_,32w0,_,8w%d,8w17,32w0,_):close_owner(16w%d);'
                        % (direction, 0x100 | direction))
        for tcpflags in (4, 20):
            rows.append('(8w1,8w4,_,32w0,_,_,8w%d,_,_):close_owner(16w0x200);' % tcpflags)
        block = block.replace('const entries={', 'const entries={' + ''.join(rows), 1)
        return resize(block, len(rows) - 4)
    text = table(text, 'owner_command', commands)
    # Closing pure ACK goes through the ordinary WorkRecord four passes. It
    # cannot publish sequence banks, and updates owner flags only on pass one.
    text = replace(text, ' action first_close(){',
                   ' action first_close_ack(){hdr.event.event=16w0x0111;}\n action first_close(){')
    text = replace(text, '16w0x0310:eth;',
                   '16w0x0310:eth;16w0x0111:eth;16w0x0211:eth;16w0x0311:eth;')
    text = replace(text, '(8w1,8w12,8w16,false,',
                   '(8w1,8w17,8w16,false,16w0xffeb,8w1..8w255,4w0,16w0):network_accept();'
                   '(8w1,8w12,8w16,false,')
    text = replace(text, '(_,8w3,8w8,_,_,_,_,_,_,_,_,_):go_ret_work();',
                   '(_,8w3,8w8,_,_,_,_,_,_,_,_,_):go_ret_work();'
                   '(_,8w3,8w17,_,_,_,_,_,_,_,_,_):go_ret_work();')
    text = replace(text, 'm.kind==8w8||m.kind==8w10||m.kind==8w12',
                   'm.kind==8w8||m.kind==8w10||m.kind==8w12||(m.kind==8w17&&m.stage==8w2)')
    # On stage one a closing ACK carries its successful CAS owner into stages
    # two/three just like a command; stage two does only an owner check.
    text = replace(text, '(8w3,8w5,8w0,32w0x70000&&&32w0xffff0000):forward_original();', '')
    text = replace(text, '(8w4,_,_,_):close_forward();', '')
    text = replace(text, '(8w10,_,_,_):forward_original();',
                   '(8w10,8w1,_,32w0x50000&&&32w0xffff0000):forward_original();'
                   '(8w10,8w1,_,32w0x90000&&&32w0xffff0000):forward_original();'
                   '(8w10,8w1,_,32w0xa0000&&&32w0xffff0000):forward_original();'
                   '(8w10,8w1,_,32w0xc0000&&&32w0xffff0000):forward_original();')
    def first(block):
        block = block.replace('m.observed:ternary;',
                              'm.observed:ternary;m.client_diff:ternary;m.server_diff:ternary;'
                              'm.direction:ternary;hdr.tcp.flags:ternary;')
        block = block.replace('actions={', 'actions={first_close_ack;', 1)
        block = re.sub(r'\(([^()]*)\):', lambda m: '(' + m[1] + ',_,_,_,_):', block)
        # The owner gen cannot alias, even if epochs still have spare values.
        rows = ['(8w1,_,_,32w0xffff&&&32w0xffff,_,_,_,_):NoAction();']
        for phase in (0x10f, 0x200):
            rows.append('(8w1,8w7,8w0,32w%d&&&32w0xffff0000,32w0,_,_,_):first_syn();'
                        % (phase << 16))
        for flags in range(1, 16):
            for direction, ownfin, peerfin in ((1, 1, 2), (2, 2, 1)):
                for ack in (0, 1):
                    if ack and not (flags & peerfin):
                        continue
                    for seq in (1 if flags & ownfin else 0,):
                        rows.append('(8w%s,_,_,32w%d&&&32w0xffff0000,32w%d,32w%d,8w%d,8w16):first_close_ack();'
                                    % ('3' if direction == 1 else '10', (0x100 | flags) << 16, seq, ack, direction))
                    rows.append('(8w4,_,_,32w%d&&&32w0xffff0000,32w0,32w%d,8w%d,8w17):first_close();'
                                % ((0x100 | flags) << 16, ack, direction))
        block = block.replace('const entries={', 'const entries={' + ''.join(rows), 1)
        return resize(block, len(rows) + 1)
    text = table(text, 'first_event', first)
    def pending_abort(block):
        block = block.replace('hdr.tcp.flags:ternary;', 'hdr.tcp.flags:ternary;m.new_seq:ternary;')
        block = re.sub(r'\(([^()]*)\):', lambda m: '(' + m[1] + ',_):', block)
        row = '(8w4,_,8w0,32w0x20000&&&32w0xffff0000,_,32w0,8w2,8w20,32w1):first_close();'
        block = block.replace('const entries={', 'const entries={' + row, 1)
        return resize(block, 1)
    text = table(text, 'first_event', pending_abort)
    text = replace(text, '((m.work_op==8w1&&m.work_phase==32w4)||(m.kind==8w4&&m.shape_valid==8w1))',
                   '(m.work_phase==32w4&&(m.work_op==8w1||(m.kind==8w4&&m.shape_valid==8w1)))')
    text = replace(text, '}else if(m.work_op==8w1){busy_t.apply();}',
                   '}else if(m.work_op==8w1){busy_t.apply();}else if(m.kind==8w4){deny();}')
    text = provenance('/* Generated isolated N protected reconnect candidate. */\n' + text)
    # Stateless routing and CRC preparation may precede the top-level verdict.
    # The routing lookup runs before ports so an original master packet still
    # takes its mandatory normalization lap. Work and all banks remain behind
    # the unchanged network/profile qualification.
    text = replace(text, '  ports.apply();network.apply();',
                   '  connection.apply();crc_t.apply();ports.apply();network.apply();')
    text = replace(text, '   connection.apply();crc_t.apply();\n', '')
    # The early lookup only prepares direction and destination; ports owns
    # the original/recirculation route until a qualified terminal departure.
    for action in ('forward_flow', 'reverse_flow'):
        start = text.index('action ' + action + '(')
        end = text.index('}', start)
        block = text[start:end].replace('tm.ucast_egress_port=port;', '')
        text = text[:start] + block + text[end:]
    text = replace(text, 'action terminal_strip(){',
                   'action terminal_strip(){tm.ucast_egress_port=m.output_port;')
    # This stateless hash currently drifts into stage 2 despite an empty
    # stage 1, extending every qualified bank chain. Require the free slot.
    text = replace(text, 'table crc_t{', '@stage(1) table crc_t{')
    for crc_table in ('rd_second_crc_t', 'rd_tail_crc_t', 'rd_request_crc_t',
                      'response_crct_t', 'input_tail_t'):
        text = replace(text, 'table ' + crc_table + '{',
                       '@stage(2) table ' + crc_table + '{')
    # Profiles, hash calculations and bad-packet flags are stateless packet
    # preparation. Keep Work and every register bank behind the original
    # network/port/profile verdict, but do not serialize preparation behind it.
    start = text.index('   if(m.packet_kind==8w5||m.packet_kind==8w6||m.packet_kind==8w7){')
    end = text.index('   guard.apply();', start)
    preparation = text[start:end]
    assert '.execute(' not in preparation
    text = text[:start] + text[end:]
    text = replace(text, 'connection.apply();crc_t.apply();ports.apply();network.apply();',
                   'connection.apply();crc_t.apply();\n' + preparation + '  ports.apply();network.apply();')
    # Pass zero has already qualified the exact close frontier. Carry its
    # desired owner phase in origin.normalized_epoch, which close returns never
    # use for a fresh-SYN epoch store. Pass one's full old-owner CAS can then
    # run alongside the sequence-bank reads, without a new sequence dependency.
    text = replace(text, 'action close_owner(bit<16> phase){m.expected=hdr.expected_cell.expected_cell;'
                   'm.desired=phase++hdr.expected_cell.expected_cell[15:0];m.owner_op=8w1;}',
                   'action close_owner(){m.expected=hdr.expected_cell.expected_cell;'
                   'm.desired=hdr.origin.normalized_epoch[15:0]++hdr.expected_cell.expected_cell[15:0];m.owner_op=8w1;}')
    def close_commands(block):
        block = block.replace('m.direction:ternary;hdr.tcp.flags:ternary;'
                              'm.server_diff:ternary;hdr.expected_cell.expected_cell[31:16]:ternary;', '')
        block = re.sub(r'\([^()]*\):close_owner\([^()]*\);', '', block)
        block = re.sub(r'\(([^()]*)\):', lambda m: '(' + ','.join(m[1].split(',')[:-4]) + '):', block)
        block = block.replace('const entries={',
                              'const entries={(8w1,8w4,32w4,32w0,8w0):close_owner();'
                              '(8w1,8w17,32w1,32w0,8w0):close_owner();', 1)
        rows = block[block.index('const entries={'):].count(':')
        return re.sub(r'size=\d+;', 'size=%d;' % rows, block, count=1)
    text = table(text, 'owner_command', close_commands)
    close_rows = ['(8w4,_,_,_):qualify_close(16w0x200);',
                  '(8w20,_,_,_):qualify_close(16w0x200);']
    for flags in range(1, 16):
        for direction, fin, ackbit, peerfin in ((1, 1, 4, 2), (2, 2, 8, 1)):
            for delta in (0, 1):
                if delta and not flags & peerfin:
                    continue
                for tcpflags in (16, 17):
                    after = flags | (fin if tcpflags == 17 else 0) | (ackbit if delta else 0)
                    close_rows.append('(8w%d,8w%d,16w%d,32w%d):qualify_close(16w%d);'
                                      % (tcpflags, direction, 0x100 | flags, delta, 0x100 | after))
    close_rows += ['(8w17,8w1,_,32w0):qualify_close(16w0x101);',
                   '(8w17,8w2,_,32w0):qualify_close(16w0x102);']
    close_table = ('action qualify_close(bit<16> phase){m.desired=(bit<32>)phase;}\n'
                   'table close_phase_t{key={hdr.tcp.flags:ternary;m.direction:ternary;'
                   'm.observed[31:16]:ternary;m.server_diff:ternary;}'
                   'actions={qualify_close;NoAction;}size=%d;const entries={%s}'
                   'const default_action=NoAction();}\n' % (len(close_rows), ''.join(close_rows)))
    text = replace(text, ' action first_close(){', close_table + ' action first_close(){')
    text = replace(text, 'action first_close(){hdr.event.event=16w0x0104;',
                   'action first_close(){hdr.origin.normalized_epoch=m.desired;hdr.event.event=16w0x0104;')
    text = replace(text, 'action first_close_ack(){hdr.event.event=16w0x0111;}',
                   'action first_close_ack(){hdr.origin.normalized_epoch=m.desired;hdr.event.event=16w0x0111;}')
    text = replace(text, 'snapshot_t.apply();first_event.apply();',
                   'if(m.kind==8w4||m.packet_kind==8w3){close_phase_t.apply();}'
                   'snapshot_t.apply();first_event.apply();')
    widths = {name: 1 for name in ('same_syn', 'lap', 'committed', 'response', 'matched',
              'enabled', 'changed', 'badh', 'badb', 'bad1', 'badt', 'return_abort', 'data_valid',
              'go', 'parsed', 'port_valid', 'network_valid', 'shape_valid', 'epoch_valid', 'emit_loop')}
    widths.update(direction=2, stage=2, owner_op=1, sequence_valid=3)
    text = narrow_metadata(text, widths, '\nparser IgParser(')
    text = replace(text, '\ncontrol Ingress(',
                   '\n@pa_container_size("ingress", "m.expected_work_phase", 32)\n'
                   '@pa_solitary("ingress", "m.expected_work_phase")\ncontrol Ingress(')
    # Keep the full Work generation/phase SALU comparisons. Split the sole
    # zero-generation qualification from its dispatch TCAM so a 72-bit key
    # does not couple the two SALU operands to the operation container.
    work = (INTEG / 'connection' / 'binding' / 'work_record.p4').read_text()
    work = replace(work, 'operation : exact; generation : ternary; expected_phase : ternary;',
                   'operation : exact; expected_phase : ternary;')
    work = replace(work, '            (1, 0, _) : unavailable_work();\n', '')
    work = re.sub(r'\((\d+), _, ([^)]*)\) :', r'(\1, \2) :', work)
    work = replace(work, 'size = 10;', 'size = 9;')
    work = replace(work, 'apply { dispatch.apply(); }',
                   'apply { if (operation == 1 && generation == 0) { unavailable_work(); } else { dispatch.apply(); } }')
    return replace(text, '#include "work_record.p4"', work)


def provenance(text):
    """Private 16-byte E envelope; an 8-byte origin only on N work returns.

    The original padded-wire ACK is immutable through N's WorkRecord passes.
    E normalization only reads banks. A qualified N terminal requests accounting
    commit, including a dedicated commit return before a READ/OPERATE enters T.
    """
    text = replace(text, 'header t0_h{',
                   'header ack_origin_h{bit<32> wire_ack;bit<32> normalized_epoch;}\nheader t0_h{')
    text = replace(text, 't0_h t0;eth_h eth;', 't0_h t0;ack_origin_h origin;eth_h eth;')
    text = replace(text, 'struct meta_t{',
                   'struct meta_t{bit<32> wire_ack;bit<32> normalized_epoch;bit<8> same_syn;bit<8> lap;bit<8> committed;')
    text = replace(text, 'm.parsed=8w0;',
                   'm.wire_ack=32w0;m.normalized_epoch=32w0;m.same_syn=8w0;m.lap=8w0;m.committed=8w0;'
                   'm.parsed=8w0;')
    text = replace(text, 'RETURN_PORT:envelope;default:eth;',
                   'RETURN_PORT:envelope;N_ACK_RETURN:normalized;default:native_prefix;')
    states = ''' state normalized{pkt.extract(hdr.envelope);pkt.extract(hdr.work_generation);pkt.extract(hdr.expected_cell);pkt.extract(hdr.event);transition select(hdr.event.event[15:8],hdr.event.reserved){(8w0xe1,16w0):normalized_input;(8w0xe6,16w0):committed_input;default:reject;}}
 state normalized_input{m.wire_ack=hdr.work_generation.generation;m.normalized_epoch=hdr.envelope.epoch;m.same_syn=(bit<8>)hdr.expected_cell.expected_cell;m.lap=8w1;transition eth;}
 state committed_input{m.committed=8w1;transition eth;}
 state origin{pkt.extract(hdr.origin);m.wire_ack=hdr.origin.wire_ack;m.normalized_epoch=hdr.origin.normalized_epoch;transition eth;}
 state native_prefix{hdr.envelope.setValid();hdr.envelope.epoch=32w0;hdr.work_generation.setValid();hdr.work_generation.generation=32w0;hdr.expected_cell.setValid();hdr.expected_cell.expected_cell=32w0;hdr.event.setValid();hdr.event.event=16w0xe200;hdr.event.reserved=16w0;transition eth;}
'''
    text = replace(text, ' state envelope{', states + ' state envelope{')
    # Every supported work event extracts its immutable origin after optional
    # t0; private producer formats remain parser-port bound.
    begin = text.index(' state envelope_event{')
    end = text.index('\n state eth{', begin)
    block = text[begin:end].replace(':eth;', ':origin;')
    text = text[:begin] + block + text[end:]
    text = replace(text, 'state read_t0{pkt.extract(hdr.t0);transition eth;}',
                   'state read_t0{pkt.extract(hdr.t0);transition origin;}')
    text = replace(text, 'action normalize_ack(){tm.ucast_egress_port=N_ACK_RETURN;',
                   'action normalize_ack(){hdr.event.event=16w0xe000;tm.ucast_egress_port=N_ACK_RETURN;')
    # On a normal master return preserve the normalization epoch; stale laps
    # are rejected by the existing stage-one epoch gate before bank writes.
    text = replace(text, ' action snapshot_epoch_zero(){',
                   ' action snapshot_lap(){snapshot();hdr.envelope.epoch=m.normalized_epoch;}\n action snapshot_epoch_zero(){')
    text = replace(text, 'table snapshot_t{key={m.epoch:exact;}actions={snapshot;snapshot_epoch_zero;}size=1;const entries={32w0:snapshot_epoch_zero();}',
                   'table snapshot_t{key={m.lap:ternary;m.epoch:ternary;}actions={snapshot;snapshot_lap;snapshot_epoch_zero;}size=2;'
                   'const entries={(8w1,_):snapshot_lap();(_,32w0):snapshot_epoch_zero();}')
    # Both snapshot variants save the immutable origin. Initialization is
    # always complete even if a header shares PHV with live ingress metadata.
    text = text.replace('hdr.event.reserved=16w0;m.emit_loop=8w1;',
                        'hdr.event.reserved=16w0;hdr.origin.setValid();hdr.origin.wire_ack=m.wire_ack;'
                        'hdr.origin.normalized_epoch=m.normalized_epoch;m.emit_loop=8w1;')
    # A fresh SYN is permitted only from the current normalization generation.
    # Stage-zero can claim diagnostic Work; this conditional stage-one epoch
    # store is the authority and fails closed before client or owner writes.
    text = replace(text, 'v=hdr.envelope.epoch;r=32w0;',
                   'if(v==hdr.origin.normalized_epoch){v=hdr.envelope.epoch;r=32w0;}else{r=32w1;}')
    def first(block):
        block = block.replace('m.new_seq:ternary;', 'm.new_seq:ternary;m.same_syn:ternary;')
        block = re.sub(r'\(([^()]*)\):', lambda m: '(' + m[1] + ',_):', block)
        # SYNACK always ACKs exactly the current client frontier.
        block = re.sub(r'(\(8w2,(?:_|8w7),8w0,32w(?:0x20000&&&32w0xffff0000|0x20001)),_,_,_,_,_',
                       r'\1,32w0,_,_,_,_', block)
        block = block.replace('(8w1,_,8w0,32w0,_,_,_,_,_,_)',
                              '(8w1,_,8w0,32w0,32w0,_,_,_,_,_)')
        rows = ['(8w1,_,_,32w%d&&&32w0xffff0000,_,_,_,_,_,8w1):NoAction();' % (phase << 16)
                for phase in (0x10f, 0x200)]
        block = block.replace('const entries={', 'const entries={' + ''.join(rows), 1)
        return resize(block, 2)
    text = table(text, 'first_event', first)
    text = replace(text, 'action terminal_strip(){hdr.envelope.setInvalid();hdr.work_generation.setInvalid();hdr.expected_cell.setInvalid();hdr.event.setInvalid();}',
                   'action terminal_strip(){hdr.work_generation.generation=hdr.origin.wire_ack;hdr.expected_cell.expected_cell=32w0;'
                   'hdr.event.event=16w0xe300;hdr.origin.setInvalid();}\n'
                   'action terminal_ack(){terminal_strip();hdr.event.event=16w0xe400;}\n'
                   'action terminal_synack(){terminal_strip();hdr.event.event=16w0xe700;}\n'
                   'action terminal_open(){hdr.work_generation.generation=32w0;hdr.expected_cell.expected_cell=32w0;'
                   'hdr.event.event=16w0x0e00;hdr.origin.setInvalid();tm.ucast_egress_port=READ_HANDOFF_PORT;m.emit_loop=8w0;}')
    # Terminal kind plus direction decides qualified accounting. The fresh
    # SYNACK opcode is never emitted for a retransmitted handshake.
    def terminal(block):
        block = block.replace('m.epoch_diff:exact;', 'm.epoch_diff:exact;m.direction:ternary;')
        block = re.sub(r'\(([^()]*)\):', lambda m: '(' + m[1] + ',_):', block)
        block = block.replace('actions={', 'actions={terminal_open;terminal_synack;terminal_ack;', 1)
        rows = ['(8w1,32w0,32w0,_):terminal_open();', '(8w2,32w0,32w0,_):terminal_synack();',
                '(_,32w0,32w0,8w1):terminal_ack();']
        # ACK accounting catchall comes after READ/OP/abort-specific decisions.
        block = block.replace('const entries={', 'const entries={' + ''.join(rows[:2]), 1)
        block = block.replace('(_,32w0,32w0,_):terminal_strip();', rows[2] + '(_,32w0,32w0,_):terminal_strip();')
        return resize(block, 3)
    text = table(text, 'read_terminal_t', terminal)
    text = replace(text, 'action emit_tev(bit<16> event){hdr.expected_cell.expected_cell=hdr.t0.t0q;hdr.event.event=event;hdr.t0.setInvalid();tm.ucast_egress_port=READ_HANDOFF_PORT;m.emit_loop=8w0;}',
                   'action emit_tev(bit<16> event){hdr.expected_cell.expected_cell=hdr.t0.t0q;hdr.event.event=event;'
                   'hdr.work_generation.generation=hdr.origin.wire_ack;hdr.origin.setInvalid();hdr.t0.setInvalid();'
                   'tm.ucast_egress_port=READ_HANDOFF_PORT;m.emit_loop=8w0;}\n'
                   'action commit_before_t(bit<8> kind){hdr.expected_cell.expected_cell=hdr.t0.t0q;'
                   'hdr.event.event=8w0xe5++kind;hdr.work_generation.generation=hdr.origin.wire_ack;'
                   'hdr.origin.setInvalid();hdr.t0.setInvalid();tm.ucast_egress_port=N_ACK_RETURN;m.emit_loop=8w0;}')
    text = replace(text, 'actions={terminal_open;terminal_synack;terminal_ack;emit_tev;',
                   'actions={terminal_open;terminal_synack;terminal_ack;commit_before_t;emit_tev;')
    text = text.replace(':emit_tev(16w0x0900);', ':commit_before_t(8w9);')
    text = text.replace(':emit_tev(16w0x0c00);', ':commit_before_t(8w12);')
    text = replace(text, 'action emit_reset(){hdr.event.event=8w13++m.direction;',
                   'action emit_reset(){hdr.work_generation.generation=hdr.origin.wire_ack;hdr.origin.setInvalid();hdr.event.event=8w13++m.direction;')
    # A qualified E commit return bypasses N Work and cannot dirty authority.
    text = replace(text, ' action deny(){md.drop_ctl=3w1;}',
                   ' action deny(){md.drop_ctl=3w1;}\n'
                   ' action committed_to_t(bit<16> event){hdr.event.event=event;'
                   'tm.ucast_egress_port=READ_HANDOFF_PORT;tm.bypass_egress=1w0;}\n'
                   ' table committed_t{key={hdr.event.event:exact;}actions={committed_to_t;deny;}size=2;'
                   'const entries={16w0xe609:committed_to_t(16w0x0900);16w0xe60c:committed_to_t(16w0x0c00);}'
                   'const default_action=deny();}')
    text = replace(text, '  ports.apply();network.apply();\n  if(m.packet_kind==8w13)',
                   '  ports.apply();network.apply();\n'
                   '  if(m.committed==8w1){committed_t.apply();}\n  else if(m.packet_kind==8w13)')
    return text

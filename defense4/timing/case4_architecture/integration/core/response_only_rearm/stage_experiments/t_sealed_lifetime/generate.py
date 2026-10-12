"""One isolated T lifetime experiment, derived only from immutable checkpoint 55."""
import hashlib
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CANDIDATE = HERE.parent.parent
FROZEN = CANDIDATE / 'evidence' / 'incremental_55' / 'response_only.p4'
FROZEN_SHA = '628af1c66da5b61a7b4062dfae40b3e14320bc5d370d20219d893fef3862b261'
MARKERS = {'N': '/* Generated isolated N protected reconnect candidate. */',
           'E': '/* Generated isolated E protected reconnect candidate. */',
           'T': '/* Generated isolated T reconnect candidate. */'}


def frozen():
    raw = FROZEN.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == FROZEN_SHA
    return raw.decode()


def role(name):
    text = frozen()
    start = text.index(MARKERS[name])
    end = text.index(MARKERS[{'N': 'E', 'E': 'T'}[name]]) if name != 'T' else text.index('\nPipeline(')
    return text[start:end]


def transform(text):
    # Prepare the second comparison operand in the parser, before either
    # lifetime access. No MAU table or additional register input is needed.
    prepare = 'md.packet_epoch = hdr.tev.epoch;'
    assert text.count(prepare) == 2
    text = text.replace(prepare, prepare + '\n        md.epoch_delta = 1w1 ++ hdr.tev.epoch[30:0];')
    start = text.index('    Register<bit<32>, bit<1>>(1, 0) cur_epoch_reg;')
    end = text.index('    Register<bit<32>, bit<1>>(1, 0) gen_alloc_reg;', start)
    lifetime = '''    // bit31 seals the current lifetime; bits30:0 retain its bounded epoch.
    Register<bit<32>, bit<1>>(1, 0) cur_epoch_reg;
    RegisterAction<bit<32>, bit<1>, bit<32>>(cur_epoch_reg) epoch_open = {
        void apply(inout bit<32> value, out bit<32> out_value) {
            // A live epoch is positive; a sealed epoch is negative as int32.
            // Exactly one comparison can accept each encoding. Bounds are
            // rejected by lifetime_access before this action can write.
            if (value < md.packet_epoch || (int<32>)value < (int<32>)md.epoch_delta) {
                value = md.packet_epoch; out_value = 0;
            } else { out_value = 1; }
        }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(cur_epoch_reg) epoch_read = {
        void apply(inout bit<32> value, out bit<32> out_value) { out_value = value; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(cur_epoch_reg) epoch_match = {
        void apply(inout bit<32> value, out bit<32> out_value) { out_value = value ^ md.packet_epoch; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(cur_epoch_reg) epoch_close = {
        void apply(inout bit<32> value, out bit<32> out_value) {
            out_value = value ^ md.packet_epoch;
            if (value == md.packet_epoch && md.packet_epoch != 0) { value = value | 32w0x80000000; }
        }
    };
    action open_epoch() { md.epoch_delta = epoch_open.execute(0); }
    action read_epoch() { md.packet_epoch = epoch_read.execute(0); md.epoch_delta = 0; }
    action match_epoch() { md.epoch_delta = epoch_match.execute(0); }
    action close_epoch() { md.epoch_delta = epoch_close.execute(0); }
    action reject_open() { md.epoch_delta = 1; }
    table lifetime_access {
        key = { ig_intr_md.ingress_port : ternary; md.event_kind : ternary;
                hdr.ladder.role : ternary; md.packet_epoch : ternary; }
        actions = { open_epoch; read_epoch; match_epoch; close_epoch; reject_open; }
        const entries = {
            (t_T_IN, t_KIND_OPEN, _, 0) : reject_open();
            (t_T_IN, t_KIND_OPEN, _, 32w0x7fffffff) : reject_open();
            (t_T_IN, t_KIND_OPEN, _, 32w0x80000000 &&& 32w0x80000000) : reject_open();
            (t_T_IN, t_KIND_OPEN, _, _) : open_epoch();
            (t_T_IN, t_KIND_RESET, _, _) : close_epoch();
            (t_T_IN, _, _, _) : match_epoch();
            (t_PKTGEN_RETURN, t_KIND_OPERATE, _, _) : match_epoch();
            (t_HELD_RETURN, _, t_ROLE_ACK_HELD, _) : match_epoch();
            (t_HELD_RETURN, _, t_ROLE_RESP_HELD, _) : match_epoch();
            (t_HB_RETURN, _, t_ROLE_OP_HELD, _) : match_epoch();
        }
        default_action = read_epoch(); size = 10;
    }
'''
    text = text[:start] + lifetime + text[end:]
    start = text.index('    table gen_access {')
    end = text.index('    action read_t0()', start)
    text = text[:start] + '''    table gen_access {
        key = { ig_intr_md.ingress_port : ternary; md.event_kind : ternary;
                md.enabled : ternary; md.packet_epoch : ternary; md.epoch_delta : ternary; }
        actions = { live_gen; bad_gen; duplicate_close_gen; live_admit_gen; live_reset_gen; }
        const entries = {
            (_, _, _, 0, _) : bad_gen();
            (_, _, _, 32w0x7fffffff, _) : bad_gen();
            (_, _, _, 32w0x80000000 &&& 32w0x80000000, _) : bad_gen();
            (t_T_IN, t_KIND_OPEN, _, _, 0) : live_reset_gen();
            (t_T_IN, t_KIND_RESET, _, _, 32w0x80000000) : duplicate_close_gen();
            (t_T_IN, t_KIND_RESET, _, _, 0) : live_reset_gen();
            (t_T_IN, t_KIND_REQUEST, 0, _, 0) : live_gen();
            (t_T_IN, t_KIND_REQUEST, _, _, 0) : live_admit_gen();
            (_, _, _, _, 0) : live_gen();
        }
        default_action = bad_gen(); size = 9;
    }
''' + text[end:]
    start = text.index('    table tin_verdict {')
    end = text.index('\n    table token_verdict', start)
    block = text[start:end]
    assert block.count('md.q_diff : ternary;') == 1
    block = block.replace('md.q_diff : ternary; ', '')
    def row(match):
        terms = [term.strip() for term in match[2].split(',')]
        # This baseline REQUEST bypass row is unreachable: live qualification
        # already rejects q_diff==0. A sealed lifetime retains that rejection.
        if terms[0] == 't_KIND_REQUEST' and terms[2] == '0':
            return ''
        del terms[2]
        return match[1] + '(' + ', '.join(terms) + ')' + match[3]
    block = re.sub(r'^(\s*)\(([^()\n]*)\)(\s*:.*)$', row, block, flags=re.M)
    block = block.replace('size = 20;', 'size = 19;')
    text = text[:start] + block + text[end:]
    assert text.count('quarantine_access.apply();') == 1
    text = text.replace('lifetime_access.apply(); quarantine_access.apply(); gen_access.apply();',
                        'lifetime_access.apply(); gen_access.apply();')
    text = text.replace('bit<32> q_diff;', '')
    assert 'md.q_diff' not in text
    return text


def full_source():
    text = frozen()
    old = role('T')
    return text.replace(old, transform(old), 1)


def source_role(name, experimental=True):
    """Only identifier/port adapters for the retained source harness.

    QueueSim and SourcePipeline use their default isolated test ports. Actual
    full-composite output retains checkpoint 55's exact hardware port map.
    """
    text = transform(role(name)) if name == 'T' and experimental else role(name)
    prefix = {'N': 'n', 'E': 'r', 'T': 't'}[name]
    text = re.sub(r'\b' + prefix + r'_(\w+)', r'\1', text)
    if name == 'N':
        text = text.replace('N_ACK_RETURN=9w48;', 'N_ACK_RETURN=9w70;')
        text = text.replace('READ_HANDOFF_PORT=9w180;', 'READ_HANDOFF_PORT=9w197;')
    elif name == 'E':
        text = text.replace('9w48: provenance;', '9w70: provenance; 9w64: provenance;')
        # The E source adapter cuts at the standalone main marker. Checkpoint
        # 55 already stripped mains for composition, so restore only the marker.
        text += '\nPipeline() source_adapter_marker;\n'
    else:
        for key, old, new in (('T_IN', 180, 197), ('HB_RETURN', 181, 198),
                              ('HELD_RETURN', 182, 199), ('RELAY_PORT', 9, 64)):
            text, count = re.subn(r'(const PortId_t ' + key + r'\s*=\s*)9w' + str(old) + r';',
                                  r'\g<1>9w' + str(new) + ';', text)
            assert count == 1, key
    return '#include <core.p4>\n#include <tna.p4>\n' + text


def write(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=False)
    text = full_source()
    (directory / 'response_only.p4').write_text(text)
    metadata = json.loads(FROZEN.with_suffix('.inputs.json').read_text())
    metadata.update(experiment='t_sealed_lifetime', parent_source_sha256=FROZEN_SHA,
                    source_sha256=hashlib.sha256(text.encode()).hexdigest())
    (directory / 'response_only.inputs.json').write_text(json.dumps(metadata, indent=2) + '\n')


if __name__ == '__main__':
    write(sys.argv[1])

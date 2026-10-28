"""Check close/retry routing against the frozen pre-layout decision tables."""
import json
import random
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WIDTHS = (8, 3, 1, 32, 32, 32, 2, 8, 32, 1, 2, 8, 32)
OLD_FIELDS = ('m.kind','m.sequence_valid','m.matched','m.observed','m.client_diff','m.server_diff',
              'm.direction','hdr.tcp.flags','m.new_seq','m.same_syn','m.retry','hdr.dl.len','m.diff_application')

def pattern(text, width):
    if text == '_':
        return 0, 0
    words = text.split('&&&')
    value = int(words[0].split('w')[-1], 0)
    mask = int(words[1].split('w')[-1], 0) if len(words) == 2 else (1 << width)-1
    return value & mask, mask

def compile_rows(rows, widths):
    return [(tuple(pattern(k, w) for k, w in zip(key, widths)), action, argument)
            for key, action, argument in rows]

def lookup(rows, values):
    for key, action, argument in rows:
        if all((value & mask) == expected for value, (expected, mask) in zip(values, key)):
            return action, argument
    return 'NoAction', ''

def current_rows():
    source = (ROOT/'p4/response_only.p4').read_text()
    table = re.search(r'\btable first_event\{.*?const entries=\{(.*?)\}\}', source, re.S).group(1)
    return [(key.split(','), action, argument) for key, action, argument in
            re.findall(r'\(([^()]*)\):([a-zA-Z_0-9]+)\(([^()]*)\);', table)]

def test_close_phase_fusion_preserves_event_and_authority():
    frozen = json.loads((ROOT/'tests/fixtures/p4/n_event_tables.json').read_text())
    old = compile_rows(frozen['first_event'], WIDTHS)
    close = compile_rows(frozen['close_phase'], (8,2,16,32))
    definitions = current_rows()
    source = (ROOT/'p4/response_only.p4').read_text()
    key_text = re.search(r'\btable first_event\{key=\{([^}]+)\}', source).group(1)
    fields = [part.split(':')[0] for part in key_text.split(';') if part]
    fused = 'm.diff_real_links' in fields
    repacked = fused and 'm.diff_real_off' not in fields
    widths = dict(zip(OLD_FIELDS, WIDTHS))
    widths.update({'m.diff_real_links':8,'m.diff_real_tcp_dst':8,'m.diff_real_off':8,'m.diff_native_end':8,'m.response':1})
    packed_app = 'bit<16> diff_application;' in source
    if packed_app:
        widths['m.diff_application'] = 16
    current = compile_rows(definitions, [widths[field] for field in fields])
    sequence = None
    if 'm.sequence_valid' not in fields:
        sequence = json.loads((ROOT/'tests/fixtures/p4/n_sequence_guard.json').read_text())
        seq_rows = compile_rows(sequence['guard'], (32,32))
    rng = random.Random(0xD3)
    samples = []
    # Every prior rule, its wildcard space, and each one-bit mask boundary.
    for key, _, _ in old:
        for _ in range(24):
            values = [v | (rng.getrandbits(w) & ~mask) for (v, mask), w in zip(key, WIDTHS)]
            samples.append(values)
            for column, (_, mask) in enumerate(key):
                if mask:
                    changed = values.copy()
                    changed[column] ^= mask & -mask
                    samples.append(changed)
    # Exercise close rows with each meaningful kind/owner/sequence combination.
    for key, _, _ in close:
        flags, direction, phase, diff = [v for v, _ in key]
        for kind in (3,4,10):
            for sequence_value in (0,1,2,5,7):
                for client in (0,1,0xffffffff):
                    samples.append([kind,sequence_value,0,phase<<16,client,diff,direction,flags,0,0,0,0,0])
    # Successful SBO, wrong tuple, wrong application and exact duplicate cases.
    for key, _, _ in old:
        if key[0][0] not in (6,7):
            continue
        for app in (0,0x300,0x400,0xfffffeff,0xffffff0f,0x10000):
            values = [v for v, _ in key]
            values[12] = app
            samples.append(values)
    for index, original in enumerate(samples):
        values = original.copy()
        if sequence:
            action, _ = lookup(seq_rows, (values[4],values[5]))
            values[1] = sequence['values'][sequence['default'] if action == 'NoAction' else action]
        if packed_app and values[0] in (6,7) and values[12] not in (0,0x300,0x400,0xfffffeff,0xffffff0f):
            # Control state/inputs are at most0x04cf (function+app byte).
            # Exercise the wider signed domain too, without impossible32-bit aliases.
            values[12] = rng.randrange(-0x4cf,0x4d0) & 0xffffffff
        response = 1 if values[0] == 6 else 0
        wrong = index % 6
        raw = [int(wrong == j+1) for j in range(4)] + [response]
        if fused and values[0] in (6,7):
            allowed = (0x300,0x400) if response else (0xfffffeff,0xffffff0f)
            values[2] = int(not any(raw[:4]) and values[12] in allowed)
        expected, _ = lookup(old, values)
        phase_action, argument = lookup(close, (values[7],values[6],values[3]>>16,values[5]))
        expected_phase = int(argument.split('w')[1], 0) if phase_action == 'qualify_close' else 0
        current_values = dict(zip(OLD_FIELDS,values))
        current_values.update(zip(('m.diff_real_links','m.diff_real_tcp_dst','m.diff_real_off','m.diff_native_end','m.response'),raw))
        if repacked:
            current_values['m.diff_real_links'] |= raw[2]
        if packed_app:
            current_values['m.diff_application'] &= 0xffff
        actual, argument = lookup(current, [current_values[field] for field in fields])
        actual_phase = int(argument.split('w')[1], 0) if actual.endswith('_qualified') else 0
        actual = actual[:-len('_qualified')] if actual.endswith('_qualified') else actual
        assert actual == expected, values
        if expected in ('first_close','first_close_ack'):
            assert actual_phase == expected_phase, values

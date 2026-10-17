"""Offline compile probes; NOT production candidates or compiler-qualified fixes.

Usage: python probe_candidates.py /path/to/repo OUTPUT_DIRECTORY
Pins the inspected m9_01 source. No repository file is modified.
"""
import hashlib
import json
from pathlib import Path
import re
import sys

CT = Path('defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/ctl_timing_01')
BASE_SHA = '6590141fc68b43788de7e969badf3d6bdf24ba0615a56631497ca39854c0ce0f'

def once(s, old, new):
    assert s.count(old) == 1, (old[:100], s.count(old))
    return s.replace(old, new)

def block(s, start):
    a = s.index(start)
    b = s.index('{', a)
    depth = 1
    e = b + 1
    while depth:
        depth += (s[e] == '{') - (s[e] == '}')
        e += 1
    if s[e:e+1] == ';': e += 1
    return s[a:e]

def n_bank_diffs(s):
    # Bank outputs become differences from the OLD register value, including on writes.
    # Operand selection can execute before the stateful read; final actions only route outputs.
    s = once(s, 'bit<32> client;', 'bit<32> client; bit<32> client_probe; bit<32> server_probe;')
    for bank in ('client', 'server'):
        for action in ('read_', 'write_'):
            old = block(s, ' RegisterAction<bit<32>,bit<1>,bit<32>>('+bank+') '+action+bank+'=')
            new = once(old, 'r=v;', 'r=m.'+bank+'_probe-v;')
            s = once(s, old, new)
    formulas = {
        'syn': ('m.new_seq', '32w0', 'hdr.tcp.ack', 'm.client'),
        'synack': ('hdr.tcp.ack', 'm.new_seq', 'm.client', 'm.server'),
        'forward': ('hdr.tcp.seq', 'hdr.tcp.ack', 'm.client', 'm.server'),
        'reverse': ('hdr.tcp.ack', 'hdr.tcp.seq', 'm.server', 'm.client'),
        'reset_forward': ('hdr.tcp.seq', '32w0', 'm.client', '32w0'),
        'reset_reverse': ('32w0', 'hdr.tcp.seq', 'm.server', '32w0'),
        'response': ('m.ack_native', 'hdr.tcp.seq', 'm.client', 'm.server'),
        'read_response': ('hdr.tcp.ack', 'hdr.tcp.seq', 'm.client', 'm.server'),
    }
    prep = ''
    for name, (cp, sp, cd, sd) in formulas.items():
        prep += f' action prep_diff_{name}(){{m.client_probe={cp};m.server_probe={sp};}}\n'
        old = block(s, ' action diff_'+name+'()')
        s = once(s, old, f' action diff_{name}(){{m.client_diff={cd};m.server_diff={sd};}}')
    old_table = block(s, ' table sequence_diff{')
    prep += old_table.replace('table sequence_diff{', 'table sequence_operands{').replace('diff_', 'prep_diff_')
    s = once(s, old_table, prep+'\n'+old_table)
    s = once(s, 'next_seq_t.apply();epoch_t.apply();client_t.apply();server_t.apply();',
             'next_seq_t.apply();sequence_operands.apply();epoch_t.apply();client_t.apply();server_t.apply();')
    return s

def t_single_child(s):
    # Explicitly exclude child>0. Three transport frames in E remain ONE response event in T.
    s = once(s, '(11, 0) : opaque_ethernet;', '(11, 0) : single_response_child;')
    s = once(s, '    state parse_ladder {',
             '    state single_response_child { transition select(hdr.tev.stage) { 0: opaque_ethernet; default: reject; } }\n    state parse_ladder {')
    for i in (1, 2):
        s = once(s, f'    Register<bit<32>, bit<1>>(1, 0xffffffff) child_seen{i}_reg;', '')
        for action in (f'child_try{i}', f'child_read{i}'):
            s = once(s, block(s, f'    RegisterAction<bit<32>, bit<1>, bit<32>>(child_seen{i}_reg) {action} ='), '')
        for action in (f'read_seen{i}', f'try_seen{i}'):
            s = once(s, block(s, f'    action {action}()'), '')
        s = once(s, block(s, f'    table child_seen{i}_access {{'), '')
        s = once(s, f'child_seen{i}_access.apply();', '')
    a = '                if (hdr.tev.stage == 0) { md.dup_diff = md.seen0_diff; }\n                else if (hdr.tev.stage == 1) { md.dup_diff = md.seen1_diff; }\n                else { md.dup_diff = md.seen2_diff; }'
    s = once(s, a, '                md.dup_diff = md.seen0_diff;')
    # Keep key arity in this first probe: fixed nonzero diffs cannot signal a missing child.
    # Compiler should constant-fold these keys/rows; inspect optimized table report to verify.
    s = once(s, 'child_seen0_access.apply();', 'child_seen0_access.apply(); md.seen1_diff = 32w0xffffffff; md.seen2_diff = 32w0xffffffff;')
    return s

def n_zero_unused_timestamp(s):
    old = 'hdr.t0.t0q=p.global_tstamp[31:8]++8w0;'
    assert s.count(old) == 5
    # Preserve envelope lengths and parser/deparser contract. T anchors from its own clock;
    # it never reads tev.t0q. Removing four wire bytes would be a separate ABI change.
    return s.replace(old, 'hdr.t0.t0q=32w0;')

def main():
    repo, out = map(Path, sys.argv[1:])
    source = (repo / CT / 'evidence/m9_01/response_only.p4').read_text()
    assert hashlib.sha256(source.encode()).hexdigest() == BASE_SHA
    out.mkdir(parents=True, exist_ok=True)
    records = {}
    for name, fn, unchanged in [('n_bank_diffs', n_bank_diffs, ('E','T')), ('t_single_child', t_single_child, ('N','E')), ('n_zero_unused_timestamp', n_zero_unused_timestamp, ('E','T'))]:
        candidate = fn(source)
        # Reuse repository's section definitions for exact unchanged-role checks.
        import importlib.util
        spec = importlib.util.spec_from_file_location('audit_combined', repo / CT.parent / 'combined_nt_01/generate.py')
        mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
        for role in unchanged: assert mod.segment(candidate, role) == mod.segment(source, role)
        (out/(name+'.p4')).write_text(candidate)
        records[name] = {'sha256': hashlib.sha256(candidate.encode()).hexdigest(), 'unchanged_roles': list(unchanged), 'compiler_status': 'NOT_RUN'}
    (out/'manifest.json').write_text(json.dumps({'base_sha256': BASE_SHA, 'probes':records}, indent=2)+'\n')

if __name__ == '__main__': main()

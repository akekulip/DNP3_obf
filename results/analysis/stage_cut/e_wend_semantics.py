#!/usr/bin/env python3
"""Source-bound differential checks for the E img_wend scheduling transformation.

This checks the changed SALU/sequence algebra and action-selection domains. It is not
an SDK model or hardware proof; those gates remain required for a retained candidate.
"""
from pathlib import Path
import hashlib
import itertools
import json
import random
import re

ROOT = Path(__file__).resolve().parents[3]
BASE = ROOT / 'results/builds/c69_baseline/response_only.p4'
TRIAL = ROOT / 'results/builds/c72_e_wend_02/response_only.p4'
MASK = (1 << 32) - 1


def effect(old, mode, direction, shape, first, front, grant, v, qx, inc, seq):
    armed = (direction == 1 and shape == 1) or mode == 1
    if not armed:
        return v, seq, None
    if first and direction == 1 and shape == 1:
        return qx, seq, None
    if direction == 1 and shape == 4:
        # The first two constant classify_fwd rows take priority over every other row.
        result_commit = front == 0 and grant == 1
        commit = result_commit if old else grant == 1
        if old:
            return (v + inc) & MASK if commit else v, (v + qx) & MASK, None
        # New SALU returns old v in forward-unused m.r. The later finish adds final qx.
        old_v = v
        next_v = (v + inc) & MASK if commit else v
        return next_v, (old_v + qx) & MASK, None
    if direction == 2 and shape == 4:
        return v, seq, (qx - v) & MASK
    return v, seq, None


def main():
    base, trial = BASE.read_text(), TRIAL.read_text()
    prefix = 'control r_Egress('
    suffix = 'control r_EgDeparser('
    assert base.split(prefix)[0] == trial.split(prefix)[0], 'non-E prefix changed'
    assert base.split(suffix)[1] == trial.split(suffix)[1], 'non-E suffix changed'
    ebase = base.split(prefix)[1].split(suffix)[0]
    etrial = trial.split(prefix)[1].split(suffix)[0]
    old_classifier = ebase[ebase.index('    table classify_fwd {'):ebase.index('    Register<bit<32>, r_slot_t>(16, 0) img_wend;')]
    new_classifier = etrial[etrial.index('    table classify_fwd {'):etrial.index('    Register<bit<32>, r_slot_t>(16, 0) img_wend;')]
    assert old_classifier == new_classifier
    assert 'const entries = {(0, 0, _, _, _, _, _, _, _, _, _, _, _, _, _, _): out_translate();(0, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _): out_commit();' in old_classifier
    assert old_classifier.count(': out_commit()') == 1
    # Grant starts at zero and only acct_try can set it. Each of its table rows
    # requires front_ret==0, and front_ret is not written again after accounting.
    assert len(re.findall(r'm\.grant\s*=', base)) == 2
    assert 'm.grant = (bit<1>)(0);' in base
    assert 'm.grant = (bit<1>)(acct_try.execute(m.idx));' in base
    acct = ebase[ebase.index('    table acct_t {'):ebase.index('    Register<bit<32>, r_slot_t>(16, 0) img_end;')]
    rows = re.findall(r'\(([^()]*)\): do_acct_try\(\)', acct)
    assert len(rows) == 3
    assert all(row.split(',')[3].strip() == '0' for row in rows)
    assert len(re.findall(r'm\.front_ret\s*=', base)) == 1
    assert etrial.index('front_t.apply();') < etrial.index('acct_t.apply();') < etrial.index('img_wend_t.apply();')
    assert 'void apply(inout bit<32> v, out bit<32> rv) { rv = v; v = v + m.t; }' in etrial
    assert 'void apply(inout bit<32> v, out bit<32> rv) { rv = v; }' in etrial
    assert 'action finish_forward_sequence() { hdr.tcp.seq = m.r + m.qx; }' in etrial
    assert 'if ((bit<8>)m.shape == r_SH_ACK) { finish_forward_sequence_t.apply(); }' in etrial
    assert re.findall(r'Register<[^;]+;', ebase) == re.findall(r'Register<[^;]+;', etrial)
    edges = [0, 1, 2, 49, 60, 61, 91, 134, 141, 158, 0x7fffffff, 0x80000000, 0xffffffc4, MASK]
    count = 0
    for mode, direction, shape, first, front, grant in itertools.product(range(3), range(4), range(8), range(2), edges, range(2)):
        if grant and front != 0:
            continue  # unreachable by the checked grant-writer invariant
        for v in edges:
            args = (mode, direction, shape, first, front, grant, v, MASK, 141, 0x12345678)
            assert effect(True, *args) == effect(False, *args), args
            count += 1
    rng = random.Random(69)
    for _ in range(100000):
        args = (rng.randrange(3), rng.randrange(4), rng.randrange(8), rng.randrange(2),
                rng.choice([0, rng.getrandbits(32)]), rng.randrange(2), *[rng.getrandbits(32) for _ in range(4)])
        if args[5] and args[4] != 0:
            args = (*args[:4], 0, *args[5:])
        assert effect(True, *args) == effect(False, *args), args
        count += 1
    result = {'status': 'PASS', 'cases': count, 'source_sha256': hashlib.sha256(TRIAL.read_bytes()).hexdigest(),
              'scope': 'changed SALU/action-selection/32-bit sequence algebra only; not model or hardware',
              'non_E_source_byte_exact': True, 'persistent_register_declarations_unchanged': True}
    (ROOT / 'results/analysis/stage_cut/e_wend_02_semantics.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()

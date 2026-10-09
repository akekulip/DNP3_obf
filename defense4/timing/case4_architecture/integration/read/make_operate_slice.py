#!/usr/bin/env python3
"""Generate operate_slice.p4: read_queue_timing.p4's OPERATE path, extracted VERBATIM, as a compilable test fixture.

Written when read_queue_timing.p4 as a whole did not compile (TIMING_QUEUE_MIGRATION_STATUS.md); since
2026-10-09 it does, and this slice remains a smaller model fixture for the OPERATE path. This script copies,
character for character, everything the OPERATE admission/clone/release path executes: the prelude
(constants, headers, metadata, IngressParser), the IngressDeparser + Pipeline tail, the named
registers/register actions/actions/tables below, and the apply-block pieces PKTGEN_RETURN, T_IN's OPERATE
register block, and HB_RETURN. Only the glue that joins those pieces is new (marked GLUE; it calls
hold_operate, which tin_verdict selects in the full file). It is a test fixture for the model, not a
variant of the production file.

  python3 make_operate_slice.py [out.p4]                 (default: operate_slice.p4 next to this script)
  python3 make_operate_slice.py --capture-hb [out.p4]    (default: operate_slice_capture.p4)

--capture-hb replaces ONLY the HB_RETURN branch (the release logic, which F1 does not touch) with GLUE that
sends every HB_RETURN arrival, ladder header intact, to a front port: OP blocker -> 1, anything else -> 2.
Reason: the verbatim HB_RETURN branch does not place on Tofino-1 on its own (op_done_reg is read and then
written by a dependent table; bf-p4c: "Table placement was not able to allocate ... in the same stage along
with Register Ingress.op_done_reg", evidence/mirror_f1_01/compile_slice_local_02). The capture variant
exposes exactly what the clone admission produces, so it can be counted and byte-checked on the model.
"""
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCE = HERE / 'read_queue_timing.p4'

DECLS = ['set_params', 'params', 'clock_sample', 'clock',
         'op_gen_alloc_reg', 'op_gen_peek', 'op_gen_bump', 'op_done_reg', 'op_done_read', 'op_done_try',
         'op_t0_reg', 'op_t0_read', 'op_t0_arm', 'outcomes', 'bump_outcome', 'count', 'bump', 'outcome_count',
         'passthrough_tev_relay', 'hold_operate', 'admit_operate_held', 'drop_clone',
         'keep_blocking', 'stop_blocking', 'stop_blocking_stale', 'stop_blocking_tmo', 'stop_blocking_off',
         'op_offset', 'compute_op_t0_masked', 'compute_op_delta', 'op_lgen_diff', 'read_op_done', 'try_op_done',
         'release_operate', 'rewait_operate', 'flush_operate_stale', 'flush_operate_off',
         'release_operate_counted', 'set_op_go', 'op_go_check', 'unmatched', 'hb_verdict']


def balanced(text, start):
    """Index just past the brace block whose '{' is the first one at or after `start`."""
    i = text.index('{', start)
    depth = 0
    for j in range(i, len(text)):
        depth += {'{': 1, '}': -1}.get(text[j], 0)
        if depth == 0:
            return j + 1
    raise ValueError('unbalanced braces')


def decl(body, name):
    m = re.search(r'^[ \t]*(action\s+%s\s*\(|table\s+%s\b|Register<[^;]*>\s*\([^;]*\)\s*%s\s*;|'
                  r'RegisterAction<[^=]*>\s*\(\w+\)\s*%s\s*=)' % ((re.escape(name),) * 4), body, re.M)
    if not m:
        raise KeyError(name)
    if m.group(1).startswith('Register<'):
        return body[m.start():body.index(';', m.start()) + 1]
    end = balanced(body, m.start())
    if body[end:end + 1] == ';':
        end += 1
    return body[m.start():end]


def branch(body, header):
    start = body.index(header)
    return body[start:balanced(body, start)]


CAPTURE_HB = (
    'if (ig_intr_md.ingress_port == HB_RETURN) {\n'
    '            // GLUE (--capture-hb): export every HB_RETURN arrival, ladder intact, for counting.\n'
    '            if (hdr.ladder.role == ROLE_OP_BLK) { ig_tm_md.ucast_egress_port = 9w1; }\n'
    '            else { ig_tm_md.ucast_egress_port = 9w2; }\n'
    '        }')


def build(capture_hb=False):
    text = SOURCE.read_text()
    ing = text.index('control Ingress(')
    tail = text.index('control IngressDeparser(')
    prelude, ingress, rest = text[:ing], text[ing:tail], text[tail:]
    sig_end = ingress.index('{') + 1
    apply_at = ingress.index('\n    apply {')
    body, apply = ingress[sig_end:apply_at], ingress[apply_at:]
    pieces = [decl(body, n) for n in DECLS]
    pktgen = branch(apply, 'if (ig_intr_md.ingress_port == PKTGEN_RETURN) {')
    operate = branch(apply, 'if (hdr.tev.kind == KIND_OPERATE && md.enabled != 0) {\n                md.op_gen = op_gen_bump')
    hb = branch(apply, 'if (ig_intr_md.ingress_port == HB_RETURN) {')
    copied = [pktgen, operate] + ([] if capture_hb else [hb])
    if capture_hb:
        hb = CAPTURE_HB
    glue_apply = (
        '\n    apply {\n'
        '        ig_tm_md.bypass_egress = 0;\n'
        '        md.outcome_code = OUT_NONE;\n'
        '        params.apply(); clock.apply();\n'
        '        ' + pktgen + '\n'
        '        // GLUE: T_IN with only the policy-off OPERATE passthrough and the OPERATE admission: the\n'
        '        // copied register block, then hold_operate (tin_verdict\'s OPERATE row in the full file).\n'
        '        else if (ig_intr_md.ingress_port == T_IN) {\n'
        '            if (md.enabled == 0) { passthrough_tev_relay(); }\n'
        '            else {\n'
        '                ' + operate + '\n'
        '                if (hdr.tev.kind == KIND_OPERATE) { hold_operate(); } else { unmatched(); }\n'
        '            }\n'
        '        }\n'
        '        else ' + hb + '\n'
        '        else { unmatched(); }\n'
        '        outcome_count.apply();\n'
        '    }\n}\n\n')
    header = ('// GENERATED by make_operate_slice.py from read_queue_timing.p4 -- do not edit. Test fixture for\n'
              '// the local model: the OPERATE admission / mirror clone / release path, copied verbatim.\n')
    return header + prelude + ingress[:sig_end] + '\n' + '\n'.join('    ' + p.lstrip() for p in pieces) + glue_apply + rest, \
        pieces + copied


def verify(out_text, pieces):
    """Every copied piece occurs verbatim in BOTH the source and the generated fixture."""
    src = SOURCE.read_text()
    return all(p in src and p.strip() in out_text for p in pieces)


if __name__ == '__main__':
    args = sys.argv[1:]
    capture = '--capture-hb' in args
    args = [a for a in args if a != '--capture-hb']
    out = Path(args[0]) if args else HERE / ('operate_slice_capture.p4' if capture else 'operate_slice.p4')
    text, pieces = build(capture)
    out.write_text(text)
    ok = verify(text, pieces)
    print('wrote', out, '| verbatim pieces', len(pieces), '| all verbatim:', ok)
    sys.exit(0 if ok else 1)

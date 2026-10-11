"""Reset plan for T's registers (read/read_queue_timing.p4), derived from the P4 declarations.

TIMING_QUEUE_MIGRATION_STATUS.md, "Control-plane reset rule": child_seen{0,1,2}_reg, ack_commit_gen_reg
and quarantine_reg reset to 0xffffffff, not 0, because each is compared for equality with a live READ
generation or epoch and 0 is both the first generation and a possible epoch. A zeroed quarantine_reg
quarantines epoch 0. A BF Runtime table clear writes 0, so a controller must write the declared reset
value back instead of clearing. Nothing in controller/ or core/ did this before this module.

The plan is read from the source, not typed here, so it cannot drift from the declarations. Rows are
(bfrt_register_table, index, data_field, value); the composed program prefixes T's control with t_ and
places it in pipe 1 (core/response_only/compose.py). Source-level only: no BF Runtime client.
"""
import re
from pathlib import Path

T_SRC = Path(__file__).resolve().parent.parent / 'read' / 'read_queue_timing.p4'
DECL = re.compile(r'Register<bit<(\d+)>,\s*bit<(\d+)>>\(\s*(\d+)\s*,\s*(0x[0-9a-fA-F]+|\d+)\s*\)\s*(\w+)\s*;')
COUNTERS = {'outcomes'}          # outcome counters: cleared to 0 like any counter, listed separately


def declarations(src=T_SRC):
    text = re.sub(r'/\*.*?\*/|//[^\n]*', ' ', Path(src).read_text(), flags=re.S)
    return [dict(name=m[5], width=int(m[1]), size=int(m[3]), reset=int(m[4], 0)) for m in DECL.finditer(text)]


def reset_plan(prefix='t_', control='Ingress', src=T_SRC):
    rows = []
    for d in declarations(src):
        table = 'pipe.%s%s.%s' % (prefix, control, d['name'])
        rows += [(table, i, '%s%s.%s.f1' % (prefix, control, d['name']), d['reset']) for i in range(d['size'])]
    return rows


def nonzero_resets(src=T_SRC):
    return sorted(d['name'] for d in declarations(src) if d['reset'] != 0)


def check_readback(readback, prefix='t_', control='Ingress', src=T_SRC):
    """readback: {(bfrt_table, index): value}. Returns [(table, index, want, got)] for every register cell
    that does not hold its declared reset value (a missing cell counts as a mismatch)."""
    bad = []
    for table, index, _field, want in reset_plan(prefix, control, src):
        got = readback.get((table, index))
        if got != want:
            bad.append((table, index, want, got))
    return bad

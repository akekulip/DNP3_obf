"""c70 trial (E experiment): remove E's three always-zero READ-CRC predicates rbad0, rbad1 and rbadt.

In the c69 profile the only assignment to each predicate is the zeroing at E's parser start: their compares were
deleted by two_read_reduce (c0/c1/c2 are extracted only by state read_b0, which no transition reaches), and E's
producers of their inputs (in_rb0_t, in_rb1_t, in_rt_t) are declared but never applied. Removed: the three fields,
their pa_solitary pragmas, the zeroing, their acct_t and classify_fwd key columns with each const entry's matching
positions (row order kept; every removed value must be 0 or _, which an always-zero field matches), and the unapplied
producers with their hashes, actions and the in_rb0/in_rb1 fields. Kept: m.in_rt (status_crc_t writes it, cbadt reads
it) and the badh/cbad0/cbadt CRC checks. Only E changes.

Result (2026-10-26): compiles; final placement shows no physical resource change against c69, so c70 is not
retained (read_complete_01/evidence/c69_hw_ne_20261026/c70_resource_comparison.json).
"""
import re

from .common import combined, once

PREDICATES = ('rbad0', 'rbad1', 'rbadt')
TABLES = ('acct_t', 'classify_fwd')


def _closing(text, open_index, pair='{}'):
    """Index just past the bracket that closes text[open_index]."""
    depth = 0
    for i in range(open_index, len(text)):
        depth += (text[i] == pair[0]) - (text[i] == pair[1])
        if depth == 0:
            return i + 1
    raise ValueError('strip_rbad: unbalanced %s at %d' % (pair, open_index))


def _split_top(text, sep):
    """Split on sep outside any (), {} or <> nesting."""
    parts, depth, start = [], 0, 0
    for i, ch in enumerate(text):
        depth += (ch in '({<') - (ch in ')}>')
        if ch == sep and depth == 0:
            parts.append(text[start:i])
            start = i + 1
    parts.append(text[start:])
    return parts


def strip_table(t, name):
    """Drop the predicate key columns of one table and the same positions from each const entry."""
    start = t.index('table %s {' % name)
    end = _closing(t, t.index('{', start))
    body = t[start:end]
    key_open = body.index('key = {')
    key_end = _closing(body, body.index('{', key_open))
    keys = [k.strip() for k in body[body.index('{', key_open) + 1:key_end - 1].split(';') if k.strip()]
    drop = [i for i, k in enumerate(keys) if k.split(':')[0].strip() in ('m.' + p for p in PREDICATES)]
    if len(drop) != len(PREDICATES):
        raise ValueError('strip_rbad: %s keys %r' % (name, keys))
    new_key = body[key_open:key_end]
    for p in PREDICATES:
        new_key = once(new_key, 'm.%s : ternary; ' % p, '')
    entries_open = body.index('const entries = {')
    brace = body.index('{', entries_open)
    entries_end = _closing(body, brace)
    rows = [r for r in _split_top(body[brace + 1:entries_end - 1], ';') if r.strip()]
    new_rows = []
    for row in rows:
        lead = row[:len(row) - len(row.lstrip())]
        tuple_open = row.index('(')
        tuple_end = _closing(row, tuple_open, '()')
        values = _split_top(row[tuple_open + 1:tuple_end - 1], ',')
        if len(values) != len(keys):
            raise ValueError('strip_rbad: %s entry has %d values for %d keys: %s' % (name, len(values), len(keys), row))
        removed = [values[i].strip() for i in drop]
        if any(v not in ('0', '_') for v in removed):
            raise ValueError('strip_rbad: %s entry matches a nonzero predicate %r: %s' % (name, removed, row))
        kept = [v for i, v in enumerate(values) if i not in drop]
        kept[0] = kept[0].lstrip()
        new_rows.append(lead + row[:tuple_open].lstrip() + '(' + ','.join(kept) + ')' + row[tuple_end:])
    new_body = (body[:key_open] + new_key + body[key_end:brace + 1] + ';'.join(new_rows) + ';'
                + body[entries_end - 1:])
    return t[:start] + new_body + t[end:]


def transform(src):
    old = combined.segment(src, 'E')
    e = old
    # Premises, checked on the input: one assignment each (the zeroing) and no applied producer.
    for p in PREDICATES:
        if len(re.findall(r'm\.%s\s*=' % p, e)) != 1 or 'm.%s = 0;' % p not in e:
            raise ValueError('strip_rbad: %s is not assigned only by the parser zeroing' % p)
    for table in ('in_rb0_t', 'in_rb1_t', 'in_rt_t'):
        if table + '.apply()' in e:
            raise ValueError('strip_rbad: %s is applied in E' % table)
    e = once(e, 'bit<1> badh; bit<1> rbad0; bit<1> rbad1; bit<1> rbadt; bit<1> cbad0; bit<1> cbadt;',
             'bit<1> badh; bit<1> cbad0; bit<1> cbadt;')
    e = once(e, 'bit<16> in_dl; bit<16> in_rb0; bit<16> in_rb1; bit<16> in_rt;', 'bit<16> in_dl; bit<16> in_rt;')
    e = once(e, '@pa_solitary("egress","m.badh") @pa_solitary("egress","m.rbad0") @pa_solitary("egress","m.rbad1")\n'
                '@pa_solitary("egress","m.rbadt") @pa_solitary("egress","m.cbad0") @pa_solitary("egress","m.cbadt")',
             '@pa_solitary("egress","m.badh") @pa_solitary("egress","m.cbad0") @pa_solitary("egress","m.cbadt")')
    e = once(e, 'm.badh = 0; m.rbad0 = 0; m.rbad1 = 0; m.rbadt = 0; m.cbad0 = 0; m.cbadt = 0;',
             'm.badh = 0; m.cbad0 = 0; m.cbadt = 0;')
    for name in ('in_rb0', 'in_rb1', 'in_rt'):
        start = e.index('    Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_%s;\n' % name)
        end = e.index('\n', e.index('    table %s_t{' % name)) + 1
        e = e[:start] + e[end:]
    for table in TABLES:
        e = strip_table(e, table)
    e = once(e, '        /* rbad0/rbad1/rbadt checks removed: c0/c1/c2 are only extracted by read_b0, which no state reaches */\n',
             '        /* the rbad0/rbad1/rbadt READ-CRC predicates are removed (c70): c0/c1/c2 are only extracted by read_b0,\n'
             '           which no state reaches, so they were constant zero */\n')
    for name in PREDICATES + ('in_rb0', 'in_rb1', 'hash_in_rt', 'in_rt_t'):
        if re.search(r'\b%s\b' % name, e.replace('the rbad0/rbad1/rbadt READ-CRC predicates', '')):
            raise ValueError('strip_rbad: %s still present' % name)
    if 'm.in_rt' not in e or 'm.cbadt' not in e:
        raise ValueError('strip_rbad: removed a working CRC input')
    return once(src, old, e)

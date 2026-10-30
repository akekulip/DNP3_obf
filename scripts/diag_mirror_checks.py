#!/usr/bin/env python3
"""Static checks of a compiled diagnostic build BASE_diag_mirror against its base (reads only; writes one JSON report).

  python3 scripts/diag_mirror_checks.py results/builds/BASE_diag_mirror [--baseline results/builds/BASE]

The baseline defaults to the base the build name derives from (c72_diag_mirror -> c72, c74_diag_mirror -> c74).

1. Pipe-0 mirror guard, both deparsers (the bf-p4c type-0 trap, scripts/hardware/check_mirror_select.py):
   entry 1 takes its session from m.diag_ses; the select and session containers each hold one field; the session
   container is zeroed by the parser; a hidden table whose hit and miss both continue sets mirror_type to 1 on
   every pass, so any other entry is unreachable. The only constant written to m.diag_ses is that gress's session.
2. Pipe-1 mirror guard: the unchanged installer guard (check_mirror_select.check_out) on both builds.
3. Pipe-1 equivalence: the two p1 .bfa files are compared after mapping compiler-generated names (they embed
   source line numbers and a program-wide gateway counter) by order of first appearance. The report counts every
   remaining differing line and classifies it.
"""
import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GRESS = {'ingress': 'ig_intr_md_for_dprsr', 'egress': 'eg_intr_md_for_dprsr'}


def sections(bfa):
    """{top-level header: body text} for a .bfa file."""
    out, name, lines = {}, None, []
    for line in bfa.splitlines():
        if line and not line.startswith((' ', '#')):
            if name is not None:
                out.setdefault(name, []).extend(lines)
            name, lines = line.rstrip(':'), []
        else:
            lines.append(line)
    if name is not None:
        out.setdefault(name, []).extend(lines)
    return {k: '\n'.join(v) for k, v in out.items()}


def containers(phv):
    out, cur = {}, None
    for line in phv.splitlines():
        m = re.match(r'^    ([A-Z]+\d+):\s*$', line)
        if m:
            cur = out.setdefault(m.group(1), [])
            continue
        n = re.match(r'^    - \{ name : ([^,]+),', line)
        if n and cur is not None:
            cur.append(n.group(1).strip())
    return out


def mirror_block(deparser):
    i = deparser.find('\n  mirror:')
    if i < 0:
        return None, {}
    sel = re.search(r'select: ([A-Z]+\d+)\S*\s*# .*?: \w+::(\S+)', deparser[i:]).groups()
    entries, cur = {}, None
    for line in deparser[i:].splitlines()[2:]:
        if not line.startswith('    '):
            break
        m = re.match(r'^    (\d+):', line)
        if m:
            cur = int(m.group(1)); entries[cur] = []
            continue
        f = re.match(r'^      - ([A-Z]+\d+)\S*\s*# .*?: \w+::(\S+)', line)
        if f and cur is not None:
            entries[cur].append(f.groups())
    return sel, entries


def unconditional_setter(stages, field):
    """Hidden tables (hit target == miss target) whose action sets `field` to 1."""
    found = []
    for text in stages:
        blocks = re.split(r'\n(?=  \w+ \S+(?: \d+)?:\n)', text)      # one block per table / indirect table
        by_name = {re.match(r'  \w+ (\S+)', b).group(1): b for b in blocks if re.match(r'  \w+ \S+', b)}
        for name, block in by_name.items():
            if not re.match(r'  \w+_match tbl_', block):
                continue
            hit, miss = re.search(r'hit: \[\s*(\S+)\s*\]', block), re.search(r'miss:\s*(\S+)', block)
            ind = re.search(r'indirect: (\S+)', block)
            actions = by_name.get(ind.group(1) + ':', by_name.get(ind.group(1), '')) if ind else block
            if hit and miss and hit.group(1) == miss.group(1) and re.search(r'set %s, 1\b' % re.escape(field), actions):
                found.append(name)
    return found


def session_constants(stages):
    """Every constant written to m.diag_ses in this gress's actions."""
    values = []
    for text in stages:
        for action in re.split(r'\n      \w+\(\d+, \d+\):', text):
            if re.search(r'set m\.diag_ses, \$constant\d+', action):
                values += [int(v) for v in re.findall(r'\$constant\d+: (\d+)', action)]
    return sorted(set(values))


def guard_pipe0(out, expected):
    bfa_path = Path(out) / 'p0' / 'response_only.bfa'
    parts = sections(bfa_path.read_text())
    result, ok = {}, True
    for gress, prefix in GRESS.items():
        cont = containers(parts['phv ' + gress])
        zero = set(re.findall(r'[A-Z]+\d+', re.search(r'init_zero: \[([^\]]*)\]', parts['parser ' + gress]).group(1)))
        (sel_c, sel_f), entries = mirror_block(parts['deparser ' + gress])
        stages = [v for k, v in parts.items() if re.match(r'stage \d+ %s$' % gress, k)]
        setters = unconditional_setter(stages, prefix + '.mirror_type')
        one = entries.get(1, [])
        ses_c = one[0][0] if one else None
        checks = dict(
            select_is_mirror_type=sel_f == prefix + '.mirror_type',
            entry1_session_is_diag_ses=bool(one) and one[0][1] == 'm.diag_ses' and len(one) == 1,
            select_container_solitary=cont.get(sel_c) == [prefix + '.mirror_type'],
            session_container_solitary=cont.get(ses_c) == ['m.diag_ses'],
            session_zeroed_by_parser=ses_c in zero,          # a dropped "= 0" still reads as session 0
            mirror_type_written_every_pass=bool(setters),
            other_entries_unreachable=set(entries) <= {1} or bool(setters),
            session_constants=session_constants(stages) == [expected[gress]])
        result[gress] = dict(checks=checks, select=[sel_c, sel_f], select_zeroed_by_parser=sel_c in zero,
                             entries={str(k): v for k, v in entries.items()},
                             unconditional_mirror_type_setters=setters, session_constants=session_constants(stages),
                             containers={c: cont.get(c) for c in {sel_c, ses_c} | {e[0][0] for e in entries.values() if e}})
        ok &= all(checks.values())
    return ok, dict(bfa=str(bfa_path), bfa_sha256=hashlib.sha256(bfa_path.read_bytes()).hexdigest(), gress=result)


def _rename_by_order(text, pattern):
    seen = []
    for m in re.finditer(pattern, text):
        if m.group(0) not in seen:
            seen.append(m.group(0))
    return seen


def normalised(text):
    text = re.sub(r'run_id: "[0-9a-f]+"', 'run_id: X', text)
    for pattern, tag in ((r'\btbl_response_only\d+(?:_\d+)?', 'TBL'), (r'\bresponse_only\d+(?:_\d+)?(?=[(\s,]|$)', 'ACT'),
                         (r'\bcond-\d+', 'COND')):
        for i, name in enumerate(_rename_by_order(text, pattern)):
            text = re.sub(r'(?<![\w-])%s(?![\w])' % re.escape(name), '%s%d' % (tag, i), text)
    return text


def pipe1_equivalence(base_out, cand_out):
    a = normalised((Path(base_out) / 'p1/response_only.bfa').read_text()).splitlines()
    b = normalised((Path(cand_out) / 'p1/response_only.bfa').read_text()).splitlines()
    differing = [(x, y) for x, y in zip(a, b) if x != y]
    seeds = [d for d in differing if re.match(r'^\s*seed: 0x[0-9a-f]+$', d[0]) and re.match(r'^\s*seed: 0x[0-9a-f]+$', d[1])]
    other = [d for d in differing if d not in seeds]
    return not other and len(a) == len(b), dict(
        lines=[len(a), len(b)], differing_lines=len(differing), exact_match_hash_seed_lines=len(seeds),
        other_differing_lines=other[:20],
        note='Exact-match hash-group seeds choose the RAM way an entry is stored in, not the match result. Recompiling '
             'the unmodified canonical source reproduces its p0 and p1 .bfa byte for byte (except run_id), so these '
             'seeds follow from the pipe-0 additions compiled earlier in the same program, not run-to-run noise.')


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('build', type=Path)
    parser.add_argument('--baseline', type=Path, help='default: results/builds/BASE for BUILD = BASE_diag_mirror')
    args = parser.parse_args()
    build = args.build.resolve()
    if args.baseline is None:
        if not build.name.endswith('_diag_mirror'):
            parser.error('BUILD must be BASE_diag_mirror, or give --baseline')
        args.baseline = build.parent / build.name[:-len('_diag_mirror')]
    base = args.baseline.resolve()
    sys.path.insert(0, str(ROOT / 'scripts/hardware'))
    import check_mirror_select
    import diag_mirror_sessions
    c = diag_mirror_sessions.load(build)
    ok0, p0 = guard_pipe0(build / 'compile_local/out', dict(ingress=c['session_rx'], egress=c['session_tx']))
    ok1c, notes1c = check_mirror_select.check_out(build / 'compile_local/out')
    ok1b, notes1b = check_mirror_select.check_out(base / 'compile_local/out')
    ok_eq, eq = pipe1_equivalence(base / 'compile_local/out', build / 'compile_local/out')
    report = dict(schema='c72-diag-mirror-checks-v1', build=build.name,
                  source_sha256=hashlib.sha256((build / 'response_only.p4').read_bytes()).hexdigest(),
                  baseline=base.name, session_config_errors=diag_mirror_sessions.validate(c),
                  pipe0_mirror_guard=dict(passed=ok0, **p0),
                  pipe1_mirror_guard=dict(candidate=dict(passed=ok1c, notes=notes1c), baseline=dict(passed=ok1b, notes=notes1b)),
                  pipe1_equivalence=dict(passed=ok_eq, **eq))
    passed = ok0 and ok1c and ok1b and ok_eq and not report['session_config_errors']
    report['passed'] = passed
    (build / 'diag_mirror_checks.json').write_text(json.dumps(report, indent=1) + '\n')
    print(json.dumps(dict(passed=passed, pipe0=ok0, pipe1_guard=[ok1c, ok1b], pipe1_equivalence=ok_eq,
                          differing=eq['differing_lines'], seeds=eq['exact_match_hash_seed_lines'])))
    return 0 if passed else 1


if __name__ == '__main__':
    sys.exit(main())

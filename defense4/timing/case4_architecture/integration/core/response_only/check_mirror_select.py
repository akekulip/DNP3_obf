#!/usr/bin/env python3
"""Static check of T's (pipe 1) deparser mirror configuration in a compiled build.

  python3 check_mirror_select.py <compile dir containing out/p1/*.bfa> [...]      exit 1 on any failing build

Why (route_ab_01/token_stale_01): Tofino-1's ingress deparser looks up its mirror entry by mirror_type for EVERY
packet. bf-p4c gives the `mirror_type == 0` entry a session id taken from a compiler temporary ($tmpN) that no
action writes, on the assumption it stays 0 (no session). In every production build that temporary shares a
container with md.cur_gen (the live READ generation), so every T pass that does not clone was mirrored to session
cur_gen[9:0]; on the switch only session 7 exists, so while the live READ generation is 7 (mod 1024) every T pass
was copied to PKTGEN_RETURN, the READ clones re-mirrored themselves and fired the READ generator, and copied tokens
were accepted as tokens. Pinning md.cur_gen only moved the temporary next to md.new_gen.

A build passes when no deparser mirror entry other than the clone type can be selected with a session id that
some other field also uses:
  * every non-clone entry's session container holds only that entry's field, OR
  * mirror_type is written to the clone type by an unconditional statement (a hidden table whose hit and miss both
    continue), so the other entries are never selected; then the clone entry's session (md.clone_ses) and
    mirror_type must each be in a container of their own, so the unwritten value is 0 (no session).
"""
import glob
import re
import sys
from pathlib import Path

CLONE_TYPE = 1


def containers(bfa):
    """{container: [field names]} from the first (ingress) live-range listing in the .bfa."""
    out, cur = {}, None
    for line in bfa.splitlines():
        m = re.match(r'^    ([BHW]\d+):\s*$', line)
        if m:
            if m.group(1) in out:          # second listing (egress) starts: stop at the first
                break
            cur = m.group(1)
            out[cur] = []
            continue
        n = re.match(r'^    - \{ name : ([^,]+),', line)
        if n and cur:
            out[cur].append(n.group(1).strip())
        elif cur and not line.startswith('    '):
            cur = None
    return out


def mirror_entries(bfa):
    """(select container, {select value: [(container, field)]}) from the ingress deparser's mirror block."""
    i = bfa.index('\n  mirror:\n')
    block = bfa[i:].split('\n')[2:]
    sel = re.search(r'select: (\S+)', bfa[i:i + 200]).group(1).split('(')[0]
    entries, cur = {}, None
    for line in block:
        if not line.startswith('    '):
            break
        m = re.match(r'^    (\d+):', line)
        if m:
            cur = int(m.group(1)); entries[cur] = []
            continue
        f = re.match(r'^      - ([BHW]\d+)\S*\s*# .*ingress::(\S+)', line)
        if f and cur is not None:
            entries[cur].append((f.group(1), f.group(2)))
    return sel, entries


def unconditional_clone_type(bfa):
    """True if some hidden table whose hit and miss both go to the same next node sets mirror_type to the clone
    type (the statement at the top of apply), i.e. mirror_type is the clone type on every pass."""
    lines = bfa.splitlines()
    for k, line in enumerate(lines):
        if re.search(r'set ig_intr_md_for_dprsr\.mirror_type, %d\b' % CLONE_TYPE, line):
            for j in range(k, max(k - 40, 0), -1):          # the owning table header
                h = re.match(r'^  (?:ternary|exact)_match (tbl_\S+) \d+:', lines[j])
                if h:
                    body = '\n'.join(lines[j:j + 8])
                    hit = re.search(r'hit: \[\s*(\S+)\s*\]', body)
                    miss = re.search(r'miss:\s*(\S+)', body)
                    if hit and miss and hit.group(1) == miss.group(1):
                        return h.group(1)
                    break
    return None


def check(build):
    """A compile directory laid out as <build>/out/p1/*.bfa (the evidence layout)."""
    return check_out(Path(build) / 'out')


def check_out(out_dir):
    """The compiled output directory itself, whatever it is named (the deploy layout uses out_<buildname>):
    reads <out_dir>/p1/*.bfa."""
    bfas = glob.glob(str(Path(out_dir) / 'p1' / '*.bfa'))
    if len(bfas) != 1:
        return False, ['%s: expected one p1/*.bfa, found %d' % (out_dir, len(bfas))]
    bfa = Path(bfas[0]).read_text()
    cont = containers(bfa)
    sel, entries = mirror_entries(bfa)
    notes, shared = [], []
    for value, fields in sorted(entries.items()):
        if not fields:
            continue
        c, field = fields[0]                       # the session id
        others = [n for n in cont.get(c, []) if n != field]
        notes.append('select %d: session %s from %s%s' % (value, field, c, ' shared with %s' % others if others else ''))
        if value != CLONE_TYPE and others:
            shared.append(value)
    init = unconditional_clone_type(bfa)
    notes.append('unconditional mirror_type=%d: %s' % (CLONE_TYPE, init or 'none'))
    if not shared:
        return True, notes
    if init:
        solo = [c for c, _ in entries.get(CLONE_TYPE, [])[:1]] + [sel]
        crowded = {c: cont.get(c) for c in solo if len(cont.get(c, [])) != 1}
        if not crowded:
            notes.append('non-clone entries %s are unreachable; clone session and select containers are solitary' % shared)
            return True, notes
        notes.append('clone session / select containers not solitary: %s' % crowded)
    notes.append('FAIL: non-clone mirror entries %s can be selected with a session id another field writes' % shared)
    return False, notes


if __name__ == '__main__':
    ok_all = True
    for b in sys.argv[1:]:
        ok, notes = check(b)
        ok_all &= ok
        print(('PASS ' if ok else 'FAIL ') + b)
        for n in notes:
            print('   ' + n)
    sys.exit(0 if ok_all else 1)

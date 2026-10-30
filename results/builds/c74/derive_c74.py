#!/usr/bin/env python3
"""Derive the c74 source from c72 (record of how results/builds/c74/response_only.p4 was produced).

  python3 results/builds/c74/derive_c74.py results/builds/c72/response_only.p4 OUT.p4 MANIFEST.json

c74 = c72 + the connection-start loss correction, as const-entry rows only. No action, key, register, header,
metadata field or control-flow line changes; every edit stays inside an existing line, so line numbers (and the
bf-p4c names derived from them) equal c72's. Each edit asserts its exact match count.

  H1  busy_t: READ (kind 9), SELECT (5) and OPERATE (7) take the existing master-direction retry path instead of
      busy_drop: busy_retry_ack on the native pass (envelope epoch, generation, origin wire_ack/normalized_epoch,
      budget n_RETRY_BUDGET), busy_retry_rst_next while the budget lasts, busy_exhausted at budget 1. Exactly the
      rows kind 3 (master pure ACK) already has. retry_stale (row 1) still drops a retry of an old epoch.
      guard: the matching go_retry(9/5/7) rows for the retry pass (m.retry == 1), with the same CRC/profile columns
      as each kind's go_new row, placed before the catch-all go_stale rows.
      SYN (1), SYN-ACK (2) and replay (12) keep busy_drop (see README).
  H2  first_event: a master pure ACK (flags exactly 0x10, direction 1, same_syn 0) that finds owner 0xd/0xe with
      client_diff exactly -25 or -27 (its sequence is the first octet of the admitted 25/27-octet READ) and
      server_diff exactly 0 (its ACK is the relay's current native sequence) is forward_original (event code 8),
      the existing old-ACK forward. Every other kind-3 miss still takes the default NoAction (code 255, abort).
"""
import difflib
import hashlib
import json
import sys
from pathlib import Path

H1_BUSY_OLD = '(8w5,_,_):busy_drop();(8w7,_,_):busy_drop();(8w9,_,_):busy_drop();'
H1_BUSY_NEW = ''.join('(8w%d,2w0,_):busy_retry_ack();(8w%d,2w1,6w1):busy_exhausted();(8w%d,2w1,_):busy_retry_rst_next();'
                      % (k, k, k) for k in (5, 7, 9))
GUARD_ANCHOR = '(2w0,8w11,8w0,2w2,1w1,1w1,8w1,1w0,16w0x993a,16w0x993a,16w0x993a,16w0x993a,_,2w1):go_retry(8w11);'
GUARD_NEW = ('(2w0,8w9,8w0,2w1,1w1,1w1,8w1,1w0,16w0x993a,16w0x993a,_,_,_,2w1):go_retry(8w9);'
             '(2w0,8w5,8w0,2w1,1w1,1w1,8w1,1w0,16w0x993a,16w0x993a,_,16w0x993a,_,2w1):go_retry(8w5);'
             '(2w0,8w7,8w0,2w1,1w1,1w1,8w1,1w0,16w0x993a,16w0x993a,_,16w0x993a,_,2w1):go_retry(8w7);')
# The native go_new rows the retry rows copy (columns 0-12 identical, retry column 2w1 instead of _).
GUARD_NATIVE = ('(2w0,8w9,8w0,2w1,1w1,1w1,8w1,1w0,16w0x993a,16w0x993a,_,_,_,_):go_new(8w9);',
                '(2w0,8w5,8w0,2w1,1w1,1w1,8w1,1w0,16w0x993a,16w0x993a,_,16w0x993a,_,_):go_new(8w5);',
                '(2w0,8w7,8w0,2w1,1w1,1w1,8w1,1w0,16w0x993a,16w0x993a,_,16w0x993a,_,_):go_new(8w7);')
H2_ANCHOR = ('(8w3,1w0,32w0xc0000&&&32w0xffff0000,32w0x0&&&32w0xffffffff,32w0x0&&&32w0xffffffff,'
             '_,_,_,_,_,_,_,_,_,_,_):forward_original();')
H2_NEW = ('/* c74: the late handshake ACK, old pure ACK at the admitted READ start, forwarded unchanged */'
          + ''.join('(8w3,1w0,32w0x%x0000&&&32w0xffff0000,32w0x%08x,32w0x00000000,2w1,8w0x10,_,1w0,_,_,_,_,_,_,_)'
                    ':forward_original();' % (owner, (-length) & 0xffffffff)
                    for length in (25, 27) for owner in (0xd, 0xe)))
BUSY_COMMENT = ' /* c74: READ/SELECT/OPERATE retry through n_RETRY_BUDGET like kind 3; SYN, SYN-ACK, replay drop */'
SIZES = (('table busy_t{', 'size=22;', 'size=28;'), ('table guard{', 'size=54;', 'size=57;'),
         ('@stage(9) table first_event{', 'size=401;', 'size=405;'))


def replace_once(text, old, new, log, label):
    count = text.count(old)
    assert count == 1, (label, old[:80], count)
    log.append(dict(edit=label, old=old, new=new, match_count=count))
    return text.replace(old, new)


def derive(text):
    log = []
    for row in GUARD_NATIVE:   # the copied rows exist exactly once
        assert text.count(row) == 1, row
    text = replace_once(text, H1_BUSY_OLD, H1_BUSY_NEW, log, 'H1 busy_t request rows')
    text = replace_once(text, GUARD_ANCHOR, GUARD_ANCHOR + GUARD_NEW, log, 'H1 guard retry rows')
    text = replace_once(text, H2_ANCHOR, H2_ANCHOR + H2_NEW, log, 'H2 first_event late handshake ACK rows')
    for head, old, new in SIZES:
        start = text.index(head)
        end = text.index('}', text.index(old, start))
        assert text.count(head) == 1 and text[start:end].count(old) == 1, head
        at = text.index(old, start)
        text = text[:at] + new + text[at + len(old):]
        log.append(dict(edit='size ' + head, old=old, new=new, match_count=1))
    line = next(i for i, l in enumerate(text.split('\n')) if l.startswith('table busy_t{'))
    lines = text.split('\n')
    assert lines[line].endswith('const default_action=busy_pass();}')
    lines[line] += BUSY_COMMENT
    log.append(dict(edit='busy_t comment', line=line + 1, new=BUSY_COMMENT, match_count=1))
    return '\n'.join(lines), log


def main():
    source, out, manifest = (Path(p) for p in sys.argv[1:4])
    before = source.read_text()
    after, log = derive(before)
    assert before.count('\n') == after.count('\n'), 'c74 must keep c72 line numbers'
    out.write_text(after)
    changed = [i + 1 for i, (a, b) in enumerate(zip(before.split('\n'), after.split('\n'))) if a != b]
    diff = ''.join(difflib.unified_diff(before.splitlines(True), after.splitlines(True), 'c72/response_only.p4',
                                        'c74/response_only.p4', n=0))
    manifest.write_text(json.dumps(dict(
        source=str(source), source_sha256=hashlib.sha256(before.encode()).hexdigest(),
        output_sha256=hashlib.sha256(after.encode()).hexdigest(), lines=after.count('\n'),
        changed_c72_lines=changed, edits=log, unified_diff_sha256=hashlib.sha256(diff.encode()).hexdigest()),
        indent=1) + '\n')
    sys.stdout.write(diff)


if __name__ == '__main__':
    main()

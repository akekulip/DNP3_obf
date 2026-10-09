"""Diagnostic only (compile-only): wrap apply-block statements into one-action tables pinned with
@stage(N), to test whether a 12-stage placement exists at all. Never the production source.

usage: pin_variant.py <src.p4> <spec.json: [[statement, stage], ...]> <out.p4>
"""
import json
import sys
from pathlib import Path

src = Path(sys.argv[1]).read_text()
spec = json.loads(Path(sys.argv[2]).read_text())
marker = '\n    apply {\n        ig_tm_md.bypass_egress'
at = src.index(marker)
head, body = src[:at], src[at:]
decls = []
for i, (stmt, stage) in enumerate(spec):
    n = body.count(stmt)
    assert n >= 1, stmt
    for k in range(n):
        name = 'pin_%d_%d' % (i, k)
        decls.append('    action %s_a() { %s }\n'
                     '    @stage(%d) table %s { actions = { %s_a; } default_action = %s_a(); size = 1; }\n'
                     % (name, stmt, stage, name, name, name))
        body = body.replace(stmt, name + '.apply();', 1)
Path(sys.argv[3]).write_text(head + '\n' + ''.join(decls) + body)

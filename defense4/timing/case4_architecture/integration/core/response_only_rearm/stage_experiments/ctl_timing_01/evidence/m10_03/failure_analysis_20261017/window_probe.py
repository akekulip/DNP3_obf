"""Does a held response escape between N's reset cancellation and T's close? Source interpreter, m9 and m10."""
import sys
from pathlib import Path
CT = Path(sys.argv[1]); sys.path.insert(0, str(CT / 'tests'))
import test_m6_lifecycle as l
import contention_source as cs
import test_reset_race as r
for name in ('m9_01', 'm10_03'):
    src = CT / 'evidence' / name / 'response_only.p4'
    rows = []
    for kind in ('READ', 'SELECT'):
        # find this kind's response release time on an undisturbed run
        p0, f0, _ = l.held(src, kind)
        rel = [t for t, raw in p0.to_master() if len(raw) == cs.RESPONSE_LEN]
        p1, ta, _ = l._schedule(src, kind); t_rel = rel[0] - 0
        for back in range(1, 40):                        # RST arrival `back` laps before the release
            p, ta, _ = l._schedule(src, kind)
            p.at(t_rel - back * 1000 + 2, cs.vectors.packet(20, *l.RST[kind]), master=True)
            p.settle()
            resets = r.relayed_resets(p)
            after = [t for t, raw in p.to_master() if len(raw) == cs.RESPONSE_LEN and resets and t >= resets[0][0]]
            leaked_before = [t for t, raw in p.to_master() if len(raw) == cs.RESPONSE_LEN and (not resets or t < resets[0][0])]
            if after or (resets and leaked_before):
                rows.append((kind, back, 'after' if after else 'before-relay', l.owner_state(p)))
    print(name, rows[:20], 'cases', len(rows))

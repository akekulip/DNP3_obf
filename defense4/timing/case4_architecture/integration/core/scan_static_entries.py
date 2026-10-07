#!/usr/bin/env python3
"""List tables whose const-entry count exceeds the declared size in compiled context.json files
(such a build compiles but the driver refuses to load it: 'Not enough space adding static entry N').
usage: scan_static_entries.py <out dir or evidence root> ...   exit 1 if any offender"""
import glob, json, os, sys
bad = 0
for root in sys.argv[1:]:
    paths = glob.glob(os.path.join(root, '*', 'context.json')) or \
        glob.glob(os.path.join(root, '**', 'out', '*', 'context.json'), recursive=True)
    for p in sorted(paths):
        for t in json.load(open(p))['tables']:
            n = len(t.get('static_entries') or [])
            if n > t['size']:
                print('%s: %s size=%d static_entries=%d' % (p, t['name'], t['size'], n)); bad = 1
sys.exit(bad)

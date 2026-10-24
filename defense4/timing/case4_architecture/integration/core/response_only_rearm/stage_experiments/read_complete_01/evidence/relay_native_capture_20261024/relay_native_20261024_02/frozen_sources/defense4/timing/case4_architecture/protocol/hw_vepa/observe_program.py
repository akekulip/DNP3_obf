#!/usr/bin/env python3
"""Print the program the running bf_switchd loaded, as one JSON line. Runs on the switch host; stdlib only.

  observe_program.py     ->  {"program": "case4_response_path", "conf": "/.../conf.json"}

Reads --conf-file from `ps` (exactly one bf_switchd must be running, as hw/bringup_composite.py requires) and
the program name from that conf's p4_devices[0].p4_programs[0]. Read-only."""
import json
import os
import subprocess
import sys


def running_confs(ps_text):
    confs = []
    for line in ps_text.splitlines():
        words = line.split()
        if not words or os.path.basename(words[0]) != 'bf_switchd':
            continue
        for i, w in enumerate(words):
            if w == '--conf-file' and i + 1 < len(words):
                confs.append(words[i + 1])
            elif w.startswith('--conf-file='):
                confs.append(w.split('=', 1)[1])
    return confs


def main():
    out = subprocess.run(['ps', '-eo', 'args'], stdout=subprocess.PIPE, universal_newlines=True, check=True).stdout
    confs = running_confs(out)
    if len(confs) != 1:
        sys.exit('expected exactly one running bf_switchd with --conf-file, found %d' % len(confs))
    prog = json.load(open(confs[0]))['p4_devices'][0]['p4_programs'][0]['program-name']
    print(json.dumps({'program': prog, 'conf': confs[0]}))


if __name__ == '__main__':
    main()

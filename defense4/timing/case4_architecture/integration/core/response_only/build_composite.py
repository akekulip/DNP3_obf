#!/usr/bin/env python3
"""Compose and compile the response-only composite, and refuse a build that fails a guard.

  python3 build_composite.py <new evidence dir> <name> [--sdk local|switch|both] [compose.py port flags...]

Writes <dir>/source_<name>/response_only.p4 (+ inputs.json) with compose.py and the given port flags, compiles it
with case4_architecture/build.py (SDE 9.13.1, <dir>/<name>_compile_local) and/or installed_sdk_build.py (the switch's
9.13.2, compile only, <dir>/<name>_compile_switch_9132), then runs every build guard on each output:

  * check_mirror_select.check: T's deparser can never mirror a pass that did not ask for a clone
    (route_ab_01/token_stale_01). A failing build is NOT for loading.

The guard result is written next to each build (mirror_guard.txt). Exit status 0 only if every compile exited 0
and every guard passed. Refuses an existing output directory (evidence directories are never overwritten).

For the hardware installer (hw/, not edited here): call check_mirror_select.check(<build dir>) and refuse to load
when it returns False, e.g.
    sys.path.insert(0, '<integration>/core/response_only'); import check_mirror_select
    ok, notes = check_mirror_select.check(build_dir)
"""
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CASE4 = HERE.parent.parent.parent
sys.path.insert(0, str(HERE))
import check_mirror_select  # noqa: E402

GUARDS = (('mirror_select', check_mirror_select.check),)


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    out, name, rest = Path(argv[0]).resolve(), argv[1], argv[2:]
    sdk = 'both'
    if '--sdk' in rest:
        i = rest.index('--sdk')
        sdk = rest[i + 1]
        rest = rest[:i] + rest[i + 2:]
    src_dir = out / ('source_%s' % name)
    if src_dir.exists():
        print('refusing: %s exists' % src_dir)
        return 2
    src_dir.mkdir(parents=True)
    src = src_dir / 'response_only.p4'
    subprocess.run([sys.executable, str(HERE / 'compose.py'), str(src)] + rest, check=True)
    builds = []
    if sdk in ('local', 'both'):
        builds.append((out / ('%s_compile_local' % name), [sys.executable, str(CASE4 / 'build.py'), str(src), None, '--timeout', '600']))
    if sdk in ('switch', 'both'):
        builds.append((out / ('%s_compile_switch_9132' % name), [sys.executable, str(CASE4 / 'installed_sdk_build.py'), str(src), None]))
    procs = []
    for dest, cmd in builds:
        cmd[cmd.index(None)] = str(dest)
        log = open(str(dest) + '.stdout', 'w')
        procs.append((dest, subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT, cwd=str(CASE4)), log))
    ok_all = True
    for dest, proc, log in procs:
        rc = proc.wait()
        log.close()
        with open(str(dest) + '.stdout', 'a') as f:
            f.write('exit %d\n' % rc)
        print('%s: compile exit %d' % (dest.name, rc))
        if rc != 0:
            ok_all = False
            continue
        lines = []
        for gname, guard in GUARDS:
            ok, notes = guard(dest)
            ok_all &= ok
            lines.append('%s %s' % ('PASS' if ok else 'FAIL', gname))
            lines += ['   ' + n for n in notes]
        (dest / 'mirror_guard.txt').write_text('\n'.join(lines) + '\n')
        print('\n'.join('   ' + l for l in lines))
    print('ALL BUILDS AND GUARDS PASS' if ok_all else 'REFUSED: a compile or a guard failed')
    return 0 if ok_all else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

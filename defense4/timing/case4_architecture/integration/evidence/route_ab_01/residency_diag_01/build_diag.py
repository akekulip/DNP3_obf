#!/usr/bin/env python3
"""Compose and locally compile the RESIDENCY DIAGNOSTIC composite: the sbo_admission_01 program (b8a35c6c6)
with T replaced by read/read_queue_timing_diag.p4 (per-role re-wait + per-role blocker-lap counters) and
nothing else changed. Same ports as sbo_admission_01 (port_map.HARDWARE_SHARED_PORT: relay 9, N_ACK_RETURN 48,
T_IN 180, HB_RETURN 181, HELD_RETURN 182), so the only difference from the loaded build is the instrumentation.

  python3 build_diag.py                 # regen diag P4, compose, write source_hw/, compile local 9.13.1
The 9.13.2 switch compile is a separate step (installed_sdk_build.py on the switch host); this script prints
the composed source path and the exact command for it.
"""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
INTEG = HERE.parents[2]
RESP = INTEG / 'core' / 'response_only'
READ = INTEG / 'read'
sys.path[:0] = [str(RESP), str(READ)]
import make_diag_t  # noqa: E402
import compose  # noqa: E402
import compose_t_response as ct  # noqa: E402
import port_map as pm  # noqa: E402

LOCAL_BFP4C = '/home/philip/bf-sde-9.13.1/install/bin/bf-p4c'
SWITCH_COMPILER = '/home/decps/Downloads/bf-sde-9.13.2/install/bin/bf-p4c'


def main():
    diag = READ / 'read_queue_timing_diag.p4'
    diag.write_text(make_diag_t.generate(make_diag_t.SRC.read_text()))
    ct.T_SRC = diag                                   # compose reads and hashes this; everything else is production
    src, meta = compose.generate(ports=pm.HARDWARE_SHARED_PORT)

    source_dir = HERE / 'source_hw'
    source_dir.mkdir(parents=True, exist_ok=True)
    p4 = source_dir / 'response_only.p4'
    p4.write_text(src)
    (source_dir / 'response_only.inputs.json').write_text(json.dumps(meta, indent=2) + '\n')
    print('composed', p4, '| T source:', meta['inputs'].get('read_queue_timing_diag.p4', '(missing!)')[:16],
          '| ports:', meta['port_map'])

    out = HERE / 'local_compile' / 'out'
    out.mkdir(parents=True, exist_ok=True)
    log = HERE / 'local_compile' / 'compile.log'
    cmd = [LOCAL_BFP4C, '--target', 'tofino', '--arch', 'tna', '-g', '-o', str(out), str(p4)]
    print('compiling (9.13.1):', ' '.join(cmd))
    with open(log, 'w') as f:
        rc = subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT).returncode
    print('local compile exit', rc, '(log', log, ')')
    if rc == 0:
        hashes = {rel: hashlib.sha256((out / rel).read_bytes()).hexdigest()
                  for rel in ('bfrt.json', 'p0/tofino.bin', 'p1/tofino.bin') if (out / rel).is_file()}
        (HERE / 'local_compile' / 'manifest.json').write_text(json.dumps(
            dict(compiler='bf-p4c 9.13.1 (local)', artifact_sha256=hashes), indent=2) + '\n')
        for rel, h in hashes.items():
            print('  %s  %s' % (h, rel))
    print('\n9.13.2 switch compile (run on the switch host, not here):')
    print('  python3 %s %s %s' % (INTEG.parent / 'installed_sdk_build.py', p4, HERE / 'hw_compile_switch_9132'))
    return rc


if __name__ == '__main__':
    sys.exit(main())

#!/usr/bin/env python3
"""Build the repeated-SBO endpoint fork against the pinned OpenDNP3 tree (software endpoint only).

Source: sources/SocketGatePad58B.cpp, the candidate_endpoint fork (pre-READ grace) plus CASE4_SBO_CYCLES and
append-only per-command records. The pinned baseline sources and the earlier endpoint builds are not modified;
this writes only build/ beside this file (git-ignored) and records a manifest with every input hash.

It also builds sources/SocketGateReadSchedule.cpp (the same fork plus the opt-in CASE4_READ_SCHEDULE / CASE4_DB
READ-class schedule; README.md) into build/case4_socket_gate_read_schedule against the same library, and records it
under read_schedule_endpoint. case4_socket_gate_pad58b is built exactly as before.
"""
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
TREE = Path('/tmp/dnp3-case4-endpoint-controls-20261012-01')
PIN = '4648fcb898456d1cb70b5baecc38cc256c859c2e'
LIB_SHA = '6b99199ec4878f55a20cf43c6fc6ed47f50fadb7afbbdbabec71b53334e69c72'
PARENT = HERE.parent / 'candidate_endpoint/sources'
PARENT_PINS = {'SocketGatePad58B.cpp': '08ff3cb7d47c795a2b8bccd88f73abcaa30760bbcd7d5fea7264b25b5def0d0f',
               'DecoyGateCommandHandler.h': 'e1070d8de2e60fac3eb6e4e640eeed9bf857531f819732ac680f54407923d2d2'}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def compile_binary(source, binary, output):
    """Compile one endpoint source against the copied pinned library; fail on any compiler output."""
    compiler = Path('/usr/bin/c++')
    command = [str(compiler), '-O3', '-DNDEBUG', '-Wall', '-I' + str(TREE / 'source/cpp/lib/include'),
               str(source), str(output / 'lib/libopendnp3.so'),
               '-Wl,-rpath,$ORIGIN/lib', '-o', str(output / binary)]
    result = subprocess.run(command, capture_output=True, text=True)
    (output / ('build.log' if binary == 'case4_socket_gate_pad58b' else binary + '.build.log')).write_text(
        result.stdout + result.stderr)
    result.check_returncode()
    if result.stderr.strip():
        raise ValueError('compiler warnings: %s' % result.stderr[:500])
    return compiler, command


def main():
    library = TREE / 'build/cpp/lib/libopendnp3.so'
    if not library.is_file():
        raise SystemExit('pinned OpenDNP3 build missing: %s (rebuild OpenDNP3 %s there first)' % (library, PIN))
    if sha(library) != LIB_SHA:
        raise ValueError('pinned OpenDNP3 library identity mismatch')
    for name, digest in PARENT_PINS.items():
        if sha(PARENT / name) != digest:
            raise ValueError('parent endpoint source %s changed; it is a pinned record' % name)
    if sha(HERE / 'sources/DecoyGateCommandHandler.h') != PARENT_PINS['DecoyGateCommandHandler.h']:
        raise ValueError('command handler must be byte-identical to its pinned source')
    output = HERE / 'build'
    (output / 'lib').mkdir(parents=True, exist_ok=True)
    shutil.copy2(library, output / 'lib/libopendnp3.so')
    compiler, command = compile_binary(HERE / 'sources/SocketGatePad58B.cpp', 'case4_socket_gate_pad58b', output)
    _, schedule_command = compile_binary(HERE / 'sources/SocketGateReadSchedule.cpp',
                                         'case4_socket_gate_read_schedule', output)
    lib_line = sha(output / 'lib/libopendnp3.so') + '  ./libopendnp3.so\n'
    manifest = dict(scope='repeated SELECT/OPERATE cycles on one connection; software endpoint only',
                    opendnp3_commit=PIN, command=command, compiler=str(compiler.resolve()),
                    compiler_version=subprocess.run([str(compiler), '--version'], capture_output=True, text=True,
                                                    check=True).stdout.strip(),
                    binary_sha256=sha(output / 'case4_socket_gate_pad58b'),
                    library_sha256=sha(output / 'lib/libopendnp3.so'),
                    library_directory_sha256=hashlib.sha256(lib_line.encode()).hexdigest(),
                    library_directory_hash_recipe='cd lib && find . -type f | sort | xargs sha256sum | sha256sum',
                    source_hashes={name: sha(HERE / 'sources' / name) for name in PARENT_PINS},
                    parent_source_hashes=PARENT_PINS,
                    read_schedule_endpoint=dict(
                        scope='the same fork plus the opt-in READ-class schedule (CASE4_READ_SCHEDULE=rotate4|mixed_full|'
                              'mixed|full), database (CASE4_DB=base|large) and the strict declared-padding check '
                              '(CASE4_PAD_EXPECT); unset, its wire bytes are the existing workload',
                        command=schedule_command,
                        binary_sha256=sha(output / 'case4_socket_gate_read_schedule'),
                        library_sha256=sha(output / 'lib/libopendnp3.so'),
                        library_directory_sha256=hashlib.sha256(lib_line.encode()).hexdigest(),
                        source_hashes={name: sha(HERE / 'sources' / name)
                                       for name in ('SocketGateReadSchedule.cpp', 'DecoyGateCommandHandler.h')},
                        derived_from={'SocketGatePad58B.cpp': sha(HERE / 'sources/SocketGatePad58B.cpp')},
                        fixture_from='core/response_only_rearm/stage_experiments/full_read_01/endpoint/FullReadGate.cpp'))
    (output / 'build_manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps(manifest, indent=2))


if __name__ == '__main__':
    main()

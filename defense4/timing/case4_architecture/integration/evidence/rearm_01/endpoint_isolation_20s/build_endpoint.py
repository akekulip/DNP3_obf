#!/usr/bin/env python3
"""Build the opt-in 20 s isolation endpoint against the already pinned OpenDNP3 tree.

Lineage: tracked candidate_endpoint source (08ff..., pre-READ cap 5000) -> endpoint_barrier_10s
(f892..., cap 10000, the pinned Vision barrier 8270...) -> this fixture. The build refuses unless the
parent sources carry their pinned hashes and isolation_20s.patch applied to the 10 s parent reproduces
sources/SocketGatePad58B.cpp byte for byte. Compiler, flags, library and tree are the 10 s build's.
"""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
TREE = Path('/tmp/dnp3-case4-endpoint-controls-20261012-01')
PIN = '4648fcb898456d1cb70b5baecc38cc256c859c2e'
LIB_SHA = '6b99199ec4878f55a20cf43c6fc6ed47f50fadb7afbbdbabec71b53334e69c72'
OLD_BINARY_SHA = '7446e921d0ef28ae06bd31165d0048a0612ccf6590f4080e72e2ea939f9579c9'
ORIGIN = HERE.parents[4] / 'framework/size/endpoint_gate'
BASE_PINS = {'SocketGatePad58B.cpp': 'aa574dbdf6fac27fa19364b5f46bc75514b203dd161b132faf07b2c46bd346e9',
             'DecoyGateCommandHandler.h': 'e1070d8de2e60fac3eb6e4e640eeed9bf857531f819732ac680f54407923d2d2'}
TRACKED = HERE.parent / 'candidate_endpoint/sources'
TRACKED_SOCKET_SHA = '08ff3cb7d47c795a2b8bccd88f73abcaa30760bbcd7d5fea7264b25b5def0d0f'
PARENT = HERE.parent / 'endpoint_barrier_10s'
PARENT_PINS = {'SocketGatePad58B.cpp': 'f892c9a7753b2c207ae7433177d07422575b3d0bcffe8a599e044d6576f9c342',
               'DecoyGateCommandHandler.h': BASE_PINS['DecoyGateCommandHandler.h']}
PARENT_BINARY_SHA = '8270132ea76123e72cb5f4d196d5726c49f5f95d2516a468fc882bed84127158'
PATCH = HERE / 'isolation_20s.patch'
CANDIDATE_PINS = {'SocketGatePad58B.cpp': 'c99bc20d77c4b4b692d8731a2222d9ef403cf3602dbc4a93a77fe83ad65b0d90',
                  'DecoyGateCommandHandler.h': BASE_PINS['DecoyGateCommandHandler.h']}
COMPILER = Path('/usr/bin/c++')


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def reproduce_from_patch():
    """Apply the recorded patch to the 10 s parent in a scratch directory; return the patched bytes."""
    with tempfile.TemporaryDirectory() as scratch:
        out = Path(scratch) / 'SocketGatePad58B.cpp'
        subprocess.run(['patch', '--quiet', '--batch', '-o', str(out), str(PARENT / 'sources/SocketGatePad58B.cpp'),
                        str(PATCH)], check=True, capture_output=True, text=True)
        return out.read_bytes()


def inputs():
    library = TREE / 'build/cpp/lib/libopendnp3.so'
    paths = [ORIGIN / name for name in BASE_PINS] + [library, TREE / 'build/case4_socket_gate_pad58b',
             TRACKED / 'SocketGatePad58B.cpp', PARENT / 'build/case4_socket_gate_pad58b'] + \
        [PARENT / 'sources' / name for name in PARENT_PINS]
    return {str(path): sha(path) for path in paths}


def main():
    library = TREE / 'build/cpp/lib/libopendnp3.so'
    before = inputs()
    if sha(library) != LIB_SHA or sha(TREE / 'build/case4_socket_gate_pad58b') != OLD_BINARY_SHA or \
            any(sha(ORIGIN / name) != digest for name, digest in BASE_PINS.items()):
        raise ValueError('pinned controls source/binary/library identity mismatch')
    if sha(TRACKED / 'SocketGatePad58B.cpp') != TRACKED_SOCKET_SHA:
        raise ValueError('tracked candidate_endpoint source identity mismatch')
    if any(sha(PARENT / 'sources' / name) != digest for name, digest in PARENT_PINS.items()) or \
            sha(PARENT / 'build/case4_socket_gate_pad58b') != PARENT_BINARY_SHA:
        raise ValueError('10 s parent source/binary identity mismatch')
    if reproduce_from_patch() != (HERE / 'sources/SocketGatePad58B.cpp').read_bytes():
        raise ValueError('isolation_20s.patch applied to the 10 s parent does not reproduce sources/')
    for name, digest in CANDIDATE_PINS.items():
        if digest is not None and sha(HERE / 'sources' / name) != digest:
            raise ValueError('candidate 20 s endpoint source identity mismatch: ' + name)
    output = HERE / 'build'
    output.mkdir(exist_ok=True)
    (output / 'lib').mkdir(exist_ok=True)
    shutil.copy2(library, output / 'lib/libopendnp3.so')
    command = [str(COMPILER), '-O3', '-DNDEBUG', '-I' + str(TREE / 'source/cpp/lib/include'),
               str(HERE / 'sources/SocketGatePad58B.cpp'), str(output / 'lib/libopendnp3.so'),
               '-Wl,-rpath,$ORIGIN/lib', '-o', str(output / 'case4_socket_gate_pad58b')]
    result = subprocess.run(command, capture_output=True, text=True)
    (output / 'build.log').write_text(result.stdout + result.stderr)
    result.check_returncode()
    after = inputs()
    if before != after:
        raise ValueError('baseline inputs changed during candidate build')
    headers = TREE / 'source/cpp/lib/include'
    header_hashes = {str(path.relative_to(headers)): sha(path) for path in sorted(headers.rglob('*')) if path.is_file()}
    lib_line = sha(output / 'lib/libopendnp3.so') + '  ./libopendnp3.so\n'
    binary = output / 'case4_socket_gate_pad58b'
    manifest = dict(
        scope='opt-in 20 s pre-READ pause with endpoint-local release permission; isolation tests only; software only',
        opendnp3_commit=PIN, source_tree=str(TREE / 'source'), command=command, compiler=str(COMPILER.resolve()),
        compiler_sha256=sha(COMPILER), compiler_version=subprocess.run([str(COMPILER), '--version'],
                                                                       capture_output=True, text=True,
                                                                       check=True).stdout.strip(),
        header_tree_sha256=hashlib.sha256(json.dumps(header_hashes, sort_keys=True).encode()).hexdigest(),
        binary_path=str(binary), binary_sha256=sha(binary),
        library_sha256=sha(output / 'lib/libopendnp3.so'),
        library_directory_sha256=hashlib.sha256(lib_line.encode()).hexdigest(),
        library_directory_hash_recipe='cd lib && find . -type f | sort | xargs sha256sum | sha256sum',
        lineage=dict(tracked_candidate_endpoint_socket_sha256=TRACKED_SOCKET_SHA,
                     parent_10s_sources=PARENT_PINS, parent_10s_binary_sha256=PARENT_BINARY_SHA),
        patch=str(PATCH.name), patch_sha256=sha(PATCH), patch_reproduces_sources=True,
        changed_source_policy=('SocketGatePad58B.cpp = 10 s parent + isolation_20s.patch: (a) CASE4_PRE_READ_GRACE_MS '
                               'cap 10000 -> 20000; (b) opt-in CASE4_PRE_READ_PERMIT gate between the pause and the '
                               'first Scan (rc 75 no permit by deadline, rc 76 permit refused); without '
                               'CASE4_PRE_READ_PERMIT the behaviour is the parent\'s'),
        permit_grace_ms=2000, permit_rc=dict(absent_or_late=75, refused=76),
        source_hashes={name: sha(HERE / 'sources' / name) for name in CANDIDATE_PINS},
        baseline_before=before, baseline_after=after, baseline_unchanged=before == after)
    (output / 'build_manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    (HERE / 'manifest').mkdir(exist_ok=True)
    shutil.copy2(output / 'build_manifest.json', HERE / 'manifest/build_manifest.json')
    print(json.dumps(manifest, indent=2))


if __name__ == '__main__':
    main()

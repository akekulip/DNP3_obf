#!/usr/bin/env python3
"""Build only the isolated endpoint against the already pinned OpenDNP3 tree."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
TREE = Path('/tmp/dnp3-case4-endpoint-controls-20261012-01')
PIN = '4648fcb898456d1cb70b5baecc38cc256c859c2e'
LIB_SHA = '6b99199ec4878f55a20cf43c6fc6ed47f50fadb7afbbdbabec71b53334e69c72'
OLD_BINARY_SHA = '7446e921d0ef28ae06bd31165d0048a0612ccf6590f4080e72e2ea939f9579c9'
ORIGIN = HERE.parents[4] / 'framework/size/endpoint_gate'
BASE_PINS = {'SocketGatePad58B.cpp': 'aa574dbdf6fac27fa19364b5f46bc75514b203dd161b132faf07b2c46bd346e9',
             'DecoyGateCommandHandler.h': 'e1070d8de2e60fac3eb6e4e640eeed9bf857531f819732ac680f54407923d2d2'}
PARENT_SOCKET_SHA = '08ff3cb7d47c795a2b8bccd88f73abcaa30760bbcd7d5fea7264b25b5def0d0f'
CANDIDATE_PINS = {'SocketGatePad58B.cpp': 'f892c9a7753b2c207ae7433177d07422575b3d0bcffe8a599e044d6576f9c342',
                  'DecoyGateCommandHandler.h': BASE_PINS['DecoyGateCommandHandler.h']}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    library = TREE / 'build/cpp/lib/libopendnp3.so'
    old_binary = TREE / 'build/case4_socket_gate_pad58b'
    before = {str(ORIGIN/name): sha(ORIGIN/name) for name in BASE_PINS}
    before.update({str(library): sha(library), str(old_binary): sha(old_binary)})
    if sha(library) != LIB_SHA or sha(old_binary) != OLD_BINARY_SHA or any(sha(ORIGIN/name) != digest for name,digest in BASE_PINS.items()):
        raise ValueError('pinned controls source/binary/library identity mismatch')
    if any(sha(HERE / 'sources' / name) != digest for name, digest in CANDIDATE_PINS.items()):
        raise ValueError('candidate 10s endpoint source identity mismatch')
    output = HERE / 'build'; output.mkdir(exist_ok=True)
    (output/'lib').mkdir(exist_ok=True)
    shutil.copy2(library, output/'lib/libopendnp3.so')
    compiler = Path('/usr/bin/c++')
    command = [str(compiler), '-O3', '-DNDEBUG', '-I'+str(TREE/'source/cpp/lib/include'),
               str(HERE/'sources/SocketGatePad58B.cpp'), str(output/'lib/libopendnp3.so'),
               '-Wl,-rpath,$ORIGIN/lib', '-o', str(output/'case4_socket_gate_pad58b')]
    result = subprocess.run(command, capture_output=True, text=True)
    (output/'build.log').write_text(result.stdout + result.stderr)
    result.check_returncode()
    after = {path: sha(path) for path in before}
    if before != after:
        raise ValueError('baseline inputs changed during candidate build')
    headers = TREE/'source/cpp/lib/include'
    header_hashes = {str(path.relative_to(headers)): sha(path) for path in sorted(headers.rglob('*')) if path.is_file()}
    lib_line = sha(output/'lib/libopendnp3.so') + '  ./libopendnp3.so\n'
    manifest = dict(scope='isolated pre-READ readiness control; software only', opendnp3_commit=PIN,
                    source_tree=str(TREE/'source'), command=command, compiler=str(compiler.resolve()),
                    compiler_sha256=sha(compiler), compiler_version=subprocess.run([str(compiler),'--version'],
                    capture_output=True,text=True,check=True).stdout.strip(),
                    header_tree_sha256=hashlib.sha256(json.dumps(header_hashes,sort_keys=True).encode()).hexdigest(),
                    binary_path=str(output/'case4_socket_gate_pad58b'), binary_sha256=sha(output/'case4_socket_gate_pad58b'),
                    library_sha256=sha(output/'lib/libopendnp3.so'),
                    library_directory_sha256=hashlib.sha256(lib_line.encode()).hexdigest(),
                    library_directory_hash_recipe='cd lib && find . -type f | sort | xargs sha256sum | sha256sum',
                    parent_socket_sha256=PARENT_SOCKET_SHA,
                    changed_source_policy='SocketGatePad58B.cpp copied from parent 08ff source; only pre-READ max 5000->10000',
                    source_hashes={name: sha(HERE/'sources'/name) for name in CANDIDATE_PINS},
                    baseline_before=before, baseline_after=after, baseline_unchanged=before == after)
    (output/'build_manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps(manifest,indent=2))


if __name__ == '__main__':
    main()

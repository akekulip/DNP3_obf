#!/usr/bin/env python3
"""Fresh pinned OpenDNP3 builds; import is inert and every result is retained."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile

PIN = '4648fcb898456d1cb70b5baecc38cc256c859c2e'
HERE = Path(__file__).resolve().parent
FRAMEWORK = HERE.parents[1]
REPO = HERE.parents[4]
sys.path.insert(0, str(FRAMEWORK))
from runner.evidence import reserve_run, sha256


def build_gate(run, source_repo, work, dependency_cache=None, jobs=2, sockets=False, qualifier=False, pad58=False, pad58b=False):
    source_repo, work = Path(source_repo).resolve(), Path(work).resolve()
    for protected in (REPO.resolve(), source_repo):
        if work == protected or protected in work.parents:
            raise ValueError('build work must be outside both source trees')
    work.mkdir(parents=True, exist_ok=False)
    run.write_json('build_work.json', {'path': str(work), 'retained': True})
    status_before = subprocess.check_output(['git', '-C', str(source_repo), 'status', '--porcelain'])
    archive = subprocess.check_output(['git', '-C', str(source_repo), 'archive', PIN])
    run.record('pinned_archive', commit=PIN, sha256=hashlib.sha256(archive).hexdigest())
    source = work / 'source'; source.mkdir()
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        tar.extractall(source)
    names = ['run.py', 'emit_vectors.py', 'DecoyGateCommandHandler.h', 'TestCase4.cpp']
    if sockets: names += ['SocketGate.cpp', 'socket_lab.py']
    if qualifier and not sockets: names += ['TestCase4Qualifier.cpp', 'emit_vectors_qualifier.py']
    if pad58 and not sockets: names += ['TestCase4Pad58.cpp', 'emit_vectors_pad58.py']
    if pad58b and not sockets: names += ['TestCase4Pad58B.cpp', 'emit_vectors_pad58b.py']
    snapshots = {name: run.snapshot(HERE / name) for name in names}
    sources = ['case4_padding.py', 'case4_transport.py', 'rrc.py']
    if qualifier and not sockets: sources.append('case4_qualifier_rewrite.py')
    if pad58 and not sockets: sources.append('case4_pad58.py')
    if pad58b and not sockets: sources.append('case4_pad58b.py')
    for name in sources:
        run.snapshot(HERE.parent / name)
    if sockets:
        (source / 'SocketGate.cpp').write_bytes(snapshots['SocketGate.cpp'].read_bytes())
        (source / 'DecoyGateCommandHandler.h').write_bytes(snapshots['DecoyGateCommandHandler.h'].read_bytes())
        cmake = source / 'CMakeLists.txt'
        cmake.write_text(cmake.read_text() + '\nadd_executable(case4_socket_gate SocketGate.cpp)\ntarget_link_libraries(case4_socket_gate PRIVATE opendnp3)\n')
        target = 'case4_socket_gate'
        binary_relative = 'case4_socket_gate'
    else:
        unit = source / 'cpp/tests/unit'
        (unit / 'utils/DecoyGateCommandHandler.h').write_bytes(snapshots['DecoyGateCommandHandler.h'].read_bytes())
        (unit / 'TestCase4.cpp').write_bytes(snapshots['TestCase4.cpp'].read_bytes())
        vectors = subprocess.check_output([sys.executable, str(snapshots['emit_vectors.py'])], env=dict(os.environ, PYTHONPATH=str(run.path / 'sources')))
        (unit / 'vectors.h').write_bytes(vectors)
        run.write_bytes('vectors.h', vectors)
        extra_sources = ''
        if qualifier:
            # Small, scoped extension: a second TEST_CASE source validating the
            # sibling qualifier-rewrite codec through the same production
            # Endpoint fixture. Independent file, independent vectors header,
            # same binary target -- not a change to the default (non-qualifier) build.
            (unit / 'TestCase4Qualifier.cpp').write_bytes(snapshots['TestCase4Qualifier.cpp'].read_bytes())
            qvectors = subprocess.check_output([sys.executable, str(snapshots['emit_vectors_qualifier.py'])], env=dict(os.environ, PYTHONPATH=str(run.path / 'sources')))
            (unit / 'vectors_qualifier.h').write_bytes(qvectors)
            run.write_bytes('vectors_qualifier.h', qvectors)
            extra_sources += ' ./TestCase4Qualifier.cpp'
        if pad58:
            # Small, scoped extension: a second (independent of --qualifier)
            # TEST_CASE source validating Option B's uniform-58-byte pad codec
            # through the same production Endpoint fixture. Independent file,
            # independent vectors header, same binary target -- not a change
            # to the default build or to the --qualifier path.
            (unit / 'TestCase4Pad58.cpp').write_bytes(snapshots['TestCase4Pad58.cpp'].read_bytes())
            p58vectors = subprocess.check_output([sys.executable, str(snapshots['emit_vectors_pad58.py'])], env=dict(os.environ, PYTHONPATH=str(run.path / 'sources')))
            (unit / 'vectors_pad58.h').write_bytes(p58vectors)
            run.write_bytes('vectors_pad58.h', p58vectors)
            extra_sources += ' ./TestCase4Pad58.cpp'
        if pad58b:
            # Small, scoped extension: a third (independent of --qualifier and
            # --pad58) TEST_CASE source validating Option B''s whitelisted-
            # qualifier pad codec through the same production Endpoint
            # fixture. Independent file, independent vectors header, same
            # binary target -- not a change to the default build or to the
            # --qualifier/--pad58 paths.
            (unit / 'TestCase4Pad58B.cpp').write_bytes(snapshots['TestCase4Pad58B.cpp'].read_bytes())
            p58bvectors = subprocess.check_output([sys.executable, str(snapshots['emit_vectors_pad58b.py'])], env=dict(os.environ, PYTHONPATH=str(run.path / 'sources')))
            (unit / 'vectors_pad58b.h').write_bytes(p58bvectors)
            run.write_bytes('vectors_pad58b.h', p58bvectors)
            extra_sources += ' ./TestCase4Pad58B.cpp'
        cmake = unit / 'CMakeLists.txt'
        cmake.write_text(cmake.read_text() + '''
    add_executable(case4_endpoint ./main.cpp ./TestCase4.cpp''' + extra_sources + '''
     ./utils/APDUHelpers.cpp ./utils/APDUHexBuilders.cpp ./utils/BufferHelpers.cpp
     ./utils/CopyableBuffer.cpp ./utils/DNPHelpers.cpp ./utils/LinkHex.cpp
     ./utils/LinkLayerTest.cpp ./utils/MasterTestFixture.cpp ./utils/MockTransportSegment.cpp
     ./utils/OutstationTestObject.cpp ./utils/ProtocolUtil.cpp ./utils/TransportTestObject.cpp)
    target_compile_features(case4_endpoint PRIVATE cxx_std_14)
    target_link_libraries(case4_endpoint PRIVATE catch dnp3mocks)
    target_include_directories(case4_endpoint PRIVATE ./ ../../lib/src)
    ''')
        target = 'case4_endpoint'
        binary_relative = 'cpp/tests/unit/case4_endpoint'
    build = work / 'build'
    build.mkdir()
    configure = ['cmake', '-S', str(source), '-B', str(build), '-DDNP3_TESTS=' + ('OFF' if sockets else 'ON'), '-DCMAKE_BUILD_TYPE=Release']
    if dependency_cache:
        dependencies = ['asio', 'exe4cpp', 'ser4cpp']
        for name in dependencies:
            dep = Path(dependency_cache).resolve() / (name + '-src')
            if not dep.is_dir(): raise ValueError('missing declared dependency cache: ' + str(dep))
            configure.append('-DFETCHCONTENT_SOURCE_DIR_' + name.upper() + '=' + str(dep))
        if not sockets:
            # Pinned Catch is a single DOWNLOAD_NO_EXTRACT header. Its CMake
            # target includes build/catch-src, not FetchContent's source dir.
            header = Path(dependency_cache).resolve().parent / 'catch-src/catch.hpp'
            data = header.read_bytes()
            if hashlib.sha1(data).hexdigest().upper() != 'C127EBB7A4F65C6CEFF7587C8EF18F84A74D6C15':
                raise ValueError('cached Catch header differs from pinned dependency declaration')
            (build / 'catch-src').mkdir()
            (build / 'catch-src/catch.hpp').write_bytes(data)
            configure.append('-DFETCHCONTENT_SOURCE_DIR_CATCH=' + str(build / 'catch-src'))
            run.record('pinned_catch_header', sha256=hashlib.sha256(data).hexdigest())
    steps = [(configure, 'configure.log'), (['cmake', '--build', str(build), '--target', target, '-j' + str(jobs)], 'build.log')]
    binary = build / binary_relative
    if not sockets: steps.append(([str(binary)], 'test.log'))
    result = 0
    for command, filename in steps:
        run.record('command', argv=command, log=filename)
        with (run.path / filename).open('x') as log:
            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT).returncode
        if result: break
    manifest = {'opendnp3_commit': PIN, 'archive_sha256': hashlib.sha256(archive).hexdigest(),
                'archive_model': 'git archive pinned clean commit; dirty sibling excluded',
                'software_only': True, 'scope': 'production TCP sockets' if sockets else 'production contexts; no TCP sockets',
                'qualifier_rewrite_included': bool(qualifier and not sockets),
                'pad58_included': bool(pad58 and not sockets),
                'pad58b_included': bool(pad58b and not sockets),
                'result': result, 'binary_path': str(binary), 'binary_sha256': sha256(binary) if binary.exists() else None,
                'production_library_sha256': sha256(build / 'cpp/lib/libopendnp3.so') if (build / 'cpp/lib/libopendnp3.so').exists() else None,
                'files': {name: sha256(path) for name, path in snapshots.items()},
                'wire_transform_sha256': sha256(run.path / 'sources/case4_padding.py'),
                'transport_sha256': sha256(run.path / 'sources/case4_transport.py'),
                'crc_model_sha256': sha256(run.path / 'sources/rrc.py'),
                'qualifier_rewrite_sha256': sha256(run.path / 'sources/case4_qualifier_rewrite.py') if (qualifier and not sockets) else None,
                'pad58_sha256': sha256(run.path / 'sources/case4_pad58.py') if (pad58 and not sockets) else None,
                'pad58b_sha256': sha256(run.path / 'sources/case4_pad58b.py') if (pad58b and not sockets) else None,
                'dependency_declarations': {p.name: sha256(p) for p in (source / 'deps').glob('*.cmake')},
                'compiler': subprocess.check_output(['c++', '--version'], text=True).splitlines()[0],
                'cmake': subprocess.check_output(['cmake', '--version'], text=True).splitlines()[0],
                'sibling_status_unchanged': status_before == subprocess.check_output(['git', '-C', str(source_repo), 'status', '--porcelain'])}
    run.write_json('manifest.json', manifest)
    return manifest


def reuse_socket_artifact(run, manifest_path):
    """Reuse immutable build identity; this always creates a new socket trial."""
    manifest = json.loads(Path(manifest_path).read_text())
    if manifest.get('opendnp3_commit') != PIN or manifest.get('result') != 0 or manifest.get('scope') != 'production TCP sockets':
        raise ValueError('not a successful pinned production socket build')
    binary = Path(manifest['binary_path'])
    library = binary.parent / 'cpp/lib/libopendnp3.so'
    if sha256(binary) != manifest['binary_sha256'] or sha256(library) != manifest.get('production_library_sha256'):
        raise ValueError('production artifact changed since pinned build')
    for name in ('SocketGate.cpp', 'DecoyGateCommandHandler.h'):
        if sha256(HERE / name) != manifest['files'].get(name):
            raise ValueError('production endpoint application changed; fresh build required')
    names = ['run.py', 'emit_vectors.py', 'DecoyGateCommandHandler.h', 'TestCase4.cpp', 'SocketGate.cpp', 'socket_lab.py']
    snapshots = {name: run.snapshot(HERE / name) for name in names}
    for name in ('case4_padding.py', 'case4_transport.py', 'rrc.py'): run.snapshot(HERE.parent / name)
    manifest.update(reused_build_manifest_sha256=sha256(manifest_path),
                    files={name: sha256(path) for name,path in snapshots.items()},
                    wire_transform_sha256=sha256(run.path/'sources/case4_padding.py'),
                    transport_sha256=sha256(run.path/'sources/case4_transport.py'),
                    crc_model_sha256=sha256(run.path/'sources/rrc.py'))
    run.record('verified_production_artifact_reuse', manifest=str(Path(manifest_path).absolute()),
               binary_sha256=manifest['binary_sha256'], library_sha256=manifest['production_library_sha256'])
    run.write_json('manifest.json',manifest)
    return manifest


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path, help='fresh exclusive evidence directory')
    parser.add_argument('--source', type=Path, default=Path(os.environ.get('OPENDNP3_SRC', str(REPO.parent / 'opendnp3-community'))))
    parser.add_argument('--work', type=Path, help='fresh external build directory, retained on failure')
    parser.add_argument('--dependency-cache', type=Path, help='existing pinned build header dependency cache; production library is rebuilt')
    parser.add_argument('--jobs', type=int, choices=range(1, 5), default=2)
    parser.add_argument('--sockets', action='store_true')
    parser.add_argument('--qualifier', action='store_true', help='also build/run TestCase4Qualifier.cpp (qualifier-rewrite codec); non-sockets builds only')
    parser.add_argument('--pad58', action='store_true', help='also build/run TestCase4Pad58.cpp (Option B uniform-58-byte pad codec); non-sockets builds only')
    parser.add_argument('--pad58b', action='store_true', help="also build/run TestCase4Pad58B.cpp (Option B' whitelisted-qualifier pad codec); non-sockets builds only")
    parser.add_argument('--built-manifest', type=Path, help='reuse a hash-verified pinned production socket artifact in a fresh acquisition')
    args = parser.parse_args(argv)
    if args.qualifier and args.sockets:
        raise ValueError('--qualifier is only defined for the non-sockets production-context build')
    if args.pad58 and args.sockets:
        raise ValueError('--pad58 is only defined for the non-sockets production-context build')
    if args.pad58b and args.sockets:
        raise ValueError('--pad58b is only defined for the non-sockets production-context build')
    run = reserve_run(args.output, {'scope': 'OpenDNP3 socket gate' if args.sockets else 'OpenDNP3 production context gate', 'commit': PIN, 'attempted_pairs': 1})
    with run:
        if args.built_manifest:
            if not args.sockets or args.work or args.dependency_cache:
                raise ValueError('artifact reuse requires sockets and excludes build/work arguments')
            manifest = reuse_socket_artifact(run, args.built_manifest)
        else:
            manifest = build_gate(run, args.source, args.work or Path('/tmp') / ('case4-endpoint-' + run.token), args.dependency_cache, args.jobs, args.sockets, args.qualifier, args.pad58, args.pad58b)
        if manifest['result']:
            run.finish('failed', {'reason': 'pinned gate build/test failed', 'exit_code': manifest['result']})
            return manifest['result']
        if args.sockets:
            from socket_lab import launch
            result = launch(run, manifest)
            run.finish('passed' if result['passed'] else 'failed', result)
            return 0 if result['passed'] else 1
        run.finish('passed', {'scope': manifest['scope'], 'test_log': 'test.log'})
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

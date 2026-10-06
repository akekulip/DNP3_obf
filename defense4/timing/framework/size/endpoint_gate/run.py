#!/usr/bin/env python3
"""Build/run isolated OpenDNP3 contexts from a pinned commit; never edit sibling."""
from contextlib import nullcontext
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import io

PIN = '4648fcb898456d1cb70b5baecc38cc256c859c2e'
HERE = Path(__file__).resolve().parent
REPO = HERE.parents[4]
SRC = Path(os.environ.get('OPENDNP3_SRC', str(REPO.parent / 'opendnp3-community')))
OUT = HERE / 'evidence'
OUT.mkdir(exist_ok=True)
archive = subprocess.check_output(['git', '-C', str(SRC), 'archive', PIN])
status_before = subprocess.check_output(['git', '-C', str(SRC), 'status', '--porcelain'])
work_override = os.environ.get('CASE4_GATE_WORK')
if work_override:
    work_path = Path(work_override).resolve()
    for protected in (REPO.resolve(), SRC.resolve()):
        if work_path == protected or protected in work_path.parents:
            raise ValueError('CASE4_GATE_WORK must be outside the DNP3 and OpenDNP3 source trees')
    work_path.mkdir(parents=True, exist_ok=True)
with (nullcontext(work_override) if work_override else tempfile.TemporaryDirectory(prefix='case4-endpoint-')) as work:
    source = Path(work) / 'source'; source.mkdir(exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        tar.extractall(source)
    unit = source / 'cpp/tests/unit'
    (unit / 'utils/DecoyGateCommandHandler.h').write_bytes((HERE / 'DecoyGateCommandHandler.h').read_bytes())
    (unit / 'TestCase4.cpp').write_bytes((HERE / 'TestCase4.cpp').read_bytes())
    vectors = subprocess.check_output(['python3', str(HERE / 'emit_vectors.py')])
    (unit / 'vectors.h').write_bytes(vectors)
    (OUT / 'vectors.h').write_bytes(vectors)
    cmake = unit / 'CMakeLists.txt'
    cmake.write_text(cmake.read_text() + '''
add_executable(case4_endpoint ./main.cpp ./TestCase4.cpp
 ./utils/APDUHelpers.cpp ./utils/APDUHexBuilders.cpp ./utils/BufferHelpers.cpp
 ./utils/CopyableBuffer.cpp ./utils/DNPHelpers.cpp ./utils/LinkHex.cpp
 ./utils/LinkLayerTest.cpp ./utils/MasterTestFixture.cpp ./utils/MockTransportSegment.cpp
 ./utils/OutstationTestObject.cpp ./utils/ProtocolUtil.cpp ./utils/TransportTestObject.cpp)
target_compile_features(case4_endpoint PRIVATE cxx_std_14)
target_link_libraries(case4_endpoint PRIVATE catch dnp3mocks)
target_include_directories(case4_endpoint PRIVATE ./ ../../lib/src)
''')
    build = Path(work) / 'build'
    steps = [(['cmake','-S',str(source),'-B',str(build),'-DDNP3_TESTS=ON','-DCMAKE_BUILD_TYPE=Release'], 'configure.log'),
             (['cmake','--build',str(build),'--target','case4_endpoint','-j4'], 'build.log'),
             ([str(build/'cpp/tests/unit/case4_endpoint')], 'test.log')]
    binary_sha = None
    result = 0
    for command, filename in steps:
        with (OUT / filename).open('w') as log:
            run = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
        result = run.returncode
        if result:
            print(f'FAILED {filename}: see {OUT / filename}'); break
    binary = build/'cpp/tests/unit/case4_endpoint'
    if binary.exists(): binary_sha = hashlib.sha256(binary.read_bytes()).hexdigest()
    manifest = {'opendnp3_commit':PIN, 'archive_sha256':hashlib.sha256(archive).hexdigest(),
                'archive_model':'git archive pinned clean commit; sibling dirty files excluded',
                'software_only':True,'result':result,'binary_sha256':binary_sha,
                'files':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in [HERE/'TestCase4.cpp',HERE/'DecoyGateCommandHandler.h',HERE/'emit_vectors.py',HERE/'run.py']},
                'vector_sha256':hashlib.sha256(vectors).hexdigest(),
                'wire_transform_sha256':hashlib.sha256((HERE.parent/'case4_padding.py').read_bytes()).hexdigest(),
                'crc_model_sha256':hashlib.sha256((HERE.parent/'rrc.py').read_bytes()).hexdigest(),
                'dependency_declarations':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (source/'deps').glob('*.cmake')},
                'compiler':subprocess.check_output(['c++','--version'],text=True).splitlines()[0],
                'cmake':subprocess.check_output(['cmake','--version'],text=True).splitlines()[0],
                'sibling_status_unchanged':status_before==subprocess.check_output(['git','-C',str(SRC),'status','--porcelain'])}
    (OUT/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps(manifest,indent=2))
raise SystemExit(result)

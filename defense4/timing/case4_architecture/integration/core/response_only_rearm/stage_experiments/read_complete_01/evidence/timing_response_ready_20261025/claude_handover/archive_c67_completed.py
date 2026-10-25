"""Retain completed c67 logs using the repository restore helper's existing format."""
import hashlib
import json
import lzma
import shutil
from pathlib import Path

ROOT = Path('/home/philip/Projects/DNP3')
STAGE = ROOT / 'defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments'
MANIFEST = STAGE / 'read_complete_01/evidence/c67_dependency_retention_20261025/manifest.json'


def digest(stream):
    result, size = hashlib.sha256(), 0
    for block in iter(lambda: stream.read(1024 * 1024), b''):
        result.update(block)
        size += len(block)
    return result.hexdigest(), size


record = json.loads(MANIFEST.read_text()) if MANIFEST.exists() else dict(
    candidate='m12p_c67_sdk9132', scope='Completed attempts, including failures; raw logs retained byte-exact', logs={})
for run in sorted((STAGE / 'ctl_timing_01/evidence').glob('model_*_m12p_c67_sdk9132_[0-9][0-9]')):
    launch = run / 'launch_command.json'
    if not launch.exists() or type(json.loads(launch.read_text()).get('exit_code')) is not int:
        continue
    assert len(list(run.glob('*_results.json'))) == 1, run
    closure = json.loads((run / 'dependency_closure.json').read_text())
    logs = sorted(run.glob('model_*.log'))
    assert len(logs) == 1 and (run / 'model.out').is_file(), run
    for log in [run / 'model.out'] + logs:
        with log.open('rb') as source:
            raw_hash, raw_size = digest(source)
        archive = Path(str(log) + '.xz')
        if not archive.exists():
            temporary = Path(str(archive) + '.takeover.tmp')
            with temporary.open('xb') as packed:
                with lzma.LZMAFile(packed, 'w', preset=3) as compressor, log.open('rb') as source:
                    shutil.copyfileobj(source, compressor, 1024 * 1024)
            temporary.rename(archive)
        with lzma.open(archive, 'rb') as restored:
            assert digest(restored) == (raw_hash, raw_size), archive
        with archive.open('rb') as packed:
            packed_hash, packed_size = digest(packed)
        item = dict(archive=str(archive.relative_to(ROOT)), archive_bytes=packed_size,
                    archive_sha256=packed_hash, raw_bytes=raw_size, sha256=raw_hash)
        key = str(log.relative_to(ROOT))
        assert key not in record['logs'] or record['logs'][key] == item, key
        pin = closure.get('postchecks', {}).get('reset_application', {}).get('input_sha256', {}).get(log.name)
        assert pin is None or pin == raw_hash, log
        record['logs'][key] = item
    MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    temporary_manifest = MANIFEST.with_suffix('.takeover.tmp')
    with temporary_manifest.open('x') as output:
        json.dump(record, output, indent=1)
        output.write('\n')
    temporary_manifest.replace(MANIFEST)
    print(run.name, 'retained', flush=True)
print('Pinned logs:', len(record['logs']), flush=True)

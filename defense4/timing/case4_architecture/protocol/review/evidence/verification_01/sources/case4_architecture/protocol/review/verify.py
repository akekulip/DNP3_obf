"""Seal bounded independent source review; no target/model/compiler execution."""
import json
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ARCH = HERE.parents[1]
sys.path.insert(0, str(ARCH.parent / 'framework'))
from runner.evidence import reserve_run, sha256


def verify(destination):
    with reserve_run(destination, {'scope': 'bounded root-source fragment review',
                     'full_target': False, 'physical_measurements': False}) as run:
        inputs = list(HERE.glob('*.py')) + [HERE / 'REPORT.md']
        inputs += [ARCH / path for path in (
            'integration/egress_wire.p4', 'integration/egress_selected_wire.p4',
            'integration/egress_compose.py', 'integration/read/validator.p4',
            'integration/assembly_passes/producer.p4', 'integration/assembly_passes/generate.py',
            'integration/assembly_passes/evidence/producer_02/source/producer.p4',
            'integration/assembly_passes/evidence/producer_03/source/producer.p4',
            'integration/assembly_passes/evidence/fixed_worker_0_04/source/fixed_worker_0.p4',
            'integration/assembly_passes/evidence/staged_worker_0_01/source/staged_worker_0.p4',
            'integration/evidence/egress_wire_02/source/egress_wire.p4',
            'tests/source_control.py', 'protocol/source_eval.py',
            'protocol/egress/source_packets.py', 'protocol/assembly/assembly_eval.py',
            'protocol/egress/tests/test_packets.py', 'protocol/tests/test_protocol.py',
            'protocol/tests/test_carving.py', 'protocol/generate_padding.py',
            'protocol/generate_images.py')]
        inputs += [ARCH.parent / 'framework/size/case4_padding.py',
                   ARCH.parent / 'framework/runner/evidence.py']
        identities = {}
        for path in inputs:
            relative = str(path.relative_to(ARCH.parent))
            identities[relative] = sha256(path)
            run.snapshot(path, relative)
        result = subprocess.run([sys.executable, '-m', 'unittest', 'discover',
                                 '-s', str(HERE), '-p', 'test_*.py', '-v'],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        run.write_bytes('tests.log', result.stdout)
        unchanged = all(sha256(ARCH.parent / name) == value for name, value in identities.items())
        details = {'tests_exit_code': result.returncode, 'tests': 18,
                   'source_sha256': identities, 'inputs_unchanged': unchanged,
                   'full_target': False, 'compiler_qualification': False,
                   'physical_measurements': False}
        run.write_json('manifest.json', details)
        run.finish('passed' if result.returncode == 0 and unchanged else 'failed', details)
        return details


if __name__ == '__main__':
    print(json.dumps(verify(Path(sys.argv[1])), indent=2))

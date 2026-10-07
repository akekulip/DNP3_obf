"""Evidence must not silently lose failed runs or accept stale source/artifacts."""
import importlib.util
import json
from pathlib import Path
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]


class BuildEvidence(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('architecture_build', ROOT / 'build.py')
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root / 'test.p4'
        self.source.write_text('#include "local.p4"\n')
        (self.root / 'local.p4').write_text('// exact local dependency\n')
        self.compiler = self.root / 'compiler'
        self.compiler.write_text('#!/usr/bin/env python3\nimport sys\n'
                                 'if "--version" in sys.argv: print("fixture compiler")\n'
                                 'else: print("fixture placement failure"); sys.exit(3)\n')
        self.compiler.chmod(0o700)

    def test_failure_retains_source_dependencies_and_result(self):
        out = self.root / 'run01'
        result = self.module.compile_candidate(self.source, out, self.compiler)
        self.assertEqual(result['exit_code'], 3)
        self.assertEqual(result['milestone'], 'compile_failed')
        self.assertEqual(set(result['source_files']), {'test.p4', 'local.p4'})
        self.assertEqual((out / 'source' / 'local.p4').read_bytes(),
                         (self.root / 'local.p4').read_bytes())
        self.assertEqual(json.loads((out / 'manifest.json').read_text()), result)
        with self.assertRaises(FileExistsError):
            self.module.compile_candidate(self.source, out, self.compiler)

    def test_changed_source_fails_fresh_identity_check(self):
        out = self.root / 'run01'
        self.module.compile_candidate(self.source, out, self.compiler)
        self.assertEqual(self.module.verify_evidence(out)['source_matches'], True)
        self.source.write_text('// modified\n')
        self.assertEqual(self.module.verify_evidence(out)['source_matches'], False)

    def test_failed_build_never_qualifies(self):
        out = self.root / 'run01'
        self.module.compile_candidate(self.source, out, self.compiler)
        self.assertFalse(self.module.verify_evidence(out)['compiled_artifacts_verified'])

    def test_incomplete_success_is_evidence_failure(self):
        self.compiler.write_text('#!/usr/bin/env python3\nprint("fixture compiler")\n')
        out = self.root / 'run01'
        result = self.module.compile_candidate(self.source, out, self.compiler)
        self.assertEqual(result['milestone'], 'evidence_failed')
        self.assertIn('evidence_error', result)
        self.assertFalse(self.module.verify_evidence(out)['compiled_artifacts_verified'])

    def test_changed_snapshot_rejected(self):
        out = self.root / 'run01'
        self.module.compile_candidate(self.source, out, self.compiler)
        (out / 'source' / 'local.p4').write_text('// corrupt snapshot\n')
        self.assertFalse(self.module.verify_evidence(out)['snapshots_match'])

    def test_timeout_preserves_failed_run(self):
        self.compiler.write_text('#!/usr/bin/env python3\nimport sys,time\n'
                                 'if "--version" in sys.argv: print("fixture compiler")\n'
                                 'else: time.sleep(20)\n')
        out = self.root / 'run01'
        result = self.module.compile_candidate(self.source, out, self.compiler, timeout=0.05)
        self.assertEqual(result['exit_code'], 124)
        self.assertTrue(result['timed_out'])
        self.assertFalse(self.module.verify_evidence(out)['compiled_artifacts_verified'])

    def test_timeout_terminates_compiler_descendants(self):
        marker = self.root / 'orphan'
        child = f'import time; time.sleep(0.25); open({str(marker)!r}, "w").write("orphan")'
        self.compiler.write_text('#!/usr/bin/env python3\nimport sys,time,subprocess\n'
            'if "--version" in sys.argv: print("fixture compiler")\n'
            f'else: subprocess.Popen([sys.executable, "-c", {child!r}]); time.sleep(20)\n')
        self.module.compile_candidate(self.source, self.root / 'run01', self.compiler, timeout=0.1)
        time.sleep(0.3)
        self.assertFalse(marker.exists(), 'timed-out compiler left a producer running')

    def test_binary_omitted_from_manifest_never_qualifies(self):
        out = self.root / 'run01'
        result = self.module.compile_candidate(self.source, out, self.compiler)
        artifact = out / 'out' / 'bfrt.json'
        artifact.parent.mkdir()
        artifact.write_text('{}')
        result.update(exit_code=0, milestone='primitive_compiled',
                      artifact_sha256={'bfrt.json': self.module.sha(artifact)})
        (out / 'manifest.json').write_text(json.dumps(result))
        self.assertFalse(self.module.verify_evidence(out)['compiled_artifacts_verified'])

    def test_primary_source_identity_must_match_snapshot_inventory(self):
        out = self.root / 'run01'
        result = self.module.compile_candidate(self.source, out, self.compiler)
        result['source_sha256'] = '0' * 64
        (out / 'manifest.json').write_text(json.dumps(result))
        self.assertFalse(self.module.verify_evidence(out)['source_matches'])

    def test_reported_resources_must_match_hashed_context(self):
        out = self.root / 'run01'
        result = self.module.compile_candidate(self.source, out, self.compiler)
        artifacts = {'bfrt.json': '{}', 'pipe/context.json': '{"tables":[]}',
                     'pipe/tofino.bin': 'fixture binary'}
        for name, content in artifacts.items():
            file = out / 'out' / name
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text(content)
        (out / 'out/pipe/logs').mkdir()
        result.update(exit_code=0, milestone='primitive_compiled',
            artifact_sha256={name:self.module.sha(out / 'out' / name) for name in artifacts},
            resources=self.module.resource_summary(out / 'out'))
        (out / 'manifest.json').write_text(json.dumps(result))
        self.assertTrue(self.module.verify_evidence(out)['compiled_artifacts_verified'])
        result['resources']['stages']['ingress'] = 12
        (out / 'manifest.json').write_text(json.dumps(result))
        self.assertFalse(self.module.verify_evidence(out)['compiled_artifacts_verified'])

    def test_changed_compiler_identity_rejected(self):
        out = self.root / 'run01'
        result = self.module.compile_candidate(self.source, out, self.compiler)
        result['compiler_sha256'] = '0' * 64
        (out / 'manifest.json').write_text(json.dumps(result))
        self.assertFalse(self.module.verify_evidence(out)['compiler_matches'])

    def test_two_pipes_require_both_binaries_and_separate_resources(self):
        out = self.root / 'run01'
        result = self.module.compile_candidate(self.source, out, self.compiler)
        artifacts = {'bfrt.json': '{}'}
        pipes = []
        for name, stage in (('authority', 9), ('render', 6)):
            artifacts[name+'/context.json'] = json.dumps({'tables': [{
                'direction':'ingress','table_type':'match','stage_number':stage}]})
            artifacts[name+'/tofino.bin'] = name+' fixture binary'
            pipes.append({'pipe_name':name,'files':{'context':{'path':name+'/context.json'}}})
        artifacts['manifest.json'] = json.dumps({'programs':[{'pipes':pipes}]})
        for name, content in artifacts.items():
            file = out / 'out' / name
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text(content)
        resources = self.module.resource_summary(out / 'out')
        self.assertEqual(resources['pipes']['authority']['stages']['ingress'], 10)
        self.assertEqual(resources['pipes']['render']['stages']['ingress'], 7)
        self.assertEqual(resources['stages']['ingress'], 10)
        result.update(exit_code=0, milestone='primitive_compiled', resources=resources,
            artifact_sha256={name:self.module.sha(out / 'out' / name) for name in artifacts})
        (out / 'manifest.json').write_text(json.dumps(result))
        self.assertTrue(self.module.verify_evidence(out)['compiled_artifacts_verified'])
        del result['artifact_sha256']['render/tofino.bin']
        (out / 'manifest.json').write_text(json.dumps(result))
        self.assertFalse(self.module.verify_evidence(out)['compiled_artifacts_verified'])


if __name__ == '__main__':
    unittest.main()

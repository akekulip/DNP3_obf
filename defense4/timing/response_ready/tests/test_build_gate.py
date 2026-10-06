import gzip
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from defense4.timing.response_ready import verify_build


def digest(data): return hashlib.sha256(data).hexdigest()

class BuildGateTests(unittest.TestCase):
    def fixture(self, root, stages=7, compressed=False):
        source = root / 'current.p4'
        source.write_text('immutable candidate source')
        build = root / 'build'
        build.mkdir()
        (build / 'defense4_timing.p4').write_bytes(source.read_bytes())
        context = json.dumps({'tables':[{'direction':'ingress', 'stage_tables':[{'stage_number':stages-1}]}]}).encode()
        bfrt = b'{"tables": []}'
        if compressed:
            (build / 'context.json.gz').write_bytes(gzip.compress(context))
            (build / 'bfrt.json').write_bytes(bfrt)
        else:
            (build / 'out' / 'pipe').mkdir(parents=True)
            (build / 'out' / 'pipe' / 'context.json').write_bytes(context)
            (build / 'out' / 'bfrt.json').write_bytes(bfrt)
        summary = f'Table allocation done\nNumber of stages for ingress table allocation: {stages}\nNumber of stages for egress table allocation: 0\nCritical path length through the table dependency graph: {stages}\nNumber of tables allocated: 2\n'
        (build / 'table_summary.log').write_text(summary)
        manifest = dict(source_sha256=digest(source.read_bytes()), compiler='p4c 9.13.1', exit_code=0,
                        command=['bf-p4c','--target','tofino','--arch','tna','-DU_BOR','-o',str(build/'out'),str(build/'defense4_timing.p4')],
                        ingress_stages=stages, egress_stages=0, critical_path=stages, tables=2,
                        context_stages=dict(ingress_stages=stages,egress_stages=0),
                        artifact_sha256={'pipe/context.json':digest(context),'bfrt.json':digest(bfrt)})
        (build / 'manifest.json').write_text(json.dumps(manifest))
        return source, build

    def test_valid_seven_retained_or_output(self):
        for compressed in (False,True):
            with tempfile.TemporaryDirectory() as tmp:
                source, build = self.fixture(Path(tmp), compressed=compressed)
                r = verify_build.verify_build(source, build)
                self.assertTrue(r['passed'], r)
                self.assertEqual(r['context_stages']['ingress_stages'],7)
                self.assertFalse(r['deployment_authorized'])

    def test_stale_source_or_snapshot(self):
        for stale in ('source','snapshot'):
            with tempfile.TemporaryDirectory() as tmp:
                source, build = self.fixture(Path(tmp))
                (source if stale=='source' else build/'defense4_timing.p4').write_text('changed')
                self.assertFalse(verify_build.verify_build(source,build)['passed'])

    def test_tampered_context_or_bfrt(self):
        for name in ('context.json.gz','bfrt.json'):
            with tempfile.TemporaryDirectory() as tmp:
                source, build = self.fixture(Path(tmp),compressed=True)
                (build/name).write_bytes(gzip.compress(b'{"tables":[]}') if name.endswith('.gz') else b'{"tables":[{}]}')
                self.assertFalse(verify_build.verify_build(source,build)['passed'])

    def test_wrong_final_report_even_with_old_seven(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, build = self.fixture(Path(tmp))
            p = build/'table_summary.log'
            p.write_text(p.read_text()+p.read_text().replace('allocation: 7','allocation: 8'))
            self.assertFalse(verify_build.verify_build(source,build)['passed'])

    def test_eight_stages_and_missing_bor_failed_compile(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, build = self.fixture(Path(tmp),stages=8)
            self.assertFalse(verify_build.verify_build(source,build)['passed'])
        for mutation in ('missing_bor','failed_compile','undefined_bor'):
            with tempfile.TemporaryDirectory() as tmp:
                source, build = self.fixture(Path(tmp))
                p=build/'manifest.json'
                m=json.loads(p.read_text())
                if mutation=='missing_bor': m['command'].remove('-DU_BOR')
                elif mutation=='undefined_bor': m['command'].append('-UU_BOR')
                else: m['exit_code']=1
                p.write_text(json.dumps(m))
                self.assertFalse(verify_build.verify_build(source,build)['passed'])

if __name__ == '__main__': unittest.main()

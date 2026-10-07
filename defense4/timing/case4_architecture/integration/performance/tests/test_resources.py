import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import accounting as api


def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()


class ResourceTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.e=self.root/'evidence'
        (self.e/'source').mkdir(parents=True);(self.e/'out/pipe/logs').mkdir(parents=True)
        self.source=self.root/'probe.p4';self.source.write_text('resource fixture, never actually compiled')
        (self.e/'source/probe.p4').write_bytes(self.source.read_bytes())
        self.compiler=self.root/'compiler';self.compiler.write_text('mock compiler identity')
        (self.e/'compile.log').write_text('explicit fixture')
        for path in ('bfrt.json','pipe/tofino.bin'):(self.e/'out'/path).write_text('fixture')
        context=dict(tables=[dict(direction='ingress',table_type='stateful',name='Ingress.owner',size=4,stage_number=2)])
        (self.e/'out/pipe/context.json').write_text(json.dumps(context))
        phv=dict(schema_version='3.0.0',containers=[dict(gress='ingress',container_type='normal',
            bit_width=32,phv_number=0,slices=[dict(slice_info=dict(lsb=0,msb=31),
                field_slice=dict(field_name='Ingress.owner',slice_info=dict(lsb=0,msb=31)),
                reads=[dict(location=dict(type='mau',stage=2))],
                writes=[dict(location=dict(type='mau',stage=0))])])])
        (self.e/'out/pipe/logs/phv.json').write_text(json.dumps(phv))
        spec=api.importlib.util.spec_from_file_location('fixture_builder',api.ARCH/'build.py')
        builder=api.importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)
        self.m=dict(source=str(self.source),source_sha256=sha(self.source),source_files={'probe.p4':sha(self.source)},
            exit_code=0,milestone='primitive_compiled',full_target=False,compiler='p4c9.13.1 fixture',
            compiler_path=str(self.compiler),compiler_sha256=sha(self.compiler),
            compile_log_sha256=sha(self.e/'compile.log'),artifact_sha256={p:sha(self.e/'out'/p) for p in
                ('bfrt.json','pipe/context.json','pipe/tofino.bin')},resources=builder.resource_summary(self.e/'out'))
        self.write()

    def write(self):(self.e/'manifest.json').write_text(json.dumps(self.m))

    def multiple_pipes(self):
        import shutil
        shutil.copytree(self.e/'out/pipe',self.e/'out/render')
        (self.e/'out/manifest.json').write_text(json.dumps(dict(programs=[dict(pipes=[
            dict(pipe_name=name,files=dict(context=dict(path=name+'/context.json')))
            for name in ('pipe','render')])])) )
        self.m['artifact_sha256']={str(p.relative_to(self.e/'out')):sha(p)
            for p in (self.e/'out').rglob('*') if p.is_file() and p.name in
            ('bfrt.json','context.json','tofino.bin','manifest.json')}
        spec=api.importlib.util.spec_from_file_location('multi_fixture_builder',api.ARCH/'build.py')
        builder=api.importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)
        self.m['resources']=builder.resource_summary(self.e/'out');self.write()

    def test_every_pipeline_cost_and_phv_inventory_is_retained(self):
        self.multiple_pipes()
        result=api.load_resources(self.e)
        self.assertTrue(result['primitive_resources_verified'])
        self.assertEqual(set(result['phv']['pipes']),{'pipe','render'})
        self.assertEqual(result['resources']['stateful_tables'][1]['pipeline'],'render')
        self.m['artifact_sha256'].pop('render/tofino.bin');self.write()
        self.assertFalse(api.load_resources(self.e)['primitive_resources_verified'])

    def test_rechecks_reports_and_derives_actual_context_costs(self):
        result=api.load_resources(self.e)
        self.assertTrue(result['primitive_resources_verified'])
        self.assertEqual(result['resources']['stages'],{'ingress':3,'egress':0})
        self.assertEqual(result['phv']['container_classes'],{'ingress:normal:32':1})
        self.assertFalse(result['full_target_verified'])

    def test_manifest_cannot_underreport_actual_stage_count(self):
        self.m['resources']['stages']['ingress']=0;self.write()
        self.assertFalse(api.load_resources(self.e)['primitive_resources_verified'])

    def test_phv_summary_retains_actual_placement_and_stage_span(self):
        phv=api.load_resources(self.e)['phv']
        self.assertIn('placements',phv)
        self.assertEqual(phv['placements'][0]['container_bits'],[0,31])
        self.assertEqual(phv['placements'][0]['mau_stage_span'],[0,2])
        self.assertFalse(phv['alignment_and_live_ranges_verified'])

    def test_resource_evidence_cannot_omit_required_binary_identity(self):
        self.m['artifact_sha256'].pop('pipe/tofino.bin');self.write()
        self.assertFalse(api.load_resources(self.e)['primitive_resources_verified'])

    def test_missing_or_changed_compiler_reports_binary_refuse_cost_proof(self):
        for path in (self.compiler,self.e/'out/pipe/logs/phv.json',self.e/'out/pipe/tofino.bin'):
            original=path.read_bytes();path.write_text('changed')
            self.assertFalse(api.load_resources(self.e)['primitive_resources_verified'])
            path.write_bytes(original)

    def test_retained_snapshot_cost_is_distinct_from_current_source_fit(self):
        self.source.write_text('next uncompiled candidate')
        result=api.load_resources(self.e,allow_historical=True)
        self.assertFalse(result['primitive_resources_verified'])
        self.assertTrue(result['snapshot_resources_verified'])
        self.assertEqual(result['resources']['stages']['ingress'],3)
        self.assertFalse(result['verification']['source_matches'])

if __name__=='__main__':unittest.main()

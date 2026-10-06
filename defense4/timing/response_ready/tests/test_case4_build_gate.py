"""Offline resource-profile regression tests; no build/load/traffic side effects."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from defense4.timing.response_ready import verify_build
import test_build_gate as baseline


class Case4BuildGate(unittest.TestCase):
    def fixture(self, root, stages=12, version='9.13.1'):
        source, build = baseline.BuildGateTests().fixture(root, stages=stages)
        source.write_text('const bit<32> SLOT_CAPACITY = 32w1;\n'
            'Register<bit<32>, bit<1>>(SLOT_CAPACITY, 0) reg_owner;\n'
            'Register<bit<16>, bit<1>>(1, 0) reg_app_seq;\n')
        (build / 'defense4_timing.p4').write_bytes(source.read_bytes())
        m = json.loads((build / 'manifest.json').read_text())
        m.update(source_sha256=baseline.digest(source.read_bytes()),compiler='p4c '+version+' (SHA: abc123)')
        context = json.loads((build / 'out/pipe/context.json').read_text())
        context.update(target='tofino',compiler_version=version+' (abc123)',run_id='resource-run')
        context['tables'][0]['name']='Ingress.tbl_stage_fixture'
        context['tables'] += [dict(name='Ingress.'+name,table_type='stateful',size=1,
            direction='ingress',stage_tables=[dict(stage_number=0,meter_alu_index=i)])
            for i,name in enumerate(('reg_owner','reg_app_seq'))]
        (build / 'out/pipe/context.json').write_text(json.dumps(context))
        bfrt = dict(tables=[dict(name='pipe.Ingress.'+name,table_type='Register',size=1)
                           for name in ('reg_owner','reg_app_seq')])
        (build / 'out/bfrt.json').write_text(json.dumps(bfrt))
        (build / 'out/pipe/tofino.bin').write_bytes(b'compiled binary')
        m['artifact_sha256'] = {name:baseline.digest((build/'out'/name).read_bytes())
                               for name in ('pipe/context.json','bfrt.json','pipe/tofino.bin')}
        resources = {'phv_allocation_summary.log':'PHV ALLOCATION SUCCESSFUL\n',
                     'mau.resources.log':f'Compiler version: {version}\nRun ID: resource-run\nMeter ALU\n',
                     'assembly.bfa':'run_id: "resource-run"\n  stateful fixture$salu.Ingress.reg_owner:\n  stateful fixture$salu.Ingress.reg_app_seq:\n'}
        for name,text in resources.items(): (build/name).write_text(text)
        m['resource_report_sha256'] = {name:baseline.digest((build/name).read_bytes()) for name in resources}
        (build/'manifest.json').write_text(json.dumps(m))
        return source, build

    def test_cli_explicit_profile_accepts_real_target_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            source,build=self.fixture(Path(tmp))
            with contextlib.redirect_stdout(io.StringIO()) as output:
                code=verify_build.main([str(source),str(build),'--profile','case4'])
            self.assertEqual(code,0)
            report=json.loads(output.getvalue())
            self.assertTrue(report['passed'])
            self.assertFalse(report['deployment_authorized'])
            self.assertFalse(report['deployment_build_eligible'])
            self.assertFalse(report['joint_mechanism_verified'])
            self.assertEqual(report['resource_evidence']['register_capacity']['Ingress.reg_app_seq'],1)

    def test_default_seven_stage_gate_is_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            source,build=self.fixture(Path(tmp),stages=8)
            self.assertFalse(verify_build.verify_build(source,build)['passed'])
            self.assertTrue(verify_build.verify_build(source,build,profile='case4')['passed'])

    def test_thirteen_stage_candidate_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            source,build=self.fixture(Path(tmp),stages=13)
            self.assertFalse(verify_build.verify_build(source,build,profile='case4')['passed'])

    def test_9132_build_eligibility_is_explicit_and_never_deployment_authorization(self):
        with tempfile.TemporaryDirectory() as tmp:
            source,build=self.fixture(Path(tmp),version='9.13.2')
            result=verify_build.verify_build(source,build,profile='case4')
            self.assertTrue(result['passed'],result)
            self.assertTrue(result['deployment_build_eligible'])
            self.assertFalse(result['deployment_authorized'])

    def test_missing_or_tampered_resources_fail(self):
        for name in ('phv_allocation_summary.log','mau.resources.log','assembly.bfa','out/pipe/tofino.bin'):
            with tempfile.TemporaryDirectory() as tmp:
                source,build=self.fixture(Path(tmp));(build/name).write_text('tampered')
                self.assertFalse(verify_build.verify_build(source,build,profile='case4')['passed'],name)

    def test_target_compiler_register_and_salu_mismatches_fail(self):
        for mutation in ('target','compiler','capacity','salu'):
            with tempfile.TemporaryDirectory() as tmp:
                source,build=self.fixture(Path(tmp)); p=build/'out/pipe/context.json'
                context=json.loads(p.read_text())
                if mutation=='target':context['target']='tofino2'
                if mutation=='compiler':context['compiler_version']='9.13.2 (different)'
                if mutation=='capacity':context['tables'][1]['size']=2
                if mutation=='salu':context['tables'][1]['stage_tables'][0]['meter_alu_index']=4
                p.write_text(json.dumps(context))
                man=json.loads((build/'manifest.json').read_text())
                man['artifact_sha256']['pipe/context.json']=baseline.digest(p.read_bytes())
                (build/'manifest.json').write_text(json.dumps(man))
                self.assertFalse(verify_build.verify_build(source,build,profile='case4')['passed'],mutation)

    def test_compiler_manifest_must_match_target_and_architecture(self):
        with tempfile.TemporaryDirectory() as tmp:
            source,build=self.fixture(Path(tmp));p=build/'manifest.json';m=json.loads(p.read_text())
            m['command'][m['command'].index('tofino')]='tofino2';p.write_text(json.dumps(m))
            self.assertFalse(verify_build.verify_build(source,build,profile='case4')['passed'])



class Case4ReportFailures(unittest.TestCase):
    fixture = Case4BuildGate.fixture
    def test_empty_phv_report_is_a_failed_gate_not_an_exception(self):
        with tempfile.TemporaryDirectory() as tmp:
            source,build=self.fixture(Path(tmp));p=build/'phv_allocation_summary.log';p.write_text('')
            man=json.loads((build/'manifest.json').read_text())
            man['resource_report_sha256'][p.name]=baseline.digest(p.read_bytes())
            (build/'manifest.json').write_text(json.dumps(man))
            self.assertFalse(verify_build.verify_build(source,build,profile='case4')['passed'])

    def test_wrong_resource_run_identity_is_rejected_even_with_updated_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            source,build=self.fixture(Path(tmp));p=build/'mau.resources.log'
            p.write_text(p.read_text().replace('resource-run','another-run'))
            man=json.loads((build/'manifest.json').read_text())
            man['resource_report_sha256'][p.name]=baseline.digest(p.read_bytes())
            (build/'manifest.json').write_text(json.dumps(man))
            self.assertFalse(verify_build.verify_build(source,build,profile='case4')['passed'])


class Case4ConstCapacity(unittest.TestCase):
    fixture = Case4BuildGate.fixture

    def test_constant_entries_cannot_exceed_compiled_table_capacity(self):
        with tempfile.TemporaryDirectory() as tmp:
            source,build=self.fixture(Path(tmp));p=build/'out/pipe/context.json'
            context=json.loads(p.read_text())
            context['tables'].append(dict(name='Ingress.tbl_capacity',table_type='match',size=2,
                direction='ingress',stage_tables=[dict(stage_number=0)],static_entries=[{}, {}, {}]))
            p.write_text(json.dumps(context));man=json.loads((build/'manifest.json').read_text())
            man['artifact_sha256']['pipe/context.json']=baseline.digest(p.read_bytes())
            (build/'manifest.json').write_text(json.dumps(man))
            self.assertFalse(verify_build.verify_build(source,build,profile='case4')['passed'])


if __name__ == "__main__":
    unittest.main()

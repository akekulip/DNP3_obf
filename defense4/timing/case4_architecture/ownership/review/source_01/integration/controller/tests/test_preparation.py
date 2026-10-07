import hashlib
import importlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
try:api=importlib.import_module('preparation')
except ModuleNotFoundError:api=None


def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()


class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(api,'exact-source inert preparation is not implemented')
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.evidence=self.root/'evidence'
        (self.evidence/'source').mkdir(parents=True);(self.evidence/'out/pipe/logs').mkdir(parents=True)
        self.source=self.root/'candidate.p4';self.source.write_text('explicit mock source fixture')
        (self.evidence/'source/candidate.p4').write_bytes(self.source.read_bytes())
        self.compiler=self.root/'mock-compiler';self.compiler.write_text('not a compiler')
        tables=[]
        for name in ('holding','pgen','params','owner'):
            tables.append(dict(name='pipe.Ingress.'+name,key=[],action_specs=[
                dict(name='Ingress.set_'+name,data=[dict(name='value',type=dict(type='uint32',width=32))])]))
        (self.evidence/'out/bfrt.json').write_text(json.dumps(dict(tables=tables)))
        for name in ('pipe/tofino.bin','pipe/logs/phv.log'):
            (self.evidence/'out'/name).write_text('mock artifact '+name)
        (self.evidence/'out/pipe/context.json').write_text(json.dumps(dict(tables=[
            dict(direction='ingress',table_type='match',stage_number=0,name='Ingress.mock')])))
        (self.evidence/'compile.log').write_text('explicit mock compile log')
        manifest=dict(source=str(self.source),source_sha256=sha(self.source),
            source_files={'candidate.p4':sha(self.source)},compiler_path=str(self.compiler),
            compiler_sha256=sha(self.compiler),compiler='p4c9.13.2 mock fixture',
            command=['not executed'],exit_code=0,milestone='primitive_compiled',full_target=False,
            artifact_sha256={name:sha(self.evidence/'out'/name) for name in
                ('bfrt.json','pipe/context.json','pipe/tofino.bin')},
            compile_log_sha256=sha(self.evidence/'compile.log'),
            resources=api._builder().resource_summary(self.evidence/'out'))
        (self.evidence/'manifest.json').write_text(json.dumps(manifest))
        self.profile=dict(operations=['READ','SELECT','OPERATE'],da_ms=10,gap_ms=1,
            readiness_ms=30,heartbeat_request_us=100,policy_cap_ms=40,
            translation_capacity=2,padding='35_55_crob',split='57_28_29')
        def op(table,value,phase,role,lifetime='configuration'):
            return dict(table='pipe.Ingress.'+table,fields={'action_name':'Ingress.set_'+table,'value':value},
                key=None,kind='default',phase=phase,role=role,lifetime=lifetime)
        self.inventory=[op('holding',0,'disable','holding_gate'),op('pgen',0,'disable','packet_generator'),
            op('params',10,'configure','policy'),op('owner',0,'configure','timing_owner','timing'),
            op('holding',1,'enable','holding_gate'),op('pgen',1,'enable','packet_generator')]

    def qualification(self):
        return dict(mock_only=True,reviewed_complete=True,compiler_identity_approved=True,
            schema_mapping_reviewed=True,required_behaviors=sorted(api.REQUIRED_BEHAVIORS),
            profile_sha256=api.digest(self.profile),inventory_sha256=api.digest(self.inventory))

    def registered(self):
        return patch.dict(api.QUALIFIED_TARGETS,{sha(self.evidence/'manifest.json'):self.qualification()})

    def test_every_pipeline_binary_is_bound_in_the_preparation_identity(self):
        import shutil
        shutil.copytree(self.evidence/'out/pipe',self.evidence/'out/render')
        (self.evidence/'out/manifest.json').write_text(json.dumps(dict(programs=[dict(pipes=[
            dict(pipe_name=name,files=dict(context=dict(path=name+'/context.json')))
            for name in ('pipe','render')])])) )
        path=self.evidence/'manifest.json';manifest=json.loads(path.read_text())
        manifest['artifact_sha256']={str(p.relative_to(self.evidence/'out')):sha(p)
            for p in (self.evidence/'out').rglob('*') if p.is_file() and p.name in
            ('bfrt.json','context.json','tofino.bin','manifest.json')}
        manifest['resources']=api._builder().resource_summary(self.evidence/'out')
        path.write_text(json.dumps(manifest))
        with self.registered():result=api.prepare(self.evidence,self.profile,self.inventory,mock=True)
        self.assertTrue(result['prepared'])
        self.assertEqual(set(result['identity']['binary_sha256_by_pipeline']),{'pipe','render'})
        manifest['artifact_sha256'].pop('render/tofino.bin');path.write_text(json.dumps(manifest))
        with self.registered():result=api.prepare(self.evidence,self.profile,self.inventory,mock=True)
        self.assertFalse(result['prepared'])
        self.assertEqual(result['actions'],[])

    def test_primitive_fit_cannot_be_enrolled_as_complete_from_manifest_flags(self):
        result=api.prepare(self.evidence,self.profile,self.inventory)
        self.assertFalse(result['prepared']);self.assertEqual(result['actions'],[])
        self.assertIn('reviewed complete qualification', ';'.join(result['blockers']))

    def test_mock_complete_fixture_produces_only_an_inert_exact_inventory(self):
        with self.registered():result=api.prepare(self.evidence,self.profile,self.inventory,mock=True)
        self.assertTrue(result['prepared'])
        self.assertFalse(result['hardware_authorized'])
        self.assertEqual(result['evidence_kind'],'mock_only')
        self.assertEqual(result['actions'][0]['fields']['value'],0)
        self.assertEqual(result['actions'][-1]['fields']['value'],1)
        self.assertIn('all_connections_retired',result['runtime_preconditions'])

    def test_mock_registry_cannot_prepare_a_deployable_real_package(self):
        with self.registered():result=api.prepare(self.evidence,self.profile,self.inventory)
        self.assertFalse(result['prepared'])

    def test_exact_source_artifacts_schema_and_reports_are_required(self):
        for relative in ('out/pipe/tofino.bin','out/bfrt.json','out/pipe/logs/phv.log'):
            path=self.evidence/relative;original=path.read_bytes();path.write_bytes(b'changed')
            with self.registered():result=api.prepare(self.evidence,self.profile,self.inventory,mock=True)
            self.assertFalse(result['prepared']);self.assertEqual(result['actions'],[])
            path.write_bytes(original)
        self.source.write_text('changed current source')
        with self.registered():self.assertFalse(api.prepare(self.evidence,self.profile,self.inventory,mock=True)['prepared'])

    def test_required_binary_cannot_be_omitted_from_a_re_registered_manifest(self):
        path=self.evidence/'manifest.json';manifest=json.loads(path.read_text())
        manifest['artifact_sha256'].pop('pipe/tofino.bin');path.write_text(json.dumps(manifest))
        with self.registered():
            self.assertFalse(api.prepare(self.evidence,self.profile,self.inventory,mock=True)['prepared'])

    def test_declared_primary_source_hash_cannot_differ_from_actual_source(self):
        path=self.evidence/'manifest.json';manifest=json.loads(path.read_text())
        manifest['source_sha256']='a'*64;path.write_text(json.dumps(manifest))
        with self.registered():
            self.assertFalse(api.prepare(self.evidence,self.profile,self.inventory,mock=True)['prepared'])

    def test_stage_cost_is_derived_from_hash_bound_context(self):
        path=self.evidence/'manifest.json';manifest=json.loads(path.read_text())
        manifest['resources']['stages']['ingress']=0;path.write_text(json.dumps(manifest))
        with self.registered():
            self.assertFalse(api.prepare(self.evidence,self.profile,self.inventory,mock=True)['prepared'])

    def test_entire_configuration_and_inventory_match_before_preparation(self):
        with self.registered():
            profile=dict(self.profile,policy_cap_ms=100)
            self.assertFalse(api.prepare(self.evidence,profile,self.inventory,mock=True)['prepared'])
            inventory=[dict(op) for op in self.inventory];inventory[2]=dict(inventory[2],fields={'unexpected':1})
            self.assertFalse(api.prepare(self.evidence,self.profile,inventory,mock=True)['prepared'])

    def test_rollback_refuses_runtime_owner_even_from_the_correct_program(self):
        identity=dict(api.candidate_identity(self.evidence),inventory_sha256=api.digest(self.inventory))
        snapshot=dict(identity=identity,
            entries=[dict(self.inventory[3],fields={'action_name':'Ingress.set_owner','value':0x80000001})])
        with self.assertRaisesRegex(ValueError,'runtime'):
            api.configuration_rollback(snapshot,self.evidence/'out/bfrt.json',expected_identity=identity,
                inventory=self.inventory)

    def test_runtime_owner_cannot_be_relabeled_as_configuration(self):
        identity=dict(api.candidate_identity(self.evidence),inventory_sha256=api.digest(self.inventory))
        entries=[dict(op) for op in self.inventory]
        entries[3]=dict(entries[3],lifetime='configuration',fields={'action_name':'Ingress.set_owner','value':0x80000001})
        with self.assertRaisesRegex(ValueError,'runtime'):
            api.configuration_rollback(dict(identity=identity,entries=entries),self.evidence/'out/bfrt.json',
                expected_identity=identity,inventory=self.inventory)

    def test_configuration_rollback_uses_current_disable_and_saved_values_last(self):
        identity=dict(api.candidate_identity(self.evidence),inventory_sha256=api.digest(self.inventory))
        entries=[]
        for index,value in ((0,0),(1,0),(2,5)):
            entry=dict(self.inventory[index]);entry['fields']=dict(entry['fields'],value=value);entries.append(entry)
        result=api.configuration_rollback(dict(identity=identity,entries=entries),self.evidence/'out/bfrt.json',
            expected_identity=identity,inventory=self.inventory)
        self.assertEqual([a['phase'] for a in result['actions']],['disable','disable','configure','enable','enable'])
        self.assertEqual(result['actions'][2]['fields']['value'],5)
        self.assertEqual(result['actions'][-1]['fields']['value'],0)
        self.assertFalse(result['runtime_state_restored']);self.assertFalse(result['physical_drain_verified'])

    def test_rollback_cannot_skip_or_duplicate_a_configuration_target(self):
        identity=dict(api.candidate_identity(self.evidence),inventory_sha256=api.digest(self.inventory))
        for entries in ([self.inventory[0]], [self.inventory[0],self.inventory[0],self.inventory[1],self.inventory[2]]):
            with self.assertRaisesRegex(ValueError,'each exact'):
                api.configuration_rollback(dict(identity=identity,entries=entries),self.evidence/'out/bfrt.json',
                    expected_identity=identity,inventory=self.inventory)

    def test_policy_off_does_not_clear_live_translation(self):
        result=api.prepare(self.evidence,self.profile,self.inventory)
        self.assertEqual(result['policy_off']['translation'],'retain until verified connection retirement')
        self.assertEqual(result['policy_off']['tail_repair'],'native sender retransmission; no manufactured ACK')

    def test_blocked_package_output_is_exclusive(self):
        path=self.root/'package.json';api.write_package(path,{'prepared':False})
        with self.assertRaises(FileExistsError):api.write_package(path,{})

if __name__=='__main__':unittest.main()

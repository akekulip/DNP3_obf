"""Offline inventory/readback/rollback proof, never a compiled complete mapping."""
import dataclasses
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'control'))
import profiles as pf
from schema import Schema, WriteOperation
from test_schema_operations import document


class Device:
    def __init__(self, schema):
        self.schema=schema
        self.state={}
        self.calls=[]
        self.fail_once=None

    def read_operation(self, op):
        op=self.schema.check_operation(op)
        self.calls.append(('read',op.table))
        value=self.state.get((op.table,json.dumps(op.key,sort_keys=True)))
        return None if value is None else dict(value)

    def write_operation(self, op):
        op=self.schema.check_operation(op)
        self.calls.append(('write',op.table,dict(op.fields)))
        if self.fail_once==op.table:
            self.fail_once=None
            raise RuntimeError('injected write failure')
        self.state[(op.table,json.dumps(op.key,sort_keys=True))]=dict(op.fields)

    def delete_operation(self, op):
        self.calls.append(('delete',op.table))
        self.state.pop((op.table,json.dumps(op.key,sort_keys=True)),None)


class BindingTests(unittest.TestCase):
    def setUp(self):
        import case4_binding
        self.api=case4_binding
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.source=self.root/'candidate.p4'; self.source.write_text('offline synthetic source')
        doc=document()
        doc['tables'].append(dict(doc['tables'][0],name='pipe.Ingress.pgen'))
        doc['tables'].append(dict(doc['tables'][0],name='pipe.Ingress.tbl_params'))
        self.spec=Schema(doc)
        self.device=Device(self.spec)
        self.profile=pf.Profile('case4',10,1,connection_id='trial-1',build_id='offline-fixture',
            completion_deadline_ms=35, measured_heartbeat_max_us=150,
            measured_drain_max_ms=2,measured_release_max_us=50,
            operation='SBO',operation_profile_sha256='a'*64)

    def binding(self, **over):
        operations=(
            WriteOperation('pipe.Ingress.control',{'action_name':'Ingress.configure','enabled':0},phase='disable',role='processing'),
            WriteOperation('pipe.Ingress.pgen',{'action_name':'Ingress.configure','enabled':0},phase='disable',role='pktgen'),
            WriteOperation('pipe.Ingress.owner',{'Ingress.owner.f1':0},key={'$REGISTER_INDEX':0},kind='register',role='tuple_cookie_ledger_seed'),
            WriteOperation('pipe.Egress.mapping',{'action_name':'Egress.translate','delta':20},key={'flow':7},kind='entry',role='translation'),
            WriteOperation('pipe.Ingress.control',{'action_name':'Ingress.configure','enabled':1},phase='enable',role='processing'),
            WriteOperation('pipe.Ingress.pgen',{'action_name':'Ingress.configure','enabled':1},phase='enable',role='pktgen'))
        values=dict(source_path=str(self.source),source_sha256=hashlib.sha256(self.source.read_bytes()).hexdigest(),
            schema_sha256=self.spec.sha256,build_id='offline-fixture',program_name='synthetic',
            operations=operations,capabilities=self.api.REQUIRED_CAPABILITIES,
            operation='SBO',operation_profile_sha256='a'*64,
            configuration=self.api.profile_configuration(self.profile))
        values.update(over)
        return self.api.Case4Binding(**values)

    def seed(self):
        for op in self.binding().operations[:3]:
            self.device.write_operation(op)
        self.device.calls.clear()

    def approved(self, binding):
        return patch.dict(self.api.QUALIFIED_BINDINGS,{binding.fingerprint():{
            'source_sha256':binding.source_sha256,'schema_sha256':binding.schema_sha256,
            'build_id':binding.build_id,'program_name':binding.program_name,
            'capabilities':sorted(self.api.REQUIRED_CAPABILITIES),
            'allowed_operations':[binding.operation],
            'operation_profile_sha256':binding.operation_profile_sha256,
            'control_processing_enabled':binding.operation != 'READ',
            'mock_only':True}})

    def test_unregistered_component_refuses_before_device_reads(self):
        with self.assertRaises(pf.ActivationError):
            self.api.activate(self.device,self.profile,self.binding(),mock=True,backup_path=self.root/'backup.json')
        self.assertEqual(self.device.calls,[])

    def test_invalid_operation_fails_as_validation_before_device_calls(self):
        profile=dataclasses.replace(self.profile,operation='bad')
        with self.assertRaises(ValueError):
            pf.plan(profile,{})
        self.assertEqual(self.device.calls,[])

    def test_read_context_cannot_activate_a_control_inventory(self):
        binding=self.binding()
        profile=dataclasses.replace(self.profile,operation='READ',operation_profile_sha256='')
        with self.approved(binding):
            with self.assertRaises(pf.ActivationError):
                self.api.activate(self.device,profile,binding,mock=True,backup_path=self.root/'backup.json')
        self.assertEqual(self.device.calls,[])

    def test_registered_profile_scope_is_checked_before_device_calls(self):
        binding=self.binding()
        with self.approved(binding):
            self.api.QUALIFIED_BINDINGS[binding.fingerprint()]['operation_profile_sha256']='b'*64
            with self.assertRaises(pf.ActivationError):
                self.api.activate(self.device,self.profile,binding,mock=True,backup_path=self.root/'backup.json')
        self.assertEqual(self.device.calls,[])

    def test_selected_padding_cannot_differ_from_inventory_configuration(self):
        binding=self.binding()
        profile=dataclasses.replace(self.profile,padding_profile='none')
        with self.approved(binding):
            with self.assertRaises(pf.ActivationError):
                self.api.activate(self.device,profile,binding,mock=True,backup_path=self.root/'backup.json')
        self.assertEqual(self.device.calls,[])

    def test_read_inventory_cannot_enable_control_roles_or_default_padding(self):
        profile=dataclasses.replace(self.profile,operation='READ',operation_profile_sha256='')
        binding=self.binding(operation='READ',operation_profile_sha256='')
        with self.approved(binding):
            with self.assertRaises(pf.ActivationError):
                self.api.preflight(self.spec,profile,binding,mock=True)
            profile=dataclasses.replace(profile,padding_profile='none')
        binding=dataclasses.replace(binding,configuration=self.api.profile_configuration(profile))
        with self.approved(binding):
            self.api.preflight(self.spec,profile,binding,mock=True)
        binding=dataclasses.replace(binding,operations=binding.operations[:3]+(
            dataclasses.replace(binding.operations[3],role='control_padding'),)+binding.operations[4:])
        with self.approved(binding):
            with self.assertRaises(pf.ActivationError):
                self.api.activate(self.device,profile,binding,mock=True,backup_path=self.root/'backup.json')
        self.assertEqual(self.device.calls,[])

    def test_whole_schema_and_source_validated_before_any_device_call(self):
        for bad in ('source','field','capability'):
            binding=self.binding()
            if bad=='source': binding=dataclasses.replace(binding,source_sha256='a'*64)
            if bad=='field': binding=dataclasses.replace(binding,operations=binding.operations[:3]+(
                dataclasses.replace(binding.operations[3],fields={'action_name':'Egress.translate','delta':1 << 32}),)+binding.operations[4:])
            if bad=='capability': binding=dataclasses.replace(binding,capabilities=frozenset())
            with self.approved(binding):
                with self.assertRaises((pf.ActivationError,ValueError)):
                    self.api.activate(self.device,self.profile,binding,mock=True,backup_path=self.root/'backup.json')
            self.assertEqual(self.device.calls,[])

    def test_snapshot_is_exclusive_enable_last_and_restore_deletes_created_entry(self):
        binding=self.binding(); self.seed()
        before=dict(self.device.state)
        path=self.root/'backup.json'
        with self.approved(binding):
            record=self.api.activate(self.device,self.profile,binding,mock=True,backup_path=path)
            self.assertFalse(record['is_evidence_of_switch_state'])
            writes=[c for c in self.device.calls if c[0]=='write']
            self.assertEqual(writes[0][2]['enabled'],0)
            self.assertEqual(writes[-1][2]['enabled'],1)
            self.assertTrue(path.exists())
            self.api.restore(self.device,binding,json.loads(path.read_text()),mock=True)
            self.assertEqual(self.device.state,before)
            count=len(self.device.calls)
            with self.assertRaises(FileExistsError):
                self.api.activate(self.device,self.profile,binding,mock=True,backup_path=path)
            self.assertFalse(any(c[0]=='write' for c in self.device.calls[count:]))

    def test_mid_plan_failure_retains_failure_and_verified_rollback(self):
        binding=self.binding(); self.seed(); before=dict(self.device.state)
        self.device.fail_once='pipe.Egress.mapping'
        with self.approved(binding):
            with self.assertRaises(pf.ActivationError) as caught:
                self.api.activate(self.device,self.profile,binding,mock=True,backup_path=self.root/'backup.json')
        self.assertTrue(caught.exception.record['rollback']['restored'])
        self.assertEqual(self.device.state,before)
        self.assertIn('injected',caught.exception.record['failure']['reason'])

    def test_interrupt_after_each_enable_restores_then_propagates_cancellation(self):
        for role in ('processing','pktgen'):
            with self.subTest(role=role):
                self.device=Device(self.spec); self.seed(); before=dict(self.device.state)
                binding=self.binding(); original=self.device.write_operation
                fired=[False]
                def interrupt(op):
                    original(op)
                    if op.phase=='enable' and op.role==role and not fired[0]:
                        fired[0]=True
                        raise KeyboardInterrupt('cancelled after enable')
                self.device.write_operation=interrupt
                with self.approved(binding):
                    with self.assertRaises(KeyboardInterrupt):
                        self.api.activate(self.device,self.profile,binding,mock=True,
                            backup_path=self.root/(role+'.json'))
                self.assertEqual(self.device.state,before)

    def test_second_interrupt_retains_failed_restore_and_disables_components(self):
        binding=self.binding();self.seed(); original=self.device.write_operation
        interruptions=[0]
        def interrupt(op):
            original(op)
            if (interruptions[0]==0 and op.phase=='enable' and op.role=='processing') or (
                    interruptions[0]==1 and op.phase=='disable'):
                interruptions[0]+=1
                raise KeyboardInterrupt('interrupt '+str(interruptions[0]))
        self.device.write_operation=interrupt
        with self.approved(binding):
            with self.assertRaises(KeyboardInterrupt) as caught:
                self.api.activate(self.device,self.profile,binding,mock=True,backup_path=self.root/'backup.json')
        self.assertFalse(caught.exception.record['rollback']['restored'])
        self.assertTrue(caught.exception.record['rollback']['traffic_must_remain_stopped'])
        for table in ('pipe.Ingress.control','pipe.Ingress.pgen'):
            self.assertEqual(self.device.state[(table,'null')]['enabled'],0)

    def test_mock_qualification_cannot_open_real_activation(self):
        binding=self.binding()
        with self.approved(binding):
            with self.assertRaises(pf.ActivationError):
                self.api.activate(self.device,self.profile,binding,mock=False,backup_path=self.root/'backup.json')
        self.assertEqual(self.device.calls,[])

    def test_deployment_boolean_cannot_replace_fresh_artifact_gate(self):
        binding=self.binding()
        with self.approved(binding):
            self.api.QUALIFIED_BINDINGS[binding.fingerprint()].update(mock_only=False,deployment_allowed=True)
            with self.assertRaises(pf.ActivationError):
                self.api.preflight(self.spec,self.profile,binding,mock=False)

    def test_compiler_proof_cannot_substitute_for_loaded_program_identity(self):
        binding=self.binding()
        with self.approved(binding):
            self.api.QUALIFIED_BINDINGS[binding.fingerprint()].update(mock_only=False,deployment_allowed=True,
                verify_artifacts=lambda b:dict(identity=b.identity(),verified=True,full_target=True,
                    compiler_identity_approved=True,artifact_hashes_verified=True))
            with self.assertRaises(pf.ActivationError) as caught:
                self.api.activate(self.device,self.profile,binding,mock=False,backup_path=self.root/'backup.json')
        self.assertIn('loaded',str(caught.exception))
        self.assertEqual(self.device.calls,[])

    def test_control_profile_cannot_reuse_read_admission(self):
        profile=dataclasses.replace(self.profile,operation='SBO',operation_profile_sha256='a'*64)
        admission={'verdict':'admitted_conditional','claim':{'kind':'admitted_conditional'},
            'policy':{'anchor':'request','d_a_ms':10,'clrt_new_ms':1,'policy_cap_ms':40,
            'context':{'connection_id':'trial-1','build_id':'offline-fixture','operation':'READ'}},
            'policy_cap':{'ok':True,'cap_ms':40},'checks':[]}
        self.assertIn('operation',self.api._admission_problem(profile,admission))

    def test_admission_cannot_silently_raise_fixed_policy_cap(self):
        admission={'verdict':'admitted_conditional','claim':{'kind':'admitted_conditional'},
            'policy':{'anchor':'request','d_a_ms':10,'clrt_new_ms':1,'policy_cap_ms':100,
            'context':{'connection_id':'trial-1','build_id':'offline-fixture','operation':'READ'}},
            'policy_cap':{'ok':True,'cap_ms':100},'checks':[]}
        self.assertIn('cap',self.api._admission_problem(self.profile,admission))

    def test_profiles_api_accepts_only_a_qualified_mock_inventory(self):
        binding=self.binding();self.seed()
        with self.approved(binding):
            record=pf.activate(self.device,self.profile,{},binding=binding,mock=True,
                backup_path=self.root/'backup.json')
        self.assertTrue(record['steps'])
        self.assertFalse(record['is_evidence_of_switch_state'])


if __name__=='__main__':unittest.main()

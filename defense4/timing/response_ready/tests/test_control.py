import unittest
from unittest.mock import patch, Mock
import tempfile
from pathlib import Path
import json
from defense4.timing.response_ready import control

class ControlTests(unittest.TestCase):
    def test_fixed_plan(self):
        for da in (5, 10, 15, 20):
            p = control.build_plan(da)
            d = p['defaults']
            self.assertEqual(d[control.RELEASE]['gap_ticks'], 999936)
            self.assertEqual(d[control.PARAMS]['da_dr'], d[control.PARAMS]['d_ticks'] + 999936)
            self.assertEqual(d[control.PARAMS]['budget'], 18000)
            self.assertEqual(d[control.BOR]['anchor_req'], 1)
        with self.assertRaises(ValueError): control.build_plan(4)

    def snapshot(self, p):
        return {'tables': {**{n: {'default': [d]} for n,d in p['defaults'].items()}, control.RANDOM: {'entries': []}}}

    def test_readback_strict_and_bfrt_wrapper(self):
        p = control.build_plan(10)
        s = self.snapshot(p)
        control.audit_readback(s, p)
        s['tables'][control.RELEASE]['default'] = [{'data': p['defaults'][control.RELEASE]}]
        control.audit_readback(s, p)
        s['tables'][control.RANDOM]['entries'] = [{}]
        with self.assertRaises(ValueError): control.audit_readback(s, p)
        s = self.snapshot(p)
        s['tables'][control.PARAMS]['default'][0] = dict(s['tables'][control.PARAMS]['default'][0], da_dr=999936)
        with self.assertRaises(ValueError): control.audit_readback(s, p)
        s = self.snapshot(p)
        del s['tables'][control.RELEASE]['default'][0]['action_name']
        with self.assertRaises(ValueError): control.audit_readback(s, control.build_plan(10))

    def test_schema_exact(self):
        s = {'tables':[{'name':control.RELEASE, 'action_specs':[{'name':'Ingress.set_read_release','data':[{'name':'enabled','type':{'type':'uint8','width':8}}, {'name':'gap_ticks','type':{'type':'uint32','width':32}}]}]}]}
        control.validate_schema(s)
        s['tables'][0]['action_specs'][0]['data'][1]['type']['width'] = 16
        with self.assertRaises(ValueError): control.validate_schema(s)

    def test_apply_requires_guards_before_connection(self):
        with patch.dict('os.environ', {}, clear=True), patch.object(control.configure, '_load_bfrt') as load:
            with self.assertRaises(RuntimeError): control.apply_live(control.build_plan(5), False, None)
            load.assert_not_called()
        with patch.dict('os.environ', {'DEFENSE4_HW_AUTHORIZED': '1'}), patch.object(control.configure, '_load_bfrt') as load:
            with self.assertRaises(RuntimeError): control.apply_live(control.build_plan(5), False, None)
            with self.assertRaises(ValueError): control.apply_live(control.build_plan(5), True, None)
            load.assert_not_called()

class FakeData:
    def __init__(self, values): self.values = values
    def to_dict(self): return dict(self.values)

class FakeTable:
    def __init__(self, name, value):
        self.value = value
        self.info = Mock()
        self.info.name_get.return_value = name
        self.info.action_name_list_get.return_value = ['Ingress.set_read_release']
        self.info.data_field_name_list_get.return_value = ['enabled', 'gap_ticks']
        self.info.data_field_size_get.side_effect = lambda field, action: (1,8) if field == 'enabled' else (4,32)
    def entry_get(self, *args, **kwargs): return iter([])
    def default_entry_get(self, *args, **kwargs): return iter([(FakeData(self.value), None)])
    def make_data(self, values, action): return dict(values, action_name=action)
    def default_entry_set(self, target, data): self.value = data

class ApplyTests(unittest.TestCase):
    def test_apply_sdk_surface_backup_and_readback_failure(self):
        for corrupt in (False, True):
            plan = control.build_plan(10)
            tables = {n: FakeTable(n, dict(d)) for n,d in plan['defaults'].items()}
            tables[control.RANDOM] = FakeTable(control.RANDOM, {})
            if corrupt:
                tables[control.BOR].default_entry_set = lambda target, data: None
                tables[control.BOR].value['anchor_req'] = 0
            interface, info, gc = Mock(), Mock(), Mock()
            info.table_get.side_effect = tables.__getitem__
            gc.DataTuple.side_effect = lambda k,v: (k,v)
            with tempfile.TemporaryDirectory() as tmp, patch.dict('os.environ', {'DEFENSE4_HW_AUTHORIZED':'1'}), patch.object(control.configure, '_load_bfrt', return_value=(gc, interface, info, object())):
                backup = Path(tmp)/'backup.json'
                if corrupt:
                    with self.assertRaises(ValueError): control.apply_live(plan, True, backup)
                else:
                    result = control.apply_live(plan, True, backup)
                    self.assertTrue(control.audit_readback(result, plan)['verified'])
                self.assertIn('tables', json.loads(backup.read_text()))
                with self.assertRaises(FileExistsError): control.apply_live(plan, True, backup)
                interface.tear_down_stream.assert_called_once()

if __name__ == '__main__': unittest.main()

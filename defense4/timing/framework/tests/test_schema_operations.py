"""Whole-plan validation covers keyed tables/registers and egress, not just defaults."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'control'))
import schema


def document():
    return {'tables': [
        {'name':'pipe.Ingress.control', 'key':[], 'action_specs':[
            {'name':'Ingress.configure', 'data':[{'name':'enabled','type':{'type':'uint8','width':8}}]}]},
        {'name':'pipe.Egress.mapping', 'key':[{'name':'flow','match_type':'Exact','type':{'type':'uint16','width':16}}],
         'action_specs':[{'name':'Egress.translate','data':[{'name':'delta','type':{'type':'uint32','width':32}}]}]},
        {'name':'pipe.Ingress.owner', 'key':[{'name':'$REGISTER_INDEX','match_type':'Exact','type':{'type':'uint32','width':32}}],
         'table_type':'Register',
         'data':[{'name':'Ingress.owner.f1','type':{'type':'uint32','width':32}}]},
    ]}


class OperationSchema(unittest.TestCase):
    def operation(self, **over):
        values=dict(table='pipe.Egress.mapping', fields={'action_name':'Egress.translate','delta':20},
                    key={'flow':7}, kind='entry')
        values.update(over)
        return schema.WriteOperation(**values)

    def test_real_egress_name_and_exact_key_width_are_checked(self):
        spec=schema.Schema(document())
        op=spec.check_operation(self.operation())
        self.assertEqual(op.table,'pipe.Egress.mapping')
        for key in ({}, {'flow':1 << 16}, {'flow':True}, {'wrong':7}):
            with self.assertRaises(schema.SchemaError):
                spec.check_operation(self.operation(key=key))

    def test_register_data_requires_its_real_compiled_field(self):
        spec=schema.Schema(document())
        op=self.operation(table='pipe.Ingress.owner',kind='register',key={'$REGISTER_INDEX':0},
                          fields={'Ingress.owner.f1':0})
        self.assertEqual(spec.check_operation(op).fields,{'Ingress.owner.f1':0})
        with self.assertRaises(schema.SchemaError):
            spec.check_operation(self.operation(table='pipe.Ingress.owner',kind='register',
                key={'$REGISTER_INDEX':0},fields={'cookie':0}))
        with self.assertRaises(schema.SchemaError):
            spec.check_operation(self.operation(table='pipe.Ingress.owner',kind='entry',
                key={'$REGISTER_INDEX':0},fields={'Ingress.owner.f1':0}))

    def test_entire_inventory_is_validated_before_execution(self):
        spec=schema.Schema(document())
        with self.assertRaises(schema.SchemaError):
            spec.check_operations([self.operation(),self.operation(fields={'action_name':'Egress.translate','delta':1 << 32})])

    def test_default_cannot_hide_an_entry_key(self):
        with self.assertRaises(schema.SchemaError):
            schema.Schema(document()).check_operation(self.operation(kind='default'))


class LegacyRestorePreflight(unittest.TestCase):
    def test_late_invalid_restore_field_cannot_mutate_release_first(self):
        from test_control_adapter import make, pf, CONSTS
        dev,calls=make()
        pf.activate(dev,pf.Profile('combined',10,1),CONSTS,mock=True)
        saved={t:dev.read(t) for t in (pf.PARAMS,pf.BOR,pf.RELEASE)}
        saved[pf.PARAMS]=dict(saved[pf.PARAMS],not_compiled=1)
        calls.clear()
        with self.assertRaises(schema.SchemaError):
            pf.restore(dev,saved)
        self.assertEqual(calls,[])


if __name__=='__main__': unittest.main()

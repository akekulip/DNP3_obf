"""The isolated model has one device and two disjoint compiled-program scopes."""
import copy
from pathlib import Path
import sys
import unittest
HERE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(HERE))


class ModelConfiguration(unittest.TestCase):
    def config(self,name,device=0):
        return {'p4_devices':[{'device-id':device,'p4_programs':[{'program-name':name,'p4_pipelines':[{'pipeline-name':'pipe','pipe_scope':[0,1,2,3],'context':'retained-context','config':'retained-bin'}]}]}]}

    def test_two_programs_one_device_disjoint_scopes_without_changing_artifact_paths(self):
        self.assertTrue((HERE/'make_model_config.py').exists(),'scoped same-device model config missing')
        import make_model_config as mc
        n=self.config('ne');m=self.config('m');before=copy.deepcopy((n,m))
        got=mc.combine(n,m)
        self.assertEqual((n,m),before)
        device=got['p4_devices'][0];self.assertEqual(device['device-id'],0)
        self.assertEqual(len(got['p4_devices']),1)
        for program,scope in zip(device['p4_programs'],([0],[1])):
            pipe=program['p4_pipelines'][0]
            self.assertEqual(pipe['pipe_scope'],scope)
            self.assertEqual(pipe['context'],'retained-context');self.assertEqual(pipe['config'],'retained-bin')

    def test_foreign_device_or_duplicate_program_or_extra_pipeline_refused(self):
        self.assertTrue((HERE/'make_model_config.py').exists())
        import make_model_config as mc
        for n,m in ((self.config('ne'),self.config('m',1)),(self.config('ne'),self.config('ne'))):
            with self.assertRaises(ValueError):mc.combine(n,m)
        n=self.config('ne');n['p4_devices'][0]['p4_programs'][0]['p4_pipelines'].append({'pipe_scope':[1]})
        with self.assertRaises(ValueError):mc.combine(n,self.config('m'))


if __name__=='__main__':unittest.main()

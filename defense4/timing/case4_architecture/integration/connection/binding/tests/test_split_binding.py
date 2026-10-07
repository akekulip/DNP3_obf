"""Narrow actual-source gates, not parser execution or physical handoff proof."""
import re
import sys
import unittest
from pathlib import Path

HERE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(HERE.parents[2]/'protocol'))
from source_eval import Source


class SplitBinding(unittest.TestCase):
    def source(self,values):
        text=(HERE/'split_binding.p4').read_text().replace('RETURN_PORT','9w68')
        # Substitution order matters for the longer port name.
        text=text.replace('VALIDATION_9w68','9w70').replace('ig.ingress_port','m.ingress_port')
        text=re.sub(r'(9w\d+):(\w+\(\);)',r'(\1):\2',text)
        return Source(text,values)

    def test_authority_refuses_raw_external_port_even_if_ports_table_enabled(self):
        for port,expected in ((9,0),(10,0),(68,1),(70,1)):
            source=self.source({'m.ingress_port':port,'m.port_valid':1,'m.authority_trusted':0})
            source.table('authority_port_guard')
            self.assertEqual(source.env['m.authority_trusted'],expected)
            self.assertEqual(source.env['m.port_valid'],1)

    def test_validation_guard_requires_every_actual_crc_and_profile_result(self):
        good={'m.enabled':1,'m.profile':1,'m.badh':0,'m.badb':0,'m.bad1':0,'m.badt':0}
        for changed in (None,'m.enabled','m.profile','m.badh','m.badb','m.bad1','m.badt'):
            fields=dict(good,**{'m.data_valid':0})
            if changed:fields[changed]=1-fields[changed]
            source=self.source(fields);source.table('data_guard')
            self.assertEqual(source.env['m.data_valid'],int(changed is None))

    def test_validation_handoff_preserves_original_no_external_proof_header(self):
        text=(HERE/'split_binding.p4').read_text()
        validation=text[text.index('control ValidationIngress('):text.index('control Ingress(')]
        self.assertNotIn('Register<',validation)
        self.assertNotIn('setValid()',validation)
        self.assertNotRegex(validation,r'\bwork\.apply\(')
        self.assertIn('tm.ucast_egress_port=VALIDATION_RETURN_PORT',validation)
        self.assertIn('Switch(validation,authority)',text)

if __name__=='__main__':unittest.main()

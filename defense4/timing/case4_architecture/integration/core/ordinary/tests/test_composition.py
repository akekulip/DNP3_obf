"""The ordinary composition binds unmodified role bodies and their exact inputs."""
from pathlib import Path
import hashlib
import sys
import unittest
HERE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(HERE))


class Composition(unittest.TestCase):
    def test_two_pipes_preserve_actual_controls_and_bind_each_source(self):
        self.assertTrue((HERE/'compose.py').exists(),'actual N/M/E composition generator missing')
        import compose
        source,identity=compose.generate()
        self.assertIn('Pipeline(n_IgParser(),n_Ingress(),n_IgDeparser(),e_EgParser(),e_Egress(),e_EgDeparser()) p0;',source)
        self.assertIn('Pipeline(m_IgParser(),m_Ingress(),m_IgDeparser(),m_EgParser(),m_Egress(),m_EgDeparser()) p1;',source)
        for name in ('n.p4','m.p4','e.p4','work_record.p4'):
            self.assertEqual(identity[name],hashlib.sha256((HERE/name).read_bytes()).hexdigest())
        self.assertIn('n_expected_work_cell_t',source)
        self.assertIn('mirror.emit<e_completion_h>',source)
        self.assertIn('pkt.extract(ig);pkt.advance(PORT_METADATA_SIZE)',source)
        self.assertNotIn('register_write',source)

    def test_ne_program_uses_same_actual_role_bodies_without_m_phv_layout(self):
        import compose
        source,identity=compose.generate('ne')
        self.assertIn('Switch(p0) main;',source)
        self.assertNotIn('m_Ingress',source)
        self.assertIn('n_Ingress',source);self.assertIn('e_Egress',source)
        self.assertEqual(set(identity),{'n.p4','e.p4','work_record.p4'})


if __name__=='__main__':unittest.main()

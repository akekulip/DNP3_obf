"""Source composition identity tests; no compiler or target behavior claim."""
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE / 'p4'))
import make_joint_processing_probe as compose


class ProcessingComposition(unittest.TestCase):
    def test_inputs_bound_and_incomplete_processing_cannot_claim_joint(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / 'probe.p4'
            with patch.object(compose, 'OUT', output):
                manifest = compose.generate()
            text = output.read_text()
            self.assertEqual(manifest['output_sha256'], hashlib.sha256(output.read_bytes()).hexdigest())
            self.assertEqual(json.loads(output.with_suffix('.inputs.json').read_text()), manifest)
            for path, expected in manifest['sources'].items():
                self.assertEqual(hashlib.sha256(Path(path).read_bytes()).hexdigest(), expected)
            self.assertFalse(manifest['joint_mechanism_verified'])
            self.assertFalse(manifest['deployment_permitted'])
            self.assertIn('WORK_TYPE : extract_mapping', text)
            self.assertIn('mapping.apply(hdr,m,ig,parser_md,deparser_md,tm)', text)
            self.assertIn('timing.apply(hdr,meta,ig,parser_md,deparser_md,tm)', text)
            self.assertIn('size_EgDeparser()', text)
            self.assertNotIn('ingress_intrinsic_mapping_meta_t', text)
            self.assertNotIn('hdr.validated.setValid()', text)
            self.assertIn('finished_t.apply();reject();', text)

    def test_changed_parser_seam_refuses_composition(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / 'timing.p4'
            source.write_text(compose.TIMING.read_text().replace(
                'ETHERTYPE_CASE4_VALIDATED : extract_validated; default : reject;',
                'ETHERTYPE_CASE4_VALIDATED : changed_seam; default : reject;'))
            output = Path(temp) / 'probe.p4'
            with patch.object(compose, 'TIMING', source), patch.object(compose, 'OUT', output):
                with self.assertRaisesRegex(ValueError, 'seam changed'):
                    compose.generate()
            self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()

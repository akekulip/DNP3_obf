import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parents[1]

class TemplateTests(unittest.TestCase):
    def selector(self):
        spec = importlib.util.spec_from_file_location('two_read_templates', HERE / 'two_read_templates.py')
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod.select_templates

    def test_real_relay_selected_for_relay_shapes(self):
        variants, path = self.selector()(HERE.parent / 'read_complete_01/vectors', {91: {}, 134: {}})
        self.assertEqual(path.name, 'two_read_templates_relay.json')
        self.assertEqual(set(variants), {'v0', 'v1'})
        self.assertEqual({len(bytes.fromhex(v['classes']['integrity']['native'])) for v in variants.values()}, {134})

    def test_missing_variant_class_or_empty_rejected(self):
        source = json.loads((HERE.parent / 'read_complete_01/vectors/two_read_templates_relay.json').read_text())
        for mutate in (lambda x: x.update(variants={}), lambda x: x['variants'].pop('v1'),
                       lambda x: x['variants']['v0']['classes'].pop('mixed'),
                       lambda x: x['variants']['v1']['classes']['mixed'].update(native='')):
            with self.subTest(mutate=mutate), tempfile.TemporaryDirectory() as tmp:
                doc = json.loads(json.dumps(source)); mutate(doc)
                Path(tmp, 'two_read_templates_relay.json').write_text(json.dumps(doc))
                with self.assertRaisesRegex(AssertionError, 'no two-READ template'):
                    self.selector()(Path(tmp), {91: {}, 134: {}})

if __name__ == '__main__':
    unittest.main()

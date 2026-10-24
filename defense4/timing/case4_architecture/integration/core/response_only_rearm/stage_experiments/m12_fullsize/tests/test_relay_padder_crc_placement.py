"""Isolate P1's input CRC from independent connection writes; retain all bytes."""
import json
import struct
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from m12gen import relay_ts, relay_sbo
from m12gen.build import build
import test_relay_ts as ts
import test_two_read_pad as read


class PadderCRCPlacement(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with patch.object(relay_ts, 'padder_crc_placement', side_effect=lambda src: src):
            cls.original, _ = build(**ts.FLAGS, relay_ts=True)
        cls.selected, _ = build(**ts.FLAGS, relay_ts=True)

    def test_only_one_hint_on_instantiated_pipe1_egress(self):
        hint = '@pa_solitary("egress","m.in_rb0")\n'
        self.assertEqual(self.selected.count(hint), 1)
        self.assertIn(hint + 'control x_Egress(', self.selected)
        self.assertEqual(self.selected.replace(hint, ''), self.original)

    def test_actual_relay_padding_bad_crc_bad_profile_and_missing_size_row(self):
        vectors = ts.HERE.parent / 'read_complete_01/vectors'
        templates = json.loads((vectors / 'two_read_templates_relay.json').read_text())
        constants = json.loads((vectors / 'constants_two_read_relay.json').read_text())['shapes']
        derive = read._module('placement_relay_derive', vectors / 'derive_two_read_relay.py')
        tev = bytearray(16); tev[12] = 11
        count = 0
        for variant in templates['variants'].values():
            for cls, shape in (('mixed', 'mixed_g1v2_g30v1_91'), ('integrity', 'integrity_134')):
                native = bytes.fromhex(variant['classes'][cls]['native'])
                bad_crc = bytearray(native); bad_crc[26] ^= 1
                bad_profile = bytearray(native); bad_profile[15] ^= 1
                bad_profile[26:28] = struct.pack('<H', relay_sbo.crc(bad_profile[10:26]))
                for case, payload in (('valid', native), ('bad_crc', bytes(bad_crc)),
                                      ('bad_profile', bytes(bad_profile)), ('no_row', native)):
                    incoming = bytes(tev) + ts.packet(payload, reverse=True)
                    outputs = []
                    for text in (self.original, self.selected):
                        e = read.interp.ESource(read.padder_source(text))
                        if case != 'no_row':
                            e.install('p1_conn', [0xc0a80a07, 0xc0a80a01, 20000, 56857], 'p1_pad_ok', [])
                        out = e.inject(180, incoming)
                        self.assertEqual(e.env.get('m.pad'), int(case == 'valid'), (cls, case))
                        self.assertEqual(out[70:82], ts.DATA_OPTIONS)
                        expected = derive.derive.construct(native, constants[shape]) if case == 'valid' else payload
                        self.assertEqual(out[82:], expected, (cls, case))
                        if case == 'bad_crc':
                            self.assertNotEqual(e.env.get('m.in_rb0'), 0x993a)
                        elif case != 'no_row':
                            self.assertEqual(e.env.get('m.in_rb0'), 0x993a)
                        outputs.append((out, dict(e.env), dict(e.valid)))
                    self.assertEqual(outputs[0], outputs[1], (cls, case))
                    count += 1
        self.assertEqual(count, 16)


if __name__ == '__main__':
    unittest.main()

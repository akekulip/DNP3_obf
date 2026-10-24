"""The sel751 configs carry the READ link addresses in the installer's wire order (hdr.dl as sent)."""
import importlib.util
import json
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('make_sel751_configs', HERE / 'hw' / 'make_sel751_configs.py')
make = importlib.util.module_from_spec(spec)
spec.loader.exec_module(make)
NATIVE = HERE / 'evidence/relay_native_capture_20261024/relay_native_20261024_02'


class ReadAddresses(unittest.TestCase):
    def test_native_relay_read_addresses_are_wire_order(self):
        # DNP3 destination 0, source 1, little-endian on the wire: octets 00 00 / 01 00.
        self.assertEqual(make.read_link_addresses(NATIVE), (0x0000, 0x0100))

    def test_every_c51_config_carries_them(self):
        for path in sorted((HERE / 'hw/config').glob('rc01_m12p_c51_sdk9132_sel751_*.json')):
            endpoints = json.loads(path.read_text())['endpoints']
            self.assertEqual((endpoints['read_dst'], endpoints['read_src']), (0x0000, 0x0100), path.name)


if __name__ == '__main__':
    unittest.main()

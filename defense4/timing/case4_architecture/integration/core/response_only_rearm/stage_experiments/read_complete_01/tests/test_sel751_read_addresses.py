"""sel751 READ link addresses: logical in the config (endpoint_profiles), wire order at the installer (N compares
the parsed hdr.dl octets). rc01_hw_c51_20261024_11's MAU snapshot found the logical source passed unconverted."""
import importlib.util
import json
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
ARCH = HERE.parents[4]
spec = importlib.util.spec_from_file_location('make_sel751_configs', HERE / 'hw' / 'make_sel751_configs.py')
make = importlib.util.module_from_spec(spec)
spec.loader.exec_module(make)
sys.path.insert(0, str(ARCH / 'protocol' / 'hw_vepa'))
import campaign  # noqa: E402
NATIVE = HERE / 'evidence/relay_native_capture_20261024/relay_native_20261024_02/relay_wire.json'


class ReadAddresses(unittest.TestCase):
    def test_native_relay_read_addresses_are_logical_destination0_source1(self):
        self.assertEqual(make.read_link_addresses(json.loads(NATIVE.read_text())), (0, 1))

    def test_every_c51_config_validates_and_reaches_the_installer_in_wire_order(self):
        paths = sorted((HERE / 'hw/config').glob('rc01_m12p_c51_sdk9132_sel751_*.json'))
        self.assertEqual(len(paths), 17)   # nine original (.166) + eight v19 (Vision at 10.10.54.19)
        for path in paths:
            cfg = json.loads(path.read_text())
            campaign.validate_profile(cfg)
            self.assertEqual(campaign.installer_read_addresses(cfg), (0x0000, 0x0100), path.name)

    def test_software_fixture_wire_values_pass_unchanged(self):
        cfg = json.loads((HERE / 'hw/config/rc01_m12p_c29_sdk9132_reference.json').read_text())
        self.assertEqual(campaign.installer_read_addresses(cfg), (0x0a00, 0x0100))


if __name__ == '__main__':
    unittest.main()

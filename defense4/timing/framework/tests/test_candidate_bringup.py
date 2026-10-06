"""The candidate bring-up may call only what the proven hw_configure_all calls, and none of the steps that do not fit the candidate."""
import json
import re
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
TIMING = HERE.parents[1]
SETUP = (TIMING / "stage_reduction/control/defense4_timing_setup.py").read_text()
BRING = (HERE.parent / "control/candidate_bringup.py").read_text()
sys.path.insert(0, str(HERE.parent / "control"))
import candidate_bringup as cb  # noqa: E402


def calls(text):
    return set(re.findall(r"\b((?:m|d3|caseA)\.[A-Za-z_]+|hw_[A-Za-z_]+|verify_commit_map)\(", text))


def frozen_sequence():
    body = SETUP[SETUP.index("def hw_configure_all"):SETUP.index("def hw_rollback")]
    return {re.sub(r"^(m|d3)\.", lambda m_: m_.group(0), c) for c in calls(body)}


class Bringup(unittest.TestCase):
    def test_current_case4_constants_are_separate_and_source_bound(self):
        import hashlib
        source = TIMING / "response_ready/src/defense4_response_ready.p4"
        c = json.loads((HERE.parent / "control/consts_case4.json").read_text())
        self.assertEqual(c["_source_sha256"], hashlib.sha256(source.read_bytes()).hexdigest())
        modes = {name: int(value) for name, value in re.findall(
            r"const bit<8>\s+(MODE_\w+)\s*=\s*8w(\d+)\s*;", source.read_text())}
        self.assertEqual({name: value for name, value in c.items() if name.startswith("MODE_")}, modes)
        self.assertIs(c["_deployment_authorized"], False)
        self.assertIn('default=str(HERE / "consts.json")', BRING)
        self.assertNotIn('default=str(HERE / "consts_case4.json")', BRING)

    def test_every_helper_it_calls_is_in_the_proven_sequence(self):
        proven = {c.replace("m.", "") if c.startswith("m.") else c for c in frozen_sequence()}
        mine = {c.replace("m.", "") if c.startswith("m.") else c for c in calls(BRING.split("def main")[1])}
        helpers = {c for c in mine if c.startswith(("hw_", "d3.", "caseA."))}
        self.assertTrue(helpers)
        self.assertEqual(sorted(helpers - proven), [], "a helper outside the 2026-09-25 sequence")

    def test_the_removed_steps_are_removed(self):
        code = BRING.split("def main")[1]
        for name in ("hw_config_codebook", "hw_verify_tbl_commit", "verify_commit_map", "config_params_d4", "hw_config_tbl_bor_params"):
            self.assertNotIn(name + "(", code, name)
            self.assertIn(name, SETUP, "the frozen sequence really did call it")

    def test_declared_lists_match_the_code(self):
        for name in cb.REMOVED:
            self.assertIn(name.split(".")[-1], SETUP)
        self.assertEqual(len(cb.PROVEN_STEPS), 10)

    def test_pktgen_is_enabled_last_and_only_after_the_checks(self):
        code = BRING.split("def main")[1]
        self.assertLess(code.index("enable=False"), code.index("enable=True"))
        self.assertLess(code.index("pf.activate"), code.index("enable=True"))
        self.assertIn("if not chk.blocked()", code)

    def test_codebook_must_be_empty_and_adapter_used_for_the_parameters(self):
        self.assertIn("tbl_bor_codebook", BRING)
        self.assertIn("pf.activate", BRING)
        self.assertIn("read_len", SETUP)             # the frozen script's own --read-len 0 requirement is kept
        self.assertIn('"--read-len", "0"', BRING)

    def test_list_mode_touches_nothing(self):
        self.assertEqual(cb.main(["--list"]), 0)

    def test_historical_constants_are_bound_to_the_retained_bringup_build(self):
        c = json.loads((HERE.parent / "control/consts.json").read_text())
        import hashlib
        baseline = TIMING / "response_ready/evidence/sde_9_13_2_build_03"
        manifest = json.loads((baseline / "manifest.json").read_text())
        source = baseline / "defense4_timing.p4"
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        self.assertEqual(manifest["source_sha256"], digest)
        self.assertEqual(c["_source_sha256"], digest)
        self.assertEqual(manifest["exit_code"], 0)
        self.assertIn("p4c 9.13.2", manifest["compiler"])
        modes = {name: int(value) for name, value in re.findall(
            r"const bit<8>\s+(MODE_\w+)\s*=\s*8w(\d+)\s*;", source.read_text())}
        self.assertEqual({name: value for name, value in c.items() if name.startswith("MODE_")}, modes)
        self.assertEqual((c["MODE_OFF"], c["MODE_D2_RESP"], c["MODE_D4_DUAL"]), (0, 2, 4))


if __name__ == "__main__":
    unittest.main()

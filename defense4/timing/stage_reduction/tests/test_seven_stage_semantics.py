#!/usr/bin/env python3
"""Regression tests for the seven-stage timing candidate rewrites."""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve()
STAGE_REDUCTION = HERE.parents[1]
if str(STAGE_REDUCTION) not in sys.path:
    sys.path.insert(0, str(STAGE_REDUCTION))

import verify_stage_reduction_semantics as sem


SOURCE = sem.read_source(sem.CANDIDATE_P4)
CONSTS = sem.extract_consts(SOURCE)


def _swap_source_order(source: str, first: str, second: str) -> str:
    first_index = source.index(first)
    second_index = source.index(second)
    if not first_index < second_index:
        raise AssertionError("swap helper expects snippets in source order")
    return source[:first_index] + second + source[first_index + len(first) : second_index] + first + source[second_index + len(second) :]


class TestSevenStageAckFirstWidth(unittest.TestCase):
    def test_deadline_arm_once_uses_full_word_predicate_with_same_value_contract(self) -> None:
        clean = sem.strip_comments(SOURCE)
        self.assertIn('bit<32> ack_first', clean)
        self.assertIn('@pa_container_size("ingress", "meta.ack_first", 32)', clean)
        body = sem.extract_register_action_block(SOURCE, "deadline_arm_once")
        self.assertIn("out bit<32> rv", body)
        for stored in (0, CONSTS["UNARMED_WORD"], 0x00000001, 0xFFFFFF01):
            with self.subTest(stored=hex(stored)):
                rv, new_stored = sem.eval_deadline_arm_once_body(body, stored, 0x01000001, CONSTS)
                self.assertIn(rv, (0, 1))
                self.assertEqual((rv, new_stored), sem.deadline_arm_once_candidate(stored, 0x01000001, CONSTS))

    def test_deadline_arm_once_width_mutation_controls_fail(self) -> None:
        body = sem.extract_register_action_block(SOURCE, "deadline_arm_once")
        mutations = {
            "returns raw prestate": body.replace("rv = 32w1;", "rv = v;", 1),
            "returns non predicate": body.replace("rv = 32w1;", "rv = 32w2;", 1),
            "does not write candidate": body.replace("v = meta.dl_val;", "", 1),
        }
        for label, mutated in mutations.items():
            with self.subTest(label=label):
                with self.assertRaises(AssertionError):
                    sem.eval_deadline_arm_once_body(mutated, CONSTS["UNARMED_WORD"], 0x01000001, CONSTS)


class TestSevenStageDependencyOrder(unittest.TestCase):
    def test_source_preserves_tracker_and_authorise_dependency_order(self) -> None:
        sem.assert_seven_stage_dependency_order(SOURCE)

    def test_dependency_order_mutation_controls_fail(self) -> None:
        seq_block = re.search(
            r"if\s*\(\s*meta\.sess\s*==\s*SESS_MASTER.*?\)\s*\{\s*meta\.seq_diff\s*=\s*exp_seq_w\.execute\(0\);\s*\}\s*"
            r"else\s*\{\s*meta\.seq_diff\s*=\s*exp_seq_r\.execute\(0\);\s*\}",
            SOURCE,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(seq_block)
        authorise_guard = "if (meta.pkt_class == CLASS_RESP) { tbl_resp_authorise.apply(); }"
        mutations = {
            "expected ack before exp-ack candidate": _swap_source_order(
                SOURCE,
                "tbl_build_exp_ack.apply();",
                "tbl_expected_ack.apply();",
            ),
            "authorise before seq trackers": _swap_source_order(
                SOURCE,
                seq_block.group(0),
                authorise_guard,
            ),
            "authorise before session port": _swap_source_order(
                SOURCE,
                "meta.sport_diff = sess_port_rmw.execute(0);",
                authorise_guard,
            ),
            "authorise before expected ack": _swap_source_order(
                SOURCE,
                "tbl_expected_ack.apply();",
                authorise_guard,
            ),
        }
        for label, mutated in mutations.items():
            with self.subTest(label=label):
                with self.assertRaises(AssertionError):
                    sem.assert_seven_stage_dependency_order(mutated)


class TestSevenStageEpochSplit(unittest.TestCase):
    def test_epoch_source_uses_token_owned_retirement_only(self) -> None:
        sem.assert_seven_stage_epoch_action_bodies(SOURCE)
        apply_block = sem.extract_named_block(SOURCE, "apply")
        self.assertIn("if (meta.bor_pc == BPC_TOKEN)        { meta.blk_op_live = epoch_token.execute(0); }", apply_block)
        self.assertIn("else                                 { meta.epoch_stored = epoch_read.execute(0); }", apply_block)

    def test_epoch_split_matches_old_token_watchdog_semantics_full_byte_domain(self) -> None:
        bor_pcs = [
            CONSTS["BPC_TOKEN"],
            CONSTS["BPC_PREPARE"],
            CONSTS["BPC_RELEASE"],
            CONSTS["BPC_OPERATE"],
            CONSTS["BPC_PKTGEN_OP"],
            CONSTS["BPC_NONE"],
        ]
        for bor_pc in bor_pcs:
            for epoch_stored in range(256):
                for hdr_gen in range(256):
                    for budget_zero in (0, 1):
                        with self.subTest(bor_pc=bor_pc, epoch_stored=epoch_stored, hdr_gen=hdr_gen, budget_zero=budget_zero):
                            expected = sem.epoch_baseline_selected(
                                bor_pc=bor_pc,
                                epoch_stored=epoch_stored,
                                hdr_gen=hdr_gen,
                                budget_zero=budget_zero,
                                consts=CONSTS,
                            )
                            actual = sem.epoch_candidate_selected(
                                bor_pc=bor_pc,
                                epoch_stored=epoch_stored,
                                hdr_gen=hdr_gen,
                                budget_zero=budget_zero,
                                consts=CONSTS,
                            )
                            self.assertEqual(actual, expected)

    def test_epoch_source_mutation_controls_fail(self) -> None:
        mutations = {
            "read retires again": SOURCE.replace("void apply(inout bit<8> v, out bit<8> rv) { rv = v; }", "void apply(inout bit<8> v, out bit<8> rv) { rv = v; v = EPOCH_NONE; }", 1),
            "token loses budget guard": SOURCE.replace("meta.budget_zero == 8w1 && hdr.ib.gen == v", "hdr.ib.gen == v", 1),
            "token uses stale tok_spent": SOURCE.replace("meta.budget_zero == 8w1", "meta.tok_spent == 8w1", 1),
        }
        for label, mutated in mutations.items():
            with self.subTest(label=label):
                with self.assertRaises(AssertionError):
                    sem.assert_seven_stage_epoch_action_bodies(mutated)


class TestSevenStageExpectedAckSelector(unittest.TestCase):
    def test_expected_ack_source_is_bound_to_raw_selector_and_salu_actions(self) -> None:
        sem.assert_seven_stage_expected_ack_source(SOURCE)
        table = sem.parse_const_table(SOURCE, "tbl_expected_ack", CONSTS)
        self.assertEqual(table.keys, ("dequeued", "is_pktgen", "role", "sess"))

    def test_expected_ack_selector_matches_original_class_arm_branch(self) -> None:
        table = sem.parse_const_table(SOURCE, "tbl_expected_ack", CONSTS)
        roles = [0, CONSTS["ROLE_ARM"], CONSTS.get("ROLE_ACK", 4), CONSTS.get("ROLE_RESP", 5), CONSTS.get("ROLE_BLOCK", 3), 255]
        sessions = [CONSTS.get("SESS_NONE", 0), CONSTS.get("SESS_RELAY", 1), CONSTS["SESS_MASTER"], 255]
        for dequeued in (0, 1, 2, 255):
            for is_pktgen in (0, 1, 2, 255):
                for role in roles:
                    for sess in sessions:
                        fields = {
                            "dequeued": dequeued,
                            "is_pktgen": is_pktgen,
                            "role": role,
                            "sess": sess,
                        }
                        with self.subTest(**fields):
                            expected = sem.expected_ack_baseline_selector(**fields, consts=CONSTS)
                            self.assertEqual(table.apply(fields), expected)

    def test_expected_ack_actions_preserve_register_outputs_and_writes(self) -> None:
        table = sem.parse_const_table(SOURCE, "tbl_expected_ack", CONSTS)
        cases = [
            {"dequeued": 0, "is_pktgen": 0, "role": CONSTS["ROLE_ARM"], "sess": CONSTS["SESS_MASTER"]},
            {"dequeued": 0, "is_pktgen": 1, "role": CONSTS["ROLE_ARM"], "sess": CONSTS["SESS_MASTER"]},
            {"dequeued": 1, "is_pktgen": 0, "role": CONSTS["ROLE_ARM"], "sess": CONSTS["SESS_MASTER"]},
            {"dequeued": 0, "is_pktgen": 0, "role": CONSTS["ROLE_ARM"], "sess": CONSTS.get("SESS_RELAY", 1)},
        ]
        registers = [0, 1, 0x01020304, 0xFFFFFFFF]
        ack_values = [0, 1, 0x11111111, 0xFFFFFFFF]
        cand_values = [0, 1, 0x22222222, 0xFFFFFFFF]
        for fields in cases:
            action = table.apply(fields)
            for stored in registers:
                for ack_no in ack_values:
                    for exp_ack_cand in cand_values:
                        with self.subTest(fields=fields, stored=hex(stored), ack_no=hex(ack_no), exp_ack_cand=hex(exp_ack_cand)):
                            expected_action = sem.expected_ack_baseline_selector(**fields, consts=CONSTS)
                            self.assertEqual(action, expected_action)
                            self.assertEqual(
                                sem.expected_ack_action_effect(action, stored=stored, ack_no=ack_no, exp_ack_cand=exp_ack_cand),
                                sem.expected_ack_action_effect(expected_action, stored=stored, ack_no=ack_no, exp_ack_cand=exp_ack_cand),
                            )

    def test_expected_ack_source_mutation_controls_fail(self) -> None:
        missing_pktgen_priority = re.sub(
            r"\(8w0,\s*8w1,\s*8w0&&&8w0,\s*8w0&&&8w0\)\s*:\s*read_expected_ack\(\);",
            "",
            SOURCE,
            count=1,
        )
        mutations = {
            "missing pktgen priority": missing_pktgen_priority,
            "write row becomes read": SOURCE.replace("(8w0, 8w0&&&8w0, ROLE_ARM, SESS_MASTER) : write_expected_ack();", "(8w0, 8w0&&&8w0, ROLE_ARM, SESS_MASTER) : read_expected_ack();", 1),
            "write action calls reader": SOURCE.replace("meta.ack_diff = exp_ack_w.execute(0);", "meta.ack_diff = exp_ack_r.execute(0);", 1),
            "reader writes candidate": SOURCE.replace("rv = hdr.tcp.ack_no - v;\n        }", "rv = hdr.tcp.ack_no - v;\n            v = meta.exp_ack_cand;\n        }", 1),
        }
        self.assertNotEqual(missing_pktgen_priority, SOURCE)
        for label, mutated in mutations.items():
            with self.subTest(label=label):
                with self.assertRaises(AssertionError):
                    sem.assert_seven_stage_expected_ack_source(mutated)


class TestSevenStageRespAuthoriseGuard(unittest.TestCase):
    def test_resp_authorise_is_guarded_and_preserves_non_response_tag_val(self) -> None:
        sem.assert_resp_authorise_guard_source(SOURCE)
        table = sem.parse_const_table(SOURCE, "tbl_resp_authorise", CONSTS)
        pkt_classes = [CONSTS.get("CLASS_OTHER", 0), CONSTS["CLASS_ARM"], CONSTS.get("CLASS_ACK", 2), CONSTS.get("CLASS_BLOCK_DEQ", 3), CONSTS["CLASS_RESP"], CONSTS.get("CLASS_ACK_REL", 5)]
        diffs = [(0, 0, 0), (1, 0, 0), (0, 1, 0), (0, 0, 1), (0x12345678, 0x9ABCDEF0, 0x1234)]
        for pkt_class in pkt_classes:
            for seq_diff, ack_diff, sport_diff in diffs:
                for tag_val in (0, CONSTS["TAG_NO_WRITE"], CONSTS["TAG_PENDING_DELTA"], 0xFF):
                    fields = {"pkt_class": pkt_class, "seq_diff": seq_diff, "ack_diff": ack_diff, "sport_diff": sport_diff}
                    with self.subTest(fields=fields, tag_val=tag_val):
                        old = sem.resp_authorise_old_effect(table, fields, tag_val, CONSTS)
                        guarded = sem.resp_authorise_guarded_effect(table, fields, tag_val, CONSTS)
                        if pkt_class == CONSTS["CLASS_RESP"]:
                            self.assertEqual(guarded, old)
                        else:
                            self.assertEqual(guarded, tag_val & 0xFF)


    def test_resp_authorise_failopen_chain_preserves_end_metadata(self) -> None:
        table = sem.parse_const_table(SOURCE, "tbl_resp_authorise", CONSTS)
        resp_fields = {"pkt_class": CONSTS["CLASS_RESP"], "seq_diff": 0, "ack_diff": 0, "sport_diff": 0}
        resp_tag = sem.resp_authorise_guarded_effect(table, resp_fields, CONSTS["TAG_NO_WRITE"], CONSTS)
        cases = [
            (CONSTS["CLASS_RESP"], CONSTS.get("MODE_D4_DUAL", 4), 0, CONSTS["TAG_NO_WRITE"], resp_tag, 0xAA, (resp_tag, False)),
            (CONSTS["CLASS_ARM"], CONSTS["MODE_OFF"], 0, 0x55, 0x99, 0xAA, (CONSTS["TAG_NO_WRITE"], False)),
            (CONSTS["CLASS_ARM"], CONSTS["MODE_FAIL_OPEN"], 0, 0x55, 0x99, 0xAA, (CONSTS["TAG_NO_WRITE"], False)),
            (CONSTS["CLASS_ARM"], CONSTS.get("MODE_D4_DUAL", 4), 0, 0x55, 0x99, 0xAA, (0xAA, False)),
            (CONSTS.get("CLASS_BLOCK_DEQ", 3), CONSTS.get("MODE_D4_DUAL", 4), 1, 0x55, 0x99, 0xAA, (0x55, True)),
            (CONSTS.get("CLASS_OTHER", 0), CONSTS.get("MODE_D4_DUAL", 4), 0, 0x55, 0x99, 0xAA, (0x55, False)),
        ]
        for pkt_class, mode, budget_zero, tag_val, auth_tag, fo_take, expected in cases:
            with self.subTest(pkt_class=pkt_class, mode=mode, budget_zero=budget_zero):
                actual = sem.failopen_authorise_chain_effect(
                    pkt_class=pkt_class,
                    mode=mode,
                    budget_zero=budget_zero,
                    tag_val=tag_val,
                    resp_authorised_tag=auth_tag,
                    fo_take_value=fo_take,
                    consts=CONSTS,
                )
                self.assertEqual(actual, expected)

    def test_resp_authorise_guard_mutation_controls_fail(self) -> None:
        mutations = {
            "unguarded apply": SOURCE.replace("if (meta.pkt_class == CLASS_RESP) { tbl_resp_authorise.apply(); }", "tbl_resp_authorise.apply();", 1),
            "wrong guard class": SOURCE.replace("if (meta.pkt_class == CLASS_RESP) { tbl_resp_authorise.apply(); }", "if (meta.pkt_class == CLASS_ARM) { tbl_resp_authorise.apply(); }", 1),
        }
        for label, mutated in mutations.items():
            with self.subTest(label=label):
                with self.assertRaises(AssertionError):
                    sem.assert_resp_authorise_guard_source(mutated)


if __name__ == "__main__":
    unittest.main(verbosity=2)

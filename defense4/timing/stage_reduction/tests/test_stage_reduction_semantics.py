#!/usr/bin/env python3
"""Regression tests for semantics-preserving timing stage reductions."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve()
STAGE_REDUCTION = HERE.parents[1]
if str(STAGE_REDUCTION) not in sys.path:
    sys.path.insert(0, str(STAGE_REDUCTION))

import verify_stage_reduction_semantics as sem


BASELINE_SOURCE = sem.read_source(sem.BASELINE_P4)
BASELINE_CONSTS = sem.extract_consts(BASELINE_SOURCE)


def candidate_source_or_skip(testcase: unittest.TestCase) -> str:
    if not sem.CANDIDATE_P4.exists():
        testcase.skipTest(f"candidate source not present yet: {sem.CANDIDATE_P4}")
    return sem.read_source(sem.CANDIDATE_P4)


class TestSourceAnchors(unittest.TestCase):
    def test_baseline_constants_are_the_timing_contract(self) -> None:
        expected = {
            "TICK_MASK": 0xFFFFFF00,
            "ARMED_MARK": 0x00000001,
            "UNARMED_WORD": 0x00000002,
            "DL_NO_WRITE": 0x00000000,
            "EPOCH_NONE": 0,
            "GEN_INACTIVE": 0,
            "BPC_OPERATE": 2,
            "BPC_TOKEN": 3,
            "BPC_RELEASE": 4,
            "BPC_PKTGEN_OP": 5,
        }
        for name, value in expected.items():
            self.assertEqual(BASELINE_CONSTS[name], value, name)

    def test_baseline_still_contains_the_actions_being_optimized(self) -> None:
        for name in ("deadline_arm_once", "ready_read", "tbl_deadline_expiry", "tbl_tresp_expiry", "tbl_topj_expiry"):
            with self.subTest(name=name):
                self.assertIn(name, BASELINE_SOURCE)

    def test_candidate_has_folded_decode_before_hold_ordering(self) -> None:
        source = candidate_source_or_skip(self)
        apply_block = sem.extract_named_block(source, "apply")
        normalized = " ".join(apply_block.split())
        self.assertIn("tbl_select_deadlines.apply(); tbl_state_decode.apply(); tbl_resp_deadline.apply();", normalized)
        self.assertLess(apply_block.index("tbl_state_decode.apply()"), apply_block.index("tbl_hold_ok.apply()"))
        self.assertNotIn("meta.bor_pc == BPC_OPERATE && meta.hold_ok == 8w1", apply_block)
        self.assertNotIn("meta.anchor_req == 8w1 && meta.pkt_class == CLASS_ARM", apply_block)


class TestDeadlineExpiryMask(unittest.TestCase):
    def test_all_expiry_tables_use_the_same_wrap_safe_mask(self) -> None:
        entries = {
            name: sem.extract_single_ternary_entry(BASELINE_SOURCE, name)
            for name in ("tbl_deadline_expiry", "tbl_tresp_expiry", "tbl_topj_expiry")
        }
        for name, entry in entries.items():
            with self.subTest(table=name):
                self.assertEqual(entry.value, 0)
                self.assertEqual(entry.mask, 0x800000FF)

    def test_wrap_case_rejects_the_direct_leq_shortcut(self) -> None:
        entry = sem.extract_single_ternary_entry(BASELINE_SOURCE, "tbl_topj_expiry")
        deadline = 0xFFF00001
        now = 0x00100001
        age = sem.age_word(now, deadline)
        self.assertTrue(sem.table_expired(age, entry))
        self.assertFalse(sem.direct_leq_due(now, deadline))

    def test_unarmed_and_future_deadlines_do_not_look_expired(self) -> None:
        entry = sem.extract_single_ternary_entry(BASELINE_SOURCE, "tbl_deadline_expiry")
        for now in (0x00000001, 0x00010001, 0xFFFFFF01):
            with self.subTest(now=hex(now), case="unarmed"):
                age = sem.age_word(now, BASELINE_CONSTS["UNARMED_WORD"])
                self.assertFalse(sem.table_expired(age, entry))

        now = 0x00100001
        future_deadline = 0x00200001
        self.assertFalse(sem.table_expired(sem.age_word(now, future_deadline), entry))


class TestDeadlineArmOncePredicate(unittest.TestCase):
    def test_candidate_predicate_contract_matches_baseline_ack_first(self) -> None:
        baseline_action = sem.extract_register_action_block(BASELINE_SOURCE, "deadline_arm_once")
        dl_val = 0x01000001
        stored_words = [
            0,
            BASELINE_CONSTS["UNARMED_WORD"],
            0x00000001,
            0x00FF0001,
            0xFFFFFF01,
        ]
        for stored in stored_words:
            with self.subTest(stored=hex(stored)):
                baseline_rv, baseline_new = sem.eval_deadline_arm_once_body(
                    baseline_action, stored, dl_val, BASELINE_CONSTS
                )
                baseline_ack_first = 1 if baseline_rv == BASELINE_CONSTS["UNARMED_WORD"] else 0
                candidate_rv, candidate_new = sem.deadline_arm_once_candidate(stored, dl_val, BASELINE_CONSTS)
                self.assertEqual(candidate_rv, baseline_ack_first)
                self.assertEqual(candidate_new, baseline_new)

    def test_candidate_source_returns_byte_predicate_when_present(self) -> None:
        source = candidate_source_or_skip(self)
        action = sem.extract_register_action_block(source, "deadline_arm_once")
        dl_val = 0x01000001
        for stored in (0, BASELINE_CONSTS["UNARMED_WORD"], 0x00000001, 0xFFFFFF01):
            with self.subTest(stored=hex(stored)):
                rv, new_stored = sem.eval_deadline_arm_once_body(action, stored, dl_val, BASELINE_CONSTS)
                self.assertIn(rv, (0, 1))
                self.assertEqual((rv, new_stored), sem.deadline_arm_once_candidate(stored, dl_val, BASELINE_CONSTS))


class TestReadyReadPredicate(unittest.TestCase):
    def test_ready_equality_candidate_preserves_full_byte_domain(self) -> None:
        baseline_action = sem.extract_register_action_block(BASELINE_SOURCE, "ready_read")
        for epoch in range(256):
            for ready in range(256):
                with self.subTest(epoch=epoch, ready=ready):
                    raw = sem.eval_ready_read_body(baseline_action, ready, epoch)
                    baseline_ready = 1 if epoch != BASELINE_CONSTS["EPOCH_NONE"] and raw == epoch else 0
                    candidate_predicate = sem.ready_read_candidate(ready, epoch, BASELINE_CONSTS)
                    candidate_ready = 1 if epoch != BASELINE_CONSTS["EPOCH_NONE"] and candidate_predicate == 1 else 0
                    self.assertEqual(candidate_ready, baseline_ready)

    def test_epoch_zero_is_not_ready_even_when_ready_register_is_zero(self) -> None:
        _raw, baseline_ready = sem.ready_read_baseline(0, 0, BASELINE_CONSTS)
        candidate_predicate = sem.ready_read_candidate(0, 0, BASELINE_CONSTS)
        self.assertEqual(candidate_predicate, 1)
        self.assertEqual(baseline_ready, 0)
        self.assertEqual(1 if 0 != BASELINE_CONSTS["EPOCH_NONE"] and candidate_predicate else 0, 0)

    def test_candidate_source_returns_ready_predicate_when_present(self) -> None:
        source = candidate_source_or_skip(self)
        action = sem.extract_register_action_block(source, "ready_read")
        try:
            probe = sem.eval_ready_read_body(action, 2, 1)
        except AssertionError as exc:
            self.fail(str(exc))
        self.assertIn(probe, (0, 1), "candidate ready_read must return a byte predicate, not raw ready_stored")
        for epoch in range(256):
            for ready in range(256):
                with self.subTest(epoch=epoch, ready=ready):
                    rv = sem.eval_ready_read_body(action, ready, epoch)
                    self.assertEqual(rv, sem.ready_read_candidate(ready, epoch, BASELINE_CONSTS))


class TestBorTerminalPriority(unittest.TestCase):
    def test_baseline_bor_terminal_priority_over_full_small_domain(self) -> None:
        outcomes = set()
        for case in sem.enumerate_bor_terminal_domain(BASELINE_CONSTS):
            outcome = sem.bor_terminal_baseline(**case, consts=BASELINE_CONSTS)
            outcomes.add(outcome)

            if case["bor_pc"] == BASELINE_CONSTS["BPC_TOKEN"] and case["blk_op_live"] == 0:
                self.assertEqual(outcome, "OUT_OP_TERM_STALE")
            if (
                case["bor_pc"] == BASELINE_CONSTS["BPC_TOKEN"]
                and case["blk_op_live"] == 1
                and case["expired_topj"] == 1
            ):
                self.assertEqual(outcome, "OUT_OP_TERM_DL")
            if (
                case["bor_pc"] == BASELINE_CONSTS["BPC_TOKEN"]
                and case["blk_op_live"] == 1
                and case["expired_topj"] == 0
                and case["budget_zero"] == 1
            ):
                self.assertEqual(outcome, "OUT_OP_TERM_TMO")

        required = {
            "OUT_OP_DUP",
            "OUT_OP_HOLD",
            "OUT_OP_TERM_STALE",
            "OUT_OP_TERM_DL",
            "OUT_OP_TERM_TMO",
            "OUT_OP_LOOP",
            "OUT_OP_RELAY",
            "OUT_OP_ADMIT",
            "OUT_PKTGEN_DROP",
            "FALLTHROUGH_FRESH",
            "FALLTHROUGH",
        }
        self.assertTrue(required.issubset(outcomes))

    def test_candidate_has_no_late_bor_if_ladder_when_bor_rows_move_into_decide_tables(self) -> None:
        source = candidate_source_or_skip(self)
        fresh = sem.parse_const_table(source, "tbl_decide_fresh", sem.extract_consts(source))
        deq = sem.parse_const_table(source, "tbl_decide_deq", sem.extract_consts(source))
        self.assertIn("bor_pc", fresh.keys)
        self.assertIn("bor_pc", deq.keys)
        apply_block = sem.extract_named_block(source, "apply")
        self.assertNotIn("tbl_bor_decide", source)
        for terminal_outcome in (
            "OUT_OP_DUP",
            "OUT_OP_HOLD",
            "OUT_OP_TERM_STALE",
            "OUT_OP_TERM_DL",
            "OUT_OP_TERM_TMO",
            "OUT_OP_LOOP",
            "OUT_OP_RELAY",
            "OUT_PKTGEN_DROP",
        ):
            self.assertNotIn(terminal_outcome, apply_block)
        normalized_apply = " ".join(apply_block.split())
        self.assertIn("if (meta.dequeued == 8w0) { tbl_decide_fresh.apply(); }", normalized_apply)
        self.assertIn("else { tbl_decide_deq.apply();", normalized_apply)

    def test_candidate_fresh_table_bor_rows_match_old_priority_when_present(self) -> None:
        source = candidate_source_or_skip(self)
        consts = sem.extract_consts(source)
        fresh = sem.parse_const_table(source, "tbl_decide_fresh", consts)
        self.assertIn("bor_pc", fresh.keys)

        base = {
            key: 0
            for key in fresh.keys
        }
        cases = [
            ("operate duplicate", {"bor_pc": consts["BPC_OPERATE"], "verdict_bor": consts["V_OP_DUP"]}, "OUT_OP_DUP"),
            (
                "operate fresh hold",
                {"bor_pc": consts["BPC_OPERATE"], "verdict_bor": consts["V_OP_FRESH"], "hold_ok": 1},
                "OUT_OP_HOLD",
            ),
            (
                "pktgen op admitted",
                {"bor_pc": consts["BPC_PKTGEN_OP"], "epoch_stored": 1},
                "OUT_OP_ADMIT",
            ),
            (
                "pktgen op no epoch",
                {"bor_pc": consts["BPC_PKTGEN_OP"], "epoch_stored": consts["EPOCH_NONE"]},
                "OUT_PKTGEN_DROP",
            ),
        ]
        for label, fields, expected in cases:
            packet = dict(base)
            packet.update(fields)
            with self.subTest(label=label):
                self.assertEqual(fresh.apply(packet), expected)

    def test_candidate_deq_table_bor_rows_match_old_priority_when_present(self) -> None:
        source = candidate_source_or_skip(self)
        consts = sem.extract_consts(source)
        deq = sem.parse_const_table(source, "tbl_decide_deq", consts)
        self.assertIn("bor_pc", deq.keys)

        due_age = 0x00000000
        future_age = 0x80000000
        cases = [
            ("release", {"bor_pc": consts["BPC_RELEASE"]}, "OUT_OP_RELAY"),
            ("token stale", {"bor_pc": consts["BPC_TOKEN"], "blk_op_live": 0, "age_topj": due_age, "budget_zero": 1}, "OUT_OP_TERM_STALE"),
            ("token due", {"bor_pc": consts["BPC_TOKEN"], "blk_op_live": 1, "age_topj": due_age, "budget_zero": 1}, "OUT_OP_TERM_DL"),
            ("token timeout", {"bor_pc": consts["BPC_TOKEN"], "blk_op_live": 1, "age_topj": future_age, "budget_zero": 1}, "OUT_OP_TERM_TMO"),
            ("token loop", {"bor_pc": consts["BPC_TOKEN"], "blk_op_live": 1, "age_topj": future_age, "budget_zero": 0}, "OUT_OP_LOOP"),
        ]
        for label, fields, expected in cases:
            packet = {key: 0 for key in deq.keys}
            packet.update(fields)
            with self.subTest(label=label):
                self.assertEqual(deq.apply(packet), expected)


class TestCandidateActionBodyAnchors(unittest.TestCase):
    def test_candidate_action_bodies_match_deadline_model(self) -> None:
        source = candidate_source_or_skip(self)
        sem.assert_current_candidate_action_bodies(source)

    def test_deadline_model_rejects_common_source_mutations(self) -> None:
        source = candidate_source_or_skip(self)
        mutations = {
            "ack arm becomes read": source.replace("meta.ack_first = deadline_arm_once.execute(0);", "meta.age = deadline_read.execute(0);", 1),
            "arm fresh stops disarming": source.replace("meta.age = deadline_disarm.execute(0);", "meta.age = deadline_read.execute(0);", 1),
            "response disarm becomes read": source.replace("meta.age_resp = tresp_disarm.execute(0);", "meta.age_resp = tresp_read.execute(0);", 1),
            "operate selector loses op candidate": source.replace("meta.dl_val = meta.dl_cand_op", "meta.dl_val = meta.dl_cand", 1),
            "ack release resurrects tag_val write": source.replace("action dec_ack_rel() {", "action dec_ack_rel() { meta.tag_val = meta.cur_gen;", 1),
        }
        for label, mutated in mutations.items():
            with self.subTest(label=label):
                with self.assertRaises(AssertionError):
                    sem.assert_current_candidate_action_bodies(mutated)


class TestStateDecodeFoldedOverrides(unittest.TestCase):
    def test_candidate_state_decode_folds_anchor_and_operate_hold_overrides(self) -> None:
        source = candidate_source_or_skip(self)
        consts = sem.extract_consts(source)
        table = sem.parse_const_table(source, "tbl_state_decode", consts)
        self.assertEqual(
            table.keys,
            ("bor_pc", "hold_ok", "anchor_req", "pkt_class", "tag_diff", "seq_diff", "ack_diff", "sport_diff"),
        )
        block = sem.extract_named_block(source, "apply")
        self.assertNotIn("meta.anchor_req == 8w1 && meta.pkt_class == CLASS_ARM", block)
        self.assertNotIn("meta.bor_pc == BPC_OPERATE && meta.hold_ok == 8w1", block)
        self.assertIn("dec_arm_request", sem.extract_named_block(source, "tbl_state_decode"))
        self.assertIn("dec_ack_arm_op", sem.extract_named_block(source, "tbl_state_decode"))

    def test_candidate_state_decode_matches_baseline_plus_old_overrides(self) -> None:
        baseline_table = sem.parse_const_table(BASELINE_SOURCE, "tbl_state_decode", BASELINE_CONSTS)
        source = candidate_source_or_skip(self)
        consts = sem.extract_consts(source)
        candidate_table = sem.parse_const_table(source, "tbl_state_decode", consts)

        pkt_classes = [consts[name] for name in (
            "CLASS_OTHER", "CLASS_ARM", "CLASS_ACK", "CLASS_BLOCK_DEQ", "CLASS_RESP", "CLASS_ACK_REL"
        )]
        tracker_cases = [
            (0, 0, 0),
            (1, 0, 0),
            (0, 1, 0),
            (0, 0, 1),
            (0x12345678, 0x9ABCDEF0, 0x1234),
        ]
        for pkt_class in pkt_classes:
            for tag_diff in range(256):
                for seq_diff, ack_diff, sport_diff in tracker_cases:
                    for anchor_req in (0, 1):
                        for bor_pc in range(6):
                            for hold_ok in (0, 1):
                                fields = {
                                    "pkt_class": pkt_class,
                                    "tag_diff": tag_diff,
                                    "seq_diff": seq_diff,
                                    "ack_diff": ack_diff,
                                    "sport_diff": sport_diff,
                                    "anchor_req": anchor_req,
                                    "bor_pc": bor_pc,
                                    "hold_ok": hold_ok,
                                }
                                with self.subTest(
                                    pkt_class=pkt_class,
                                    tag_diff=tag_diff,
                                    trackers=(seq_diff, ack_diff, sport_diff),
                                    anchor_req=anchor_req,
                                    bor_pc=bor_pc,
                                    hold_ok=hold_ok,
                                ):
                                    expected = sem.baseline_state_decode_with_overrides(
                                        baseline_table, fields, BASELINE_CONSTS
                                    )
                                    actual = sem.candidate_state_decode_effect(candidate_table, fields, consts)
                                    self.assertEqual(actual, expected)


class TestAckReleaseDependencyFold(unittest.TestCase):
    def test_ack_release_rmw_cur_gen_rewrite_preserves_update_and_return(self) -> None:
        source = candidate_source_or_skip(self)
        action = sem.extract_register_action_block(source, "ack_rel_rmw")
        self.assertIn("rv = meta.cur_gen - v", action)
        self.assertIn("if (meta.cur_gen != TAG_NO_WRITE) { v = meta.cur_gen; }", " ".join(action.split()))
        consts = sem.extract_consts(source)
        tag_no_write = consts["TAG_NO_WRITE"]
        for stored in range(256):
            for cur_gen in range(256):
                with self.subTest(stored=stored, cur_gen=cur_gen):
                    # Old path first ran dec_ack_rel(), making meta.tag_val = meta.cur_gen.
                    old_rv = (cur_gen - stored) & 0xFF
                    old_new = cur_gen if cur_gen != tag_no_write else stored
                    new_rv = (cur_gen - stored) & 0xFF
                    new_new = cur_gen if cur_gen != tag_no_write else stored
                    self.assertEqual((new_rv, new_new), (old_rv, old_new))

    def test_fresh_decision_uses_rel_diff_for_ack_release_timing(self) -> None:
        source = candidate_source_or_skip(self)
        table = sem.extract_named_block(source, "tbl_decide_fresh")
        self.assertIn("meta.rel_diff", table)
        self.assertNotIn("meta.tag_diff", table)
        consts = sem.extract_consts(source)
        fresh = sem.parse_const_table(source, "tbl_decide_fresh", consts)
        self.assertIn("rel_diff", fresh.keys)


class TestTopjHoldInlineWhenPresent(unittest.TestCase):
    def test_topj_rmw_is_folded_into_hold_path_when_present(self) -> None:
        source = candidate_source_or_skip(self)
        apply_block = sem.extract_named_block(source, "apply")
        self.assertNotIn("meta.age_topj = topj_rmw.execute(0);", apply_block)
        self.assertIn("meta.age_topj = topj_arm.execute(0)", sem.extract_named_block(source, "hold_and_arm"))
        self.assertIn("meta.age_topj = topj_read.execute(0)", sem.extract_named_block(source, "read_topj"))
        hold = sem.parse_const_table(source, "tbl_hold_ok", sem.extract_consts(source))
        self.assertIn("read_topj", {row.action for row in hold.rows})

    def test_topj_inline_matches_old_hold_then_rmw_semantics(self) -> None:
        source = candidate_source_or_skip(self)
        apply_block = sem.extract_named_block(source, "apply")
        self.assertNotIn("meta.age_topj = topj_rmw.execute(0);", apply_block)
        consts = sem.extract_consts(source)
        hold = sem.parse_const_table(source, "tbl_hold_ok", consts)
        now = 0x01000001
        for bor_pc in range(6):
            for epoch_stored in (0, 1, 2, 0xFF):
                for ready_stored in (0, 1):
                    for gen_stored in (0, 1, 2, 0xFF):
                        for stored_topj in (0x00010001, 0xFFF00001):
                            for topj_cand in (consts["DL_NO_WRITE"], 0x02000001):
                                fields = {
                                    "bor_pc": bor_pc,
                                    "epoch_stored": epoch_stored,
                                    "ready_stored": ready_stored,
                                    "gen_stored": gen_stored,
                                }
                                action = hold.apply(fields)
                                old_holds = (
                                    bor_pc == consts["BPC_OPERATE"]
                                    and epoch_stored != consts["EPOCH_NONE"]
                                    and ready_stored == 1
                                    and gen_stored == consts["GEN_INACTIVE"]
                                )
                                old_executes = bor_pc in (consts["BPC_OPERATE"], consts["BPC_TOKEN"])
                                if old_holds:
                                    old_hold_ok = 1
                                    old_new = topj_cand if topj_cand != consts["DL_NO_WRITE"] else stored_topj
                                    old_age = (now - old_new) & 0xFFFFFFFF
                                elif old_executes:
                                    old_hold_ok = 0
                                    old_new = stored_topj
                                    old_age = (now - stored_topj) & 0xFFFFFFFF
                                else:
                                    old_hold_ok = 0
                                    old_new = stored_topj
                                    old_age = None

                                if action == "hold_and_arm":
                                    new_hold_ok = 1
                                    new_new = topj_cand if topj_cand != consts["DL_NO_WRITE"] else stored_topj
                                    new_age = (now - new_new) & 0xFFFFFFFF
                                elif action == "read_topj":
                                    new_hold_ok = 0
                                    new_new = stored_topj
                                    new_age = (now - stored_topj) & 0xFFFFFFFF
                                elif action == "clr_hold_ok":
                                    new_hold_ok = 0
                                    new_new = stored_topj
                                    new_age = None
                                else:
                                    self.fail(f"unexpected hold action {action!r}")

                                with self.subTest(
                                    bor_pc=bor_pc,
                                    epoch_stored=epoch_stored,
                                    ready_stored=ready_stored,
                                    gen_stored=gen_stored,
                                    stored_topj=hex(stored_topj),
                                    topj_cand=hex(topj_cand),
                                ):
                                    self.assertEqual((new_hold_ok, new_new, new_age), (old_hold_ok, old_new, old_age))


class TestDeadlineRegisterFold(unittest.TestCase):
    def test_deadline_tables_are_split_on_identical_decode_keys(self) -> None:
        source = candidate_source_or_skip(self)
        self.assertIn("tbl_resp_deadline", source)
        consts = sem.extract_consts(source)
        state = sem.parse_const_table(source, "tbl_state_decode", consts)
        response = sem.parse_const_table(source, "tbl_resp_deadline", consts)
        selector = sem.parse_const_table(source, "tbl_select_deadlines", consts)
        self.assertEqual(response.keys, state.keys)
        self.assertEqual(selector.keys, ("bor_pc", "hold_ok"))
        apply_block = sem.extract_named_block(source, "apply")
        normalized = " ".join(apply_block.split())
        self.assertIn("tbl_select_deadlines.apply(); tbl_state_decode.apply(); tbl_resp_deadline.apply();", normalized)
        self.assertNotIn("if (meta.verdict == V_ACK_ARM)", apply_block)

    def test_folded_deadline_register_actions_match_old_post_decode_behavior(self) -> None:
        source = candidate_source_or_skip(self)
        self.assertIn("tbl_resp_deadline", source)
        baseline_table = sem.parse_const_table(BASELINE_SOURCE, "tbl_state_decode", BASELINE_CONSTS)
        consts = sem.extract_consts(source)
        state_table = sem.parse_const_table(source, "tbl_state_decode", consts)
        response_table = sem.parse_const_table(source, "tbl_resp_deadline", consts)
        select_table = sem.parse_const_table(source, "tbl_select_deadlines", consts)

        pkt_classes = [consts[name] for name in (
            "CLASS_OTHER", "CLASS_ARM", "CLASS_ACK", "CLASS_BLOCK_DEQ", "CLASS_RESP", "CLASS_ACK_REL"
        )]
        tracker_cases = [
            (0, 0, 0),
            (1, 0, 0),
            (0, 1, 0),
            (0, 0, 1),
            (0x12345678, 0x9ABCDEF0, 0x1234),
        ]
        stored_cases = [
            (consts["UNARMED_WORD"], consts["UNARMED_WORD"]),
            (0x00010001, 0x00020001),
            (0xFFF00001, 0x00000001),
        ]
        values_base = {
            "now_word": 0x00100001,
            "dl_cand": 0x11110001,
            "tresp_cand": 0x22220001,
            "dl_cand_op": 0x33330001,
            "tresp_cand_op": 0x44440001,
        }

        for pkt_class in pkt_classes:
            for tag_diff in range(256):
                for seq_diff, ack_diff, sport_diff in tracker_cases:
                    for anchor_req in (0, 1):
                        for bor_pc in range(6):
                            for hold_ok in (0, 1):
                                fields = {
                                    "pkt_class": pkt_class,
                                    "tag_diff": tag_diff,
                                    "seq_diff": seq_diff,
                                    "ack_diff": ack_diff,
                                    "sport_diff": sport_diff,
                                    "anchor_req": anchor_req,
                                    "bor_pc": bor_pc,
                                    "hold_ok": hold_ok,
                                }
                                for deadline_stored, response_stored in stored_cases:
                                    values = dict(values_base)
                                    values["deadline_stored"] = deadline_stored
                                    values["response_stored"] = response_stored
                                    with self.subTest(
                                        pkt_class=pkt_class,
                                        tag_diff=tag_diff,
                                        trackers=(seq_diff, ack_diff, sport_diff),
                                        anchor_req=anchor_req,
                                        bor_pc=bor_pc,
                                        hold_ok=hold_ok,
                                        deadline_stored=hex(deadline_stored),
                                        response_stored=hex(response_stored),
                                    ):
                                        expected = sem.baseline_deadline_outcome(
                                            baseline_table, fields, BASELINE_CONSTS, values
                                        )
                                        actual = sem.candidate_deadline_outcome(
                                            state_table, response_table, select_table, fields, consts, values
                                        )
                                        self.assertEqual(actual, expected)


class TestBorHoldAndTokenRewrites(unittest.TestCase):
    def test_candidate_hold_ok_table_uses_raw_keys_and_matches_old_hold_condition(self) -> None:
        source = candidate_source_or_skip(self)
        consts = sem.extract_consts(source)
        table = sem.parse_const_table(source, "tbl_hold_ok", consts)
        self.assertEqual(table.keys, ("bor_pc", "epoch_stored", "ready_stored", "gen_stored"))
        block = sem.extract_named_block(source, "tbl_hold_ok")
        self.assertNotIn("meta.op_matched", block)
        self.assertNotIn("meta.op_ready", block)
        self.assertNotIn("meta.verdict_bor", block)

        for bor_pc in range(0, 6):
            for epoch_stored in (0, 1, 2, 0x7F, 0x80, 0xFF):
                for ready_stored in (0, 1):
                    for gen_stored in (0, 1, 2, 0xFF):
                        with self.subTest(
                            bor_pc=bor_pc,
                            epoch_stored=epoch_stored,
                            ready_stored=ready_stored,
                            gen_stored=gen_stored,
                        ):
                            old_holds = (
                                bor_pc == consts["BPC_OPERATE"]
                                and epoch_stored != consts["EPOCH_NONE"]
                                and ready_stored == 1
                                and gen_stored == consts["GEN_INACTIVE"]
                            )
                            action = table.apply(
                                {
                                    "bor_pc": bor_pc,
                                    "epoch_stored": epoch_stored,
                                    "ready_stored": ready_stored,
                                    "gen_stored": gen_stored,
                                }
                            )
                            self.assertEqual(action == "hold_and_arm", old_holds)

    def test_epoch_token_matches_epoch_read_for_token_live_and_retire_effects(self) -> None:
        source = candidate_source_or_skip(self)
        self.assertIn("epoch_token.execute(0)", source)
        self.assertIn("if (meta.bor_pc == BPC_TOKEN)        { meta.blk_op_live = epoch_token.execute(0); }", source)
        consts = sem.extract_consts(source)
        for epoch_stored in range(256):
            for hdr_gen in range(256):
                for tok_spent in (0, 1):
                    with self.subTest(epoch_stored=epoch_stored, hdr_gen=hdr_gen, tok_spent=tok_spent):
                        old_rv, old_epoch = sem.epoch_read_baseline(epoch_stored, hdr_gen, tok_spent, consts)
                        new_live, new_epoch = sem.epoch_token_candidate(epoch_stored, hdr_gen, tok_spent, consts)
                        self.assertEqual(new_live, 1 if hdr_gen == old_rv else 0)
                        self.assertEqual(new_epoch, old_epoch)

    def test_ready_confirm_write_is_equivalent_on_live_token_guard(self) -> None:
        source = candidate_source_or_skip(self)
        action = sem.extract_register_action_block(source, "ready_confirm")
        self.assertIn("v = hdr.ib.gen", action)
        for ready_stored in (0, 1, 2, 0x7F, 0x80, 0xFF):
            for epoch_stored in range(256):
                hdr_gen = epoch_stored
                with self.subTest(ready_stored=ready_stored, epoch_stored=epoch_stored):
                    self.assertEqual(
                        sem.ready_confirm_candidate(ready_stored, hdr_gen),
                        sem.ready_confirm_baseline(ready_stored, epoch_stored),
                    )


class TestCandidateRawAgeDecisionKeys(unittest.TestCase):
    def test_candidate_decide_deq_uses_raw_age_keys_when_present(self) -> None:
        source = candidate_source_or_skip(self)
        table = sem.extract_named_block(source, "tbl_decide_deq")
        self.assertNotIn("meta.expired     : ternary", table)
        self.assertNotIn("meta.expired_resp: ternary", table)
        self.assertIn("meta.age", table)
        self.assertIn("meta.age_resp", table)
        self.assertIn("0x800000FF", table)


if __name__ == "__main__":
    unittest.main(verbosity=2)

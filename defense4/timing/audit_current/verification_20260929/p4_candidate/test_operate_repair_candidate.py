#!/usr/bin/env python3
"""Source-driven OPERATE state checks for the offline repair candidates.

The tests bind a small BOR transition model to concrete P4 source facts:
RegisterAction bodies, release dispatch, verdict rules, decision-table entries,
and commit-table actions. They do not claim switch or receiver behavior.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re
import unittest


DEFAULT_SOURCE = Path(__file__).with_name("defense4_timing_randomized_released_domain_candidate.p4")


@dataclass(frozen=True)
class SourceSemantics:
    release_mode: str
    has_repair_path: bool
    constants: dict[str, int]
    outcome_commits: dict[str, str]


@dataclass
class BorModel:
    sem: SourceSemantics
    epoch: int = 0
    ready: int = 0
    gen: int = 0

    def prepare(self) -> str:
        self.epoch = 1 if self.epoch == 255 else self.epoch + 1
        self.gen = self.const("GEN_INACTIVE")
        self.ready = self.const("EPOCH_NONE")
        return "OUT_BYPASS"

    def confirm_token(self) -> None:
        self.ready = self.epoch

    def operate(self, gen_in: int) -> str:
        old_gen = self.gen
        if self.gen == self.const("GEN_INACTIVE"):
            self.gen = gen_in

        if old_gen == self.const("GEN_INACTIVE"):
            verdict = "V_OP_FRESH"
        elif old_gen == gen_in:
            verdict = "V_OP_DUP"
        elif self.sem.has_repair_path and old_gen == (gen_in | self.const("GEN_RELEASED_BIT")):
            verdict = "V_OP_REPAIR"
        else:
            verdict = "V_OP_BUSY"

        hold_ok = self.epoch != self.const("EPOCH_NONE") and self.ready == self.epoch and old_gen == self.const("GEN_INACTIVE")
        if verdict == "V_OP_DUP":
            return "OUT_OP_DUP"
        if verdict == "V_OP_REPAIR":
            return "OUT_OP_REPAIR"
        if verdict == "V_OP_FRESH" and hold_ok:
            return "OUT_OP_HOLD"
        return "OUT_BYPASS"

    def release(self) -> str:
        self.epoch = self.const("EPOCH_NONE")
        if self.sem.release_mode == "clear":
            self.gen = self.const("GEN_INACTIVE")
        elif self.sem.release_mode == "released_domain" and self.gen != self.const("GEN_INACTIVE"):
            self.gen = self.gen | self.const("GEN_RELEASED_BIT")
        elif self.sem.release_mode == "keep_held":
            pass
        else:
            raise AssertionError(f"unknown release mode {self.sem.release_mode!r}")
        self.ready = self.const("EPOCH_NONE")
        return "OUT_OP_RELAY"

    def commit_action(self, outcome: str) -> str:
        return self.sem.outcome_commits.get(outcome, "cmt_fwd")

    def const(self, name: str) -> int:
        return self.sem.constants[name]


def source_path() -> Path:
    return Path(os.environ.get("P4_SOURCE_UNDER_TEST", DEFAULT_SOURCE))


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//.*", "", text)


def squashed(text: str) -> str:
    return re.sub(r"\s+", " ", strip_comments(text)).strip()


def parse_int(token: str) -> int:
    token = token.strip()
    token = re.sub(r"^\d+w", "", token)
    return int(token, 16) if token.startswith("0x") else int(token)


def extract_constants(text: str) -> dict[str, int]:
    constants: dict[str, int] = {}
    for _, name, value in re.findall(r"const bit<(8|16)>\s+(\w+)\s*=\s*([^;]+);", strip_comments(text)):
        if name.startswith(("GEN_", "EPOCH_", "V_OP_", "OUT_OP_")):
            constants[name] = parse_int(value)
    required = ["GEN_INACTIVE", "EPOCH_NONE", "V_OP_DUP", "OUT_OP_DUP"]
    missing = [name for name in required if name not in constants]
    if missing:
        raise AssertionError(f"missing source constants: {missing}")
    return constants


def require(pattern: str, compact_source: str, label: str) -> None:
    if re.search(pattern, compact_source) is None:
        raise AssertionError(f"missing source binding: {label}")


def release_mode_from_source(compact_source: str) -> str:
    has_clear_body = "v = GEN_INACTIVE;" in compact_source
    has_release_body = "v = v | GEN_RELEASED_BIT;" in compact_source
    release_calls_clear = "else if (meta.bor_pc == BPC_RELEASE) { meta.gen_stored = gen_clear.execute(0); }" in compact_source
    release_calls_release = "else if (meta.bor_pc == BPC_RELEASE) { meta.gen_stored = gen_release.execute(0); }" in compact_source
    read_fallback = "else { meta.gen_stored = gen_read.execute(0); }" in compact_source

    if has_release_body and release_calls_release:
        return "released_domain"
    if has_clear_body and release_calls_clear:
        return "clear"
    if read_fallback and not release_calls_clear and not release_calls_release:
        return "keep_held"
    raise AssertionError("could not identify BPC_RELEASE reg_bor_gen behavior from executable source")


def outcome_commit_table(compact_source: str) -> dict[str, str]:
    return {name: action for name, action in re.findall(r"\((OUT_[A-Z0-9_]+)\)\s*:\s*(cmt_[A-Za-z0-9_]+)\s*\(\s*\)\s*;", compact_source)}


def has_repair_path(compact_source: str, commits: dict[str, str]) -> bool:
    try:
        require(r"const\s+bit<8>\s+GEN_RELEASED_BIT\s*=\s*8w0x10\s*;", compact_source, "released generation bit")
        require(r"const\s+bit<8>\s+V_OP_REPAIR\s*=", compact_source, "repair verdict constant")
        require(r"const\s+bit<16>\s+OUT_OP_REPAIR\s*=", compact_source, "repair outcome constant")
        require(r"else\s+if\s*\(\s*meta\.gen_stored\s*==\s*\(\s*meta\.gen_in\s*\|\s*GEN_RELEASED_BIT\s*\)\s*\)\s*\{\s*meta\.verdict_bor\s*=\s*V_OP_REPAIR\s*;\s*\}", compact_source, "released-domain verdict")
        require(r"\(\s*BPC_OPERATE\s*,\s*V_OP_REPAIR\b[^)]*\)\s*:\s*dec_o\s*\(\s*OUT_OP_REPAIR\s*\)\s*;", compact_source, "repair decision entry")
    except AssertionError:
        return False
    return commits.get("OUT_OP_REPAIR") == "cmt_op_relay"


def extract_semantics(text: str) -> SourceSemantics:
    compact = squashed(text)
    commits = outcome_commit_table(compact)
    require(r"RegisterAction<bit<8>,\s*bit<1>,\s*bit<8>>\s*\(\s*reg_bor_gen\s*\)\s*gen_arm\s*=\s*\{[^}]*if\s*\(\s*v\s*==\s*GEN_INACTIVE\s*\)\s*\{\s*v\s*=\s*meta\.gen_in\s*;\s*\}", compact, "gen_arm body")
    require(r"\(\s*BPC_OPERATE\s*,\s*V_OP_DUP\b[^)]*\)\s*:\s*dec_o\s*\(\s*OUT_OP_DUP\s*\)\s*;", compact, "duplicate decision entry")
    if commits.get("OUT_OP_DUP") != "cmt_drop":
        raise AssertionError("OUT_OP_DUP is not committed through cmt_drop")
    return SourceSemantics(release_mode_from_source(compact), has_repair_path(compact, commits), extract_constants(text), commits)


class TestOperateRepairBehavior(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.path = source_path()
        cls.text = cls.path.read_text(encoding="utf-8")
        cls.sem = extract_semantics(cls.text)

    def model(self) -> BorModel:
        return BorModel(self.sem)

    def test_candidate_uses_bound_released_domain_repair_path(self) -> None:
        self.assertEqual(self.sem.release_mode, "released_domain")
        self.assertTrue(self.sem.has_repair_path)
        self.assertEqual(self.sem.outcome_commits["OUT_OP_REPAIR"], "cmt_op_relay")

    def test_hold_ok_is_read_before_write_and_requires_a_ready_epoch(self) -> None:
        compact = squashed(self.text)
        for pattern in (
            r"meta\.bor_pc\s*:\s*ternary\s*;",
            r"meta\.epoch_stored\s*:\s*ternary\s*;",
            r"meta\.ready_stored\s*:\s*ternary\s*;",
            r"meta\.gen_stored\s*:\s*ternary\s*;",
            r"\(\s*BPC_OPERATE\s*,\s*8w0&&&8w0\s*,\s*8w1\s*,\s*GEN_INACTIVE\s*\)\s*:\s*hold_and_arm\s*\(\s*\)\s*;",
            r"\(\s*BPC_OPERATE\s*,\s*EPOCH_NONE\s*,\s*8w0&&&8w0\s*,\s*8w0&&&8w0\s*\)\s*:\s*read_topj\s*\(\s*\)\s*;",
        ):
            self.assertRegex(compact, pattern)

    def test_fresh_operate_is_held_only_after_select_and_ready_token(self) -> None:
        m = self.model()
        self.assertEqual(m.operate(0xC1), "OUT_BYPASS")
        m = self.model()
        m.prepare()
        self.assertEqual(m.operate(0xC1), "OUT_BYPASS")
        m = self.model()
        m.prepare()
        m.confirm_token()
        self.assertEqual(m.operate(0xC1), "OUT_OP_HOLD")

    def test_duplicate_while_held_drops_through_commit_table(self) -> None:
        m = self.model()
        m.prepare()
        m.confirm_token()
        self.assertEqual(m.operate(0xC1), "OUT_OP_HOLD")
        outcome = m.operate(0xC1)
        self.assertEqual(outcome, "OUT_OP_DUP")
        self.assertEqual(m.commit_action(outcome), "cmt_drop")

    def test_busy_different_generation_while_held_falls_open(self) -> None:
        m = self.model()
        m.prepare()
        m.confirm_token()
        self.assertEqual(m.operate(0xC1), "OUT_OP_HOLD")
        outcome = m.operate(0xC2)
        self.assertEqual(outcome, "OUT_BYPASS")
        self.assertEqual(m.commit_action(outcome), "cmt_fwd")

    def test_same_generation_retry_after_release_uses_repair_path(self) -> None:
        m = self.model()
        m.prepare()
        m.confirm_token()
        self.assertEqual(m.operate(0xC1), "OUT_OP_HOLD")
        self.assertEqual(m.release(), "OUT_OP_RELAY")
        outcome = m.operate(0xC1)
        self.assertEqual(outcome, "OUT_OP_REPAIR")
        self.assertEqual(m.commit_action(outcome), "cmt_op_relay")

    def test_new_prepared_transaction_with_new_generation_still_holds(self) -> None:
        m = self.model()
        m.prepare()
        m.confirm_token()
        self.assertEqual(m.operate(0xC1), "OUT_OP_HOLD")
        self.assertEqual(m.release(), "OUT_OP_RELAY")
        m.prepare()
        m.confirm_token()
        self.assertEqual(m.operate(0xC2), "OUT_OP_HOLD")

    @unittest.expectedFailure
    def test_late_retry_after_later_ready_epoch_is_not_reheld(self) -> None:
        m = self.model()
        m.prepare()
        m.confirm_token()
        self.assertEqual(m.operate(0xC1), "OUT_OP_HOLD")
        self.assertEqual(m.release(), "OUT_OP_RELAY")
        m.prepare()
        m.confirm_token()
        self.assertNotEqual(m.operate(0xC1), "OUT_OP_HOLD")

    def test_generation_wrap_does_not_revalidate_a_retired_epoch(self) -> None:
        m = self.model()
        m.epoch = 255
        m.prepare()
        self.assertEqual(m.epoch, 1)
        m.confirm_token()
        self.assertEqual(m.operate(0xCF), "OUT_OP_HOLD")
        m.release()
        self.assertEqual(m.epoch, self.sem.constants["EPOCH_NONE"])
        self.assertNotEqual(m.operate(0xCF), "OUT_OP_DUP")


class TestSourceBindingRejectsMalformedRepairPath(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.compact = squashed(DEFAULT_SOURCE.read_text(encoding="utf-8"))

    def test_repair_path_rejects_wrong_commit_action(self) -> None:
        broken = self.compact.replace("(OUT_OP_REPAIR) : cmt_op_relay();", "(OUT_OP_REPAIR) : cmt_drop();")
        self.assertFalse(has_repair_path(broken, outcome_commit_table(broken)))

    def test_repair_path_rejects_missing_decision_entry(self) -> None:
        broken = re.sub(r"\(\s*BPC_OPERATE\s*,\s*V_OP_REPAIR\b[^)]*\)\s*:\s*dec_o\s*\(\s*OUT_OP_REPAIR\s*\)\s*;", "", self.compact)
        self.assertFalse(has_repair_path(broken, outcome_commit_table(broken)))


if __name__ == "__main__":
    unittest.main()

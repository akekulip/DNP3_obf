#!/usr/bin/env python3
"""Source-backed semantic checks for the timing stage-reduction work.

The helpers in this file intentionally read the P4 source for constants,
action bodies, and table masks.  The executable model below is only the
small timing/BOR fragment that the proposed stage-reduction edits touch.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[3]
BASELINE_P4 = ROOT / "defense4" / "timing" / "anchor_fix" / "src" / "defense4_rrc_bor_unified12.p4"
CANDIDATE_P4 = ROOT / "defense4" / "timing" / "stage_reduction" / "src" / "defense4_timing.p4"

U32 = 0xFFFFFFFF


def read_source(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _eval_preprocessor_expr(expr: str, defines: set[str]) -> bool:
    """Evaluate the small #if subset present in the P4 sources."""
    expr = re.sub(r"defined\(([^()]+)\)", lambda m: "1" if m.group(1).strip() in defines else "0", expr)
    expr = re.sub(r"defined\s+([A-Za-z0-9_]+)", lambda m: "1" if m.group(1) in defines else "0", expr)
    expr = re.sub(r"\b[A-Za-z_][A-Za-z0-9_]*\b", "0", expr)
    expr = expr.replace("||", " or ").replace("&&", " and ").replace("!", " not ")
    if not re.fullmatch(r"[0-9\s()orandnot]+", expr):
        return False
    return bool(eval(expr, {"__builtins__": {}}, {}))


def preprocess_defines(source: str, defines: set[str] | None = None) -> str:
    defines = defines or {"U_BOR"}
    out: list[str] = []
    stack: list[tuple[bool, bool]] = []
    active = True
    for line in source.splitlines():
        stripped = line.strip()
        if stripped.startswith("#ifdef "):
            name = stripped.split(None, 1)[1].strip()
            parent = active
            branch = name in defines
            stack.append((parent, branch))
            active = parent and branch
            continue
        if stripped.startswith("#ifndef "):
            name = stripped.split(None, 1)[1].strip()
            parent = active
            branch = name not in defines
            stack.append((parent, branch))
            active = parent and branch
            continue
        if stripped.startswith("#if "):
            parent = active
            branch = _eval_preprocessor_expr(stripped[3:].strip(), defines)
            stack.append((parent, branch))
            active = parent and branch
            continue
        if stripped.startswith("#else"):
            if not stack:
                continue
            parent, branch = stack[-1]
            branch = not branch
            stack[-1] = (parent, branch)
            active = parent and branch
            continue
        if stripped.startswith("#endif"):
            if not stack:
                continue
            parent, _branch = stack.pop()
            active = parent
            continue
        if active:
            out.append(line)
    return "\n".join(out)


def strip_comments(source: str) -> str:
    source = preprocess_defines(source)
    source = re.sub(r"/\*.*?\*/", "", source, flags=re.DOTALL)
    source = re.sub(r"//.*", "", source)
    return re.sub(r"^[ \t]*#.*$", "", source, flags=re.MULTILINE)


def parse_p4_int(token: str) -> int:
    match = re.fullmatch(r"(?:\d+w)?(0x[0-9A-Fa-f]+|\d+)", token.strip())
    if not match:
        raise ValueError(f"not a P4 integer literal: {token!r}")
    value = match.group(1)
    return int(value, 16 if value.startswith("0x") else 10)


def extract_consts(source: str) -> dict[str, int]:
    consts: dict[str, int] = {}
    pattern = re.compile(
        r"const\s+[A-Za-z0-9_<>\s]+?\s+([A-Za-z0-9_]+)\s*=\s*((?:\d+w)?(?:0x[0-9A-Fa-f]+|\d+));"
    )
    for name, literal in pattern.findall(source):
        consts[name] = parse_p4_int(literal)
    return consts


def _extract_block_after(source: str, start: int) -> str:
    brace = source.find("{", start)
    if brace == -1:
        raise ValueError("opening brace not found")
    depth = 0
    for index in range(brace, len(source)):
        char = source[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[brace : index + 1]
    raise ValueError("unterminated block")


def extract_table_block(source: str, name: str) -> str:
    clean = strip_comments(source)
    match = re.search(rf"\btable\s+{re.escape(name)}\s*\{{", clean)
    if not match:
        raise KeyError(name)
    return _extract_block_after(clean, match.start())


def extract_register_action_block(source: str, name: str) -> str:
    clean = strip_comments(source)
    match = re.search(rf"^[ \t]*RegisterAction\b.*\)\s+{re.escape(name)}\s*=\s*\{{", clean, flags=re.MULTILINE)
    if not match:
        raise KeyError(name)
    return _extract_block_after(clean, match.start())


def extract_named_block(source: str, name: str) -> str:
    clean = strip_comments(source)
    if name == "apply":
        control = re.search(r"\bcontrol\s+Ingress\b", clean)
        if not control:
            raise KeyError(name)
        for match in re.finditer(r"\bapply\s*(?:\([^)]*\))?\s*\{", clean[control.start():], flags=re.DOTALL):
            block = _extract_block_after(clean, control.start() + match.start())
            if "tbl_decide_fresh.apply" in block or "tbl_decide_deq.apply" in block:
                return block
        raise KeyError(name)
    patterns = (
        rf"\btable\s+{re.escape(name)}\s*\{{",
        rf"\baction\s+{re.escape(name)}\s*\(",
        rf"^[ \t]*RegisterAction\b.*\)\s+{re.escape(name)}\s*=\s*\{{",
    )
    for pattern in patterns:
        match = re.search(pattern, clean, flags=re.DOTALL | re.MULTILINE)
        if match:
            return _extract_block_after(clean, match.start())
    raise KeyError(name)


@dataclass(frozen=True)
class TernaryEntry:
    value: int
    mask: int
    action: str

    def matches(self, key: int) -> bool:
        return (key & self.mask) == self.value


def extract_single_ternary_entry(source: str, table_name: str) -> TernaryEntry:
    block = extract_table_block(source, table_name)
    match = re.search(
        r"\((\d+w(?:0x[0-9A-Fa-f]+|\d+))\s*&&&\s*(\d+w(?:0x[0-9A-Fa-f]+|\d+))\)\s*:\s*([A-Za-z0-9_]+)\(",
        block,
    )
    if not match:
        raise AssertionError(f"{table_name} has no single ternary entry")
    value, mask, action = match.groups()
    return TernaryEntry(parse_p4_int(value), parse_p4_int(mask), action)


@dataclass(frozen=True)
class TableRow:
    matches: tuple[tuple[int, int], ...]
    action: str
    argument: str | None


@dataclass(frozen=True)
class ParsedTable:
    keys: tuple[str, ...]
    rows: tuple[TableRow, ...]
    default_argument: str | None
    default_action: str | None = None

    def apply(self, fields: dict[str, int]) -> str | None:
        for row in self.rows:
            if all((fields.get(key, 0) & mask) == value for key, (value, mask) in zip(self.keys, row.matches)):
                return row.argument if row.argument is not None else row.action
        return self.default_argument if self.default_argument is not None else self.default_action


def _resolve_value(expr: str, consts: dict[str, int]) -> int:
    expr = expr.strip()
    if re.fullmatch(r"(?:\d+w)?(?:0x[0-9A-Fa-f]+|\d+)", expr):
        return parse_p4_int(expr)
    if expr in consts:
        return consts[expr]
    raise ValueError(f"cannot resolve P4 expression {expr!r}")


def _parse_match(expr: str, consts: dict[str, int]) -> tuple[int, int]:
    if "&&&" in expr:
        value, mask = expr.split("&&&", 1)
        return _resolve_value(value, consts), _resolve_value(mask, consts)
    return _resolve_value(expr, consts), U32


def _split_top_level_csv(text: str) -> list[str]:
    fields: list[str] = []
    depth = 0
    start = 0
    for index, char in enumerate(text):
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif char == "," and depth == 0:
            fields.append(text[start:index].strip())
            start = index + 1
    fields.append(text[start:].strip())
    return fields


def parse_const_table(source: str, table_name: str, consts: dict[str, int]) -> ParsedTable:
    block = extract_table_block(source, table_name)
    key_match = re.search(r"key\s*=\s*\{(?P<body>.*?)\}", block, flags=re.DOTALL)
    if not key_match:
        raise AssertionError(f"{table_name} has no key block")
    keys = tuple(re.findall(r"meta\.([A-Za-z0-9_]+)\s*:", key_match.group("body")))

    default_match = re.search(r"const\s+default_action\s*=\s*([A-Za-z0-9_]+)\(([^()]*)\)", block)
    default_action = default_match.group(1).strip() if default_match else None
    default_argument = default_match.group(2).strip() if default_match and default_match.group(2).strip() else None

    rows: list[TableRow] = []
    row_pattern = re.compile(r"\((?P<tuple>[^;]+?)\)\s*:\s*(?P<action>[A-Za-z0-9_]+)\((?P<arg>[^()]*)\)\s*;")
    for match in row_pattern.finditer(block):
        raw_fields = _split_top_level_csv(match.group("tuple"))
        if len(raw_fields) != len(keys):
            continue
        matches = tuple(_parse_match(field, consts) for field in raw_fields)
        argument = match.group("arg").strip() or None
        rows.append(TableRow(matches, match.group("action"), argument))
    return ParsedTable(keys, tuple(rows), default_argument, default_action)


def now_word(ts32: int, consts: dict[str, int]) -> int:
    return ((ts32 & consts["TICK_MASK"]) | consts["ARMED_MARK"]) & U32


def age_word(now: int, deadline: int) -> int:
    return (now - deadline) & U32


def table_expired(age: int, entry: TernaryEntry) -> bool:
    return entry.matches(age)


def direct_leq_due(now: int, deadline: int) -> bool:
    return deadline <= now


def deadline_arm_once_baseline(stored: int, dl_val: int, consts: dict[str, int]) -> tuple[int, int, int]:
    """Return (rv, new_stored, ack_first) for the baseline action plus follow-up test."""
    rv = stored & U32
    new_stored = dl_val & U32 if stored == consts["UNARMED_WORD"] else stored & U32
    ack_first = 1 if rv == consts["UNARMED_WORD"] else 0
    return rv, new_stored, ack_first


def eval_deadline_arm_once_body(body: str, stored: int, dl_val: int, consts: dict[str, int]) -> tuple[int, int]:
    """Evaluate the tiny action subset accepted for deadline_arm_once variants."""
    clean = " ".join(strip_comments(body).split())
    if "rv = v;" in clean and "if (v == UNARMED_WORD) { v = meta.dl_val; }" in clean:
        rv = stored & U32
        new_stored = dl_val & U32 if stored == consts["UNARMED_WORD"] else stored & U32
        return rv, new_stored

    zero_literal = r"(?:8w0|32w0|0)"
    one_literal = r"(?:8w1|32w1|1)"
    sets_zero_first = re.search(rf"\brv\s*=\s*{zero_literal}\s*;", clean)
    sets_one_in_unarmed = re.search(
        rf"if\s*\(\s*v\s*==\s*UNARMED_WORD\s*\)\s*\{{[^}}]*rv\s*=\s*{one_literal}\s*;[^}}]*v\s*=\s*meta\.dl_val\s*;",
        clean,
    )
    sets_value_in_unarmed = re.search(
        rf"if\s*\(\s*v\s*==\s*UNARMED_WORD\s*\)\s*\{{[^}}]*v\s*=\s*meta\.dl_val\s*;[^}}]*rv\s*=\s*{one_literal}\s*;",
        clean,
    )
    has_else_zero = re.search(rf"else\s*\{{[^}}]*rv\s*=\s*{zero_literal}\s*;", clean)
    if (sets_zero_first or has_else_zero) and (sets_one_in_unarmed or sets_value_in_unarmed):
        matched = stored == consts["UNARMED_WORD"]
        return (1 if matched else 0), (dl_val & U32 if matched else stored & U32)

    raise AssertionError(f"unsupported deadline_arm_once body: {clean}")


def deadline_arm_once_candidate(stored: int, dl_val: int, consts: dict[str, int]) -> tuple[int, int]:
    """Expected candidate contract: rv is the byte predicate prestate == UNARMED_WORD."""
    armed_this_time = 1 if stored == consts["UNARMED_WORD"] else 0
    new_stored = dl_val & U32 if armed_this_time else stored & U32
    return armed_this_time, new_stored




def epoch_read_baseline(epoch_stored: int, hdr_gen: int, tok_spent: int, consts: dict[str, int]) -> tuple[int, int]:
    rv = epoch_stored & 0xFF
    new_epoch = consts["EPOCH_NONE"] if tok_spent == 1 and (hdr_gen & 0xFF) == rv else rv
    return rv, new_epoch


def epoch_token_candidate(epoch_stored: int, hdr_gen: int, tok_spent: int, consts: dict[str, int]) -> tuple[int, int]:
    matched = 1 if (hdr_gen & 0xFF) == (epoch_stored & 0xFF) else 0
    new_epoch = consts["EPOCH_NONE"] if tok_spent == 1 and matched else epoch_stored & 0xFF
    return matched, new_epoch


def ready_confirm_baseline(ready_stored: int, epoch_stored: int) -> tuple[int, int]:
    new_ready = epoch_stored & 0xFF
    return new_ready, new_ready


def ready_confirm_candidate(ready_stored: int, hdr_gen: int) -> tuple[int, int]:
    new_ready = hdr_gen & 0xFF
    return new_ready, new_ready

def ready_read_baseline(ready_stored: int, epoch_stored: int, consts: dict[str, int]) -> tuple[int, int]:
    op_matched = 1 if epoch_stored != consts["EPOCH_NONE"] else 0
    op_ready = 1 if op_matched and ready_stored == epoch_stored else 0
    return ready_stored & 0xFF, op_ready


def eval_ready_read_body(body: str, ready_stored: int, epoch_stored: int) -> int:
    """Evaluate the tiny action subset accepted for ready_read variants."""
    clean = " ".join(strip_comments(body).split())
    if "rv = v;" in clean:
        return ready_stored & 0xFF
    sets_zero_first = "rv = 8w0;" in clean or "rv = 0;" in clean
    sets_one_on_match = re.search(r"if\s*\(\s*v\s*==\s*meta\.epoch_stored\s*\)\s*\{[^}]*rv\s*=\s*8w1\s*;", clean)
    has_else_zero = re.search(r"else\s*\{[^}]*rv\s*=\s*8w0\s*;", clean)
    if (sets_zero_first or has_else_zero) and sets_one_on_match:
        return 1 if (ready_stored & 0xFF) == (epoch_stored & 0xFF) else 0
    raise AssertionError(f"unsupported ready_read body: {clean}")


def ready_read_candidate(ready_stored: int, epoch_stored: int, consts: dict[str, int]) -> int:
    return 1 if ready_stored == epoch_stored else 0



@dataclass(frozen=True)
class DecodeEffect:
    verdict: str | None
    dl_val: str
    dl_val_resp: str
    tag_val: str | None = None


def state_decode_effect_from_action(action: str, consts: dict[str, int]) -> DecodeEffect:
    """Summarize the externally relevant writes made by a state-decode action."""
    if action.endswith("_op"):
        base = action[:-3]
        if base == "dec_arm_request":
            return DecodeEffect("V_ARM_FRESH", "dl_cand_op", "tresp_cand_op")
        effect = state_decode_effect_from_action(base, consts)
        return DecodeEffect(effect.verdict, "dl_cand_op", "tresp_cand_op", effect.tag_val)

    mapping = {
        "dec_arm_request": DecodeEffect("V_ARM_FRESH", "dl_cand", "tresp_cand"),
        "dec_arm_fresh": DecodeEffect("V_ARM_FRESH", "UNARMED_WORD", "UNARMED_WORD"),
        "dec_arm_dup": DecodeEffect("V_ARM_DUP", "DL_NO_WRITE", "DL_NO_WRITE"),
        "dec_arm_busy": DecodeEffect("V_ARM_BUSY", "DL_NO_WRITE", "DL_NO_WRITE"),
        "dec_ack_arm": DecodeEffect("V_ACK_ARM", "dl_cand", "tresp_cand"),
        "dec_ack_reject": DecodeEffect("V_ACK_REJECT", "DL_NO_WRITE", "DL_NO_WRITE"),
        "dec_block_live": DecodeEffect("V_BLOCK_LIVE", "DL_NO_WRITE", "DL_NO_WRITE"),
        "dec_block_pending": DecodeEffect("V_BLOCK_PENDING", "DL_NO_WRITE", "DL_NO_WRITE"),
        "dec_resp": DecodeEffect("V_RESP", "DL_NO_WRITE", "DL_NO_WRITE"),
        "dec_resp_bypass": DecodeEffect("V_RESP_BYPASS", "DL_NO_WRITE", "DL_NO_WRITE"),
        "dec_ack_rel": DecodeEffect(None, "DL_NO_WRITE", "DL_NO_WRITE"),
        "dec_none": DecodeEffect(None, "DL_NO_WRITE", "DL_NO_WRITE"),
    }
    if action not in mapping:
        raise KeyError(action)
    return mapping[action]


def baseline_state_decode_with_overrides(
    table: ParsedTable, fields: dict[str, int], consts: dict[str, int]
) -> DecodeEffect:
    action = table.apply(fields)
    if action is None:
        raise AssertionError("state decode table returned no action")
    effect = state_decode_effect_from_action(action, consts)
    if (
        fields.get("anchor_req", 0) == 1
        and fields["pkt_class"] == consts["CLASS_ARM"]
        and effect.verdict == "V_ARM_FRESH"
    ):
        effect = DecodeEffect(effect.verdict, "dl_cand", "tresp_cand", effect.tag_val)
    if fields.get("bor_pc", 0) == consts["BPC_OPERATE"] and fields.get("hold_ok", 0) == 1:
        effect = DecodeEffect(effect.verdict, "dl_cand_op", "tresp_cand_op", effect.tag_val)
    return effect


def candidate_state_decode_effect(table: ParsedTable, fields: dict[str, int], consts: dict[str, int]) -> DecodeEffect:
    action = table.apply(fields)
    if action is None:
        raise AssertionError("state decode table returned no action")
    return state_decode_effect_from_action(action, consts)



def _norm_p4(block: str) -> str:
    return " ".join(strip_comments(block).split())


def assert_current_candidate_action_bodies(source: str) -> None:
    """Tie the table-level semantic model to the actual action bodies in the candidate source."""
    state_expectations = {
        "dec_arm_fresh": ("meta.verdict = V_ARM_FRESH", "deadline_disarm.execute(0)"),
        "dec_arm_request": ("meta.verdict = V_ARM_FRESH", "deadline_rmw.execute(0)"),
        "dec_arm_dup": ("meta.verdict = V_ARM_DUP", "deadline_read.execute(0)"),
        "dec_arm_busy": ("meta.verdict = V_ARM_BUSY", "deadline_read.execute(0)"),
        "dec_ack_arm": ("meta.verdict = V_ACK_ARM", "deadline_arm_once.execute(0)"),
        "dec_ack_reject": ("meta.verdict = V_ACK_REJECT", "deadline_read.execute(0)"),
        "dec_block_live": ("meta.verdict = V_BLOCK_LIVE", "deadline_read.execute(0)"),
        "dec_block_pending": ("meta.verdict = V_BLOCK_PENDING", "deadline_read.execute(0)"),
        "dec_resp": ("meta.verdict = V_RESP", "deadline_read.execute(0)"),
        "dec_resp_bypass": ("meta.verdict = V_RESP_BYPASS", "deadline_read.execute(0)"),
        "dec_ack_rel": (None, "deadline_read.execute(0)"),
        "dec_none": (None, "deadline_read.execute(0)"),
        "dec_arm_request_op": ("meta.verdict = V_ARM_FRESH", "deadline_rmw.execute(0)"),
        "dec_arm_fresh_op": ("meta.verdict = V_ARM_FRESH", "deadline_rmw.execute(0)"),
        "dec_arm_dup_op": ("meta.verdict = V_ARM_DUP", "deadline_rmw.execute(0)"),
        "dec_arm_busy_op": ("meta.verdict = V_ARM_BUSY", "deadline_rmw.execute(0)"),
        "dec_ack_arm_op": ("meta.verdict = V_ACK_ARM", "deadline_arm_once.execute(0)"),
        "dec_ack_reject_op": ("meta.verdict = V_ACK_REJECT", "deadline_rmw.execute(0)"),
        "dec_block_live_op": ("meta.verdict = V_BLOCK_LIVE", "deadline_rmw.execute(0)"),
        "dec_block_pending_op": ("meta.verdict = V_BLOCK_PENDING", "deadline_rmw.execute(0)"),
        "dec_resp_op": ("meta.verdict = V_RESP", "deadline_rmw.execute(0)"),
        "dec_resp_bypass_op": ("meta.verdict = V_RESP_BYPASS", "deadline_rmw.execute(0)"),
        "dec_ack_rel_op": (None, "deadline_rmw.execute(0)"),
        "dec_none_op": (None, "deadline_rmw.execute(0)"),
    }
    for name, (verdict, call) in state_expectations.items():
        body = _norm_p4(extract_named_block(source, name))
        if verdict is not None and verdict not in body:
            raise AssertionError(f"{name} missing {verdict}")
        if call not in body:
            raise AssertionError(f"{name} missing {call}")
        if name == "dec_ack_rel" and "meta.tag_val" in body:
            raise AssertionError("dec_ack_rel must not keep the dead tag_val assignment")

    response_expectations = {
        "resp_dl_read": "tresp_read.execute(0)",
        "resp_dl_rmw": "tresp_rmw.execute(0)",
        "resp_dl_disarm": "tresp_disarm.execute(0)",
        "resp_dl_arm": "tresp_arm_once.execute(0)",
    }
    for name, call in response_expectations.items():
        body = _norm_p4(extract_named_block(source, name))
        if call not in body:
            raise AssertionError(f"{name} missing {call}")

    select_rrc = _norm_p4(extract_named_block(source, "select_rrc_deadlines"))
    if "meta.dl_val = meta.dl_cand" not in select_rrc or "meta.dl_val_resp = meta.tresp_cand" not in select_rrc:
        raise AssertionError("select_rrc_deadlines must select RRC candidates")
    select_op = _norm_p4(extract_named_block(source, "select_operate_deadlines"))
    if "meta.dl_val = meta.dl_cand_op" not in select_op or "meta.dl_val_resp = meta.tresp_cand_op" not in select_op:
        raise AssertionError("select_operate_deadlines must select OPERATE candidates")

    deadline_read = _norm_p4(extract_register_action_block(source, "deadline_read"))
    if "rv = meta.now_word - v" not in deadline_read or re.search(r"(?<!r)\bv\s*=", deadline_read):
        raise AssertionError("deadline_read must return age without writing")
    deadline_disarm = _norm_p4(extract_register_action_block(source, "deadline_disarm"))
    if "rv = meta.now_word - v" not in deadline_disarm or "v = UNARMED_WORD" not in deadline_disarm:
        raise AssertionError("deadline_disarm must return age and write UNARMED_WORD")
    tresp_read = _norm_p4(extract_register_action_block(source, "tresp_read"))
    if "rv = meta.now_word - v" not in tresp_read or re.search(r"(?<!r)\bv\s*=", tresp_read):
        raise AssertionError("tresp_read must return age without writing")
    tresp_disarm = _norm_p4(extract_register_action_block(source, "tresp_disarm"))
    if "rv = meta.now_word - v" not in tresp_disarm or "v = UNARMED_WORD" not in tresp_disarm:
        raise AssertionError("tresp_disarm must return age and write UNARMED_WORD")

@dataclass(frozen=True)
class DeadlineOutcome:
    verdict: str | None
    tag_val: str | None
    deadline_output: tuple[str, int] | None
    deadline_new: int
    response_output: tuple[str, int] | None
    response_new: int


def _deadline_candidate_value(selector: str, values: dict[str, int], consts: dict[str, int]) -> int:
    if selector == "DL_NO_WRITE":
        return consts["DL_NO_WRITE"]
    if selector == "UNARMED_WORD":
        return consts["UNARMED_WORD"]
    return values[selector] & U32


def _deadline_read(stored: int, now: int) -> tuple[tuple[str, int], int]:
    return ("age", (now - stored) & U32), stored & U32


def _deadline_write_age(stored: int, now: int, value: int) -> tuple[tuple[str, int], int]:
    return ("age", (now - stored) & U32), value & U32


def _deadline_arm_bool(stored: int, value: int, consts: dict[str, int]) -> tuple[tuple[str, int], int]:
    first = 1 if (stored & U32) == consts["UNARMED_WORD"] else 0
    new_value = value & U32 if first else stored & U32
    return ("ack_first", first), new_value


def _response_arm_unused(stored: int, value: int, consts: dict[str, int]) -> tuple[None, int]:
    new_value = value & U32 if (stored & U32) == consts["UNARMED_WORD"] else stored & U32
    return None, new_value


def baseline_deadline_outcome(
    table: ParsedTable,
    fields: dict[str, int],
    consts: dict[str, int],
    values: dict[str, int],
) -> DeadlineOutcome:
    effect = baseline_state_decode_with_overrides(table, fields, consts)
    dl_value = _deadline_candidate_value(effect.dl_val, values, consts)
    resp_value = _deadline_candidate_value(effect.dl_val_resp, values, consts)
    stored_deadline = values["deadline_stored"] & U32
    stored_response = values["response_stored"] & U32
    now = values["now_word"] & U32

    if effect.verdict == "V_ACK_ARM":
        deadline_output, deadline_new = _deadline_arm_bool(stored_deadline, dl_value, consts)
        response_output, response_new = _response_arm_unused(stored_response, resp_value, consts)
    else:
        if dl_value != consts["DL_NO_WRITE"]:
            deadline_output, deadline_new = _deadline_write_age(stored_deadline, now, dl_value)
        else:
            deadline_output, deadline_new = _deadline_read(stored_deadline, now)
        if resp_value != consts["DL_NO_WRITE"]:
            response_output, response_new = _deadline_write_age(stored_response, now, resp_value)
            response_output = ("age_resp", response_output[1])
        else:
            response_output, response_new = _deadline_read(stored_response, now)
            response_output = ("age_resp", response_output[1])

    return DeadlineOutcome(effect.verdict, effect.tag_val, deadline_output, deadline_new, response_output, response_new)


def _selected_deadline_values(select_table: ParsedTable, fields: dict[str, int], values: dict[str, int]) -> tuple[int, int]:
    action = select_table.apply(fields)
    if action == "select_operate_deadlines":
        return values["dl_cand_op"] & U32, values["tresp_cand_op"] & U32
    if action == "select_rrc_deadlines":
        return values["dl_cand"] & U32, values["tresp_cand"] & U32
    raise AssertionError(f"unexpected deadline selector action {action!r}")


def _candidate_deadline_action(
    action: str, stored: int, now: int, selected: int, consts: dict[str, int]
) -> tuple[tuple[str, int] | None, int]:
    if action == "dec_ack_arm" or action == "dec_ack_arm_op":
        return _deadline_arm_bool(stored, selected, consts)
    if action in {"dec_arm_fresh"}:
        return _deadline_write_age(stored, now, consts["UNARMED_WORD"])
    if action.endswith("_op") or action == "dec_arm_request":
        return _deadline_write_age(stored, now, selected)
    return _deadline_read(stored, now)


def _candidate_response_action(
    action: str, stored: int, now: int, selected: int, consts: dict[str, int]
) -> tuple[tuple[str, int] | None, int]:
    if action == "resp_dl_arm":
        return _response_arm_unused(stored, selected, consts)
    if action == "resp_dl_disarm":
        out, new_value = _deadline_write_age(stored, now, consts["UNARMED_WORD"])
        return ("age_resp", out[1]), new_value
    if action == "resp_dl_rmw":
        out, new_value = _deadline_write_age(stored, now, selected)
        return ("age_resp", out[1]), new_value
    if action == "resp_dl_read":
        out, new_value = _deadline_read(stored, now)
        return ("age_resp", out[1]), new_value
    raise AssertionError(f"unexpected response deadline action {action!r}")


def candidate_deadline_outcome(
    state_table: ParsedTable,
    response_table: ParsedTable,
    select_table: ParsedTable,
    fields: dict[str, int],
    consts: dict[str, int],
    values: dict[str, int],
) -> DeadlineOutcome:
    state_action = state_table.apply(fields)
    response_action = response_table.apply(fields)
    if state_action is None or response_action is None:
        raise AssertionError("candidate deadline tables returned no action")
    effect = state_decode_effect_from_action(state_action, consts)
    selected_dl, selected_resp = _selected_deadline_values(select_table, fields, values)
    deadline_output, deadline_new = _candidate_deadline_action(
        state_action, values["deadline_stored"], values["now_word"], selected_dl, consts
    )
    response_output, response_new = _candidate_response_action(
        response_action, values["response_stored"], values["now_word"], selected_resp, consts
    )
    return DeadlineOutcome(effect.verdict, effect.tag_val, deadline_output, deadline_new, response_output, response_new)

def bor_terminal_baseline(
    *,
    bor_pc: int,
    verdict_bor: int,
    hold_ok: int,
    blk_op_live: int,
    expired_topj: int,
    budget_zero: int,
    epoch_stored: int,
    consts: dict[str, int],
) -> str:
    if bor_pc == consts["BPC_OPERATE"]:
        if verdict_bor == consts["V_OP_DUP"]:
            return "OUT_OP_DUP"
        if verdict_bor == consts["V_OP_FRESH"] and hold_ok == 1:
            return "OUT_OP_HOLD"
        return "FALLTHROUGH_FRESH"
    if bor_pc == consts["BPC_TOKEN"]:
        if blk_op_live != 1:
            return "OUT_OP_TERM_STALE"
        if expired_topj == 1:
            return "OUT_OP_TERM_DL"
        if budget_zero == 1:
            return "OUT_OP_TERM_TMO"
        return "OUT_OP_LOOP"
    if bor_pc == consts["BPC_RELEASE"]:
        return "OUT_OP_RELAY"
    if bor_pc == consts["BPC_PKTGEN_OP"]:
        if epoch_stored != consts["EPOCH_NONE"]:
            return "OUT_OP_ADMIT"
        return "OUT_PKTGEN_DROP"
    return "FALLTHROUGH"


def enumerate_bor_terminal_domain(consts: dict[str, int]) -> Iterable[dict[str, int]]:
    for bor_pc in range(0, 6):
        for verdict_bor in range(0, 4):
            for hold_ok in range(0, 2):
                for blk_op_live in range(0, 2):
                    for expired_topj in range(0, 2):
                        for budget_zero in range(0, 2):
                            for epoch_stored in (0, 1, 0x7F, 0x80, 0xFF):
                                yield {
                                    "bor_pc": bor_pc,
                                    "verdict_bor": verdict_bor,
                                    "hold_ok": hold_ok,
                                    "blk_op_live": blk_op_live,
                                    "expired_topj": expired_topj,
                                    "budget_zero": budget_zero,
                                    "epoch_stored": epoch_stored,
                                }


def assert_seven_stage_epoch_action_bodies(source: str) -> None:
    epoch_read = _norm_p4(extract_register_action_block(source, "epoch_read"))
    if "rv = v" not in epoch_read or re.search(r"(?<!r)\bv\s*=", epoch_read):
        raise AssertionError("epoch_read must be a pure pre-state read")
    epoch_token = _norm_p4(extract_register_action_block(source, "epoch_token"))
    if "rv = 8w0" not in epoch_token:
        raise AssertionError("epoch_token must default live predicate to zero")
    if "if (hdr.ib.gen == v) { rv = 8w1; }" not in epoch_token:
        raise AssertionError("epoch_token must return hdr.ib.gen == epoch pre-state")
    if "if (meta.budget_zero == 8w1 && hdr.ib.gen == v) { v = EPOCH_NONE; }" not in epoch_token:
        raise AssertionError("epoch_token must retire only on spent matching token")
    if "tok_spent" in strip_comments(source):
        raise AssertionError("seven-stage source must not use tok_spent")


def epoch_baseline_selected(
    *, bor_pc: int, epoch_stored: int, hdr_gen: int, budget_zero: int, consts: dict[str, int]
) -> tuple[str, int, int]:
    if bor_pc == consts["BPC_TOKEN"]:
        rv, new_epoch = epoch_read_baseline(epoch_stored, hdr_gen, budget_zero, consts)
        live = 1 if (hdr_gen & 0xFF) == (rv & 0xFF) else 0
        return "token", live, new_epoch
    if bor_pc == consts["BPC_PREPARE"]:
        return "prepare", epoch_stored & 0xFF, 0 if (epoch_stored & 0xFF) == 255 else ((epoch_stored + 1) & 0xFF)
    if bor_pc == consts["BPC_RELEASE"]:
        return "release", epoch_stored & 0xFF, consts["EPOCH_NONE"]
    return "read", epoch_stored & 0xFF, epoch_stored & 0xFF


def epoch_candidate_selected(
    *, bor_pc: int, epoch_stored: int, hdr_gen: int, budget_zero: int, consts: dict[str, int]
) -> tuple[str, int, int]:
    if bor_pc == consts["BPC_TOKEN"]:
        live, new_epoch = epoch_token_candidate(epoch_stored, hdr_gen, budget_zero, consts)
        return "token", live, new_epoch
    if bor_pc == consts["BPC_PREPARE"]:
        return "prepare", epoch_stored & 0xFF, 0 if (epoch_stored & 0xFF) == 255 else ((epoch_stored + 1) & 0xFF)
    if bor_pc == consts["BPC_RELEASE"]:
        return "release", epoch_stored & 0xFF, consts["EPOCH_NONE"]
    return "read", epoch_stored & 0xFF, epoch_stored & 0xFF


def assert_seven_stage_expected_ack_source(source: str) -> None:
    clean = strip_comments(source)
    if "tbl_expected_ack.apply()" not in clean:
        raise AssertionError("expected-ACK selector table must be applied")
    if "if (meta.pkt_class == CLASS_ARM) { meta.ack_diff = exp_ack_w.execute(0);" in clean:
        raise AssertionError("old pkt_class-dependent exp_ack branch must be removed")
    table = extract_named_block(source, "tbl_expected_ack")
    for needle in (
        "meta.dequeued",
        "meta.is_pktgen",
        "meta.role",
        "meta.sess",
        "write_expected_ack",
        "read_expected_ack",
    ):
        if needle not in table:
            raise AssertionError(f"tbl_expected_ack missing {needle}")
    consts = extract_consts(source)
    parsed = parse_const_table(source, "tbl_expected_ack", consts)
    pktgen_arm = {"dequeued": 0, "is_pktgen": 1, "role": consts["ROLE_ARM"], "sess": consts["SESS_MASTER"]}
    raw_arm = {"dequeued": 0, "is_pktgen": 0, "role": consts["ROLE_ARM"], "sess": consts["SESS_MASTER"]}
    if parsed.apply(pktgen_arm) != "read_expected_ack":
        raise AssertionError("pktgen priority read row missing")
    if parsed.apply(raw_arm) != "write_expected_ack":
        raise AssertionError("raw CLASS_ARM-equivalent write row missing")
    write_body = _norm_p4(extract_named_block(source, "write_expected_ack"))
    read_body = _norm_p4(extract_named_block(source, "read_expected_ack"))
    if "meta.ack_diff = exp_ack_w.execute(0)" not in write_body:
        raise AssertionError("write_expected_ack must call exp_ack_w")
    if "meta.ack_diff = exp_ack_r.execute(0)" not in read_body:
        raise AssertionError("read_expected_ack must call exp_ack_r")
    exp_w = _norm_p4(extract_register_action_block(source, "exp_ack_w"))
    if "rv = hdr.tcp.ack_no - v" not in exp_w or "v = meta.exp_ack_cand" not in exp_w:
        raise AssertionError("exp_ack_w must return diff and install candidate")
    exp_r = _norm_p4(extract_register_action_block(source, "exp_ack_r"))
    if "rv = hdr.tcp.ack_no - v" not in exp_r or re.search(r"(?<!r)\bv\s*=", exp_r):
        raise AssertionError("exp_ack_r must return diff without writing")


def expected_ack_baseline_selector(*, dequeued: int, is_pktgen: int, role: int, sess: int, consts: dict[str, int]) -> str:
    if dequeued == 0:
        if is_pktgen == 1:
            return "read_expected_ack"
        if role == consts["ROLE_ARM"] and sess == consts["SESS_MASTER"]:
            return "write_expected_ack"
    return "read_expected_ack"


def expected_ack_action_effect(action: str, *, stored: int, ack_no: int, exp_ack_cand: int) -> tuple[int, int]:
    diff = (ack_no - stored) & U32
    if action == "write_expected_ack":
        return diff, exp_ack_cand & U32
    if action == "read_expected_ack":
        return diff, stored & U32
    raise AssertionError(f"unexpected expected-ACK action {action!r}")


def assert_resp_authorise_guard_source(source: str) -> None:
    apply_block = _norm_p4(extract_named_block(source, "apply"))
    chain = (
        "if (meta.pkt_class == CLASS_RESP) { tbl_resp_authorise.apply(); } "
        "else if (meta.pkt_class == CLASS_ARM)"
    )
    if chain not in apply_block:
        raise AssertionError("tbl_resp_authorise must be first in the CLASS_RESP/CLASS_ARM mutually exclusive chain")
    if apply_block.count("tbl_resp_authorise.apply();") != 1:
        raise AssertionError("tbl_resp_authorise must have exactly one guarded apply")
    if "else if (meta.pkt_class == CLASS_BLOCK_DEQ && meta.budget_zero == 8w1)" not in apply_block:
        raise AssertionError("fail-open note branch must remain in the same mutually exclusive chain")
    block = extract_named_block(source, "tbl_resp_authorise")
    for needle in ("resp_authorise", "resp_deauthorise", "resp_untouched", "meta.pkt_class", "meta.seq_diff", "meta.ack_diff", "meta.sport_diff"):
        if needle not in block:
            raise AssertionError(f"tbl_resp_authorise missing {needle}")


def assert_seven_stage_dependency_order(source: str) -> None:
    apply_block = extract_named_block(source, "apply")
    positions = {
        "tbl_build_exp_ack": apply_block.find("tbl_build_exp_ack.apply();"),
        "exp_seq_w": apply_block.find("exp_seq_w.execute(0)"),
        "exp_seq_r": apply_block.find("exp_seq_r.execute(0)"),
        "sess_port_rmw": apply_block.find("sess_port_rmw.execute(0)"),
        "tbl_expected_ack": apply_block.find("tbl_expected_ack.apply();"),
        "guarded_resp_authorise": apply_block.find("if (meta.pkt_class == CLASS_RESP) { tbl_resp_authorise.apply(); }"),
    }
    missing = [name for name, index in positions.items() if index == -1]
    if missing:
        raise AssertionError(f"missing seven-stage dependency-order anchor(s): {', '.join(missing)}")
    if not positions["tbl_build_exp_ack"] < positions["tbl_expected_ack"]:
        raise AssertionError("tbl_build_exp_ack must run before tbl_expected_ack")
    if not positions["exp_seq_w"] < positions["guarded_resp_authorise"]:
        raise AssertionError("exp_seq_w tracker action must run before guarded tbl_resp_authorise")
    if not positions["exp_seq_r"] < positions["guarded_resp_authorise"]:
        raise AssertionError("exp_seq_r tracker action must run before guarded tbl_resp_authorise")
    if not positions["sess_port_rmw"] < positions["guarded_resp_authorise"]:
        raise AssertionError("sess_port_rmw must run before guarded tbl_resp_authorise")
    if not positions["tbl_expected_ack"] < positions["guarded_resp_authorise"]:
        raise AssertionError("tbl_expected_ack must run before guarded tbl_resp_authorise")
    assert_resp_authorise_guard_source(source)


def resp_authorise_old_effect(table: ParsedTable, fields: dict[str, int], tag_val: int, consts: dict[str, int]) -> int:
    action = table.apply(fields)
    if action == "resp_authorise":
        return consts["TAG_PENDING_DELTA"]
    if action == "resp_deauthorise":
        return 0
    if action == "resp_untouched":
        return tag_val & 0xFF
    raise AssertionError(f"unexpected resp_authorise action {action!r}")


def resp_authorise_guarded_effect(table: ParsedTable, fields: dict[str, int], tag_val: int, consts: dict[str, int]) -> int:
    if fields["pkt_class"] != consts["CLASS_RESP"]:
        return tag_val & 0xFF
    return resp_authorise_old_effect(table, fields, tag_val, consts)


def failopen_authorise_chain_effect(
    *,
    pkt_class: int,
    mode: int,
    budget_zero: int,
    tag_val: int,
    resp_authorised_tag: int,
    fo_take_value: int,
    consts: dict[str, int],
) -> tuple[int, bool]:
    if pkt_class == consts["CLASS_RESP"]:
        return resp_authorised_tag & 0xFF, False
    if pkt_class == consts["CLASS_ARM"]:
        if mode == consts["MODE_OFF"] or mode == consts["MODE_FAIL_OPEN"]:
            return consts["TAG_NO_WRITE"], False
        return fo_take_value & 0xFF, False
    if pkt_class == consts["CLASS_BLOCK_DEQ"] and budget_zero == 1:
        return tag_val & 0xFF, True
    return tag_val & 0xFF, False

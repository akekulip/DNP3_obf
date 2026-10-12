#!/usr/bin/env python3
"""Generate isolated E window-fold experiment from immutable incremental_55 source."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
BASE = HERE.parents[1]
SOURCE = BASE / "evidence" / "incremental_55" / "response_only.p4"
BASE_SHA256 = "628af1c66da5b61a7b4062dfae40b3e14320bc5d370d20219d893fef3862b261"

OLD_BASE_ACTION = "action reverse_window_base() { m.s_end = m.s_end + widen_win.get({hdr.tcp.window}); }"
NEW_BASE_ACTION = (
    "action reverse_window_base() { m.s_end = m.s_end + widen_win.get({hdr.tcp.window}); "
    "m.s_end = m.s_end + m.r; }"
)

OLD_ACTIONS = """action rev_translate() { hdr.tcp.ack = m.q + m.r; m.result = r_OUT_REV_TRANSLATE; m.changed = 1; }
    action rev_withhold_zero() { hdr.tcp.ack = m.p; hdr.tcp.window = 0; m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_withhold_open() { hdr.tcp.ack = m.p; m.s_end = m.s_end + m.r; m.wide = (bit<1>)(1);
                                 m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_drop() { m.result = r_OUT_REV_DROP_STALE; md.drop_ctl = 3w1; }
    table classify_rev {
        key = { m.r : ternary; hdr.tcp.window : range; }
        actions = { rev_translate; rev_withhold_zero; rev_withhold_open; rev_drop; }
        size = 118; const default_action = rev_drop();
        const entries = {
"""
NEW_ACTIONS = """Hash<bit<16>>(HashAlgorithm_t.IDENTITY) narrow_win;
    action rev_translate() { hdr.tcp.ack = m.q + m.r; m.result = r_OUT_REV_TRANSLATE; m.changed = 1; }
    action rev_withhold_zero() { hdr.tcp.ack = m.p; hdr.tcp.window = 0; m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_withhold_exact() { hdr.tcp.ack = m.p; hdr.tcp.window = narrow_win.get({m.s_end[15:0]});
                                  m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_withhold_clamp() { hdr.tcp.ack = m.p; hdr.tcp.window = 0xffff;
                                  m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_drop() { m.result = r_OUT_REV_DROP_STALE; md.drop_ctl = 3w1; }
    table classify_rev {
        key = { m.r : ternary; hdr.tcp.window : range; m.s_end : ternary; }
        actions = { rev_translate; rev_withhold_zero; rev_withhold_exact; rev_withhold_clamp; rev_drop; }
        size = 176; const default_action = rev_drop();
        const entries = {
"""

OLD_WINDOW_BLOCK = """    Hash<bit<16>>(HashAlgorithm_t.IDENTITY) narrow_win;
    action window_exact() { hdr.tcp.window = narrow_win.get({m.s_end[15:0]}); }
    action window_clamp() { hdr.tcp.window = 0xffff; }
    table window_t {
        key = { m.s_end : ternary; }
        actions = { window_exact; window_clamp; } size = 2; const default_action = window_clamp();
        const entries = { 32w0 &&& 32w0xFFFF0000 : window_exact(); 32w0 &&& 32w0 : window_clamp(); }
    }

"""

OLD_APPLY = "            if ((bit<8>)m.wide == 1) { window_t.apply(); }\n"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def classify_entries() -> str:
    lines = ["            (32w0 &&& 32w0x80000000, _, _) : rev_translate();"]
    for distance in range(1, 59):
        r = (1 << 32) - distance
        lines.append(f"            (32w0x{r:08x}, 16w0 .. 16w{distance - 1}, _) : rev_withhold_zero();")
        lines.append(
            f"            (32w0x{r:08x}, 16w{distance} .. 16w65535, "
            "32w0 &&& 32w0xFFFF0000) : rev_withhold_exact();"
        )
        lines.append(f"            (32w0x{r:08x}, 16w{distance} .. 16w65535, _) : rev_withhold_clamp();")
    return "\n".join(lines) + "\n"


def transform(text: str) -> tuple[str, dict[str, int]]:
    counts: dict[str, int] = {}
    counts["base_action"] = text.count(OLD_BASE_ACTION)
    assert counts["base_action"] == 1, counts
    text = text.replace(OLD_BASE_ACTION, NEW_BASE_ACTION)

    counts["actions_prefix"] = text.count(OLD_ACTIONS)
    assert counts["actions_prefix"] == 1, counts
    text = text.replace(OLD_ACTIONS, NEW_ACTIONS)

    start = text.index(NEW_ACTIONS) + len(NEW_ACTIONS)
    end = text.index("        }\n    }\n    Hash<bit<16>>(HashAlgorithm_t.IDENTITY) narrow_win;", start)
    old_entry_text = text[start:end]
    counts["old_classify_entry_lines"] = sum(1 for line in old_entry_text.splitlines() if ": rev_" in line)
    text = text[:start] + classify_entries() + text[end:]

    counts["window_block"] = text.count(OLD_WINDOW_BLOCK)
    assert counts["window_block"] == 1, counts
    text = text.replace(OLD_WINDOW_BLOCK, "")

    counts["window_apply"] = text.count(OLD_APPLY)
    assert counts["window_apply"] == 1, counts
    text = text.replace(OLD_APPLY, "")

    return text, counts


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=HERE / "evidence" / "full_01")
    args = ap.parse_args()
    src_sha = sha256(SOURCE)
    if src_sha != BASE_SHA256:
        raise SystemExit(f"immutable source sha mismatch: {src_sha}")
    text, counts = transform(SOURCE.read_text())
    args.out.mkdir(parents=True, exist_ok=False)
    out = args.out / "response_only.p4"
    out.write_text(text)
    manifest = {
        "experiment": "e_window_fold_classify",
        "status": "source_generated_uncompiled",
        "baseline_source": str(SOURCE),
        "baseline_sha256": src_sha,
        "source_sha256": hashlib.sha256(text.encode()).hexdigest(),
        "replacement_counts": counts,
        "entries": {"classify_rev": 175, "window_t_removed": True},
        "intent": "Precompute reverse endpoint before classify_rev, then classify zero/exact/clamp in classify_rev and remove final window_t.",
    }
    (args.out / "source_manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(json.dumps(manifest, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Generate full_03 E fold: classify exact/clamp from post-window B without final window_t."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
BASE = HERE.parents[1]
SOURCE = BASE / "evidence" / "incremental_55" / "response_only.p4"
BASE_SHA256 = "628af1c66da5b61a7b4062dfae40b3e14320bc5d370d20219d893fef3862b261"

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
NEW_ACTIONS = """action rev_translate() { hdr.tcp.ack = m.q + m.r; m.result = r_OUT_REV_TRANSLATE; m.changed = 1; }
    action rev_withhold_zero() { hdr.tcp.ack = m.p; hdr.tcp.window = 0; m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_withhold_exact_1() { hdr.tcp.ack = m.p; hdr.tcp.window = m.s_end[15:0] - 16w1;
                                         m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_withhold_exact_2() { hdr.tcp.ack = m.p; hdr.tcp.window = m.s_end[15:0] - 16w2;
                                         m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_withhold_exact_3() { hdr.tcp.ack = m.p; hdr.tcp.window = m.s_end[15:0] - 16w3;
                                         m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_withhold_exact_4() { hdr.tcp.ack = m.p; hdr.tcp.window = m.s_end[15:0] - 16w4;
                                         m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_withhold_exact_5() { hdr.tcp.ack = m.p; hdr.tcp.window = m.s_end[15:0] - 16w5;
                                         m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_withhold_exact_6() { hdr.tcp.ack = m.p; hdr.tcp.window = m.s_end[15:0] - 16w6;
                                         m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_withhold_exact_7() { hdr.tcp.ack = m.p; hdr.tcp.window = m.s_end[15:0] - 16w7;
                                         m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_withhold_exact_8() { hdr.tcp.ack = m.p; hdr.tcp.window = m.s_end[15:0] - 16w8;
                                         m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_withhold_exact_9() { hdr.tcp.ack = m.p; hdr.tcp.window = m.s_end[15:0] - 16w9;
                                         m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_withhold_exact_10() { hdr.tcp.ack = m.p; hdr.tcp.window = m.s_end[15:0] - 16w10;
                                         m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_withhold_exact_11() { hdr.tcp.ack = m.p; hdr.tcp.window = m.s_end[15:0] - 16w11;
                                         m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_withhold_exact_12() { hdr.tcp.ack = m.p; hdr.tcp.window = m.s_end[15:0] - 16w12;
                                         m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_withhold_exact_13() { hdr.tcp.ack = m.p; hdr.tcp.window = m.s_end[15:0] - 16w13;
                                         m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_withhold_exact_14() { hdr.tcp.ack = m.p; hdr.tcp.window = m.s_end[15:0] - 16w14;
                                         m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_withhold_exact_15() { hdr.tcp.ack = m.p; hdr.tcp.window = m.s_end[15:0] - 16w15;
                                         m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_withhold_exact_16() { hdr.tcp.ack = m.p; hdr.tcp.window = m.s_end[15:0] - 16w16;
                                         m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_withhold_exact_17() { hdr.tcp.ack = m.p; hdr.tcp.window = m.s_end[15:0] - 16w17;
                                         m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_withhold_exact_18() { hdr.tcp.ack = m.p; hdr.tcp.window = m.s_end[15:0] - 16w18;
                                         m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_withhold_exact_19() { hdr.tcp.ack = m.p; hdr.tcp.window = m.s_end[15:0] - 16w19;
                                         m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_withhold_exact_20() { hdr.tcp.ack = m.p; hdr.tcp.window = m.s_end[15:0] - 16w20;
                                         m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_withhold_exact_21() { hdr.tcp.ack = m.p; hdr.tcp.window = m.s_end[15:0] - 16w21;
                                         m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_withhold_exact_22() { hdr.tcp.ack = m.p; hdr.tcp.window = m.s_end[15:0] - 16w22;
                                         m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_withhold_exact_23() { hdr.tcp.ack = m.p; hdr.tcp.window = m.s_end[15:0] - 16w23;
                                         m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_withhold_exact_24() { hdr.tcp.ack = m.p; hdr.tcp.window = m.s_end[15:0] - 16w24;
                                         m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_withhold_exact_25() { hdr.tcp.ack = m.p; hdr.tcp.window = m.s_end[15:0] - 16w25;
                                         m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_withhold_exact_26() { hdr.tcp.ack = m.p; hdr.tcp.window = m.s_end[15:0] - 16w26;
                                         m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_withhold_exact_27() { hdr.tcp.ack = m.p; hdr.tcp.window = m.s_end[15:0] - 16w27;
                                         m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_withhold_exact_28() { hdr.tcp.ack = m.p; hdr.tcp.window = m.s_end[15:0] - 16w28;
                                         m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_withhold_exact_29() { hdr.tcp.ack = m.p; hdr.tcp.window = m.s_end[15:0] - 16w29;
                                         m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_withhold_exact_30() { hdr.tcp.ack = m.p; hdr.tcp.window = m.s_end[15:0] - 16w30;
                                         m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_withhold_exact_31() { hdr.tcp.ack = m.p; hdr.tcp.window = m.s_end[15:0] - 16w31;
                                         m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_withhold_exact_32() { hdr.tcp.ack = m.p; hdr.tcp.window = m.s_end[15:0] - 16w32;
                                         m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_withhold_exact_33() { hdr.tcp.ack = m.p; hdr.tcp.window = m.s_end[15:0] - 16w33;
                                         m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_withhold_exact_34() { hdr.tcp.ack = m.p; hdr.tcp.window = m.s_end[15:0] - 16w34;
                                         m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_withhold_exact_35() { hdr.tcp.ack = m.p; hdr.tcp.window = m.s_end[15:0] - 16w35;
                                         m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_withhold_exact_36() { hdr.tcp.ack = m.p; hdr.tcp.window = m.s_end[15:0] - 16w36;
                                         m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_withhold_exact_37() { hdr.tcp.ack = m.p; hdr.tcp.window = m.s_end[15:0] - 16w37;
                                         m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_withhold_exact_38() { hdr.tcp.ack = m.p; hdr.tcp.window = m.s_end[15:0] - 16w38;
                                         m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_withhold_exact_39() { hdr.tcp.ack = m.p; hdr.tcp.window = m.s_end[15:0] - 16w39;
                                         m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_withhold_exact_40() { hdr.tcp.ack = m.p; hdr.tcp.window = m.s_end[15:0] - 16w40;
                                         m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_withhold_exact_41() { hdr.tcp.ack = m.p; hdr.tcp.window = m.s_end[15:0] - 16w41;
                                         m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_withhold_exact_42() { hdr.tcp.ack = m.p; hdr.tcp.window = m.s_end[15:0] - 16w42;
                                         m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_withhold_exact_43() { hdr.tcp.ack = m.p; hdr.tcp.window = m.s_end[15:0] - 16w43;
                                         m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_withhold_exact_44() { hdr.tcp.ack = m.p; hdr.tcp.window = m.s_end[15:0] - 16w44;
                                         m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_withhold_exact_45() { hdr.tcp.ack = m.p; hdr.tcp.window = m.s_end[15:0] - 16w45;
                                         m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_withhold_exact_46() { hdr.tcp.ack = m.p; hdr.tcp.window = m.s_end[15:0] - 16w46;
                                         m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_withhold_exact_47() { hdr.tcp.ack = m.p; hdr.tcp.window = m.s_end[15:0] - 16w47;
                                         m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_withhold_exact_48() { hdr.tcp.ack = m.p; hdr.tcp.window = m.s_end[15:0] - 16w48;
                                         m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_withhold_exact_49() { hdr.tcp.ack = m.p; hdr.tcp.window = m.s_end[15:0] - 16w49;
                                         m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_withhold_exact_50() { hdr.tcp.ack = m.p; hdr.tcp.window = m.s_end[15:0] - 16w50;
                                         m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_withhold_exact_51() { hdr.tcp.ack = m.p; hdr.tcp.window = m.s_end[15:0] - 16w51;
                                         m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_withhold_exact_52() { hdr.tcp.ack = m.p; hdr.tcp.window = m.s_end[15:0] - 16w52;
                                         m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_withhold_exact_53() { hdr.tcp.ack = m.p; hdr.tcp.window = m.s_end[15:0] - 16w53;
                                         m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_withhold_exact_54() { hdr.tcp.ack = m.p; hdr.tcp.window = m.s_end[15:0] - 16w54;
                                         m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_withhold_exact_55() { hdr.tcp.ack = m.p; hdr.tcp.window = m.s_end[15:0] - 16w55;
                                         m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_withhold_exact_56() { hdr.tcp.ack = m.p; hdr.tcp.window = m.s_end[15:0] - 16w56;
                                         m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_withhold_exact_57() { hdr.tcp.ack = m.p; hdr.tcp.window = m.s_end[15:0] - 16w57;
                                         m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_withhold_exact_58() { hdr.tcp.ack = m.p; hdr.tcp.window = m.s_end[15:0] - 16w58;
                                         m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_withhold_clamp() { hdr.tcp.ack = m.p; hdr.tcp.window = 0xffff;
                                  m.result = r_OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_drop() { m.result = r_OUT_REV_DROP_STALE; md.drop_ctl = 3w1; }
    table classify_rev {
        key = { m.r : ternary; hdr.tcp.window : range; m.s_end[31:16] : ternary; m.s_end[15:0] : range; }
        actions = { rev_translate; rev_withhold_zero; rev_withhold_exact_1; rev_withhold_exact_2; rev_withhold_exact_3; rev_withhold_exact_4; rev_withhold_exact_5; rev_withhold_exact_6; rev_withhold_exact_7; rev_withhold_exact_8; rev_withhold_exact_9; rev_withhold_exact_10; rev_withhold_exact_11; rev_withhold_exact_12; rev_withhold_exact_13; rev_withhold_exact_14; rev_withhold_exact_15; rev_withhold_exact_16; rev_withhold_exact_17; rev_withhold_exact_18; rev_withhold_exact_19; rev_withhold_exact_20; rev_withhold_exact_21; rev_withhold_exact_22; rev_withhold_exact_23; rev_withhold_exact_24; rev_withhold_exact_25; rev_withhold_exact_26; rev_withhold_exact_27; rev_withhold_exact_28; rev_withhold_exact_29; rev_withhold_exact_30; rev_withhold_exact_31; rev_withhold_exact_32; rev_withhold_exact_33; rev_withhold_exact_34; rev_withhold_exact_35; rev_withhold_exact_36; rev_withhold_exact_37; rev_withhold_exact_38; rev_withhold_exact_39; rev_withhold_exact_40; rev_withhold_exact_41; rev_withhold_exact_42; rev_withhold_exact_43; rev_withhold_exact_44; rev_withhold_exact_45; rev_withhold_exact_46; rev_withhold_exact_47; rev_withhold_exact_48; rev_withhold_exact_49; rev_withhold_exact_50; rev_withhold_exact_51; rev_withhold_exact_52; rev_withhold_exact_53; rev_withhold_exact_54; rev_withhold_exact_55; rev_withhold_exact_56; rev_withhold_exact_57; rev_withhold_exact_58; rev_withhold_clamp; rev_drop; }
        size = 234; const default_action = rev_drop();
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


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def classify_entries() -> str:
    lines = ["            (32w0 &&& 32w0x80000000, _, _, _) : rev_translate();"]
    for distance in range(1, 59):
        r = (1 << 32) - distance
        lines.append(f"            (32w0x{r:08x}, 16w0 .. 16w{distance - 1}, _, _) : rev_withhold_zero();")
        lines.append(
            f"            (32w0x{r:08x}, 16w{distance} .. 16w65535, 16w0, "
            f"16w{distance} .. 16w65535) : rev_withhold_exact_{distance}();"
        )
        lines.append(
            f"            (32w0x{r:08x}, 16w{distance} .. 16w65535, 16w1, "
            f"16w0 .. 16w{distance - 1}) : rev_withhold_exact_{distance}();"
        )
        lines.append(f"            (32w0x{r:08x}, 16w{distance} .. 16w65535, _, _) : rev_withhold_clamp();")
    return "\n".join(lines) + "\n"


def transform(text: str) -> tuple[str, dict[str, int]]:
    counts = {"actions_prefix": text.count(OLD_ACTIONS), "window_block": text.count(OLD_WINDOW_BLOCK), "window_apply": text.count(OLD_APPLY)}
    assert counts["actions_prefix"] == 1, counts
    assert counts["window_block"] == 1, counts
    assert counts["window_apply"] == 1, counts
    text = text.replace(OLD_ACTIONS, NEW_ACTIONS)
    start = text.index(NEW_ACTIONS) + len(NEW_ACTIONS)
    end = text.index("        }\n    }\n    Hash<bit<16>>(HashAlgorithm_t.IDENTITY) narrow_win;", start)
    old_entry_text = text[start:end]
    counts["old_classify_entry_lines"] = sum(1 for line in old_entry_text.splitlines() if ": rev_" in line)
    text = text[:start] + classify_entries() + text[end:]
    text = text.replace(OLD_WINDOW_BLOCK, "")
    text = text.replace(OLD_APPLY, "")
    counts["new_classify_entry_lines"] = 1 + 58 * 4
    return text, counts


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=HERE / "evidence" / "full_03")
    args = ap.parse_args()
    source_bytes = SOURCE.read_bytes()
    source_sha = sha256_bytes(source_bytes)
    if source_sha != BASE_SHA256:
        raise SystemExit(f"immutable source sha mismatch: {source_sha}")
    text, counts = transform(source_bytes.decode())
    args.out.mkdir(parents=True, exist_ok=False)
    (args.out / "response_only.p4").write_text(text)
    manifest = {
        "experiment": "e_window_fold_classify/full_03",
        "status": "source_generated_uncompiled",
        "baseline_source": str(SOURCE),
        "baseline_sha256": source_sha,
        "source_sha256": hashlib.sha256(text.encode()).hexdigest(),
        "replacement_counts": counts,
        "intent": "Keep reverse_gap/reverse_window_base unchanged; split classify_rev by B=m.s_end interval and subtract immediate distance in exact actions; remove final window_t.",
        "entries": {"classify_rev": 233, "window_t_removed": True},
    }
    (args.out / "source_manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(json.dumps(manifest, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

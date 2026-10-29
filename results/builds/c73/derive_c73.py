#!/usr/bin/env python3
"""Derive the c73 source from c72 by REAL deletion (record of how p4/response_only.p4 c73 was produced).

  python3 results/builds/c73/derive_c73.py results/builds/c72/response_only.p4 OUT.p4 MANIFEST.json

Edits = the read-only inventory's cumulative variant D2 (A2 certain set + B2 + C2 + D2) MINUS the kind-12 replay
domain, plus a "tidy" group of direct consequences (stale comments, r_OUT_* constants whose only use was a removed
m.result write, whitespace left inside edited lines). Each edit asserts its exact match count. The edits first run in
blank-line mode (line count preserved, as in the inventory variants); then every line that was non-blank in c72 and
became blank is deleted, so MANIFEST names c72 line numbers exactly. Optional env BLANK_OUT=path writes the
line-preserving twin (used for the generated-name-only compile check).
"""
import json
import re
import sys
from pathlib import Path

SRC, OUT, MANIFEST = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
text0 = SRC.read_text()
PARTS = "N1 N2 N3 N4 U2 E1 E2 E3 T".split()   # U2: keep r_IgParser/r_Ingress/r_IgDeparser (pragma trap)
def nl(s):
    return "\n" * s.count("\n")


def match_brace(s, i):
    d = 0
    for j in range(i, len(s)):
        if s[j] == "{":
            d += 1
        elif s[j] == "}":
            d -= 1
            if d == 0:
                return j
    raise ValueError


class Ed:
    def __init__(self, t):
        self.t = t
        self.log = []

    def exact(self, old, new="", count=1):
        n = self.t.count(old)
        assert n == count, (old[:80], n, count)
        if new == "":
            new = nl(old)
        self.t = self.t.replace(old, new)
        self.log.append(("exact", old[:70].replace("\n", "\\n"), count))

    def rx(self, pat, count=None, repl=None, scope=None):
        reg = re.compile(pat)
        lo, hi = (0, len(self.t)) if scope is None else scope_span(self.t, scope)
        seg = self.t[lo:hi]
        found = list(reg.finditer(seg))
        if count is not None:
            assert len(found) == count, (pat, len(found), count)
        seg2 = reg.sub((lambda m: nl(m.group(0))) if repl is None else repl, seg)
        self.t = self.t[:lo] + seg2 + self.t[hi:]
        self.log.append(("rx", pat, len(found)))

    def block(self, head_pat, count=1, scope=None):
        """Remove `<head>{...}` (head regex ends just before '{') plus a trailing ';'."""
        lo, hi = (0, len(self.t)) if scope is None else scope_span(self.t, scope)
        found = 0
        while True:
            m = re.compile(head_pat + r"(?=\{)").search(self.t, lo, hi)
            if not m:
                break
            b = self.t.index("{", m.end() - 1)
            e = match_brace(self.t, b) + 1
            if e < len(self.t) and self.t[e] == ";":
                e += 1
            old = self.t[m.start():e]
            self.t = self.t[:m.start()] + nl(old) + self.t[e:]
            hi -= len(old) - len(nl(old))
            found += 1
        assert found == count, (head_pat, found, count)
        self.log.append(("block", head_pat, found))


def scope_span(t, name):
    m = re.search(r"^\s*(control|parser)\s+" + name + r"\s*\(", t, re.M)
    p = t.index("(", m.start())
    d = 0
    while True:
        if t[p] == "(":
            d += 1
        elif t[p] == ")":
            d -= 1
            if d == 0:
                break
        p += 1
    b = t.index("{", p)
    return m.start(), match_brace(t, b) + 1


def act(name):
    return r"\baction\s+" + name + r"\s*\([^)]*\)\s*"


def tab(name):
    return r"(?:@stage\(\d+\)\s*)?\btable\s+" + name + r"\s*"


GROUP = []   # (group label, Ed.log index range) for the manifest


def mark(e, label):
    GROUP.append((label, len(e.log)))


def group_a(e):
    if "N1" in PARTS:
        # ---- N ingress: unapplied tables, their actions and hashes
        for t in ("syn_shapes", "short_shapes", "available_t", "epoch_guard", "read_request_profile",
                  "rd_second_crc_t", "rd_request_crc_t", "rd_tail_crc_t"):
            e.block(tab(t), scope="n_Ingress")
        for a in ("syn_shape", "synack_shape", "ack_shape", "close_shape", "available", "epoch_ok",
                  "rd_second_crc", "rd_request_crc", "rd_tail_crc"):
            e.block(act(a), scope="n_Ingress")
        for h in ("hash_rd_second", "hash_rd_request", "hash_rd_tail"):
            e.rx(r"Hash<bit<16>>\(HashAlgorithm_t\.CUSTOM,poly\) " + h + r";", 1, scope="n_Ingress")
    if "N2" in PARTS:
        # N metadata fields never read (and their writes)
        dead_n = ("cache_mode association_allowed operate_qualified prefix_difference accepted_diff bad1 "
                  "compare_frozen_decoy_object diff_frozen_decoy_object compare_frozen_decoy_on "
                  "compare_frozen_decoy_off diff_frozen_decoy_off context_generation native_end changed "
                  "tcp_length decoy_index decoy_code decoy_repeat decoy_on decoy_off badb badt data_valid "
                  "epoch_valid emit_loop counter").split()
        for f in dead_n:
            e.rx(r"(?<=[{;])(bit<\d+>)\s+" + f + r";", 1, repl="", scope=None)
            for sc in ("n_IgParser", "n_Ingress"):
                e.rx(r"(?<![\w.])m\." + f + r"\s*=\s*[^;]*;", None, repl="", scope=sc)
    if "N3" in PARTS:
        # N headers never extracted (rd_req stays: read_input_t row, group C)
        for inst, ty in (("second", "n_block_h"), ("response_tail", "n_response_tail_h"),
                         ("rd_tail", "n_read_tail_h"), ("rb", "n_replay_h")):
            e.exact(ty + " " + inst + ";", "")
        e.exact("header n_response_tail_h{bit<32> w0;bit<32> w1;bit<8> w2;bit<16> crc;}\n", "\n")
        e.exact("header n_read_tail_h{bit<8> value;bit<16> crc;}\n", "\n")
        e.exact("header n_replay_h{bit<8> value;}\n", "\n")
    if "N4" in PARTS:
        # N parser states with no path from start
        for st in ("ip_flags mss_check mss_syn mss_synack read_dl read_request read_response_block "
                   "read_response_ip_flags read_response_second read_response_tail read_response_tcp "
                   "response_block response_dl response_ip_flags response_tcp tcp ts_read_ip_flags "
                   "ts_read_opt ts_read_tcp").split():
            e.block(r"\bstate\s+" + st + r"\s*", scope="n_IgParser")
    if "U" in PARTS or "U2" in PARTS:
        # uninstantiated controls/parsers (U2 keeps r_Ig*: the pragma block before r_IgParser stays dropped)
        keep_r = "U" not in PARTS
        for c in ("n_EgParser", "n_Egress", "n_EgDeparser") + (() if keep_r else ("r_IgParser", "r_Ingress", "r_IgDeparser")) + (
                  "t_EmptyEgressParser", "t_EmptyEgress", "t_EmptyEgressDeparser"):
            lo, hi = scope_span(e.t, c)
            old = e.t[lo:hi]
            e.t = e.t[:lo] + nl(old) + e.t[hi:]
            e.log.append(("scope", c, 1))
    if "E1" in PARTS:
        # ---- E egress
        for t in ("in_rb0_t", "in_rb1_t", "in_rt_t", "crc_read_tail_t", "crc_read_b_t"):
            e.block(tab(t), scope="r_Egress")
        for a in ("in_rb0", "in_rb1", "in_rt", "crc_read_tail", "crc_read_b"):
            e.block(act(a), scope="r_Egress")
        for h in ("hash_in_rb0", "hash_in_rb1", "hash_in_rt", "hash_read_tail", "hash_read_b"):
            e.rx(r"Hash<bit<16>>\(HashAlgorithm_t\.CUSTOM,poly\) " + h + r";", 1, scope="r_Egress")
        e.exact("Checksum() tcp_read; ", "")
    if "E2" in PARTS:
        e.exact("bit<16> rtcrc; bit<16> rtcrc_b; ", "")
        e.exact("bit<16> in_rb0; bit<16> in_rb1; ", "")
        # m.result: written 19x, never read, not allocated
        e.exact("bit<8>  result; ", "")
        for sc in ("r_EgParser", "r_Egress"):
            e.rx(r"(?<![\w.])m\.result\s*=\s*[^;]*;", None, repl="", scope=sc)
    if "E3" in PARTS:
        for ty in ("r_ctl_tail_p1_h", "r_ctl_tail_p2_h", "r_read_d56_h"):
            e.rx(r"header " + ty + r"\{[^}]*\}\n", 1, repl="\n")
        e.block(r"\bstate\s+mss\s*", scope="r_EgParser")
        e.exact("const bit<8> r_SH_NONE = 0; ", "")
    if "T" in PARTS:
        # ---- T ingress
        for a in ("admit_gen", "bypass_request", "flush_ack_off", "flush_response_off", "peek_gen",
                  "reset_bump_gen", "stop_blocking_off", "unmatched"):
            e.block(act(a), scope="t_Ingress")
        e.exact("bit<32> cur_epoch_val; ", "")
        e.exact("bit<32> quarantined_epoch; ", "")
        e.exact("bit<32> seen1_diff; bit<32> seen2_diff; ", "")
        e.exact("md.seen1_diff = 32w0xffffffff; md.seen2_diff = 32w0xffffffff;", "")
        # ---- x egress
        e.exact("bit<2> p1_res; ", "")
        e.rx(r"(?<![\w.])m\.p1_res\s*=\s*[^;]*;", 4, repl="", scope=None)


def group_b(e):
    # read_b0 is unreachable, so these E headers are never valid; drop them from struct, checksums, emits
    e.block(r"\bstate\s+read_b0\s*", scope="r_EgParser")
    e.exact(" r_read_hdr40_h ra; r_read_d32_h p03; r_read_crc_h ca;", "")
    e.exact("r_read_hdr40_h rbh; r_read_d16_h p45; r_read_crc_h c0; r_read_d32_h p69; r_read_d24_h p1012; r_read_crc_h cb;", "")
    e.exact("r_read_hdr_h rc; r_read_d72_h p1321; r_read_crc_h c1; r_read_d8_h p22; r_read_crc_h c2; ", "")
    e.exact(" r_ctl_dl_h cd3;", "")
    blk = ("hdr.robj.g_start, hdr.robj.g_stop, hdr.p03.d, hdr.p45.d, hdr.c0.crc,\n"
           "                hdr.p69.d, hdr.p1012.d, hdr.p1321.d, hdr.c1.crc,\n"
           "                hdr.p22.d, hdr.c2.crc, 8w0,\n")
    e.exact(blk, "hdr.robj.g_start, hdr.robj.g_stop,\n\n\n", count=2)   # 30 bytes: parity preserved
    for inst in ("p03", "p45", "c0", "p69", "p1012", "p1321", "c1", "p22", "c2", "cd3"):
        e.rx(r"\s?pkt\.emit\(hdr\." + inst + r"\);", 1, repl="", scope="r_EgDeparser")
    for f in ("p03.d", "p45.d", "c0.crc", "p69.d", "p1012.d", "p1321.d", "c1.crc", "p22.d", "c2.crc"):
        e.exact('@pa_no_overlay("egress", "hdr.%s")\n' % f, "\n")
    for ty in ("r_read_hdr40_h", "r_read_d32_h", "r_read_d16_h", "r_read_d24_h", "r_read_d72_h",
               "r_read_d8_h", "r_read_hdr_h", "r_read_crc_h"):
        e.rx(r"header " + ty + r"\{[^}]*\}\n", 1, repl="\n")


def group_c_without_kind12(e):
    # N: packet_kind 9 always has rd_req_full or rd_req_mx valid -> row and hdr.rd_req are dead
    e.exact("(8w9,false,false,_):read_request_input();", "")
    e.block(act("read_request_input"), scope="n_Ingress")
    e.rx(r"read_request_input;", 1, repl="", scope="n_Ingress")
    e.exact("n_read_req_h rd_req;", "")
    e.exact('@pa_mutually_exclusive("ingress", "hdr.rd_req", "hdr.rd_req_full")\n', "\n")
    e.exact('@pa_mutually_exclusive("ingress", "hdr.rd_req", "hdr.rd_req_mx")\n', "\n")
    e.rx(r"header n_read_req_h\{[^}]*\}\n", 1, repl="\n")
    # (kind-12 replay domain intentionally NOT removed: needs Philip's confirmation that it is retired)
    # never-selectable actions of const tables
    for a in ("close_pending", "close_free", "first_close_ack", "close_forward"):
        e.block(act(a), scope="n_Ingress")
        e.rx(r"(?<=[{;])" + a + r";", 1, repl="", scope="n_Ingress")
    e.block(act("rev_withhold_zero"), scope="r_Egress")
    e.exact("rev_withhold_zero; ", "")
    # E: rbad0/rbad1/rbadt are constant 0 (parser init only): drop them as keys
    e.exact("m.rbad0 : ternary; m.rbad1 : ternary; m.rbadt : ternary; ", "", count=2)
    for tname in ("acct_t", "classify_fwd"):
        lo, hi = scope_span(e.t, "r_Egress")
        m = re.compile(r"table\s+" + tname + r"\s*\{").search(e.t, lo, hi)
        b = e.t.index("{", m.end() - 1)
        end = match_brace(e.t, b)
        seg = e.t[b:end]
        ent = seg.index("const entries")

        def drop(mm):
            cols = [c for c in re.split(r",(?![^()]*\))", mm.group(1))]
            # key columns 10,11,12 (0-based) are rbad0, rbad1, rbadt
            assert all(c.strip() in ("0", "_") for c in cols[10:13]), cols
            return "(" + ",".join(cols[:10] + cols[13:]) + "):"
        new = seg[:ent] + re.sub(r"\(((?:[^()]|\([^()]*\))*)\)\s*:", drop, seg[ent:])
        e.t = e.t[:b] + new + e.t[end:]
        e.log.append(("rbad-cols", tname, 1))
    e.exact("bit<1> rbad0; bit<1> rbad1; bit<1> rbadt; ", "")
    e.exact(" m.rbad0 = 0; m.rbad1 = 0; m.rbadt = 0;", "")
    e.exact('@pa_solitary("egress","m.rbad0") @pa_solitary("egress","m.rbad1")', "")
    e.exact('@pa_solitary("egress","m.rbadt") ', "")


def group_d(e):
    # n_ExpectedWorkRecord operation 3 (inspect): m.work_op is only ever 0, 1 or 2
    e.block(r"RegisterAction<n_expected_work_cell_t, bit<1>, bit<32>>\(work\) inspect\s*=\s*", scope="n_ExpectedWorkRecord")
    e.exact("    action inspect_work() { observed_phase = inspect.execute(0); }\n", "\n")
    e.exact("actions = { claim_work; return_work; read_work; inspect_work; unavailable_work; }",
            "actions = { claim_work; return_work; read_work; unavailable_work; }")
    for p in ("1", "2", "3"):
        e.exact("            (3, %s) : inspect_work();\n" % p, "\n")
    e.exact("            (3, _) : unavailable_work();\n", "\n")
    e.exact("const default_action = read_work(); size = 9;", "const default_action = read_work(); size = 5;")
    e.exact("// operation3 inspects the full qualified pin without accelerating terminal.\n", "\n")
    # r_Egress.odd_ip_t: odd_conn's writes (m.dir, m.idx) are followed by drop_lifetime() and never read
    e.block(act("odd_conn"), scope="r_Egress")
    e.block(tab("odd_ip_t"), scope="r_Egress")
    e.exact("if ((bit<8>)m.ip_odd == 1) { odd_ip_t.apply(); drop_lifetime(); }",
            "if ((bit<8>)m.ip_odd == 1) { drop_lifetime(); }")
    # stale comment: rbad and read_b0 no longer exist
    e.exact("        /* rbad0/rbad1/rbadt checks removed: c0/c1/c2 are only extracted by read_b0, which no state reaches */\n", "\n")


def group_tidy(e):
    """Consequences of the removals above, no new semantics: r_OUT_* constants whose only use was a removed
    m.result write, comments that described m.result, and whitespace left inside edited lines."""
    e.exact("const bit<8> r_OUT_COMMIT = 1;  const bit<8> r_OUT_TRANSLATE = 2; const bit<8> r_OUT_ZERO = 3;\n"
            "const bit<8> r_OUT_REPLAY = 4;  const bit<8> r_OUT_STALE = 5;     const bit<8> r_OUT_DROP_OVERLAP = 6;\n"
            "const bit<8> r_OUT_DROP_AHEAD = 7; const bit<8> r_OUT_DROP_ODD = 8;\n"
            "const bit<8> r_OUT_REV_TRANSLATE = 9; const bit<8> r_OUT_REV_WITHHOLD = 10; const bit<8> r_OUT_REV_DROP_STALE = 11;\n"
            "const bit<8> r_OUT_NATIVE = 12; const bit<8> r_OUT_ARM_MAP = 13; const bit<8> r_OUT_ARM_NAT = 14;\n"
            "const bit<8> r_OUT_DROP_MERGED = 15; const bit<8> r_OUT_RESET_FRONT = 16;   // replay with a native suffix: not checksummable in one pass (spec 10)\n",
            "const bit<8> r_OUT_DROP_OVERLAP = 6; const bit<8> r_OUT_DROP_AHEAD = 7; const bit<8> r_OUT_DROP_MERGED = 15;   // out_drop(why) labels\n"
            + "\n" * 5)
    e.exact("    /* settle_t drops untranslatable shapes on mapped connections (drop_odd) and gives m.result its value on\n"
            "       paths no classifier writes. */\n",
            "    /* settle_t drops untranslatable shapes on mapped connections (drop_odd). native/armed_map/armed_nat are\n"
            "       empty: tofino-model telemetry markers whose Execute Action lines the model gate counts. */\n")
    e.exact("settle_t.apply();      // outcomes no classifier produces; the classifiers overwrite m.result later",
            "settle_t.apply();      // outcomes no classifier produces")
    for old, new in (
            ("\n         m.changed = 0; m.pad = 0;", "\n        m.changed = 0; m.pad = 0;"),
            ("{ m.qx = m.q;      m.pad = 1; }", "{ m.qx = m.q;  m.pad = 1; }"),
            ("{ m.qx = m.q;   m.changed = 1; }", "{ m.qx = m.q;  m.changed = 1; }"),
            ("{ m.qx = m.pm;       m.changed = 1; }", "{ m.qx = m.pm; m.changed = 1; }"),
            ("{ m.qx = m.pm;     m.pad = 1; }", "{ m.qx = m.pm; m.pad = 1; }"),
            ("{ m.qx = m.pm;      m.changed = 1; }", "{ m.qx = m.pm; m.changed = 1; }"),
            ("{  md.drop_ctl = 3w1; }", "{ md.drop_ctl = 3w1; }"),
            ("{ m.qx = m.q + negn;  m.changed = 1; }", "{ m.qx = m.q + negn; m.changed = 1; }"),
            ("{ hdr.tcp.ack = m.q + m.r;  m.changed = 1; }", "{ hdr.tcp.ack = m.q + m.r; m.changed = 1; }"),
            ("                                  m.changed = 1; }", "                                 m.changed = 1; }"),
            ("() {  }", "() { }"),
            ("child_seen0_access.apply();   \n", "child_seen0_access.apply();\n"),
            ("m.mx = 0; m.fl = 0; \n", "m.mx = 0; m.fl = 0;\n"),
            ("m.mx = 1;  }", "m.mx = 1; }"),
            ("m.fl = 1;  }", "m.fl = 1; }"),
            ("m.conn_ok = 1;  }", "m.conn_ok = 1; }")):
        e.exact(old, new, count={"{  md.drop_ctl = 3w1; }": 3, "() {  }": 3}.get(old, 1))
    # the include guard and comment of the removed t_EmptyEgress* shells
    e.rx(r"#ifndef CASE4_PROBE_SHELL_P4\n#define CASE4_PROBE_SHELL_P4\n// No target side effects[^\n]*\n\n*#endif\n", 1)
    for img in ("c4", "c3", "73", "62"):
        e.exact("32w0xffffff%s;  m.changed = 1; }" % img, "32w0xffffff%s; m.changed = 1; }" % img)


e = Ed(text0)
mark(e, "A2"); group_a(e)
mark(e, "B2"); group_b(e)
mark(e, "C2-minus-kind12"); group_c_without_kind12(e)
mark(e, "D2"); group_d(e)
mark(e, "tidy"); group_tidy(e)
assert e.t.count("\n") == text0.count("\n"), "line count changed"
import os
if os.environ.get("BLANK_OUT"): Path(os.environ["BLANK_OUT"]).write_text(e.t)
old, new = text0.split("\n"), e.t.split("\n")
deleted, edited, out = [], [], []
for i, (a, b) in enumerate(zip(old, new), 1):
    if (a.strip() and not b.strip()) or (a and not a.strip() and b == ""):
        deleted.append(i)
        continue
    if a != b:
        if b != b.rstrip() and a == a.rstrip():
            b = b.rstrip()
        edited.append(i)
    out.append(b)
result = "\n".join(out)
OUT.write_text(result)


def ranges(lines):
    spans = []
    for n in lines:
        if spans and n == spans[-1][1] + 1:
            spans[-1][1] = n
        else:
            spans.append([n, n])
    return ["%d" % a if a == b else "%d-%d" % (a, b) for a, b in spans]


bounds = [g[1] for g in GROUP] + [len(e.log)]
MANIFEST.write_text(json.dumps(dict(
    c72_lines=text0.count("\n"), c72_bytes=len(text0.encode()), c73_lines=result.count("\n"), c73_bytes=len(result.encode()),
    c72_lines_deleted=len(deleted), c72_lines_partially_edited=len(edited),
    deleted_c72_line_ranges=ranges(deleted), edited_c72_lines=edited,
    edits={label: [list(r) for r in e.log[bounds[k]:bounds[k + 1]]] for k, (label, _) in enumerate(GROUP)}), indent=1) + "\n")
print("c72", text0.count("\n"), len(text0.encode()), "-> c73", result.count("\n"), len(result.encode()),
      "deleted lines", len(deleted), "edited lines", len(edited))

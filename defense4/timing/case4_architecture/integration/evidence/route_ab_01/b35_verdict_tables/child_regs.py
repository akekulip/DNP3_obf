"""Replace the {gen, mask} response-child register with one single-word register per child (b40).

bfas rejects the masked condition `(value.mask & BIT) != 0` on a two-field register ("Syntax error,
expecting register slice", b38/b39). Per child k, child_seen<k>_reg holds the READ generation in which
child k was last admitted: admitting returns value ^ cur_gen (0 = duplicate in this generation) and
records cur_gen; "some child seen in cur_gen" is any of the three reading 0. Same semantics as the
pair (which reset its mask whenever the generation changed and tested one bit per child).
"""
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
t = path.read_text()


def rep(a, b, n=1):
    global t
    k = t.count(a)
    assert k == n, (k, a[:100])
    t = t.replace(a, b)


rep("struct gen_mask_t { bit<32> gen; bit<32> mask; }\n", "")
rep("    bit<8> resp_seen_mask; bit<8> dup;",
    "    // seen<k>_diff: child_seen<k>_reg XOR cur_gen, 0 = response child k admitted in this generation.\n"
    "    // dup_diff: the same for the child being admitted on this T_IN pass, before it is recorded.\n"
    "    bit<32> seen0_diff; bit<32> seen1_diff; bit<32> seen2_diff; bit<32> dup_diff;")
s = t.index("    Register<gen_mask_t, bit<1>>(1, {0, 0}) resp_mask_reg;")
e = t.index("    };", t.index("mask_try_admit2 = {")) + len("    };")
regs = """    // Response children (route_ab_01/b40): one single-word register per child k (tev.stage 0, 1, 2+),
    // holding the READ generation in which child k was last admitted; initial 0xffffffff so that no
    // child reads as seen in generation 0 (restore that value, not 0, on any clear). Replaces a {gen,
    // mask} pair whose `(value.mask & BIT) != 0` condition bfas rejects ("expecting register slice").
"""
for k in range(3):
    regs += """    Register<bit<32>, bit<1>>(1, 0xffffffff) child_seen%(k)d_reg;
    RegisterAction<bit<32>, bit<1>, bit<32>>(child_seen%(k)d_reg) child_try%(k)d = {
        void apply(inout bit<32> value, out bit<32> out_value) { out_value = value ^ md.cur_gen; value = md.cur_gen; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(child_seen%(k)d_reg) child_read%(k)d = {
        void apply(inout bit<32> value, out bit<32> out_value) { out_value = value ^ md.cur_gen; }
    };
""" % {'k': k}
regs += """    action read_seen0() { md.seen0_diff = child_read0.execute(0); }
    action read_seen1() { md.seen1_diff = child_read1.execute(0); }
    action read_seen2() { md.seen2_diff = child_read2.execute(0); }"""
t = t[:s] + regs + t[e:]

rep("""                if (hdr.tev.stage == 0) { md.dup = (bit<8>)mask_try_admit0.execute(0); }
                else if (hdr.tev.stage == 1) { md.dup = (bit<8>)mask_try_admit1.execute(0); }
                else { md.dup = (bit<8>)mask_try_admit2.execute(0); }""",
    """                if (hdr.tev.stage == 0) { md.dup_diff = child_try0.execute(0); }
                else if (hdr.tev.stage == 1) { md.dup_diff = child_try1.execute(0); }
                else { md.dup_diff = child_try2.execute(0); }""")
rep("            md.resp_seen_mask = (bit<8>)mask_read.execute(0);\n",
    "            read_seen0(); read_seen1(); read_seen2();\n")

# tin_verdict: dup key
rep("                md.done_diff : ternary; md.dup : ternary; }", "                md.done_diff : ternary; md.dup_diff : ternary; }")
rep("            (KIND_RESPONSE, _, _, 0, _, 1) : drop_duplicate_response();",
    "            (KIND_RESPONSE, _, _, 0, _, 0) : drop_duplicate_response();")

SEEN = {'_': '_, _, _', '8w1 &&& 8w1': '0, _, _', '8w2 &&& 8w2': '_, 0, _', '8w4 &&& 8w4': '_, _, 0'}


def convert_rows(table, index, width):
    """Rewrite the resp_seen_mask element (position `index`) of every const entry in `table`."""
    global t
    s = t.index('    table %s {' % table)
    e = t.index('        default_action', s)
    body = t[s:e]

    def fix(m):
        items = [x.strip() for x in m.group(1).split(',')]
        assert len(items) == width, (table, items)
        items[index:index + 1] = [SEEN[items[index]]]
        return '(' + ', '.join(items) + ')'
    body = re.sub(r'\(([^()]*)\)(?=\s*:)', fix, body)
    t = t[:s] + body + t[e:]


rep("                md.da_delta : ternary; md.resp_seen_mask : ternary; }",
    "                md.da_delta : ternary; md.seen0_diff : ternary; md.seen1_diff : ternary;\n"
    "                md.seen2_diff : ternary; }")
convert_rows('ack_go_check', 4, 5)
rep("                md.commit_diff : ternary; md.resp_seen_mask : ternary; hdr.ladder.budget : ternary; }",
    "                md.commit_diff : ternary; md.seen0_diff : ternary; md.seen1_diff : ternary;\n"
    "                md.seen2_diff : ternary; hdr.ladder.budget : ternary; }")
convert_rows('held_verdict', 8, 10)
path.write_text(t)
print('ok')

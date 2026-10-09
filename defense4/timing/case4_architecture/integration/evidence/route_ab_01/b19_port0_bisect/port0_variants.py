"""Diagnostic-only: vary one sub-piece of the port-0 (generator token) branch at a time."""
import sys
from pathlib import Path
src = Path(sys.argv[1]).read_text(); out = Path(sys.argv[2]); out.mkdir(parents=True, exist_ok=True)
OPM = "if (md.token_gen != (md.op_gen & 32w0xffff)) { drop_timer_stale(); }"
RDM = "if (md.token_gen != (md.cur_gen & 32w0xffff)) { drop_timer_stale(); }"
V = {
 'p1_no_mask_compare_op':   [(OPM, "if (md.token_gen != md.op_gen) { drop_timer_stale(); }")],
 'p2_no_mask_compare_read': [(RDM, "if (md.token_gen != md.cur_gen) { drop_timer_stale(); }")],
 'p3_no_compares':          [(OPM, "if (false) { drop_timer_stale(); }"), (RDM, "if (false) { drop_timer_stale(); }")],
 'p4_no_op_peek':           [("                md.op_gen = op_gen_peek.execute(0);\n", "")],
 'p5_no_packet_id_gate':    [("} else if (((bit<32>)hdr.timer.packet_id & 32w1) == 0) {", "} else if (true) {")],
 'p6_no_seeds':             [("else { seed_op_blocker(); }", "else { drop_timer(); }"), ("else { seed_ack_blocker(); }", "else { drop_timer(); }"), ("else { seed_resp_blocker(); }", "else { drop_timer(); }")],
 'p7_no_casts':             [("            md.token_domain = (bit<32>)hdr.timer.app_id;\n            md.token_gen = (bit<32>)hdr.timer.batch_id;\n            if (md.token_domain == 1) {",
                              "            if (hdr.timer.app_id == 1) {")] ,
}
for n, reps in V.items():
    t = src
    for a, b in reps:
        k = t.count(a); assert k >= 1, (n, a)
        t = t.replace(a, b)
    (out / (n + '.p4')).write_text(t); print(n)

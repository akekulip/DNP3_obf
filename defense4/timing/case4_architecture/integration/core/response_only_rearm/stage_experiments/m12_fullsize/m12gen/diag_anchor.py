"""Diagnostic transaction anchors on T's switch clock (m12p_c52d; a separate evidence tier, Philip 2026-10-25).

STATUS: does not fit (three SDK 9.13.2 attempts, ctl_timing_01/evidence/C52D_FIT_RECORD_20261025.md); the
branch is stopped. Kept so the attempts regenerate byte for byte; c52 stays the measured baseline, and without
--diag-anchors the generator emits c52 byte for byte. This layer only ADDS a recorder to T (pipe-1 ingress).

Six write-once rings (RING slots, slot = generation[7:0], cleared by the control plane before each trial),
attempt-3 design:
  d_p1  READ admission (T_IN REQUEST that admits a generation; t0_admit writes md.now)
  d_p2  genuine ACK commit (the commit_at_access rows; the anchor of D), in the held branch
  d_p3  ACK release (ACK_COMMIT; ACK_FALLBACK sets tag bit 30)
  d_p4  response release (RESP_RELEASE; RESP_FALLBACK sets tag bit 30)
  d_p5  OPERATE anchor (op_t0_arm), OPERATE lane (tag bit 30, op_gen)
  d_p6  OPERATE release (OP_RELEASE), OPERATE lane
Slot: lo = md.now (global_tstamp[39:8] & ~1: 256 ns units, 512 ns grid; lo bit 0 = duplicate mark),
hi = bit 31 collided | bit 30 flag | epoch[13:0] << 16 | generation[15:0]. T parses no TCP header, so the TCP SEQ
is not in the tag. Release points are T decision passes, not wire departure.
"""
from .common import once

RING = 256
POINTS = ('d_p1', 'd_p2', 'd_p3', 'd_p4', 'd_p5', 'd_p6')
FLAG = '32w0x40000000'


def record_action(reg, name, tag):
    return '''    RegisterAction<t_d_pair_t, bit<8>, bit<32>>(%s) %s = {
        void apply(inout t_d_pair_t v, out bit<32> rv) {
            if (v.hi == 0) { v.hi = %s; v.lo = md.now; }
            else if (v.hi != %s) { v.hi = v.hi | 32w0x80000000; }
            else { v.lo = v.lo | 32w1; }
            rv = 0;
        }
    };
''' % (reg, name, tag, tag)


def declarations():
    out = ['    // ---- diagnostic anchors (m12p_c52d, recording only; see m12gen/diag_anchor.py) ----\n']
    for reg in POINTS:
        out.append('    Register<t_d_pair_t, bit<8>>(%d) %s;\n' % (RING, reg))
    # One RegisterAction per register, two PHV inputs (the lane tag and md.now): a second action on the same register
    # with another tag field made three inputs (m12p_c52d attempt 1: "d_p1 requires more than 2 PHV inputs").
    # One tag field for both lanes (m12p_c52d2: a second 32-bit tag alive to the last stage left T's clock chain
    # unallocated in PHV). The OPERATE lane carries bit 30 in P5/P6.
    for reg in POINTS:
        out.append(record_action(reg, reg + '_rec', 'md.d_tag'))
    out.append('''    action d_tag_admit() {
        md.d_tag = 2w0 ++ md.packet_epoch[13:0] ++ md.new_gen[15:0];
        md.d_idx = md.new_gen[7:0];
    }
    // An OPERATE admission records only P5 (OPERATE lane, bit 30); the READ-lane generation it also opens shows as
    // a P1 gap, which the readback reports instead of a record.
    action d_tag_admit_op() {
        md.d_tag = 2w1 ++ md.packet_epoch[13:0] ++ md.op_gen[15:0];
        md.d_idx = md.op_gen[7:0];
    }
    action d_tag_held() {
        md.d_tag = 2w0 ++ hdr.ladder.budget[13:0] ++ hdr.ladder.generation;
        md.d_idx = hdr.ladder.generation[7:0];
    }
    action d_tag_hb() {
        md.d_tag = 2w1 ++ hdr.ladder.budget[13:0] ++ hdr.ladder.generation;
        md.d_idx = hdr.ladder.generation[7:0];
    }
    action d_p1_req() { d_p1_rec.execute(md.d_idx); }
    table d_rec_p1 {
        key = { ig_intr_md.ingress_port : exact; md.event_kind : ternary; md.enabled : ternary; md.e_bad : ternary;
                md.new_gen : ternary; }
        actions = { d_p1_req; NoAction; }
        const entries = {
            (t_T_IN, t_KIND_REQUEST, 0, _, _) : NoAction();
            (t_T_IN, t_KIND_REQUEST, _, 0, 32w0xffff) : NoAction();
            (t_T_IN, t_KIND_REQUEST, _, 0, _) : d_p1_req();
        }
        default_action = NoAction(); size = 3;
    }
    action d_p2_commit() { d_p2_rec.execute(md.d_idx); }
    table d_rec_p2 {   // the commit_at_access rows, applied in the held branch while the ladder is valid
        key = { hdr.ladder.role : ternary; md.done_diff : ternary; md.commit_ok : ternary; }
        actions = { d_p2_commit; NoAction; }
        const entries = {
            (t_ROLE_ACK_HELD, 0, _) : NoAction();
            (t_ROLE_ACK_HELD, _, 1) : d_p2_commit();
        }
        default_action = NoAction(); size = 2;
    }
    // A fallback release carries bit 30 in its tag, set after the verdict from the outcome alone (constant OR).
    action d_mark_fallback() { md.d_tag = md.d_tag | 32w0x40000000; }
    table d_flag {
        key = { md.outcome_code : exact; }
        actions = { d_mark_fallback; NoAction; }
        const entries = { 8 : d_mark_fallback(); 9 : d_mark_fallback(); }
        default_action = NoAction(); size = 2;
    }
    action d_p3_commit() { d_p3_rec.execute(md.d_idx); }
    action d_p3_fallback() { d_p3_rec.execute(md.d_idx); }
    table d_rec_p3 {
        key = { md.outcome_code : exact; }
        actions = { d_p3_commit; d_p3_fallback; NoAction; }
        const entries = { 2 : d_p3_commit(); 8 : d_p3_fallback(); }
        default_action = NoAction(); size = 2;
    }
    action d_p4_release() { d_p4_rec.execute(md.d_idx); }
    action d_p4_fallback() { d_p4_rec.execute(md.d_idx); }
    table d_rec_p4 {
        key = { md.outcome_code : exact; }
        actions = { d_p4_release; d_p4_fallback; NoAction; }
        const entries = { 3 : d_p4_release(); 9 : d_p4_fallback(); }
        default_action = NoAction(); size = 2;
    }
    action d_p5_arm() { d_p5_rec.execute(md.d_idx); }
    table d_rec_p5 {
        key = { ig_intr_md.ingress_port : exact; md.event_kind : ternary; md.enabled : ternary; md.e_bad : ternary;
                md.op_gen : ternary; }
        actions = { d_p5_arm; NoAction; }
        const entries = {
            (t_T_IN, t_KIND_OPERATE, 0, _, _) : NoAction();
            (t_T_IN, t_KIND_OPERATE, _, 0, 32w0xffff) : NoAction();
            (t_T_IN, t_KIND_OPERATE, _, 0, 32w0 &&& 32w0xffff0000) : d_p5_arm();   // op_t0_arm: op_gen < 0xffff
        }
        default_action = NoAction(); size = 3;
    }
    action d_p6_release() { d_p6_rec.execute(md.d_idx); }
    table d_rec_p6 {
        key = { md.outcome_code : exact; }
        actions = { d_p6_release; NoAction; }
        const entries = { 5 : d_p6_release(); }
        default_action = NoAction(); size = 1;
    }
''')
    return ''.join(out)


def transform(src):
    src = once(src, 'struct t_metadata_t {',
               'struct t_d_pair_t { bit<32> lo; bit<32> hi; }   // d_: diagnostic anchor slot (time, tag)\n'
               'struct t_metadata_t {')
    src = once(src, '    bit<32> cur_gen; bit<32> new_gen; bit<32> t0_v;',
               '    bit<32> cur_gen; bit<32> new_gen; bit<32> t0_v;\n'
               '    bit<32> d_tag; bit<8> d_idx;')
    src = once(src, '    // ---- ladder dispatch: held originals release or rewait',
               declarations() + '    // ---- ladder dispatch: held originals release or rewait')
    src = once(src, '        } else if (ig_intr_md.ingress_port == t_T_IN) {\n',
               '        } else if (ig_intr_md.ingress_port == t_T_IN) {\n'
               '            if (md.event_kind == t_KIND_OPERATE) { d_tag_admit_op(); } else { d_tag_admit(); }\n')
    src = once(src, '            compute_da_delta(); compute_readiness_delta(); compute_pb_delta(); read_lgen_diff();\n',
               '            compute_da_delta(); compute_readiness_delta(); compute_pb_delta(); read_lgen_diff();\n'
               '            d_tag_held();\n')
    src = once(src, '            compute_op_t0_masked(); compute_op_delta(); op_lgen_diff();\n',
               '            compute_op_t0_masked(); compute_op_delta(); op_lgen_diff();\n            d_tag_hb();\n')
    src = once(src, '            commit_at_access.apply(); commit_generation_access.apply();\n',
               '            commit_at_access.apply(); commit_generation_access.apply();\n            d_rec_p2.apply();\n')
    src = once(src, '        outcome_count.apply();\n',
               '        outcome_count.apply();\n'
               '        // diagnostic anchors: record after the verdict (m12p_c52d)\n'
               '        d_rec_p1.apply(); d_rec_p5.apply();\n'
               '        d_flag.apply(); d_rec_p3.apply(); d_rec_p4.apply(); d_rec_p6.apply();\n')
    return src

#!/usr/bin/env python3
"""Generate read_queue_timing_diag.p4 from the production read_queue_timing.p4 by applying ONLY residency
instrumentation (plan step 3.1). It adds observability; it changes no forwarding, no timing, no verdict logic.

Why a generator instead of a hand-kept copy: the diff from production is a handful of exact edits, and this
script fails loudly if any production anchor moves, so the diagnostic build can never silently drift from the
build it instruments (sbo_admission_01 @ b8a35c6c6).

Three things become observable, all through the EXISTING single-call-site outcome mechanism (count() names an
outcome; outcome_count bumps the `outcomes` register once per pass) so no new register, no new table, and no
new per-pass register access is added:

  1. OUT_HELD_REWAIT (index 1) was shared by rewait_ack/rewait_response/rewait_operate. It now counts ACK
     held-original re-waits only; response re-waits go to index 14, OPERATE re-waits to index 15.
  2. keep_blocking (the blocker re-circulation action) counted nothing. It now names a per-role lap outcome:
     ACK-blocker lap -> 16, RESP-blocker lap -> 17, OPERATE-blocker lap -> 18.
  3. The `outcomes` register widens from bit<4> x16 to bit<5> x32 to hold indices 14..18. Register width is
     free on Tofino-1 (same stage, same SALU); indices 0..13 keep their meaning and their values.

  python3 make_diag_t.py [out.p4]     # default: read_queue_timing_diag.p4 beside this file
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = HERE / 'read_queue_timing.p4'

# Diagnostic outcome indices (role-split re-waits and per-role blocker laps). Index 1 (OUT_HELD_REWAIT) is
# kept for OPERATE re-wait: it is the one re-wait count a composite scenario asserts
# (model_drive_composite.py's T_released_the_OPERATE_once_after_holding reads OUT_HELD_REWAIT as the
# OPERATE-hold signal), so leaving OPERATE there keeps default 70/70 green at zero stage cost. ACK and RESP
# re-wait move to the free indices 14/15. Index -> role is also printed by snapshot_counters.py's DIAG map.
DIAG_ACK_REWAIT, DIAG_RESP_REWAIT = 14, 15
DIAG_ACK_LAP, DIAG_RESP_LAP, DIAG_OP_LAP = 16, 17, 18

EDITS = [
    # 1. widen the outcomes register and its bump path to a 32-entry, 5-bit-indexed bank
    ('Register<bit<32>, bit<4>>(16, 0) outcomes;',
     'Register<bit<32>, bit<5>>(32, 0) outcomes;   /* diag: 16->32 to hold indices 14..18 (width is free) */'),
    ('RegisterAction<bit<32>, bit<4>, bit<32>>(outcomes) bump_outcome',
     'RegisterAction<bit<32>, bit<5>, bit<32>>(outcomes) bump_outcome'),
    ('action bump(bit<4> idx) { bump_outcome.execute(idx); }',
     'action bump(bit<5> idx) { bump_outcome.execute(idx); }'),
    # outcome_count: add the five diagnostic indices; widen size to the register width
    ('            7 : bump(7); 8 : bump(8); 9 : bump(9); 10 : bump(10); 11 : bump(11); 12 : bump(12); 13 : bump(13);\n'
     '        }\n        default_action = NoAction(); size = 16;',
     '            7 : bump(7); 8 : bump(8); 9 : bump(9); 10 : bump(10); 11 : bump(11); 12 : bump(12); 13 : bump(13);\n'
     '            14 : bump(14); 15 : bump(15); 16 : bump(16); 17 : bump(17); 18 : bump(18);   /* diag */\n'
     '        }\n        default_action = NoAction(); size = 32;'),
    # 2. split the held-original re-wait counts. OPERATE (HB_RETURN qid 2) keeps OUT_HELD_REWAIT (index 1);
    #    ACK (HELD_RETURN qid 6) -> 14, RESP (HELD_RETURN qid 4) -> 15.
    ('ig_tm_md.ucast_egress_port = HELD_RETURN; ig_tm_md.qid = 6;\n        count(OUT_HELD_REWAIT);',
     'ig_tm_md.ucast_egress_port = HELD_RETURN; ig_tm_md.qid = 6;\n        count(%d);   /* diag: ACK re-wait */' % DIAG_ACK_REWAIT),
    ('ig_tm_md.ucast_egress_port = HELD_RETURN; ig_tm_md.qid = 4;\n        count(OUT_HELD_REWAIT);',
     'ig_tm_md.ucast_egress_port = HELD_RETURN; ig_tm_md.qid = 4;\n        count(%d);   /* diag: RESP re-wait */' % DIAG_RESP_REWAIT),
    # 3. count blocker laps per role: keep_blocking names an outcome (a metadata write; outcome_count already runs)
    ('action keep_blocking(PortId_t port, bit<5> qid) {\n'
     '        hdr.ladder.budget = hdr.ladder.budget - 1;\n'
     '        ig_tm_md.ucast_egress_port = port; ig_tm_md.qid = qid;\n    }',
     'action keep_blocking(PortId_t port, bit<5> qid, bit<8> lap_code) {\n'
     '        hdr.ladder.budget = hdr.ladder.budget - 1;\n'
     '        ig_tm_md.ucast_egress_port = port; ig_tm_md.qid = qid;\n'
     '        md.outcome_code = lap_code;   /* diag: per-role blocker lap */\n    }'),
    ('keep_blocking(HELD_RETURN, 7);', 'keep_blocking(HELD_RETURN, 7, %d);' % DIAG_ACK_LAP),
    ('keep_blocking(HELD_RETURN, 5);', 'keep_blocking(HELD_RETURN, 5, %d);' % DIAG_RESP_LAP),
    ('keep_blocking(HB_RETURN, 3);', 'keep_blocking(HB_RETURN, 3, %d);' % DIAG_OP_LAP),
    # record the mapping in the source as a comment, after the OUT_* constants
    ('const bit<8> OUT_NONE = 0xff;',
     'const bit<8> OUT_NONE = 0xff;\n'
     '// DIAGNOSTIC (make_diag_t.py): index 1 OPERATE re-wait (OUT_HELD_REWAIT, kept so the composite OPERATE\n'
     '// assertion stays green), 14 ACK re-wait, 15 RESP re-wait, 16 ACK-blocker lap, 17 RESP-blocker lap,\n'
     '// 18 OPERATE-blocker lap. Indices 0..13 unchanged.'),
]


def generate(src_text):
    out = src_text
    for old, new in EDITS:
        if out.count(old) != 1:
            raise SystemExit('make_diag_t.py: anchor not unique (%d) -- production P4 moved:\n  %r'
                             % (out.count(old), old[:70]))
        out = out.replace(old, new)
    banner = ('/* GENERATED by read/make_diag_t.py from read_queue_timing.p4 -- residency instrumentation only.\n'
              '   Do not edit by hand; edit make_diag_t.py. Not a production build. */\n')
    return banner + out


if __name__ == '__main__':
    dst = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / 'read_queue_timing_diag.p4'
    dst.write_text(generate(SRC.read_text()))
    print('wrote', dst)

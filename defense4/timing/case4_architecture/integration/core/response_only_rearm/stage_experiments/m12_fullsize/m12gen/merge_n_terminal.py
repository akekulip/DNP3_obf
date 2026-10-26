"""c71 trial (N experiment): consolidate N's terminal construction for work phases 1 and 2.

In c69 the phase-1/2 branch applies next_stage_t and then, by epoch, kind and ownership, abort_t or carry_t. The
compiler orders abort_t after next_stage_t (OUTPUT and ANTI_ACTION_READ edges on hdr.event.event), which places
abort_t in N's last stage beside first_event. Here next_stage() is folded into abort_work() (as one whole-field event write) and carry_current(),
whose fields are disjoint from it, and exactly one of the three keyless tables applies on each path: the decisions,
table names, snapshots, generation ownership, retries and FIN/RST paths are unchanged, and no field, key or table is
added. first_event's placement is bound separately (snapshot_t and close_phase_t edges) and is not changed here.
Only N changes.

Result (2026-10-26): does not compile — three PHV-allocation failures slicing hdr.event.event (two slice writes
in one stage); c71 is not retained (m12p_c71_sdk9132/compile_attempt_0{1,2,3}).
"""
from .common import combined, once

BRANCH = ('     next_stage_t.apply();\n'
          '     if(m.epoch_diff!=32w0){abort_t.apply();}\n'
          '     else if(m.kind==8w8||m.kind==8w25||m.kind==8w24||m.kind==8w10||m.kind==8w12||'
          '(m.kind==8w17&&(bit<8>)m.stage==8w2)){if(m.owner_diff!=32w0){abort_t.apply();}}\n'
          '     else{if((bit<8>)m.owner_op==8w1&&m.owner_diff==32w0){carry_t.apply();}else{abort_t.apply();}}\n')
MERGED = ('     if(m.epoch_diff!=32w0){abort_t.apply();}\n'
          '     else if(m.kind==8w8||m.kind==8w25||m.kind==8w24||m.kind==8w10||m.kind==8w12||'
          '(m.kind==8w17&&(bit<8>)m.stage==8w2)){if(m.owner_diff!=32w0){abort_t.apply();}else{next_stage_t.apply();}}\n'
          '     else{if((bit<8>)m.owner_op==8w1&&m.owner_diff==32w0){carry_t.apply();}else{abort_t.apply();}}\n')
NEXT_STAGE = (' action next_stage(){hdr.event.event[15:8]=hdr.event.event[15:8]+8w1;m.emit_loop=(bit<1>)(8w1);'
              'tm.ucast_egress_port=n_RETURN_PORT;tm.bypass_egress=1w1;}\n')
CARRY = ' action carry_current(){hdr.expected_cell.expected_cell=m.desired;}\n'
ABORT = ' action abort_work(){hdr.event.event[7:0]=8w255;hdr.t0.setInvalid();}\n'


def transform(src):
    old = combined.segment(src, 'N')
    n = old
    for name in ('next_stage_t.apply()', 'abort_t.apply()', 'carry_t.apply()'):
        if n.count(name) != BRANCH.count(name):
            raise ValueError('merge_n_terminal: %s is applied outside the phase-1/2 branch' % name)
    n = once(n, BRANCH, MERGED)
    n = once(n, NEXT_STAGE + ' table next_stage_t', NEXT_STAGE + ' table next_stage_t')     # anchor check only
    n = once(n, CARRY, ' action carry_current(){next_stage();hdr.expected_cell.expected_cell=m.desired;}\n')
    # One whole-field write: event[15:8]+1 and event[7:0]=255 as two slice writes in one action leave hdr.event.event
    # unsliceable for PHV allocation (first c71 compile, compile_attempt_01); the value written is the same.
    n = once(n, ABORT, ' action abort_work(){hdr.event.event=(hdr.event.event[15:8]+8w1)++8w255;'
                       'm.emit_loop=(bit<1>)(8w1);tm.ucast_egress_port=n_RETURN_PORT;tm.bypass_egress=1w1;'
                       'hdr.t0.setInvalid();}\n')
    # The merged abort writes event[15:8] (+1) and event[7:0] (=255) in one action; c69 wrote them in different stages.
    # Split the field into two 8-bit containers (second c71 compile, compile_attempt_02: still unsliceable).
    n = once(n, '@pa_solitary("ingress", "m.expected_work_phase")\n',
             '@pa_solitary("ingress", "m.expected_work_phase")\n@pa_container_size("ingress", "hdr.event.event", 8, 8)\n')
    return once(src, old, n)

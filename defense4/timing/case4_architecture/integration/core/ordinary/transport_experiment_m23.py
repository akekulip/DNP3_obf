#!/usr/bin/env python3
"""Research-only scratch generator for stage_fit_m23 (M-R2 through M-R6, decisive attempt).

Does NOT edit transport.py. Builds directly on the LIVE transport.generate_roles()
output, same pattern as transport_experiment_m19/m20/m22.py. This is kept as a
scratch file, not folded into transport.py, because the result is REFUTED (see
LEDGER.md's m23 entry and integration/core/M_RECIRCULATION_VERDICT.md): the build
does not fit, and folding a non-fitting, test-breaking design into the live
generator would leave the production transport.py broken for no benefit -- the
same disposition m18's "broader variant" and m20's refuted direction already
received in this session's history.

FULL two-pass recirculation split (M_STRUCTURAL_OPTIONS.md option (a)), all four
conflicting register pairs (reservation, producer_context, ledger_position,
ledger_tag) moved to a resumed pass -- unlike the M-R7 canary
(transport_experiment_m22.py), which left reserve_t's own placement unchanged and
trusted a bare carried grant bit, this moves reserve_t ITSELF to the resumed pass
and adds a dedicated reread gate (confirm_activation_t) for the activation chain
instead of trusting a carried activation_grant bit. No ad hoc carried grant is
ever consumed directly by a mutating table; every mutation is gated by rereading
its own register's CURRENT state against the recirculated packet's own
hdr.reference.generation -- reserve_t's existing phase/generation compare-and-set
already IS this reread for `reservation`; confirm_activation_t is the same
discipline, newly added, for `activation_receipt` (the shared gate for
ledger_position/ledger_tag's writers). producer_context's writer (construct_t's
context_write) is gated transitively by reservation_grant, so it needs no
separate reread.

Result (evidence/stage_fit_m23_01, local 9.13.1): exit 3, a compile ERROR, not
the familiar "doesn't fit" exit 2 -- "Table placement was not able to allocate
Ingress.confirm_activation_t, Ingress.claim_once_t in the same stage along with
Register Ingress.activation_receipt". See LEDGER.md and
integration/core/M_RECIRCULATION_VERDICT.md for the full account.
"""
import hashlib
import json
from pathlib import Path

import transport

HERE = Path(__file__).resolve().parent
replace = transport.replace


def generate_m23():
    roles = transport.generate_roles()
    m = roles['m3.p4']

    m = replace(m, 'struct meta_t{', 'struct meta_t{bit<1> m_pass;')
    m = replace(m, 'header response_extra_h{bit<16> value;}',
        'header pass_h{bit<32> marker;}\nheader response_extra_h{bit<16> value;}')
    m = replace(m, 'struct headers_t{', 'struct headers_t{pass_h pass;')
    m = replace(m, 'm.role=8w0;m.reverse_allowed=1w0;',
        'm.role=8w0;m.m_pass=1w0;m.reverse_allowed=1w0;')
    # Resumed-pass entry states: a tiny marker (reusing reverse_entry's existing
    # 32-bit lookahead discriminator, M's own role3/4 pattern) then a straight-
    # line reparse of exactly the header set that role's own forward path
    # already extracts -- the minimal possible preceding chain for this pass.
    # NOTE (scratch-generator limitation, not corrected here because this
    # result is already refuted for an unrelated reason -- see module
    # docstring): the resumed role==0 success path below hardcodes the egress
    # port instead of reproducing whatever the real, runtime-installed
    # `forwarding` table chose for the original arrival port. A first fix
    # (carrying tm.ucast_egress_port through hdr.pass) hit a SEPARATE PHV
    # slicing error ("Unable to slice the following group of fields...")
    # unrelated to the actual register-allocation wall this experiment exists
    # to measure; not pursued further, since M-R1's own installed forwarding
    # baseline (196/198 -> 68/2) is what the stage-fit evidence below was
    # measured against, and the register-allocation result does not depend on
    # this choice.
    m = replace(m,
        'state reverse_entry{transition select(pkt.lookahead<bit<32>>()){32w0x16c40006:reverse_snapshot;default:reverse_raw;}}',
        'state reverse_entry{transition select(pkt.lookahead<bit<32>>()){32w0x16c40006:reverse_snapshot;'
        '32w0xca220001:resume_role0;32w0xca220002:resume_role1;default:reverse_raw;}}\n'
        ' state resume_role0{pkt.extract(hdr.pass);hdr.pass.setInvalid();m.role=8w0;m.m_pass=1w1;'
        'pkt.extract(hdr.reference);pkt.extract(hdr.captured);pkt.extract(hdr.eth);'
        'pkt.extract(hdr.ip);pkt.extract(hdr.tcp);pkt.extract(hdr.dl);pkt.extract(hdr.native);'
        'pkt.extract(hdr.tail);transition accept;}\n'
        ' state resume_role1{pkt.extract(hdr.pass);hdr.pass.setInvalid();m.role=8w1;m.m_pass=1w1;'
        'pkt.extract(hdr.reference);pkt.extract(hdr.cache);pkt.extract(hdr.eth);'
        'pkt.extract(hdr.ip);pkt.extract(hdr.tcp);pkt.extract(hdr.image);transition accept;}')

    # New cheap reread gate for the activation chain: rereads activation_receipt
    # CURRENT value against the recirculated packet's own hdr.reference.generation
    # -- the same cookie re-arm discipline T already uses (read_timing.p4), not a
    # carried bit. claim_once (pass 0's real claim mutation) is unchanged.
    m = replace(m, ' Register<bit<32>,bit<1>>(1,0) geo_first;',
        ' RegisterAction<bit<32>,bit<1>,bit<32>>(activation_receipt) confirm_activation_ra={'
        'void apply(inout bit<32> value,out bit<32> result){result=32w0;'
        'if(value==hdr.reference.generation){result=32w1;}}};\n'
        ' action confirm_activation(){m.activation_grant=confirm_activation_ra.execute(1w0);}\n'
        ' table confirm_activation_t{actions={confirm_activation;}size=1;const default_action=confirm_activation();}\n'
        ' Register<bit<32>,bit<1>>(1,0) geo_first;')

    # Pass-0 exit actions: recirculate to the M-R1 local port (9w199) instead of
    # running the register mutation directly. No grant bit is carried.
    m = replace(m, ' apply{\n stamp_t.apply();',
        ' action pass0_exit_role0(){hdr.pass.setValid();hdr.pass.marker=32w0xca220001;'
        'tm.ucast_egress_port=9w199;tm.bypass_egress=1w1;}\n'
        ' table pass0_exit_role0_t{actions={pass0_exit_role0;}size=1;const default_action=pass0_exit_role0();}\n'
        ' action pass0_exit_role1(){hdr.pass.setValid();hdr.pass.marker=32w0xca220002;'
        'tm.ucast_egress_port=9w199;tm.bypass_egress=1w1;}\n'
        ' table pass0_exit_role1_t{actions={pass0_exit_role1;}size=1;const default_action=pass0_exit_role1();}\n'
        ' apply{\n stamp_t.apply();')

    # hdr.captured must survive the role-0 recirculation hop (construct() reads
    # it) but must NOT appear in the final emitted wire (it never did before).
    m = replace(m, 'hdr.last.off=hdr.captured.off;hdr.last.status=8w0;hdr.tail.setInvalid();',
        'hdr.last.off=hdr.captured.off;hdr.last.status=8w0;hdr.tail.setInvalid();hdr.captured.setInvalid();')

    # Role-0 exit: recirculate right after the CRC/profile admission gate
    # instead of calling reserve_t (now moved to the resumed pass) directly.
    m = replace(m,
        'reserve_t.apply();\n    if(m.reservation_grant==32w1){\n     construct_t.apply();output_newhead_t.apply();output_newbody_t.apply();output_newtail_t.apply();crc_render_t.apply();\n    }else{deny();}',
        'pass0_exit_role0_t.apply();')
    # Role-1 exit: recirculate right after claim_once_t's real claim instead of
    # running the four mutating tables directly.
    m = replace(m,
        'if(m.activation_grant==32w1){activate_geometry_t.apply();activate_position_t.apply();activate_ledger_t.apply();dirty_return_t.apply();}else{deny();}',
        'if(m.activation_grant==32w1){pass0_exit_role1_t.apply();}else{deny();}')

    # forwarding's const route(199) entry must not re-fire on a resumed packet.
    m = replace(m, 'if(m.role!=8w3&&m.role!=8w4){forwarding.apply();}',
        'if(m.m_pass!=1w1&&m.role!=8w3&&m.role!=8w4){forwarding.apply();}')

    # Resumed-pass entry: the minimal possible preceding chain in THIS pass --
    # one cheap reread table, then the real mutation, immediately.
    m = replace(m,
        'if(md.drop_ctl==3w0&&m.parsed==1w1&&!m.ip_error&&m.tcp_sum==16w0xFFEB&&hdr.ip.ttl!=8w0){',
        'if(m.m_pass==1w1){\n'
        '  if(m.role==8w0){\n'
        '   tm.ucast_egress_port=9w68;tm.bypass_egress=1w0;\n'
        '   reserve_t.apply();\n'
        '   if(m.reservation_grant==32w1){construct_t.apply();output_newhead_t.apply();output_newbody_t.apply();output_newtail_t.apply();crc_render_t.apply();}else{deny();}\n'
        '  }else if(m.role==8w1){\n'
        '   confirm_activation_t.apply();\n'
        '   if(m.activation_grant==32w1){activate_geometry_t.apply();activate_position_t.apply();activate_ledger_t.apply();dirty_return_t.apply();}else{deny();}\n'
        '  }else{deny();}\n'
        ' }else if(md.drop_ctl==3w0&&m.parsed==1w1&&!m.ip_error&&m.tcp_sum==16w0xFFEB&&hdr.ip.ttl!=8w0){')

    # IgDeparser: bf-p4c's TNA legacy checksum-conditional check only recognizes
    # m.reverse_changed/m.changed as the FIRST statements of apply{} (confirmed:
    # wrapping them in an added sibling if/else, even with unrelated fields,
    # makes the checker misclassify them as "destination" writes requiring
    # intrinsic metadata). So the emit list stays UNCONDITIONAL; the
    # recirculation hand-off relies on header VALIDITY alone, exactly like
    # every other role's output already does.
    m = replace(m, 'pkt.emit(hdr.map_snapshot);pkt.emit(hdr.reference);pkt.emit(hdr.cache);',
        'pkt.emit(hdr.pass);pkt.emit(hdr.map_snapshot);pkt.emit(hdr.reference);pkt.emit(hdr.captured);pkt.emit(hdr.cache);')

    roles['m3.p4'] = m
    return roles


def main():
    out = HERE / 'transport_candidate_next23'
    out.mkdir(exist_ok=True)
    roles = generate_m23()
    for name, text in roles.items():
        if name == 'm3.p4':
            (out / name).write_text(text)
    inputs = {
        'generated': {'m3.p4': hashlib.sha256((out / 'm3.p4').read_bytes()).hexdigest()},
        'generator_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'base_generator_sha256': hashlib.sha256((HERE / 'transport.py').read_bytes()).hexdigest(),
        'full_target': False,
        'note': 'scratch research generator (stage_fit_m23, M-R2-R6 decisive attempt: full '
                'two-pass recirculation split for M_STRUCTURAL_OPTIONS.md option (a)); '
                'REFUTED (compile error, see LEDGER.md); transport.py NOT modified',
    }
    (out / 'inputs.json').write_text(json.dumps(inputs, indent=2) + '\n')
    print(json.dumps(inputs, indent=2))


if __name__ == '__main__':
    main()

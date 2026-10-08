#!/usr/bin/env python3
"""Research-only scratch generator for stage_fit_m22 (M-R7 canary).

Does NOT edit transport.py. Builds directly on the LIVE transport.generate_roles()
output (i.e. the exact apply{} block M_STRUCTURAL_OPTIONS.md section 1 quotes, now
carrying the M-R1 forwarding fix for local port 199/pipe1-local71).

Implements the MINIMAL two-pass skeleton for M_STRUCTURAL_OPTIONS.md option (a):
split role 0's reserve_t from construct_t+output-CRC chain, and role 1's
claim_once_t from activate_geometry_t/activate_position_t/activate_ledger_t/
dirty_return_t, round-tripping both through M-R1's new recirculation port (9w199)
via a new pass_h{marker;carry} header. This is a resource/placement canary only:
the carried `carry` field is trusted directly as the resumed reservation_grant /
activation_grant with NO reread-before-trust discipline (that is M-R2/M-R4/M-R6's
job, explicitly out of scope here per the task's own instruction).

Mechanism:
- New header pass_h{bit<32> marker;bit<32> carry;}, new meta field m.m_pass.
- Role 0's reserve_t success branch now calls pass0_exit_role0_t (recirculates to
  9w199 carrying reservation_grant) instead of construct_t+output_new*+crc_render.
- Role 1's claim_once_t success branch now calls pass0_exit_role1_t (recirculates
  to 9w199 carrying activation_grant) instead of activate_geometry_t/
  activate_position_t/activate_ledger_t/dirty_return_t.
- The parser's existing reverse_entry state (9w199) already discriminates by a
  32-bit magic lookahead (role 3/4 mapping-snapshot traffic vs raw reverse ACK);
  two new magic values are added there for pass-0-exit traffic, routing to new
  resume_role0/resume_role1 states that set m.role back to 0/1, m.m_pass=1, and
  the resumed grant metadata, then accept with NO further header extraction --
  the minimal possible preceding chain in the ingress pass that runs
  construct_t/activate_* (apply{}'s very first branch after forwarding).
- apply{}'s top level becomes `if(m.m_pass==1w1){<construct_t|activate_* early>}
  else if(<original outer gate>){<original body, with the two exit points
  replaced>}` -- role 3/4's mapping chain and its own register reads are
  completely untouched, matching M_STRUCTURAL_OPTIONS.md section 2(a) point 3.
"""
import hashlib
import json
from pathlib import Path

import transport

HERE = Path(__file__).resolve().parent
replace = transport.replace


def generate_m22():
    roles = transport.generate_roles()
    m = roles['m3.p4']

    # 1) Role-0 pass-0 exit: replace the construct_t+output-CRC chain with a
    #    recirculation to 9w199 carrying reservation_grant. Do this BEFORE
    #    inserting the pass-1 resume branch below, which re-introduces an
    #    identical call sequence (textually) inside the new early branch --
    #    replacing first keeps this substring unique (count=1).
    m = replace(m,
        'construct_t.apply();output_newhead_t.apply();output_newbody_t.apply();output_newtail_t.apply();crc_render_t.apply();',
        'pass0_exit_role0_t.apply();')

    # 2) Role-1 pass-0 exit: same, for the four activate_*/dirty_return_t calls.
    m = replace(m,
        'if(m.activation_grant==32w1){activate_geometry_t.apply();activate_position_t.apply();activate_ledger_t.apply();dirty_return_t.apply();}else{deny();}',
        'if(m.activation_grant==32w1){pass0_exit_role1_t.apply();}else{deny();}')

    # 3) New header pass_h (carries pass-0's grant result across recirculation).
    m = replace(m, 'header eth_h {bit<48> dst;bit<48> src;bit<16> type;}',
        'header pass_h{bit<32> marker;bit<32> carry;}\n'
        'header eth_h {bit<48> dst;bit<48> src;bit<16> type;}')

    # 4) headers_t gets a pass_h member.
    m = replace(m, 'struct headers_t{', 'struct headers_t{pass_h pass;')

    # 5) meta_t gets the pass-boundary marker.
    m = replace(m, 'struct meta_t{', 'struct meta_t{bit<1> m_pass;')

    # 6) Parser start state initializes m_pass=0 for every freshly-parsed packet.
    m = replace(m, 'm.role=8w0;m.reverse_allowed=1w0;',
        'm.role=8w0;m.m_pass=1w0;m.reverse_allowed=1w0;')

    # 7) reverse_entry (9w199) gains two new magic-lookahead cases alongside the
    #    existing mapping-snapshot/raw-reverse discrimination; two new states
    #    resume the role-0/role-1 pass with the minimal possible preceding chain.
    m = replace(m,
        'state reverse_entry{transition select(pkt.lookahead<bit<32>>()){32w0x16c40006:reverse_snapshot;default:reverse_raw;}}',
        'state reverse_entry{transition select(pkt.lookahead<bit<32>>()){32w0x16c40006:reverse_snapshot;'
        '32w0xca220001:resume_role0;32w0xca220002:resume_role1;default:reverse_raw;}}\n'
        ' state resume_role0{pkt.extract(hdr.pass);m.role=8w0;m.m_pass=1w1;'
        'm.reservation_grant=hdr.pass.carry;transition accept;}\n'
        ' state resume_role1{pkt.extract(hdr.pass);m.role=8w1;m.m_pass=1w1;'
        'm.activation_grant=hdr.pass.carry;transition accept;}')

    # 8) New Ingress actions/tables for the pass-0 exit (recirculate to 9w199).
    m = replace(m, ' apply{\n stamp_t.apply();',
        ' action pass0_exit_role0(){hdr.pass.setValid();hdr.pass.marker=32w0xca220001;'
        'hdr.pass.carry=m.reservation_grant;tm.ucast_egress_port=9w199;tm.bypass_egress=1w1;}\n'
        ' table pass0_exit_role0_t{actions={pass0_exit_role0;}size=1;const default_action=pass0_exit_role0();}\n'
        ' action pass0_exit_role1(){hdr.pass.setValid();hdr.pass.marker=32w0xca220002;'
        'hdr.pass.carry=m.activation_grant;tm.ucast_egress_port=9w199;tm.bypass_egress=1w1;}\n'
        ' table pass0_exit_role1_t{actions={pass0_exit_role1;}size=1;const default_action=pass0_exit_role1();}\n'
        ' apply{\n stamp_t.apply();')

    # 9) apply{}'s top level: a resumed pass (m.m_pass==1) runs construct_t or
    #    activate_*/dirty_return_t immediately -- the minimal preceding chain
    #    this canary exists to test -- instead of the original outer gate.
    #    Role 3/4's mapping chain (inside the original body, unchanged below)
    #    is not touched.
    m = replace(m,
        'if(md.drop_ctl==3w0&&m.parsed==1w1&&!m.ip_error&&m.tcp_sum==16w0xFFEB&&hdr.ip.ttl!=8w0){',
        'if(m.m_pass==1w1){if(m.role==8w0){construct_t.apply();output_newhead_t.apply();'
        'output_newbody_t.apply();output_newtail_t.apply();crc_render_t.apply();}'
        'else if(m.role==8w1){activate_geometry_t.apply();activate_position_t.apply();'
        'activate_ledger_t.apply();dirty_return_t.apply();}'
        '}else if(md.drop_ctl==3w0&&m.parsed==1w1&&!m.ip_error&&m.tcp_sum==16w0xFFEB&&hdr.ip.ttl!=8w0){')

    roles['m3.p4'] = m
    return roles


def main():
    out = HERE / 'transport_candidate_next22'
    out.mkdir(exist_ok=True)
    roles = generate_m22()
    for name, text in roles.items():
        if name == 'm3.p4':
            (out / name).write_text(text)
    inputs = {
        'generated': {'m3.p4': hashlib.sha256((out / 'm3.p4').read_bytes()).hexdigest()},
        'generator_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'base_generator_sha256': hashlib.sha256((HERE / 'transport.py').read_bytes()).hexdigest(),
        'full_target': False,
        'note': 'scratch research generator (stage_fit_m22, M-R7 canary: two-pass '
                'recirculation skeleton for M_STRUCTURAL_OPTIONS.md option (a)); '
                'transport.py NOT modified',
    }
    (out / 'inputs.json').write_text(json.dumps(inputs, indent=2) + '\n')
    print(json.dumps(inputs, indent=2))


if __name__ == '__main__':
    main()

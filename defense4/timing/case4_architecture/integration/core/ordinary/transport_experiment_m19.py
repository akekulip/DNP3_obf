#!/usr/bin/env python3
"""Research-only scratch generator for stage_fit_m19 (role==0 chain experiment).

Does NOT edit transport.py. Imports its generate_roles() (= the real, current
m18 state) and applies two additional, independent restructurings to role==0's
native/DNP3 admission chain, per LEDGER.md's 2026-10-07 "stage_fit_m18" entry
asking whether that chain has the same kind of avoidable redundancy N's
stage_fit_analysis_01 found and fixed:

Fix A (false WAW removal): `profile_0` (role==0's own admission table, via
`eligible()`) is forced to sit AFTER `activation_identity_t_0`/
`activation_reservation_t_0` (role==1/2's tables) purely because `eligible()`
writes the SAME metadata field (`m.profile`) that role==1/2's `activate_allowed()`
also writes, and because m18's merge keyed `activation_reservation_t` on
`m.profile` (an IXBAR read of a field role==0 also writes). Since role==0 and
role==1/2 are mutually exclusive on `m.role`, role==0's own admission result
does not need to share that field at all. Giving role==0 its own field
(`m.profile0`) removes both the WAW (`activation_identity_t_0 -- OUTPUT -->
profile_0`) and the anti-dependency (`activation_reservation_t_0 --
ANTI_ACTION_READ --> profile_0`) confirmed in
`evidence/stage_fit_m18_01/out/pipe/logs/table_dependency_graph.log` lines
427-428. No check is weakened: role==0's gate (`m.enabled==1w1&&m.profile0==1w1`)
is identical in effect to the old `m.enabled==1w1&&m.profile==1w1`; only the
PHV container backing it changes.

Fix B (construct_t decoupling): `output_newhead_t`/`output_newbody_t`/
`output_newtail_t` currently re-read the headers `construct_t` just populated
(`hdr.appended.*`, `hdr.last.*`, the changed `hdr.dl.len`) purely to recompute a
hash over values that are, in every case but one, already available UNCHANGED
from parsing (`hdr.tail.*`, `hdr.captured.*`, or a literal). Hashing directly
from those source fields (and the one changed field, `hdr.dl.len: 75->44`, as
the compile-time literal `8w44` it is always set to) removes the
`construct_t_0 -- IXBAR_READ --> output_new*_t_0` edges entirely
(`table_dependency_graph.log` lines 442-456). The new-hash outputs are also
renamed (`m.new_hcrc`/`new_bcrc`/`new_tcrc`) instead of reusing `m.hcrc`/
`m.bcrc`/`m.tcrc` (the INCOMING-CRC variables `input_head_t`/`input_body_t`/
`input_tail_t` already use), removing the matching WAW against the badh/badb/
badt checks (`cond-40/41/42 -- ANTI_ACTION_READ --> output_new*_t_0`). This is a
value-preserving refactor (the three hashes are computed over exactly the same
bytes as before; only which already-available copy of each byte is read, and
which PHV field the RESULT lands in, changes) -- it does not touch
`construct_t`'s own header-field writes, the admission predicates, the
reservation register claim in `reserve_t`, or the final emitted frame.

Neither fix touches `claim_once_t`, `activate_geometry_t`/`activate_position_t`/
`activate_ledger_t`, `dirty_return_t`, `qualify_context_t`, or any
match-action table's key/entries/gating beyond the two renames above.
"""
import hashlib
import json
from pathlib import Path

import transport

HERE = Path(__file__).resolve().parent
replace = transport.replace


def generate_m19():
    roles = transport.generate_roles()
    m = roles['m3.p4']

    # --- Fix A: give role==0's own admission result its own PHV field. ---
    m = replace(m, 'struct meta_t{', 'struct meta_t{bit<1> profile0;')
    m = replace(m, 'm.profile=1w0;', 'm.profile=1w0;m.profile0=1w0;')
    m = replace(m, 'action eligible(){m.profile=1w1;}', 'action eligible(){m.profile0=1w1;}')
    m = replace(m, 'if(m.enabled==1w1&&m.profile==1w1){\n   input_head_t.apply();',
                   'if(m.enabled==1w1&&m.profile0==1w1){\n   input_head_t.apply();')

    # --- Fix B: compute the three outgoing CRCs from already-available source
    # fields (or the one literal construct_t always assigns) instead of
    # re-reading construct_t's output, and give the results their own fields. ---
    m = replace(m, 'struct meta_t{', 'struct meta_t{bit<16> new_hcrc;bit<16> new_bcrc;bit<16> new_tcrc;')
    m = replace(
        m,
        'action output_newhead(){m.hcrc=hash_newhead.get({hdr.dl.magic,hdr.dl.len,hdr.dl.ctrl,hdr.dl.dst,hdr.dl.src});}',
        'action output_newhead(){m.new_hcrc=hash_newhead.get({hdr.dl.magic,8w44,hdr.dl.ctrl,hdr.dl.dst,hdr.dl.src});}')
    m = replace(
        m,
        'action output_newbody(){m.bcrc=hash_newbody.get({hdr.appended.off,hdr.appended.status,hdr.appended.group,hdr.appended.variation,hdr.appended.qualifier,hdr.appended.count,hdr.appended.index,hdr.appended.code,hdr.appended.repeat,hdr.appended.on_first});}',
        'action output_newbody(){m.new_bcrc=hash_newbody.get({hdr.tail.off,hdr.tail.status,8w12,8w1,8w0x28,16w0x0100,hdr.captured.index,hdr.captured.code,hdr.captured.repeat,hdr.captured.on[31:16]});}')
    m = replace(
        m,
        'action output_newtail(){m.tcrc=hash_newtail.get({hdr.last.on_last,hdr.last.off,hdr.last.status});}',
        'action output_newtail(){m.new_tcrc=hash_newtail.get({hdr.captured.on[15:0],hdr.captured.off,8w0});}')
    m = replace(
        m,
        'action crc_render(){hdr.dl.crc=m.hcrc[7:0]++m.hcrc[15:8];hdr.appended.crc=m.bcrc[7:0]++m.bcrc[15:8];hdr.last.crc=m.tcrc[7:0]++m.tcrc[15:8];}',
        'action crc_render(){hdr.dl.crc=m.new_hcrc[7:0]++m.new_hcrc[15:8];hdr.appended.crc=m.new_bcrc[7:0]++m.new_bcrc[15:8];hdr.last.crc=m.new_tcrc[7:0]++m.new_tcrc[15:8];}')

    roles['m3.p4'] = m
    return roles


def main():
    out = HERE / 'transport_candidate_next19'
    out.mkdir(exist_ok=True)
    roles = generate_m19()
    for name, text in roles.items():
        if name == 'm3.p4':
            (out / name).write_text(text)
    inputs = {
        'generated': {'m3.p4': hashlib.sha256((out / 'm3.p4').read_bytes()).hexdigest()},
        'generator_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'base_generator_sha256': hashlib.sha256((HERE / 'transport.py').read_bytes()).hexdigest(),
        'full_target': False,
        'note': 'scratch research generator (stage_fit_m19); transport.py NOT modified',
    }
    (out / 'inputs.json').write_text(json.dumps(inputs, indent=2) + '\n')
    print(json.dumps(inputs, indent=2))


if __name__ == '__main__':
    main()

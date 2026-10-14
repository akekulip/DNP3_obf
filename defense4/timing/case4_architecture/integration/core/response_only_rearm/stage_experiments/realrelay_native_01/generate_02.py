"""full_02: generate.py (full_01) plus three review fixes. generate.py is not edited, so full_01 stays reproducible.

1. Pending-open abort (review HIGH). A clean SYN leaves N's owner at phase 2. If the relay answers with an
   option-bearing SYN-ACK, full_01 left the tuple at phase 2 for good. Now, at stage 0, option_native_t
   qualifies that SYN-ACK: owner phase 2, relay direction, flags exactly 0x12 (the value sequence_diff
   computes diff_synack for), client_diff 0 (it acknowledges the pending SYN). It is sent on one N lap as
   event 0x011a (stage 1, kind 26, unused). The lap carries the owner value N read at stage 0 as
   expected_cell and the N epoch as envelope epoch. On the lap, owner_command (new row, size 22 -> 23)
   requests the existing owner CAS to phase 0x0200 with the generation kept, so the outcome is the same as
   the relay refusing the SYN with RST. abort_open_t then forwards the frame to the master as provenance
   0xe8 (E: pass_native, bytes unchanged) only when the CAS matched and the epoch is unchanged; otherwise
   terminal_abort drops it. E is not armed: no 0xe7 SYN-ACK commit is ever emitted. The rearm frontier
   rules then apply to the next clean SYN from phase 0x0200.
2. Network checks restored (review MEDIUM). `foreign` no longer sets network_valid in the parser.
   It sets tcp_sum to 0 (the TCP checksum residual cannot be computed because the option bytes are not
   subtracted) and the `network` table gains rows (parsed 0, kind 0 | 26, flags any, ip_error false,
   tcp_sum 0, TTL 1..255, reserved 0, urgent 0), size 32 with 31 entries. A foreign segment with TTL 0
   or a bad IPv4 checksum gets no network_valid, so guard never runs and E drops it as before.
3. MSS+WS+SACK without TS: not made native (that needs per-incarnation state). The model driver shows
   that it fails closed without wedging the tuple.

  python3 generate_02.py OUT_DIR
"""
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('realrelay_native_v1', HERE / 'generate.py')
v1 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v1)

ABORT_KIND, ABORT_EVENT = 26, 0x011a

N2_EDITS = (
    # 2: the parser no longer grants network validity
    ('m.packet_kind=8w20;m.network_valid=(bit<1>)(8w1);transition accept;}',
     'm.packet_kind=8w20;m.tcp_sum=16w0;transition accept;}'),
    ('(1w1,8w12,8w16,false,16w0xffeb,8w1..8w255,4w0,16w0):network_accept();}}',
     '(1w1,8w12,8w16,false,16w0xffeb,8w1..8w255,4w0,16w0):network_accept();'
     '(1w0,8w0,_,false,16w0,8w1..8w255,4w0,16w0):network_accept();'
     '(1w0,8w26,_,false,16w0,8w1..8w255,4w0,16w0):network_accept();}}'),
    # 1: the abort lap parses through to the TCP header
    ('16w0x030c:origin;default:accept;}}', '16w0x030c:origin;16w0x011a:origin;default:accept;}}'),
    # 1: stage-0 qualification of the option-bearing SYN-ACK of a pending clean open
    ('table option_native_t{key={m.observed:ternary;}actions={native_pass;NoAction;}size=3;const entries={'
     '32w0x00000000&&&32w0xffff0000:native_pass();32w0x010f0000&&&32w0xffff0000:native_pass();'
     '32w0x02000000&&&32w0xffff0000:native_pass();}',
     ' action native_abort_open(){hdr.envelope.epoch=m.epoch;hdr.work_generation.generation=32w1;'
     'hdr.expected_cell.expected_cell=m.observed;hdr.event.event=16w0x011a;hdr.event.reserved=16w0;'
     'hdr.origin.setValid();hdr.origin.wire_ack=32w0;hdr.origin.normalized_epoch=32w0;m.emit_loop=(bit<1>)(8w1);'
     'tm.ucast_egress_port=n_RETURN_PORT;tm.bypass_egress=1w1;}\n'
     ' table option_native_t{key={m.observed:ternary;m.direction:ternary;hdr.tcp.flags:ternary;m.client_diff:ternary;}'
     'actions={native_pass;native_abort_open;NoAction;}size=4;const entries={'
     '(32w0x00000000&&&32w0xffff0000,_,_,_):native_pass();(32w0x010f0000&&&32w0xffff0000,_,_,_):native_pass();'
     '(32w0x02000000&&&32w0xffff0000,_,_,_):native_pass();'
     '(32w0x00020000&&&32w0xffff0000,2w2,8w0x12,32w0):native_abort_open();}'),
    # 1: the lap goes (read-only path, like stage 0) ...
    ('go_native();(2w0,8w20,8w0,2w2,_,_,_,_,_,_,_,_,_):go_native();',
     'go_native();(2w0,8w20,8w0,2w2,_,_,_,_,_,_,_,_,_):go_native();(2w1,8w20,8w26,2w2,_,_,_,_,_,_,_,_,_):go_native();'),
    # ... requests the owner CAS phase 2 -> 0x0200 (generation kept) ...
    ('action publish_response_op(){',
     'action abort_open(){m.expected=hdr.expected_cell.expected_cell;m.desired=16w0x0200++hdr.expected_cell.expected_cell[15:0];'
     'm.owner_op=(bit<1>)(8w1);}\naction publish_response_op(){'),
    ('publish_response_op;NoAction;}size=22;', 'publish_response_op;abort_open;NoAction;}size=23;'),
    ('(2w3,8w255,32w3,32w0,1w1):quarantine_abort();}}',
     '(2w3,8w255,32w3,32w0,1w1):quarantine_abort();(2w1,8w26,_,32w0,_):abort_open();}}'),
    # ... and leaves native only if that CAS matched in the same epoch
    ('const entries={(1w1,32w0,32w0):emit_reset();}const default_action=terminal_abort();}',
     'const entries={(1w1,32w0,32w0):emit_reset();}const default_action=terminal_abort();}\n'
     'action native_after_abort(){hdr.origin.setInvalid();hdr.event.event=16w0xe800;tm.ucast_egress_port=m.output_port;'
     'tm.bypass_egress=1w0;m.emit_loop=(bit<1>)(8w0);}\n'
     'table abort_open_t{key={m.owner_op:exact;m.owner_diff:exact;m.epoch_diff:exact;}'
     'actions={native_after_abort;terminal_abort;}size=1;const entries={(1w1,32w0,32w0):native_after_abort();}'
     'const default_action=terminal_abort();}'),
    ('}else if(m.kind==8w4){reset_boundary.apply();}',
     '}else if(m.kind==8w4){reset_boundary.apply();}else if(m.kind==8w26){abort_open_t.apply();}'),
)


NO_ORIGIN = (
    ('16w0x030c:origin;16w0x011a:origin;default:accept;}}', '16w0x030c:origin;16w0x011a:eth;default:accept;}}'),
    ('hdr.origin.setValid();hdr.origin.wire_ack=32w0;hdr.origin.normalized_epoch=32w0;m.emit_loop=(bit<1>)(8w1);'
     'tm.ucast_egress_port=n_RETURN_PORT;tm.bypass_egress=1w1;}',
     'm.emit_loop=(bit<1>)(8w1);tm.ucast_egress_port=n_RETURN_PORT;tm.bypass_egress=1w1;}'),
    ('action native_after_abort(){hdr.origin.setInvalid();hdr.event.event=16w0xe800;',
     'action native_after_abort(){hdr.event.event=16w0xe800;'),
)


def edits(variant):
    if variant == 'network-only':
        return N2_EDITS[:2]
    out = list(N2_EDITS)
    if variant == 'no-origin':
        for old, new in NO_ORIGIN:
            out = [(o, n.replace(old, new) if old in n else n) for o, n in out]
            assert any(new in n for _, n in out), old[:60]
    return out


def full_source(variant='full'):
    base = v1.frozen()
    text, (old_n, old_e, old_t) = v1.full_source()
    n1, e1 = (v1.combined.segment(text, name) for name in ('N', 'E'))
    v1.fresh(n1, ('0x011a', '8w26,_', '(2w1,8w20,8w26', 'abort_open', 'native_abort_open', 'native_after_abort',
                  '(1w0,8w0,', '(1w0,8w26,', 'tcp_sum=16w0'))
    n2 = n1
    for old, new in edits(variant):
        n2 = v1.once(n2, old, new)
    source = text.replace(n1, n2, 1)
    assert v1.combined.segment(source, 'T') == old_t, 'T must be byte-identical to the input'
    assert v1.combined.segment(source, 'E') == e1, 'E must be byte-identical to full_01'
    assert source.replace(n2, old_n, 1).replace(e1, old_e, 1) == base, 'only N and E may differ from the input'
    return source, (old_n, old_e, old_t), text


def write(directory, variant='full'):
    directory = Path(directory)
    text, old, v1_text = full_source(variant)
    directory.mkdir(parents=True, exist_ok=False)
    (directory / 'response_only.p4').write_text(text)
    metadata = json.loads(v1.SOURCE.with_suffix('.inputs.json').read_text())
    metadata.update(experiment='realrelay_native_01/full_02', generate_02_variant=variant, source_sha256=hashlib.sha256(text.encode()).hexdigest(),
                    dup_hold_source={'path': str(v1.SOURCE), 'sha256': v1.SOURCE_SHA256},
                    full_01_source_sha256=hashlib.sha256(v1_text.encode()).hexdigest(),
                    generator_sha256={'generate.py': hashlib.sha256((HERE / 'generate.py').read_bytes()).hexdigest(),
                                      'generate_02.py': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()},
                    native_profile={'n_foreign_packet_kind': v1.FOREIGN_KIND, 'n_native_event': '0x%04x' % v1.NATIVE_EVENT,
                                    'e_native_prov_kind': '0x%02x' % (v1.NATIVE_EVENT >> 8),
                                    'e_outcome_native_pass': v1.E_NATIVE_PASS,
                                    'native_owner_phases': ['0x%04x' % p for p in v1.NATIVE_PHASES],
                                    'pending_open_abort': {'from_phase': '0x0002', 'to_phase': '0x0200',
                                                           'lap_event': '0x%04x' % ABORT_EVENT, 'lap_kind': ABORT_KIND},
                                    'fin_psh_ack_0x19': 'admitted as FIN|ACK (flags 8w17 masked 8w0xf7)'},
                    segment_sha256={name: hashlib.sha256(v1.combined.segment(text, name).encode()).hexdigest()
                                    for name in ('N', 'E', 'T')},
                    input_segment_sha256={name: hashlib.sha256(seg.encode()).hexdigest()
                                          for name, seg in zip(('N', 'E', 'T'), old)})
    (directory / 'response_only.inputs.json').write_text(json.dumps(metadata, indent=2) + '\n')


if __name__ == '__main__':
    write(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else 'full')

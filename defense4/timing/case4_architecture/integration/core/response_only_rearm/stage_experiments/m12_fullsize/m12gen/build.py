"""Compose the transforms for one build and write its source, inputs record and supported profile."""
import hashlib
import json

from . import mapper, read_policy, segmented, two_read
from .common import (CONSTANTS, CONSTANTS_TWO, HERE, M11_09, M11_09_PROFILE, M11_09_SHA, combined)

TRANSFORM = {
    'read_prefix_p1': lambda src: read_policy.transform_read_prefix_p1(src, read_policy.policy_shape()),
    'read_prepadded_e': lambda src: read_policy.transform_read_prepadded_e(src, read_policy.policy_shape()),
    'read_passthrough_n': read_policy.transform_read_passthrough_n,
    'two_read_pad_pipe1': two_read.transform_two_read_pad_pipe1,
    'two_read_e': two_read.transform_two_read_e,
    'two_read_admit_n': two_read.transform_two_read_admit_n,
    'two_read_reduce': two_read.transform_two_read_reduce,
    'n_busy_ack_retry': two_read.transform_n_busy_ack_retry,
    'segmented_pad_pipe1': lambda src: segmented.transform_segmented_pad_pipe1(src, segmented.segmented_shape()),
    'segmented_classifier': segmented.transform_segmented_classifier,
    'segmented_t': segmented.transform_segmented_t,
    'n_read_completes_handshake': two_read.transform_n_read_completes_handshake,
}


def generator_files():
    """Every file the generator's output depends on, by path relative to m12_fullsize, with its sha256."""
    files = [HERE / 'make_m12.py'] + sorted((HERE / 'm12gen').glob('*.py'))
    return {str(p.relative_to(HERE)): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}


def build(only=None, c3='ladder', shapes='none', segmented_pad=False, segmented_full=False, two_read_build=False,
          reduce=False, ack_retry=False, read_handshake=False):
    src = M11_09.read_text()
    if hashlib.sha256(src.encode()).hexdigest() != M11_09_SHA:
        raise SystemExit('m11_09 source changed')
    if two_read_build:
        # two-READ-target profile (attempts m12p_c21+; first placing build m12p_c23): mixed READ 91 -> 141 and base
        # full (integrity/class0) READ 247 -> 271 REPLACE the range READ transformation; SBO 37 -> 61 unchanged.
        # m12p_c22 stacked an extra N mixed-admission transform on read_passthrough_n and needed a 13th pipe-0 stage;
        # this build replaces the analog/class0 admission by the mixed one (transform_two_read_admit_n).
        cm, cf = two_read.two_read_shapes()
        transforms = ['mapper_var', 'two_read_pad_pipe1', 'two_read_e', 'two_read_admit_n']
        if reduce:   # m12p_c26: behavior-preserving resource reduction (transform_two_read_reduce)
            transforms.append('two_read_reduce')
        if ack_retry:   # m12p_c27: F1, busy pure ACKs retried (transform_n_busy_ack_retry)
            transforms.append('n_busy_ack_retry')
        if read_handshake:   # m12p_c28: a READ that overtakes the final ACK completes the handshake
            transforms.append('n_read_completes_handshake')
        shape_image = {'read': cm['target'], 'ctl': 61}
        per_image = {cm['native_total']: cm['target'], cf['native_total']: cf['target'], 37: 61, 61: 61}
    else:
        # the frozen read_complete_01 policy (range READ 49 -> 141 from derived constants) + SBO 61
        c = read_policy.policy_shape()
        transforms = ['mapper_var', 'read_prefix_p1', 'read_prepadded_e']
        if shapes == 'passthrough':
            transforms.append('read_passthrough_n')
        if segmented_pad:
            transforms.append('segmented_pad_pipe1')
        if segmented_full:
            transforms += ['segmented_pad_pipe1', 'segmented_classifier', 'segmented_t']
        shape_image = {'read': c['target'], 'ctl': 61}
        per_image = {c['native_total']: c['target'], 37: 61, 61: 61}   # 61: handshake virtual image
        if segmented_full:
            # the committed 401-octet segmented image needs its own reverse-ACK withhold window so the master's ACKs
            # are remapped across the +24 shift for the WHOLE 401 image. native 377 -> image 401; keyed in classify_rev
            # on native length mod 256 (377 & 0xFF = 121, distinct).
            per_image[segmented.segmented_shape()['native_total']] = segmented.segmented_shape()['target']
    applied = []
    for name in transforms:
        if name == 'mapper_var':
            src = mapper.transform_mapper_var(src, shape_image, per_image, c3_cimg=(c3 == 'cimg'))
        else:
            src = TRANSFORM[name](src)
        applied.append(name)
        if only and name == only:
            break
    return src, applied


def write_outputs(out, a, src, applied):
    """Write response_only.p4, response_only.inputs.json and supported_profile.json for one build.

    The candidate is runnable only when the mapper AND every size-path transform agree; a partial set (--only) is a
    placement experiment and is flagged non-runnable so nothing treats it as integrated."""
    (out / 'response_only.p4').write_text(src)
    sha = hashlib.sha256(src.encode()).hexdigest()
    if a.two_read:
        cm, cf = two_read.two_read_shapes()
        c = cm
        required = {'mapper_var', 'two_read_pad_pipe1', 'two_read_e', 'two_read_admit_n'}
        if a.reduce:
            required.add('two_read_reduce')
        if getattr(a, 'ack_retry', False):
            required.add('n_busy_ack_retry')
        if getattr(a, 'read_handshake', False):
            required.add('n_read_completes_handshake')
        read_native, read_out = cm['native_total'], cm['target']
        scope = ('two-READ-target profile (Claude_Two_READ_Targets_Hardware_Directive.md): mixed READ (one request, '
                 'g1v2 q00 0-15 + g30v1 q00 0-7) %d->%d as [%s] with %d G1V2 points %d..%d, and the base-database full '
                 'READ (integrity poll) %d->%d as [%s] with %d points %d..%d, both by the pipe-1 prefix construction; '
                 'SELECT/OPERATE 37->61 unchanged. By declaration: the range READ keeps m11_09 admission and timing '
                 'and passes at native 49 (not padded); analog and class0 READ requests are NOT admitted by N (their '
                 'admission was replaced by the mixed one, m12p_c23): on an admitted connection N withholds them, '
                 'also when retransmitted, forwarding nothing either way and leaving the connection state unchanged '
                 '(measured on the model, two_read_robust X), so a master that issues one stalls until its '
                 'application times out; the native two-segment 377 response is out of scope. '
                 'READ responses are admitted by N first block only (link and block-0 CRCs checked; TCP checksum '
                 'WAIVED -- m.tcp_sum written 0xffeb -- not computed)'
                 % (cm['native_total'], cm['target'], ', '.join(map(str, cm['frames_out'])), cm['padding_points'],
                    cm['padding_indices'][0], cm['padding_indices'][1], cf['native_total'], cf['target'],
                    ', '.join(map(str, cf['frames_out'])), cf['padding_points'], cf['padding_indices'][0],
                    cf['padding_indices'][1]))
        if a.reduce:
            scope += ('; resource-reduced (m12p_c26): pipe-1 block-0 CRC by residue, outcome/IP-length/checksum conditions '
                      'set where decided, unreachable E read_b0 CRC compares removed -- behavior unchanged')
        if getattr(a, 'ack_retry', False):
            scope += ('; m12p_c27 (F1): a pure ACK (kind 3 master, kind 10 outstation) that finds the N work cell busy '
                      'is retried on the 32-lap budget instead of busy_pass (which E dropped); count_busy[6] counts retries')
        if getattr(a, 'read_handshake', False):
            scope += ('; m12p_c28: a READ request that overtakes the final handshake ACK (owner phase 4, sequence check '
                      'passing) is admitted as completing the handshake instead of refused; the late pure ACK is dropped')
    else:
        c = read_policy.policy_shape()
        required = {'mapper_var', 'read_prefix_p1', 'read_prepadded_e'}
        read_native, read_out = c['native_total'], c['target']
        scope = ('read_complete_01 policy hardware shape set, phase A: range READ 49->%d (prefix, G1V2 %d..%d '
                 'synthetic) + SELECT/OPERATE 37->61; analog/class0/integrity/segmented READ classes NOT yet in '
                 'this build' % (c['target'], c['reserved_first_index'], c['reserved_first_index'] + c['padding_points'] - 1))
        if a.shapes == 'passthrough':
            required.add('read_passthrough_n')
            scope = ('read_complete_01 policy hardware shape set, phase S1: range READ 49->%d (prefix) + SELECT/OPERATE '
                     '37->61 + pass-through READ classes at native size (analog 22->141, class0 18->247, integrity '
                     '27->247; one link frame each, first-block-only N admission, TCP checksum of the response waived '
                     'in N); segmented READ classes NOT yet in this build' % c['target'])
    runnable = required.issubset(set(applied))
    segs = {role: hashlib.sha256(combined.segment(src, role).encode()).hexdigest() for role in ('N', 'E', 'T')}
    # segmented_t adds the second response-child register (child_seen1_reg), so the sealed profile must declare two
    # T child banks for the segmented build; every other build keeps the single child_seen0_reg (t_child_count 1).
    t_child_count = 2 if 'segmented_t' in applied else 1
    profile = {'candidate': {'build': str(out), 'milestone': 'm12', 'source_sha256': sha, 'segment_sha256': segs,
                             'artifact_sha256': {}},
               'reset_restart_required': True, 't_child_count': t_child_count}
    # complete supported profile (candidate_campaign's control-timing contract): N/T values inherited unchanged from
    # m11_09; the READ image is stated separately from the control image
    m11 = json.loads(M11_09_PROFILE.read_text())
    profile.update({k: m11[k] for k in ('profile_version', 'clock', 'timing_ns', 'n', 'ports')})
    if not a.two_read:     # the two-READ build writes its own note below
        profile['_note'] = ('read_complete_01 policy build: N/T values unchanged from m11_09 (T segment and timing '
                            'parameters inherited); encoding differs: SELECT/OPERATE output 61 (output_octets), READ '
                            'output %d (read_output_octets, pipe-1 egress prefix, %d synthetic G1V2 points %d..%d). '
                            'Arbitrary input sizes are not supported.'
                            % (c['target'], c['padding_points'], c['reserved_first_index'],
                               c['reserved_first_index'] + c['padding_points'] - 1))
    profile['encoding'] = {
        'native_input_octets': {'READ': 49, 'SELECT': 37, 'OPERATE': 37}, 'output_octets': 61,
        'output_octets_note': 'SELECT/OPERATE image (the control-timing contract field); the READ image is read_output_octets',
        'read_output_octets': c['target'],
        'read_construction': 'prefix (read_complete_01/vectors/constants.json shape %s)' % c['shape'],
        'control_application_partition': m11['encoding']['control_application_partition'],
        'control_partition_note': m11['encoding']['control_partition_note']}
    if a.two_read:
        cm, cf = two_read.two_read_shapes()
        profile['_note'] = ('two-READ-target build: N/T values unchanged from m11_09 (T segment and timing '
                            'parameters inherited); encoding: SELECT/OPERATE output 61 (output_octets); READ images per '
                            'native length (read_images): mixed %d->%d and full %d->%d by the pipe-1 egress prefix '
                            '(G1V2 points 1024..). Other READ lengths are not padded; arbitrary input sizes are not '
                            'supported.' % (cm['native_total'], cm['target'], cf['native_total'], cf['target']))
        profile['encoding'].update({
            'native_input_octets': {'READ': [cm['native_total'], cf['native_total']], 'SELECT': 37, 'OPERATE': 37},
            'read_output_octets': [cm['target'], cf['target']],
            'read_images': {str(cm['native_total']): cm['target'], str(cf['native_total']): cf['target']},
            'read_construction': 'prefix (read_complete_01/vectors/constants_two_read.json shapes %s, %s)'
                                 % (cm['shape'], cf['shape'])})
    gen_files = generator_files()
    shapes2 = two_read.two_read_shapes() if a.two_read else None
    (out / 'response_only.inputs.json').write_text(json.dumps({
        'milestone': 'm12', 'image_len': read_out, 'transforms_applied': applied, 'scope': scope,
        'full_target': runnable, 'runnable': runnable,
        'intermediate_note': None if runnable else
        'PARTIAL build: %s not applied — placement experiment only, not a working integrated candidate'
        % sorted(required - set(applied)),
        'source_sha256': sha, 'segment_sha256': segs, 'supported_profile': profile,
        't_time': {'unit_ns': 256, 'grid_ns': 512, 'source': 'global_tstamp[39:8] & ~1'},
        't_lifetime_encoding': 'sealed_low31',
        'native_lengths': {'READ': read_native, 'SELECT_OPERATE': 37},
        'read_boundary': 'cimg' if a.c3 == 'cimg' else 'max_image_ladder',
        **({'passthrough_reads': {n: {'request_octets': v[0], 'request_dl_len': v[1], 'response_octets': v[2],
                                      'response_dl_len': v[3], 'output_octets': v[2]}
                                  for n, v in read_policy.PASSTHROUGH_READS.items()}}
           if a.shapes == 'passthrough' and not a.two_read else {}),
        # two-READ build: no READ class passes through -- integrity 247 is PADDED (271), analog/class0 are not admitted
        **({'passthrough_reads': {}, 'not_admitted_reads': ['analog', 'class0']} if a.two_read else {}),
        **({'read_images': {str(s['native_total']): s['target'] for s in shapes2},
            'read_shapes': {name: {k: s[k] for k in ('native_total', 'native_link_len', 'native_ip_len', 'target',
                                                     'frames_out', 'added', 'padding_points', 'padding_indices',
                                                     'prefix_link_len', 'request_len', 'request_link_len',
                                                     'request_ip_len', 'request_objects')}
                            for name, s in zip(('mixed', 'full'), shapes2)}} if a.two_read else {}),
        'output_lengths': ({'READ': {'mixed': shapes2[0]['target'], 'full': shapes2[1]['target']},
                            'SELECT_OPERATE': 61} if a.two_read else {'READ': read_out, 'SELECT_OPERATE': 61}),
        'policy': (dict(constants_file='read_complete_01/vectors/constants_two_read.json',
                        constants_sha256=hashlib.sha256(CONSTANTS_TWO.read_bytes()).hexdigest(),
                        policy_targets=json.loads(CONSTANTS_TWO.read_text())['policy_targets'],
                        p1_read_pad_conn_table='p1.x_Egress.p1_conn') if a.two_read else
                   dict(constants_sha256=hashlib.sha256(CONSTANTS.read_bytes()).hexdigest(),
                        policy_targets=json.loads(CONSTANTS.read_text())['policy_targets'],
                        p1_read_pad_conn_table='p1.x_Egress.p1_conn')),
        # generator identity: a digest over every generator file (make_m12.py and the m12gen package), listed below
        'generator_sha256': hashlib.sha256(json.dumps(gen_files, sort_keys=True).encode()).hexdigest(),
        'generator_files': gen_files,
        'read_growth': read_out - read_native, 'control_growth': 24,
        'port_map': {'relay_port': 9, 'n_ack_return': 48, 't_in': 180, 'hb_return': 181, 'held_return': 182},
        'successor_of': {'build': 'm11_09', 'source_sha256': M11_09_SHA}}, indent=2) + '\n')
    (out / 'supported_profile.json').write_text(json.dumps(profile, indent=2) + '\n')
    return sha


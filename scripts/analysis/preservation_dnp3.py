"""DNP3 layer of the E1 preservation check: link frames (every CRC), transport segments (63 -> 0), application
fragments, the build's declared padding, and a field-level comparison of the original application content.

Declared padding, as the build declares it (c72; c72_diag_mirror adds only mirror hunks, so its copy of the source,
results/builds/c72_diag_mirror/response_only.p4, has the same actions 30 lines later, e.g. prefix_mx at 2220):

READ  results/builds/<build>/response_only.inputs.json `policy` binds tests/fixtures/vectors/
      constants_two_read_relay.json by SHA-256 (9e715d8f...); its shapes give prefix_link_len 39/17 (lines 53, 101)
      and padobj_head (lines 56, 104). p4/response_only.p4, pipe-1 egress x_Egress, applies them:
  2185-2189 read_profile  pads only IP length 143 + LEN 0x4c (mixed 91) or 186 + 0x73 (integrity 134), transport
                          FIR|FIN, application FIR|FIN without CON/UNS, function 0x81, first object g1v2 q0x00 0..15.
  2190-2200 prefix_mx     a new link frame (LEN 39, the native CTRL/DST/SRC): transport FIR|s, the native application
                          control, function and IIN, then g1v2 q0x01 1024..1049 (0x01020100041904, line 2194) and
                          22 zero point octets. The native frame keeps its link header; its transport becomes FIN|s+1
                          (set_tp_t, 2166-2167) and its first four application octets become zero (the last four of
                          the 26 padding points); block-0 CRC recomputed; IP length 193 (+50).
  2202-2211 prefix_full   the same with LEN 17 and g1v2 q0x01 1024..1027 (0x01020100040304), IP length 210 (+24).
  2224-2232 x_EgDeparser  IP checksum (IP ID unchanged) and TCP checksum.
      In application coordinates the declared prefix is app[4:4+7+points] = padobj_header + `points` zero octets.
      Software oracle: scripts/model/read_policy_expect.py:264-277 construct().
SELECT/OPERATE  p4/response_only.p4:1150 ctl_eligible (pipe-0 egress): the whole 49-octet response becomes transport
      FIR|s + application octets 0..14 and FIN|s+1 + octets 15..31 (60 octets, no application octet added);
      supported_profile.json encoding.control_application_partition [15, 17]; inputs control_growth 11;
      oracle scripts/model/relay_sbo_vectors.py:30-36 control_image().
"""
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'scripts/hardware/active_harness'), str(ROOT / 'scripts/checks')]
import dnp3_codec as codec  # noqa: E402
import wire_check as wc  # noqa: E402

FIR, FIN = codec.TRANSPORT_FIR, codec.TRANSPORT_FIN
# p4/response_only.p4 prefix_mx (2190-2200) and prefix_full (2202-2211): LEN, padding object header, TCP growth.
P4_READ = {'mixed_g1v2_g30v1_91': dict(link_len=39, header='01020100041904', growth=50),
           'integrity_134': dict(link_len=17, header='01020100040304', growth=24)}
IIN_NAMES = ('IIN1.0 broadcast', 'IIN1.1 class_1_events', 'IIN1.2 class_2_events', 'IIN1.3 class_3_events',
             'IIN1.4 need_time', 'IIN1.5 local_control', 'IIN1.6 device_trouble', 'IIN1.7 device_restart',
             'IIN2.0 no_func_code_support', 'IIN2.1 object_unknown', 'IIN2.2 parameter_error',
             'IIN2.3 event_buffer_overflow', 'IIN2.4 already_executing', 'IIN2.5 config_corrupt',
             'IIN2.6 reserved', 'IIN2.7 reserved')


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load_declared(inputs_path):
    """The build's declared padding: the hash-bound constants file, refused unless it agrees with the P4."""
    inputs_path = Path(inputs_path)
    inputs = json.loads(inputs_path.read_text())
    policy = inputs['policy']
    if sha256(ROOT / policy['constants_file']) != policy['constants_sha256']:
        raise ValueError('declared READ constants differ from the hash the build recorded')
    shapes = {}
    for name, c in json.loads((ROOT / policy['constants_file']).read_text())['shapes'].items():
        head = bytes.fromhex(c['padobj_head'])
        prefix = bytes.fromhex(c['padobj_header']) + bytes(c['padding_points'])
        if (P4_READ.get(name) != dict(link_len=c['prefix_link_len'], header=c['padobj_header'],
                                      growth=c['target'] - c['native_total'])
                or head + bytes(4) != prefix or c['prefix_link_len'] != 10 + len(head)):
            raise ValueError('declared READ shape %s disagrees with the P4 prefix construction' % name)
        shapes[name] = dict(native=c['native_total'], target=c['target'], growth=c['target'] - c['native_total'],
                            link_len=c['prefix_link_len'], head=head, prefix=prefix)
    profile = json.loads((inputs_path.parent / 'supported_profile.json').read_text())
    partition = tuple(profile['encoding']['control_application_partition'])
    growth = inputs['output_lengths']['SELECT_OPERATE'] - inputs['native_lengths']['SELECT_OPERATE']
    if growth != inputs['control_growth'] or len(partition) != 2:
        raise ValueError('declared control image disagrees with its declared lengths')
    return dict(source_sha256=inputs['source_sha256'], build=profile['candidate']['build'], shapes=shapes,
                constants_file=policy['constants_file'], constants_sha256=policy['constants_sha256'],
                control=dict(partition=partition, growth=growth))


def summary(declared):
    shapes = {name: dict(native=s['native'], target=s['target'], growth=s['growth'], prefix_link_len=s['link_len'],
                         application_prefix_hex=s['prefix'].hex()) for name, s in declared['shapes'].items()}
    return dict(constants_file=declared['constants_file'], constants_sha256=declared['constants_sha256'],
                read_shapes=shapes, control_image=dict(partition=list(declared['control']['partition']),
                                                       growth=declared['control']['growth']),
                source=__doc__.split('\n\n', 1)[1])


def link_frames(data, base):
    """Back-to-back link frames of one contiguous stream run at stream offset base; header and block CRCs checked."""
    frames, errors, at = [], [], 0
    while at < len(data):
        try:
            frame, _ = codec.parse_frame(data[at:], verify_crc=False)
        except codec.FrameError as error:
            errors.append(dict(offset=base + at, error=str(error)))
            break
        if frame is None:
            errors.append(dict(offset=base + at, error='incomplete link frame, %d octets left' % (len(data) - at)))
            break
        ok, reason = wc.dnp3_ok(frame.wire)
        frames.append(dict(offset=base + at, wire=frame.wire, user=frame.user_data, crc_ok=ok, crc=reason))
        at += frame.total
    return frames, errors


def fragments(frames):
    """Application fragments with their frames, through the codec's transport assembler (sequence 63 -> 0)."""
    assembler, parts, out, errors = codec.TransportAssembler(), [], [], []
    for frame in frames:
        try:
            done = assembler.add(frame['user'])
        except codec.TransportError as error:
            errors.append(dict(offset=frame['offset'], error=str(error)))
            parts = []
            if not frame['user'] or not frame['user'][0] & FIR:
                continue
            done = assembler.add(frame['user'])        # the FIR that ended an unfinished fragment starts the next
        parts = [frame] if frame['user'][0] & FIR else parts + [frame]
        if done is not None:
            out.append(dict(start=parts[0]['offset'], end=frame['offset'] + len(frame['wire']), frames=parts,
                            wire=b''.join(f['wire'] for f in parts), app=done, crc_ok=all(f['crc_ok'] for f in parts)))
            parts = []
    if parts:
        errors.append(dict(offset=parts[0]['offset'], error='fragment without FIN at the end of the stream'))
    return out, errors


def _frame(header8, user):
    header = header8[:2] + bytes([5 + len(user)]) + header8[3:8]
    return header + codec.crc_le(header) + b''.join(
        user[i:i + 16] + codec.crc_le(user[i:i + 16]) for i in range(0, len(user), 16))


def _single(native):
    try:
        frame, rest = codec.parse_frame(native, verify_crc=False)
    except codec.FrameError:
        return None
    return frame if frame is not None and not rest and len(frame.user_data) >= 5 else None


def read_image(native, shape):
    """The declared READ image of a single-frame native response (P4 prefix_mx / prefix_full)."""
    frame = _single(native)
    if frame is None:
        return None
    user, seq = frame.user_data, frame.user_data[0] & 63
    return (_frame(native[:8], bytes([FIR | seq]) + user[1:5] + shape['head'])
            + _frame(native[:8], bytes([(user[0] & FIN) | ((seq + 1) & 63)]) + bytes(4) + user[5:]))


def control_image(native, partition):
    """The declared SELECT/OPERATE reframing (P4 ctl_eligible); the application octets are unchanged."""
    frame = _single(native)
    if frame is None or sum(partition) != len(frame.user_data) - 1:
        return None
    user, cut = frame.user_data, partition[0] + 1
    return (_frame(native[:8], bytes([user[0] & 0x7f]) + user[1:cut])
            + _frame(native[:8], bytes([FIN | ((user[0] + 1) & 63)]) + user[cut:]))


def classify(native, image, declared):
    """(form, expected image, declared growth): the exact declared form, else the one the image's framing names."""
    forms = {'native': (native['wire'], 0),
             'control_image': (control_image(native['wire'], declared['control']['partition']),
                               declared['control']['growth'])}
    forms.update(('read_' + name, (read_image(native['wire'], shape), shape['growth']))
                 for name, shape in declared['shapes'].items())
    for form, (wire, growth) in forms.items():
        if wire is not None and wire == image['wire']:
            return form, wire, growth
    lens = [f['wire'][2] for f in image['frames']]
    names = [name for name, shape in declared['shapes'].items() if len(lens) > 1 and lens[0] == shape['link_len']]
    a, b = declared['control']['partition']
    form = 'read_' + names[0] if names else 'control_image' if lens == [6 + a, 6 + b] else 'native'
    return (form,) + forms[form]


def strip(app, form, declared):
    """(application without the declared prefix, the octets found where the prefix is declared, or None)."""
    if not form.startswith('read_'):
        return app, None
    n = len(declared['shapes'][form[5:]]['prefix'])
    return app[:4] + app[4 + n:], app[4:4 + n]


def byte_diff(expected, actual):
    offsets = [i for i in range(max(len(expected), len(actual)))
               if i >= len(expected) or i >= len(actual) or expected[i] != actual[i]]
    return None if not offsets else dict(offsets=offsets[:32], differing=len(offsets),
                                         expected_len=len(expected), actual_len=len(actual))


def describe(app, request=False):
    """Every compared field of one application fragment. A request's objects are decoded by the response decoder
    with its function and IIN octets replaced (as relay_check does for the CROB echo)."""
    parsed = codec.parse_application_response(app[:1] + b'\x81\x00\x00' + app[2:] if request else app)
    ac = app[0] if app else 0
    fields = {'app_control.fir': ac >> 7 & 1, 'app_control.fin': ac >> 6 & 1, 'app_control.con': ac >> 5 & 1,
              'app_control.uns': ac >> 4 & 1, 'app_control.seq': ac & 15,
              'function': app[1] if len(app) > 1 else None}
    if not request:
        fields.update(('iin.' + name, parsed.iin >> k & 1 if parsed.iin >= 0 else None)
                      for k, name in enumerate(IIN_NAMES))
    objects = [dict(header=[o['group'], o['variation'], o['qualifier'], o['count'],
                            o['points'][0]['index'] if o['points'] else None,
                            o['points'][-1]['index'] if o['points'] else None], points=o['points'])
               for o in parsed.objects]
    return fields, objects, parsed.problems


def compare_application(relay, master, request=False):
    """Field differences between the relay's original fragment and the master's (declared prefix removed)."""
    diffs, raw = [], byte_diff(relay, master)
    if raw:
        diffs.append(dict(field='raw_application', **raw))
    (fa, oa, pa), (fb, ob, pb) = describe(relay, request), describe(master, request)
    diffs += [dict(field=key, relay=fa[key], master=fb[key]) for key in fa if fa[key] != fb[key]]
    ha, hb = [o['header'] for o in oa], [o['header'] for o in ob]
    if ha != hb:
        kind = ('reordered' if sorted(ha) == sorted(hb) else 'dropped' if len(hb) < len(ha) and
                all(h in ha for h in hb) else 'added' if len(hb) > len(ha) and all(h in hb for h in ha) else 'changed')
        diffs.append(dict(field='object_headers', kind=kind, relay=ha, master=hb))
    for i, (x, y) in enumerate(zip(oa, ob)):
        if x['header'] != y['header']:
            continue
        for p, q in zip(x['points'], y['points']):
            diffs += [dict(field='objects[%d] g%dv%d index %d %s' % (i, x['header'][0], x['header'][1], p['index'], k),
                           relay=p[k], master=q.get(k)) for k in p if k != 'index' and p[k] != q.get(k)]
    if pa != pb:
        diffs.append(dict(field='decode_problems', relay=pa, master=pb))
    return diffs

"""File-backed packet-boundary evidence for 61-octet candidate qualification.

The standards artifact binds hashes for these files, but this module recomputes
and interprets the actual evidence from the run directory. It fails closed when
capture qualification evidence is absent, malformed, or self-attested without the
underlying capture/settings files.
"""
import hashlib
import json
import os
from pathlib import Path

import wire_check

SCHEMA_VERSION = 'dnp3-boundary-v1'
OFFLOAD_KEYS = ('gro', 'lro', 'rx-gro-hw', 'rx_gro_hw')
OPTIONAL_OFFLOAD_KEYS = ('rx-gro-list', 'rx_gro_list')
CAPTURE_KEYS = (
    'capture_offloads',
    'calibration_expected',
    'calibration_in',
    'calibration_out',
    'calibration_result',
    'run_result',
)


def load_json(path):
    return json.load(open(path))


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def _path(captures, name):
    entry = (captures or {}).get(name)
    if isinstance(entry, (str, os.PathLike)):
        return str(entry)
    if isinstance(entry, dict):
        return entry.get('path')
    return None


def _require_paths(failures, captures, names):
    paths = {}
    for name in names:
        path = _path(captures, name)
        if not path:
            failures.append('boundary context missing %s path' % name)
            continue
        if not Path(path).is_file():
            failures.append('boundary %s unreadable: %s' % (name, path))
            continue
        paths[name] = path
    return paths


def _feature_bool(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in ('on', 'true', 'yes', 'enabled'):
            return True
        if lowered in ('off', 'false', 'no', 'disabled'):
            return False
    return value


def _features(section):
    if not isinstance(section, dict):
        return {}
    features = section.get('features', section)
    if not isinstance(features, dict):
        return {}
    return {str(k): _feature_bool(v) for k, v in features.items()}


def _offload_is_off(features, key):
    names = {key, key.replace('-', '_'), key.replace('_', '-')}
    present = [features[name] for name in names if name in features]
    return bool(present) and all(value is False for value in present)


def _validate_offloads(path):
    failures = []
    try:
        data = load_json(path)
    except (OSError, ValueError) as error:
        return ['capture offload evidence unreadable: %s' % error]
    if not isinstance(data, dict):
        return ['capture offload evidence is not an object']
    if not data.get('interface'):
        failures.append('capture offload interface missing')
    before = _features(data.get('before'))
    during = _features(data.get('during'))
    after = _features(data.get('after'))
    for key in ('gro', 'lro', 'rx-gro-hw'):
        if not _offload_is_off(during, key):
            failures.append('capture offload during.%s is not disabled' % key)
    for key in OPTIONAL_OFFLOAD_KEYS:
        if key in during and during[key] is not False:
            failures.append('capture offload during.%s is not disabled' % key)
    if data.get('restore_ok') is not True:
        failures.append('capture offload restore_ok is not true')
    if before and after and before != after:
        failures.append('capture offload after features do not match before features')
    commands = data.get('commands')
    if not isinstance(commands, list) or not commands:
        failures.append('capture offload commands missing')
    for section_name in ('before', 'during', 'after'):
        section = data.get(section_name)
        if not isinstance(section, dict) or not section.get('command'):
            failures.append('capture offload %s.command missing' % section_name)
    return failures


def _stat_dicts(value):
    found = []
    if isinstance(value, dict):
        keys = set(value)
        if keys & {'captured', 'captured_packets', 'received_by_filter'} and \
                keys & {'dropped_kernel', 'dropped_by_kernel'}:
            found.append(value)
        for item in value.values():
            found.extend(_stat_dicts(item))
    elif isinstance(value, list):
        for item in value:
            found.extend(_stat_dicts(item))
    return found


def _stats_failures(data, label):
    failures = []
    stats = _stat_dicts(data)
    if not stats:
        return ['%s tcpdump stats missing' % label]
    for i, stat in enumerate(stats):
        captured = stat.get('captured', stat.get('captured_packets', stat.get('received_by_filter')))
        dropped_kernel = stat.get('dropped_kernel', stat.get('dropped_by_kernel', 0))
        dropped_iface = stat.get('dropped_interface', stat.get('dropped_by_interface', 0))
        if not isinstance(captured, int) or isinstance(captured, bool) or captured <= 0:
            failures.append('%s tcpdump stats[%d] captured=%r' % (label, i, captured))
        if dropped_kernel != 0:
            failures.append('%s tcpdump stats[%d] dropped_kernel=%r' % (label, i, dropped_kernel))
        if dropped_iface != 0:
            failures.append('%s tcpdump stats[%d] dropped_interface=%r' % (label, i, dropped_iface))
    return failures


def _command_text(command):
    # vision_run.py records argv lists; str(list) would hide '-Q in' as "'-Q', 'in'"
    if isinstance(command, (list, tuple)):
        return ' '.join(str(arg) for arg in command)
    return str(command)


def _capture_commands(data):
    commands = data.get('capture_commands') if isinstance(data, dict) else None
    if isinstance(commands, dict):
        return [_command_text(v) for v in commands.values()]
    if isinstance(commands, list):
        return [_command_text(v) for v in commands]
    return []


def _load_result(path, label):
    try:
        data = load_json(path)
    except (OSError, ValueError) as error:
        return None, ['%s unreadable: %s' % (label, error)]
    if not isinstance(data, dict):
        return None, ['%s is not an object' % label]
    failures = _stats_failures(data, label)
    commands = _capture_commands(data)
    if not commands:
        failures.append('%s capture_commands missing' % label)
    return data, failures


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _payloads(path):
    segs, _ = wire_check.parse(path)
    return [seg for seg in segs if seg.get('len', 0) > 0]


def _pcap_frames(path):
    frames, _ = wire_check.read_pcap(path)
    return [frame for _t, frame in frames]


def _looks_like_ethernet_frame(data):
    return isinstance(data, (bytes, bytearray)) and len(data) >= 54 and data[12:14] == b'\x08\x00' and data[23] == 6


def _assert_coalescible_calibration(segs, label):
    failures = []
    if len(segs) < 2:
        return ['%s must contain at least two coalescible TCP packets' % label]
    first = segs[0]
    for i, seg in enumerate(segs):
        if (seg.get('src'), seg.get('dst'), seg.get('sport'), seg.get('dport')) !=                 (first.get('src'), first.get('dst'), first.get('sport'), first.get('dport')):
            failures.append('%s packet[%d] is not on the calibration flow' % (label, i))
        if seg.get('ack') != first.get('ack'):
            failures.append('%s packet[%d] ack differs from first packet' % (label, i))
        if i:
            prev = segs[i - 1]
            if seg.get('seq') != ((prev.get('seq') or 0) + (prev.get('len') or 0)) & 0xffffffff:
                failures.append('%s packet[%d] sequence is not contiguous' % (label, i))
    return failures


def _link_users(payload):
    users, base = [], 0
    while base < len(payload):
        if len(payload) - base < 10 or payload[base:base + 2] != b'\x05\x64':
            raise ValueError('no DNP3 link start at %d' % base)
        if wire_check.dnp3_crc(payload[base:base + 8]) != int.from_bytes(payload[base + 8:base + 10], 'little'):
            raise ValueError('DNP3 header CRC at %d' % base)
        n = payload[base + 2] - 5
        if n < 0:
            raise ValueError('DNP3 LEN < 5 at %d' % base)
        p, user = base + 10, bytearray()
        remaining = n
        while remaining:
            k = min(16, remaining)
            block = payload[p:p + k]
            crc = payload[p + k:p + k + 2]
            if len(block) != k or len(crc) != 2:
                raise ValueError('truncated DNP3 block at %d' % p)
            if wire_check.dnp3_crc(block) != int.from_bytes(crc, 'little'):
                raise ValueError('DNP3 block CRC at %d' % p)
            user.extend(block)
            p += k + 2
            remaining -= k
        users.append(bytes(user))
        base = p
    return users


def _response_app_seq(payload):
    users = _link_users(payload)
    if not users:
        raise ValueError('no DNP3 users in segment')
    first = users[0]
    if len(first) < 3 or first[2] not in (0x81, 0x82, 0x83):
        raise ValueError('segment is not a DNP3 response')
    return first[1] & 0x0F


def _verdict_app_seq(verdict):
    for key in ('app_seq', 'request_app_seq', 'wire_app_seq', 'application_sequence'):
        if key in verdict:
            value = verdict.get(key)
            if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 15:
                return value
    return None


def _required_lengths(required_payload_len):
    """One required payload length (int) or several (a READ image beside the control image)."""
    if isinstance(required_payload_len, int):
        return {required_payload_len}
    return set(required_payload_len)


def _checker_expectations(checker_result, required_payload_len):
    failures = []
    if required_payload_len is None:
        return [], failures
    if not isinstance(checker_result, dict):
        return [], ['checker result missing for boundary exchange binding']
    raw = checker_result.get('raw_result') if isinstance(checker_result.get('raw_result'), dict) else checker_result
    verdicts = raw.get('verdicts') if isinstance(raw, dict) else None
    if not isinstance(verdicts, list):
        return [], ['checker result verdicts missing for boundary exchange binding']
    expected = []
    for verdict in verdicts:
        if not isinstance(verdict, dict):
            continue
        if verdict.get('wire_len') not in _required_lengths(required_payload_len):
            continue
        app_seq = _verdict_app_seq(verdict)
        if app_seq is None:
            failures.append('checker verdict %r lacks application sequence for boundary binding' %
                            verdict.get('index'))
            continue
        expected.append({'index': verdict.get('index'), 'kind': verdict.get('kind'), 'app_seq': app_seq,
                         'request_serial': verdict.get('request_serial'),
                         'wire_image_sha256': verdict.get('wire_image_sha256'),
                         'tuple': verdict.get('tuple'), 'incarnation': (verdict.get('tuple') or {}).get('incarnation')})
    return expected, failures


def _validate_calibration(expected_path, out_path, in_path, result_path):
    failures = []
    try:
        expected = load_json(expected_path)
    except (OSError, ValueError) as error:
        return ['calibration expected unreadable: %s' % error]
    if not isinstance(expected, dict):
        return ['calibration expected is not an object']
    if expected.get('direction') != 'in':
        failures.append('calibration expected direction must be in')
    frames_hex = expected.get('frames')
    if not isinstance(frames_hex, list) or not frames_hex:
        failures.append('calibration expected frames missing')
        frames = []
    else:
        frames = []
        for i, value in enumerate(frames_hex):
            try:
                frames.append(bytes.fromhex(value))
            except (TypeError, ValueError):
                failures.append('calibration expected frames[%d] is not hex' % i)
    _, result_failures = _load_result(result_path, 'calibration result')
    failures.extend(result_failures)
    full_frame_mode = bool(frames) and all(_looks_like_ethernet_frame(frame) for frame in frames)
    if full_frame_mode:
        for label, path in (('calibration_out', out_path), ('calibration_in', in_path)):
            try:
                actual = _pcap_frames(path)
                segs = _payloads(path)
            except (OSError, ValueError, KeyError, TypeError) as error:
                failures.append('%s parse failed: %s' % (label, error))
                continue
            if len(actual) != len(frames):
                failures.append('%s frame count %d, expected %d' % (label, len(actual), len(frames)))
            for i, (got, want) in enumerate(zip(actual, frames)):
                if got != want:
                    failures.append('%s frame[%d] does not match expected Ethernet frame' % (label, i))
            failures.extend(_assert_coalescible_calibration(segs, label))
        return failures
    for label, path in (('calibration_out', out_path), ('calibration_in', in_path)):
        try:
            segs = _payloads(path)
        except (OSError, ValueError, KeyError, TypeError) as error:
            failures.append('%s parse failed: %s' % (label, error))
            continue
        payloads = [seg['payload'] for seg in segs]
        if len(payloads) != len(frames):
            failures.append('%s payload count %d, expected %d' % (label, len(payloads), len(frames)))
            continue
        for i, (got, want) in enumerate(zip(payloads, frames)):
            if got != want:
                failures.append('%s payload[%d] does not match expected calibration frame' % (label, i))
    return failures


def _seg_tuple(seg):
    return {'src': {'ip': seg.get('src'), 'port': seg.get('sport')},
            'dst': {'ip': seg.get('dst'), 'port': seg.get('dport')}}


def _tuple_matches(seg, expected_tuple, outstation_port, master_port):
    if isinstance(expected_tuple, dict):
        src = expected_tuple.get('src') or {}
        dst = expected_tuple.get('dst') or {}
        if src.get('ip') and seg.get('src') != src.get('ip'):
            return False
        if dst.get('ip') and seg.get('dst') != dst.get('ip'):
            return False
        if src.get('port') and seg.get('sport') != src.get('port'):
            return False
        if dst.get('port') and seg.get('dport') != dst.get('port'):
            return False
        return True
    return seg.get('sport') == outstation_port and (master_port is None or seg.get('dport') == master_port)


def _validate_physical_main(in_path, result_path, *, required_payload_len=None, expected_attempts=0,
                            checker_result=None):
    failures = []
    try:
        result, result_failures = _load_result(result_path, 'run result')
        failures.extend(result_failures)
        commands = _capture_commands(result or {})
        if not any('-Q in' in command or 'direction=in' in command or ' incoming' in command for command in commands):
            failures.append('run result does not retain an incoming physical capture command')
    except Exception as error:  # load_result is fail-closed; this protects malformed nested values.
        failures.append('run result parse failed: %s' % error)
    try:
        segs = _payloads(in_path)
    except (OSError, ValueError, KeyError, TypeError) as error:
        return failures + ['physical incoming capture parse failed: %s' % error]
    if required_payload_len is not None and expected_attempts:
        expected, checker_failures = _checker_expectations(checker_result, required_payload_len)
        failures.extend(checker_failures)
        if len(expected) != expected_attempts:
            failures.append('checker transformed response count %d, expected %d' % (len(expected), expected_attempts))
        outstation_port = None
        master_port = None
        if isinstance(checker_result, dict):
            outstation_port = checker_result.get('outstation_port')
            master_port = checker_result.get('master_port')
        outstation_port = 20000 if outstation_port is None else outstation_port
        next_expected = 0
        consumed = []
        seen_retx = set()
        protected_seen = 0
        expected_tuple = expected[0].get('tuple') if expected else None
        for seg in segs:
            if not _tuple_matches(seg, expected_tuple, outstation_port, master_port):
                continue
            protected_seen += 1
            payload = seg.get('payload', b'')
            payload_hash = _sha(payload)
            retx_key = (seg.get('src'), seg.get('dst'), seg.get('sport'), seg.get('dport'), seg.get('seq'), payload_hash)
            if retx_key in seen_retx:
                continue
            seen_retx.add(retx_key)
            if seg.get('len') not in _required_lengths(required_payload_len):
                failures.append('physical protected response segment %r len %r, expected %s' %
                                (seg.get('index'), seg.get('len'), required_payload_len))
                continue
            try:
                app_seq = _response_app_seq(payload)
            except ValueError as error:
                failures.append('physical incoming protected segment %r is not a valid DNP3 response: %s' %
                                (seg.get('index'), error))
                continue
            if next_expected < len(expected):
                want = expected[next_expected]
                if app_seq == want['app_seq'] and (want.get('wire_image_sha256') in (None, payload_hash)):
                    consumed.append(want)
                    next_expected += 1
                    continue
            matching_consumed = [row for row in consumed if row['app_seq'] == app_seq]
            if matching_consumed:
                if any(row.get('wire_image_sha256') == payload_hash for row in matching_consumed):
                    failures.append('physical incoming retransmission %r repeats response with new TCP key' %
                                    seg.get('index'))
                else:
                    failures.append('physical incoming protected segment %r repeats app_seq %r with different image' %
                                    (seg.get('index'), app_seq))
                continue
            failures.append('physical incoming protected segment %r app_seq/hash does not match checker exchanges' %
                            seg.get('index'))
        if protected_seen == 0:
            failures.append('physical incoming capture has no protected response payload evidence')
        if next_expected < min(len(expected), expected_attempts):
            failures.append('missing transformed response attempts: observed %d, expected %d' %
                            (next_expected, expected_attempts))
    return failures


def validate_boundary_evidence(captures, *, required_payload_len=None, expected_attempts=0, checker_result=None):
    failures = []
    paths = _require_paths(failures, captures, ('in',) + CAPTURE_KEYS)
    if failures:
        return {'ok': False, 'failures': failures, 'required_payload_len': required_payload_len,
                'expected_attempts': expected_attempts}
    failures.extend(_validate_offloads(paths['capture_offloads']))
    failures.extend(_validate_calibration(paths['calibration_expected'], paths['calibration_out'],
                                          paths['calibration_in'], paths['calibration_result']))
    failures.extend(_validate_physical_main(paths['in'], paths['run_result'],
                                            required_payload_len=required_payload_len,
                                            expected_attempts=expected_attempts,
                                            checker_result=checker_result))
    return {'ok': not failures, 'failures': failures, 'required_payload_len': required_payload_len,
            'expected_attempts': expected_attempts}


# Compatibility wrapper for early tests/tools that supplied a separate proof JSON.
def validate_boundary_proof(proof, captures, *, required_payload_len=None, expected_attempts=0,
                            checker_result=None):
    return validate_boundary_evidence(captures, required_payload_len=required_payload_len,
                                      expected_attempts=expected_attempts, checker_result=checker_result)

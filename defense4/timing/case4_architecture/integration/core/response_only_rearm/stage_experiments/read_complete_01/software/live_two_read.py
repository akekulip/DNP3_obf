"""Live software check of the two-READ-target profile (91 -> 141, 247 -> 271) against the HARDWARE workload binary.

The real outstation and master of rearm_01/repeat_sbo_endpoint (case4_socket_gate_read_schedule, pinned OpenDNP3
4648fcb) talk over two loopback TCP legs through a Python proxy. On a padded case the proxy pads every READ response
with general_read_padding.pad_read(targets=[141, 271], reserved 1024..4095) -- the software reference the switch must
reproduce -- and forwards SELECT/OPERATE and every request unchanged. No switch, no timing: this establishes the
encodings against live natives and the live master's acceptance, not the P4 path.

The master runs the mixed_full schedule (mixed READ, then SELECT/OPERATE cycles each followed by the next READ:
mixed, integrity, mixed, ...) with the STRICT declared-padding check (CASE4_PAD_EXPECT): originals unchanged in their
native header structure, no repeated index, exactly the declared padding points (indices, values, flags, count, one
header before the originals); with no declaration any added point fails.

Positive cases must pass with every READ exact: mixed [91] -> [50, 91] (target 141, 26 points), integrity [247] ->
[24, 247] (target 271, 4 points), by the prefix construction. Negative cases must be REJECTED BY THE MASTER'S FIXTURE
CHECK on the first (mixed) READ: that READ completed (delivered) and matches_fixture is false, with no proxy error and no
master stderr. A negative case failing for any other reason (timeout, crash, proxy error) is a FAILURE of this check.
  native_v0            proxy forwards natives, nothing declared                         -> passes
  padded_v0/_v1/_v3    proxy pads, mixed=26,integrity=4 declared; values/flags varied   -> passes
  padded_undeclared    proxy pads, nothing declared (padding-off arm seeing padding)    -> rejected
  declared_unpadded    padding declared, proxy forwards natives                         -> rejected
  wrong_count          proxy pads, mixed=25 declared                                    -> rejected
  corrupt_original     one original analog value changed (CRCs re-made), then padded    -> rejected
  The remaining negative cases replace the mixed READ's response with a crafted, validly framed APDU (link and
  transport octets from the live native) and leave every other READ correctly padded:
  pad_index_shift      padding at 1025..1050 instead of 1024..1049                       -> rejected
  pad_nonzero_flags    padding points carry 0x01 (ONLINE) instead of 0x00                -> rejected
  pad_after_originals  padding header placed after the original headers                 -> rejected
  pad_mixed_header     one padding header covering 1000..1025 (original + reserved)      -> rejected
  pad_g1v1             padding as G1V1 (packed) instead of G1V2                          -> rejected
  duplicate_analog     correct padding + an extra G30V1 header repeating analog 7        -> rejected
  reordered_originals  correct padding, original G30V1 header before G1V2                -> rejected

  $RESEARCH_PYTHON live_two_read.py --out DIR [--cycles 8]
Evidence per case: both legs (request, native response, sent response, pad_read result) per exchange, the master's
and outstation's JSON, and summary.json with the frame lengths, padding inventory and verdicts.
"""
import argparse
import collections
import hashlib
import json
import os
import pathlib
import select
import socket
import subprocess
import sys
import threading

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / 'source/full_read_01'))
import general_read_padding as gp  # noqa: E402
from live_check import consume  # noqa: E402

std = gp.std
ENDPOINT = HERE.parents[4] / 'evidence/rearm_01/repeat_sbo_endpoint'
BINARY = ENDPOINT / 'build/case4_socket_gate_read_schedule'
TARGETS = [141, 271]
PAD_START, PAD_STOP = 1024, 4095
DECLARED = 'mixed=26,integrity=4'
EXPECTED_SHAPES = {91: dict(sent=[50, 91], target=141, points=26), 247: dict(sent=[24, 247], target=271, points=4)}
CASES = [  # name, pad, CASE4_PAD_EXPECT, fixture variant, tamper, expect master success
    ('native_v0', False, None, 0, None, True),
    ('padded_v0', True, DECLARED, 0, None, True),
    ('padded_v1', True, DECLARED, 1, None, True),
    ('padded_v3', True, DECLARED, 3, None, True),
    ('padded_undeclared', True, None, 0, None, False),
    ('declared_unpadded', False, DECLARED, 0, None, False),
    ('wrong_count', True, 'mixed=25,integrity=4', 0, None, False),
    ('corrupt_original', True, DECLARED, 0, 'corrupt_original', False),
    ('pad_index_shift', True, DECLARED, 0, 'pad_index_shift', False),
    ('pad_nonzero_flags', True, DECLARED, 0, 'pad_nonzero_flags', False),
    ('pad_after_originals', True, DECLARED, 0, 'pad_after_originals', False),
    ('pad_mixed_header', True, DECLARED, 0, 'pad_mixed_header', False),
    ('pad_g1v1', True, DECLARED, 0, 'pad_g1v1', False),
    ('duplicate_analog', True, DECLARED, 0, 'duplicate_analog', False),
    ('reordered_originals', True, DECLARED, 0, 'reordered_originals', False),
]


def sha(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


def one_frame(native, app):
    """Frame an APDU as ONE link frame with the native's link header fields and transport sequence (FIR|FIN), every
    CRC valid: a well-formed DNP3 response, so only the master's content check can reject it."""
    frames = gp.split_frames(native)
    assert len(frames) == 1
    hdr, user = std.deframe(frames[0])
    hdr = bytearray(hdr)
    hdr[2] = 5 + 1 + len(app)
    assert 1 + len(app) <= 250, 'crafted APDU exceeds one link frame'
    return std.frame(bytes(hdr), bytes([std.FIR | std.FIN | (user[0] & 63)]) + app)


def split_mixed(native):
    """(4-octet application header, G1V2 header+16 objects, G30V1 header+40 objects) of a native mixed response."""
    app = std.deframe(gp.split_frames(native)[0])[1][1:]
    head, body = app[:4], app[4:]
    assert body[:5] == bytes([1, 2, 0, 0, 15]) and body[21:26] == bytes([30, 1, 0, 0, 7]), body[:26].hex()
    return head, body[:21], body[21:]


def g1_header(variation, start, stop, data):
    return bytes([1, variation, 0x01]) + start.to_bytes(2, 'little') + stop.to_bytes(2, 'little') + data


def tampered_mixed(native, kind):
    head, bi, ai = split_mixed(native)
    pad = g1_header(2, 1024, 1049, bytes(26))
    if kind == 'pad_index_shift':
        app = head + g1_header(2, 1025, 1050, bytes(26)) + bi + ai
    elif kind == 'pad_nonzero_flags':
        app = head + g1_header(2, 1024, 1049, b'\x01' * 26) + bi + ai
    elif kind == 'pad_after_originals':
        app = head + bi + ai + pad
    elif kind == 'pad_mixed_header':
        app = head + g1_header(2, 1000, 1025, bytes(26)) + bi + ai
    elif kind == 'pad_g1v1':
        app = head + g1_header(1, 1024, 1049, bytes(4)) + bi + ai              # 26 packed bits -> 4 octets
    elif kind == 'duplicate_analog':
        app = head + pad + bi + ai + bytes([30, 1, 0, 7, 7]) + ai[-5:]          # analog 7 again, same value
    elif kind == 'reordered_originals':
        app = head + pad + ai + bi
    else:
        raise ValueError(kind)
    return one_frame(native, app)


def corrupt_last_value(native):
    """Change the last original object octet of a single-frame response (the high byte of its last G30V1 value for
    the mixed READ) and re-frame, so every link CRC is valid again: a measurement change the strict check must
    catch, not a CRC error the stack would drop."""
    frames = gp.split_frames(native)
    assert len(frames) == 1, 'corruption case is defined for one-frame natives'
    hdr, user = std.deframe(frames[0])
    user = bytearray(user)
    user[-1] ^= 0x01
    return std.frame(hdr, bytes(user))


def run_case(root, name, pad, expect, variant, tamper, cycles):
    d = root / name
    d.mkdir(parents=True)
    stop = d / 'stop'
    env = {k: v for k, v in os.environ.items() if not k.startswith('CASE4_')}
    env.update(CASE4_PAD58B_SOCKET_GATE='1', CASE4_DB='base', CASE4_FIXTURE_VARIANT=str(variant))
    ls = socket.socket(); ls.bind(('127.0.0.1', 0)); ls.listen(1)
    reserve = socket.socket(); reserve.bind(('127.0.0.1', 0)); port = reserve.getsockname()[1]; reserve.close()
    station = subprocess.Popen([str(BINARY), 'outstation', '127.0.0.1', str(port), str(stop), '60'], env=env,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert station.stdout.readline().strip() == 'READY'
    records, errors, pending, requests = [], [], [], collections.deque()

    def proxy():
        try:
            m, _ = ls.accept(); o = socket.create_connection(('127.0.0.1', port))
            buffers = {m: bytearray(), o: bytearray()}
            with m, o:
                while True:
                    ready, _, _ = select.select([m, o], [], [], 15)
                    if not ready:
                        raise TimeoutError('idle')
                    for src in ready:
                        data = src.recv(65536)
                        if not data:
                            return
                        buffers[src] += data
                        for f in consume(buffers[src]):
                            _, u = std.deframe(f)
                            if src is m:
                                requests.append(f); o.sendall(f)
                                continue
                            pending.append(f)
                            if not u[0] & std.FIN:
                                continue
                            native = b''.join(pending); pending.clear(); q = requests.popleft()
                            func = std.deframe(q)[1][2]
                            sent, info, tampered = native, None, False
                            if func == 0x01:                       # READ: the only function this profile pads
                                body = native
                                if tamper == 'corrupt_original':
                                    body, tampered = corrupt_last_value(native), True
                                if tamper and tamper != 'corrupt_original' and len(native) == 91:
                                    sent, tampered = tampered_mixed(native, tamper), True
                                elif pad:
                                    r = gp.pad_read(q, body, TARGETS, pad_start=PAD_START, pad_stop=PAD_STOP)
                                    if r.status != 'padded':
                                        raise AssertionError('pad_read status %s for native %d' % (r.status, len(body)))
                                    sent = r.output
                                    info = {k: v for k, v in vars(r).items() if k != 'output'}
                                else:
                                    sent = body
                            m.sendall(sent)
                            records.append(dict(function=func, request=q.hex(), native=native.hex(), sent=sent.hex(),
                                                native_frames=[len(f) for f in gp.split_frames(native)],
                                                sent_frames=[len(f) for f in gp.split_frames(sent)],
                                                tampered=tampered, padding=info))
        except Exception as e:  # recorded; the case then fails on the error
            errors.append(repr(e))

    t = threading.Thread(target=proxy, daemon=True); t.start()
    menv = dict(env, CASE4_READ_SCHEDULE='mixed_full', CASE4_SBO_CYCLES=str(cycles), CASE4_READ_PAUSE_MS='0')
    if expect:
        menv['CASE4_PAD_EXPECT'] = expect
    try:
        master = subprocess.run([str(BINARY), 'master', '127.0.0.1', str(ls.getsockname()[1]), str(stop), '1', '', '8',
                                 '0'], env=menv, capture_output=True, text=True, timeout=60)
    finally:
        stop.touch()
    so, _se = station.communicate(timeout=20)
    t.join(5)
    mjson = [line for line in master.stdout.splitlines() if line.startswith('{')]
    sjson = [line for line in so.splitlines() if line.startswith('{')]
    (d / 'master.json').write_text((mjson[-1] if mjson else '{}') + '\n')
    (d / 'outstation.json').write_text((sjson[-1] if sjson else '{}') + '\n')
    (d / 'legs.json').write_text(json.dumps(records, indent=1) + '\n')
    mrec = json.loads(mjson[-1]) if mjson else {}
    reads = [r for r in records if r['function'] == 0x01]
    commands = mrec.get('read_commands', [])
    return dict(case=name, master_rc=master.returncode, master_success=bool(mrec.get('success')),
                master_read_commands_ok=bool(mrec.get('read_commands_ok')), proxy_errors=errors,
                master_stderr=master.stderr[-400:], pad_expect=mrec.get('pad_expect'),
                reads=len(reads), sbo_responses=len(records) - len(reads),
                read_classes=[c['class'] for c in commands], read_success=[c['success'] for c in commands],
                read_completed=[c['completed'] for c in commands],
                read_matches_fixture=[c['matches_fixture'] for c in commands],
                padding_points=[c.get('padding_points') for c in commands],
                read_shapes=[dict(native=r['native_frames'], sent=r['sent_frames'], tampered=r['tampered'],
                                  target=(r['padding'] or {}).get('target'),
                                  points=(r['padding'] or {}).get('padding_points'),
                                  construction=(r['padding'] or {}).get('construction')) for r in reads])


def verdict(r, want, pad):
    """The intended outcome, not merely the expected exit status."""
    clean = not r['proxy_errors'] and not r['master_stderr'].strip() and r['reads'] > 0
    if want:
        if not (clean and r['master_success'] and r['master_rc'] == 0 and all(r['read_success'])):
            return 'FAIL: positive case not accepted'
        for s in r['read_shapes']:
            n = s['native'][0] if len(s['native']) == 1 else None
            if pad:
                e = EXPECTED_SHAPES.get(n)
                if not e or (s['sent'], s['target'], s['points'], s['construction']) != (e['sent'], e['target'], e['points'], 'prefix'):
                    return 'FAIL: padded shape %r' % s
            elif s['sent'] != s['native']:
                return 'FAIL: native case altered a response %r' % s
        return 'pass'
    if not clean or r['master_success'] or r['master_rc'] == 0:
        return 'FAIL: negative case not rejected cleanly'
    first = (r['read_completed'] or [False])[0], (r['read_matches_fixture'] or [True])[0], (r['read_classes'] or [''])[0]
    if first != (True, False, 'mixed'):
        return 'FAIL: rejected for another reason (first READ completed/matches/class = %r)' % (first,)
    return 'pass'


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--out', required=True, type=pathlib.Path)
    ap.add_argument('--cycles', type=int, default=8)
    a = ap.parse_args(argv)
    a.out.mkdir(parents=True, exist_ok=False)
    results, verdicts = [], {}
    for name, pad, expect, variant, tamper, want in CASES:
        r = run_case(a.out, name, pad, expect, variant, tamper, a.cycles)
        r['expected_master_success'] = want
        r['verdict'] = verdict(r, want, pad and tamper is None)
        results.append(r); verdicts[name] = r['verdict']
        print('%-20s master_success=%-5s expected=%-5s -> %s' % (name, r['master_success'], want, r['verdict']))
    summary = dict(binary=str(BINARY), binary_sha256=sha(BINARY), build_manifest_sha256=sha(ENDPOINT / 'build/build_manifest.json'),
                   pad_read_sha256=sha(HERE / 'source/full_read_01/general_read_padding.py'), runner_sha256=sha(__file__),
                   targets=TARGETS, reserved=[PAD_START, PAD_STOP], declared=DECLARED, cycles=a.cycles,
                   tier='live software endpoints over loopback TCP through a padding proxy; NOT the switch, NOT timing',
                   verdicts=verdicts, cases=results)
    (a.out / 'summary.json').write_text(json.dumps(summary, indent=1) + '\n')
    return 0 if all(v == 'pass' for v in verdicts.values()) else 1


if __name__ == '__main__':
    sys.exit(main())

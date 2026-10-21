"""Live pinned-endpoint check of the SELECTED READ policy (software proxy; two TCP legs; no switch/timing).

Adapted from the handoff live_check.run: a response already at a target is forwarded unchanged and
recorded as such (explicit status), never counted as padded. Reserved indices 1024.. (16-bit qualifier).
"""
import argparse, collections, json, os, pathlib, select, socket, subprocess, sys, threading
HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / 'source/full_read_01'))
import general_read_padding as gp  # noqa: E402
from live_check import consume  # noqa: E402
s = gp.std
POLICY = json.loads((HERE.parent / 'policy/policy.json').read_text())
TARGETS = POLICY['selected']['targets']
START = POLICY['profile']['reserved_padding_range'][0]


def run(binary, root, name, mode, db, padded, reads=16):
    d = root / (name + ('_padded' if padded else '_native')); d.mkdir()
    stop = d / 'stop'; env = dict(os.environ, FULL_READ_GATE='1')
    ls = socket.socket(); ls.bind(('127.0.0.1', 0)); ls.listen(1)
    reserve = socket.socket(); reserve.bind(('127.0.0.1', 0)); port = reserve.getsockname()[1]; reserve.close()
    out = subprocess.Popen([str(binary), 'outstation', '127.0.0.1', str(port), str(stop), '45', db], env=env,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    records, errors, pending, requests = [], [], [], collections.deque()
    assert out.stdout.readline().strip() == 'READY'

    def proxy():
        try:
            m, _ = ls.accept(); o = socket.create_connection(('127.0.0.1', port)); buffers = {m: bytearray(), o: bytearray()}
            with m, o:
                while True:
                    ready, _, _ = select.select([m, o], [], [], 10)
                    if not ready:
                        raise TimeoutError('idle')
                    for src in ready:
                        data = src.recv(65536)
                        if not data:
                            return
                        buffers[src] += data
                        for f in consume(buffers[src]):
                            _, u = s.deframe(f)
                            if src is m:
                                requests.append(f); o.sendall(f); records.append(dict(direction='request', native=f.hex()))
                            else:
                                pending.append(f)
                                if not u[0] & s.FIN:
                                    continue
                                native = b''.join(pending); pending.clear(); q = requests.popleft(); sent = native; info = None
                                if padded:
                                    r = gp.pad_read(q, native, TARGETS, pad_start=START, pad_stop=4095)
                                    if r.status not in ('padded', 'already_at_target'):
                                        raise AssertionError(r.status)
                                    sent = r.output; info = {k: v for k, v in vars(r).items() if k != 'output'}
                                m.sendall(sent); records.append(dict(direction='response', native=native.hex(), sent=sent.hex(), padding=info))
        except Exception as e:
            errors.append(repr(e))
    t = threading.Thread(target=proxy, daemon=True); t.start()
    try:
        master = subprocess.run([str(binary), 'master', '127.0.0.1', str(ls.getsockname()[1]), str(stop), str(reads), mode, '1'],
                                env=env, capture_output=True, text=True, timeout=35)
        t.join(11)
    finally:
        stop.touch(); so, se = out.communicate(timeout=5); ls.close()
        (d / 'outstation.log').write_text(so + se); (d / 'wire.json').write_text(json.dumps(records, indent=1))
        (d / 'errors.json').write_text(json.dumps(errors))
    (d / 'master.json').write_text(master.stdout); (d / 'master.stderr').write_text(master.stderr)
    assert not errors, errors
    assert not t.is_alive() and master.returncode == 0
    result = json.loads(master.stdout)
    assert len(result['scans']) == reads and all(x['completed'] for x in result['scans'])
    assert result['tasks'] == {'SUCCESS': reads}, result['tasks']
    return result, records


def main():
    ap = argparse.ArgumentParser(); ap.add_argument('--binary', required=True); ap.add_argument('--output', required=True); a = ap.parse_args()
    binary = pathlib.Path(a.binary).resolve(); root = pathlib.Path(a.output).resolve(); root.mkdir(parents=True, exist_ok=False)
    summary = []
    for name, mode, db in [('range', 'range', 'base'), ('analog', 'analog', 'base'), ('class0', 'class0', 'base'),
                           ('integrity', 'integrity', 'base'), ('segmented', 'integrity', 'large')]:
        native, _ = run(binary, root, name, mode, db, False)
        padded, records = run(binary, root, name, mode, db, True)
        resp = [r for r in records if r['direction'] == 'response']
        for a_, b_, r in zip(native['scans'], padded['scans'], resp):
            assert all(b_['points'][k] == v for k, v in a_['points'].items())
            n = r['padding']['padding_points']; extra = set(b_['points']) - set(a_['points'])
            assert extra == {'bi:' + str(i) for i in range(START, START + n)}
            assert all(b_['points'][k] == [0, 0] for k in extra)
            assert len(bytes.fromhex(r['sent'])) == r['padding']['target'] and r['padding']['target'] in TARGETS
        assert native['iin'] == padded['iin'] and native['other_types'] == padded['other_types']
        st = resp[0]['padding']
        summary.append(dict(name=name, mode=mode, db=db, reads=16, status=st['status'], construction=st['construction'] if st['status'] == 'padded' else None,
                            target=st['target'], padding_points=st['padding_points'],
                            native_frames=[len(x) for x in gp.split_frames(bytes.fromhex(resp[0]['native']))],
                            output_frames=[len(x) for x in gp.split_frames(bytes.fromhex(resp[0]['sent']))],
                            originals_preserved=True, iin=padded['iin'], tasks=padded['tasks']))
        print(name, 'PASS', summary[-1], flush=True)
    (root / 'summary.json').write_text(json.dumps(summary, indent=1))


if __name__ == '__main__':
    main()

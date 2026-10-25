"""Bound SEL-751 master workload. Uses only active Session and frozen guarded builders."""
import os
from pathlib import Path
import sys
import time
import socket
import struct

sys.path.insert(0, str(Path(__file__).resolve().parent / 'active_harness'))
# Repository checkout and deployed helper use the same master sources.
if not (Path(__file__).resolve().parent / 'active_harness').is_dir():
    sys.path.insert(0, str(Path(__file__).resolve().parents[3] / 'active_harness'))

from session import Session
from sbo_driver import one_sbo, guarded
from read_requests import mixed_read_frame, integrity_read_frame
from dnp3_codec import FUNC_READ, FUNC_SELECT, FUNC_OPERATE, parse_frame
from endpoint_profiles import MASTER_IP, RELAY_IP, RELAY_PORT


def preflight():
    """Validate the deployed import/build closure without instantiating a Session or socket."""
    frames = [guarded(function, seq, [1, 3]) for function, seq in ((FUNC_SELECT, 0), (FUNC_OPERATE, 1))]
    for frame in frames + [mixed_read_frame(2), integrity_read_frame(3)]:
        decoded, rest = parse_frame(frame)
        if decoded is None or rest:
            raise ValueError('deployed builder emitted an invalid frame')
    if [len(frame) for frame in frames] != [45, 45]:
        raise ValueError('deployed guarded control builders do not emit the physical two-CROB request shape')
    return dict(ok=True, endpoint_profile='sel751', control_request_lengths=[len(frame) for frame in frames],
                socket_opened=False)


def workload(master_port, reads, schedule='mixed_full', sbo_cycles=0, run_sbo=True,
             gap_ms=0, read_pause_ms=25, close_grace_ms=0, budget_ms=3000, close_mode='graceful',
             loss_target=None):
    if os.environ.get('DEFENSE4_HW_AUTHORIZED') != '1':
        raise ValueError('relay master requires DEFENSE4_HW_AUTHORIZED=1')
    if not 1024 <= master_port <= 65535 or reads < 1 or sbo_cycles < 0 or sbo_cycles >= reads:
        raise ValueError('invalid bounded relay workload')
    if schedule not in ('mixed_full', 'mixed', 'full'):
        raise ValueError('unsupported relay READ schedule')
    if close_mode not in ('graceful', 'rst'):
        raise ValueError('unsupported physical close mode')
    records, seq = [], 0
    order = ('mixed', 'integrity') if schedule == 'mixed_full' else (('mixed',) if schedule == 'mixed' else ('integrity',))
    def sbo(session):
        nonlocal seq
        selected, operated = one_sbo(session, seq & 15, (seq + 1) & 15, [1, 3], budget_ms, False)
        seq += 2
        records.extend([selected.as_dict(), operated.as_dict()])
        return selected.ok and operated.ok
    with Session(RELAY_IP, RELAY_PORT, source_address=(MASTER_IP, master_port)) as session:
        if loss_target is not None:
            # identity loss (relay_loss.RelayLoss): ISNs now, then every request passes through before_send, which
            # arms the u32 rule immediately before the target leaves; a failure there raises before the send.
            loss_target.on_connect()
            send = session.transaction
            def transaction(**kwargs):
                loss_target.before_send(kwargs['operation'], kwargs['frame'], session.sock)
                return send(**kwargs)
            session.transaction = transaction
        for i in range(reads):
            if i and i <= sbo_cycles and not sbo(session):
                break
            name = order[i % len(order)]
            builder = mixed_read_frame if name == 'mixed' else integrity_read_frame
            groups = {(1, 2), (30, 1)} if name == 'mixed' else {(1, 2), (10, 2), (30, 4)}
            outcome = session.transaction(operation='READ', frame=builder(seq & 15), function=FUNC_READ,
                                          app_seq=seq & 15, budget_ms=budget_ms, expect_read_groups=groups,
                                          expect_read_workload=name)
            rec = outcome.as_dict()
            rec['workload'] = name
            records.append(rec)
            seq += 1
            if not outcome.ok:
                break
            time.sleep((read_pause_ms + gap_ms) / 1000)
        if run_sbo and not sbo_cycles and len(records) == reads and all(r['outcome'] == 'OK' for r in records):
            sbo(session)
        time.sleep(close_grace_ms / 1000)
        if close_mode == 'rst':
            session.sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
    expected_sbo = sbo_cycles if sbo_cycles else int(run_sbo)
    counts = {name: sum(r['operation'] == name and r['outcome'] == 'OK' for r in records)
              for name in ('READ', 'SELECT', 'OPERATE')}
    ok = counts == dict(READ=reads, SELECT=expected_sbo, OPERATE=expected_sbo)
    return dict(schema='sel751-master-v1', endpoint_profile='sel751', ok=ok, records=records,
                counts=counts, planned=dict(READ=reads, SELECT=expected_sbo, OPERATE=expected_sbo),
                read_pause_ms=read_pause_ms, run_sbo=run_sbo, close_grace_ms=close_grace_ms,
                sbo_cycles=sbo_cycles, read_schedule=schedule,
                close_mode=close_mode,
                observation_scope='master application/socket; TCP ACK evidence requires pcap')


if __name__ == '__main__':
    import argparse
    import json
    parser = argparse.ArgumentParser(description='Read-only deployed relay-helper and frozen-builder preflight')
    parser.add_argument('--preflight', action='store_true', required=True)
    parser.parse_args()
    import vision_run, endpoint_profiles, relay_check, capture_observation, wire_check, loss, relay_loss
    print(json.dumps(preflight()))

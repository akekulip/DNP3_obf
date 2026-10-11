#!/usr/bin/env python3
"""Tofino-model driver for the single-pipe candidate (simplify/single_pipe/single_pipe.p4).

Run inside integration/core/launch_model.sh (it sets PROG, OUT, SDE, MODEL_GRPC). Phase P (padding through the
timing ingress, timing left at its unconfigured defaults):

  1. the master's SYN with the rig's real option set (MSS, SACK-permitted, Timestamps, NOP, WScale) leaves the
     relay port with MSS followed by 16 NOP bytes and a valid TCP checksum (edit S2);
  2. the outstation's MSS-only SYN-ACK reaches the master unchanged and arms the mapper (ARM_MAP);
  3. a READ round trip: request and master ACKs reverse-mapped on 64 (edit S3's fold on the reverse path), the
     outstation's 49-byte response padded to the 58-byte image on 9 with valid CRCs and checksums, the master's
     ACK of the image translated back.

Expected frames come from independent software: vectors.packet / frames (RFC 1071 checksums), the pad58b
codec and case4_response_mapper.ResponseMapper, the same oracles the composite driver uses. Model results are
functional only; the model clock is not timing evidence.
"""
import hashlib
import json
import os
import struct
import sys
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
CASE4 = HERE.parent.parent
INTEG = CASE4 / 'integration'
SDE_PY = os.environ.get('SDE', '/tmp/claude-0/sde') + '/install/lib/python3.13/site-packages'
sys.path[:0] = [SDE_PY, SDE_PY + '/tofino', SDE_PY + '/tofino/bfrt_grpc', str(HERE), str(INTEG / 'core'),
                str(INTEG / 'core' / 'harness'), str(INTEG / 'connection' / 'binding' / 'tests'),
                str(CASE4 / 'protocol'), str(CASE4.parent / 'framework' / 'size')]
from model_driver import Model, Report, same_frame, gc  # noqa: E402
import case4_pad58b as b  # noqa: E402
import case4_response_mapper as rm  # noqa: E402
import cp_single_pipe as cps  # noqa: E402
import read_support as rs  # noqa: E402
import response_path_cp as rp  # noqa: E402
import vectors  # noqa: E402

MASTER_PORT, RELAY_PORT = cps.MASTER_PORT, cps.RELAY_PORT
MASTER = rp.Endpoint('10.0.0.1', vectors.CLIENT_PORT, MASTER_PORT)
OUTSTATION = rp.Endpoint('10.0.0.2', vectors.SERVER_PORT, RELAY_PORT)
CODES = dict(commit=1, translate=2, zero=3, replay=4, stale=5, rev_translate=9, rev_withhold=10, native=12,
             arm_map=13, arm_nat=14)
MSS = 1460
TS = (868055293, 0)


def syn_with_options(options, seq=100):
    """vectors.packet's layout with an arbitrary option block (master -> outstation SYN)."""
    src, dst, sport, dport = vectors.CLIENT, vectors.SERVER, vectors.CLIENT_PORT, vectors.SERVER_PORT
    tcp = struct.pack('!HHIIBBHHH', sport, dport, seq, 0, ((20 + len(options)) // 4) << 4, 2, 4096, 0, 0) + options
    pseudo = struct.pack('!IIBBH', src, dst, 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack('!H', vectors.checksum(pseudo + tcp)) + tcp[18:]
    ip = struct.pack('!BBHHHBBHII', 0x45, 0, 20 + len(tcp), 1, 0x4000, 64, 6, 0, src, dst)
    ip = ip[:10] + struct.pack('!H', vectors.checksum(ip)) + ip[12:]
    return bytes.fromhex('001122334455aabbccddeeff0800') + ip + tcp


RIG_OPTIONS = (struct.pack('!BBH', 2, 4, MSS) + bytes((4, 2)) + struct.pack('!BBII', 8, 10, *TS) + bytes((1,))
               + bytes((3, 3, 7)))
SCRUBBED = struct.pack('!BBH', 2, 4, MSS) + bytes([1]) * 16
assert len(RIG_OPTIONS) == len(SCRUBBED) == 20


def main():
    out_dir = Path(os.environ['OUT'])
    rep = Report(os.environ['PROG'], physical=False,
                 driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                 scope='single-pipe candidate, phase P: SYN scrub, mapper arming, READ padded through the timing ingress')
    ok = False
    try:
        m = Model(ports=[], enable=False)
        m.enable_ports([MASTER_PORT, RELAY_PORT, 8, 10, 68])
        import time
        time.sleep(2.0)
        rep.record['meta']['port_enable_errors'] = m.port_errors
        rows = cps.e_conn_rows(0, OUTSTATION, MASTER)
        for table, key, action, data, priority in rows:
            m.add('pipe.r_' + table, dict(key), 'r_' + action, dict(data), priority)
        rep.record['meta']['rows'] = [[t, list(k), a, list(d), p] for t, k, a, d, p in rows]
        counter = m.table('pipe.r_Egress.outcome')

        def counts():
            for op in ('Sync', 'SyncCounters'):
                try:
                    counter.operations_execute(m.target, op)
                    break
                except Exception:
                    pass
            got = {}
            for code in range(16):
                for data, _k in counter.entry_get(m.target, [counter.make_key([gc.KeyTuple('$COUNTER_INDEX', code)])],
                                                  {'from_hw': True}):
                    v = data.to_dict()['$COUNTER_SPEC_PKTS']
                    got[code] = sum(v) if isinstance(v, list) else v
            return got

        ports = [MASTER_PORT, RELAY_PORT]

        def step(name, in_port, sent, want_port, want_frame, want_codes):
            m.drain(ports)
            before = counts()
            got = m.exchange(in_port, sent, ports, timeout=2.0, quiet=0.5)
            after = counts()
            other = [p for p in ports if p != want_port]
            good = (len(got[want_port]) == 1 and same_frame(got[want_port][0], want_frame, sent)
                    and not any(got[p] for p in other))
            rep.add(name, 'frame', 'frame' if good else 'mismatch', ok=good,
                    received={p: [g.hex() for g in got[p]] for p in ports}, want=want_frame.hex())
            delta = {c: after[c] - before[c] for c in after if after[c] != before[c]}
            rep.add(name + '_outcomes', want_codes, delta)
            return got

        sw = rm.ResponseMapper(merged_suffix_ok=False)
        # 1. SYN scrub
        step('master_SYN_options_scrubbed_on_relay_port', MASTER_PORT, syn_with_options(RIG_OPTIONS), RELAY_PORT,
             syn_with_options(SCRUBBED), {CODES['native']: 1})
        # 2. MSS-only SYN-ACK arms the mapper
        synack = vectors.packet(18, 900, 101, reverse=True, mss=MSS)
        sw.syn_ack(900)
        step('outstation_SYNACK_arms_mapper', RELAY_PORT, synack, MASTER_PORT, synack, {CODES['arm_map']: 1})
        # 3. handshake ACK, reverse path
        r = sw.reverse(901, 4096)
        step('master_handshake_ACK_reverse_mapped', MASTER_PORT, vectors.packet(16, 101, 901), RELAY_PORT,
             vectors.packet(16, 101, r.ack), {CODES['rev_' + r.case]: 1})
        # 4. READ request
        r = sw.reverse(901, 4096)
        req = rs.request_frame()
        step('READ_request_reverse_mapped', MASTER_PORT, vectors.packet(24, 101, 901, payload=req), RELAY_PORT,
             vectors.packet(24, 101, r.ack, payload=req), {CODES['rev_' + r.case]: 1})
        nxt = 101 + len(req)
        # 5. outstation pure ACK of the request
        f = sw.forward(901, 0)
        step('outstation_ACK_forwarded', RELAY_PORT, vectors.packet(16, 901, nxt, reverse=True), MASTER_PORT,
             vectors.packet(16, f.seq, nxt, reverse=True), {CODES[f.case] if f.case in CODES else 0: 1})
        # 6. READ response padded to the 58-byte image
        resp = rs.response_frame()
        image, delta = b.pad_read_response(resp)
        f = sw.forward(901, len(resp), delta)
        rep.add('oracle_READ_response_commits_and_pads', ('commit', 9, 58), (f.case, delta, len(image)))
        step('READ_response_padded_to_master', RELAY_PORT, vectors.packet(24, 901, nxt, reverse=True, payload=resp),
             MASTER_PORT, vectors.packet(24, f.seq, nxt, reverse=True, payload=image), {CODES[f.case]: 1})
        # 7. master ACKs the image; the reverse path maps it back to the outstation's sequence space
        r = sw.reverse(901 + len(image), 4096)
        rep.add('oracle_master_ACK_maps_back', ('translate', 901 + len(resp)), (r.case, r.ack))
        step('master_ACK_of_image_mapped_back', MASTER_PORT, vectors.packet(16, nxt, 901 + len(image)), RELAY_PORT,
             vectors.packet(16, nxt, r.ack), {CODES['rev_' + r.case]: 1})
        ok = True
    except BaseException as error:
        rep.record['error'] = type(error).__name__ + ': ' + str(error)
        rep.record['traceback'] = traceback.format_exc()
        rep.add('execution', 'completed', 'error', ok=False)
    finally:
        passed = rep.finish(str(out_dir / 'cases.json'))
        (out_dir / 'driver_source.py').write_bytes(Path(__file__).read_bytes())
        (out_dir / 'input_sources.json').write_text(json.dumps(
            {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
             for p in (HERE / 'single_pipe.p4', HERE / 'cp_single_pipe.py', HERE / 'make_single_pipe.py')}, indent=2) + '\n')
    return 0 if (ok and passed) else 1


if __name__ == '__main__':
    sys.exit(main())

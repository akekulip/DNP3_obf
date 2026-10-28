#!/usr/bin/env python3
"""Replay retained c72 padded READ responses, transport wraps included, to the opendnp3 master in pydnp3.

tshark 4.4.9 cannot reassemble a two-segment response whose transport sequence goes 63 -> 0 (valid modulo 64). This
feeds the EXACT retained bytes of each padded connection (relay_wire.json) to an independent reassembly implementation.
- A localhost "replay outstation" answers each READ fragment with the next retained READ response, in recorded order.
  SELECT/OPERATE are not replayed (READ only); any other request is recorded and left unanswered, nothing synthesised.
- The master's link addresses are the recorded ones, so retained link headers are delivered unmodified. It issues each
  READ with the recorded object headers (Header.Range8/Range16/AllObjects via IMaster.Scan); the server checks that the
  live function and object bytes equal the recorded request.
- opendnp3 matches the response APPLICATION sequence to its request. Where they differ, ONLY that nibble of the
  application control byte is rewritten and the CRC of the data block holding it recomputed; transport headers are
  never touched in the test run. Every changed byte is recorded.
- Pass per response: task SUCCESS, SOEHandler callbacks (group/variation/qualifier, indices, values) equal to the
  repository codec's decode of the retained bytes, no WARN/ERR log entry, live request equal to the recorded one.
  Per run: opendnp3 transport/link error counters stay 0 and no unexpected request arrives.
- CONTROL: the same replay with wrap responses renumbered by independent_decode.renumber (sequences 0, 1).
- NEGATIVE CONTROL: one wrap response with its second segment numbered 5 instead of 0 must be rejected.
Scope: offline, localhost, no hardware contact; one master implementation (opendnp3 2.x inside pydnp3).

  python3 scripts/analysis/opendnp3_wrap_check.py --output results/analysis/opendnp3_wrap/opendnp3_wrap.json
"""
import argparse
import json
import os
from pathlib import Path
import re
import socket
import sys
import threading
import time

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'scripts/hardware/active_harness'))
sys.path.insert(0, str(REPO / 'scripts/analysis'))
import dnp3_codec  # noqa: E402
import independent_decode as idec  # noqa: E402

SCHEMA = 'c72-opendnp3-wrap-check-v1'
PREFIX = 'rc01_hw_c72_eval_20261027_01'
PADDED_ARMS = ('combined', 'size_only')
DEFAULT_BLOCKS = ('e01_d5_r01', 'e02_d10_r01', 'e03_d15_r01', 'e04_d20_r01')
TRANSPORT_RX_ERRORS = ('numTransportErrorRx', 'numTransportIgnore', 'numTransportDiscard', 'numTransportBufferOverflow')
LINK_ERRORS = ('numUnexpectedFrame', 'numUnknownSource', 'numUnknownDestination', 'numBadMasterBit')
LOG_ERR, LOG_WARN, LOG_TRANSPORT_RX = 2, 4, 512
LOG_LEVELS = 15 | LOG_TRANSPORT_RX | 2048            # NORMAL | TRANSPORT_RX | APP_HEADER_RX
FINISHED = []


def first_block_crc(p, length):
    """Offsets of the CRC octets of a frame's first data block (frame at p, total length `length`)."""
    block = min(16, length - 12)
    return p + 10 + block, p + 11 + block


def label(wire, offset):
    frames = idec.link_frames(wire)
    if offset == frames[0][0] + 11:
        return 'app_ctrl'
    for p, length in frames:
        if offset == p + 10:
            return 'transport'
        if offset in first_block_crc(p, length):
            return 'block_crc'
    return 'other'


def byte_changes(retained, sent):
    return [dict(offset=i, field=label(retained, i), old='%02x' % a, new='%02x' % b)
            for i, (a, b) in enumerate(zip(retained, sent)) if a != b]


def set_app_seq(wire, seq):
    """Rewrite only the application-sequence nibble and the CRC of the data block holding it."""
    p, length = idec.link_frames(wire)[0]
    if not wire[p + 10] & dnp3_codec.TRANSPORT_FIR:
        raise ValueError('first link frame is not a FIR transport segment')
    out = bytearray(wire)
    out[p + 11] = (out[p + 11] & 0xf0) | (seq & 15)
    lo, hi = first_block_crc(p, length)
    out[lo:hi + 1] = dnp3_codec.crc_le(bytes(out[p + 10:lo]))
    out = bytes(out)
    return out, byte_changes(wire, out)


def prepare(wire, seq, control=False):
    """Bytes to send for a live request sequence: optional wrap renumbering (control only), then the app nibble."""
    base = idec.renumber(wire) if control and idec.wraps(wire) else wire
    sent, _ = set_app_seq(base, seq)
    return sent, byte_changes(wire, sent)


def application_fragment(wire):
    frames = [dnp3_codec.parse_frame(wire[p:p + n])[0] for p, n in idec.link_frames(wire)]
    return dnp3_codec.reassemble_application(frames)[0]


def wrap_indices(exchanges):
    return [i for i, e in enumerate(exchanges) if idec.wraps(bytes.fromhex(e['response']['wire_hex']))]


def scan_headers(request_app_hex):
    """Recorded READ request -> opendnp3 header specs that re-encode the same object bytes."""
    app = bytes.fromhex(request_app_hex)
    if len(app) < 2 or app[1] != dnp3_codec.FUNC_READ:
        raise ValueError('not a READ request: %s' % request_app_hex)
    p, specs = 2, []
    while p < len(app):
        group, variation, qualifier = app[p:p + 3]
        p += 3
        if qualifier == 0x06:
            specs.append(('all', group, variation))
            continue
        if qualifier not in (0x00, 0x01):
            raise ValueError('qualifier 0x%02x has no opendnp3 Scan mapping' % qualifier)
        w = 1 + qualifier                                    # 0x00: 8-bit start/stop, 0x01: 16-bit
        specs.append(('range%d' % (8 * w), group, variation, int.from_bytes(app[p:p + w], 'little'),
                      int.from_bytes(app[p + w:p + 2 * w], 'little')))
        p += 2 * w
    return specs


def codec_view(app_hex):
    """Repository codec decode: problems and [{group, variation, qualifier, points: [[index, value], ...]}]."""
    r = dnp3_codec.parse_application_response(bytes.fromhex(app_hex))
    return list(r.problems), [dict(group=o['group'], variation=o['variation'], qualifier=o['qualifier'],
                                   points=[[pt['index'], pt['value']] for pt in o['points']]) for o in r.objects]


class ReplayOutstation(threading.Thread):
    """Localhost TCP server that answers READ fragments with retained response bytes, in order."""

    def __init__(self, wires, control):
        super().__init__(daemon=True)
        self.wires, self.control = wires, control
        self.sock = socket.create_server(('127.0.0.1', 0))
        self.sock.settimeout(15)
        self.port = self.sock.getsockname()[1]
        self.records, self.unexpected, self.errors, self.link = [], [], [], set()

    def run(self):
        try:
            conn, _ = self.sock.accept()
            frames, transport = dnp3_codec.Reassembler(), dnp3_codec.TransportAssembler()
            while True:
                data = conn.recv(65536)
                if not data:
                    break
                frames.feed(data)
                for frame in frames.frames():
                    self.link.add((frame.destination, frame.source))
                    if frame.control & 0x0f not in (3, 4) or not frame.user_data:
                        self.unexpected.append(dict(link_control='%02x' % frame.control))
                        continue
                    fragment = transport.add(frame.user_data)
                    if fragment is not None:
                        self.answer(conn, fragment)
            conn.close()
        except Exception as exc:                            # recorded, never hidden
            self.errors.append('%s: %s' % (type(exc).__name__, exc))
        finally:
            self.sock.close()

    def answer(self, conn, fragment):
        if fragment[1] != dnp3_codec.FUNC_READ or len(self.records) >= len(self.wires):
            self.unexpected.append(dict(app_hex=fragment.hex()))   # left unanswered: fail closed
            return
        retained = self.wires[len(self.records)]
        sent, changes = prepare(retained, fragment[0] & 15, self.control)
        self.records.append(dict(live_request_app_hex=fragment.hex(), byte_changes=changes,
                                 sent_transport_seqs=[sent[p + 10] & 0x3f for p, _ in idec.link_frames(sent)]))
        conn.sendall(sent)


class Master:
    """One pydnp3 (opendnp3) master on one TCP channel; one READ task at a time."""

    def __init__(self, port, local, remote, timeout_s=2):
        from pydnp3 import asiodnp3, asiopal, opendnp3, openpal
        self.od, self.log, self.lock = opendnp3, [], threading.Lock()
        self.opened, self.done = threading.Event(), threading.Event()
        self.fragment, self.completion = [], None
        owner = self

        class LogHandler(openpal.ILogHandler):
            def Log(self, entry):
                with owner.lock:
                    owner.log.append((entry.filters.GetBitfield(), entry.loggerid, entry.message))

        class SOE(opendnp3.ISOEHandler):
            def Process(self, info, values):
                base = getattr(opendnp3, type(values).__name__.replace('ICollection', 'IVisitor'))

                class Visitor(base):
                    def __init__(self):
                        super().__init__()
                        self.points = []

                    def OnValue(self, x):
                        self.points.append([x.index, x.value.value])
                visitor = Visitor()
                values.Foreach(visitor)
                group, variation = map(int, re.search(r'Group(\d+)Var(\d+)', str(info.gv)).groups())
                owner.fragment.append(dict(group=group, variation=variation, qualifier=int(info.qualifier),
                                           points=visitor.points))

            def Start(self):
                pass

            def End(self):
                pass

        class App(opendnp3.IMasterApplication):
            def OnOpen(self):
                owner.opened.set()

            def OnTaskComplete(self, info):
                owner.completion = str(info.result).split('.')[-1]
                owner.done.set()

            def AssignClassDuringStartup(self):
                return False

            def Now(self):
                return openpal.UTCTimestamp()

        self.handlers = (LogHandler(), SOE(), App())
        self.manager = asiodnp3.DNP3Manager(1, self.handlers[0])
        self.channel = self.manager.AddTCPClient('replay', LOG_LEVELS, asiopal.ChannelRetry().Default(),
                                                 '127.0.0.1', '0.0.0.0', port, None)
        cfg = asiodnp3.MasterStackConfig()
        cfg.master.responseTimeout = openpal.TimeDuration().Seconds(timeout_s)
        cfg.master.disableUnsolOnStartup = False             # no startup traffic: only the replayed READs
        cfg.master.startupIntegrityClassMask = opendnp3.ClassField()
        cfg.master.unsolClassMask = opendnp3.ClassField()
        cfg.master.eventScanOnEventsAvailableClassMask = opendnp3.ClassField()
        cfg.master.integrityOnEventOverflowIIN = False
        cfg.master.ignoreRestartIIN = True                   # the retained IIN carries DEVICE_RESTART
        cfg.link.LocalAddr, cfg.link.RemoteAddr = local, remote
        self.master = self.channel.AddMaster('master', self.handlers[1], self.handlers[2], cfg)
        self.master.Enable()
        if not self.opened.wait(10):
            raise RuntimeError('opendnp3 channel did not open')

    def stats(self, quiet_s=0.5):
        """Error counters, read once at the end of a run. GetStackStatistics blocks while holding the GIL, and the
        DNP3 thread needs the GIL to log, so it is called only after the log has been quiet for `quiet_s`."""
        while True:
            count = len(self.log)
            time.sleep(quiet_s)
            if len(self.log) == count:
                break
        s = self.master.GetStackStatistics()
        return dict({n: getattr(s.transport.rx, n) for n in TRANSPORT_RX_ERRORS},
                    **{n: getattr(s.link, n) for n in LINK_ERRORS})

    def read(self, specs, wait_s=6):
        build = dict(all=self.od.Header.AllObjects, range8=self.od.Header.Range8, range16=self.od.Header.Range16)
        headers = [build[s[0]](*s[1:]) for s in specs]
        mark = len(self.log)
        self.fragment, self.completion = [], None
        self.done.clear()
        self.master.Scan(headers, self.od.TaskConfig().Default())
        completion = self.completion if self.done.wait(wait_s) else 'NO_TASK_COMPLETION'
        with self.lock:
            entries = self.log[mark:]
        return dict(observed=list(self.fragment), completion=completion,
                    warnings=[m for f, _, m in entries if f & (LOG_ERR | LOG_WARN)],
                    transport_rx=[m for f, _, m in entries if f & LOG_TRANSPORT_RX])

    def close(self):
        """Observed: Disable/IChannel.Shutdown, or Shutdown with live master/channel refs, deadlock (GIL vs
        callbacks); freeing the manager or handlers double-frees. So: drop refs, Shutdown, keep the rest alive."""
        del self.master, self.channel
        self.manager.Shutdown()
        FINISHED.append(self)


def link_addresses(read):
    response = dnp3_codec.parse_frame(bytes.fromhex(read['response']['wire_hex']))[0]
    request = dnp3_codec.parse_frame(bytes.fromhex(read['request']['wire_hex']))[0]
    if (request.destination, request.source) != (response.source, response.destination):
        raise ValueError('recorded request/response link addresses are not mirrored')
    return dict(master=response.destination, outstation=response.source)


def replay(reads, indices, control):
    wires = [bytes.fromhex(reads[k]['response']['wire_hex']) for k in indices]
    addresses = link_addresses(reads[indices[0]])
    server = ReplayOutstation(wires, control)
    server.start()
    master = Master(server.port, addresses['master'], addresses['outstation'])
    rows = []
    try:
        for n, k in enumerate(indices):
            e = reads[k]
            result = master.read(scan_headers(e['application']['request_app_hex']))
            problems, expected = codec_view(e['application']['response_app_hex'])
            record = server.records[n] if n < len(server.records) else {}
            live = record.get('live_request_app_hex', '')
            row = dict(read_index=k, exchange_index=e['_index'], workload=e['workload'], wrap=idec.wraps(wires[n]),
                       recorded_app_seq=int(e['application']['response_app_hex'][:2], 16) & 15,
                       live_app_seq=int(live[:2], 16) & 15 if live else None,
                       request_match=live[2:] == e['application']['request_app_hex'][2:],
                       byte_changes=record.get('byte_changes'), sent_transport_seqs=record.get('sent_transport_seqs'),
                       completion=result['completion'], values_match=result['observed'] == expected,
                       points=sum(len(o['points']) for o in expected), codec_problems=problems,
                       warnings=result['warnings'], transport_rx=result['transport_rx'])
            row['ok'] = (row['request_match'] and row['completion'] == 'SUCCESS' and row['values_match']
                         and not (problems or row['warnings']))
            if not row['values_match']:
                row['observed'], row['expected'] = result['observed'], expected
            rows.append(row)
        counters = master.stats()
    finally:
        master.close()
        server.join(5)
    out = dict(replayed=len(rows), wrap=sum(r['wrap'] for r in rows), delivered_ok=sum(r['ok'] for r in rows),
               errors=sum(not r['ok'] for r in rows), stack_error_counters=counters, link_addresses=addresses,
               live_link_addresses_match=server.link == {(addresses['outstation'], addresses['master'])},
               unexpected_requests=server.unexpected, server_errors=server.errors,
               transport_bytes_changed=sum(c['field'] == 'transport' for r in rows for c in r['byte_changes'] or []),
               responses=rows)
    out['run_ok'] = (out['errors'] == 0 and not any(counters.values()) and out['live_link_addresses_match']
                     and not (server.unexpected or server.errors))
    return out


def load(directory):
    """All exchanges of one connection (each tagged with its recorded position) and the READ subset."""
    exchanges = json.loads((Path(directory) / 'relay_wire.json').read_text())['exchanges']
    for i, e in enumerate(exchanges):
        e['_index'] = i
    return exchanges, [e for e in exchanges if e['operation'] == 'READ']


def check_connection(directory, reads=None):
    """Test run (retained bytes) and control run (wraps renumbered) for one connection."""
    directory = Path(directory).resolve()
    exchanges, read_exchanges = load(directory)
    indices = list(reads) if reads is not None else list(range(len(read_exchanges)))
    return dict(connection=str(directory.relative_to(REPO)), arm=directory.parent.name,
                d_ms=int(re.search(r'_d(\d+)_', directory.parents[2].name).group(1)),
                read_responses=len(read_exchanges),
                wrap_responses_all_operations=[dict(exchange_index=i, operation=exchanges[i]['operation'])
                                               for i in wrap_indices(exchanges)],
                test=replay(read_exchanges, indices, control=False),
                control=replay(read_exchanges, indices, control=True))


def resequence(wire, frame, seq):
    """Negative control only: set one frame's transport sequence and recompute that block's CRC."""
    out, (p, length) = bytearray(wire), idec.link_frames(wire)[frame]
    out[p + 10] = (out[p + 10] & 0xc0) | seq
    lo, hi = first_block_crc(p, length)
    out[lo:hi + 1] = dnp3_codec.crc_le(bytes(out[p + 10:lo]))
    return bytes(out)


def negative_control(directory, seq=5):
    """The first READ wrap response with its second segment numbered `seq` instead of 0 must be rejected."""
    _, reads = load(directory)
    k = next(n for n, e in enumerate(reads) if idec.wraps(bytes.fromhex(e['response']['wire_hex'])))
    reads[k]['response']['wire_hex'] = resequence(bytes.fromhex(reads[k]['response']['wire_hex']), 1, seq).hex()
    run = replay(reads, [k], control=False)
    return dict(connection=str(Path(directory).resolve().relative_to(REPO)), read_index=k, second_segment_seq=seq,
                rejected=run['errors'] == 1 and run['responses'][0]['completion'] != 'SUCCESS', run=run)


def summarize(run):
    return {k: run[k] for k in ('replayed', 'wrap', 'delivered_ok', 'errors', 'transport_bytes_changed', 'run_ok')}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--campaign-prefix', default=PREFIX)
    parser.add_argument('--blocks', nargs='+', default=list(DEFAULT_BLOCKS),
                        help='block suffixes or globs, e.g. e01_d5_r01 or "*"')
    args = parser.parse_args(argv)
    import pydnp3                                           # an import failure is the blocker: let it raise
    reports, started = [], time.time()
    for block in args.blocks:
        for arm in PADDED_ARMS:
            for trial in sorted((REPO / 'results/hardware/blocks').glob(
                    '%s_%s/physical_relay/%s/*_t*' % (args.campaign_prefix, block, arm))):
                report = check_connection(trial)
                reports.append(report)
                print(json.dumps(dict(connection=report['connection'], test=summarize(report['test']),
                                      control=summarize(report['control']))), flush=True)
    total = {run: {k: sum(r[run][k] for r in reports) for k in summarize(reports[0][run])} for run in
             ('test', 'control')} if reports else {}
    negative = negative_control(REPO / reports[0]['connection']) if reports else None
    out = dict(schema=SCHEMA, campaign_prefix=args.campaign_prefix, blocks=args.blocks, arms=list(PADDED_ARMS),
               master='opendnp3 2.x (asiodnp3 API) statically linked in pydnp3 0.1.0, ChargePoint fork build; '
                      'exact opendnp3 release not recorded in the binary',
               pydnp3=pydnp3.__file__, python=sys.version.split()[0], seconds=round(time.time() - started, 1),
               method=__doc__.strip(),
               scope='offline localhost replay of master-NIC captures to one master implementation; READ exchanges '
                     'only; not relay-side preservation; no hardware contact',
               totals=total, negative_control=negative, connections=reports)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(out, indent=1, sort_keys=True) + '\n')
    print(json.dumps(dict(total, negative_control_rejected=negative and negative['rejected'])))
    passed = reports and negative['rejected'] and all(r[run]['run_ok'] for r in reports for run in ('test', 'control'))
    return 0 if passed else 1


if __name__ == '__main__':
    code = main()
    sys.stdout.flush()
    os._exit(code)                                          # pydnp3 double-frees at interpreter teardown

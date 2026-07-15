"""
ack_separation_probe.py -- Phase-2A socket-level ACK-separation experiment.

Research question (plan section 5A)
-----------------------------------
For a flow where the outstation currently PIGGYBACKS its TCP ACK onto the DNP3
response (a single "ACK-bearing DNP3 response" segment), can we induce the host
TCP stack to instead emit a PURE TCP ACK *before* the DNP3 response, purely by
DELAYING the application write() -- with NO packet forging? Forging a TCP ACK is
explicitly OUT OF SCOPE for this phase. The objective is a repeatable, natural
host behaviour that produces:

    request -> pure TCP ACK -> DNP3 response

Mechanism
---------
A TCP server receives a request, records arrival (time.monotonic_ns), prepares a
fixed-size response, DELAYS the application write() by a controlled amount, then
writes the response. If the write is delayed past the receiving kernel's delayed-
ACK timer, the kernel should emit a standalone (pure) ACK for the request first
(-> separate). If the app writes quickly, the ACK piggybacks onto the response
segment (-> combined). Whether this actually happens is a *host/kernel* behaviour,
NOT a protocol guarantee (see the section-12 caveats in the notes output).

Modes
-----
  --loopback   spawn the server in a background thread and run the client against
               127.0.0.1 from one command (dev smoke test; loopback != wire).
  --server     accept connections; per request wait the client-stated delay, then
               send a fixed-size response. (Run this on the outstation host.)
  --client     connect, and for each (socket-option config, delay, rep) send a
               request and time the round trip. (Run this on the master host.)

Socket-option sweep -- ONE FACTOR AT A TIME (plan 5A): a baseline, then server-side
TCP_NODELAY on vs off, then client-side TCP_QUICKACK where available. Each config
differs from baseline by exactly one factor; the config and the options actually
set are recorded on every row.

Detecting the pure ACK requires a packet capture. This tool uses the SAME
capability-aware approach as rto_probe.py: it does NOT trust shutil.which -- it
PROBES whether tshark can actually capture (a 1 s attempt, checking for the
permission-denied string), because dumpcap can fail with returncode 0 for a user
who lacks capture privilege. If no unprivileged capture is available (the likely
case on the dev box), the tool STILL measures request->response timing and DNP3
success per delay, and records honestly that pure-ACK EMISSION detection requires
a privileged capture (tcpdump/tshark with CAP_NET_RAW or root) and could NOT be
determined on this run. It does not guess yes/no. When a capture IS available it
analyses it to fill pure_ack_emitted, request_to_ack_ms, request_to_response_ms,
ack_to_response_ms, retransmissions, and per-rep stability.

Outputs (always overwritten; deterministic ordering):
  reports/ack_separation_matrix.csv   raw per-(config,delay,rep) rows + aggregate
  reports/ack_separation_matrix.json  structured results incl. method + environment
  reports/ack_separation_notes.md     matrix table, interpretation, socket-option
                                       findings, offload/capture caveats, the honest
                                       section-12 caveats, and the two-host rig command

Example
-------
    python3 ack_separation_probe.py --loopback
    sudo python3 ack_separation_probe.py --client --connect-host 10.10.54.158 \
        --iface eth0 --delays 0,1,2,5,10,20,50 --reps 20
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time

HARNESS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HARNESS_DIR)  # so 'lab_config' imports regardless of cwd

import lab_config as cfg

stdout_stream = logging.StreamHandler(sys.stdout)
stdout_stream.setFormatter(logging.Formatter('%(asctime)s\t%(name)s\t%(levelname)s\t%(message)s'))

_log = logging.getLogger(__name__)
_log.addHandler(stdout_stream)
_log.setLevel(logging.INFO)

# Wire format. A short control frame at connection start tells the server which
# server-side socket option to apply for this config; then a strict fixed-size
# ping-pong keeps the stream aligned. The server applies the delay carried IN each
# request (no server-side cycle to desync).
CTRL_MAGIC = b'ACFG'
CTRL_STRUCT = struct.Struct('!4si')   # magic, server_nodelay (-1=default, 0=off, 1=on)
CTRL_SIZE = 16                        # padded fixed control-frame size (bytes)
CTRL_ACK = b'AOK\x00'                 # 4-byte control acknowledgement
CTRL_ACK_SIZE = 4

REQ_MAGIC = b'AREQ'
REQ_STRUCT = struct.Struct('!4sII')   # magic, seq, requested_delay_ms
REQ_SIZE = 32                         # padded fixed request size (bytes)

RESP_MAGIC = b'ARSP'
RESP_HDR = struct.Struct('!4sII')     # magic, seq, applied_delay_ms

# Probe defaults. Response size mirrors the validated full DNP3 read response
# (~2407 B, 9 link frames) so segment counts are representative. Delays in ms.
DEFAULT_RESP_SIZE = 2407
DEFAULT_DELAYS = '0,1,2,5,10,20,50'
DEFAULT_REPS = 20
DEFAULT_PROBE_PORT = 20051  # dedicated probe port; not the live DNP3 port (20000)

# Socket-option configurations, ONE FACTOR AT A TIME. Each differs from `baseline`
# by exactly one factor. server_nodelay: None => leave OS default (do not setsockopt);
# True/False => set TCP_NODELAY to 1/0 on the server's accepted socket.
# client_quickack: apply TCP_QUICKACK=1 on the client socket (re-armed each recv,
# because Linux clears it after one ACK) only when the option exists.
CONFIGS = [
    {'name': 'baseline', 'server_nodelay': None, 'client_quickack': False},
    {'name': 'server_nodelay_on', 'server_nodelay': True, 'client_quickack': False},
    {'name': 'server_nodelay_off', 'server_nodelay': False, 'client_quickack': False},
    {'name': 'client_quickack_on', 'server_nodelay': None, 'client_quickack': True},
]

HAS_QUICKACK = hasattr(socket, 'TCP_QUICKACK')

RAW_COLUMNS = [
    'row_type', 'config', 'server_nodelay', 'client_quickack', 'requested_delay_ms',
    'rep', 'request_to_response_ms', 'response_received', 'response_bytes_ok', 'reset',
    'pure_ack_emitted', 'request_to_ack_ms', 'ack_to_response_ms', 'retransmissions',
    'capture_status',
]
AGG_COLUMNS = [
    'row_type', 'config', 'server_nodelay', 'client_quickack', 'requested_delay_ms',
    'reps', 'req_to_resp_ms_mean', 'req_to_resp_ms_max', 'responses_ok',
    'response_bytes_ok_all', 'resets', 'pure_ack_yes', 'pure_ack_no',
    'pure_ack_unknown', 'pure_ack_frac', 'request_to_ack_ms_mean',
    'ack_to_response_ms_mean', 'retransmissions_sum', 'capture_status',
]


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #
def parse_delays(text):
    """Parse a comma-separated millisecond delay list into a list of ints."""
    delays = []
    for tok in text.split(','):
        tok = tok.strip()
        if tok:
            delays.append(int(tok))
    if not delays:
        raise ValueError('empty --delays list')
    return delays


def _recv_exact(sock, nbytes):
    """Receive exactly ``nbytes`` from ``sock``; return None on clean EOF."""
    chunks = []
    remaining = nbytes
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            return None
        chunks.append(chunk)
        remaining -= len(chunk)
    return b''.join(chunks)


def _mean(values):
    return round(sum(values) / len(values), 3) if values else None


def _nodelay_label(value):
    """Human label for a config's server_nodelay tri-state."""
    if value is None:
        return 'default'
    return 'on' if value else 'off'


def _quickack_label(want):
    """Human label for a config's client_quickack request, honouring availability."""
    if not want:
        return 'default'
    return 'on' if HAS_QUICKACK else 'unavailable'


# --------------------------------------------------------------------------- #
# Server
# --------------------------------------------------------------------------- #
def _handle_connection(conn, peer, resp_size):
    """Serve one client connection: read the config frame, then the request loop.

    The client sends a CTRL frame first so the server can apply the requested
    server-side socket option to THIS accepted socket. Each request then carries
    its own delay; the server records arrival, waits the delay, and writes a
    fixed-size response -- the application-write delay under test.
    """
    ctrl = _recv_exact(conn, CTRL_SIZE)
    if ctrl is None:
        return
    magic, server_nodelay = CTRL_STRUCT.unpack(ctrl[:CTRL_STRUCT.size])
    if magic != CTRL_MAGIC:
        _log.warning('Server: bad control magic %r from %s; dropping.', magic, peer)
        return
    if server_nodelay in (0, 1):
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, server_nodelay)
        _log.info('Server: applied TCP_NODELAY=%d for %s.', server_nodelay, peer)
    else:
        _log.info('Server: leaving TCP_NODELAY at OS default for %s.', peer)
    conn.sendall(CTRL_ACK)

    payload_tail = b'\x00' * max(0, resp_size - RESP_HDR.size)
    while True:
        req = _recv_exact(conn, REQ_SIZE)
        if req is None:
            return  # client finished this config's connection
        magic, seq, delay_ms = REQ_STRUCT.unpack(req[:REQ_STRUCT.size])
        if magic != REQ_MAGIC:
            _log.warning('Server: bad request magic %r; stopping this connection.', magic)
            return
        # Record arrival; the delay between here and the write() is the app-write
        # delay whose effect on ACK piggybacking we are probing.
        _arrival_ns = time.monotonic_ns()
        if delay_ms > 0:
            time.sleep(delay_ms / 1000.0)
        conn.sendall(RESP_HDR.pack(RESP_MAGIC, seq, delay_ms) + payload_tail)


def run_server(host, port, resp_size, ready_event=None, stop_event=None):
    """Accept connections and serve each fully; loop until ``stop_event`` (if any).

    The client opens one connection per socket-option config, so the server must
    accept repeatedly rather than handling a single connection.
    """
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(4)
    srv.settimeout(1.0)
    _log.info('Server listening on %s:%s (resp_size=%d).', host, port, resp_size)
    if ready_event is not None:
        ready_event.set()
    try:
        while True:
            if stop_event is not None and stop_event.is_set():
                return
            try:
                conn, peer = srv.accept()
            except socket.timeout:
                continue
            _log.info('Server accepted connection from %s.', peer)
            try:
                _handle_connection(conn, peer, resp_size)
            finally:
                conn.close()
    finally:
        srv.close()
        _log.info('Server stopped.')


# --------------------------------------------------------------------------- #
# Capture capability (same capability-aware approach as rto_probe.py)
# --------------------------------------------------------------------------- #
def _tshark_can_capture(iface):
    """True only if tshark can ACTUALLY capture on ``iface`` (privilege probe).

    shutil.which finding tshark is NOT enough: on a host where the user is not in
    the capture group, dumpcap prints 'Permission denied' -- and may still exit 0.
    So we attempt a real 1 s capture and inspect the output text, not just the
    return code.
    """
    if shutil.which('tshark') is None:
        return False
    try:
        proc = subprocess.run(
            ['tshark', '-i', iface, '-a', 'duration:1', '-c', '1', '-w', os.devnull],
            capture_output=True, text=True, timeout=8)
    except (subprocess.TimeoutExpired, OSError):
        return False
    blob = (proc.stdout + proc.stderr).lower()
    if 'denied' in blob or "couldn't run dumpcap" in blob or 'permission' in blob:
        return False
    return proc.returncode == 0


def probe_capture_method(iface, force=None):
    """Decide how (or whether) pure-ACK emission can be observed.

    Returns (method, detail) where method is 'tshark' or 'none'. Only a packet
    capture can reveal a pure ACK, so unlike rto_probe there is no ss/netstat
    fallback for THIS measurement -- without a capture, pure-ACK emission is
    simply undetermined and reported as such.
    """
    if force == 'none':
        return 'none', 'capture disabled by --no-capture'
    if force == 'tshark':
        return 'tshark', 'forced by --method tshark'
    if _tshark_can_capture(iface):
        return 'tshark', 'live tshark capture of the probe port (privileged)'
    if shutil.which('tshark') is None and shutil.which('tcpdump') is None:
        return 'none', 'no capture tool (tshark/tcpdump) on PATH'
    return 'none', ('capture tool present but this user lacks capture privilege '
                    '(dumpcap permission denied); needs CAP_NET_RAW or root')


def _start_tshark_capture(iface, port, pcap_path):
    """Start a background tshark capture of the probe; return the Popen handle."""
    if os.path.exists(pcap_path):
        os.remove(pcap_path)
    proc = subprocess.Popen(
        ['tshark', '-i', iface, '-f', 'tcp port {}'.format(port), '-w', pcap_path],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.0)  # let the capture come up before traffic flows
    return proc


def _stop_tshark_capture(proc):
    """Terminate the capture process and let it flush the pcap."""
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
    time.sleep(0.5)


def _tshark_packets(pcap_path, port):
    """Return per-packet tuples (epoch, srcport, tcp_len, ack_flag, is_retrans).

    Extracts the fields needed to tell a pure ACK (server->client, len==0, ACK set)
    from an ACK-bearing response (server->client, len>0). Modelled on rto_probe's
    field-extraction path (proven working there).
    """
    try:
        proc = subprocess.run(
            ['tshark', '-r', pcap_path, '-Y', 'tcp.port=={}'.format(port),
             '-T', 'fields',
             '-e', 'frame.time_epoch', '-e', 'tcp.srcport', '-e', 'tcp.len',
             '-e', 'tcp.flags.ack', '-e', 'tcp.analysis.retransmission'],
            capture_output=True, text=True, timeout=120)
    except (subprocess.TimeoutExpired, OSError):
        return []
    packets = []
    for line in proc.stdout.splitlines():
        fields = line.split('\t')
        if len(fields) < 4:
            continue
        try:
            epoch = float(fields[0])
            srcport = int(fields[1]) if fields[1] else -1
            tcp_len = int(fields[2]) if fields[2] else 0
            ack_flag = fields[3] in ('1', 'True', 'true')
        except ValueError:
            continue
        is_retrans = len(fields) >= 5 and fields[4].strip() not in ('', '0')
        packets.append((epoch, srcport, tcp_len, ack_flag, is_retrans))
    return packets


# --------------------------------------------------------------------------- #
# Client
# --------------------------------------------------------------------------- #
def _new_record(config, delay_ms, rep, capture_status):
    return {
        'config': config['name'],
        'server_nodelay': _nodelay_label(config['server_nodelay']),
        'client_quickack': _quickack_label(config['client_quickack']),
        'requested_delay_ms': delay_ms,
        'rep': rep,
        'request_to_response_ms': None,
        'response_received': False,
        'response_bytes_ok': False,
        'reset': False,
        # Capture-only fields: left unknown/None unless a capture is analysed.
        'pure_ack_emitted': 'unknown',
        'request_to_ack_ms': None,
        'ack_to_response_ms': None,
        'retransmissions': None,
        'capture_status': capture_status,
        # Wall-clock window (time.time) for bucketing capture packets, as in rto_probe.
        'wall_start': None,
        'wall_end': None,
    }


def run_client_config(connect_host, port, config, delays, reps, resp_size,
                      capture_status, seq_start):
    """Run one socket-option config over a single connection; return (records, seq).

    Ordering is deterministic: delays in the given order, reps 0..reps-1 within
    each delay. Each request carries its delay so the server never desyncs.
    """
    records = []
    seq = seq_start
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10.0)
    sock.connect((connect_host, port))
    try:
        # Control handshake: tell the server which server-side option to apply.
        nodelay_code = -1 if config['server_nodelay'] is None else int(config['server_nodelay'])
        ctrl = CTRL_STRUCT.pack(CTRL_MAGIC, nodelay_code)
        ctrl = ctrl + b'\x00' * (CTRL_SIZE - len(ctrl))
        sock.sendall(ctrl)
        if _recv_exact(sock, CTRL_ACK_SIZE) != CTRL_ACK:
            _log.warning('Client: no control-ack for config %s.', config['name'])

        want_quickack = config['client_quickack'] and HAS_QUICKACK
        for delay_ms in delays:
            for rep in range(reps):
                rec = _new_record(config, delay_ms, rep, capture_status)
                req = REQ_STRUCT.pack(REQ_MAGIC, seq, delay_ms)
                req = req + b'\x00' * (REQ_SIZE - len(req))
                seq += 1
                # TCP_QUICKACK is one-shot on Linux (cleared after one ACK), so
                # re-arm it immediately before this exchange when the config asks.
                if want_quickack:
                    try:
                        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_QUICKACK, 1)
                    except OSError:
                        pass
                rec['wall_start'] = time.time()
                t0 = time.monotonic_ns()
                try:
                    sock.sendall(req)
                    resp = _recv_exact(sock, resp_size)
                    t1 = time.monotonic_ns()
                    rec['wall_end'] = time.time()
                    if resp is None:
                        _log.warning('Client: EOF before full response (%s delay=%d rep=%d).',
                                     config['name'], delay_ms, rep)
                    else:
                        rec['response_received'] = True
                        rec['request_to_response_ms'] = round((t1 - t0) / 1e6, 3)
                        rmagic, rseq, _applied = RESP_HDR.unpack(resp[:RESP_HDR.size])
                        rec['response_bytes_ok'] = (
                            rmagic == RESP_MAGIC and rseq == seq - 1 and len(resp) == resp_size)
                except ConnectionResetError:
                    rec['reset'] = True
                    rec['wall_end'] = time.time()
                    _log.warning('Client: connection reset (%s delay=%d rep=%d).',
                                 config['name'], delay_ms, rep)
                except socket.timeout:
                    rec['wall_end'] = time.time()
                    _log.warning('Client: response timeout (%s delay=%d rep=%d).',
                                 config['name'], delay_ms, rep)
                records.append(rec)
    finally:
        sock.close()
    return records, seq


# --------------------------------------------------------------------------- #
# Capture analysis (rig path: only runs when a capture was taken)
# --------------------------------------------------------------------------- #
def analyze_capture(records, pcap_path, port):
    """Fill pure_ack_emitted and the ACK/response timings per record from a pcap.

    For each request window [wall_start, wall_end] (windows are non-overlapping --
    strict ping-pong, sequential connections), find the request packet
    (client->server, len>0), the first server->client len==0 ACK, and the first
    server->client len>0 response. A pure ACK "before" the response means the
    delayed write let the kernel emit a standalone ACK first.
    """
    packets = _tshark_packets(pcap_path, port)
    if not packets:
        _log.warning('Capture analysis: no packets parsed from %s.', pcap_path)
        for rec in records:
            rec['capture_status'] = 'analyzed-empty'
        return records

    windows = [(r['wall_start'], r['wall_end'], r) for r in records
               if r['wall_start'] is not None and r['wall_end'] is not None]
    windows.sort(key=lambda w: w[0])

    for start, end, rec in windows:
        in_win = [p for p in packets if start <= p[0] <= end]
        req_epoch = next((p[0] for p in in_win if p[1] != port and p[2] > 0), None)
        server_pkts = [p for p in in_win if p[1] == port]
        resp_epoch = next((p[0] for p in server_pkts if p[2] > 0), None)
        # A pure ACK is a zero-length ACK from the server that arrives before the
        # first server response segment in this window.
        pure_ack_epoch = None
        for epoch, _src, tcp_len, ack_flag, _rt in server_pkts:
            if tcp_len == 0 and ack_flag:
                if resp_epoch is None or epoch < resp_epoch:
                    pure_ack_epoch = epoch
                    break
        rec['retransmissions'] = sum(1 for p in in_win if p[4])
        rec['capture_status'] = 'analyzed'
        if pure_ack_epoch is not None:
            rec['pure_ack_emitted'] = 'yes'
            if req_epoch is not None:
                rec['request_to_ack_ms'] = round((pure_ack_epoch - req_epoch) * 1e3, 3)
            if resp_epoch is not None:
                rec['ack_to_response_ms'] = round((resp_epoch - pure_ack_epoch) * 1e3, 3)
        elif resp_epoch is not None:
            rec['pure_ack_emitted'] = 'no'  # ACK piggybacked on the response segment
        else:
            rec['pure_ack_emitted'] = 'unknown'  # window had no server data packet
        if req_epoch is not None and resp_epoch is not None:
            rec['request_to_response_ms_wire'] = round((resp_epoch - req_epoch) * 1e3, 3)
    return records


# --------------------------------------------------------------------------- #
# Aggregation + output
# --------------------------------------------------------------------------- #
def aggregate(records, configs, delays):
    """Aggregate raw records into one row per (config, delay), deterministic order."""
    rows = []
    for config in configs:
        for delay_ms in delays:
            subset = [r for r in records
                      if r['config'] == config['name'] and r['requested_delay_ms'] == delay_ms]
            if not subset:
                continue
            rtts = [r['request_to_response_ms'] for r in subset
                    if r['request_to_response_ms'] is not None]
            r2a = [r['request_to_ack_ms'] for r in subset if r['request_to_ack_ms'] is not None]
            a2r = [r['ack_to_response_ms'] for r in subset if r['ack_to_response_ms'] is not None]
            retrans = [r['retransmissions'] for r in subset if r['retransmissions'] is not None]
            yes = sum(1 for r in subset if r['pure_ack_emitted'] == 'yes')
            no = sum(1 for r in subset if r['pure_ack_emitted'] == 'no')
            unknown = sum(1 for r in subset if r['pure_ack_emitted'] == 'unknown')
            decided = yes + no
            rows.append({
                'config': config['name'],
                'server_nodelay': _nodelay_label(config['server_nodelay']),
                'client_quickack': _quickack_label(config['client_quickack']),
                'requested_delay_ms': delay_ms,
                'reps': len(subset),
                'req_to_resp_ms_mean': _mean(rtts),
                'req_to_resp_ms_max': max(rtts) if rtts else None,
                'responses_ok': sum(1 for r in subset if r['response_received']),
                'response_bytes_ok_all': all(r['response_bytes_ok'] for r in subset),
                'resets': sum(1 for r in subset if r['reset']),
                'pure_ack_yes': yes,
                'pure_ack_no': no,
                'pure_ack_unknown': unknown,
                'pure_ack_frac': round(yes / decided, 3) if decided else None,
                'request_to_ack_ms_mean': _mean(r2a),
                'ack_to_response_ms_mean': _mean(a2r),
                'retransmissions_sum': sum(retrans) if retrans else None,
                'capture_status': subset[0]['capture_status'],
            })
    return rows


def write_csv(path, records, agg_rows):
    """Write aggregate rows then raw rows into one CSV, with a row_type column."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    columns = ['row_type'] + [c for c in AGG_COLUMNS if c != 'row_type'] + \
              [c for c in RAW_COLUMNS if c not in AGG_COLUMNS and c != 'row_type']
    with open(path, 'w', newline='') as fh:
        writer = csv.DictWriter(fh, fieldnames=columns, extrasaction='ignore')
        writer.writeheader()
        for a in agg_rows:
            row = dict(a)
            row['row_type'] = 'aggregate'
            writer.writerow(row)
        for r in records:
            row = dict(r)
            row['row_type'] = 'raw'
            writer.writerow(row)


def write_json(path, payload):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as fh:
        json.dump(payload, fh, indent=2, default=str)


def _rig_command(port, resp_size, delays, reps):
    """Return the exact two-host rig commands as a (hulk, vision) tuple."""
    delays_str = ','.join(str(d) for d in delays)
    hulk = ('# On Hulk (outstation host {ip}) -- run the delay server:\n'
            'python3 ack_separation_probe.py --server --bind-ip 0.0.0.0 '
            '--port {port} --resp-size {rsize}\n'
            '#   (optional both-endpoint cross-check, in a second Hulk shell):\n'
            '#   sudo tcpdump -i <egress-iface> -w hulk_ack_sep.pcap \'tcp port {port}\''
            ).format(ip=cfg.OUTSTATION_IP, port=port, rsize=resp_size)
    vision = ('# On Vision (master host {ip}) -- run the measuring client UNDER sudo\n'
              '# so its tshark capture path activates and pure-ACK detection works:\n'
              'sudo python3 ack_separation_probe.py --client '
              '--connect-host {oip} --port {port} \\\n'
              '    --iface <egress-iface> --delays {delays} --reps {reps} --resp-size {rsize}'
              ).format(ip=cfg.MASTER_IP, oip=cfg.OUTSTATION_IP, port=port,
                       delays=delays_str, reps=reps, rsize=resp_size)
    return hulk, vision


def write_notes(path, meta, agg_rows):
    """Write the human-readable markdown note with the honest section-12 caveats."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    delays = meta['delays']
    hulk_cmd, vision_cmd = _rig_command(meta['port'], meta['resp_size'], delays, meta['reps'])
    capture_ok = meta['method'] == 'tshark'

    def _f(value):
        return 'n/a' if value is None else value

    lines = []
    lines.append('# Socket-level ACK-separation experiment (Phase 2A)')
    lines.append('')
    lines.append('Generated by `ack_separation_probe.py` (plan section 5A). Question: can '
                 'DELAYING the application write() induce the host TCP stack to emit a '
                 '**pure TCP ACK** before the DNP3 response -- i.e. turn an ACK-bearing '
                 'DNP3 response into `request -> pure TCP ACK -> DNP3 response` -- with NO '
                 'packet forging? Forging a TCP ACK is out of scope for this phase.')
    lines.append('')
    lines.append('## Run metadata')
    lines.append('')
    lines.append('| field | value |')
    lines.append('| --- | --- |')
    lines.append('| mode | {} |'.format(meta['mode']))
    lines.append('| capture method | **{}** ({}) |'.format(meta['method'], meta['method_detail']))
    lines.append('| connection | {} -> {}:{} |'.format(
        meta['connect_host'], meta['connect_host'], meta['port']))
    lines.append('| capture interface | {} |'.format(meta['iface']))
    lines.append('| delays (ms) | {} |'.format(','.join(str(d) for d in delays)))
    lines.append('| reps per (config,delay) | {} |'.format(meta['reps']))
    lines.append('| response size (B) | {} |'.format(meta['resp_size']))
    lines.append('| socket-option configs | {} |'.format(', '.join(c['name'] for c in CONFIGS)))
    lines.append('| TCP_QUICKACK available | {} |'.format('yes' if HAS_QUICKACK else 'no'))
    lines.append('| python | {} |'.format(meta['python']))
    lines.append('| host | {} |'.format(meta['host']))
    lines.append('')

    lines.append('## Result matrix (aggregate per config x delay)')
    lines.append('')
    lines.append('| config | server NODELAY | client QUICKACK | delay (ms) | reps | '
                 'req->resp mean (ms) | req->resp max (ms) | resp OK | bytes OK | resets | '
                 'pure ACK (yes/no/unk) | pure ACK frac | req->ACK mean (ms) | '
                 'ACK->resp mean (ms) | retrans sum |')
    lines.append('| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | :---: | ---: | '
                 ':---: | ---: | ---: | ---: | ---: |')
    for a in agg_rows:
        pa = '{}/{}/{}'.format(a['pure_ack_yes'], a['pure_ack_no'], a['pure_ack_unknown'])
        lines.append('| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |'.format(
            a['config'], a['server_nodelay'], a['client_quickack'], a['requested_delay_ms'],
            a['reps'], _f(a['req_to_resp_ms_mean']), _f(a['req_to_resp_ms_max']),
            a['responses_ok'], 'yes' if a['response_bytes_ok_all'] else 'NO', a['resets'],
            pa, _f(a['pure_ack_frac']), _f(a['request_to_ack_ms_mean']),
            _f(a['ack_to_response_ms_mean']), _f(a['retransmissions_sum'])))
    lines.append('')

    lines.append('## Interpretation')
    lines.append('')
    if capture_ok:
        lines.append('- `pure ACK (yes/no/unk)` counts how many of the reps showed a standalone '
                     'server->client zero-length ACK BEFORE the DNP3 response segment. Read down '
                     'the delay column within each config to find the smallest application-write '
                     'delay at which a separate ACK begins to appear, and whether it is stable '
                     'across reps (`pure ACK frac` near 1.0 = reliably separated).')
        lines.append('- `req->ACK mean` and `ACK->resp mean` give the observer-visible split once '
                     'a pure ACK is emitted; `req->resp mean` is the end-to-end round trip the '
                     'client measured with `time.monotonic_ns()`.')
    else:
        lines.append('- **Pure-ACK EMISSION could NOT be determined on this run.** Detecting a '
                     'pure TCP ACK requires a packet capture, and no unprivileged capture was '
                     'available here ({}). The tool did NOT guess yes/no: every '
                     '`pure ACK` cell is reported as unknown (`unk`), and `req->ACK` / `ACK->resp` '
                     'are `n/a`.'.format(meta['method_detail']))
        lines.append('- What WAS measured on this run: `request_to_response_ms` (client-side round '
                     'trip via `time.monotonic_ns()`), DNP3-response success (`resp OK`), '
                     'byte-size correctness (`bytes OK`), and resets, per (config, delay, rep). '
                     'The round trip tracks the applied application-write delay, confirming the '
                     'delay mechanism works; it says nothing about ACK piggybacking.')
        lines.append('- To fill the ACK columns, re-run with a privileged capture '
                     '(tcpdump/tshark with CAP_NET_RAW or root), ideally on the two-host rig below.')
    lines.append('')

    lines.append('## Socket-option findings (one factor at a time)')
    lines.append('')
    lines.append('- The sweep varies exactly ONE factor per config vs `baseline`: server-side '
                 '`TCP_NODELAY` on, `TCP_NODELAY` off, then client-side `TCP_QUICKACK` on '
                 '(where the option exists). The options actually set are recorded on every row '
                 '(`server_nodelay`, `client_quickack`).')
    if not capture_ok:
        lines.append('- Because pure-ACK emission is a *capture-only* observation, the effect of '
                     'these options on ACK separation is NOT resolved on this run -- only their '
                     '(minor) effect on `request_to_response_ms` is visible here.')
    lines.append('- Endpoint note: the pure ACK of interest is the **server** ACKing the '
                 'client\'s request, so the **server\'s** delayed-ACK / QUICKACK behaviour is '
                 'what governs it. This sweep sets `TCP_QUICKACK` on the CLIENT (per the plan), '
                 'which governs the client\'s ACK of the server\'s response instead. A follow-up '
                 'that toggles QUICKACK / the delayed-ACK timer on the SERVER is the direct knob '
                 'for the request->pure-ACK behaviour and is a natural next one-factor extension.')
    lines.append('')

    lines.append('## Offload and host-capture caveats')
    lines.append('')
    lines.append('- **TSO/GSO/GRO and checksum offload** can make a host capture show segmentation '
                 'and sizes that differ from the actual on-wire packets: with GRO/LRO the capture '
                 'may coalesce several wire segments into one large record, and with TSO/GSO the '
                 'capture may show one large record that the NIC later splits. This can hide or '
                 'merge a pure ACK relative to the response, so trust NIC-level or peer-side '
                 'captures over a same-host capture when segmentation matters.')
    lines.append('- **A host-side capture is not the wire.** It taps between the application and '
                 'the NIC, so its timestamps include host queueing and are not the exact on-wire '
                 'times (plan section 12: "a host-side capture does not always represent exact '
                 'wire timing").')
    lines.append('- **Loopback (`--loopback`) is doubly unrepresentative.** The `lo` path has '
                 '~0 ms delay and no loss, the delayed-ACK dynamics differ from a real NIC/wire, '
                 'and loopback offload behaviour is its own special case. Loopback is a smoke '
                 'test of the mechanism and the tooling only.')
    lines.append('')

    lines.append('## Honest caveats (plan section 12 -- strict research claims)')
    lines.append('')
    lines.append('- **Socket delay does NOT always force a separate ACK.** Whether a delayed '
                 'write produces a pure ACK depends on the receiving kernel\'s delayed-ACK timer, '
                 'quickack state, the peer\'s window/behaviour, and offload -- it is a host/kernel '
                 'behaviour, not a protocol guarantee. Any positive result is "measured on this '
                 'device, trace, host, and configuration", not a general claim.')
    lines.append('- **Loopback != wire.** Do not generalise any loopback observation to the rig or '
                 'to a real DNP3 device.')
    lines.append('- Not all DNP3 devices use the same TCP ACK behaviour; results here do not '
                 'transfer across devices or stacks without re-measurement.')
    lines.append('')

    lines.append('## Two-host rig command (authoritative pure-ACK detection)')
    lines.append('')
    lines.append('Run on the real rig (master **Vision {}** <-> outstation host **Hulk {}**) with '
                 'a PRIVILEGED capture so the pure ACK is actually observed on the wire. Capture '
                 'at both endpoints if possible (plan 5A):'.format(cfg.MASTER_IP, cfg.OUTSTATION_IP))
    lines.append('')
    lines.append('```bash')
    lines.append(hulk_cmd)
    lines.append('')
    lines.append(vision_cmd)
    lines.append('```')
    lines.append('')
    lines.append('Under `sudo` on Vision the client\'s `tshark` capture path activates '
                 'automatically; the pcap is analysed to fill `pure_ack_emitted`, '
                 '`request_to_ack_ms`, `ack_to_response_ms`, `retransmissions`, and per-rep '
                 'stability. Without capture privilege the run still records timing + DNP3 '
                 'success and marks pure-ACK detection as undetermined.')
    lines.append('')
    with open(path, 'w') as fh:
        fh.write('\n'.join(lines))


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
def _build_meta(mode, method, method_detail, connect_host, iface, delays, reps, resp_size, port):
    return {
        'mode': mode,
        'method': method,
        'method_detail': method_detail,
        'connect_host': connect_host,
        'iface': iface,
        'delays': delays,
        'reps': reps,
        'resp_size': resp_size,
        'port': port,
        'configs': [c['name'] for c in CONFIGS],
        'quickack_available': HAS_QUICKACK,
        'python': '{}.{}.{}'.format(*sys.version_info[:3]),
        'host': socket.gethostname(),
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
    }


def _emit_outputs(records, agg_rows, meta):
    """Write the three output files and return their absolute paths."""
    report_dir = os.path.join(HARNESS_DIR, cfg.REPORT_DIR)
    csv_path = os.path.join(report_dir, 'ack_separation_matrix.csv')
    json_path = os.path.join(report_dir, 'ack_separation_matrix.json')
    notes_path = os.path.join(report_dir, 'ack_separation_notes.md')
    write_csv(csv_path, records, agg_rows)
    write_json(json_path, {'meta': meta, 'aggregate': agg_rows, 'raw': records})
    write_notes(notes_path, meta, agg_rows)
    return csv_path, json_path, notes_path


def run_probe(connect_host, iface, port, delays, reps, resp_size, mode, force_method):
    """Run the client-side probe across all configs and write the outputs."""
    method, detail = probe_capture_method(iface, force=force_method)
    _log.info('Capture method: %s (%s).', method, detail)
    capture_status = 'analyzed' if method == 'tshark' else 'undetermined-needs-privileged-capture'

    capture_proc = None
    pcap_path = os.path.join(HARNESS_DIR, cfg.REPORT_DIR, 'ack_separation_capture.pcap')
    if method == 'tshark':
        try:
            capture_proc = _start_tshark_capture(iface, port, pcap_path)
        except OSError as exc:
            _log.warning('tshark capture failed to start (%s); continuing without capture.', exc)
            capture_proc = None
            method, detail = 'none', 'tshark capture failed to start: {}'.format(exc)
            capture_status = 'undetermined-capture-start-failed'

    records = []
    seq = 0
    for config in CONFIGS:
        if config['client_quickack'] and not HAS_QUICKACK:
            _log.info('Config %s skipped: TCP_QUICKACK not available on this platform.',
                      config['name'])
        recs, seq = run_client_config(connect_host, port, config, delays, reps,
                                      resp_size, capture_status, seq)
        records.extend(recs)

    if method == 'tshark' and capture_proc is not None:
        _stop_tshark_capture(capture_proc)
        analyze_capture(records, pcap_path, port)

    agg_rows = aggregate(records, CONFIGS, delays)
    meta = _build_meta(mode, method, detail, connect_host, iface, delays, reps, resp_size, port)
    return _emit_outputs(records, agg_rows, meta)


def run_loopback(args):
    """Spawn the server in a background thread and probe it over 127.0.0.1."""
    delays = parse_delays(args.delays)
    ready = threading.Event()
    stop = threading.Event()
    server_thread = threading.Thread(
        target=run_server,
        args=('127.0.0.1', args.port, args.resp_size, ready, stop),
        daemon=True)
    server_thread.start()
    if not ready.wait(timeout=5):
        _log.error('Server thread failed to come up.')
        sys.exit(1)
    try:
        paths = run_probe('127.0.0.1', args.iface, args.port, delays, args.reps,
                          args.resp_size, 'loopback', args.method)
    finally:
        stop.set()
        server_thread.join(timeout=3)
    return paths


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def build_parser():
    parser = argparse.ArgumentParser(
        description='Phase-2A socket-level ACK-separation probe: does delaying the '
                    'application write induce a pure TCP ACK before the DNP3 response?')
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--loopback', action='store_true',
                      help='Run server (background thread) + client over 127.0.0.1.')
    mode.add_argument('--server', action='store_true',
                      help='Run only the delay-injecting server (for the rig / outstation host).')
    mode.add_argument('--client', action='store_true',
                      help='Run only the measuring client (for the rig / master host).')

    parser.add_argument('--connect-host', default=cfg.OUTSTATION_IP,
                        help='Server host the client connects to (default: outstation IP).')
    parser.add_argument('--bind-ip', default=cfg.BIND_IP,
                        help='Server bind address (default from lab_config).')
    parser.add_argument('--port', type=int, default=DEFAULT_PROBE_PORT,
                        help='TCP port for the probe (default %(default)s; not the DNP3 port).')
    parser.add_argument('--iface', default='lo',
                        help='Interface for the tshark capture attempt (default lo; '
                             'use the egress iface on the rig).')
    parser.add_argument('--delays', default=DEFAULT_DELAYS,
                        help='Comma-separated application-write delays in ms (default %(default)s).')
    parser.add_argument('--reps', type=int, default=DEFAULT_REPS,
                        help='Requests per (config, delay) (default %(default)s).')
    parser.add_argument('--resp-size', type=int, default=DEFAULT_RESP_SIZE,
                        help='Fixed response size in bytes (default %(default)s, mirrors the '
                             'full DNP3 read response).')
    parser.add_argument('--method', default='auto', choices=['auto', 'tshark', 'none'],
                        help='Force the capture method: auto-probe (default), force tshark, '
                             'or disable capture (none).')
    return parser


def main():
    args = build_parser().parse_args()
    force = None if args.method == 'auto' else args.method
    if args.server:
        try:
            run_server(args.bind_ip, args.port, args.resp_size)
        except KeyboardInterrupt:
            _log.info('Server interrupted.')
        return
    if args.client:
        delays = parse_delays(args.delays)
        paths = run_probe(args.connect_host, args.iface, args.port, delays,
                          args.reps, args.resp_size, 'client', force)
    else:  # --loopback
        args.method = force
        paths = run_loopback(args)

    csv_path, json_path, notes_path = paths
    _log.info('Wrote CSV:   %s', csv_path)
    _log.info('Wrote JSON:  %s', json_path)
    _log.info('Wrote notes: %s', notes_path)


if __name__ == '__main__':
    main()

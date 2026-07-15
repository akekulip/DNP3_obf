"""
rto_probe.py -- empirically probe how controlled response delays affect TCP
retransmission behaviour over a real TCP connection.

Motivation: a separate part of this project normalises response timing by holding
a DNP3 response back by a bounded delay before sending it. The binding safety
constraint is TCP retransmission: if a held response overshoots the peer's
retransmission timeout (RTO), the peer retransmits the request -- a loud tell to a
passive observer. This tool MEASURES the effective retransmission boundary from a
live connection instead of assuming the textbook ~200 ms; nothing here hardcodes a
200 ms threshold.

Modes
-----
  --loopback   spawn the server in a background thread and run the client against
               127.0.0.1 so the whole probe runs from one command (dev smoke test).
  --server     accept one connection; for each request, wait the next delay from
               the cycled delay list, then send a fixed-size response.
  --client     connect, and for each delay send a request and time the round trip,
               recording retransmission / RTO evidence. TCP handles ACKs; the
               client never ACKs at the application layer.

Retransmission evidence is counted by the best available method, chosen at run
time and recorded in the output:
  tshark  -- count tcp.analysis.retransmission / tcp.analysis.duplicate_ack from a
             capture of the probe (preferred; needs capture privilege).
  ss      -- per-request delta of the client socket's TCP_INFO retrans counter, plus
             the peer's live rto: value (works without root; no duplicate-ACK count).
  netstat -- system-wide TCPRetrans delta from /proc/net/netstat (last resort, noisy).

Outputs (always overwritten, never reused):
  reports/rto_probe_results.csv   raw per-(delay,rep) rows + per-delay aggregate rows
  reports/rto_probe_results.json  structured results incl. method + environment
  reports/rto_probe_notes.md      method, per-delay table, inferred safe hold bound,
                                  and the loopback-is-not-the-wire caveat + rig command

Example
-------
    python3 rto_probe.py --loopback
    python3 rto_probe.py --loopback --delays 100,200,250,300,500 --reps 30
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import re
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

# Wire format: fixed-size request so a strict ping-pong stream never desyncs and
# the server's per-request delay cycle stays in lock step with the client.
REQ_MAGIC = b'RTOP'
REQ_STRUCT = struct.Struct('!4sII')  # magic, seq, expected_delay_ms
REQ_SIZE = 32                        # padded fixed request size (bytes)
RESP_HDR = struct.Struct('!4sII')    # magic, seq, applied_delay_ms
RESP_MAGIC = b'RTOR'

# Probe defaults. Response size mirrors the validated full DNP3 read response
# (~2407 B, 9 link frames) so segment counts are representative; override with
# --resp-size. Delays are in milliseconds.
DEFAULT_RESP_SIZE = 2407
DEFAULT_DELAYS = '0,1,2,5,10,20,50,100'
DEFAULT_REPS = 20
DEFAULT_PROBE_PORT = 20050  # dedicated probe port; not the live DNP3 port

RAW_COLUMNS = [
    'row_type', 'requested_delay_ms', 'rep', 'rtt_ms', 'response_received',
    'reset', 'retransmissions', 'duplicate_acks', 'peer_rto_ms', 'retrans_method',
]
AGG_COLUMNS = [
    'row_type', 'requested_delay_ms', 'reps', 'rtt_ms_mean', 'rtt_ms_max',
    'retransmissions_sum', 'retransmissions_max', 'duplicate_acks_sum',
    'duplicate_acks_max', 'resets', 'responses_ok', 'peer_rto_ms_mean',
    'peer_rto_ms_max', 'retrans_method',
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


def _maybe(values, fn):
    vals = [v for v in values if v is not None]
    return fn(vals) if vals else None


# --------------------------------------------------------------------------- #
# Server
# --------------------------------------------------------------------------- #
def run_server(host, port, delays, resp_size, ready_event=None, stop_event=None):
    """Accept one connection and reply to each request after the next cycled delay.

    The delay applied to request i is ``delays[i % len(delays)]`` (the "cycle
    through the delay list" rule). Because requests are fixed-size and the client
    is strict ping-pong, this cycle stays aligned with the client's intent; the
    client's expected delay is echoed in each request and used as an authoritative
    override if a mismatch is ever detected.
    """
    payload_tail = b'\x00' * max(0, resp_size - RESP_HDR.size)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(1)
    srv.settimeout(1.0)
    _log.info('Server listening on %s:%s (resp_size=%d, delays=%s).',
              host, port, resp_size, delays)
    if ready_event is not None:
        ready_event.set()

    conn = None
    try:
        while conn is None:
            if stop_event is not None and stop_event.is_set():
                return
            try:
                conn, peer = srv.accept()
            except socket.timeout:
                continue
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        _log.info('Server accepted connection from %s.', peer)
        cycle = 0
        while True:
            req = _recv_exact(conn, REQ_SIZE)
            if req is None:
                _log.info('Server: client closed the connection.')
                break
            magic, seq, expected = REQ_STRUCT.unpack(req[:REQ_STRUCT.size])
            if magic != REQ_MAGIC:
                _log.warning('Server: bad request magic %r; stopping.', magic)
                break
            delay_ms = delays[cycle % len(delays)]
            if expected != delay_ms:
                # Strict ping-pong should keep these aligned; if not, trust the
                # client's stated intent so the measurement stays correct.
                _log.warning('Server: cycle delay %d != client-expected %d at seq %d; '
                             'using client value.', delay_ms, expected, seq)
                delay_ms = expected
            cycle += 1
            if delay_ms > 0:
                time.sleep(delay_ms / 1000.0)
            conn.sendall(RESP_HDR.pack(RESP_MAGIC, seq, delay_ms) + payload_tail)
    finally:
        if conn is not None:
            conn.close()
        srv.close()
        _log.info('Server stopped.')


# --------------------------------------------------------------------------- #
# Retransmission-evidence backends
# --------------------------------------------------------------------------- #
def _tshark_can_capture(iface):
    """True only if tshark can actually capture on ``iface`` (privilege probe).

    ``shutil.which`` finding tshark is not enough: on a host where the user is not
    in the capture group, dumpcap returns 'Permission denied'. Probe for real.
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


def _tshark_event_epochs(pcap_path, display_filter):
    """Return the frame.time_epoch list of packets matching ``display_filter``."""
    try:
        proc = subprocess.run(
            ['tshark', '-r', pcap_path, '-Y', display_filter,
             '-T', 'fields', '-e', 'frame.time_epoch'],
            capture_output=True, text=True, timeout=60)
    except (subprocess.TimeoutExpired, OSError):
        return []
    epochs = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if line:
            try:
                epochs.append(float(line))
            except ValueError:
                pass
    return epochs


def _ss_available():
    return shutil.which('ss') is not None


def _read_client_tcpinfo(local_ip, local_port, peer_ip, peer_port):
    """Return the client socket's TCP_INFO as a dict, or None if not found.

    Keys (absent fields default sensibly): retrans_total (cumulative retransmit
    count), bytes_retrans, rto_ms (the peer/this-side live RTO estimate), rtt_ms.
    """
    filt = 'src {}:{} dst {}:{}'.format(local_ip, local_port, peer_ip, peer_port)
    try:
        proc = subprocess.run(['ss', '-tinH', filt],
                              capture_output=True, text=True, timeout=5)
    except (subprocess.TimeoutExpired, OSError):
        return None
    txt = proc.stdout
    if not txt.strip():
        return None
    m_retrans = re.search(r'retrans:\d+/(\d+)', txt)
    m_bytes = re.search(r'bytes_retrans:(\d+)', txt)
    m_rto = re.search(r'\brto:(\d+)', txt)
    m_rtt = re.search(r'\brtt:([\d.]+)/', txt)
    return {
        'retrans_total': int(m_retrans.group(1)) if m_retrans else 0,
        'bytes_retrans': int(m_bytes.group(1)) if m_bytes else 0,
        'rto_ms': int(m_rto.group(1)) if m_rto else None,
        'rtt_ms': float(m_rtt.group(1)) if m_rtt else None,
    }


def _read_netstat_retrans_total():
    """Return the system-wide cumulative TCPRetrans count, or None."""
    try:
        with open('/proc/net/netstat', 'r') as fh:
            lines = fh.read().splitlines()
    except OSError:
        return None
    for i in range(0, len(lines) - 1, 2):
        header = lines[i].split()
        values = lines[i + 1].split()
        if header and header[0] == 'TcpExt:' and 'TCPRetrans' in header:
            idx = header.index('TCPRetrans')
            if idx < len(values):
                try:
                    return int(values[idx])
                except ValueError:
                    return None
    return None


def select_retrans_method(iface, port, force=None):
    """Choose the retransmission-counting method, honouring the preference order.

    Returns (method, detail) where method is 'tshark' | 'ss' | 'netstat' | 'none'.
    """
    if force and force != 'auto':
        return force, 'forced by --method'
    if _tshark_can_capture(iface):
        return 'tshark', 'tcp.analysis.retransmission / duplicate_ack from live capture'
    if _ss_available():
        return 'ss', 'per-request client-socket TCP_INFO retrans delta + peer rto'
    if _read_netstat_retrans_total() is not None:
        return 'netstat', 'system-wide /proc/net/netstat TCPRetrans delta (noisy)'
    return 'none', 'no retransmission counter available'


# --------------------------------------------------------------------------- #
# Client
# --------------------------------------------------------------------------- #
def run_client(connect_host, port, delays, reps, resp_size, method):
    """Drive the probe and return a list of raw per-(delay,rep) record dicts.

    Ordering is round-robin (rep-major) so the server's simple delay cycle stays
    aligned: round r sends one request per delay in ``delays`` order. Each record
    captures rtt, whether the response arrived, connection reset, retransmissions,
    duplicate ACKs (tshark only), and the peer's live RTO (ss only).
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.settimeout(10.0)
    sock.connect((connect_host, port))
    local_ip, local_port = sock.getsockname()
    peer_ip, peer_port = sock.getpeername()
    use_ss = _ss_available()
    use_netstat = (method == 'netstat')
    _log.info('Client connected %s:%s -> %s:%s (method=%s).',
              local_ip, local_port, peer_ip, peer_port, method)

    records = []
    seq = 0
    try:
        for rep in range(reps):
            for delay_ms in delays:
                rec = {
                    'requested_delay_ms': delay_ms, 'rep': rep, 'rtt_ms': None,
                    'response_received': False, 'reset': False,
                    'retransmissions': None, 'duplicate_acks': None,
                    'peer_rto_ms': None, 'retrans_method': method,
                    'wall_start': None, 'wall_end': None,
                }
                # RTO / retrans counters BEFORE this exchange (ss method).
                pre = _read_client_tcpinfo(local_ip, local_port, peer_ip, peer_port) if use_ss else None
                pre_ns = _read_netstat_retrans_total() if use_netstat else None
                req = REQ_STRUCT.pack(REQ_MAGIC, seq, delay_ms)
                req = req + b'\x00' * (REQ_SIZE - len(req))
                seq += 1
                rec['wall_start'] = time.time()
                t0 = time.monotonic_ns()
                try:
                    sock.sendall(req)
                    resp = _recv_exact(sock, resp_size)
                    t1 = time.monotonic_ns()
                    rec['wall_end'] = time.time()
                    if resp is None:
                        _log.warning('Client: EOF before full response (delay=%d rep=%d).',
                                     delay_ms, rep)
                    else:
                        rec['response_received'] = True
                        rec['rtt_ms'] = round((t1 - t0) / 1e6, 3)
                except ConnectionResetError:
                    rec['reset'] = True
                    rec['wall_end'] = time.time()
                    _log.warning('Client: connection reset (delay=%d rep=%d).', delay_ms, rep)
                except socket.timeout:
                    rec['wall_end'] = time.time()
                    _log.warning('Client: response timeout (delay=%d rep=%d).', delay_ms, rep)

                post = _read_client_tcpinfo(local_ip, local_port, peer_ip, peer_port) if use_ss else None
                if post is not None:
                    rec['peer_rto_ms'] = post['rto_ms']
                if method == 'ss' and pre is not None and post is not None:
                    rec['retransmissions'] = max(0, post['retrans_total'] - pre['retrans_total'])
                elif use_netstat and pre_ns is not None:
                    post_ns = _read_netstat_retrans_total()
                    if post_ns is not None:
                        rec['retransmissions'] = max(0, post_ns - pre_ns)
                records.append(rec)
                if rec['reset']:
                    raise _ProbeAborted('connection reset during probe')
    except _ProbeAborted as exc:
        _log.error('Probe aborted: %s', exc)
    finally:
        sock.close()
    return records


class _ProbeAborted(Exception):
    pass


def _fill_netstat_retrans(records):
    """Attribute system-wide TCPRetrans deltas per record (best-effort, noisy)."""
    # Re-derivation is not possible after the fact; netstat deltas are captured
    # inline only when this is the active method. Left as None otherwise.
    return records


def attribute_tshark(records, pcap_path):
    """Fill retransmissions / duplicate_acks per record from a tshark capture.

    Buckets each retransmission / duplicate-ACK packet into the request window
    [wall_start, wall_end] it falls inside. Windows are non-overlapping because the
    client is strict ping-pong.
    """
    retrans_epochs = _tshark_event_epochs(pcap_path, 'tcp.analysis.retransmission')
    dupack_epochs = _tshark_event_epochs(pcap_path, 'tcp.analysis.duplicate_ack')
    for rec in records:
        rec['retransmissions'] = 0
        rec['duplicate_acks'] = 0
    windows = [(r['wall_start'], r['wall_end'], r) for r in records
               if r['wall_start'] is not None and r['wall_end'] is not None]
    windows.sort(key=lambda w: w[0])

    def _bucket(epoch, key):
        for start, end, rec in windows:
            if start <= epoch <= end:
                rec[key] += 1
                return
    for ep in retrans_epochs:
        _bucket(ep, 'retransmissions')
    for ep in dupack_epochs:
        _bucket(ep, 'duplicate_acks')
    return records


# --------------------------------------------------------------------------- #
# Aggregation + output
# --------------------------------------------------------------------------- #
def aggregate(records, delays, method):
    """Aggregate raw records into one row per delay value."""
    rows = []
    for delay_ms in delays:
        subset = [r for r in records if r['requested_delay_ms'] == delay_ms]
        if not subset:
            continue
        rtts = [r['rtt_ms'] for r in subset if r['rtt_ms'] is not None]
        retrans = [r['retransmissions'] for r in subset if r['retransmissions'] is not None]
        dupacks = [r['duplicate_acks'] for r in subset if r['duplicate_acks'] is not None]
        rtos = [r['peer_rto_ms'] for r in subset if r['peer_rto_ms'] is not None]
        rows.append({
            'requested_delay_ms': delay_ms,
            'reps': len(subset),
            'rtt_ms_mean': _mean(rtts),
            'rtt_ms_max': max(rtts) if rtts else None,
            'retransmissions_sum': sum(retrans) if retrans else None,
            'retransmissions_max': max(retrans) if retrans else None,
            'duplicate_acks_sum': sum(dupacks) if dupacks else None,
            'duplicate_acks_max': max(dupacks) if dupacks else None,
            'resets': sum(1 for r in subset if r['reset']),
            'responses_ok': sum(1 for r in subset if r['response_received']),
            'peer_rto_ms_mean': _mean(rtos),
            'peer_rto_ms_max': max(rtos) if rtos else None,
            'retrans_method': method,
        })
    return rows


def write_csv(path, records, agg_rows):
    """Write raw rows then aggregate rows into one CSV, with a row_type column."""
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


def _infer_safe_bound(agg_rows):
    """Infer a safe hold upper bound (ms) from the MEASURED peer RTO, not a constant.

    The boundary that matters is the peer's retransmission timeout. We take the
    minimum observed peer RTO across the run (the earliest a retransmission could
    fire) and keep a conservative margin below it. Returns (bound_ms, min_rto_ms)
    or (None, None) if no RTO signal was available.
    """
    rtos = [a['peer_rto_ms_mean'] for a in agg_rows if a['peer_rto_ms_mean'] is not None]
    rto_maxes = [a['peer_rto_ms_max'] for a in agg_rows if a['peer_rto_ms_max'] is not None]
    if not rtos:
        return None, None
    min_rto = min(rtos + rto_maxes) if rto_maxes else min(rtos)
    # Half of the smallest observed RTO is a conservative headroom that also
    # leaves room for one-way path delay; do not exceed it when holding responses.
    return int(min_rto * 0.5), min_rto


def _rig_command(port, resp_size, delays, reps):
    """Return the exact host-to-host rig commands as a (hulk, vision) tuple."""
    hulk = ('# On Hulk (outstation host {}):\n'
            'python3 rto_probe.py --server --bind-ip 0.0.0.0 --port {}').format(cfg.OUTSTATION_IP, port)
    vision = ('# On Vision (master host {}):\n'
              'sudo python3 rto_probe.py --client --connect-host {} --port {} \\\n'
              '    --iface <egress-iface> --delays {} --reps {} --resp-size {}').format(
                  cfg.MASTER_IP, cfg.OUTSTATION_IP, port, delays, reps, resp_size)
    return hulk, vision


def write_notes(path, meta, agg_rows):
    """Write the human-readable markdown note with the honest loopback caveat."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    bound, min_rto = _infer_safe_bound(agg_rows)
    delays_str = ','.join(str(d) for d in meta['delays'])
    hulk_cmd, vision_cmd = _rig_command(
        meta['port'], meta['resp_size'], delays_str, meta['reps'])

    lines = []
    lines.append('# TCP retransmission / RTO safety probe')
    lines.append('')
    lines.append('Generated by `rto_probe.py`. Purpose: measure the effective TCP '
                 'retransmission boundary so a timing-normalisation hold does not '
                 'overshoot the peer RTO and trigger a request retransmission '
                 '(a passive-observable tell). No 200 ms threshold is assumed; the '
                 'bound below is derived from the measured peer RTO.')
    lines.append('')
    lines.append('## Run metadata')
    lines.append('')
    lines.append('| field | value |')
    lines.append('| --- | --- |')
    lines.append('| mode | {} |'.format(meta['mode']))
    lines.append('| retransmission method | **{}** ({}) |'.format(
        meta['method'], meta['method_detail']))
    lines.append('| connection | {} -> {}:{} |'.format(
        meta['connect_host'], meta['connect_host'], meta['port']))
    lines.append('| capture interface | {} |'.format(meta['iface']))
    lines.append('| delays (ms) | {} |'.format(delays_str))
    lines.append('| reps per delay | {} |'.format(meta['reps']))
    lines.append('| response size (B) | {} |'.format(meta['resp_size']))
    lines.append('| python | {} |'.format(meta['python']))
    lines.append('| host | {} |'.format(meta['host']))
    lines.append('')
    lines.append('## Per-delay results')
    lines.append('')
    lines.append('| delay (ms) | reps | rtt mean (ms) | rtt max (ms) | retrans sum | '
                 'retrans max | dup-ACK sum | resets | resp OK | peer RTO mean (ms) | peer RTO max (ms) |')
    lines.append('| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |')
    def _f(value):
        return 'n/a' if value is None else value
    for a in agg_rows:
        lines.append('| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |'.format(
            a['requested_delay_ms'], a['reps'], _f(a['rtt_ms_mean']), _f(a['rtt_ms_max']),
            _f(a['retransmissions_sum']), _f(a['retransmissions_max']), _f(a['duplicate_acks_sum']),
            a['resets'], a['responses_ok'], _f(a['peer_rto_ms_mean']), _f(a['peer_rto_ms_max'])))
    lines.append('')
    lines.append('## Inferred safe hold bound')
    lines.append('')
    if bound is not None:
        lines.append('- Smallest observed peer RTO: **{} ms** (measured via `ss` TCP_INFO `rto:`).'.format(min_rto))
        lines.append('- Conservative safe hold upper bound: **~{} ms** '
                     '(half the smallest observed RTO, leaving path-delay headroom).'.format(bound))
    else:
        lines.append('- No peer-RTO signal was available on this run (method `{}`); '
                     'rerun where `ss` or a capture is available to obtain the RTO.'.format(meta['method']))
    lines.append('- Interpretation: a normal Linux peer ACKs the request at the '
                 'kernel level independently of when the application emits the '
                 'response, so holding the *response* below the RTO does not by '
                 'itself cause the peer to retransmit the *request*. The peer RTO '
                 '(Linux floors it at `TCP_RTO_MIN`) is the boundary to respect; '
                 'peers whose stack couples the ACK to the application response, or '
                 'any real packet loss, shrink the margin.')
    lines.append('')
    lines.append('## Caveat: loopback is NOT the wire')
    lines.append('')
    lines.append('A `--loopback` run exercises the kernel TCP stack on a single host '
                 'over the `lo` interface with ~0 ms path delay and no loss. It does '
                 '**not** reproduce real-network RTO: the real master\'s RTO tracks '
                 'the real RTT and its variance, the real outstation\'s stack may ACK '
                 'differently, and the physical path can drop packets. Loopback '
                 'numbers here are a smoke test and a lower bound on the RTO floor '
                 '(the RTO minimum), not authoritative wire behaviour. Do not claim '
                 'loopback == wire.')
    lines.append('')
    lines.append('Authoritative numbers require the two-host lab rig: master '
                 '**Vision {}** <-> outstation host **Hulk {}**. Run the probe '
                 'host-to-host there (client on the master side so its own request '
                 'retransmissions are measured):'.format(cfg.MASTER_IP, cfg.OUTSTATION_IP))
    lines.append('')
    lines.append('```bash')
    lines.append(hulk_cmd)
    lines.append('')
    lines.append(vision_cmd)
    lines.append('```')
    lines.append('')
    lines.append('On the rig, prefer running the client under `sudo` (or with an '
                 'account in the capture group) so the `tshark` method is selected '
                 'and `tcp.analysis.retransmission` / `tcp.analysis.duplicate_ack` '
                 'are counted directly from the wire; otherwise it falls back to the '
                 '`ss` per-socket method automatically.')
    lines.append('')
    with open(path, 'w') as fh:
        fh.write('\n'.join(lines))


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
def _emit_outputs(records, agg_rows, meta):
    """Write the three output files and return their absolute paths."""
    report_dir = os.path.join(HARNESS_DIR, cfg.REPORT_DIR)
    csv_path = os.path.join(report_dir, 'rto_probe_results.csv')
    json_path = os.path.join(report_dir, 'rto_probe_results.json')
    notes_path = os.path.join(report_dir, 'rto_probe_notes.md')
    write_csv(csv_path, records, agg_rows)
    write_json(json_path, {'meta': meta, 'aggregate': agg_rows, 'raw': records})
    write_notes(notes_path, meta, agg_rows)
    return csv_path, json_path, notes_path


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
        'python': '{}.{}.{}'.format(*sys.version_info[:3]),
        'host': socket.gethostname(),
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
    }


def run_probe(connect_host, iface, port, delays, reps, resp_size, mode, force_method):
    """Run the client-side probe end to end and write the outputs."""
    method, detail = select_retrans_method(iface, port, force=force_method)
    _log.info('Retransmission method selected: %s (%s).', method, detail)

    capture_proc = None
    pcap_path = os.path.join(HARNESS_DIR, cfg.REPORT_DIR, 'rto_probe_capture.pcap')
    if method == 'tshark':
        try:
            capture_proc = _start_tshark_capture(iface, port, pcap_path)
        except OSError as exc:
            _log.warning('tshark capture failed to start (%s); falling back.', exc)
            capture_proc = None
            if _ss_available():
                method, detail = 'ss', 'per-request client-socket TCP_INFO retrans delta + peer rto'
            elif _read_netstat_retrans_total() is not None:
                method, detail = 'netstat', 'system-wide /proc/net/netstat TCPRetrans delta (noisy)'
            else:
                method, detail = 'none', 'no retransmission counter available'

    records = run_client(connect_host, port, delays, reps, resp_size, method)

    if method == 'tshark' and capture_proc is not None:
        _stop_tshark_capture(capture_proc)
        attribute_tshark(records, pcap_path)

    agg_rows = aggregate(records, delays, method)
    meta = _build_meta(mode, method, detail, connect_host, iface, delays, reps, resp_size, port)
    return _emit_outputs(records, agg_rows, meta)


def run_loopback(args):
    """Spawn the server in a background thread and probe it over 127.0.0.1."""
    delays = parse_delays(args.delays)
    ready = threading.Event()
    stop = threading.Event()
    server_thread = threading.Thread(
        target=run_server,
        args=('127.0.0.1', args.port, delays, args.resp_size, ready, stop),
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
        description='Empirically probe TCP retransmission / RTO behaviour under '
                    'controlled response delays.')
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--loopback', action='store_true',
                      help='Run server (background thread) + client over 127.0.0.1.')
    mode.add_argument('--server', action='store_true',
                      help='Run only the delay-injecting server (for the rig).')
    mode.add_argument('--client', action='store_true',
                      help='Run only the measuring client (for the rig).')

    parser.add_argument('--connect-host', default=cfg.OUTSTATION_IP,
                        help='Server host the client connects to (default: outstation IP).')
    parser.add_argument('--bind-ip', default=cfg.BIND_IP,
                        help='Server bind address (default from lab_config).')
    parser.add_argument('--port', type=int, default=DEFAULT_PROBE_PORT,
                        help='TCP port for the probe (default %(default)s).')
    parser.add_argument('--iface', default='lo',
                        help='Interface for the tshark capture attempt (default lo; '
                             'use the egress iface on the rig).')
    parser.add_argument('--delays', default=DEFAULT_DELAYS,
                        help='Comma-separated response delays in ms (default %(default)s).')
    parser.add_argument('--reps', type=int, default=DEFAULT_REPS,
                        help='Requests per delay value (default %(default)s).')
    parser.add_argument('--resp-size', type=int, default=DEFAULT_RESP_SIZE,
                        help='Fixed response size in bytes (default %(default)s).')
    parser.add_argument('--method', default='auto',
                        choices=['auto', 'tshark', 'ss', 'netstat'],
                        help='Force the retransmission-counting method (default auto).')
    return parser


def main():
    args = build_parser().parse_args()
    if args.server:
        delays = parse_delays(args.delays)
        try:
            run_server(args.bind_ip, args.port, delays, args.resp_size)
        except KeyboardInterrupt:
            _log.info('Server interrupted.')
        return
    if args.client:
        delays = parse_delays(args.delays)
        paths = run_probe(args.connect_host, args.iface, args.port, delays,
                          args.reps, args.resp_size, 'client', args.method)
    else:  # --loopback
        paths = run_loopback(args)

    csv_path, json_path, notes_path = paths
    _log.info('Wrote CSV:   %s', csv_path)
    _log.info('Wrote JSON:  %s', json_path)
    _log.info('Wrote notes: %s', notes_path)


if __name__ == '__main__':
    main()

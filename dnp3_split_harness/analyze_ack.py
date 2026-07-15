"""
analyze_ack.py -- analyze TCP ACK / response-timing behavior of a DNP3 capture.

No-arg run reads lab_config.py (pcap = captures/baseline/read_exchange.pcap,
master/outstation IPs, port) and writes reports/tcp_ack_details.csv +
reports/tcp_ack_summary.csv:

    python analyze_ack.py

Or pass flags to override. Walks each master request -> outstation reply exchange
and reports pure vs piggybacked ACKs, request->ACK and request->response delays,
and the TCP/IP fingerprint fields (options, window, TTL, IP ID, PSH) that together
form a device response fingerprint. The scapy import is deferred so ``--help``
works without scapy installed.
"""

import argparse
import csv
import logging
import os
import sys

HARNESS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HARNESS_DIR)  # so 'lab_config' imports regardless of cwd

import lab_config as cfg

stdout_stream = logging.StreamHandler(sys.stdout)
stdout_stream.setFormatter(logging.Formatter('%(asctime)s\t%(name)s\t%(levelname)s\t%(message)s'))

_log = logging.getLogger(__name__)
_log.addHandler(stdout_stream)
_log.setLevel(logging.DEBUG)

SCAPY_INSTALL_HINT = (
    'Scapy is required for PCAP analysis but is not installed.\n'
    'Install it with:  pip install scapy'
)

DETAIL_COLUMNS = [
    'pcap', 'flow_id', 'request_time', 'has_pure_ack', 'ack_delay_ms',
    'has_piggyback_ack', 'response_delay_ms', 'tcp_options', 'ttl', 'ip_id',
    'window_size', 'notes',
]

SUMMARY_COLUMNS = [
    'device', 'pcap', 'total_requests', 'pure_ack_count', 'piggyback_ack_count',
    'pure_ack_ratio', 'mean_ack_delay_ms', 'mean_response_delay_ms', 'tcp_option_signature',
]


def build_parser():
    """Build the argument parser; defaults come from lab_config.py (no scapy import)."""
    parser = argparse.ArgumentParser(
        description='Analyze TCP ACK / response-timing behavior and TCP/IP fingerprint from a PCAP.')
    parser.add_argument('--pcap', default=cfg.DEFAULT_CAPTURE,
                        help='Path to the input PCAP file (default from lab_config).')
    parser.add_argument('--master-ip', default=cfg.MASTER_IP, help='Master IP (request source).')
    parser.add_argument('--outstation-ip', default=cfg.OUTSTATION_IP, help='Outstation IP (responder).')
    parser.add_argument('--port', type=int, default=cfg.DNP3_PORT, help='DNP3 TCP port (default 20000).')
    parser.add_argument('--output-csv', default=os.path.join(cfg.REPORT_DIR, 'tcp_ack_details.csv'),
                        help='Per-request detail CSV to write.')
    parser.add_argument('--summary', default=os.path.join(cfg.REPORT_DIR, 'tcp_ack_summary.csv'),
                        help='Per-device summary CSV to write.')
    parser.add_argument('--device', default=None,
                        help='Device label for the summary (default: the outstation IP).')
    return parser


def _tcp_option_signature(tcp_layer):
    """Return a readable dash-joined TCP option name signature (e.g. NOP-NOP-Timestamp)."""
    names = []
    for opt in getattr(tcp_layer, 'options', []) or []:
        name = opt[0] if isinstance(opt, (tuple, list)) else opt
        names.append(str(name))
    return '-'.join(names)


def _has_flag(tcp_layer, letter):
    """True if the given TCP flag letter (e.g. 'A', 'P') is set."""
    return letter in str(tcp_layer.flags)


def _round_ms(seconds):
    """Convert a second delta to milliseconds rounded to 3 decimals."""
    return round(seconds * 1000.0, 3)


def analyze(pcap_path, master_ip, outstation_ip, port):
    """
        Parse ``pcap_path`` into one detail row per master request.

        A request is a master->outstation packet (to TCP ``port``) carrying a
        payload. For each request, the matching reply is the first
        outstation->master packet on the same ephemeral port with a payload; a
        pure ACK is a zero-payload ACK from the outstation before that reply.

    :return: list of detail-row dicts keyed by DETAIL_COLUMNS.
    """
    from scapy.all import rdpcap, TCP, IP, Raw  # deferred so --help needs no scapy

    packets = rdpcap(pcap_path)
    pcap_name = os.path.basename(pcap_path)

    # Pre-split the capture into the two directions, keeping timestamps.
    requests = []                 # (time, sport, pkt) master -> outstation, with payload
    out_to_master = []            # (time, dport, has_payload, pkt) outstation -> master
    for pkt in packets:
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            continue
        ip = pkt[IP]
        tcp = pkt[TCP]
        has_payload = pkt.haslayer(Raw) and len(bytes(pkt[Raw].load)) > 0
        if ip.src == master_ip and ip.dst == outstation_ip and tcp.dport == port:
            if has_payload:
                requests.append((float(pkt.time), int(tcp.sport), pkt))
        elif ip.src == outstation_ip and ip.dst == master_ip and tcp.sport == port:
            out_to_master.append((float(pkt.time), int(tcp.dport), has_payload, pkt))

    rows = []
    for req_time, sport, _req_pkt in requests:
        # First payload reply on this ephemeral port after the request.
        reply = None
        pure_ack = None
        for rt, dport, has_payload, pkt in out_to_master:
            if dport != sport or rt < req_time:
                continue
            if has_payload and reply is None:
                reply = (rt, pkt)
                break
            if (not has_payload) and pure_ack is None and _has_flag(pkt[TCP], 'A'):
                pure_ack = (rt, pkt)

        flow_id = '{}:{}->{}:{}'.format(master_ip, sport, outstation_ip, port)
        row = {c: '' for c in DETAIL_COLUMNS}
        row['pcap'] = pcap_name
        row['flow_id'] = flow_id
        row['request_time'] = '{:.6f}'.format(req_time)

        if pure_ack is not None:
            row['has_pure_ack'] = True
            row['ack_delay_ms'] = _round_ms(pure_ack[0] - req_time)
        else:
            row['has_pure_ack'] = False

        if reply is not None:
            from scapy.all import IP as _IP, TCP as _TCP  # local alias for clarity
            rpkt = reply[1]
            tcp = rpkt[_TCP]
            ip = rpkt[_IP]
            row['has_piggyback_ack'] = _has_flag(tcp, 'A')
            row['response_delay_ms'] = _round_ms(reply[0] - req_time)
            row['tcp_options'] = _tcp_option_signature(tcp)
            row['ttl'] = int(ip.ttl)
            row['ip_id'] = int(ip.id)
            row['window_size'] = int(tcp.window)
            row['notes'] = 'response PSH set' if _has_flag(tcp, 'P') else ''
        else:
            row['has_piggyback_ack'] = False
            row['notes'] = 'no response payload found'

        rows.append(row)
    return rows


def summarize(rows, device, pcap_name):
    """Aggregate detail ``rows`` into one per-device summary row dict."""
    total = len(rows)
    pure_acks = [r for r in rows if r['has_pure_ack'] is True]
    piggybacks = [r for r in rows if r['has_piggyback_ack'] is True]
    ack_delays = [r['ack_delay_ms'] for r in pure_acks if r['ack_delay_ms'] != '']
    resp_delays = [r['response_delay_ms'] for r in rows if r['response_delay_ms'] != '']

    # Most common TCP option signature across the replies.
    signatures = {}
    for r in rows:
        sig = r['tcp_options']
        if sig:
            signatures[sig] = signatures.get(sig, 0) + 1
    option_signature = max(signatures, key=signatures.get) if signatures else ''

    def _mean(values):
        return round(sum(values) / len(values), 3) if values else ''

    return {
        'device': device,
        'pcap': pcap_name,
        'total_requests': total,
        'pure_ack_count': len(pure_acks),
        'piggyback_ack_count': len(piggybacks),
        'pure_ack_ratio': round(len(pure_acks) / total, 3) if total else '',
        'mean_ack_delay_ms': _mean(ack_delays),
        'mean_response_delay_ms': _mean(resp_delays),
        'tcp_option_signature': option_signature,
    }


def _write_csv(path, columns, rows):
    """Write ``rows`` (list of dicts) to ``path`` with the given column order."""
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, 'w', newline='') as fh:
        writer = csv.DictWriter(fh, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)


def main():
    args = build_parser().parse_args()
    # Anchor relative paths to the harness directory so it runs from any cwd.
    pcap = args.pcap if os.path.isabs(args.pcap) else os.path.join(HARNESS_DIR, args.pcap)
    output_csv = (args.output_csv if os.path.isabs(args.output_csv)
                  else os.path.join(HARNESS_DIR, args.output_csv))
    summary_csv = (args.summary if os.path.isabs(args.summary)
                   else os.path.join(HARNESS_DIR, args.summary))

    try:
        import scapy  # noqa: F401  (presence check; real import is deferred in analyze())
    except ImportError:
        _log.error(SCAPY_INSTALL_HINT)
        sys.exit(1)

    if not os.path.exists(pcap):
        _log.error('PCAP not found: %s. Run a baseline capture first.', pcap)
        sys.exit(1)

    _log.info('Analyzing %s (master=%s outstation=%s port=%s).',
              pcap, args.master_ip, args.outstation_ip, args.port)
    rows = analyze(pcap, args.master_ip, args.outstation_ip, args.port)
    _log.info('Found %s request exchange(s).', len(rows))
    _write_csv(output_csv, DETAIL_COLUMNS, rows)
    _log.info('Wrote per-request detail CSV: %s', output_csv)

    device = args.device or args.outstation_ip
    summary_row = summarize(rows, device, os.path.basename(pcap))
    _write_csv(summary_csv, SUMMARY_COLUMNS, [summary_row])
    _log.info('Wrote per-device summary CSV: %s', summary_csv)
    _log.info('Summary: %s requests, %s pure-ACK, %s piggyback, option signature %r.',
              summary_row['total_requests'], summary_row['pure_ack_count'],
              summary_row['piggyback_ack_count'], summary_row['tcp_option_signature'])


if __name__ == '__main__':
    main()

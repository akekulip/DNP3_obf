"""
extract_payloads.py -- extract raw DNP3 TCP payload bytes from a PCAP.

No-arg run reads lab_config.py (pcap = captures/baseline/read_exchange.pcap,
master/outstation IPs, port -> payloads/baseline/):

    python extract_payloads.py

Or pass flags to override any default. Writes orig_*.bin (master->outstation),
resp_*.bin (outstation->master), and metadata.json (timestamps, IPs, ports,
lengths, TCP flags/seq/ack, direction) with no Ethernet/IP/TCP headers -- the
captured request->response set the replay servers reconstruct. The scapy import
is deferred so ``--help`` works without scapy installed.
"""

import argparse
import json
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
    'Scapy is required for payload extraction but is not installed.\n'
    'Install it with:  pip install scapy'
)


def build_parser():
    """Build the argument parser; defaults come from lab_config.py (no scapy import)."""
    parser = argparse.ArgumentParser(
        description='Extract raw DNP3 TCP payload bytes (no L2/L3/L4 headers) from a PCAP.')
    parser.add_argument('--pcap', default=cfg.DEFAULT_CAPTURE,
                        help='Path to the input PCAP file (default from lab_config).')
    parser.add_argument('--master-ip', default=cfg.MASTER_IP, help='Master IP address.')
    parser.add_argument('--outstation-ip', default=cfg.OUTSTATION_IP, help='Outstation IP address.')
    parser.add_argument('--port', type=int, default=cfg.DNP3_PORT, help='DNP3 TCP port (default 20000).')
    parser.add_argument('--output-dir', default=os.path.join(cfg.PAYLOAD_DIR, 'baseline'),
                        help='Directory to write payloads + metadata.')
    return parser


def _direction(src_ip, dst_ip, src_port, dst_port, master_ip, outstation_ip, port):
    """
        Classify a packet's direction.

        Returns 'orig' for master->outstation (request), 'resp' for
        outstation->master (response), or None if it does not match the pair.

        When master and outstation IPs are identical (loopback testing), IPs
        cannot distinguish direction, so the DNP3 port is used instead: the
        outstation listens on ``port``, so a packet FROM that port is a response
        and a packet TO that port is a request.
    """
    if master_ip == outstation_ip:
        if dst_port == port:
            return 'orig'
        if src_port == port:
            return 'resp'
        return None
    if src_ip == master_ip and dst_ip == outstation_ip:
        return 'orig'
    if src_ip == outstation_ip and dst_ip == master_ip:
        return 'resp'
    return None


def extract(pcap_path, master_ip, outstation_ip, port, output_dir):
    """
        Stream the PCAP and write each non-empty DNP3 TCP payload to its own
        ``.bin`` file, plus a ``metadata.json`` describing every saved payload.

    :return: number of payloads written.
    """
    from scapy.all import PcapReader, IP, TCP  # imported here so --help needs no scapy

    os.makedirs(output_dir, exist_ok=True)
    orig_count = 0
    resp_count = 0
    metadata = []

    _log.info('Reading %s (master=%s outstation=%s port=%s)',
              pcap_path, master_ip, outstation_ip, port)
    with PcapReader(pcap_path) as reader:
        for pkt in reader:
            if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
                continue
            ip = pkt[IP]
            tcp = pkt[TCP]
            if tcp.sport != port and tcp.dport != port:
                continue
            direction = _direction(ip.src, ip.dst, tcp.sport, tcp.dport,
                                   master_ip, outstation_ip, port)
            if direction is None:
                continue

            # Raw application bytes only -- no Ethernet/IP/TCP headers.
            payload = bytes(tcp.payload)
            if len(payload) == 0:
                continue  # pure ACK / handshake; no DNP3 bytes to save.

            if direction == 'orig':
                orig_count += 1
                filename = 'orig_{:04d}.bin'.format(orig_count)
            else:
                resp_count += 1
                filename = 'resp_{:04d}.bin'.format(resp_count)

            out_path = os.path.join(output_dir, filename)
            with open(out_path, 'wb') as fh:
                fh.write(payload)

            entry = {
                'filename': filename,
                'timestamp': float(pkt.time),
                'src_ip': ip.src,
                'dst_ip': ip.dst,
                'src_port': int(tcp.sport),
                'dst_port': int(tcp.dport),
                'payload_len': len(payload),
                'tcp_flags': str(tcp.flags),
                'tcp_seq': int(tcp.seq),
                'tcp_ack': int(tcp.ack),
                'direction': direction,
            }
            metadata.append(entry)
            _log.debug('Saved %s (%s bytes, %s, flags=%s)',
                       filename, len(payload), direction, tcp.flags)

    metadata_path = os.path.join(output_dir, 'metadata.json')
    with open(metadata_path, 'w') as fh:
        json.dump(metadata, fh, indent=2)

    _log.info('Wrote %s request payload(s) and %s response payload(s) to %s',
              orig_count, resp_count, output_dir)
    _log.info('Metadata: %s', metadata_path)
    return orig_count + resp_count


def main():
    args = build_parser().parse_args()
    # Anchor relative paths to the harness directory so it runs from any cwd.
    pcap = args.pcap if os.path.isabs(args.pcap) else os.path.join(HARNESS_DIR, args.pcap)
    output_dir = (args.output_dir if os.path.isabs(args.output_dir)
                  else os.path.join(HARNESS_DIR, args.output_dir))

    try:
        import scapy  # noqa: F401  (presence check; real import is deferred in extract())
    except ImportError:
        _log.error(SCAPY_INSTALL_HINT)
        sys.exit(2)

    if not os.path.exists(pcap):
        _log.error('PCAP not found: %s. Run a baseline capture first.', pcap)
        sys.exit(1)

    extract(pcap, args.master_ip, args.outstation_ip, args.port, output_dir)


if __name__ == '__main__':
    main()

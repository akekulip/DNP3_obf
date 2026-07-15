"""
Positional (ordered) confirm-aware DNP3 replay server.

Stands in for the outstation and replays the captured responses in their captured
order -- one per received master request -- so the live master stays on its
captured application-sequence trajectory, accepts the data, delivers the
measurements, and sends a DNP3 CONFIRM. The READ response is split on existing
CRC boundaries (byte-preserving). This is the earlier milestone path; the
request-aware server (tcp_split_replay_server.py) is the current default.
"""

import argparse
import json
import logging
import os
import socket
import sys
import time

from datetime import datetime

from dnp3_crc_splitter import DNP3CRCSplitter

stdout_stream = logging.StreamHandler(sys.stdout)
stdout_stream.setFormatter(logging.Formatter('%(asctime)s\t%(name)s\t%(levelname)s\t%(message)s'))

_log = logging.getLogger(__name__)
_log.addHandler(stdout_stream)
_log.setLevel(logging.DEBUG)

RECV_BUFSIZE = 65535
START = b'\x05\x64'

# DNP3 application function codes seen from a master, for readable logging.
APP_FUNC_NAMES = {
    0x00: 'CONFIRM', 0x01: 'READ', 0x02: 'WRITE',
    0x14: 'ENABLE_UNSOLICITED', 0x15: 'DISABLE_UNSOLICITED', 0x81: 'RESPONSE',
}


def describe_request(data):
    """
        Return a short human description of a master DNP3 request frame.

        Decodes only the application function code and sequence from the first
        link frame for logging; it does not validate the whole frame.

    :param data: raw bytes received from the master.
    :return: e.g. "READ (0x01) app_seq=3" or "non-DNP3/short".
    """
    if len(data) >= 13 and data[0:2] == START:
        func = data[12]
        app_seq = data[11] & 0x0F
        name = APP_FUNC_NAMES.get(func, 'UNKNOWN')
        return '{} (0x{:02x}) app_seq={}'.format(name, func, app_seq)
    return 'non-DNP3/short ({} bytes)'.format(len(data))


def load_ordered_response_groups(payload_dir):
    """
        Build the ordered list of outstation response groups from a capture's
        ``metadata.json``.

        Each master request ('orig') is followed in capture order by one run of
        consecutive outstation responses ('resp'); that run is one response group
        (one application response, possibly several TCP segments). Returns the
        groups in the exact order they must be replayed so the master stays on its
        captured trajectory and the application sequence numbers line up.

    :param payload_dir: directory holding resp_*.bin and metadata.json.
    :return: list of (label, response_bytes) in replay order.
    """
    meta_path = os.path.join(payload_dir, 'metadata.json')
    with open(meta_path) as fh:
        events = json.load(fh)

    groups = []
    current_files = []
    pending_request = None
    for event in events:
        if event['direction'] == 'orig':
            # A new request closes the previous response group.
            if current_files:
                groups.append((pending_request, current_files))
                current_files = []
            pending_request = event['filename']
        else:  # 'resp'
            current_files.append(event['filename'])
    if current_files:
        groups.append((pending_request, current_files))

    ordered = []
    for request_file, resp_files in groups:
        data = bytearray()
        for name in resp_files:
            with open(os.path.join(payload_dir, name), 'rb') as fh:
                data += fh.read()
        label = '{}->{}'.format(request_file, '+'.join(resp_files))
        ordered.append((label, bytes(data)))
    return ordered


class DNP3OrderedReplayServer:
    """
        Ordered, confirm-aware DNP3 replay/split server.

        Replaces the real outstation and replays a captured exchange faithfully:
        it waits for each master request, then sends the matching captured
        outstation response (in capture order), splitting each response on
        existing DNP3 CRC block boundaries (no byte is altered, no CRC recomputed
        -- b"".join(chunks) == response). Because the captured responses carry the
        IIN that drives the master's startup, and a solicited response echoes the
        request's application sequence, replaying in order keeps the master on its
        captured trajectory: its READ lands on the same sequence the captured READ
        response carries, so the master can accept it and send a DNP3 CONFIRM.

        Unlike the single-shot split server, this keeps ONE connection open across
        the whole request/response sequence (including the master's CONFIRM, which
        triggers the next response group).
    """

    def __init__(self, host, port, payload_dir,
                 split_mode='crc-boundary', blocks_per_chunk=1,
                 delay_between_chunks_ms=0, hold_after_response_sec=10.0,
                 request_timeout_sec=10.0, log_dir=None):
        self.host = host
        self.port = port
        self.payload_dir = payload_dir
        self.split_mode = split_mode
        self.blocks_per_chunk = blocks_per_chunk
        self.delay_between_chunks_ms = delay_between_chunks_ms
        self.hold_after_response_sec = hold_after_response_sec
        self.request_timeout_sec = request_timeout_sec
        self.log_dir = log_dir

        self.groups = load_ordered_response_groups(payload_dir)
        total = sum(len(g[1]) for g in self.groups)
        _log.info('Loaded %s ordered response group(s) from %s (%s response bytes total).',
                  len(self.groups), payload_dir, total)
        for i, (label, data) in enumerate(self.groups):
            _log.info('  group %s: %s (%s bytes)', i + 1, label, len(data))

        if self.log_dir:
            os.makedirs(self.log_dir, exist_ok=True)

    def _dump(self, name, data):
        if not self.log_dir:
            return
        with open(os.path.join(self.log_dir, name), 'wb') as fh:
            fh.write(data)

    def _split(self, response_bytes):
        """Split one response group on CRC boundaries (reuse CRCs, recompute nothing)."""
        if self.split_mode in ('crc', 'crc-boundary'):
            chunks = DNP3CRCSplitter().split(response_bytes, self.blocks_per_chunk)
        else:  # 'full' -- send whole response as one write
            chunks = [response_bytes]
        if b''.join(chunks) != response_bytes:
            raise ValueError('split did not reconstruct the response group')
        return chunks

    def _recv_request(self, conn):
        """Block (up to request_timeout_sec) for one master message; return bytes or b''."""
        conn.settimeout(self.request_timeout_sec)
        try:
            return conn.recv(RECV_BUFSIZE)
        except socket.timeout:
            return b''
        except OSError:
            return b''

    def serve_once(self):
        """Accept one connection and replay the captured exchange in order."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self.host, self.port))
            srv.listen(1)
            _log.info('Listening on %s:%s (ordered confirm-aware replay).', self.host, self.port)

            conn, addr = srv.accept()
            _log.info('Accepted connection from %s at %s', addr, datetime.now().isoformat())
            with conn:
                for i, (label, response_bytes) in enumerate(self.groups):
                    request = self._recv_request(conn)
                    if not request:
                        _log.warning('No master request before group %s (%s). '
                                     'Master idle/closed; stopping replay.', i + 1, label)
                        break
                    _log.info('Master request %s: %s [%s byte(s)]',
                              i + 1, describe_request(request), len(request))
                    self._dump('request_{:02d}.bin'.format(i + 1), request)

                    chunks = self._split(response_bytes)
                    _log.info('Replaying group %s (%s): %s byte(s) in %s chunk(s) '
                              '(split-mode=%s, byte-preserving).',
                              i + 1, label, len(response_bytes), len(chunks), self.split_mode)
                    for idx, chunk in enumerate(chunks):
                        conn.sendall(chunk)
                        if self.delay_between_chunks_ms > 0 and idx < len(chunks) - 1:
                            time.sleep(self.delay_between_chunks_ms / 1000.0)
                    _log.info('Group %s sent (%s chunk(s)).', i + 1, len(chunks))
                else:
                    _log.info('All %s response group(s) replayed in order.', len(self.groups))

                self._receive_trailing(conn)
            _log.info('Connection closed cleanly.')

    def _receive_trailing(self, conn):
        """Hold the socket open briefly and log any trailing bytes (e.g. a final CONFIRM)."""
        if self.hold_after_response_sec <= 0:
            return
        _log.info('Holding connection for trailing data / final CONFIRM (up to %ss).',
                  self.hold_after_response_sec)
        deadline = time.time() + self.hold_after_response_sec
        trailing = bytearray()
        conn.settimeout(0.5)
        while time.time() < deadline:
            try:
                data = conn.recv(RECV_BUFSIZE)
            except socket.timeout:
                continue
            except OSError:
                break
            if not data:
                _log.info('Master closed the connection.')
                break
            trailing += data
            _log.info('Trailing bytes received: %s (%s)', len(data), describe_request(data))
        if trailing:
            self._dump('trailing.bin', bytes(trailing))


def build_parser():
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        description='Ordered, confirm-aware DNP3 replay/split server: waits for each master '
                    'request and replays the matching captured response, split on CRC boundaries.')
    parser.add_argument('--host', default='0.0.0.0', help='Local interface address to bind.')
    parser.add_argument('--port', type=int, default=20000, help='TCP port (default 20000).')
    parser.add_argument('--payload-dir', required=True,
                        help='Directory with resp_*.bin + metadata.json from the baseline capture.')
    parser.add_argument('--split-mode', choices=['crc', 'crc-boundary', 'full'], default='crc-boundary',
                        help='How to split each response group (default crc-boundary).')
    parser.add_argument('--blocks-per-chunk', type=int, default=1,
                        help='CRC blocks per chunk for crc-boundary mode (default 1).')
    parser.add_argument('--delay-between-chunks-ms', type=int, default=0,
                        help='Milliseconds to sleep between chunk writes.')
    parser.add_argument('--hold-after-response-sec', type=float, default=10.0,
                        help='Seconds to hold the connection for trailing data after the last group.')
    parser.add_argument('--request-timeout-sec', type=float, default=10.0,
                        help='Seconds to wait for each master request before giving up.')
    parser.add_argument('--log-dir', default=None,
                        help='Directory to write per-request dumps and a run log.')
    return parser


def main():
    args = build_parser().parse_args()
    if args.log_dir:
        os.makedirs(args.log_dir, exist_ok=True)
        file_handler = logging.FileHandler(
            os.path.join(args.log_dir, 'ordered_replay_server_{}.log'.format(int(time.time()))))
        file_handler.setFormatter(logging.Formatter('%(asctime)s\t%(name)s\t%(levelname)s\t%(message)s'))
        logging.getLogger().addHandler(file_handler)
        logging.getLogger().setLevel(logging.DEBUG)

    meta = os.path.join(args.payload_dir, 'metadata.json')
    if not os.path.exists(meta):
        _log.error('Missing %s. Run baseline capture and extract_payloads.py first.', meta)
        sys.exit(1)

    server = DNP3OrderedReplayServer(host=args.host,
                                     port=args.port,
                                     payload_dir=args.payload_dir,
                                     split_mode=args.split_mode,
                                     blocks_per_chunk=args.blocks_per_chunk,
                                     delay_between_chunks_ms=args.delay_between_chunks_ms,
                                     hold_after_response_sec=args.hold_after_response_sec,
                                     request_timeout_sec=args.request_timeout_sec,
                                     log_dir=args.log_dir)
    server.serve_once()


if __name__ == '__main__':
    main()

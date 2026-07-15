"""
Replay a captured DNP3 response verbatim over a plain TCP socket.

Stands in for the outstation: accepts the master's connection, optionally waits,
and sends the exact captured response bytes unmodified in a single write. The OS
socket owns all TCP seq/ACK/retransmit/checksums. This is the simplest replay
path (Phase 6, exact byte fidelity); the request-aware and CRC-split servers
build on the same idea with per-request matching and chunked writes.
"""

import argparse
import logging
import os
import socket
import sys
import time

from datetime import datetime

stdout_stream = logging.StreamHandler(sys.stdout)
stdout_stream.setFormatter(logging.Formatter('%(asctime)s\t%(name)s\t%(levelname)s\t%(message)s'))

_log = logging.getLogger(__name__)
_log.addHandler(stdout_stream)
_log.setLevel(logging.DEBUG)

# Read up to this many bytes from the master's request before responding.
RECV_BUFSIZE = 65535


def build_parser():
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        description='Replay captured DNP3 response bytes verbatim over a plain TCP socket.')
    parser.add_argument('--host', default='0.0.0.0', help='Local interface address to bind.')
    parser.add_argument('--port', type=int, default=20000, help='TCP port to listen on (default 20000).')
    parser.add_argument('--response', required=True, help='Path to the response .bin to replay verbatim.')
    parser.add_argument('--delay-before-response-ms', type=int, default=0,
                        help='Milliseconds to wait after receiving the request before responding.')
    parser.add_argument('--hold-after-response-sec', type=float, default=5.0,
                        help='Seconds to keep the connection open after sending the response.')
    parser.add_argument('--log-dir', default=None,
                        help='Directory to write received/sent byte dumps and a run log.')
    return parser


class DNP3ReplayServer:
    """
        Minimal single-connection TCP server that replays captured DNP3 response
        bytes EXACTLY as recorded.

        This server intentionally crafts no raw TCP packets: it uses an ordinary
        OS socket, so TCP sequence numbers, ACKs, retransmissions and checksums
        are all handled by the kernel. Its only job is to deliver the exact
        application-layer response byte stream back to an OpenDNP3 master.

        CRITICAL: this first replay server must NOT modify the response bytes.
        Proving exact-byte replay works is a prerequisite for any later
        DNP3-aware splitting or padding.
    """

    def __init__(self, host, port, response_path,
                 delay_before_response_ms=0,
                 hold_after_response_sec=5.0,
                 log_dir=None):
        self.host = host
        self.port = port
        self.response_path = response_path
        self.delay_before_response_ms = delay_before_response_ms
        self.hold_after_response_sec = hold_after_response_sec
        self.log_dir = log_dir

        with open(response_path, 'rb') as fh:
            self.response_bytes = fh.read()
        _log.info('Loaded %s bytes of response from %s', len(self.response_bytes), response_path)

        if self.log_dir:
            os.makedirs(self.log_dir, exist_ok=True)

    def _dump(self, name, data):
        """Write a byte dump under log_dir (if configured)."""
        if not self.log_dir:
            return
        path = os.path.join(self.log_dir, name)
        with open(path, 'wb') as fh:
            fh.write(data)
        _log.debug('Wrote %s bytes to %s', len(data), path)

    def serve_once(self):
        """Accept exactly one connection, replay the response, then return."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self.host, self.port))
            srv.listen(1)
            _log.info('Listening on %s:%s (single connection).', self.host, self.port)

            conn, addr = srv.accept()
            _log.info('Connection from %s at %s', addr, datetime.now().isoformat())
            with conn:
                # Receive the master's request bytes (e.g. a READ).
                conn.settimeout(5.0)
                try:
                    request = conn.recv(RECV_BUFSIZE)
                except socket.timeout:
                    request = b''
                    _log.warning('No request received within timeout; responding anyway.')
                _log.info('Received %s request byte(s) at %s',
                          len(request), datetime.now().isoformat())
                self._dump('received_request.bin', request)

                if self.delay_before_response_ms > 0:
                    time.sleep(self.delay_before_response_ms / 1000.0)

                # Send the exact captured response bytes -- no modification.
                conn.sendall(self.response_bytes)
                _log.info('Sent %s response byte(s) verbatim at %s',
                          len(self.response_bytes), datetime.now().isoformat())
                self._dump('sent_response.bin', self.response_bytes)

                if self.hold_after_response_sec > 0:
                    _log.info('Holding connection open for %ss.', self.hold_after_response_sec)
                    time.sleep(self.hold_after_response_sec)

            _log.info('Connection closed. Exiting cleanly.')


def main():
    args = build_parser().parse_args()
    if args.log_dir:
        os.makedirs(args.log_dir, exist_ok=True)
        file_handler = logging.FileHandler(
            os.path.join(args.log_dir, 'replay_server_{}.log'.format(int(time.time()))))
        file_handler.setFormatter(logging.Formatter('%(asctime)s\t%(name)s\t%(levelname)s\t%(message)s'))
        logging.getLogger().addHandler(file_handler)
        logging.getLogger().setLevel(logging.DEBUG)

    if not os.path.exists(args.response):
        _log.error('Response file not found: %s', args.response)
        sys.exit(1)

    server = DNP3ReplayServer(host=args.host,
                              port=args.port,
                              response_path=args.response,
                              delay_before_response_ms=args.delay_before_response_ms,
                              hold_after_response_sec=args.hold_after_response_sec,
                              log_dir=args.log_dir)
    server.serve_once()


if __name__ == '__main__':
    main()

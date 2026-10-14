import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
sys.dont_write_bytecode = True
sys.path[:0] = [str(HERE), str(HERE.parents[5] / 'case4_architecture/protocol/hw_vepa/tests')]
import capture  # noqa: E402
import pcaptk as tk  # noqa: E402

M, O, MP, OP = '192.168.10.61', '192.168.10.62', 59440, 20000


def one_stream(records):
    td = tempfile.TemporaryDirectory()
    path = Path(td.name) / 'x.pcap'
    frames = [(i * 100, tk.frame(M, O, MP, OP, seq, 0, tk.PSH | tk.ACK, payload))
              for i, (seq, payload) in enumerate(records)]
    tk.write_pcap(str(path), frames)
    return td, path


class TcpStreams(unittest.TestCase):
    def test_conflicting_byte_overlap_rejected(self):
        td, path = one_stream([(100, b'ABCDE'), (103, b'xyFG')])
        self.addCleanup(td.cleanup)
        with self.assertRaisesRegex(ValueError, 'conflicting overlap'):
            capture.streams(path)

    def test_sequence_wrap_reassembled_relative_to_first_payload(self):
        td, path = one_stream([(0xfffffffc, b'ABCD'), (0, b'EFGH')])
        self.addCleanup(td.cleanup)
        self.assertEqual(next(iter(capture.streams(path).values())), b'ABCDEFGH')

    def test_consistent_retransmission_with_extra_bytes_is_accepted(self):
        td, path = one_stream([(100, b'ABC'), (100, b'ABCDE')])
        self.addCleanup(td.cleanup)
        self.assertEqual(next(iter(capture.streams(path).values())), b'ABCDE')

    def test_gap_and_ambiguous_half_space_fail_closed(self):
        cases = (([(100, b'ABC'), (105, b'DEF')], 'gap of 2 octets'),
                 ([(100, b'A'), ((100 + 0x80000000) & 0xffffffff, b'B')], 'ambiguous'))
        for records, error in cases:
            with self.subTest(error=error):
                td, path = one_stream(records)
                self.addCleanup(td.cleanup)
                with self.assertRaisesRegex(ValueError, error):
                    capture.streams(path)

    def test_handshake_backed_reconnects_are_separate_incarnations(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        path = Path(td.name) / 'x.pcap'
        records = [
            (0, tk.frame(M, O, MP, OP, 1000, 0, tk.SYN)),
            (100, tk.frame(O, M, OP, MP, 5000, 1001, tk.SYN | tk.ACK)),
            (200, tk.frame(M, O, MP, OP, 1001, 5001, tk.PSH | tk.ACK, b'first')),
            (300, tk.frame(M, O, MP, OP, 9000, 0, tk.SYN)),
            (400, tk.frame(O, M, OP, MP, 7000, 9001, tk.SYN | tk.ACK)),
            (500, tk.frame(M, O, MP, OP, 9001, 7001, tk.PSH | tk.ACK, b'second')),
        ]
        tk.write_pcap(str(path), records)
        streams = capture.streams(path, include_incarnation=True)
        payloads = sorted(streams.values())
        self.assertEqual(payloads, [b'first', b'second'])
        self.assertEqual(sorted(k[2] for k in streams), [0, 1])

    def test_require_handshake_rejects_legacy_payload_only_stream(self):
        td, path = one_stream([(100, b'ABC')])
        self.addCleanup(td.cleanup)
        with self.assertRaisesRegex(ValueError, 'without handshake'):
            capture.streams(path, require_handshake=True)

    def test_syn_retry_is_not_a_new_incarnation(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        path = Path(td.name) / 'x.pcap'
        records = [
            (0, tk.frame(M, O, MP, OP, 1000, 0, tk.SYN)),
            (50, tk.frame(M, O, MP, OP, 1000, 0, tk.SYN)),
            (100, tk.frame(O, M, OP, MP, 5000, 1001, tk.SYN | tk.ACK)),
            (150, tk.frame(M, O, MP, OP, 1001, 5001, tk.ACK)),
            (200, tk.frame(M, O, MP, OP, 1001, 5001, tk.PSH | tk.ACK, b'payload')),
        ]
        tk.write_pcap(str(path), records)
        streams = capture.streams(path, include_incarnation=True, require_handshake=True)
        self.assertEqual(list(streams.values()), [b'payload'])
        self.assertEqual(next(iter(streams))[2], 0)

    def test_wrong_synack_ack_does_not_qualify_handshake(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        path = Path(td.name) / 'x.pcap'
        records = [
            (0, tk.frame(M, O, MP, OP, 1000, 0, tk.SYN)),
            (100, tk.frame(O, M, OP, MP, 5000, 9999, tk.SYN | tk.ACK)),
            (150, tk.frame(M, O, MP, OP, 1001, 5001, tk.ACK)),
            (200, tk.frame(M, O, MP, OP, 1001, 5001, tk.PSH | tk.ACK, b'payload')),
        ]
        tk.write_pcap(str(path), records)
        with self.assertRaisesRegex(ValueError, 'without handshake'):
            capture.streams(path, require_handshake=True)

    def test_old_payload_after_reconnect_is_ambiguous(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        path = Path(td.name) / 'x.pcap'
        records = [
            (0, tk.frame(M, O, MP, OP, 1000, 0, tk.SYN)),
            (100, tk.frame(O, M, OP, MP, 5000, 1001, tk.SYN | tk.ACK)),
            (150, tk.frame(M, O, MP, OP, 1001, 5001, tk.ACK)),
            (200, tk.frame(M, O, MP, OP, 1001, 5001, tk.PSH | tk.ACK, b'first')),
            (300, tk.frame(M, O, MP, OP, 9000, 0, tk.SYN)),
            (400, tk.frame(O, M, OP, MP, 7000, 9001, tk.SYN | tk.ACK)),
            (450, tk.frame(M, O, MP, OP, 9001, 7001, tk.ACK)),
            (500, tk.frame(M, O, MP, OP, 1001, 7001, tk.PSH | tk.ACK, b'stale')),
        ]
        tk.write_pcap(str(path), records)
        with self.assertRaisesRegex(ValueError, 'ambiguous'):
            capture.streams(path, include_incarnation=True, require_handshake=True)


if __name__ == '__main__':
    unittest.main()

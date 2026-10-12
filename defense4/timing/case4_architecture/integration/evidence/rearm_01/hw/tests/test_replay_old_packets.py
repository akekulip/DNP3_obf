"""Offline tests: only the AF_PACKET boundary is mocked; no packets are transmitted."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

HW = Path(__file__).resolve().parents[1]
ARCH = HW.parents[3]
sys.path.insert(0, str(ARCH / 'protocol/hw_vepa/tests'))
import pcaptk as tk

SPEC = importlib.util.spec_from_file_location('replay_old_packets', HW / 'replay_old_packets.py')
rp = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rp)
M, O, PORT = '192.168.10.61', '192.168.10.62', 31337


def packet(seq, ack, flags, payload=b'', reverse=False, port=PORT, **kw):
    return tk.frame(O if reverse else M, M if reverse else O,
                    20000 if reverse else port, port if reverse else 20000,
                    seq, ack, flags, payload, **kw)


def handshake(client=1000, server=2000):
    return [packet(client, 0, tk.SYN), packet(server, client + 1, tk.SYN | tk.ACK, reverse=True),
            packet(client + 1, server + 1, tk.ACK)]


def response(size=49):
    user = bytes([0xc0, 0xc0, 0x81, 0, 0, 10, 2, 0, 0, 22]) + bytes(23 if size == 49 else 32)
    return tk.dnp3_frame(user)


class Replay(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.frames = handshake() + [packet(1001, 2001, tk.PSH | tk.ACK, tk.read_request()),
            packet(2001, 1021, tk.PSH | tk.ACK, response(58), reverse=True),
            packet(1021, 2059, tk.FIN | tk.ACK)]
        self.old = self.write('old.pcap', self.frames)
        self.empty = self.write('empty.pcap', [])
        self.new = self.write('new.pcap', handshake(900000, 800000))

    def write(self, name, frames):
        path = self.root / name
        tk.write_pcap(path, [(1000 + n, frame) for n, frame in enumerate(frames)])
        return str(path)

    def args(self, *extra):
        return [self.old, self.empty, '--master-port', str(PORT)] + list(extra)

    def invoke(self, *extra):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            rc = rp.main(self.args(*extra))
        return rc, json.loads(output.getvalue())

    def test_dry_run_preserves_every_byte_and_reports_missing_rst_and_padded_read(self):
        manifest, frames = rp.collect([self.old, self.empty], PORT)
        self.assertEqual(frames, self.frames)
        self.assertEqual(manifest['missing_classes'], ['RST'])
        read = next(p for p in manifest['packets'] if p['class'] == 'READ_RESPONSE')
        self.assertEqual(read['payload_bytes'], 58)
        self.assertEqual(read['src_mac'], self.frames[4][6:12].hex(':'))
        self.assertEqual(manifest['isns'], {'client': 1000, 'server': 2000})
        with patch.object(rp.socket, 'socket', side_effect=AssertionError('dry run opened socket')):
            rc, result = self.invoke()
        self.assertEqual(rc, 0)
        self.assertFalse(result['applied'])

    def test_dedupe_is_opt_in_and_rst_is_selected_when_present(self):
        rst = packet(2059, 1022, tk.RST | tk.ACK, reverse=True)
        path = self.write('duplicate.pcap', self.frames + [self.frames[0], rst])
        plain, _ = rp.collect([path], PORT)
        unique, frames = rp.collect([path], PORT, dedupe=True)
        self.assertEqual(plain['counts']['SYN'], 2)
        self.assertEqual(unique['counts']['SYN'], 1)
        self.assertEqual(unique['duplicates_skipped'], 1)
        self.assertEqual(unique['missing_classes'], [])
        self.assertIn(rst, frames)

    def test_other_flows_private_headers_bad_checksums_and_offload_are_excluded(self):
        bad_tcp = bytearray(self.frames[3]); bad_tcp[50] ^= 1
        bad_ip = bytearray(self.frames[3]); bad_ip[24] ^= 1
        private = b'\xe1\x00' + self.frames[3]
        other = packet(1, 2, tk.ACK, port=PORT + 1)
        physical = tk.frame('192.168.10.11', '192.168.10.20', PORT, 20000, 1, 2, tk.ACK)
        offload = packet(1021, 2059, tk.ACK, offload=True)
        bad_dnp = bytearray(tk.read_request()); bad_dnp[-1] ^= 1
        bad_crc = packet(1021, 2059, tk.ACK, bytes(bad_dnp))
        unsupported = packet(1021, 2059, tk.ACK, tk.read_request(func=3))
        path = self.write('filtered.pcap', self.frames + [bytes(bad_tcp), bytes(bad_ip), private,
            other, physical, offload, bad_crc, unsupported, b'\0' * 54])
        manifest, frames = rp.collect([path], PORT)
        self.assertEqual(frames, self.frames)
        reasons = [p['reason'] for p in manifest['skipped']]
        for reason in ('tcp checksum', 'ip checksum', 'TX offload placeholder', 'DNP3 CRC',
                       'other flow', 'not Ethernet IPv4', 'unselected application'):
            self.assertIn(reason, reasons)

    def test_apply_refuses_without_authorization_or_parent_interface(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(rp.socket, 'socket') as sock:
            with self.assertRaisesRegex(ValueError, 'DEFENSE4_HW_AUTHORIZED'):
                rp.main(self.args('--apply'))
            sock.assert_not_called()
        with patch.dict(os.environ, {'DEFENSE4_HW_AUTHORIZED': '1'}), patch.object(rp.socket, 'socket') as sock:
            for interface in ('', 'lo', 'loop196', 'endpoint0'):
                with self.subTest(interface=interface), self.assertRaisesRegex(ValueError, 'interface'):
                    rp.main(self.args('--apply', '--interface', interface))
            sock.assert_not_called()

    def test_apply_requires_verified_fresh_same_tuple_handshake_and_distinct_ranges(self):
        base = ['--apply', '--interface', 'enp59s0f0np0', '--new-client-isn', '900000',
                '--new-server-isn', '800000']
        same = self.write('same.pcap', handshake(1000, 800000))
        overlap = self.write('overlap.pcap', handshake(1010, 800000))
        incomplete = self.write('incomplete.pcap', handshake(900000, 800000)[:2])
        changed_port = self.write('wrong-port.pcap', [packet(900000, 0, tk.SYN, port=PORT + 1),
            packet(800000, 900001, tk.SYN | tk.ACK, reverse=True, port=PORT + 1),
            packet(900001, 800001, tk.ACK, port=PORT + 1)])
        same_args = base.copy(); same_args[4] = '1000'
        overlap_args = base.copy(); overlap_args[4] = '1010'
        with patch.dict(os.environ, {'DEFENSE4_HW_AUTHORIZED': '1'}), patch.object(rp.socket, 'socket') as sock:
            for extra in (base, base + ['--new-pcap', self.old], base + ['--new-pcap', incomplete],
                          same_args + ['--new-pcap', same], overlap_args + ['--new-pcap', overlap],
                          base + ['--new-pcap', changed_port]):
                with self.subTest(extra=extra), self.assertRaises(ValueError):
                    rp.main(self.args(*extra))
            sock.assert_not_called()

    def test_apply_sends_exact_frames_once_at_mocked_boundary(self):
        extra = ['--apply', '--interface', 'enp59s0f0np0', '--new-pcap', self.new,
                 '--new-client-isn', '900000', '--new-server-isn', '800000']
        with patch.dict(os.environ, {'DEFENSE4_HW_AUTHORIZED': '1'}), patch.object(rp.socket, 'socket') as factory:
            raw = factory.return_value.__enter__.return_value
            raw.send.side_effect = lambda frame: len(frame)
            rc, manifest = self.invoke(*extra)
        self.assertEqual(rc, 0)
        self.assertTrue(manifest['applied'])
        raw.bind.assert_called_once_with(('enp59s0f0np0', 0))
        self.assertEqual([call.args[0] for call in raw.send.call_args_list], self.frames)

    def test_backward_halfspace_is_not_a_fresh_connection(self):
        manifest,_=rp.collect([self.old,self.empty],PORT)
        backward=self.write('backward.pcap',handshake((1000-100)&0xffffffff,800000))
        with self.assertRaisesRegex(ValueError,'ambiguous'):
            rp.fresh_guard(manifest,[backward],PORT,(1000-100)&0xffffffff,800000)

    def test_multiple_incarnations_or_corrupt_capture_are_refused(self):
        repeated = self.write('ambiguous.pcap', self.frames + handshake(5000, 6000))
        with self.assertRaises(ValueError):
            rp.collect([repeated], PORT)
        truncated = self.root / 'truncated.pcap'
        truncated.write_bytes(Path(self.old).read_bytes()[:-1])
        with self.assertRaises(ValueError):
            rp.collect([str(truncated)], PORT)

    def test_native_49_and_padded_58_are_separately_identified(self):
        native = packet(2001, 1021, tk.PSH | tk.ACK, response(49), reverse=True)
        path = self.write('native.pcap', self.frames + [native])
        manifest, frames = rp.collect([path], PORT)
        self.assertEqual([p['payload_bytes'] for p in manifest['packets']
                          if p['class'] == 'READ_RESPONSE'], [58, 49])
        self.assertEqual(frames[-1], native)

    def test_physical_flow_only_never_reaches_send_boundary(self):
        path = self.write('physical.pcap', [tk.frame('192.168.10.11', '192.168.10.20', PORT,
                                                   20000, 1, 0, tk.SYN)])
        with patch.dict(os.environ, {'DEFENSE4_HW_AUTHORIZED': '1'}), patch.object(rp.socket, 'socket') as sock:
            with self.assertRaises(ValueError):
                rp.main([path, self.empty, '--master-port', str(PORT), '--apply',
                         '--interface', 'enp59s0f0np0', '--new-pcap', self.new,
                         '--new-client-isn', '900000', '--new-server-isn', '800000'])
            sock.assert_not_called()

    def test_manifest_output_cannot_overwrite_retained_capture(self):
        original = Path(self.old).read_bytes()
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaisesRegex(ValueError, 'overwrite'):
            rp.main(self.args('--json', self.old))
        self.assertEqual(Path(self.old).read_bytes(), original)


if __name__ == '__main__':
    unittest.main()

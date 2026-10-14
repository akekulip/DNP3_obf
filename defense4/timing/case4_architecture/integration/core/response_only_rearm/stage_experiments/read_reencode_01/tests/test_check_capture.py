"""check_capture.py: the IEEE verifier for hardware captures, on the retained candidate56r run (negative)
and on synthetic runs built from that run's native frames (positive, and a misplaced octet)."""
import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
sys.dont_write_bytecode = True
sys.path[:0] = [str(HERE), str(HERE / 'tests'), str(HERE.parents[5] / 'case4_architecture/protocol/hw_vepa/tests')]
import capture  # noqa: E402
import check_capture  # noqa: E402
import pcaptk as tk  # noqa: E402
import reencode  # noqa: E402
from test_standards import RUN, directed, native_read  # noqa: E402

M, O, MP, OP = '192.168.10.61', '192.168.10.62', 59440, 20000


def synthetic(tmp, transform):
    """out.pcap = the retained native exchange; in.pcap = the same with each response passed through
    transform(i, frame). Requests and responses alternate, as in the retained run."""
    reqs = directed(RUN / 'out.pcap', MP, OP)
    rsps = directed(RUN / 'out.pcap', OP, MP)
    out, inn = [], []
    for side, conv in ((out, lambda i, f: f), (inn, transform)):
        sseq, rseq, t = 1000, 5000, 0
        for i, (q, r) in enumerate(zip(reqs, rsps)):
            r = conv(i, r)
            side.append((t, tk.frame(M, O, MP, OP, sseq, rseq, tk.PSH | tk.ACK, q)))
            sseq += len(q)
            side.append((t + 100, tk.frame(O, M, OP, MP, rseq, sseq, tk.PSH | tk.ACK, r)))
            rseq += len(r)
            t += 1000
    tk.write_pcap(str(Path(tmp) / 'out.pcap'), out)
    tk.write_pcap(str(Path(tmp) / 'in.pcap'), inn)
    return tmp


@unittest.skipUnless((RUN / 'out.pcap').exists(), 'retained candidate56r capture absent')
class CheckCapture(unittest.TestCase):
    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.tmp = td.name

    def test_retained_all58_run_is_flagged(self):
        res = check_capture.check(RUN)
        kinds = [v['kind'] for v in res['verdicts'] if not v['ok']]
        self.assertEqual(kinds, ['READ'] * 20 + ['SELECT', 'OPERATE'])
        self.assertFalse(res['conformant'])

    def test_reencoded_reads_and_native_controls_pass(self):
        run = synthetic(self.tmp, lambda i, f: reencode.reencode_frame(f) or f)
        res = check_capture.check(run)
        self.assertEqual(res['failures'], [])
        self.assertEqual([v['wire_len'] for v in res['verdicts']], [58] * 20 + [37, 37])
        self.assertEqual([v['kind'] for v in res['verdicts']], ['READ'] * 20 + ['SELECT', 'OPERATE'])
        first = res['verdicts'][0]
        self.assertEqual(first['request_serial'], 0)
        self.assertEqual(first['app_seq'], first['request_app_seq'])
        self.assertEqual(first['wire_frame_count'], first['segments'])
        self.assertRegex(first['wire_image_sha256'], r'^[0-9a-f]{64}$')
        self.assertEqual(first['tuple']['src']['port'], OP)
        self.assertEqual(first['tuple']['dst']['port'], MP)

    def test_read_answered_by_a_non_read_response_fails_even_when_delivered_unchanged(self):
        import dnp3_std as std

        def null_response(i, f):
            if i != 2:
                return f
            h, u = std.deframe(f)
            user = bytes(u[:5])                         # transport + application header + IIN, no objects
            return std.frame(h[:2] + bytes([5 + len(user)]) + h[3:], user)
        reqs = directed(RUN / 'out.pcap', MP, OP)
        rsps = [null_response(i, r) for i, r in enumerate(directed(RUN / 'out.pcap', OP, MP))]
        frames, sseq, rseq, t = [], 1000, 5000, 0
        for q, r in zip(reqs, rsps):
            frames.append((t, tk.frame(M, O, MP, OP, sseq, rseq, tk.PSH | tk.ACK, q)))
            sseq += len(q)
            frames.append((t + 100, tk.frame(O, M, OP, MP, rseq, sseq, tk.PSH | tk.ACK, r)))
            rseq += len(r)
            t += 1000
        for name in ('out.pcap', 'in.pcap'):
            tk.write_pcap(str(Path(self.tmp) / name), frames)
        res = check_capture.check(self.tmp, expected_lengths={'READ': 49, 'SELECT': 37, 'OPERATE': 37})
        self.assertFalse(res['conformant'])
        bad = [v for v in res['verdicts'] if not v['ok']]
        self.assertEqual([v['index'] for v in bad], [2])
        self.assertIn('READ request', bad[0]['error'])

    def test_misplaced_status_octet_fails(self):
        def bad(i, f):
            enc = reencode.reencode_frame(f)
            if i != 3 or enc is None:
                return enc or f
            import dnp3_std as std
            h, u = std.deframe(enc)
            u = bytearray(u)
            u[12] ^= 0x80                       # P0's state bit
            return std.frame(h, bytes(u))
        res = check_capture.check(synthetic(self.tmp, bad))
        self.assertEqual([v['index'] for v in res['verdicts'] if not v['ok']], [3])

    def test_sbo_application_header_iin_and_function_must_match_native(self):
        for label, offset, xor_value in (('app control', 1, 0x01), ('function', 2, 0x02),
                                         ('IIN1', 3, 0x01), ('IIN2', 4, 0x01)):
            with self.subTest(label=label):
                def bad(i, f, offset=offset, xor_value=xor_value):
                    if i != 20:
                        return reencode.reencode_frame(f) or f
                    import dnp3_std as std
                    h, u = std.deframe(f)
                    u = bytearray(u)
                    u[offset] ^= xor_value
                    return std.frame(h, bytes(u))

                res = check_capture.check(synthetic(self.tmp, bad))
                self.assertFalse(res['conformant'])
                self.assertEqual([v['index'] for v in res['verdicts'] if not v['ok']], [20])
                self.assertTrue(any('application fragment changed' in f or 'application sequence mismatch' in f
                                    for f in res['failures']))

    def test_faithfully_delivered_select_error_passes_transport_not_sbo_success(self):
        def select_error(i, f):
            if i != 20:
                return f
            import dnp3_std as std
            h, u = std.deframe(f)
            u = bytearray(u)
            u[4] = 0x01                         # IIN2 error bit: delivered faithfully, not authorizing.
            return std.frame(h, bytes(u))

        reqs = directed(RUN / 'out.pcap', MP, OP)
        rsps = directed(RUN / 'out.pcap', OP, MP)
        out, inn = [], []
        sseq, rseq, t = 1000, 5000, 0
        for i, (q, r) in enumerate(zip(reqs, rsps)):
            r = select_error(i, r)
            for side in (out, inn):
                side.append((t, tk.frame(M, O, MP, OP, sseq, rseq, tk.PSH | tk.ACK, q)))
                side.append((t + 100, tk.frame(O, M, OP, MP, rseq, sseq + len(q), tk.PSH | tk.ACK, r)))
            sseq += len(q)
            rseq += len(r)
            t += 1000
        tk.write_pcap(str(Path(self.tmp) / 'out.pcap'), out)
        tk.write_pcap(str(Path(self.tmp) / 'in.pcap'), inn)
        run = self.tmp
        res = check_capture.check(run)
        select = res['verdicts'][20]
        self.assertEqual(select['kind'], 'SELECT')
        self.assertTrue(select['transport_ok'])
        self.assertFalse(select['select_authorizes_operate'])
        self.assertFalse(res['conformant'])

    def test_expected_lengths_are_explicit_not_observed(self):
        run = synthetic(self.tmp, lambda i, f: reencode.reencode_frame(f) or f)
        ok = check_capture.check(run, expected_lengths={'READ': 58, 'SELECT': 37, 'OPERATE': 37})
        self.assertTrue(ok['conformant'])
        self.assertTrue(all(v['transport_ok'] for v in ok['verdicts']))
        bad = check_capture.check(run, expected_lengths={'READ': 61, 'SELECT': 61, 'OPERATE': 61})
        self.assertFalse(bad['conformant'])
        self.assertIn('READ #0: wire length 58 != expected 61', bad['failures'])

    def test_request_mutation_between_capture_points_fails(self):
        reqs = directed(RUN / 'out.pcap', MP, OP)
        rsps = directed(RUN / 'out.pcap', OP, MP)
        out, inn = [], []
        sseq, rseq, t = 1000, 5000, 0
        import dnp3_std as std
        for i, (q, r) in enumerate(zip(reqs, rsps)):
            wire_q = q
            if i == 0:
                h, u = std.deframe(q)
                u = bytearray(u)
                u[-1] ^= 1
                wire_q = std.frame(h, bytes(u))
            r = reencode.reencode_frame(r) or r
            out.append((t, tk.frame(M, O, MP, OP, sseq, rseq, tk.PSH | tk.ACK, q)))
            out.append((t + 100, tk.frame(O, M, OP, MP, rseq, sseq + len(q), tk.PSH | tk.ACK, r)))
            inn.append((t, tk.frame(M, O, MP, OP, sseq, rseq, tk.PSH | tk.ACK, wire_q)))
            inn.append((t + 100, tk.frame(O, M, OP, MP, rseq, sseq + len(q), tk.PSH | tk.ACK, r)))
            sseq += len(q)
            rseq += len(r)
            t += 1000
        tk.write_pcap(str(Path(self.tmp) / 'out.pcap'), out)
        tk.write_pcap(str(Path(self.tmp) / 'in.pcap'), inn)
        run = self.tmp
        res = check_capture.check(run)
        self.assertFalse(res['conformant'])
        self.assertIn('request stream differs between capture points', res['failures'])

    def test_missing_control_response_is_counted_once(self):
        reqs = directed(RUN / 'out.pcap', MP, OP)
        rsps = directed(RUN / 'out.pcap', OP, MP)
        out, inn = [], []
        sseq, rseq, t = 1000, 5000, 0
        for i, (q, r) in enumerate(zip(reqs, rsps)):
            if i == 21:
                break
            r = reencode.reencode_frame(r) or r
            for side in (out, inn):
                side.append((t, tk.frame(M, O, MP, OP, sseq, rseq, tk.PSH | tk.ACK, q)))
                side.append((t + 100, tk.frame(O, M, OP, MP, rseq, sseq + len(q), tk.PSH | tk.ACK, r)))
            sseq += len(q)
            rseq += len(r)
            t += 1000
        # Keep the OPERATE request but omit its response.
        q = reqs[21]
        for side in (out, inn):
            side.append((t, tk.frame(M, O, MP, OP, sseq, rseq, tk.PSH | tk.ACK, q)))
        tk.write_pcap(str(Path(self.tmp) / 'out.pcap'), out)
        tk.write_pcap(str(Path(self.tmp) / 'in.pcap'), inn)
        res = check_capture.check(self.tmp)
        self.assertFalse(res['conformant'])
        self.assertIn('missing control responses: expected 2, observed 1', res['failures'])

    def test_response_app_sequence_wrap_binds_to_serialized_request(self):
        reqs, rsps = [], []
        import dnp3_std as std
        for i in range(17):
            reqs.append(tk.read_request(i & 0x0f))
            rsps.append(std.frame(bytes([0x05, 0x64, 38, 0x44, 1, 0, 0x0a, 0]),
                                  std.deframe(native_read([0x81] * 23, seq=i & 0x0f))[1]))
        out, inn = [], []
        sseq, rseq, t = 1000, 5000, 0
        for q, r in zip(reqs, rsps):
            for side in (out, inn):
                side.append((t, tk.frame(M, O, MP, OP, sseq, rseq, tk.PSH | tk.ACK, q)))
                side.append((t + 100, tk.frame(O, M, OP, MP, rseq, sseq + len(q), tk.PSH | tk.ACK, r)))
            sseq += len(q)
            rseq += len(r)
            t += 1000
        tk.write_pcap(str(Path(self.tmp) / 'out.pcap'), out)
        tk.write_pcap(str(Path(self.tmp) / 'in.pcap'), inn)
        good = check_capture.check(self.tmp)
        self.assertTrue(good['conformant'])
        self.assertEqual([v['request_serial'] for v in good['verdicts']], list(range(17)))
        self.assertEqual([v['app_seq'] for v in good['verdicts']], [i & 0x0f for i in range(17)])
        self.assertTrue(all(v['wire_image_sha256'] == hashlib.sha256(rsps[i]).hexdigest()
                            for i, v in enumerate(good['verdicts'])))
        # Mutate only the last wire response app sequence after wrap.
        h, u = std.deframe(rsps[-1])
        u = bytearray(u)
        u[1] ^= 1
        rsps[-1] = std.frame(h, bytes(u))
        out, inn = [], []
        sseq, rseq, t = 1000, 5000, 0
        for q, r in zip(reqs, rsps):
            out.append((t, tk.frame(M, O, MP, OP, sseq, rseq, tk.PSH | tk.ACK, q)))
            out.append((t + 100, tk.frame(O, M, OP, MP, rseq, sseq + len(q), tk.PSH | tk.ACK, r)))
            inn.append((t, tk.frame(M, O, MP, OP, sseq, rseq, tk.PSH | tk.ACK, q)))
            inn.append((t + 100, tk.frame(O, M, OP, MP, rseq, sseq + len(q), tk.PSH | tk.ACK, r)))
            sseq += len(q)
            rseq += len(r)
            t += 1000
        tk.write_pcap(str(Path(self.tmp) / 'out.pcap'), out)
        tk.write_pcap(str(Path(self.tmp) / 'in.pcap'), inn)
        bad = check_capture.check(self.tmp)
        self.assertFalse(bad['conformant'])
        self.assertTrue(any('application sequence mismatch' in f for f in bad['failures']))

    def test_check_capture_accepts_multiple_confirmed_incarnations(self):
        import dnp3_std as std
        out, inn = [], []
        for inc, (c0, s0, t0) in enumerate(((1000, 5000, 0), (9000, 7000, 10000))):
            q = tk.read_request(inc)
            r = std.frame(bytes([0x05, 0x64, 38, 0x44, 1, 0, 0x0a, 0]),
                          std.deframe(native_read([0x81] * 23, seq=inc))[1])
            common = [
                (t0, tk.frame(M, O, MP, OP, c0, 0, tk.SYN)),
                (t0 + 100, tk.frame(O, M, OP, MP, s0, c0 + 1, tk.SYN | tk.ACK)),
                (t0 + 200, tk.frame(M, O, MP, OP, c0 + 1, s0 + 1, tk.ACK)),
                (t0 + 300, tk.frame(M, O, MP, OP, c0 + 1, s0 + 1, tk.PSH | tk.ACK, q)),
                (t0 + 400, tk.frame(O, M, OP, MP, s0 + 1, c0 + 1 + len(q), tk.PSH | tk.ACK, r)),
            ]
            out.extend(common)
            inn.extend(common)
        tk.write_pcap(str(Path(self.tmp) / 'out.pcap'), out)
        tk.write_pcap(str(Path(self.tmp) / 'in.pcap'), inn)
        res = check_capture.check(self.tmp, require_handshake=True)
        self.assertEqual(res['failures'], [])
        self.assertEqual(res['responses'], 2)

    def test_request_only_second_incarnation_fails_closed(self):
        import dnp3_std as std
        out, inn = [], []
        for inc, (c0, s0, t0) in enumerate(((1000, 5000, 0), (9000, 7000, 10000))):
            q = tk.read_request(inc)
            frames = [
                (t0, tk.frame(M, O, MP, OP, c0, 0, tk.SYN)),
                (t0 + 100, tk.frame(O, M, OP, MP, s0, c0 + 1, tk.SYN | tk.ACK)),
                (t0 + 200, tk.frame(M, O, MP, OP, c0 + 1, s0 + 1, tk.ACK)),
                (t0 + 300, tk.frame(M, O, MP, OP, c0 + 1, s0 + 1, tk.PSH | tk.ACK, q)),
            ]
            if inc == 0:
                r = std.frame(bytes([0x05, 0x64, 38, 0x44, 1, 0, 0x0a, 0]),
                              std.deframe(native_read([0x81] * 23, seq=inc))[1])
                frames.append((t0 + 400, tk.frame(O, M, OP, MP, s0 + 1, c0 + 1 + len(q), tk.PSH | tk.ACK, r)))
            out.extend(frames)
            inn.extend(frames)
        tk.write_pcap(str(Path(self.tmp) / 'out.pcap'), out)
        tk.write_pcap(str(Path(self.tmp) / 'in.pcap'), inn)
        res = check_capture.check(self.tmp, require_handshake=True)
        self.assertFalse(res['conformant'])
        self.assertIn('missing responses: expected 1, observed 0', res['failures'])


if __name__ == '__main__':
    unittest.main()

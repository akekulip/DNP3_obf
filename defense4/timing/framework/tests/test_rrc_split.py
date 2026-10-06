"""Bounded split (RRC_49_CUT28): synthetic carve tests and a re-analysis of the 2026-08-12 raw captures.

The captures are not copied into the tree. They are read from the archive revision with `git show` and checked
against the SHA-256 values in their own manifests; the class skips when the revision is not available.
Re-analysing historical traces is not a measurement of any current build.
"""
import hashlib
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
sys.path.insert(0, str(HERE.parent / "size"))
import rrc  # noqa: E402

REV = "9ffa9102d7a60095ed286f5c5dde2561a679b3d9"
BASE = "defense4/size/native_parity/evidence/"
CAPTURES = {
    ("readsbo", "read"): ("hw_rrc_readsbo_20260812T212234Z", "929193f66e18c22ee316692e584fb55e309f1302011da9e58a3864383cc61035"),
    ("readsbo", "sbo"): ("hw_rrc_readsbo_20260812T212234Z", "7b1ed5d735007866cb9db287530cc6f167ea173210ef6c8a8896cf23fb383a60"),
    ("joint", "read"): ("hw_rrc_joint_20260812T223342Z", "0ae59e6adc547931ed01c021e60e1a27c38f871d81aa9c8db107707268261974"),
    ("joint", "sbo"): ("hw_rrc_joint_20260812T223342Z", "9f1b25048a1530c3a3e3af55bbd016e34317fe9dab41201f48060ad97289bdd2"),
}


# ---- synthetic packets ---------------------------------------------------------------------------------------
def dnp3_frame(user=bytes(range(33))):
    ln = len(user) + 5
    head = bytes([0x05, 0x64, ln, 0x44, 0x00, 0x01, 0x00, 0x03])
    out = head + struct.pack("<H", rrc.dnp3_crc(head))
    for i in range(0, len(user), 16):
        blk = user[i:i + 16]
        out += blk + struct.pack("<H", rrc.dnp3_crc(blk))
    return out


def packet(payload, seq=1000, flags=0x18, options=b"", ihl=20, frag=0, sport=20000):
    tcp_len = 20 + len(options)
    ip = bytearray(struct.pack(">BBHHHBBH4s4s", 0x40 | ihl // 4, 0, ihl + tcp_len + len(payload), 0x1234, frag, 64, 6, 0,
                               bytes([192, 168, 10, 7]), bytes([192, 168, 10, 1])))
    ip += bytes(ihl - 20)
    struct.pack_into(">H", ip, 10, rrc._csum(bytes(ip)))
    tcp = bytearray(struct.pack(">HHIIBBHHH", sport, 40000, seq, 77, (tcp_len // 4) << 4, flags, 4096, 0, 0)) + options
    seg = bytes(tcp) + payload
    struct.pack_into(">H", tcp, 16, rrc._csum(bytes(ip[12:20]) + struct.pack(">BBH", 0, 6, len(seg)) + seg))
    return bytes(6) + bytes(6) + b"\x08\x00" + bytes(ip) + bytes(tcp) + payload


TS_OPT = b"\x01\x01\x08\x0a" + bytes(range(8))           # NOP NOP timestamp: data offset 8, total length 101


class Carve(unittest.TestCase):
    def check(self, raw):
        a, b = rrc.carve(raw)
        p, p1, p2 = rrc.parse(raw), rrc.parse(a), rrc.parse(b)
        self.assertEqual(p1.payload + p2.payload, p.payload)                     # byte-exact reassembly
        self.assertEqual((len(p1.payload), len(p2.payload)), (28, 21))
        self.assertEqual(p2.seq, (p1.seq + 28) & 0xFFFFFFFF)                    # contiguous, no hole or overlap
        self.assertEqual(p1.seq, p.seq)
        for q in (p1, p2):
            self.assertTrue(rrc.ip_ok(q) and rrc.tcp_ok(q))
            self.assertEqual(q.raw[p.tcp_off + 20:p.tcp_off + p.doff], p.raw[p.tcp_off + 20:p.tcp_off + p.doff])   # options kept
            self.assertEqual((q.sport, q.dport, q.ack), (p.sport, p.dport, p.ack))
            self.assertEqual(q.raw[:14], p.raw[:14])
        self.assertEqual(p1.flags & (rrc.PSH | rrc.FIN), 0)                     # prefix never carries PSH/FIN
        self.assertEqual(p2.flags, p.flags)                                     # suffix keeps the original flags
        self.assertTrue(rrc.dnp3_frame_ok(p1.payload + p2.payload))
        return p, p1, p2

    def test_plain_header_total_length_89(self):
        raw = packet(dnp3_frame())
        self.assertEqual(struct.unpack(">H", raw[16:18])[0], 89)
        self.check(raw)

    def test_timestamp_option_total_length_101(self):
        raw = packet(dnp3_frame(), options=TS_OPT)
        self.assertEqual(struct.unpack(">H", raw[16:18])[0], 101)
        self.check(raw)

    def test_sequence_wrap(self):
        p, p1, p2 = self.check(packet(dnp3_frame(), seq=0xFFFFFFF0))
        self.assertEqual(p2.seq, (0xFFFFFFF0 + 28) & 0xFFFFFFFF)

    def test_payload_is_49_bytes(self):
        self.assertEqual(len(dnp3_frame()), 49)

    def test_carved_segments_are_independent_of_object_content(self):
        for fill in (0x00, 0xAB, 0xFF):
            self.check(packet(dnp3_frame(bytes([fill]) * 33)))

    def test_unsupported_profiles_stay_unsplit(self):
        cases = {
            "58 B response": packet(dnp3_frame(bytes(42))),
            "bad CRC": packet(dnp3_frame()[:30] + b"\x00" + dnp3_frame()[31:]),
            "IPv4 options": packet(dnp3_frame(), ihl=24),
            "fragment": packet(dnp3_frame(), frag=0x2000),
            "SYN": packet(dnp3_frame(), flags=0x12),
            "RST": packet(dnp3_frame(), flags=0x14),
            "no ACK": packet(dnp3_frame(), flags=0x08),
            "two frames": packet(dnp3_frame() + dnp3_frame()),
            "not a frame": packet(bytes(49)),
        }
        for why, raw in cases.items():
            self.assertIsNone(rrc.carve(raw), why)
            self.assertFalse(rrc.eligible(rrc.parse(raw))[0], why)

    def test_cut_is_not_configurable(self):
        for cut in (1, 27, 29, 48):
            with self.assertRaises(ValueError):
                rrc.carve(packet(dnp3_frame()), cut=cut)

    def test_one_flipped_bit_in_a_checksum_is_detected(self):
        raw = bytearray(packet(dnp3_frame()))
        raw[50] ^= 1
        p = rrc.parse(bytes(raw))
        self.assertFalse(rrc.tcp_ok(p) and rrc.ip_ok(p))


class Case4Carve(unittest.TestCase):
    def test_explicit_57_profile_reassembles_and_keeps_sequence_flags(self):
        raw = packet(dnp3_frame(bytes(range(41))), seq=0xfffffff8, flags=0x19)
        a, b = rrc.carve(raw, profile="RRC_57_CUT28")
        p, q = rrc.parse(a), rrc.parse(b)
        self.assertEqual((len(p.payload), len(q.payload)), (28, 29))
        self.assertEqual(p.payload + q.payload, rrc.parse(raw).payload)
        self.assertEqual((p.seq, q.seq), (0xfffffff8, 20))
        self.assertEqual((p.flags, q.flags), (0x10, 0x19))
        self.assertTrue(rrc.ip_ok(p) and rrc.ip_ok(q) and rrc.tcp_ok(p) and rrc.tcp_ok(q))
        self.assertIsNone(rrc.carve(raw))

    def test_bad_network_checksums_never_carved(self):
        for offset in (24, 50):
            raw = bytearray(packet(dnp3_frame())); raw[offset] ^= 1
            self.assertIsNone(rrc.carve(bytes(raw)))

    def test_truncated_and_invalid_headers_never_carved(self):
        raw = packet(dnp3_frame())
        for v in (raw[:-1], raw[:34], raw[:14] + bytes([0x44]) + raw[15:]):
            self.assertIsNone(rrc.carve(v))
        with self.assertRaises(ValueError):
            rrc.carve(raw, profile="arbitrary")


class Joint(unittest.TestCase):
    """Timing then size, in the verified order: the response is released at e_R, then replicated and carved."""

    def run_joint(self, shape, payload=None):
        sys.path.insert(0, str(HERE.parent / "model"))
        from response_ready_model import Ev, ResponseReadyModel
        r = ResponseReadyModel(10_000_000, 1_000_000).run([
            Ev(0, "REQ", epoch=1, seq=1000, length=22, app=5), Ev(500_000, "ACK", epoch=1, ack=1022, app=5),
            Ev(2_000_000, "RESP", epoch=1, ack=1022, app=5)])
        raw = packet(payload or dnp3_frame())
        out = []
        for o in r.outs:
            if o.kind != "RESP":
                continue
            segs = rrc.carve(raw) if shape else None
            out += [(o.t, s) for s in (segs or (raw,))]
        return r, raw, out

    def test_both_segments_leave_at_the_timing_release_instant(self):
        r, raw, out = self.run_joint(shape=True)
        e_r = next(o.t for o in r.outs if o.kind == "RESP")
        self.assertEqual([t for t, _ in out], [e_r, e_r])                       # no early first part
        self.assertEqual(len(out), 2)

    def test_shaping_off_forwards_the_original_unicast_unchanged(self):
        r, raw, out = self.run_joint(shape=False)
        self.assertEqual([s for _, s in out], [raw])

    def test_timing_is_independent_of_whether_the_response_is_split(self):
        a, _, _ = self.run_joint(shape=True)
        b, _, _ = self.run_joint(shape=False)
        self.assertEqual([(o.kind, o.t) for o in a.outs], [(o.kind, o.t) for o in b.outs])

    def test_an_unsupported_payload_is_released_on_time_but_not_split(self):
        r, raw, out = self.run_joint(shape=True, payload=dnp3_frame(bytes(42)))
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0][0], next(o.t for o in r.outs if o.kind == "RESP"))


def historical(run, name, sha):
    out = subprocess.run(["git", "show", "%s:%s%s/captures/%s.pcap" % (REV, BASE, run, name)], cwd=ROOT, capture_output=True)
    if out.returncode:
        return None
    if hashlib.sha256(out.stdout).hexdigest() != sha:
        raise AssertionError("archived capture %s/%s does not match its manifest hash" % (run, name))
    f = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
    f.write(out.stdout)
    f.close()
    return f.name


class HistoricalCaptures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.paths = {k: historical(run, k[1], sha) for k, (run, sha) in CAPTURES.items()}
        if any(v is None for v in cls.paths.values()):
            raise unittest.SkipTest("archive revision %s is not available" % REV[:9])

    def responses(self, key):
        out = []
        for ts, raw in rrc.read_records(self.paths[key]):
            p = rrc.parse(raw)
            if p and p.sport == 20000 and p.payload:
                out.append((ts, p))
        return out

    def test_every_capture_reproduces_the_recorded_segmentation(self):
        for key in CAPTURES:
            sizes = sorted(len(p.payload) for _, p in self.responses(key))
            want = [21] * 30 + [28] * 30 + ([58] * 2 if key[1] == "sbo" else [])
            self.assertEqual(sizes, sorted(want), key)

    def test_all_captured_checksums_are_valid(self):
        for key in CAPTURES:
            for _, p in self.responses(key):
                self.assertTrue(rrc.ip_ok(p) and rrc.tcp_ok(p), key)

    def test_pairs_are_contiguous_and_reassemble_to_one_valid_49_byte_frame(self):
        for key in CAPTURES:
            by_seq = {p.seq: p for _, p in self.responses(key) if len(p.payload) == 28}
            tails = {p.seq: p for _, p in self.responses(key) if len(p.payload) == 21}
            self.assertEqual(len(by_seq), 30, key)
            for seq, head in by_seq.items():
                tail = tails[(seq + 28) & 0xFFFFFFFF]                     # a suffix at exactly seq + 28
                whole = head.payload + tail.payload
                self.assertEqual(len(whole), 49)
                self.assertTrue(rrc.dnp3_frame_ok(whole), key)
                self.assertEqual(head.flags & (rrc.PSH | rrc.FIN), 0, "prefix carries PSH/FIN")

    def test_sequence_order_and_capture_arrival_order_are_reported_separately(self):
        for key in CAPTURES:
            r = [p for _, p in self.responses(key) if len(p.payload) in (21, 28)]
            by_arrival = [len(p.payload) for p in r]
            by_seq = [len(p.payload) for p in sorted(r, key=lambda p: p.seq)]
            self.assertEqual(by_seq[:2], [28, 21], key)                    # sequence order is always [28, 21]
            arrival_pairs = {tuple(by_arrival[i:i + 2]) for i in range(0, len(by_arrival), 2)}
            self.assertEqual(arrival_pairs, {(21, 28)}, (key, arrival_pairs))   # the suffix is captured first

    def test_the_software_carve_reproduces_the_captured_segments_byte_for_byte(self):
        checked = 0
        for key in CAPTURES:
            r = [p for _, p in self.responses(key) if len(p.payload) in (21, 28)]
            heads = {p.seq: p for p in r if len(p.payload) == 28}
            tails = {p.seq: p for p in r if len(p.payload) == 21}
            for seq, head in heads.items():
                tail = tails[(seq + 28) & 0xFFFFFFFF]
                whole = rrc._build(tail, head.payload + tail.payload, head.seq, tail.flags)   # the unsplit original
                got = rrc.carve(whole)
                self.assertIsNotNone(got, key)
                self.assertEqual(got[0], head.raw, ("prefix", key, seq))
                self.assertEqual(got[1], tail.raw, ("suffix", key, seq))
                checked += 1
        self.assertEqual(checked, 120)

    def test_unsplit_58_byte_responses_are_not_carved(self):
        small = [p for _, p in self.responses(("readsbo", "sbo")) if len(p.payload) == 58]
        self.assertEqual(len(small), 2)
        for p in small:
            self.assertIsNone(rrc.carve(p.raw))


if __name__ == "__main__":
    unittest.main()

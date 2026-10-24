"""Actual SEL two-CROB bytes; whole-frame admission and faithful 15+17 reframing."""
import importlib.util
from pathlib import Path
import sys
import unittest
import struct
import json
import hashlib
import re

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))


class RelaySBO(unittest.TestCase):
    def test_new_checksum_operands_have_instantiated_egress_overlay_protection(self):
        from m12gen.build import build
        text, _ = build(c3='cimg', shapes='passthrough', two_read_build=True, reduce=True,
                        ack_retry=True, read_handshake=True, headroom=True, relay=True, relay_sbo=True)
        annotations = text[text.index('/* attached to the instantiated egress control:'):text.index('control r_Egress(')]
        for field in ('hdr.ctn.index2', 'hdr.ctn.code2', 'hdr.ctn.count2', 'hdr.ctn.on2',
                      'hdr.cstatus.status', 'hdr.cstatus.crc'):
            self.assertIn('@pa_no_overlay("egress","%s")' % field, annotations)
    def test_status_lookup_preserves_every_crc_and_rejects_every_bad_crc(self):
        import test_n_read_shapes as shared
        from m12gen import relay_sbo as r
        from m12gen.build import build
        text, _ = build(c3='cimg', shapes='passthrough', two_read_build=True, reduce=True,
                        ack_retry=True, read_handshake=True, headroom=True, relay=True, relay_sbo=True)
        n = text[text.index('table response_status_crc_t{'):]
        n = n[:n.index('\n')]
        entries = {(int(status), int(checksum, 16)) for status, checksum in
                   re.findall(r'\(8w(\d+),16w0x([0-9a-f]+)\):response_status_good\(\);', n)}
        self.assertEqual(len(entries), 256)
        self.assertIn('const default_action=response_status_bad();', n)
        normalizer = shared.n_source(text)
        egress = shared.interp.ESource(shared.role(text, 'E'))
        for status in range(256):
            wire_crc = int.from_bytes(struct.pack('<H', r.crc(bytes([status]))), 'big')
            # Exhaust all16,777,216(status,wireCRC) inputs; exactly one goodCRC
            # perstatus and every other16bitCRC fails the exact lookup.
            self.assertTrue(all(((status, candidate) in entries) == (candidate == wire_crc)
                                for candidate in range(65536)), status)
            normalizer.begin_pass(9)
            normalizer.env.update({'hdr.cstatus.status': status, 'hdr.cstatus.crc': wire_crc})
            normalizer.table('response_status_crc_t')
            self.assertEqual(normalizer.env['m.crc1'], 0x993a)
            for bit in range(16):
                normalizer.env['hdr.cstatus.crc'] = wire_crc ^ (1 << bit)
                normalizer.table('response_status_crc_t')
                self.assertEqual(normalizer.env['m.crc1'], 0)
            egress.begin_pass(0)
            egress.env['hdr.cstatus.status'] = status
            egress.table('status_crc_t')
            self.assertEqual(egress.env['m.in_rt'], r.crc(bytes([status])))
            self.assertEqual(egress.env['m.ctcrc3'], r.crc(bytes([0, status])))
        for removed in ('hash_response_status', 'hash_in_status', 'hash_ctl_tail3'):
            self.assertNotIn(removed, text)
    def test_all_eighty_native_control_exchanges(self):
        from m12gen import relay_sbo as r
        doc = json.loads((HERE.parent / 'read_complete_01/vectors/relay_sbo_templates.json').read_text())
        source = HERE
        while not (source / '.git').exists():
            source = source.parent
        self.assertEqual(hashlib.sha256((source / doc['source']).read_bytes()).hexdigest(), doc['source_sha256'])
        self.assertEqual(len(doc['exchanges']), 80)
        self.assertEqual(sum(x['function'] == 3 for x in doc['exchanges']), 40)
        for item in doc['exchanges']:
            request, native = bytes.fromhex(item['request']), bytes.fromhex(item['native'])
            qhead, quser = r.deframe(request)
            rhead, ruser = r.deframe(native)
            self.assertEqual(len(request), 45)
            self.assertEqual(len(native), 49)
            self.assertEqual(quser[1], ruser[1])
            self.assertEqual(r.control_objects(quser[1:]), r.control_objects(ruser[1:], response=True))
            self.assertEqual(r.encode(native).hex(), item['image'])

    def test_no_unused_third_frame_terms_in_control_checksum(self):
        from m12gen.build import build
        text, _ = build(c3='cimg', shapes='passthrough', two_read_build=True, reduce=True,
                        ack_retry=True, read_handshake=True, headroom=True, relay=True, relay_sbo=True)
        checksum = text[text.index('hdr.tcp.checksum = tcp_ctl.update'):]
        checksum = checksum[:checksum.index('});')]
        self.assertNotIn('hdr.cd3.', checksum)

    def test_old_ack_is_subtracted_in_parser_without_mapper_copy(self):
        from m12gen.build import build
        text, _ = build(c3='cimg', shapes='passthrough', two_read_build=True, reduce=True,
                        ack_retry=True, read_handshake=True, headroom=True, relay=True, relay_sbo=True)
        egress = text[text.index('parser r_EgParser'):text.index('/* Generated isolated T')]
        self.assertIn('tcp_old.subtract({hdr.tcp.seq, hdr.tcp.ack, hdr.tcp.window, hdr.tcp.checksum});', egress)
        self.assertNotIn('m.ack_inv', egress)

    def test_old_ack_subtraction_commutes_with_checksum_accumulation(self):
        import random
        rng = random.Random(0xc33)
        def folded(words):
            total = sum(words)
            while total >> 16:
                total = (total & 0xffff) + (total >> 16)
            return total
        for _ in range(2048):
            old_ack = rng.getrandbits(32)
            parser_words = [rng.getrandbits(16) for _ in range(23)]
            output_words = [rng.getrandbits(16) for _ in range(31)]
            inverse = [(~old_ack >> 16) & 0xffff, ~old_ack & 0xffff]
            old = folded(output_words + inverse + [folded(parser_words)])
            new = folded(output_words + [folded(parser_words + inverse)])
            self.assertEqual(old, new)
    def test_actual_capture_and_status_preservation(self):
        from m12gen import relay_sbo as r
        native = bytes.fromhex('05642644010000002f77d2cb8180000c011702010101c8000000e2170000000000030101c8000000000000008bf700ffff')
        hdr, user = r.deframe(native)
        self.assertEqual(r.control_objects(user[1:], response=True)[0]['index'], 1)
        self.assertEqual(r.control_objects(user[1:], response=True)[1]['index'], 3)
        for seq in range(64):
            for status in (0, 1, 3, 127):
                varied = bytearray(user); varied[0] = 0xc0 | seq; varied[-1] = status
                raw = r.frame(hdr, bytes(varied))
                out = r.encode(raw)
                chunks = r.split_frames(out)
                self.assertEqual([len(x) for x in chunks], [28, 32])
                users = [r.deframe(x)[1] for x in chunks]
                self.assertEqual(b''.join(x[1:] for x in users), bytes(varied[1:]))
                self.assertEqual(users[0][0], 0x40 | seq)
                self.assertEqual(users[1][0], 0x80 | ((seq + 1) & 63))
                self.assertEqual(len(out) - len(raw), 11)

    def test_range_read_49_is_not_control(self):
        from m12gen import relay_sbo as r
        raw = bytes.fromhex('05642644010000002f77c7c08180000a02000016010101010101f3c601010101010101010101010101010101bbc301a1c9')
        with self.assertRaises(ValueError):
            r.encode(raw)

    def test_opt_in_preserves_c30_source(self):
        from m12gen.build import build
        import hashlib
        flags = dict(c3='cimg', shapes='passthrough', two_read_build=True, reduce=True,
                     ack_retry=True, read_handshake=True, headroom=True, relay=True)
        old, _ = build(**flags)
        self.assertEqual(hashlib.sha256(old.encode()).hexdigest(),
                         'b006752236a7d1cccab461a010b2b68a3ea7b5629b1097c926ebacd348126de2')
        new, applied = build(**flags, relay_sbo=True)
        self.assertIn('relay_sbo', applied)
        self.assertNotEqual(old, new)

    def test_generated_egress_bytes_match_oracle(self):
        import test_n_read_shapes as shared
        from m12gen import relay_sbo as r
        from m12gen.build import build
        text, _ = build(c3='cimg', shapes='passthrough', two_read_build=True, reduce=True,
                        ack_retry=True, read_handshake=True, headroom=True, relay=True, relay_sbo=True)
        e = shared.interp.ESource(shared.role(text, 'E'))
        native = bytes.fromhex('05642644010000002f77d2cb8180000c011702010101c8000000e2170000000000030101c8000000000000008bf700ffff')
        hdr, user = r.deframe(native)
        for seq in (0, 1, 31, 62, 63):
            for status in (0, 3):
                varied = bytearray(user); varied[0] = 0xc0 | seq; varied[-1] = status
                raw = r.frame(hdr, bytes(varied))
                record = dict(src=(bytes([10, 0, 0, 2]), 20000), dst=(bytes([10, 0, 0, 1]), 56857),
                              payload=raw, seq=900, ack=146, flags=24)
                e.begin_pass(0); e.env['eg.egress_port'] = 9
                accepted, cursor = e.packet_parser(bytes(16) + shared.frame(record))
                self.assertTrue(accepted)
                for table in ('ctl_profile', 'in_dl_t', 'in_cb0_t', 'in_ct_t',
                              'status_crc_t', 'crc_ctl_tail2_t', 'ctl_pad_t'):
                    e.table(table)
                self.assertEqual(e.env['m.ctl_shape'], 1)
                encoded = e.deparse()[70:]
                self.assertEqual(encoded, r.encode(raw), (seq, status))

    def test_generated_normalizer_admits_both_crobs_and_distinguishes_read49(self):
        import test_n_read_shapes as shared
        from m12gen import relay_sbo as r
        from m12gen.build import build
        text, _ = build(c3='cimg', shapes='passthrough', two_read_build=True, reduce=True,
                        ack_retry=True, read_handshake=True, headroom=True, relay=True, relay_sbo=True)
        n = shared.n_source(text)
        request = bytes.fromhex('056424c4000001004a59cbcb030c011702010101c800000000008136000000030101c8000000000000000015ee')
        response = bytes.fromhex('05642644010000002f77d2cb8180000c011702010101c8000000e2170000000000030101c8000000000000008bf700ffff')
        def admit(raw, reverse=False):
            n.begin_pass(9)
            record = dict(src=(bytes([10, 0, 0, 2 if reverse else 1]), 20000 if reverse else 56857),
                          dst=(bytes([10, 0, 0, 1 if reverse else 2]), 56857 if reverse else 20000),
                          payload=raw, seq=900, ack=146, flags=24)
            key = [int.from_bytes(record['src'][0], 'big'), int.from_bytes(record['dst'][0], 'big'),
                   record['src'][1], record['dst'][1]]
            n.controls['Ingress'].tables['data_connection']['runtime'].clear()
            n.install('data_connection', key, 'configure', [301, 1, 1, 200, 0])
            accepted, cursor = n.packet_parser(shared.frame(record))
            self.assertTrue(accepted)
            n.run(shared._branch(text))
            n.table('network')
            n.table('next_seq_t')
            return dict(n.env)
        for raw, kind in ((request, 5), (response, 6)):
            got = admit(raw, kind == 6)
            self.assertEqual(got['m.packet_kind'], kind)
            self.assertEqual(got['m.profile'], 1)
            self.assertEqual(got['m.hcrc'], 0x993a)
            self.assertEqual(got['m.bcrc'], 0x993a)
            self.assertEqual(got['m.tcrc'], 0x993a)
            self.assertEqual(got['m.network_valid'], 1)
            self.assertEqual(got['m.new_seq'], 900 + len(raw))
            if kind == 6:
                self.assertEqual(got['m.crc1'], 0x993a)
        header, user = r.deframe(response)
        changed = bytearray(user); changed[4] = 1
        self.assertEqual(admit(r.frame(header, bytes(changed)), True)['m.profile'], 1)
        header, user = r.deframe(request)
        for offset in (19, 20, 21, 22, 26):
            changed = bytearray(user); changed[offset] ^= 1
            self.assertEqual(admit(r.frame(header, bytes(changed)))['m.profile'], 0, offset)
        read = bytes.fromhex('05642644010000002f77c7c08180000a02000016010101010101f3c601010101010101010101010101010101bbc301a1c9')
        read_got = admit(read, True)
        self.assertEqual(read_got['m.packet_kind'], 11)
        self.assertEqual(read_got['m.profile'], 0)

    def test_half_close_retains_retry_epoch_until_terminal_close(self):
        import test_n_read_shapes as shared
        from m12gen.build import build
        text, _ = build(c3='cimg', shapes='passthrough', two_read_build=True, reduce=True,
                        ack_retry=True, read_handshake=True, headroom=True, relay=True, relay_sbo=True)
        n = shared.n_source(text)
        for kind in (4, 17):
            for phase in (0x101, 0x102, 0x103, 0x107, 0x10b, 0x10f, 0x200):
                for packet_epoch in (1, 2):
                    n.begin_pass(68)
                    key = (n.frame.path, 'retry_epoch')
                    n.cells[key][0] = 2
                    n.env.update({'m.stage': 2, 'm.kind': kind, 'm.retry': 0,
                                  'hdr.envelope.epoch': packet_epoch,
                                  'hdr.origin.normalized_epoch': phase})
                    n.table('retry_epoch_t')
                    clears = packet_epoch == 2 and (phase == 0x10f or (kind == 4 and phase == 0x200))
                    self.assertEqual(n.cells[key][0], 0 if clears else 2, (kind, phase, packet_epoch))

    def test_only_both_success_statuses_publish_select_authority(self):
        import test_n_read_shapes as shared
        from m12gen.build import build
        text, _ = build(c3='cimg', shapes='passthrough', two_read_build=True, reduce=True,
                        ack_retry=True, read_handshake=True, headroom=True, relay=True, relay_sbo=True)
        n = shared.n_source(text)
        for first, second, iin_error in ((0, 0, 0), (1, 0, 0), (0, 3, 0), (0, 0, 1)):
            n.begin_pass(68)
            n.env.update({'m.stage': 2, 'm.kind': 6, 'm.work_phase': 2, 'm.epoch_diff': 0,
                          'm.return_abort': 0, 'hdr.expected_cell.expected_cell': 0xa0005,
                          'hdr.rtail.status': first, 'hdr.cstatus.status': second,
                          'hdr.first.w1': iin_error << 24})
            n.table('owner_command')
            self.assertEqual(n.env['m.desired'] >> 16, 5 if first or second or iin_error else 10)
        action = text[text.index('action publish_response()'):]
        action = action[:action.index('\n')]
        self.assertNotIn('if(', action)


if __name__ == '__main__':
    unittest.main()

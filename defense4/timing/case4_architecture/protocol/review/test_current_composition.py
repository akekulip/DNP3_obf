"""Independent current root-source review; fragment evidence, no target traffic."""
import re
from pathlib import Path
import sys
import unittest

ARCH = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ARCH / 'protocol/egress'), str(ARCH / 'protocol/egress/tests'),
               str(ARCH / 'protocol/tests'), str(ARCH / 'tests'),
               str(ARCH.parent / 'framework/size'), str(ARCH / 'protocol/assembly')]
from source_packets import Source
from source_eval import block
import test_packets as fixtures
from source_control import Source as ControlSource
from assembly_eval import Source as AssemblySource


def cache_source():
    text = (ARCH / 'integration/egress_selected_wire.p4').read_text()
    return text[text.index('/* Actual native35'):text.index('header forward_eth_h')].replace('cache_', '')


def cache_input(text, native, generation=2, replay=None):
    source = Source(text)
    raw = fixtures.packet(native, seq=18 if replay else 0xfffffff0)
    assert source.packet_parser(raw)[0]
    source.runtime = {'forwarding': ('route', (12,)), 'connection':
                      ('configure', (0xc900, 1, 1, 0x64000000, 0x64000000, generation))}
    if replay:
        source.runtime['replay_context'] = ('cached', replay)
    source.apply_control('Ingress')
    return source.deparse('IgDeparser', ('descriptor', 'eth', 'ip', 'tcp', 'replay',
                                       'dl', 'native', 'tail', 'appended', 'last'))


def cache_output(text, internal, banks):
    source = Source(text, registers=banks)
    assert source.packet_parser(internal, 'EgParser')[0]
    source.apply_control('Egress')
    return source, source.deparse('EgDeparser', ('eth', 'ip', 'tcp', 'image'))


class CurrentCacheReview(unittest.TestCase):
    def test_actual_descriptor_parser_rejects_other_operations_and_slots(self):
        text = cache_source()
        native = fixtures.fixtures.ExactImages().native(3)
        internal = cache_input(text, native)
        for operation, slot in ((0, 0), (3, 0), (1, 2), (2, 2), (2, 255)):
            changed = bytearray(internal)
            changed[8:10] = bytes((operation, slot))
            source = Source(text)
            self.assertFalse(source.packet_parser(bytes(changed), 'EgParser')[0])
            self.assertEqual(source.registers, {})

    def test_actual_outer_parser_error_guard_prevents_all_bank_calls(self):
        text = cache_source()
        native = fixtures.fixtures.ExactImages().native(3)
        internal = cache_input(text, native)
        root = (ARCH / 'integration/egress_selected_wire.p4').read_text()
        body = block(block(root, 'control Egress('), ' apply{')
        # Delegate the actual nested-control call; execute its real bank actions.
        body = re.sub(r'cache\.apply\([^;]+\);', 'invoke_cache();', body)
        body = re.sub(r'carving\.apply\([^;]+\);', 'wrong_role();', body)
        body = body.replace('m.cache.changed', 'm.changed').replace('m.carving.changed', 'm.unused_changed')

        class Outer(Source):
            def action(self, name, args=()):
                if name == 'invoke_cache':
                    self.apply_control('Egress')
                    return
                if name == 'wrong_role':
                    raise AssertionError('cache input invoked carver')
                return super().action(name, args)

        for parser_error in (0, 1):
            source = Outer(text, {'p.parser_err': parser_error, 'm.role': 1})
            self.assertTrue(source.packet_parser(internal, 'EgParser')[0])
            source.run(body)
            self.assertEqual(len(source.registers), 14 if parser_error == 0 else 0)
            self.assertEqual(source.env.get('md.drop_ctl', 0), int(parser_error != 0))

    def test_old_nonzero_descriptor_replays_reused_slot_without_lifetime_authority(self):
        text = cache_source()
        first = fixtures.fixtures.ExactImages().native(3)
        head, user = fixtures.codec.decode_frame(first)
        changed = bytearray(user)
        changed[10] ^= 1
        second = fixtures.codec.build_frame(head, bytes(changed))
        old_read = cache_input(text, first[-1:], replay=(2, 0xfffffff0, first[-1], 0))
        source, _ = cache_output(text, cache_input(text, first, generation=2), {})
        source, _ = cache_output(text, cache_input(text, second, generation=3), source.registers)
        source, replayed = cache_output(text, old_read, source.registers)
        expected = fixtures.codec.expand_control(second, fixtures.codec.Decoy(
            201, bytes.fromhex('0101640000006400000000')))[0]
        self.assertEqual(replayed, fixtures.expected_packet(expected, seq=0xfffffff0))
        self.assertEqual(source.env.get('md.drop_ctl', 0), 0)
        self.assertEqual(source.env['hdr.descriptor.generation'], 2)
        # This is the concrete need for immutable slot/no-reuse/current owner
        # binding. It does not assert that a protected production slot is reused.


class ReadParserReview(unittest.TestCase):
    def test_real_request_bytes_count_only_after_actual_parser_and_error_guard(self):
        text = (ARCH / 'integration/read/validator.p4').read_text()
        payload = bytes.fromhex('05640dc400000100f387c0c0010a020000165a2c')
        for error in (0, 1):
            source = Source(text, {'p.parser_err': error})
            self.assertTrue(source.packet_parser(fixtures.packet(payload))[0])
            self.assertEqual(source.env['m.tcp_sum'], 0xffeb)
            source.runtime = {'forwarding': ('route', (64,)),
                              'connection': ('forward', (64, 0, 0x0100))}
            source.run(block(block(text, 'control Ingress('), '\n apply{'))
            self.assertEqual(source.registers, {} if error else {('qualified', 0): 1})
            self.assertEqual(source.deparse('IgDeparser', ('eth', 'ip', 'tcp', 'dl', 'request')),
                             fixtures.packet(payload))


class CheckedAssemblySource(AssemblySource, ControlSource):
    pass


class AssemblyAuthorityReview(unittest.TestCase):
    def source(self, parser_error=0, hops=1, private=False, text=None,
               now=0, observation=None):
        if text is None:
            text = (ARCH / 'integration/assembly_passes/producer.p4').read_text()
        fields = {'m.parsed': 1, 'm.ip_error': 0, 'm.tcp_sum': 0xffeb,
                  'm.length': 1, 'm.full_length': 1, 'm.private': int(private),
                  'hdr.tcp.seq': 1000, 'hdr.b0.data': 5, 'p.global_tstamp': now,
                  'p.parser_err': parser_error, 'hdr.ref.epoch': 1,
                  'hdr.ref.generation': 7, 'hdr.ref.event': 1,
                  'hdr.fragment.hops': hops}
        banks = {('origin', 0): {'generation': 0, 'observation': 0}}
        if observation is not None:
            banks[('origin', 0)] = {'generation': 7, 'observation': observation}
        source = CheckedAssemblySource(text, fields, registers=banks)
        source.runtime = {'connection': ('context', (1, 7, 1000))}
        source.run(block(block(text, 'control Ingress('), 'apply{'))
        return source

    def test_old_authority_parser_error_counterexample_and_current_repair(self):
        old = (ARCH / 'integration/assembly_passes/evidence/producer_02/source/producer.p4').read_text()
        source = self.source(parser_error=1, text=old)
        self.assertEqual(source.registers[('origin', 0)]['generation'], 7)
        self.assertEqual(len([key for key in source.registers if key[0].startswith('bucket_')]), 12)
        self.assertEqual(source.env.get('md.drop_ctl', 0), 0)
        # Network-check values were explicitly supplied; this proves the source
        # lacks the intrinsic error gate, not a malformed target packet trace.
        repaired = self.source(parser_error=1)
        self.assertEqual(repaired.registers, {('origin', 0): {'generation': 0, 'observation': 0}})
        self.assertEqual(repaired.env['md.drop_ctl'], 1)

    def test_authority_hop16_is_processed_as_hop17(self):
        old = (ARCH / 'integration/assembly_passes/evidence/producer_03/source/producer.p4').read_text()
        source = self.source(hops=16, private=True, text=old)
        self.assertEqual(source.env['hdr.fragment.hops'], 17)
        self.assertEqual(source.env['hdr.ref.event'], 3)
        self.assertEqual(source.env.get('md.drop_ctl', 0), 0)
        self.assertEqual(len([key for key in source.registers if key[0].startswith('bucket_')]), 12)

    def test_new_authority_hop16_refused_before_origin_or_scratch(self):
        source = self.source(hops=16, private=True)
        self.assertEqual(source.env['hdr.fragment.hops'], 16)
        self.assertEqual(source.env['hdr.ref.event'], 6)
        self.assertEqual(source.env['m.fault'], 1)
        self.assertEqual(source.registers[('origin', 0)]['generation'], 0)
        self.assertFalse(any(key[0].startswith('bucket_') for key in source.registers))
        allowed = self.source(hops=15, private=True)
        self.assertEqual(allowed.env['hdr.fragment.hops'], 16)
        self.assertEqual(allowed.env['hdr.ref.event'], 3)

    def test_old_quantized_deadline_witness_and_new_current_no_scratch(self):
        old = (ARCH / 'integration/assembly_passes/evidence/producer_03/source/producer.p4').read_text()
        previous = self.source(private=True, text=old, now=30_000_127, observation=0)
        self.assertEqual(previous.env['m.age'], 29_999_872)
        self.assertEqual(previous.env.get('m.fault', 0), 0)
        self.assertTrue(any(key[0].startswith('bucket_') for key in previous.registers))
        repaired = self.source(private=True, now=30_000_127, observation=0)
        self.assertEqual(repaired.env['m.age'], 29_999_872)
        self.assertEqual(repaired.env['m.fault'], 1)
        self.assertEqual(repaired.env['hdr.ref.event'], 6)
        self.assertFalse(any(key[0].startswith('bucket_') for key in repaired.registers))

    def test_all_origin_residues_conservative_deadline_and_wrap(self):
        text = (ARCH / 'integration/assembly_passes/producer.p4').read_text()
        expiry = re.findall(r'if\(m.age>=32w\d+\)\{bad\(\);\}', text)
        self.assertEqual(len(expiry), 1)
        source = CheckedAssemblySource(text)
        # Actual clock/observation/elapsed actions and actual expiry condition;
        # no hardcoded target threshold or synthetic expiry predicate.
        earliest = 30_000_000
        for base in (0, 0xffffff00):
            for residue in range(256):
                origin = (base + residue) & 0xffffffff
                source.env = {'p.global_tstamp': origin, 'm.generation': 7}
                source.registers = {('origin', 0): {'generation': 0, 'observation': 0}}
                source.action('clock_now')
                source.env['hdr.fragment.arrival'] = source.env['m.now']
                source.action('observation')
                initial = dict(source.registers[('origin', 0)])
                for elapsed in (29_999_616, 29_999_617, 29_999_999, 30_000_000, 30_000_001):
                    source.env.update({'p.global_tstamp': (origin + elapsed) & 0xffffffff,
                                       'm.fault': 0})
                    source.action('clock_now')
                    source.action('observation')
                    source.action('elapsed')
                    source.run(expiry[0])
                    self.assertEqual(source.registers[('origin', 0)], initial)
                    if elapsed >= 30_000_000:
                        self.assertEqual(source.env['m.fault'], 1, (base, residue, elapsed))
                    if elapsed == 29_999_616:
                        self.assertEqual(source.env['m.fault'], 0, (base, residue, elapsed))
                    if source.env['m.fault']:
                        earliest = min(earliest, elapsed)
        self.assertEqual(earliest, 29_999_617)  # At most383ns conservative early expiry.


if __name__ == '__main__':
    unittest.main()

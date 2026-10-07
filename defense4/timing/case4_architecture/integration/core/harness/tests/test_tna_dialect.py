"""Harness fixes: lazy binary operators, hex struct initializers, TNA dialect, multiple externs."""
import time
import unittest
from pathlib import Path

import support  # noqa: F401  (puts the harness on sys.path)
from interp_ext import ExtSource
from tna_dialect import normalize

ARCH = Path(__file__).resolve().parents[4]
READ = ARCH / 'integration/read'

TNA = r'''
#include <core.p4>
#include <tna.p4>
header eth_t { bit<48> dst; bit<48> src; bit<16> type; }
struct pair_t { bit<32> a; bit<32> b; }
struct header_t { pktgen_timer_header_t timer; eth_t eth; }
struct metadata_t { bit<32> now; bit<32> big; bit<32> got; bit<32> sum; }
control Adder(in bit<32> x, inout bit<32> y) {
    Register<pair_t, bit<1>>(1, {1, 0x10000}) cell;
    RegisterAction<pair_t, bit<1>, bit<32>>(cell) bump = {
        void apply(inout pair_t value, out bit<32> out_value) { value.b = value.b + x; out_value = value.b; }
    };
    apply { y = bump.execute(0); }
}
control Second(in bit<32> x, inout bit<32> y) {
    Register<bit<32>, bit<1>>(1, 7) reg;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg) rd = {
        void apply(inout bit<32> value, out bit<32> out_value) { out_value = value; }
    };
    apply { y = rd.execute(0) + x; }
}
parser IngressParser(packet_in pkt, out header_t hdr, out metadata_t md,
                     out ingress_intrinsic_metadata_t ig_intr_md) {
    Checksum() first_sum;
    state start { pkt.extract(ig_intr_md); pkt.advance(PORT_METADATA_SIZE);
        transition select(ig_intr_md.ingress_port) { 5 : timer; default : plain; } }
    state timer { pkt.extract(hdr.timer); transition plain; }
    state plain { pkt.extract(hdr.eth); transition accept; }
}
control Ingress(inout header_t hdr, inout metadata_t md,
                in ingress_intrinsic_metadata_t ig_intr_md,
                in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
                inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {
    Adder() adder; Second() second;
    apply {
        md.now = ((bit<32>)ig_prsr_md.global_tstamp) & 32w0xffffff00;
        md.big = md.now & 32w0xfffffff0;
        adder.apply(md.now, md.got);
        second.apply(md.got, md.sum);
        ig_tm_md.ucast_egress_port = 9w3;
        ig_dprsr_md.drop_ctl = 0;
    }
}
control IngressDeparser(packet_out pkt, inout header_t hdr, in metadata_t md,
                        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) { apply { pkt.emit(hdr); } }
'''
FRAME = bytes.fromhex('001122334455aabbccddeeff0800') + bytes(8)


def tna_source():
    return ExtSource(TNA, include_dir=READ)


class BinaryOperators(unittest.TestCase):
    def test_masking_with_a_large_constant_is_not_a_giant_shift(self):
        src = tna_source()
        src.begin_pass(1)
        src.env['ig.global_tstamp'] = 0x12345678
        start = time.time()
        for _ in range(200):
            self.assertEqual(src.expr('(bit<32>)ig.global_tstamp & 32w0xffffff00'), 0x12345600)
        self.assertLess(time.time() - start, 0.5)   # eager `<<` cost about 0.28 s per evaluation

    def test_operator_results_are_unchanged(self):
        src = tna_source()
        for text, want in (('32w7 + 32w9', 16), ('32w9 - 32w7', 2), ('32w6 | 32w1', 7), ('32w6 ^ 32w3', 5),
                           ('32w1 << 32w4', 16), ('32w32 >> 32w3', 4), ('32w9 / 32w2', 4), ('32w9 % 32w4', 1),
                           ('32w3 - 32w5', 0xfffffffe)):
            self.assertEqual(src.expr(text), want, text)


class Initializers(unittest.TestCase):
    def test_hex_struct_initializer_is_parsed_whole(self):
        src = tna_source()
        self.assertEqual(src.cells[('adder', 'cell')][0], {'a': 1, 'b': 0x10000})
        self.assertEqual(src.cells[('second', 'reg')][0], 7)


class Dialect(unittest.TestCase):
    def test_harness_dialect_text_is_returned_unchanged(self):
        text = 'struct headers_t{}\nstruct meta_t{}\n'
        self.assertEqual(normalize(text), text)

    def test_tna_names_are_renamed_without_touching_statements(self):
        out = normalize(TNA)
        for token in ('struct headers_t', 'struct meta_t', 'parser IgParser', 'control IgDeparser',
                      'ig.global_tstamp', 'tm.ucast_egress_port', 'md.drop_ctl', 'm.now', 'Checksum() ic;'):
            self.assertIn(token, out)
        self.assertIn('header pktgen_timer_header_t', out)
        self.assertNotIn('ig_intr_md', out)

    def test_pass_runs_with_tna_names_and_timer_header(self):
        src = tna_source()
        src.begin_pass(5)
        src.env['ig.global_tstamp'] = 0x2345678
        accepted, cursor = src.packet_parser(bytes(6) + FRAME)
        self.assertTrue(accepted)
        self.assertEqual(cursor, 6 + 14)
        src.apply_control('Ingress')
        self.assertEqual(src.env['tm.ucast_egress_port'], 3)
        self.assertEqual(src.env['m.now'], 0x2345600)

    def test_non_timer_port_skips_the_timer_header(self):
        src = tna_source()
        src.begin_pass(1)
        self.assertEqual(src.packet_parser(FRAME), (True, 14))


class MultipleExterns(unittest.TestCase):
    def test_every_instantiated_control_has_registers_and_runs(self):
        src = tna_source()
        self.assertEqual(sorted(src.controls), ['Adder', 'Ingress', 'Second'])
        src.begin_pass(1)
        src.env['ig.global_tstamp'] = 0x100
        src.packet_parser(FRAME)
        src.apply_control('Ingress')
        self.assertEqual(src.env['m.got'], 0x10000 + 0x100)
        self.assertEqual(src.env['m.sum'], 7 + 0x10100)
        self.assertEqual(src.cells[('adder', 'cell')][0]['b'], 0x10100)


class ReadTiming(unittest.TestCase):
    def test_read_timing_p4_runs_in_the_harness_unmodified(self):
        path = READ / 'read_timing.p4'
        src = ExtSource(path.read_text(), include_dir=READ)
        self.assertIn('OriginalCredit', src.controls)
        self.assertIn('ExpectedWorkRecord', src.controls)
        self.assertEqual(src.cells[('credits', 'cell')][0], {'epoch': 0, 'credit': 0})


if __name__ == '__main__':
    unittest.main()

"""The SEL-751 sends its FIN as FIN+PSH+ACK (0x19, no payload); N must treat it as FIN+ACK (0x11) (c52).

Physical evidence: native02 and the unmanaged reconnect connection show the relay FIN as FPA; on c51 every managed
graceful close stopped half-closed (rc01_hw_c51_20261024_18/20/21) because N's close rows match 0x11 only.
Source-interpreter tier (N only).
"""
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from m12gen.build import build
from m12gen.relay_sbo import FIN_FLAG_TABLES
import test_relay_half_closed_rst as half
import test_relay_ts as ts

FA, FPA = 0x11, 0x19


class RelayFinPsh(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.c51 = half.C50.parent.parent / 'm12p_c51_sdk9132/response_only.p4'
        cls.c51 = cls.c51.read_text()
        cls.selected, _ = build(**ts.FLAGS, relay_ts=True)

    def close(self, text, flags, direction=2, owner=half.OWNER_0109, seq_delta=None):
        p = half.pipeline(text)
        half.preset(p, owner=owner)
        delta = (0 if direction == 2 else 1) if seq_delta is None else seq_delta
        trace, emitted, dropped = half.inject(p, *half.rst(direction, flags, seq_delta=delta))
        return p, trace, emitted, dropped

    def test_c51_drops_the_relay_fpa_fin(self):
        p, trace, emitted, _ = self.close(self.c51, FPA)
        self.assertEqual(half.hits(trace, 'network')[0], 'NoAction')
        self.assertEqual(p.cell('', 'owner'), half.OWNER_0109)

    def test_relay_fpa_fin_closes_exactly_like_fa(self):
        results = []
        for flags in (FA, FPA):
            p, trace, emitted, dropped = self.close(self.selected, flags)
            results.append((half.hits(trace, 'network'), half.hits(trace, 'first_event'), half.hits(trace, 'close_phase_t'),
                            p.cell('', 'owner'), [port for port, _ in emitted], dropped))
        self.assertEqual(results[0], results[1])
        self.assertEqual(results[1][0][0], 'network_accept')
        self.assertEqual(results[1][1], ['first_close'])
        self.assertEqual(results[1][3] >> 16, 0x10b)

    def test_relay_answering_the_master_fin_with_fpa_directly(self):
        """No separate relay ACK: the FPA arrives while the owner still holds the master FIN (0x0101)."""
        results = []
        for flags in (FA, FPA):
            p, trace, emitted, dropped = self.close(self.selected, flags, owner=0x01010001)
            results.append((half.hits(trace, 'first_event'), p.cell('', 'owner'), [port for port, _ in emitted], dropped))
        self.assertEqual(results[0], results[1])
        self.assertEqual(results[1][0][0], 'first_close')

    def test_half_closed_rst_still_resets_on_c52(self):
        for direction, flags in ((1, 0x14), (2, 0x04)):
            p, trace, emitted, dropped = self.close(self.selected, flags, direction=direction)
            self.assertEqual(half.hits(trace, 'first_event'), ['first_close'])
            self.assertEqual(p.cell('', 'owner'), 0x02000001)

    def test_master_fpa_fin_from_open_closes_like_fa(self):
        results = []
        for flags in (FA, FPA):
            p, trace, emitted, dropped = self.close(self.selected, flags, direction=1, owner=0x00050001, seq_delta=0)
            results.append((half.hits(trace, 'first_event'), p.cell('', 'owner'), [port for port, _ in emitted]))
        self.assertEqual(results[0], results[1])
        self.assertEqual(results[1][0][0], 'first_close')

    def test_every_widened_row_matches_exactly_fa_and_fpa(self):
        """Parsed from the emitted tables: each changed flags term admits exactly {0x11, 0x19}; no other term moved."""
        n_old, n_new = half.shared.role(self.c51, 'N'), half.shared.role(self.selected, 'N')
        for name in FIN_FLAG_TABLES:
            with self.subTest(table=name):
                def terms(text):
                    table = text[text.index('table %s{' % name):]
                    table = table[:table.index('}}') + 2]
                    keys = [k for k in re.search(r'key=\{([^}]*)\}', table).group(1).split(';') if k.strip()]
                    col = next(i for i, k in enumerate(keys) if k.strip().startswith('hdr.tcp.flags'))
                    return [t.split(',')[col] for t in re.findall(r'\(([^()]*)\):', table) if len(t.split(',')) == len(keys)]
                old, new = terms(n_old), terms(n_new)
                self.assertEqual(len(old), len(new))
                for a, b in zip(old, new):
                    if a == b:
                        continue
                    self.assertEqual((a, b), ('8w17', '8w17&&&8w0xf7'))
                    value, mask = half._term(b)
                    self.assertEqual({v for v in range(256) if v & mask == value}, {0x11, 0x19})

    def test_emitted_change_is_only_fin_flag_columns_parser_row_and_short_shape_twins(self):
        import difflib
        for role in ('E', 'T'):
            self.assertEqual(half.shared.role(self.c51, role), half.shared.role(self.selected, role))
        old = self.c51.replace(';', ';\n').splitlines()
        new = self.selected.replace(';', ';\n').splitlines()
        changed = [l for l in difflib.unified_diff(old, new, lineterm='', n=0)
                   if l[:1] in '+-' and not l.startswith(('+++', '---'))]
        removed = [l[1:] for l in changed if l.startswith('-')]
        added = [l[1:] for l in changed if l.startswith('+')]
        # every removed line reappears with exactly one 8w17 column widened, or is short_shapes' size
        widened = [l for l in added if '8w17&&&8w0xf7' in l]
        self.assertEqual(sorted(l.replace('8w17&&&8w0xf7', '8w17') for l in widened),
                         sorted(l for l in removed if 'size=7' not in l))
        extra = sorted(set(added) - set(widened))
        self.assertEqual(extra, sorted(['(2w1,8w25):close_shape();', '(2w2,8w25):close_shape();',
                                        '(4w8,8w25):ts_close;', '}size=9;']))

if __name__ == '__main__':
    unittest.main()

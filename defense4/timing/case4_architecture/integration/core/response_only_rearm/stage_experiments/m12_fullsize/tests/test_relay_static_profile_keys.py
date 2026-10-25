"""Canonical keys avoid the observed SDK static-entry offset-index defect.

9.13.1's installed pipe_mgr_ctx_json_rmt_cfg.c indexes field widths by
logical position rather than slice index. Its exact algorithm predicts all
9.13.2 c48 SW/HW readback errors; this is not a claim of identical binaries.
"""
import hashlib
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from m12gen.build import build
from m12gen import relay_sbo
import test_n_read_shapes as shared
import test_relay_ts as ts


def layout(n, table):
    fields, positions = [], {}
    for expr, kind in n.controls['Ingress'].tables[table]['keys']:
        base = expr[1] if expr[0] == 'slice' else expr
        name = base[1]
        low, width = (expr[3], expr[2] - expr[3] + 1) if expr[0] == 'slice' else (0, n.width[name])
        positions.setdefault(name, len(positions))
        fields.append((name, positions[name], n.width[name], low, width, kind))
    return fields


def loader(n, table, row):
    """Replay the primary loader's byte-aligned bit copies and wrong offsets."""
    fields = layout(n, table)
    widths = [f[2] for f in fields]
    good, bad, correct, buggy = 0, 0, {}, {}
    for pos in sorted({f[1] for f in fields}):
        first = next(f for f in fields if f[1] == pos)
        correct[pos], buggy[pos] = good, bad
        good += (first[2] + 7) // 8
        bad += (widths[pos] + 7) // 8  # installed C uses [i], not [j]
    # The original writes can extend past its computed key size; allocate
    # scratch space here to reproduce values without reproducing unsafe C.
    key, mask = bytearray(128), bytearray(128)
    wanted = {}
    for f, term in zip(fields, row):
        name, pos, full, low, width, kind = f
        value = term[1][1]
        selected = (1 << width) - 1
        bits = term[2][1] if term[0] == 'mask' else selected
        wanted.setdefault(name, [0, 0])
        wanted[name][0] |= value << low
        wanted[name][1] |= (bits & selected) << low
        for buf, number in ((key, value), (mask, bits & selected)):
            for j, octet in enumerate((number << low).to_bytes((full + 7) // 8, 'big')):
                buf[buggy[pos] + j] |= octet
    observed = {}
    for name, pos, full, *_ in fields:
        off, count = correct[pos], (full + 7) // 8
        observed[name] = [int.from_bytes(key[off:off + count], 'big'),
                          int.from_bytes(mask[off:off + count], 'big')]
    return wanted, observed


class RelayStaticProfileKeys(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = (shared.STAGE / 'ctl_timing_01/evidence/m12p_c48_sdk9132/response_only.p4').read_text()
        with patch.object(relay_sbo, 'retry_fin_phase', side_effect=lambda src: src), patch.object(relay_sbo, 'half_closed_rst', side_effect=lambda src: src), patch.object(relay_sbo, 'relay_fin_psh', side_effect=lambda src: src):
            cls.selected, _ = build(**ts.FLAGS, relay_ts=True)

    def test_c48_loader_predicts_every_observed_bad_tail_field(self):
        self.assertEqual(hashlib.sha256(self.original.encode()).hexdigest(),
                         '902a84bf1714d15788b707b7c23b86c4abe8f66a4ba8395d1d52f0377a2eae66')
        n = shared.n_source(self.original)
        recorded = {
            'profile': {'hdr.tail.index2': 0, 'hdr.tail.code2': 0, 'hdr.tail.count2': 0,
                        'hdr.tail.on2': 0x300, 'hdr.tail.off2': 0x100, 'hdr.tail.status2': 1},
            'response_profile': {'hdr.rtail.code2': 0, 'hdr.rtail.count2': 0,
                                 'hdr.rtail.on2': 0x10000, 'hdr.rtail.off2': 0x1c800}}
        for table, errors in recorded.items():
            for row, _, _ in n.controls['Ingress'].tables[table]['entries']:
                wanted, actual = loader(n, table, row)
                differences = {k: v[0] for k, v in actual.items() if v[0] != wanted[k][0]}
                self.assertEqual(differences, errors, table)

    def test_selected_keys_have_unique_positions_and_loader_preserves_all_bits(self):
        n = shared.n_source(self.selected)
        for table in ('profile', 'response_profile'):
            fields = layout(n, table)
            self.assertEqual(len(fields), len({f[1] for f in fields}), table)
            for row, _, _ in n.controls['Ingress'].tables[table]['entries']:
                wanted, actual = loader(n, table, row)
                self.assertEqual(actual, wanted, table)

    def test_primary_loader_prediction_matches_committed_software_and_hardware_rows(self):
        path = shared.STAGE / 'ctl_timing_01/evidence/model_profile_diagnostic_m12p_c48_sdk9132_02/profile_table_readback.json'
        record = json.loads(path.read_text())
        self.assertEqual(record['errors'], [])
        n = shared.n_source(self.original)
        for table in ('profile', 'response_profile'):
            captured = record['tables']['p0.n_Ingress.' + table]
            fields = layout(n, table)
            self.assertEqual([(f['name'], f['position'], f['bit_width_full'], f['start_bit'],
                               f['bit_width'], f['match_type']) for f in captured['expected_match_fields']], fields)
            rows = n.controls['Ingress'].tables[table]['entries']
            for view in ('software', 'hardware'):
                self.assertEqual(captured['reads'][view]['entry_count'], len(rows))
                for (row, _, _), observed in zip(rows, captured['reads'][view]['entries']):
                    _, predicted = loader(n, table, row)
                    for name, _, full, low, width, _ in fields:
                        label = name if width == full else '%s[%d:%d]' % (name, low + width - 1, low)
                        value = observed['key'][label]
                        self.assertEqual((predicted[name][0] >> low) & ((1 << width) - 1), value['value'])
                        if 'mask' in value:
                            self.assertEqual((predicted[name][1] >> low) & ((1 << width) - 1), value['mask'])

    def test_fullword_predicates_equal_original_for_fixed_bits_and_all_wildcards(self):
        old, new = shared.n_source(self.original), shared.n_source(self.selected)
        for table in ('profile', 'response_profile'):
            for row, _, _ in old.controls['Ingress'].tables[table]['entries']:
                wanted, _ = loader(old, table, row)
                seed = {name: value for name, (value, _) in wanted.items()}
                variants = [seed]
                # Each fixed field bit remains checked. Every possible octet
                # proves all transport/application/IIN wildcard combinations
                # compositionally, including the response's entire IIN byte.
                for name, (_, mask) in wanted.items():
                    for bit in range(old.width[name]):
                        variants.append(dict(seed, **{name: seed[name] ^ (1 << bit)}))
                    if mask != (1 << old.width[name]) - 1:
                        for low in range(0, old.width[name], 8):
                            for octet in range(256):
                                variants.append(dict(seed, **{name: (seed[name] & ~(255 << low)) | (octet << low)}))
                for env in variants:
                    expected = all((env[name] & mask) == (value & mask)
                                   for name, (value, mask) in wanted.items())
                    for n in (old, new):
                        n.begin_pass(9); n.env.update(env); n.env['m.profile'] = 0; n.table(table)
                        # The alternate request FC row is also legitimate.
                        alternate = table == 'profile' and env['hdr.first.w0'] == (seed['hdr.first.w0'] ^ 0x700)
                        self.assertEqual(bool(n.env['m.profile']), expected or alternate, (table, env))

    def test_only_two_profile_tables_change_lifecycle_and_status_authority_stay_exact(self):
        old, new = self.original, self.selected
        for table in ('profile', 'response_profile'):
            a, b = 'table ' + table + '{', '\n'
            old = old[:old.index(a)] + '<' + table + '>' + old[old.index(b, old.index(a)):]
            new = new[:new.index(a)] + '<' + table + '>' + new[new.index(b, new.index(a)):]
        self.assertEqual(new, old)


if __name__ == '__main__':
    unittest.main()

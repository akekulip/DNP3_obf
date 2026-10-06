"""Every const table must be able to hold its const entries.

bf-p4c accepts a table whose const entries outnumber its declared size, and every offline model passes; the driver then fails to instantiate the device
('Not enough space adding static entry N'). Found on the switch on 2026-10-06 (tbl_owner_valid: 5 entries, size 4). This test is the offline stand-in."""
import re
import unittest
from test_p4_release import SOURCE, sem


def const_tables(src):
    out = {}
    for m in re.finditer(r'\btable\s+(\w+)\s*\{', src):
        blk = sem._extract_block_after(src, m.end() - 1)
        if 'const entries' not in blk:
            continue
        e = blk[blk.index('const entries'):]
        body = sem._extract_block_after(e, e.index('{'))
        n = len(re.findall(r'\)\s*:\s*\w+\s*\([^;]*\)\s*;', body))
        sz = re.search(r'\bsize\s*=\s*(\d+)\s*;', blk)
        out[m.group(1)] = (n, int(sz.group(1)) if sz else None)
    return out


class Capacity(unittest.TestCase):
    def test_every_const_table_has_room_for_its_entries(self):
        tables = const_tables(SOURCE.read_text())
        self.assertGreaterEqual(len(tables), 15)
        bad = {k: v for k, v in tables.items() if v[1] is None or v[0] > v[1]}
        self.assertEqual(bad, {}, "const entries exceed the declared size (entries, size)")

    def test_the_scan_catches_the_defect_that_the_hardware_found(self):
        src = SOURCE.read_text()
        i = src.index('table tbl_owner_valid {')
        j = src.index('size = ', i)
        mutant = src[:j] + 'size = 4' + src[src.index(';', j):]
        bad = {k: v for k, v in const_tables(mutant).items() if v[0] > (v[1] or 0)}
        # The working candidate adds commitment-pass ownership rows. The mutant
        # retains the historical insufficient capacity, with the current entries.
        self.assertEqual(bad, {'tbl_owner_valid':
                              (const_tables(src)['tbl_owner_valid'][0], 4)})
        self.assertGreater(bad['tbl_owner_valid'][0], 4)


if __name__ == '__main__':
    unittest.main()

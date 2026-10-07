"""Behaviour preservation of the stage-fit restructure of native_binding.p4.

The oracle is the frozen pre-restructure source (35bf9aa3..., commit 78a0b50da) in
tests/oracle_35bf9aa3_native_binding.p4. differential.py runs oracle and regenerated source
through the same whole-program interpreter from the same post-parser state and compares every
output that leaves the pipeline: private-header contents and validity, drop control, egress port,
bypass, the emit-loop flag, and every register (owner, epoch, client, server, mint counter,
WorkRecord, eight binding banks).

INTENTIONAL DIFFERENCES (everything else must be identical)
  D1  m.epoch_diff has the opposite sign (register minus header, folded into the epoch register
      action; the old table computed header minus register). Every consumer compares it with 0
      only (owner_command key, bank store key), so zero-ness is identical.
      test_epoch_diff_sign_is_the_only_change_and_zero_ness_matches checks this.
  D2  The kind-8 network rows (SYN/SYNACK/ACK flags) are new; the oracle denies the private
      forwarding pass at the `network` miss. Whole-program equivalence therefore compares against
      the oracle plus exactly those three rows (test_harness_equivalence.py).
  D3  Internal metadata that nothing outside the pass reads is not preserved: m.data_valid,
      m.cache_mode, m.kind on a guard miss, m.epoch on return passes, m.observed after the owner CAS
      (the CAS now returns observed-minus-expected), m.owner_diff on non-CAS passes.
  D4  Stage 0 with a nonzero private event kind is not reproduced. The old code overwrote
      m.kind with the packet kind there; the guard keys stage-0 rows on kind 0. The parser makes that
      state unreachable (test_stage0_never_carries_a_private_kind).
  D6  READ (kinds 9..11) is new behaviour with no oracle counterpart: a stage-0 server pure ACK
      (packet kind 3, direction 2) is now a READ_ACK candidate, kind 10. Those grid points are executed
      but excluded from the comparison (hist key READ-INTENTIONAL); they are covered by
      test_native_read.py. The READ application register must stay 0 for every other case.
  D9  Step 3 response to OPERATE: the OPERATE (kind 7, stage 1) re-stores the application, real_off and
      native_end banks and stored positions include the acknowledged insertion (select +20, operate +40).
      Bank cells are therefore compared as unchanged/written, and those three are not compared at stage 1
      kind 7. The sequence guard also has a second value (client difference 20 gives sequence_valid 2) and a
      new private kind 16 (response to OPERATE) with owner 12 to 16 to 5; both are unreachable in the grid.
  D10 PI decision (step 3): with the WorkRecord busy (or the generation counter exhausted) a data packet
      (packet kind 5, 6, 7) is dropped and counted instead of forwarded natively; the only differing
      observable is md.drop_ctl 0 -> 1. Counters (count_first, count_busy, count_term) are exposed state
      that exists only in the new source. Whole-segment resend, one-byte replay (kind 12, IP length 41)
      and the sequence_valid codes 3 and 4 are new and covered by test_step3_catchall.py.
  D5  m.expected_work_phase is assigned once at the top of apply instead of directly before
      work.apply; m.stage is never written after parsing, so the value is identical.
"""
import itertools
import multiprocessing
import re
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import differential as d  # noqa: E402

sys.path.insert(0, str(HERE.parents[2] / 'integration/core/harness'))


def chunks(iterable, size=3000):
    buf = []
    for item in iterable:
        buf.append(item)
        if len(buf) == size:
            yield buf
            buf = []
    if buf:
        yield buf


def run_all(iterable, processes=8):
    total, bad, coverage = 0, [], {'old': set(), 'new': set()}
    with multiprocessing.Pool(processes) as pool:
        for n, mismatches, _hist, cov in pool.imap_unordered(d.run_chunk, chunks(iterable)):
            total += n
            bad += mismatches
            coverage['old'] |= cov['old']
            coverage['new'] |= cov['new']
    return total, bad, coverage


class Differential(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.total, cls.bad, cls.coverage = run_all(itertools.chain(
            d.routing_grid(3), d.deep_stage0(), d.deep_return()))

    def test_zero_observable_mismatches_over_the_whole_grid(self):
        self.assertGreater(self.total, 500_000)
        self.assertEqual(self.bad[:3], [])
        print('differential cases compared: %d, mismatches: %d' % (self.total, len(self.bad)))

    @staticmethod
    def is_read_entry(table, index, src):
        """An entry that exists only for the READ kinds (9, 10, 11): the oracle has no counterpart."""
        terms, action, args = src.controls['Ingress'].tables[table]['entries'][index]
        flat = repr((terms, args))
        numbers = {int(v) for v in re.findall(r"\('num', (\d+), \d+\)", flat)}
        server_ack = table == 'sequence_diff' and action == 'diff_reverse' and numbers == {3, 2, 16}
        # H1 power-on epoch entry: the oracle grid fixes epoch 17; test_native_invariants.EpochZero covers it.
        epoch_zero = table == 'snapshot_t' and action == 'snapshot_epoch_zero'
        step3 = ('response_op' in action or action in ('seq_ok_second', 'seq_resent', 'seq_replay', 'first_replay') or 16 in numbers
                 or 12 in numbers or action.startswith('count_') or table == 'busy_t'
                 or (action.startswith('store_') and 7 in numbers))      # D9 entries, covered by test_step3_exchange
        return 'read' in action or bool(numbers & {9, 10, 11}) or server_ack or epoch_zero or step3

    def test_every_const_entry_of_every_data_path_table_was_exercised_on_both_sides(self):
        engine = d.Engine()
        skipped = {'network', 'syn_shapes', 'short_shapes', 'profile', 'response_profile', 'available_t', 'epoch_guard'}
        for side, src in (('old', engine.old), ('new', engine.new)):
            unhit = []
            for name, table in src.controls['Ingress'].tables.items():
                if table['entries'] and name not in skipped and not name.startswith('read_'):
                    unhit += [(name, i) for i in list(range(len(table['entries']))) + ['default']
                              if (name, i) not in self.coverage[side]
                              and not (side == 'new' and i != 'default' and self.is_read_entry(name, i, src))]
            self.assertEqual(unhit, [], side)

    def test_grid_has_teeth_each_mutation_of_the_new_source_is_caught(self):
        text = d.NEW.read_text()
        mutations = {
            'strip row ahead of forward rows': lambda t: t.replace(
                '(8w4,8w1,8w0,32w0x20000&&&32w0xffff0000):first_close();',
                '(8w4,_,_,_):close_forward();(8w4,8w1,8w0,32w0x20000&&&32w0xffff0000):first_close();', 1),
            'kind-4 return gets a work op': lambda t: t.replace('go_ret_nowork()', 'go_ret_work()'),
            'stage-0 close allocates': lambda t: t.replace('go_keep(8w4)', 'go_new(8w4)'),
            'store ignores epoch agreement': lambda t: t.replace(
                '(8w1,8w5,32w1,32w0):store_application()', '(8w1,8w5,32w1,_):store_application()'),
            'owner CAS compares against the wrong word': lambda t: t.replace(
                'r=v-m.expected;if(v==m.expected)', 'r=v-m.desired;if(v==m.expected)'),
            'bad CRC flag ignored for READ responses': lambda t: t.replace(
                '(_,8w6,8w6,_,_,8w1,8w1,8w0,8w0,8w0,8w0):go_ret_work()', '(_,8w6,8w6,_,_,8w1,8w1,_,_,_,_):go_ret_work()'),
            'shape_valid dropped from stage-0 rows': lambda t: t.replace(
                '(8w0,8w1,8w0,8w1,8w1,_,_,_,_,_,_):go_new(8w1)', '(8w0,8w1,8w0,8w1,_,_,_,_,_,_,_):go_new(8w1)'),
            'forward row for the wrong owner phase': lambda t: t.replace(
                '(8w1,8w1,8w0,32w0x20000&&&32w0xffff0000):forward_original();',
                '(8w1,8w1,8w0,32w0x40000&&&32w0xffff0000):forward_original();'),
            'epoch bank ignores the header': lambda t: t.replace(
                'r=v-hdr.envelope.epoch;', 'r=v-32w17;'),
        }
        sample = list(itertools.islice(d.routing_grid(1), 0, None, 7)) + list(itertools.islice(d.deep_stage0(), 0, None, 11)) \
            + list(itertools.islice(d.deep_return(), 0, None, 5))
        for name, mutate in mutations.items():
            mutated = mutate(text)
            self.assertNotEqual(mutated, text, name)
            engine = d.Engine(mutated)
            caught = 0
            for item in sample:
                index, spec, over = item if len(item) == 3 else item + ({},)
                diff, _ = engine.compare(d.case_for(index, *spec, **over))
                if diff:
                    caught += 1
                    break
            self.assertGreater(caught, 0, 'mutation not detected: ' + name)

    def test_epoch_diff_sign_is_the_only_change_and_zero_ness_matches(self):
        engine = d.Engine()
        checked = 0
        for stage in (1, 2, 3):
            for kind, pk in d.RETURN_PAIRS:
                for epoch in (17, 18):
                    for work in ((1, 1), (2, 1), (4, 1)):
                        case = d.case_for(1, stage, pk, kind, 1, d.GOOD, 1, work, 0, epoch=epoch)
                        old, new = engine.drive_epoch(case)
                        self.assertEqual(old == 0, new == 0, (stage, kind, epoch, work))
                        if old:
                            self.assertEqual((old + new) & 0xffffffff, 0)
                        checked += 1
        self.assertGreater(checked, 100)

    def test_stage0_never_carries_a_private_kind(self):
        import vectors
        src = d.ExtSource(d.NEW.read_text(), HERE)
        raw = vectors.packet(16, 100, 900)
        for event in range(0x0000, 0x0100):
            src.begin_pass(68)
            frame = (bytes.fromhex('00000011 00000001 00050001'.replace(' ', '')) + event.to_bytes(2, 'big')
                     + bytes(2) + raw)
            src.packet_parser(frame)
            self.assertEqual(src.env.get('m.parsed', 0), 0, hex(event))
        src.begin_pass(1)
        src.packet_parser(raw)
        self.assertEqual(src.env.get('m.kind', 0), 0)
        self.assertEqual(src.env.get('m.stage', 0), 0)


if __name__ == '__main__':
    unittest.main()

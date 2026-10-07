"""Whole-program old-vs-new equivalence over every packet the harness suites inject.

The harness suites (integration/core/harness/tests) are run unchanged against the regenerated
native_binding.p4. A shadow hook on Pipeline.inject replays each injected frame through a twin
Pipeline built from the frozen oracle source (35bf9aa3...), starting from a copy of the same
register state, and compares the packets that leave, the drop verdict, the pass count and every
register. The only scenarios allowed to differ are the four transparent-forwarding witnesses,
where the oracle is known to deny on pass 2 for lack of a kind-8 `network` row (the bug this
restructure fixes).
"""
import copy
import io
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
ARCH = HERE.parents[2]
HARNESS = ARCH / 'integration/core/harness'
sys.path.insert(0, str(HARNESS))
sys.path.insert(0, str(HARNESS / 'tests'))
import driver  # noqa: E402

ORACLE = HERE / 'tests/oracle_35bf9aa3_native_binding.p4'
KIND8_ROWS = ''.join('(8w1,8w8,8w%d,false,16w0xffeb,8w1..8w255,4w0,16w0):network_accept();' % f for f in (2, 18, 16))


def fixed_oracle_text():
    """The frozen oracle plus ONLY the three kind-8 network rows: the bug fix, nothing else."""
    text = ORACLE.read_text()
    marker = '(8w1,8w255,_,false'
    assert text.count(marker) == 1
    return text.replace(marker, KIND8_ROWS + marker)


class Shadow:
    def __init__(self):
        self.results = []

    def install(self):
        original_init, original_inject = driver.Pipeline.__init__, driver.Pipeline.inject
        shadow = self

        def init(pipe, source_text, config, include_dir=None, on_parser_error='drop'):
            original_init(pipe, source_text, config, include_dir=include_dir, on_parser_error=on_parser_error)
            pipe._shadow = (source_text, include_dir)

        def inject(pipe, port, frame):
            text, include_dir = pipe._shadow
            if 'table guard' not in text and 'table data_guard' in text:      # already an oracle run
                return original_inject(pipe, port, frame)
            twins = []
            for oracle_text in (ORACLE.read_text(), fixed_oracle_text()):
                twin = driver.Pipeline(oracle_text, pipe.config, include_dir=HERE,
                                       on_parser_error=pipe.on_parser_error)
                twin.src.cells = copy.deepcopy(pipe.src.cells)
                twins.append(twin)
            before = pipe.state()
            new = original_inject(pipe, port, frame)
            old, fixed = (original_inject(t, port, frame) for t in twins)
            shadow.results.append((port, bytes(frame), before, old, new, fixed))
            return new

        self.restore = lambda: (setattr(driver.Pipeline, '__init__', original_init),
                                setattr(driver.Pipeline, 'inject', original_inject))
        driver.Pipeline.__init__, driver.Pipeline.inject = init, inject


def same(old, new):
    return (old.emitted == new.emitted and old.dropped == new.dropped and old.passes == new.passes
            and old.registers == new.registers and old.parse_errors == new.parse_errors)


class HarnessEquivalence(unittest.TestCase):
    def test_every_harness_packet_behaves_identically_except_the_kind8_network_fix(self):
        shadow = Shadow()
        shadow.install()
        try:
            suite = unittest.defaultTestLoader.discover(str(HARNESS / 'tests'), pattern='test_*.py',
                                                        top_level_dir=str(HARNESS / 'tests'))
            result = unittest.TextTestRunner(stream=io.StringIO(), verbosity=0).run(suite)
        finally:
            shadow.restore()
        self.assertTrue(result.wasSuccessful(), result.failures + result.errors)
        self.assertGreaterEqual(len(shadow.results), 19)
        for port, frame, before, old, new, fixed in shadow.results:
            self.assertTrue(same(fixed, new), (frame[:16].hex(), fixed.registers, new.registers))
        different = [r for r in shadow.results if not same(r[3], r[4])]
        for port, frame, before, old, new, fixed in different:
            with self.subTest(frame=frame[:16].hex()):
                self.assertTrue(old.dropped and old.passes == 2, 'old must be the pass-2 deny')
                self.assertIn('table network -> NoAction (default)', '\n'.join(old.trace[1]))
                self.assertFalse(new.dropped)
                self.assertEqual(new.passes, 4)
                self.assertEqual(new.emitted[0][1], frame)
                self.assertEqual(old.registers['owner'], before['owner'])
                self.assertEqual(new.registers['owner'], before['owner'])
        self.assertEqual(len(different), 4, 'exactly the four witnesses may differ')
        print('harness packets replayed: %d; identical to raw oracle: %d; differing from raw oracle (witnesses, kind-8 fix): %d; identical to fixed oracle: all'
              % (len(shadow.results), len(shadow.results) - len(different), len(different)))


class PacketSweep(unittest.TestCase):
    """A seeded sample of control and data frames over owner, client, server and work state."""
    SAMPLES = 3000

    def test_sample_is_identical_to_the_fixed_oracle_and_differs_from_raw_oracle_only_at_kind8(self):
        import random
        import vectors
        rnd = random.Random(20261006)
        old_pipe = lambda text: driver.Pipeline(text, vectors.topology(), include_dir=HERE)  # noqa: E731
        new_pipe = lambda: driver.Pipeline(vectors.source_text(), vectors.topology(),  # noqa: E731
                                           include_dir=vectors.SOURCE_PATH.parent)
        raw_text, fixed_text = ORACLE.read_text(), fixed_oracle_text()
        flags_all = (2, 18, 16, 17, 20, 4)
        pipes = (old_pipe(raw_text), old_pipe(fixed_text), new_pipe())
        compared = differing = 0
        outcomes = set()
        for _ in range(self.SAMPLES):
            kind = rnd.choice(('control', 'control', 'select', 'operate'))
            reverse = kind == 'control' and rnd.random() < .4
            if kind == 'control':
                flags = rnd.choice(flags_all)
                seq, ack = rnd.choice((100, 101, 136, 900)), rnd.choice((0, 101, 901, 958))
                mss = rnd.choice((None, 1500)) if flags in (2, 18) else None
                raw = vectors.packet(flags, seq, ack, reverse, mss=mss)
            else:
                payload = vectors.native_select(fc=3 if kind == 'select' else 4)
                raw = vectors.packet(rnd.choice((24, 16)), rnd.choice((101, 136)), rnd.choice((901, 958)), payload=payload)
            port = 2 if reverse else 1
            owner = rnd.choice((0, 0x10001, 0x20001, 0x30001, 0x40001, 0x50001, 0x60001, 0x70001, 0x80001, 0x90001,
                                0xa0001, 0xb0001, 0xc0001, 0xd0001, 0x40002))
            presets = dict(owner=owner, client=rnd.choice((0, 101, 136)), server=rnd.choice((0, 901, 958)),
                           epoch=rnd.choice((17, 17, 0, 18)))
            if rnd.random() < .3:
                presets['work'] = (rnd.choice((0, 5, 29)), rnd.choice((1, 2, 3)))
            results = []
            for pipe in pipes:
                pipe.src.reset_registers()
                pipe.preset(**presets)
                results.append(pipe.inject(port, raw))
            old, fixed, new = results
            compared += 1
            outcomes.add((new.dropped, new.passes, len(new.emitted)))
            self.assertTrue(same(fixed, new), (kind, presets, raw[:40].hex(), fixed.registers, new.registers))
            if not same(old, new):
                differing += 1
                self.assertTrue(old.dropped and old.passes == 2)
                self.assertIn('table network -> NoAction (default)', '\n'.join(old.trace[1]))
        print('sweep: %d frames, identical to fixed oracle: %d, differ from raw oracle only by the kind-8 deny: %d'
              % (compared, compared, differing))
        self.assertGreater(len(outcomes), 3)


if __name__ == '__main__':
    unittest.main()

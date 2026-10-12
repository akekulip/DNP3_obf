"""Actual-source timer attribution and parity with the immutable combined binary."""
import copy
import importlib.util
import struct
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


retained = load('diag_retained_combined_tests', HERE.parent / 'combined_nt_01/tests/test_combined.py')
original = retained.combined
# Before implementation the same tests exercise the original shared counter.
experiment = load('diag_experiment', HERE / 'generate.py') if (HERE / 'generate.py').exists() else original
retained.combined = experiment
retained.lifetime.experiment = experiment
qs = retained.lifetime.qs


class Attribution(unittest.TestCase):
    def fresh(self, diagnostic=True, **params):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        source = Path(temporary.name) / 't.p4'
        source.write_text((experiment if diagnostic else original).source_role('T'))
        sim = qs.QueueSim(source=source, **params)
        if diagnostic:
            self.assertEqual(len(sim.src.cells[('', 'outcomes')]), 25)
        return sim

    @staticmethod
    def banks(sim):
        return {k: copy.deepcopy(v) for k, v in sim.src.cells.items() if k[1] != 'outcomes'}

    @staticmethod
    def event(sim, kind, epoch):
        sim.event(qs.T0, kind, qs.REQ_FRAME, epoch=epoch)
        sim.run(qs.T0)

    @staticmethod
    def token(profile, generation, packet_id):
        return bytes((qs.PKTGEN_PIPE << 3 | profile, profile)) + struct.pack('!HH', generation, packet_id) + bytes(58)

    def parity(self, before, after):
        self.assertEqual(self.banks(before), self.banks(after))
        self.assertEqual(before.emitted, after.emitted)
        self.assertEqual(before.enqueued, after.enqueued)
        self.assertEqual(before.counter(6), sum(after.counter(i) for i in (6, 23, 24)))
        for i in set(range(16)) - {6}:
            self.assertEqual(before.counter(i), after.counter(i), i)
        self.assertEqual(after.src.cells[('', 'outcomes')][16:23], [0] * 7)

    def test_raw_apps_separate_before_and_after_reopen_with_exact_parity(self):
        old, new = self.fresh(False), self.fresh()
        for sim in (old, new):
            self.event(sim, 14, 17)
        generations = (old.cell('gen_alloc_reg'), old.cell('op_gen_alloc_reg'))
        for sim in (old, new):
            self.event(sim, 13, 17)
        for reopen in (False, True):
            if reopen:
                for sim in (old, new):
                    self.event(sim, 14, 18)
            banks = self.banks(new)
            base = {i: new.counter(i) for i in (6, 23, 24)}
            for profile, generation in enumerate(generations):
                for packet_id in range(4):
                    raw = self.token(profile, generation, packet_id)
                    for sim in (old, new):
                        sim.ingress(qs.T0, qs.PKTGEN_PORT, raw)
                    self.parity(old, new)
                    self.assertEqual(self.banks(new), banks)
            self.assertEqual(new.counter(6), base[6])
            self.assertEqual(new.counter(23), base[23] + 4)
            self.assertEqual(new.counter(24), base[24] + 4)
            self.assertEqual(len(new.src.cells[('', 'outcomes')]), 25)

    def test_live_and_sealed_sentinel_are_attributed_by_app(self):
        for sealed in (False, True):
            old, new = self.fresh(False), self.fresh()
            for sim in (old, new):
                self.event(sim, 14, 17)
                if sealed:
                    self.event(sim, 13, 17)
            for profile in (0, 1):
                before = {i: new.counter(i) for i in (6, 23, 24)}
                for sim in (old, new):
                    sim.ingress(qs.T0, qs.PKTGEN_PORT, self.token(profile, 0xffff, 0))
                self.parity(old, new)
                for i in (6, 23, 24):
                    self.assertEqual(new.counter(i), before[i] + int(i == (23 if profile else 24)))

    def test_blockers_keep_six_and_current_off_originals_keep_exact_bytes(self):
        old, new = self.fresh(False, enabled=0), self.fresh(enabled=0)
        for sim in (old, new):
            self.event(sim, 14, 17)
        first_emitted = len(new.emitted)
        for role in range(11, 17):
            port = qs.PORTS['HB_RETURN' if role in (13, 16) else 'HELD_RETURN']
            generation = 0 if role < 14 else new.cell('op_gen_alloc_reg' if role == 16 else 'gen_alloc_reg')
            raw = struct.pack('!BBHI', role, 0, generation, qs.BUDGET if role < 14 else 17) + qs.RSP_FRAME
            for sim in (old, new):
                sim.ingress(qs.T0, port, raw)
            self.parity(old, new)
        self.assertEqual((new.counter(6), new.counter(23), new.counter(24)), (3, 0, 0))
        self.assertEqual(new.counter(11), 3)
        self.assertEqual(len(new.emitted), first_emitted + 3)
        for _, _, frame in new.emitted[first_emitted:]:
            self.assertEqual(frame[16:], qs.RSP_FRAME)


class Lifetime(retained.Lifetime):
    def test_old_raw_tokens_before_and_after_reopen_never_change_banks(self):
        sim = self.fresh()
        self.assertEqual(len(sim.src.cells[('', 'outcomes')]), 25)
        self.event(sim, 14, 17)
        generations = (sim.cell('gen_alloc_reg'), sim.cell('op_gen_alloc_reg'))
        self.event(sim, 13, 17)
        for reopened in (False, True):
            if reopened:
                self.event(sim, 14, 18)
            before = self.banks(sim)
            enqueued, emitted = len(sim.enqueued), len(sim.emitted)
            counters = {i: sim.counter(i) for i in (6, 23, 24)}
            for profile, generation in enumerate(generations):
                for packet_id in range(4):
                    sim.ingress(qs.T0, qs.PKTGEN_PORT, Attribution.token(profile, generation, packet_id))
                    self.assertEqual(self.banks(sim), before)
            self.assertEqual((len(sim.enqueued), len(sim.emitted)), (enqueued, emitted))
            self.assertEqual(sim.counter(6), counters[6])
            self.assertEqual(sim.counter(23), counters[23] + 4)
            self.assertEqual(sim.counter(24), counters[24] + 4)


class FullComposite(retained.FullComposite):
    def fresh(self, **params):
        pipeline = super().fresh(**params)
        raw_counter = pipeline.t.counter
        # Retained protocol tests keep the legacy aggregate contract. The
        # attribution tests above independently assert raw23/24 and blocker6.
        pipeline.t.counter = lambda index: (sum(raw_counter(i) for i in (6, 23, 24))
                                            if index == 6 else raw_counter(index))
        return pipeline


class Identity(unittest.TestCase):
    def test_only_T_diagnostic_edits_and_all_N_E_surroundings_are_exact(self):
        base, source = original.full_source(), experiment.full_source()
        for role in ('N', 'E'):
            self.assertEqual(original.segment(source, role), original.segment(base, role))
        self.assertEqual(source.replace(original.segment(source, 'T'), original.segment(base, 'T'), 1), base)
        t = original.segment(source, 'T')
        for old, new in reversed(experiment.edits()):
            t = t.replace(new, old, 1)
        self.assertEqual(t, original.segment(base, 'T'))


class Lifecycle(retained.Lifecycle):
    pass


class Residue(retained.Residue):
    pass


if __name__ == '__main__':
    unittest.main()

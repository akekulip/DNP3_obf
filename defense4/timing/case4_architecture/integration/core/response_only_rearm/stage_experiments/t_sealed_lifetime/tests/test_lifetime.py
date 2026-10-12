"""Actual-source requirements for the isolated sealed-lifetime experiment."""
import copy
import importlib.util
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('sealed_experiment', HERE / 'generate.py')
experiment = importlib.util.module_from_spec(spec)
spec.loader.exec_module(experiment)
sys.path.insert(0, str(experiment.CANDIDATE))
import make_n
import make_e
import make_t
from source_pipeline import SourcePipeline, qs, rs, vectors
spec = importlib.util.spec_from_file_location('retained_composite_tests', experiment.CANDIDATE / 'tests' / 'test_composite.py')
retained_tests = importlib.util.module_from_spec(spec)
spec.loader.exec_module(retained_tests)


class SealedLifetime(unittest.TestCase):
    def fresh(self, **kw):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        source = Path(temp.name) / 't.p4'
        source.write_text(experiment.source_role('T'))
        return qs.QueueSim(source=source, **kw)

    def banks(self, sim):
        return {key: copy.deepcopy(value) for key, value in sim.src.cells.items()
                if key[1] != 'outcomes'}

    def event(self, sim, kind, epoch, time=qs.T0):
        sim.event(time, kind, qs.REQ_FRAME, epoch=epoch)
        sim.run(time)

    def test_first_and_duplicate_close_status_and_reopen(self):
        sim = self.fresh()
        self.event(sim, 14, 17)
        self.assertEqual(sim.cell('cur_epoch_reg'), 17)
        before = (sim.cell('gen_alloc_reg'), sim.cell('op_gen_alloc_reg'))
        self.event(sim, 13, 17, qs.T0 + 1000)
        self.assertEqual(sim.cell('cur_epoch_reg'), 0x80000011)
        self.assertEqual(sim.src.env['m.e_bad'], 0)
        self.assertEqual((sim.cell('gen_alloc_reg'), sim.cell('op_gen_alloc_reg')),
                         tuple(value + 1 for value in before))
        closed = self.banks(sim)
        self.event(sim, 13, 17, qs.T0 + 2000)
        self.assertEqual(sim.src.env['m.e_bad'], 2)
        self.assertEqual(self.banks(sim), closed)
        self.event(sim, 14, 18, qs.T0 + 3000)
        self.assertEqual(sim.cell('cur_epoch_reg'), 18)
        self.assertEqual(sim.src.env['m.e_bad'], 0)
        self.assertNotIn(('', 'quarantine_reg'), sim.src.cells)

    def test_stale_close_and_nonincreasing_or_invalid_open_do_not_write(self):
        sim = self.fresh()
        self.event(sim, 14, 17)
        for kind, epoch in ((13, 16), (13, 18), (13, 0), (14, 16), (14, 17),
                            (14, 0), (14, 0x7fffffff), (14, 0x80000000), (14, 0xffffffff)):
            before = self.banks(sim)
            self.event(sim, kind, epoch)
            self.assertEqual(self.banks(sim), before, (kind, epoch))
            self.assertEqual(sim.src.env['m.e_bad'], 1)
        self.event(sim, 13, 17)
        for epoch in (0, 16, 17, 0x7fffffff, 0x80000011, 0xffffffff):
            before = self.banks(sim)
            self.event(sim, 14, epoch)
            self.assertEqual(self.banks(sim), before, epoch)
            self.assertEqual(sim.src.env['m.e_bad'], 1)

    def test_qualified_close_directions_forward_first_and_duplicate_once(self):
        for direction, destination in ((1, qs.RELAY), (2, qs.FORWARD)):
            sim = self.fresh()
            self.event(sim, 14, 17)
            for duplicate in (False, True):
                before, emitted = self.banks(sim), len(sim.emitted)
                sim.event(qs.T0, 13, qs.REQ_FRAME, epoch=17, stage=direction)
                sim.run(qs.T0)
                self.assertEqual(sim.src.env['m.e_bad'], 2 if duplicate else 0)
                self.assertEqual(len(sim.emitted), emitted + 1)
                self.assertEqual(sim.emitted[-1][1], destination)
                self.assertEqual(sim.emitted[-1][2][16:], qs.REQ_FRAME)
                if duplicate:
                    self.assertEqual(self.banks(sim), before)

    def test_old_raw_tokens_before_and_after_reopen_never_change_banks(self):
        sim = self.fresh()
        self.event(sim, 14, 17)
        generations = (sim.cell('gen_alloc_reg'), sim.cell('op_gen_alloc_reg'))
        self.event(sim, 13, 17)
        for reopened in (False, True):
            if reopened:
                self.event(sim, 14, 18)
            before = self.banks(sim)
            enqueued, emitted, stale = len(sim.enqueued), len(sim.emitted), sim.counter(6)
            for profile, generation in enumerate(generations):
                for packet_id in range(4):
                    raw = bytes((qs.PKTGEN_PIPE << 3 | profile, profile))
                    raw += struct.pack('!HH', generation, packet_id) + bytes(10)
                    sim.ingress(qs.T0, qs.PKTGEN_PORT, raw)
                    self.assertEqual(self.banks(sim), before)
            self.assertEqual((len(sim.enqueued), len(sim.emitted)), (enqueued, emitted))
            self.assertEqual(sim.counter(6), stale + 8)

    def test_old_six_ladder_roles_do_not_flush_under_off(self):
        sim = self.fresh()
        self.event(sim, 14, 17)
        generations = (sim.cell('gen_alloc_reg'), sim.cell('op_gen_alloc_reg'))
        self.event(sim, 13, 17)
        self.event(sim, 14, 18)
        sim.set_params(enabled=0)
        before = self.banks(sim)
        emitted, enqueued = len(sim.emitted), len(sim.enqueued)
        for role in range(11, 17):
            generation = generations[role in (13, 16)]
            budget = 17 if role >= 14 else qs.BUDGET
            raw = struct.pack('!BBHI', role, 0, generation, budget) + qs.RSP_FRAME
            port = qs.PORTS['HB_RETURN' if role in (13, 16) else 'HELD_RETURN']
            sim.ingress(qs.T0, port, raw)
            self.assertEqual(self.banks(sim), before, role)
        self.assertEqual((len(sim.enqueued), len(sim.emitted)), (enqueued, emitted))

    def test_current_originals_preserve_off_flush(self):
        for role in (14, 15, 16):
            sim = self.fresh(enabled=0)
            self.event(sim, 14, 17)
            generation = sim.cell('op_gen_alloc_reg' if role == 16 else 'gen_alloc_reg')
            raw = struct.pack('!BBHI', role, 0, generation, 17) + qs.RSP_FRAME
            before = len(sim.emitted)
            sim.ingress(qs.T0, qs.PORTS['HB_RETURN' if role == 16 else 'HELD_RETURN'], raw)
            self.assertEqual(len(sim.emitted), before + 1)
            self.assertEqual(sim.emitted[-1][2][16:], qs.RSP_FRAME)
            self.assertEqual(sim.cell('cur_epoch_reg'), 17)

    def test_epoch_and_generation_exhaustion_remain_closed_to_alias(self):
        sim = self.fresh()
        self.event(sim, 14, 0x7ffffffe)
        sim.src.cells[('', 'gen_alloc_reg')][0] = 0xfffe
        sim.src.cells[('', 'op_gen_alloc_reg')][0] = 0xfffe
        self.event(sim, 13, 0x7ffffffe)
        self.assertEqual(sim.cell('cur_epoch_reg'), 0xfffffffe)
        self.assertEqual(sim.cell('gen_alloc_reg'), 0xffff)
        self.assertEqual(sim.cell('op_gen_alloc_reg'), 0xffff)
        before = self.banks(sim)
        for epoch in (1, 0x7ffffffe, 0x7fffffff, 0xfffffffe):
            self.event(sim, 14, epoch)
            self.assertEqual(self.banks(sim), before)
        sim = self.fresh()
        self.event(sim, 14, 17)
        sim.src.cells[('', 'gen_alloc_reg')][0] = 0xfffe
        sim.src.cells[('', 'op_gen_alloc_reg')][0] = 0xfffe
        self.event(sim, 13, 17)
        self.event(sim, 14, 18)
        self.assertEqual(sim.cell('gen_alloc_reg'), 0xffff)
        self.assertEqual(sim.cell('op_gen_alloc_reg'), 0xffff)

    def test_fullwidth_open_comparisons_preserve_both_encodings_and_bounds(self):
        for old in (0, 1, 17, 0x40000000, 0x7ffffffd, 0x7ffffffe):
            for sealed in (False, True):
                for new in sorted({0, 1, max(0, old - 1), old, old + 1,
                                   0x7ffffffe, 0x7fffffff, 0x80000000, 0xffffffff}):
                    sim = self.fresh()
                    current = old | (0x80000000 if sealed else 0)
                    sim.src.cells[('', 'cur_epoch_reg')][0] = current
                    before = self.banks(sim)
                    self.event(sim, 14, new)
                    accepted = 0 < new < 0x7fffffff and new > old
                    self.assertEqual(sim.cell('cur_epoch_reg'), new if accepted else current,
                                     (old, sealed, new))
                    self.assertEqual(sim.src.env['m.e_bad'], 0 if accepted else 1,
                                     (old, sealed, new))
                    if not accepted:
                        self.assertEqual(self.banks(sim), before, (old, sealed, new))


class FullComposite(retained_tests.Composite):
    def setUp(self):
        for module, name in ((make_n, 'N'), (make_e, 'E'), (make_t, 'T')):
            replacement = patch.object(module, 'generate', lambda role=name: experiment.source_role(role))
            replacement.start()
            self.addCleanup(replacement.stop)

    def fresh(self, **kw):
        pipeline = SourcePipeline(**kw)
        self.addCleanup(pipeline.close)
        return pipeline.handshake()

    def test_graceful_close_after_padded_read_preserves_mapping_until_ack(self):
        pipeline = self.fresh()
        pipeline.send(rs.request_packet(seq=101, ack=901))
        pipeline.send(rs.ack_packet(seq=901, ack=121), master=False)
        pipeline.send(rs.response_packet(seq=901, ack=121), master=False)
        pipeline.run(pipeline.now + 8_000_000)
        epoch = pipeline.n.state()['epoch']
        pipeline.send(vectors.packet(17, 121, 959))
        pipeline.send(vectors.packet(17, 950, 122, reverse=True), master=False)
        pipeline.send(vectors.packet(16, 122, 960))
        self.assertEqual(pipeline.n.state()['owner'] >> 16, 0x10f)
        self.assertEqual(pipeline.t.cell('cur_epoch_reg'), epoch | 0x80000000)
        pipeline.handshake(4000, 7000)
        self.assertEqual(pipeline.t.cell('cur_epoch_reg'), pipeline.n.state()['epoch'])
        self.assertGreater(pipeline.n.state()['epoch'], epoch)
        self.assertEqual(pipeline.e.cells[('', 'acct')][0], {'lo': 7001, 'hi': 0})

    def test_rst_retirement_and_old_reset_preserve_new_authority(self):
        pipeline = self.fresh()
        epoch = pipeline.n.state()['epoch']
        pipeline.send(vectors.packet(20, 101, 901))
        self.assertEqual(pipeline.t.cell('cur_epoch_reg'), epoch | 0x80000000)
        pipeline.handshake(4000, 7000)
        before_n = {name: pipeline.n.state()[name] for name in ('owner', 'client', 'server', 'epoch')}
        before_e = copy.deepcopy(pipeline.e.cells)
        before_t = {key: copy.deepcopy(value) for key, value in pipeline.t.src.cells.items() if key[1] != 'outcomes'}
        pipeline.t.reset(pipeline.now + 1000, epoch=epoch)
        pipeline.t.run(pipeline.now + 2000)
        self.assertEqual({name: pipeline.n.state()[name] for name in before_n}, before_n)
        self.assertEqual(pipeline.e.cells, before_e)
        self.assertEqual({key: value for key, value in pipeline.t.src.cells.items() if key[1] != 'outcomes'}, before_t)


if __name__ == '__main__':
    unittest.main()

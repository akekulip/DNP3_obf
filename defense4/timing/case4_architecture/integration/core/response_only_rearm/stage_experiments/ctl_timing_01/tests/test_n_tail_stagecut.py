"""N tail fusion preserves retry accounting and byte-wise event transitions."""
import copy
import sys
from pathlib import Path

import pytest

CT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(CT), str(CT / 'tests')]
import contention_source as cs
import efficiency_candidates as gen


@pytest.fixture(params=('n_tail_fused', 'n_tail_parallel_counter'))
def variant(request):
    return request.param


def pipelines(tmp_path, variant):
    assert hasattr(gen, variant), 'the N tail probe must retain both late-path semantics'
    baseline = gen.source_for()
    result = []
    for name, text in (('baseline', baseline), ('candidate', getattr(gen, variant)(baseline))):
        path = tmp_path / (name + '.p4')
        path.write_text(text)
        result.append(cs.LapPipeline(path))
    return result


def test_every_first_event_row_preserves_retry_results_and_saturating_counters(tmp_path, variant):
    old, new = pipelines(tmp_path, variant)
    try:
        table = old.n.src.controls['Ingress'].tables['first_event']
        assert len(table['entries']) == 161
        assert len(new.n.src.controls['Ingress'].tables['first_event']['entries']) == 163
        for terms, _, _ in table['entries']:
            for retry in (0, 1, 2):
                # N's preceding retry guard only admits response kinds6/11 or reset4 here.
                # Other retry/payload combinations are refused before first_event.
                if retry == 1 and old.n.src.ev(terms[0][1])[0] not in (4, 6, 11):
                    continue
                for initial in (0, 0xfffffffe, 0xffffffff):
                    observations = []
                    for pipeline in (old, new):
                        src = pipeline.n.src
                        src.begin_pass(cs.RETURN_PORT)
                        for (node, _), term in zip(table['keys'], terms):
                            src.store(node, 0 if term[0] == 'any' else src.ev(term[1])[0])
                        src.env['m.retry'] = retry
                        src.env['hdr.event.event'] = 0x01ff  # every snapshot action initializes this
                        src.valid.update(t0=True, tcp=True, event=True)
                        src.cells[('', 'count_first')] = [initial] * 4
                        src.cells[('', 'count_term')] = [initial] * 4
                        if pipeline is new and variant == 'n_tail_parallel_counter':
                            src.table('retry_dup_t')
                        src.table('first_event')
                        if pipeline is old and retry == 1 and src.env['hdr.event.event'] == 0x0108:
                            src.env['hdr.event.event'] = 0x01ff
                            src.valid['t0'] = False
                            src.table('retry_dup_t')
                        observations.append((copy.deepcopy(src.cells), dict(src.env), dict(src.valid)))
                    assert observations[0] == observations[1], (terms, retry, initial)
    finally:
        old.close()
        new.close()


@pytest.mark.parametrize('verdict', ('abort_work', 'carry_current', None))
def test_stage_increment_commutes_with_each_verdict_and_wraps(tmp_path, verdict, variant):
    old, new = pipelines(tmp_path, variant)
    try:
        for high in range(256):
            for low in (0, 1, 8, 127, 254, 255):
                results = []
                for pipeline in (old, new):
                    src = pipeline.n.src
                    src.begin_pass(cs.RETURN_PORT)
                    src.env.update({'hdr.event.event': high << 8 | low, 'm.desired': 0x12345678})
                    src.valid.update(t0=True, event=True)
                    if pipeline is new:
                        src.action('next_stage')
                    if verdict:
                        src.action(verdict)
                    if pipeline is old:
                        src.action('next_stage')
                    results.append((dict(src.env), dict(src.valid), copy.deepcopy(src.cells)))
                assert results[0] == results[1], (high, low, verdict)
    finally:
        old.close()
        new.close()


@pytest.mark.parametrize('snapshot', ('snapshot', 'snapshot_lap', 'snapshot_epoch_zero',
                                    'snapshot_retry', 'snapshot_lap_retry'))
def test_snapshot_clears_incoming_forward_event_before_noaction(tmp_path, snapshot, variant):
    old, new = pipelines(tmp_path, variant)
    try:
        for pipeline in (old, new):
            src = pipeline.n.src
            src.begin_pass(cs.RETURN_PORT)
            src.env.update({'hdr.event.event': 0x0108, 'm.retry': 1, 'm.kind': 0})
            before = copy.deepcopy(src.cells)
            src.action(snapshot)
            assert src.env['hdr.event.event'] == 0x01ff
            if pipeline is new and variant == 'n_tail_parallel_counter':
                src.table('retry_dup_t')
            src.table('first_event')
            assert src.env['hdr.event.event'] == 0x01ff and src.cells == before
    finally:
        old.close()
        new.close()


@pytest.mark.parametrize('kind,phase,difference', ((6, 0xc0000, 0xffffffdb),
                                               (11, 0xe0000, 0xffffffcf)))
def test_parallel_counter_matches_only_the_two_input_predicates(tmp_path, kind, phase, difference):
    old, new = pipelines(tmp_path, 'n_tail_parallel_counter')
    try:
        src = new.n.src
        assert len(src.controls['Ingress'].tables['retry_dup_t']['entries']) == 2
        accepted = {'m.kind': kind, 'm.sequence_valid': 2, 'm.observed': phase,
                    'm.server_diff': difference, 'm.retry': 1}
        cases = [(accepted, 1), ({**accepted, 'm.observed': phase | 0xffff}, 1)]
        cases += [({**accepted, key: value}, 0) for key, value in (
            ('m.kind', 4), ('m.sequence_valid', 1), ('m.observed', phase ^ 0x10000),
            ('m.server_diff', difference + 1), ('m.retry', 0), ('m.retry', 2))]
        for inputs, wanted in cases:
            src.begin_pass(cs.RETURN_PORT)
            src.env.update(inputs)
            # The counter predicate must not depend on a preceding event verdict.
            src.env['hdr.event.event'] = 0x0108
            src.cells[('', 'count_term')] = [0] * 4
            src.table('retry_dup_t')
            assert src.cells[('', 'count_term')] == [wanted, 0, 0, 0], inputs
        src.cells[('', 'count_term')] = [0] * 4
        src.action('forward_retry_duplicate')
        assert src.cells[('', 'count_term')] == [0] * 4
        assert src.env['hdr.event.event'] == 0x01ff and not src.valid.get('t0', False)
    finally:
        old.close()
        new.close()

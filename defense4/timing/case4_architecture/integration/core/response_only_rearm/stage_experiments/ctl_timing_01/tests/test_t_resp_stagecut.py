"""Response-go fusion preserves source behavior while removing its metadata/SALU boundary."""
import copy
import sys
from pathlib import Path

import pytest

CT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(CT), str(CT / 'tests')]
import contention_source as cs
import efficiency_candidates as gen


def test_go_table_performs_the_one_register_access_it_selects(tmp_path):
    path = tmp_path / 'candidate.p4'
    path.write_text(gen.source_for(('t_resp_done_fused',)))
    pipeline = cs.LapPipeline(path)
    try:
        src = pipeline.t.src
        src.begin_pass(0)
        src.env.update({'m.e_bad': 0, 'm.enabled': 1, 'm.lgen_diff': 0,
                        'm.readiness_delta': 0, 'm.gap_delta': 0xffffffff,
                        'm.commit_diff': 1, 'm.ack_seen_diff': 1, 'm.pb_delta': 0xffffffff,
                        'm.cur_gen': 7})
        src.cells[('', 'resp_done_reg')][0] = 6
        src.table('resp_go_check')
        assert src.cells[('', 'resp_done_reg')][0] == 7
        assert src.env['m.done_diff'] == (6 ^ 7)
        assert sum(e.startswith('register resp_done_reg.') for e in src.events) == 1
    finally:
        pipeline.close()


# Each original priority row plus default, overlapping-ready rows, stale epoch/generation, and sign edges.
GO_CASES = [
    ('off_first', 0, 0, 0, 0, 0, 0, 0, 0, 0),
    ('readiness_first', 0, 1, 0, 0, 0xffffffff, 1, 0, 0xffffffff, 1),
    ('gap_before_ack', 0, 1, 0, 0x80000000, 0x7fffffff, 0, 0, 0xffffffff, 1),
    ('standalone_before_pb', 0, 1, 0, 0xffffffff, 0x80000000, 0, 0, 0, 0),
    ('piggyback', 0, 1, 0, 0xffffffff, 0xffffffff, 1, 1, 0, 1),
    ('default', 0, 1, 0, 0x80000000, 0xffffffff, 1, 1, 0x80000000, 0),
    ('old_epoch', 1, 1, 0, 0, 0, 0, 0, 0, 0),
    ('stale_generation', 0, 1, 1, 0, 0, 0, 0, 0, 0),
    ('readiness_upper_positive', 0, 1, 0, 0x7fffffff, 0xffffffff, 1, 0, 0, 1),
]
GEN_DONE = [(0, 0), (0, 0xffffffff), (1, 0), (1, 0xffffffff),
            (0xffffffff, 0xffffffff), (0xffffffff, 0xfffffffe), (0, 1)]


@pytest.fixture(scope='module')
def table_pipelines(tmp_path_factory):
    folder = tmp_path_factory.mktemp('t_resp_fused')
    old_path, new_path = folder / 'old.p4', folder / 'new.p4'
    old_path.write_text(gen.source_for())
    new_path.write_text(gen.source_for(('t_resp_done_fused',)))
    old, new = cs.LapPipeline(old_path), cs.LapPipeline(new_path)
    yield old, new
    old.close()
    new.close()


@pytest.mark.parametrize('case', GO_CASES, ids=[c[0] for c in GO_CASES])
@pytest.mark.parametrize('cur_gen,old_done', GEN_DONE)
def test_go_rows_defaults_and_duplicate_passes_preserve_atomic_state(table_pipelines, case, cur_gen, old_done):
    old, new = table_pipelines
    _, bad, enabled, lgen, readiness, gap, commit, ack_seen, pb, go = case
    for pipeline in (old, new):
        pipeline.t.src.cells[('', 'resp_done_reg')][0] = old_done
    for duplicate in range(2):
        snapshots = []
        for pipeline in (old, new):
            src = pipeline.t.src
            src.begin_pass(0)
            src.env.update(dict(zip(('m.e_bad', 'm.enabled', 'm.lgen_diff', 'm.readiness_delta',
                                     'm.gap_delta', 'm.commit_diff', 'm.ack_seen_diff', 'm.pb_delta'),
                                    (bad, enabled, lgen, readiness, gap, commit, ack_seen, pb))))
            src.env['m.cur_gen'] = cur_gen
            before = copy.deepcopy(src.cells)
            src.table('resp_go_check')
            if pipeline is old:
                src.action('try_resp_done')
            wanted_old = cur_gen if duplicate and go else old_done
            assert src.env['m.done_diff'] == (wanted_old ^ cur_gen)
            assert src.env['m.resp_go'] == go
            expected = copy.deepcopy(before)
            expected[('', 'resp_done_reg')][0] = cur_gen if go else wanted_old
            assert src.cells == expected
            assert sum(e.startswith('register resp_done_reg.') for e in src.events) == 1
            snapshots.append((copy.deepcopy(src.cells), src.env['m.done_diff'], src.env['m.resp_go']))
        assert snapshots[0] == snapshots[1]


def test_fusion_preserves_other_roles_counters_and_single_child_guard():
    original = gen.source_for(('t_single_child', 'n_zero_timestamp'))
    changed = gen.source_for(('t_single_child', 'n_zero_timestamp', 't_resp_done_fused'))
    for role in ('N', 'E'):
        assert gen.combined.segment(original, role) == gen.combined.segment(changed, role)
    assert '(!hdr.ladder.isValid() || hdr.ladder.child == 0)' in changed
    assert '(!hdr.tev.isValid() || hdr.tev.kind != t_KIND_RESPONSE || hdr.tev.stage == 0)' in changed
    assert gen.retained.block(original, '    table outcome_count {') == gen.retained.block(changed, '    table outcome_count {')
    assert gen.retained.block(original, '    table held_verdict {') == gen.retained.block(changed, '    table held_verdict {')
    assert gen.retained.block(original, '    table commit_at_access {') == gen.retained.block(changed, '    table commit_at_access {')
    assert 'resp_go_check.apply();\n                try_resp_done();' not in changed
    with pytest.raises(ValueError):
        gen.t_resp_done_fused(changed)


@pytest.mark.parametrize('kind', ('READ', 'SELECT', 'OPERATE'))
@pytest.mark.parametrize('offset', (0, 1, 3))
def test_contended_committed_exchanges_match_05(tmp_path, kind, offset):
    sources = []
    for name, probes in (('old', ('t_single_child', 'n_zero_timestamp')),
                         ('new', ('t_single_child', 'n_zero_timestamp', 't_resp_done_fused'))):
        path = tmp_path / (name + '.p4')
        path.write_text(gen.source_for(probes))
        sources.append(path)
    old, new = (cs.contended(path, kind, offset) for path in sources)
    try:
        assert cs.delivered_once_after_ack(old) and cs.delivered_once_after_ack(new)
        for key in ('master', 'busy', 'outcomes', 'owner_state'):
            assert old[key] == new[key]
        assert old['pipeline'].t.src.cells == new['pipeline'].t.src.cells
        assert cs.n_state(old['pipeline']) == cs.n_state(new['pipeline'])
    finally:
        old['pipeline'].close()
        new['pipeline'].close()


@pytest.mark.parametrize('kind', ('READ', 'SELECT', 'OPERATE'))
def test_reset_restart_and_reconnect_match_05(tmp_path, kind):
    from test_reset_race import closes_cleanly, RESTART, l
    records = []
    for name, probes in (('old', ('t_single_child', 'n_zero_timestamp')),
                         ('new', ('t_single_child', 'n_zero_timestamp', 't_resp_done_fused'))):
        path = tmp_path / (name + '.p4')
        path.write_text(gen.source_for(probes))
        pipeline, closed = closes_cleanly(path, kind, -3)
        try:
            assert closed and pipeline.busy(RESTART) > 0
            assert l.new_incarnation_read_completes(pipeline)
            records.append((list(pipeline.wire), copy.deepcopy(pipeline.t.src.cells), cs.n_state(pipeline)))
        finally:
            pipeline.close()
    assert records[0] == records[1]


def test_tin_done_reads_express_mutually_exclusive_event_kinds():
    changed = gen.source_for(('t_resp_done_fused', 't_resp_reads_exclusive'))
    assert ('if (md.event_kind == t_KIND_OPERATE_DUP && md.e_bad == 0 && md.enabled != 0) { read_op_done(); }\n'
            '            else if (md.event_kind == t_KIND_RESPONSE && md.e_bad == 0 && md.enabled != 0) { read_resp_done(); }') in changed


@pytest.fixture(scope='module')
def exclusive_tin_pipelines(tmp_path_factory):
    from interp_ext import parse_statements
    folder = tmp_path_factory.mktemp('t_resp_exclusive')
    records = []
    for name, probes in (('old', ('t_single_child', 'n_zero_timestamp', 't_resp_done_fused')),
                         ('new', ('t_single_child', 'n_zero_timestamp', 't_resp_done_fused', 't_resp_reads_exclusive'))):
        path = folder / (name + '.p4')
        path.write_text(gen.source_for(probes))
        pipeline = cs.LapPipeline(path)
        text = pipeline.t.src.text
        anchor = 'else if (ig.ingress_port == T_IN) {'
        start = text.index(anchor) + len(anchor)
        end = text.index('            tin_verdict.apply();', start) + len('            tin_verdict.apply();')
        records.append((pipeline, parse_statements(text[start:end])))
    yield records
    for pipeline, _ in records:
        pipeline.close()


@pytest.mark.parametrize('enabled,bad', ((1, 0), (0, 0), (1, 1)))
@pytest.mark.parametrize('initial_done', (0, 0xffffffff))
@pytest.mark.parametrize('seen_diff', (0, 1))
@pytest.mark.parametrize('response_done', (7, 6))
@pytest.mark.parametrize('operate_done', (5, 4))
def test_all_tin_kinds_preserve_done_duplicate_register_counter_and_packet_behavior(
        exclusive_tin_pipelines, enabled, bad, initial_done, seen_diff, response_done, operate_done):
    for kind in range(256):
        records = []
        for pipeline, statements in exclusive_tin_pipelines:
            src = pipeline.t.src
            src.cells[('', 'resp_done_reg')][0] = response_done
            src.cells[('', 'op_done_reg')][0] = operate_done
            src.cells[('', 'outcomes')] = [0xffffffff] * 25
            before = copy.deepcopy(src.cells)
            src.begin_pass(pipeline.t.consts()['T_IN'])
            src.env.update({'m.event_kind': kind, 'm.enabled': enabled, 'm.e_bad': bad,
                            'm.cur_gen': 7, 'm.op_gen': 5, 'm.new_gen': 7, 'm.packet_epoch': 1,
                            'm.done_diff': initial_done, 'm.dup_diff': 0xffffffff, 'm.seen0_diff': seen_diff,
                            'm.outcome_code': 255, 'hdr.tev.kind': kind, 'hdr.tev.stage': 0})
            src.exec_all(statements)
            src.table('outcome_count')
            for key in before:
                if key != ('', 'outcomes'):
                    assert src.cells[key] == before[key], (kind, key)
            reads = [e for e in src.events if e.startswith('register ')]
            live = enabled != 0 and bad == 0
            wants_read = kind in (pipeline.t.consts()['KIND_OPERATE_DUP'], pipeline.t.consts()['KIND_RESPONSE']) and live
            assert len([e for e in reads if not e.startswith('register outcomes.')]) == int(wants_read), kind
            records.append((copy.deepcopy(src.cells), dict(src.env), dict(src.valid)))
        assert records[0] == records[1], kind


@pytest.mark.parametrize('kind', ('READ', 'SELECT', 'OPERATE'))
def test_exclusive_reads_preserve_contended_exchange_and_reset(tmp_path, kind):
    from test_reset_race import closes_cleanly, l
    records = []
    for name, probes in (('old', ('t_single_child', 'n_zero_timestamp', 't_resp_done_fused')),
                         ('new', ('t_single_child', 'n_zero_timestamp', 't_resp_done_fused', 't_resp_reads_exclusive'))):
        path = tmp_path / (name + '.p4')
        path.write_text(gen.source_for(probes))
        result = cs.contended(path, kind, 0)
        try:
            assert cs.delivered_once_after_ack(result)
            exchange = (result['master'], result['busy'], result['outcomes'],
                        copy.deepcopy(result['pipeline'].t.src.cells), cs.n_state(result['pipeline']))
        finally:
            result['pipeline'].close()
        pipeline, closed = closes_cleanly(path, kind, -3)
        try:
            assert closed and l.new_incarnation_read_completes(pipeline)
            records.append((exchange, list(pipeline.wire), copy.deepcopy(pipeline.t.src.cells), cs.n_state(pipeline)))
        finally:
            pipeline.close()
    assert records[0] == records[1]


def test_single_child_held_verdict_drops_only_constant_keys_and_impossible_rows():
    original = gen.source_for(('t_single_child', 't_resp_done_fused', 't_resp_reads_exclusive'))
    changed = gen.t_held_single_child_keys(original)
    table = gen.retained.block(changed, '    table held_verdict {')
    assert 'md.seen1_diff : ternary;' not in table
    assert 'md.seen2_diff : ternary;' not in table
    assert 'default_action = unmatched(); size = 27;' in table
    old_table = gen.retained.block(original, '    table held_verdict {')
    assert changed.replace(table, old_table) == original
    with pytest.raises(ValueError, match='single-child'):
        gen.t_held_single_child_keys(gen.source_for())
    with pytest.raises(ValueError):
        gen.t_held_single_child_keys(changed)


def test_held_verdict_all_reachable_rows_priority_and_counters_under_single_child_constants(tmp_path):
    from itertools import product
    records = []
    old_probes = ('t_single_child', 't_resp_done_fused', 't_resp_reads_exclusive')
    for name, probes in (('old', old_probes), ('new', old_probes + ('t_held_single_child_keys',))):
        path = tmp_path / (name + '.p4')
        path.write_text(gen.source_for(probes))
        records.append(cs.LapPipeline(path))
    covered_rows = set()
    try:
        for role in (11, 12, 14, 15, 255):
            # Every zero/nonzero and delta-sign class used by the table, including overlaps and budget priority.
            for bad, lgen, enabled, done, da, readiness, gap, commit, seen0, budget in product((0, 1), repeat=10):
                snapshots = []
                for pipeline in records:
                    src = pipeline.t.src
                    src.begin_pass(pipeline.t.consts()['HELD_RETURN'])
                    src.cells[('', 'outcomes')] = [0xffffffff] * 25
                    src.env.update({'m.e_bad': bad, 'hdr.ladder.role': role, 'm.lgen_diff': lgen,
                                    'm.enabled': enabled, 'm.done_diff': 0xffffffff if done else 0,
                                    'm.da_delta': 0xffffffff if da else 0,
                                    'm.readiness_delta': 0x80000000 if readiness else 0,
                                    'm.gap_delta': 0xffffffff if gap else 0, 'm.commit_diff': commit,
                                    'm.seen0_diff': 0xffffffff if seen0 else 0,
                                    'm.seen1_diff': 0xffffffff, 'm.seen2_diff': 0xffffffff,
                                    'hdr.ladder.child': 0, 'hdr.ladder.generation': 7,
                                    'hdr.ladder.budget': budget, 'm.outcome_code': 255})
                    table = src.controls['Ingress'].tables['held_verdict']
                    if pipeline is records[0]:
                        keys = [src.ev(node)[0] for node, _ in table['keys']]
                        matched = next(i for i, (terms, _, _) in enumerate(table['entries'])
                                       if all(src.match(term, key) for term, key in zip(terms, keys)))
                        covered_rows.add(matched)
                    before = copy.deepcopy(src.cells)
                    src.table('held_verdict')
                    hit = next(event for event in src.events if event.startswith('table held_verdict -> '))
                    action = hit.split(' -> ', 1)[1].split(' (', 1)[0]
                    src.table('outcome_count')
                    assert sum(e.startswith('register outcomes.') for e in src.events) <= 1
                    for key in before:
                        if key != ('', 'outcomes'):
                            assert src.cells[key] == before[key]
                    snapshots.append((action, dict(src.env), dict(src.valid), copy.deepcopy(src.cells)))
                assert snapshots[0] == snapshots[1], (role, bad, lgen, enabled, done, da, readiness, gap, commit, seen0, budget)
        # These four original rows require seen1_diff/seen2_diff == 0, impossible under the proven assignments.
        assert covered_rows == set(range(31)) - {3, 4, 19, 20}
    finally:
        for pipeline in records:
            pipeline.close()


@pytest.mark.parametrize('kind', ('READ', 'SELECT', 'OPERATE'))
def test_held_key_specialization_preserves_full_exchange_and_reset(tmp_path, kind):
    from test_reset_race import closes_cleanly, l
    old_probes = ('t_single_child', 'n_zero_timestamp', 't_resp_done_fused', 't_resp_reads_exclusive')
    results = []
    for name, probes in (('old', old_probes), ('new', old_probes + ('t_held_single_child_keys',))):
        path = tmp_path / (name + '.p4')
        path.write_text(gen.source_for(probes))
        exchange = cs.contended(path, kind, 0)
        try:
            assert cs.delivered_once_after_ack(exchange)
            exchange_record = (exchange['master'], exchange['busy'], exchange['outcomes'],
                               copy.deepcopy(exchange['pipeline'].t.src.cells), cs.n_state(exchange['pipeline']))
        finally:
            exchange['pipeline'].close()
        pipeline, closed = closes_cleanly(path, kind, -3)
        try:
            assert closed and l.new_incarnation_read_completes(pipeline)
            results.append((exchange_record, list(pipeline.wire), copy.deepcopy(pipeline.t.src.cells), cs.n_state(pipeline)))
        finally:
            pipeline.close()
    assert results[0] == results[1]

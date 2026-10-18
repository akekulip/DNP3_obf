"""Regressions for source-pinned successors and honest stage accounting."""
import importlib.util
import json
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parents[1]


def module(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def test_placement_does_not_count_unoccupied_stages():
    review = module('resource_review')
    assert hasattr(review, 'placement'), 'placement must distinguish occupied stages from their span'
    record = review.placement({'tables': [
        dict(name='a', direction='ingress', stage_tables=[dict(stage_number=2)]),
        dict(name='b', direction='ingress', stage_tables=[dict(stage_number=7)]),
        dict(name='c', direction='ingress', stage_tables=[dict(stage_number=7)]),
    ]})
    assert record['ingress']['occupied_indices'] == [2, 7]
    assert record['ingress']['occupied_count'] == 2
    assert record['ingress']['stage_span'] == 6
    assert record['ingress']['maximum_occupied_stage'] == 7
    assert record['egress']['occupied_count'] == record['egress']['stage_span'] == 0
    assert record['egress']['maximum_occupied_stage'] is None


def test_unchanged_e_is_compared_with_the_declared_m10_baseline(tmp_path):
    review = module('resource_review')
    (tmp_path / 'response_only.p4').write_bytes((review.BASELINE / 'response_only.p4').read_bytes())
    result = review.review(tmp_path)
    assert result['E_byte_identical'] is True
    assert result['baseline_source_sha256'] == review.sha(review.BASELINE / 'response_only.p4')


def test_placement_includes_match_attribute_stages():
    review = module('resource_review')
    record = review.placement({'tables': [
        dict(name='parser_metadata', direction='ingress', match_attributes={
            'stage_tables': [dict(stage_number=-1)]}),
        dict(name='register', direction='ingress', stage_tables=[dict(stage_number=2)]),
        dict(name='match', direction='ingress', match_attributes={
            'stage_tables': [dict(stage_number=7)]}),
    ]})['ingress']
    assert record['occupied_indices'] == [2, 7]
    assert record['occupied_count'] == 2 and record['stage_span'] == 6


def test_generated_profile_binds_exact_source_and_preserves_frozen_input(tmp_path):
    gen = module('efficiency_candidates')
    before = (gen.BASE / 'response_only.p4').read_bytes()
    inputs = gen.generate(tmp_path / 'candidate', ['t_single_child'])
    assert gen.digest(before) == gen.BASE_SHA
    assert (gen.BASE / 'response_only.p4').read_bytes() == before
    profile = inputs['supported_profile']
    assert profile['reset_restart_required'] is True and profile['t_child_count'] == 1
    assert profile['candidate']['source_sha256'] == gen.digest((tmp_path / 'candidate/response_only.p4').read_bytes())
    assert inputs['segment_sha256']['E'] == json.loads((gen.BASE / 'response_only.inputs.json').read_text())['segment_sha256']['E']
    with pytest.raises(FileExistsError):
        gen.generate(tmp_path / 'candidate')


def test_duplicate_transform_is_refused_before_writing(tmp_path):
    gen = module('efficiency_candidates')
    with pytest.raises(ValueError, match='exactly once'):
        gen.generate(tmp_path / 'candidate', ['t_single_child', 't_single_child'])
    assert not (tmp_path / 'candidate').exists()


@pytest.mark.parametrize('kind', ('READ', 'SELECT'))
@pytest.mark.parametrize('reserved', (1, 32, 63, 64, 65535))
def test_current_successor_drops_response_retry_reserved_on_first_pass(tmp_path, kind, reserved):
    import copy
    import contention_source as cs
    from test_contention_source import _waiting_retry, _inject
    gen = module('efficiency_candidates')
    gen.generate(tmp_path / 'candidate')
    pipeline, frame = _waiting_retry(tmp_path / 'candidate/response_only.p4', kind)
    before, after, counts, wire = _inject(pipeline, cs.RETURN_PORT, cs.envelope(frame, reserved=reserved))
    assert before == after and sum(counts) == 0 and wire == []
    assert pipeline.injected_passes == 1
    # TNA still executes ingress after a parser reject. N's existing return-port guard must also
    # deny this unparsed retry without changing any register, rather than relying on simulator disposal.
    src = pipeline.n.src
    before_cells = copy.deepcopy(src.cells)
    src.begin_pass(cs.RETURN_PORT)
    accepted, _ = src.packet_parser(cs.envelope(frame, reserved=reserved))
    if reserved < 64:
        assert accepted is False
    else:
        assert src.env.get('m.parsed', 0) == 0  # pre-existing high-bit refusal leaves the payload unparsed
    src.apply_control('Ingress')
    assert src.cells == before_cells and src.env.get('md.drop_ctl') == 1


@pytest.mark.parametrize('kind', ('READ', 'SELECT'))
def test_current_successor_keeps_counted_reset_restarts(tmp_path, kind):
    from test_reset_race import closes_cleanly, RESTART
    gen = module('efficiency_candidates')
    gen.generate(tmp_path / 'candidate')
    pipeline, closed = closes_cleanly(tmp_path / 'candidate/response_only.p4', kind, -3)
    assert closed and pipeline.busy(RESTART) > 0

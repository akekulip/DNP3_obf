"""Lifecycle accounting proves surviving common releases without a fabricated J counter."""
import ast
from pathlib import Path

import pytest

DRIVER = Path(__file__).resolve().parents[1] / 'model_select_lifecycle.py'


def counted_logic(no_j):
    tree = ast.parse(DRIVER.read_text())
    node = next(node for node in ast.walk(tree)
                if isinstance(node, ast.FunctionDef) and node.name == 'counted')
    registers = {'gen_alloc_reg': 20}
    outcomes = {2: 7, 3: 7, 5: 0}
    counts = {'OPERATE': 4}
    checks, reads = {}, []
    def outcome(index):
        if no_j and index == 5:
            raise AssertionError('no-J must not read the removed OP_RELEASE outcome')
        reads.append(index)
        return outcomes[index]
    def check(name, expected, actual):
        checks[name] = (expected, actual)
        assert actual == expected, name
    namespace = dict(no_j=no_j, counts=counts, t_reg=registers.__getitem__, outcome=outcome,
                     check=check, begin_case=lambda tag: None)
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(DRIVER), 'exec'), namespace)
    return namespace['counted'], registers, outcomes, counts, checks, reads


def test_no_j_success_counts_completed_OPERATE_and_both_common_response_actions():
    counted, registers, outcomes, counts, checks, reads = counted_logic(True)
    def body():
        registers['gen_alloc_reg'] = 22
        outcomes[2] = outcomes[3] = 9
        counts['OPERATE'] = 5
    counted('timed_new_sbo', True, body, lane=2, releases=1)
    assert checks == {
        'timed_new_sbo_lane_generations': (2, 2),
        'timed_new_sbo_ACK_commits': (2, 2),
        'timed_new_sbo_response_releases': (2, 2),
        'timed_new_sbo_completed_OPERATE_exchanges': (1, 1),
    }
    assert 5 not in reads


@pytest.mark.parametrize('mutation,failed_check', [
    ('generation', 'lane_generations'), ('ACK', 'ACK_commits'),
    ('response', 'response_releases'), ('OPERATE', 'completed_OPERATE_exchanges'),
])
def test_no_j_success_cannot_hide_missing_common_commit_release_or_completed_exchange(mutation, failed_check):
    counted, registers, outcomes, counts, checks, reads = counted_logic(True)
    def body():
        registers['gen_alloc_reg'] = 23 if mutation == 'generation' else 22
        outcomes[2] = 8 if mutation == 'ACK' else 9
        outcomes[3] = 8 if mutation == 'response' else 9
        counts['OPERATE'] = 4 if mutation == 'OPERATE' else 5
    with pytest.raises(AssertionError, match=failed_check):
        counted('timed_new_sbo', True, body, lane=2, releases=1)
    assert 5 not in reads


@pytest.mark.parametrize('releases,passes', [(1, True), (0, False)])
def test_legacy_still_requires_the_independent_J_release(releases, passes):
    counted, registers, outcomes, counts, checks, reads = counted_logic(False)
    def body():
        registers['gen_alloc_reg'] = 22
        outcomes[5] = releases
    if passes:
        counted('timed_new_sbo', True, body, lane=2, releases=1)
    else:
        with pytest.raises(AssertionError, match='OPERATE_releases'):
            counted('timed_new_sbo', True, body, lane=2, releases=1)
    assert checks['timed_new_sbo_OPERATE_releases'] == (1, releases)
    assert reads == [5, 5]

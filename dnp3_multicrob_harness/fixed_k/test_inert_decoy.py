#!/usr/bin/env python3
"""Regression test for the fixed-K inert-decoy outstation backend (criteria 6.5/6.6).

Proves, INSIDE THE EMULATOR MODEL ONLY, that a configured decoy point accepts SELECT/OPERATE
(native SUCCESS on the wire) yet is inert: it never actuates, never changes simulated output
state, and never increments the actuation counter — while a real point does all three.

Run with system python3 (which has pydnp3):  python3 fixed_k/test_inert_decoy.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import run_outstation as O

SUCCESS = str(O.opendnp3.CommandStatus.SUCCESS)


def _sbo(st, index, code='LATCH_ON'):
    st.select(index, code, 1, 100, 100)
    return st.operate(index, code, 1, 100, 100)


def test_decoy_accepted_but_inert():
    # K=4 point model: real 0,1 ; decoy 2,3
    st = O.ControlTestState(control_point_count=4, decoy_indexes=(2, 3))
    real = _sbo(st, 0)
    decoy = _sbo(st, 2)
    assert str(real['status']) == SUCCESS, real
    assert str(decoy['status']) == SUCCESS, decoy            # decoy is ACCEPTED on the wire
    assert real['actuated'] is True and real['changed'] is True, real
    assert decoy['actuated'] is False and decoy['changed'] is False, decoy
    assert decoy.get('decoy') is True, decoy
    assert st.actuation_count[0] == 1 and st.actuation_count[2] == 0, st.actuation_count
    assert st.backend.is_decoy(2) and not st.backend.is_decoy(0)
    assert st.backend.real_indexes == (0, 1)


def test_decoy_never_changes_state_over_many_operates():
    st = O.ControlTestState(control_point_count=8, decoy_indexes=(4, 5, 6, 7))
    initial_decoy_state = {i: st.simulated_output_state[i] for i in (4, 5, 6, 7)}
    for _ in range(20):
        for i in (0, 1, 2, 3):
            _sbo(st, i, 'LATCH_ON')
        for i in (4, 5, 6, 7):
            _sbo(st, i, 'LATCH_ON')
    # every decoy untouched; every real actuated exactly 20 times
    for i in (4, 5, 6, 7):
        assert st.actuation_count[i] == 0, (i, st.actuation_count[i])
        assert st.simulated_output_state[i] == initial_decoy_state[i], i
    for i in (0, 1, 2, 3):
        assert st.actuation_count[i] == 20, (i, st.actuation_count[i])


def test_decoy_out_of_range_fails_loud():
    try:
        O.ControlPointBackend(4, decoy_indexes=(9,))
    except ValueError:
        return
    raise AssertionError('decoy index outside configured points must raise ValueError')


def test_parse_decoy_indexes():
    assert O._parse_decoy_indexes('16,17, 18') == (16, 17, 18)
    assert O._parse_decoy_indexes('') == ()
    assert O._parse_decoy_indexes(' 3 , 1 , 3 ') == (1, 3)   # dedup + sort


def test_default_all_real_preserves_historical_behaviour():
    # no decoys -> every point actuates, exactly the pre-fixed-K behaviour
    st = O.ControlTestState(control_point_count=4)
    r = _sbo(st, 2)
    assert r['actuated'] is True and r['changed'] is True
    assert st.backend.real_indexes == (0, 1, 2, 3)
    assert st.backend.decoy_indexes == frozenset()


if __name__ == '__main__':
    tests = [v for k, v in sorted(globals().items()) if k.startswith('test_')]
    for t in tests:
        t()
        print('PASS', t.__name__)
    print('\nALL %d INERT-DECOY REGRESSION TESTS PASS' % len(tests))

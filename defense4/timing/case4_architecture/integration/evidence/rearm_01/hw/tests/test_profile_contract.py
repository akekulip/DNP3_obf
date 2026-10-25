"""candidate_campaign's control-timing profile contract for native inputs: the range READ (49) single-READ builds and
the two-READ-target profile's READ list with its read_images map; every near-miss is refused."""
import copy
import importlib.util
from pathlib import Path

HW = Path(__file__).resolve().parents[1]


def module():
    spec = importlib.util.spec_from_file_location('candidate_campaign_contract', HW / 'candidate_campaign.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


LEGACY = {'native_input_octets': {'READ': 49, 'SELECT': 37, 'OPERATE': 37}, 'output_octets': 61}
TWO = {'native_input_octets': {'READ': [91, 247], 'SELECT': 37, 'OPERATE': 37}, 'output_octets': 61,
       'read_images': {'91': 141, '247': 271}, 'read_output_octets': [141, 271]}


def test_accepts_the_two_contracts():
    m = module()
    assert m._native_inputs_supported(LEGACY)
    assert m._native_inputs_supported(TWO)


def test_refuses_near_misses():
    m = module()
    cases = []
    for mutate in (lambda e: e['native_input_octets'].update(READ=[91]),                    # list != image keys
                   lambda e: e['read_images'].update({'91': 91}),                           # image not above native
                   lambda e: e['read_images'].pop('247'),                                   # missing image
                   lambda e: e['read_images'].update({'49': 141}),                          # extra image
                   lambda e: e['native_input_octets'].update(SELECT=38),                    # SBO native changed
                   lambda e: e.update(read_output_octets=[271, 141]),                       # outputs out of order
                   lambda e: e.pop('read_images'),                                          # list without images
                   lambda e: e['native_input_octets'].update(READ=[91, 91]),                # duplicate native
                   lambda e: e['native_input_octets'].update(READ='91')):                   # not a list of ints
        e = copy.deepcopy(TWO)
        mutate(e)
        cases.append(e)
    legacy_with_images = dict(copy.deepcopy(LEGACY), read_images={'49': 141})               # 49 + a map: ambiguous
    cases.append(legacy_with_images)
    for e in cases:
        assert not m._native_inputs_supported(e), e


def test_response_ready_profile_rejects_mixed_timing_or_source_abi():
    import pytest
    m = module()
    spec = importlib.util.spec_from_file_location('ready_sealed_profile_test',
            HW.parents[2] / 'core/response_only_rearm/hw/sealed_profile.py')
    sealed = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sealed)
    p = dict(timing_contract='response_ready_ack_d_v1', timing_ns=dict(D_release_budget=5000000,
             J_operate_hold=2400000, response_wait_timeout=500000000))
    source = 'action set_params(bit<32> gap, bit<32> op_j, bit<32> response_wait_timeout, bit<32> budget, bit<32> enabled) {}\n' \
             'md.now = ig_prsr_md.global_tstamp[39:8] & 32w0xfffffffe;'
    assert sealed.validate_timing_contract(p, source) == 'response_ready_ack_d_v1'
    with pytest.raises(ValueError, match='timing'):
        sealed.validate_timing_contract(dict(p, timing_ns=dict(p['timing_ns'], cap=40000000)), source)
    with pytest.raises(ValueError, match='ABI'):
        sealed.validate_timing_contract(p, source.replace('response_wait_timeout', 'readiness'))
    with pytest.raises(ValueError, match='profile'):
        sealed.validate_timing_contract(dict(timing_ns={}), source)

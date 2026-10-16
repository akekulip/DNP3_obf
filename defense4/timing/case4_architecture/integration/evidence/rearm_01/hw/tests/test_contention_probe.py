"""Offline tests for the ACK/response contention probe: frame bytes, the schedule/spacing plan, the judge on
synthetic captures, and a source-level check that the planned small spacings produce nonzero retries.

Nothing here touches a host, a socket, the switch or any lab network. The source-level check runs the
retained LapPipeline on the compiled m6 candidate source."""
import sys
from pathlib import Path

import pytest

HW = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HW))
import contention_probe as cp  # noqa: E402

wc = cp.wc
EP = cp.Endpoints('192.0.2.61', '192.0.2.62', 59400, 20000,
                  '02:00:00:00:00:61', '02:00:00:00:00:62', '02:00:00:00:00:09')


def _parse_one(frame_bytes):
    """One parsed segment from raw frame bytes, reusing wire_check's field layout via a tiny pcap."""
    import tempfile
    path = Path(tempfile.mkstemp(suffix='.pcap')[1])
    cp.write_pcap(path, [(0, frame_bytes)])
    segs = wc.parse(path)[0]
    path.unlink()
    return segs[0]


# ---- 1. frame construction: exact, checksum-valid bytes ------------------------------------------------
def test_request_frames_carry_exact_dnp3_bytes_and_valid_checksums():
    point = cp._point(EP, 'contended_READ_000us', 'READ', 'contended', 0, 0x1000, 0x5000, 61)
    f = point['frames']
    req = _parse_one(f['request'])
    assert (req['src'], req['dst'], req['sport'], req['dport']) == ('192.0.2.61', '192.0.2.62', 59400, 20000)
    assert req['flags'] == cp.PSH | cp.ACK
    # exact DNP3 READ request application bytes: transport/app control + FC READ + the group 10 var 2 objects
    assert req['payload'] == cp.dnp3_frame(cp.READ_REQ_HEAD, bytes((0xc0, 0xc0, 1)) + cp.READ_OBJECTS)
    ip_ok, tcp_ok, offloaded = wc.ip_tcp_checksum(req)
    assert ip_ok and tcp_ok and not offloaded
    assert wc.dnp3_ok(req['payload'])[0]


def test_select_and_operate_requests_use_the_right_function_codes():
    sel = cp._point(EP, 'c', 'SELECT', 'contended', 0, 0x1000, 0x5000, 61)['frames']['request']
    assert _parse_one(sel)['payload'] == cp.dnp3_frame(cp.CTL_REQ_HEAD, bytes((0xc0, 0xc0, 3)) + cp.crob(200))
    op = cp._point(EP, 'c', 'OPERATE', 'contended', 0, 0x1000, 0x5000, 61)
    # OPERATE runs a completed SELECT first; its own request is FC 4 and acknowledges the padded SELECT image
    frames = op['frames']
    assert 'select_req' in frames and 'select_rsp' in frames
    body = _parse_one(frames['request'])['payload']
    # link head (8) + header CRC (2), then transport/app control and the function code: FC 4 = OPERATE
    assert body[12] == 4
    assert wc.dnp3_ok(body)[0]
    # the OPERATE request acknowledges the padded SELECT image (server ISN + 1 + image_len)
    assert _parse_one(frames['request'])['ack'] == (0x5000 + 1 + 61) & cp.MASK


def test_bare_ack_is_empty_and_response_and_duplicate_are_identical():
    point = cp._point(EP, 'dup_READ', 'READ', 'contended', 0, 0x1000, 0x5000, 61, duplicate=True)
    f = point['frames']
    ack = _parse_one(f['bare_ack'])
    assert ack['len'] == 0 and ack['flags'] == cp.ACK
    assert (ack['src'], ack['dst']) == ('192.0.2.62', '192.0.2.61')
    assert f['duplicate'] == f['response']
    rsp = _parse_one(f['response'])
    assert rsp['len'] > 0 and wc.dnp3_ok(rsp['payload'])[0]
    # the bare ACK and the response share the outstation sequence number (they contend for the same lifecycle)
    assert ack['seq'] == rsp['seq'] == point['response_seq'] & cp.MASK


def test_handshake_sequence_numbers_are_consistent():
    p = cp._point(EP, 'c', 'READ', 'contended', 0, 0x1000, 0x5000, 61)
    syn, synack, ack = (_parse_one(p['frames'][n]) for n in ('syn', 'synack', 'ack'))
    assert syn['flags'] == cp.SYN and syn['seq'] == 0x1000
    assert synack['flags'] == cp.SYN | cp.ACK and synack['ack'] == 0x1001
    assert ack['seq'] == 0x1001 and ack['ack'] == 0x5001


# ---- 2. the schedule / spacing plan --------------------------------------------------------------------
def test_plan_has_control_contended_and_duplicate_points_per_kind():
    plan = cp.build_plan(EP)
    roles = [(p['kind'], p['role'], p['duplicate']) for p in plan['points']]
    for kind in ('READ', 'SELECT', 'OPERATE'):
        assert (kind, 'control', False) in roles
        assert sum(1 for k, r, d in roles if k == kind and r == 'contended' and not d) == len(cp.CONTENDED_SPACING_US)
        assert (kind, 'contended', True) in roles
    assert plan['tuple'] == ['192.0.2.61', '192.0.2.62', 59400, 20000]


def test_control_spacing_is_large_and_contended_is_small():
    plan = cp.build_plan(EP)
    for p in plan['points']:
        if p['role'] == 'control':
            assert p['spacing_us'] == cp.CONTROL_SPACING_US
        else:
            assert p['spacing_us'] in cp.CONTENDED_SPACING_US


def test_schedule_is_time_ordered_and_response_follows_bare_ack_by_the_spacing():
    plan = cp.build_plan(EP)
    times = [e['t_ns'] for e in plan['schedule']]
    assert times == sorted(times)
    # for one 5 us contended READ point, response is injected 5 us after its bare ACK
    tag = 'contended_READ_005us'
    ack = next(e for e in plan['schedule'] if e['tag'] == tag and e['frame'] == 'bare_ack')
    rsp = next(e for e in plan['schedule'] if e['tag'] == tag and e['frame'] == 'response')
    assert rsp['t_ns'] - ack['t_ns'] == 5 * 1000


# ---- 3. the judge on synthetic captures ----------------------------------------------------------------
def _counters(busy, term=(0, 0, 0, 0), outcomes=None):
    snap = {'n_counters': {'count_busy': list(busy), 'count_term': list(term)}}
    if outcomes is not None:
        snap['outcomes'] = dict(outcomes)
    return snap


def _outcome_snap(ack_commit=0, resp_release=0, ack_fb=0, resp_fb=0):
    return {'OUT_ACK_COMMIT': ack_commit, 'OUT_RESP_RELEASE': resp_release,
            'OUT_ACK_FALLBACK': ack_fb, 'OUT_RESP_FALLBACK': resp_fb}


def _rx_o_to_m(ep, response_seq, ack_val, payload_len, copies=1, t0_us=10):
    """Master-facing frames the switch would return: one bare ACK then `copies` responses at response_seq."""
    out = [(t0_us * 1000, ep.o_to_m(response_seq, ack_val, cp.ACK))]
    for i in range(copies):
        out.append(((t0_us + 2 + i) * 1000, ep.o_to_m(response_seq, ack_val, cp.PSH | cp.ACK, bytes(payload_len))))
    return out


def _eg_o_to_m(ep, response_seq, ack_val, payload_len, spacing_us, t0_us=5):
    return [(t0_us * 1000, ep.o_to_m(response_seq, ack_val, cp.ACK)),
            ((t0_us + spacing_us) * 1000, ep.o_to_m(response_seq, ack_val, cp.PSH | cp.ACK, bytes(payload_len)))]


def _plan_two_points(control_seq=0x5000, contended_seq=0x6000, duplicate=False):
    return {'tuple': ['192.0.2.61', '192.0.2.62', 59400, 20000],
            'points': [dict(tag='control_READ', kind='READ', role='control', spacing_us=cp.CONTROL_SPACING_US,
                            response_seq=control_seq, duplicate=False),
                       dict(tag='contended_READ_000us', kind='READ', role='contended', spacing_us=0,
                            response_seq=contended_seq, duplicate=duplicate)]}


def _run_judge(tmp_path, plan, eg_records, rx_records, busy, term=(0, 0, 0, 0), outcomes=None):
    eg, rx = tmp_path / 'out.pcap', tmp_path / 'in.pcap'
    cp.write_pcap(eg, eg_records)
    cp.write_pcap(rx, rx_records)
    if outcomes is None:                      # default: T committed exactly the plan's points, no fallback
        n = len(plan['points'])
        outcomes = _outcome_snap(ack_commit=n, resp_release=n)
    before = _counters([0] * len(busy), [0] * len(term), outcomes=_outcome_snap())
    after = _counters(busy, term, outcomes=outcomes)
    return cp.judge(plan, str(eg), str(rx), before, after)


def test_judge_pass(tmp_path):
    plan = _plan_two_points()
    ctl, con = plan['points']
    eg = _eg_o_to_m(EP, ctl['response_seq'], 0x1100, 61, cp.CONTROL_SPACING_US) + \
        _eg_o_to_m(EP, con['response_seq'], 0x1200, 61, 0)
    rx = _rx_o_to_m(EP, ctl['response_seq'], 0x1100, 61) + _rx_o_to_m(EP, con['response_seq'], 0x1200, 61)
    report = _run_judge(tmp_path, plan, eg, rx, busy=(0, 2, 1, 0, 0, 0, 0, 0))
    assert report['verdict'] == 'PASS', report
    assert report['retry_laps'] == 1 and report['busy_drops'] == 0


def test_judge_busy_drop_fails(tmp_path):
    plan = _plan_two_points()
    ctl, con = plan['points']
    eg = _eg_o_to_m(EP, ctl['response_seq'], 0x1100, 61, cp.CONTROL_SPACING_US) + \
        _eg_o_to_m(EP, con['response_seq'], 0x1200, 61, 0)
    rx = _rx_o_to_m(EP, ctl['response_seq'], 0x1100, 61) + _rx_o_to_m(EP, con['response_seq'], 0x1200, 61)
    report = _run_judge(tmp_path, plan, eg, rx, busy=(1, 1, 1, 0, 0, 0, 0, 0))
    assert report['verdict'] == 'FAIL'
    assert any('busy-dropped' in f for f in report['failures'])


def test_judge_no_retry_is_pending_not_pass(tmp_path):
    plan = _plan_two_points()
    ctl, con = plan['points']
    eg = _eg_o_to_m(EP, ctl['response_seq'], 0x1100, 61, cp.CONTROL_SPACING_US) + \
        _eg_o_to_m(EP, con['response_seq'], 0x1200, 61, 0)
    rx = _rx_o_to_m(EP, ctl['response_seq'], 0x1100, 61) + _rx_o_to_m(EP, con['response_seq'], 0x1200, 61)
    report = _run_judge(tmp_path, plan, eg, rx, busy=(0, 2, 0, 0, 0, 0, 0, 0))
    assert report['verdict'] == 'PENDING'
    assert 'retry coverage open' in report['pending_reason']


def test_judge_duplicate_escaping_fails(tmp_path):
    plan = _plan_two_points(duplicate=True)
    ctl, con = plan['points']
    eg = _eg_o_to_m(EP, ctl['response_seq'], 0x1100, 61, cp.CONTROL_SPACING_US) + \
        _eg_o_to_m(EP, con['response_seq'], 0x1200, 61, 0)
    rx = _rx_o_to_m(EP, ctl['response_seq'], 0x1100, 61) + \
        _rx_o_to_m(EP, con['response_seq'], 0x1200, 61, copies=2)       # duplicate reached the master
    report = _run_judge(tmp_path, plan, eg, rx, busy=(0, 2, 1, 0, 0, 0, 0, 0))
    assert report['verdict'] == 'FAIL'
    assert any('double accounting' in f for f in report['failures'])


def test_judge_wrong_image_fails(tmp_path):
    plan = _plan_two_points()
    ctl, con = plan['points']
    eg = _eg_o_to_m(EP, ctl['response_seq'], 0x1100, 61, cp.CONTROL_SPACING_US) + \
        _eg_o_to_m(EP, con['response_seq'], 0x1200, 49, 0)
    rx = _rx_o_to_m(EP, ctl['response_seq'], 0x1100, 61) + \
        _rx_o_to_m(EP, con['response_seq'], 0x1200, 49)                 # contended image differs from control
    report = _run_judge(tmp_path, plan, eg, rx, busy=(0, 2, 1, 0, 0, 0, 0, 0))
    assert report['verdict'] == 'FAIL'
    assert any('wrong image' in f for f in report['failures'])


def test_judge_measures_ingress_spacing_from_the_capture(tmp_path):
    plan = _plan_two_points()
    ctl, con = plan['points']
    eg = _eg_o_to_m(EP, ctl['response_seq'], 0x1100, 61, cp.CONTROL_SPACING_US) + \
        _eg_o_to_m(EP, con['response_seq'], 0x1200, 61, 3)             # 3 us ingress spacing on the wire
    rx = _rx_o_to_m(EP, ctl['response_seq'], 0x1100, 61) + _rx_o_to_m(EP, con['response_seq'], 0x1200, 61)
    report = _run_judge(tmp_path, plan, eg, rx, busy=(0, 2, 1, 0, 0, 0, 0, 0))
    con_row = next(r for r in report['points'] if r['tag'] == 'contended_READ_000us')
    assert con_row['measured_ingress_spacing_us'] == 3


# ---- 4. MODEL SANITY ONLY: the source model (not the probe) shows small spacings retry ------------------
# This is a sanity check on the retained LapPipeline source model, NOT probe evidence: it runs the reference
# transaction() frames through the model, not the probe's own built frames, and proves nothing about silicon.
CTL = HW.parents[2] / 'core' / 'response_only_rearm' / 'stage_experiments' / 'ctl_timing_01'
M6 = CTL / 'evidence' / 'm6_01' / 'response_only.p4'


_SOURCE_CHECK = '''
import json, sys
import contention_source as cs
m6 = sys.argv[1]
out = {}
for kind in ('READ', 'SELECT', 'OPERATE'):
    contended, clean = cs.contended(m6, kind, 0), cs.contended(m6, kind, 6)
    out[kind] = [contended['busy'][cs.RETRY], cs.delivered_once_after_ack(contended),
                 clean['busy'][cs.RETRY], cs.delivered_once_after_ack(clean)]
print(json.dumps(out))
'''


@pytest.mark.skipif(not M6.is_file(), reason='compiled m6 source not present')
def test_model_sanity_small_spacing_retries_large_spacing_does_not():
    """MODEL SANITY ONLY (not probe evidence): run the planned small/large spacings through the retained
    LapPipeline on the compiled m6 source, in a clean subprocess (contention_source needs the pristine import
    environment its own suite runs under). This exercises the source model's reference frames, not the probe's
    own built frames, so it bounds feasibility of the idea -- it is not compiler, model, or hardware proof."""
    import json
    import subprocess
    result = subprocess.run([sys.executable, '-c', _SOURCE_CHECK, str(M6)],
                            cwd=str(CTL / 'tests'), capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    out = json.loads(result.stdout)
    for kind, (con_retry, con_ok, clean_retry, clean_ok) in out.items():
        assert con_retry >= 1 and con_ok, (kind, 'contended offset 0', out[kind])
        assert clean_retry == 0 and clean_ok, (kind, 'clean offset 6', out[kind])


# ---- 5. review rows (probe_adv.py): each must fail or be INVALID ----------------------------------------
_CLEAN_BUSY = (0, 2, 1, 0, 0, 0, 0, 0)


def _review_inputs(payload_len=61):
    plan = _plan_two_points()
    ctl, con = plan['points']
    eg = _eg_o_to_m(EP, ctl['response_seq'], 0x1100, payload_len, cp.CONTROL_SPACING_US) + \
        _eg_o_to_m(EP, con['response_seq'], 0x1200, payload_len, 0)
    rx = _rx_o_to_m(EP, ctl['response_seq'], 0x1100, payload_len) + \
        _rx_o_to_m(EP, con['response_seq'], 0x1200, payload_len)
    return plan, eg, rx


def test_review_stale_retry_count_busy_4_fails(tmp_path):
    plan, eg, rx = _review_inputs()
    report = _run_judge(tmp_path, plan, eg, rx, busy=(0, 2, 1, 0, 5, 0, 0, 0))
    assert report['verdict'] == 'FAIL', report


def test_review_count_term_retried_duplicate_fails(tmp_path):
    plan, eg, rx = _review_inputs()
    report = _run_judge(tmp_path, plan, eg, rx, busy=_CLEAN_BUSY, term=(3, 0, 0, 0))
    assert report['verdict'] == 'FAIL', report


def test_review_unpadded_37_octet_responses_fail(tmp_path):
    plan, eg, rx = _review_inputs(payload_len=37)
    report = _run_judge(tmp_path, plan, eg, rx, busy=_CLEAN_BUSY)
    assert report['verdict'] == 'FAIL', report


def test_review_missing_counters_are_invalid(tmp_path):
    plan, eg, rx = _review_inputs()
    cp.write_pcap(tmp_path / 'out.pcap', eg)
    cp.write_pcap(tmp_path / 'in.pcap', rx)
    report = cp.judge(plan, str(tmp_path / 'out.pcap'), str(tmp_path / 'in.pcap'), {}, {})
    assert report['verdict'] == 'INVALID', report


def test_review_no_egress_capture_is_invalid(tmp_path):
    plan, _eg, rx = _review_inputs()
    report = _run_judge(tmp_path, plan, [], rx, busy=_CLEAN_BUSY)
    assert report['verdict'] == 'INVALID', report


def test_review_operate_outstation_seq_advances_by_native_37():
    op = cp._point(EP, 'o', 'OPERATE', 'contended', 0, 0x1000, 0x5000, 61)
    # outstation-side sequence: server ISN + 1 + the 37-octet native SELECT response
    assert _parse_one(op['frames']['response'])['seq'] == (0x5000 + 1 + 37) & cp.MASK
    # master-side acknowledgement still covers the 61-octet padded image
    assert _parse_one(op['frames']['request'])['ack'] == (0x5000 + 1 + 61) & cp.MASK


def test_review_double_ack_master_order_fails(tmp_path):
    # master side sees response, then two bare ACKs: order is not [bare ACK, response] -> FAIL
    plan = _plan_two_points()
    ctl, con = plan['points']
    eg = _eg_o_to_m(EP, ctl['response_seq'], 0x1100, 61, cp.CONTROL_SPACING_US) + \
        _eg_o_to_m(EP, con['response_seq'], 0x1200, 61, 0)
    rx = _rx_o_to_m(EP, ctl['response_seq'], 0x1100, 61) + \
        [(30 * 1000, EP.o_to_m(con['response_seq'], 0x1200, cp.PSH | cp.ACK, bytes(61))),
         (31 * 1000, EP.o_to_m(con['response_seq'], 0x1200, cp.ACK)),
         (32 * 1000, EP.o_to_m(con['response_seq'], 0x1200, cp.ACK))]
    report = _run_judge(tmp_path, plan, eg, rx, busy=_CLEAN_BUSY)
    assert report['verdict'] == 'FAIL', report


def test_review_control_not_delivered_fails(tmp_path):
    # the control response never reaches the master -> FAIL (every control must deliver exactly once)
    plan = _plan_two_points()
    ctl, con = plan['points']
    eg = _eg_o_to_m(EP, ctl['response_seq'], 0x1100, 61, cp.CONTROL_SPACING_US) + \
        _eg_o_to_m(EP, con['response_seq'], 0x1200, 61, 0)
    rx = _rx_o_to_m(EP, con['response_seq'], 0x1200, 61)       # only the contended point delivered
    report = _run_judge(tmp_path, plan, eg, rx, busy=_CLEAN_BUSY)
    assert report['verdict'] == 'FAIL', report
    assert not report['control_clean']


def test_review_untimed_escape_fails_on_t_outcome_mismatch(tmp_path):
    # both points reach the master, but T released only one (RESP_RELEASE=1 != 2 delivered): an untimed
    # escape is not counted by T's committed path -> FAIL
    plan, eg, rx = _review_inputs()
    report = _run_judge(tmp_path, plan, eg, rx, busy=_CLEAN_BUSY,
                        outcomes=_outcome_snap(ack_commit=2, resp_release=1))
    assert report['verdict'] == 'FAIL', report
    assert any('RESP_RELEASE' in f for f in report['failures'])


def test_review_untimed_escape_fails_on_delay_tolerance(tmp_path):
    # control response is released ~500 us after its ACK (T's hold); the contended point escapes at ~0 us,
    # outside the 100 us tolerance -> FAIL even though T outcomes and counters look clean
    plan = _plan_two_points()
    ctl, con = plan['points']
    eg = _eg_o_to_m(EP, ctl['response_seq'], 0x1100, 61, cp.CONTROL_SPACING_US) + \
        _eg_o_to_m(EP, con['response_seq'], 0x1200, 61, 0)
    rx = [(10 * 1000, EP.o_to_m(ctl['response_seq'], 0x1100, cp.ACK)),
          (510 * 1000, EP.o_to_m(ctl['response_seq'], 0x1100, cp.PSH | cp.ACK, bytes(61))),  # 500 us release
          (10 * 1000, EP.o_to_m(con['response_seq'], 0x1200, cp.ACK)),
          (10 * 1000, EP.o_to_m(con['response_seq'], 0x1200, cp.PSH | cp.ACK, bytes(61)))]    # 0 us escape
    report = _run_judge(tmp_path, plan, eg, rx, busy=_CLEAN_BUSY)
    assert report['verdict'] == 'FAIL', report
    assert any('escapes control' in f for f in report['failures'])


def test_judge_clean_run_with_retry_passes(tmp_path):
    # a fully clean run WITH a retry lap and consistent master delays is the only PASS
    plan = _plan_two_points()
    ctl, con = plan['points']
    eg = _eg_o_to_m(EP, ctl['response_seq'], 0x1100, 61, cp.CONTROL_SPACING_US) + \
        _eg_o_to_m(EP, con['response_seq'], 0x1200, 61, 0)
    rx = _rx_o_to_m(EP, ctl['response_seq'], 0x1100, 61) + _rx_o_to_m(EP, con['response_seq'], 0x1200, 61)
    report = _run_judge(tmp_path, plan, eg, rx, busy=(0, 2, 1, 0, 0, 0, 0, 0))
    assert report['verdict'] == 'PASS', report

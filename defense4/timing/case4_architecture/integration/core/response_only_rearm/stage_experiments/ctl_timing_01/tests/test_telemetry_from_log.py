"""telemetry_from_log.py: c68's removed switch counters recounted from the model log, with c67's semantics."""
import json
import sys
from pathlib import Path

import pytest

CORE = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(CORE))
import telemetry_from_log as t  # noqa: E402

LOG = """\
:10-25 19:18:17.810100:        :0x839:-:<0,1,3>:Execute Action: t_Ingress.rewait_ack
:10-25 19:18:17.810363:        :0x839:-:<0,1,7>:Execute Default Action: t_Ingress.drop_old_epoch
:10-25 19:18:17.900000:        :0x840:0x83f:<0,1,7>:Execute Action: t_Ingress.release_ack_commit
:10-25 19:18:17.900100:        :0x841:-:<0,1,7>:Execute Action: t_Ingress.drop_timer_stale_operate
:10-25 19:18:17.900200:        :0x842:-:<0,0,9>:Execute Action: n_Ingress.busy_retry
:10-25 19:18:17.900300:        :0x843:-:<0,0,9>:Execute Default Action: n_Ingress.busy_retry
:10-25 19:18:17.900400:        :0x844:-:<0,0,10>:Execute Action: n_Ingress.count_refused
:10-25 19:18:17.900500:        :0x845:-:<0,1,7>:Execute Action: t_Ingress.release_response
"""


def test_action_map_from_pinned_c67_source():
    mapping = t.action_map()
    assert mapping['t_Ingress.release_ack_commit'] == ('p1.t_Ingress.outcomes', 2)
    assert mapping['t_Ingress.release_response_counted'] == ('p1.t_Ingress.outcomes', 3)
    assert mapping['t_Ingress.release_operate_counted'] == ('p1.t_Ingress.outcomes', 5)
    assert mapping['t_Ingress.drop_timer_stale_operate'] == ('p1.t_Ingress.outcomes', 23)
    assert mapping['t_Ingress.drop_timer_stale_read'] == ('p1.t_Ingress.outcomes', 24)
    assert mapping['n_Ingress.busy_retry'] == ('p0.n_Ingress.count_busy', 2)
    assert mapping['n_Ingress.count_refused'] == ('p0.n_Ingress.count_first', 0)
    assert mapping['n_Ingress.count_retry_duplicate'] == ('p0.n_Ingress.count_term', 0)
    assert 't_Ingress.release_response' not in mapping            # the uncounted helper action


def test_counts_last_t_outcome_per_pass_and_every_n_bump(tmp_path):
    log = tmp_path / 'model_x.log'
    log.write_text(LOG)
    counts = t.counts(log, t.action_map())
    # pass 0x839: rewait then the default drop_old_epoch -> only the last (14) counts, as c67's outcome_code
    assert counts.get(('p1.t_Ingress.outcomes', 1), 0) == 0
    assert counts[('p1.t_Ingress.outcomes', 14)] == 1
    assert counts[('p1.t_Ingress.outcomes', 2)] == 1
    assert counts[('p1.t_Ingress.outcomes', 23)] == 1
    assert counts[('p0.n_Ingress.count_busy', 2)] == 2              # hit and default miss both execute
    assert counts[('p0.n_Ingress.count_first', 0)] == 1


def test_counts_are_incremental(tmp_path, monkeypatch):
    log = tmp_path / 'model_y.log'
    log.write_text(LOG.splitlines(True)[0])
    t._CACHE.clear()
    assert t.counts(log)[('p1.t_Ingress.outcomes', 1)] == 1
    with open(log, 'a') as out:
        out.write(LOG.splitlines(True)[1])
    later = t.counts(log)
    assert later[('p1.t_Ingress.outcomes', 1)] == 0 and later[('p1.t_Ingress.outcomes', 14)] == 1


def test_profile_switch(tmp_path, monkeypatch):
    inputs = tmp_path / 'inputs.json'
    inputs.write_text(json.dumps({'supported_profile': {'switch_telemetry': False}}))
    monkeypatch.setenv('PORT_MAP', str(inputs))
    assert t.build_has_telemetry() is False
    inputs.write_text(json.dumps({'supported_profile': {}}))
    assert t.build_has_telemetry() is True


@pytest.mark.parametrize('trace', ['', 'unrecognized simulator output\n', LOG.splitlines()[2]])
def test_unusable_trace_cannot_qualify_the_surviving_response(tmp_path, trace):
    # Exercise the real parser and the real abort response verdict. Even valid
    # packet output cannot stand in for the required observed commit/release.
    from test_abort_response_ready import judge
    log = tmp_path / 'model_incomplete.log'
    log.write_text(trace)
    counts = t.counts(log, t.action_map())
    assert not judge(deltas={
        'ACK_COMMIT': counts.get(('p1.t_Ingress.outcomes', 2), 0),
        'RESP_RELEASE': counts.get(('p1.t_Ingress.outcomes', 3), 0)})


def test_missing_trace_cannot_supply_a_counter_value(tmp_path, monkeypatch):
    monkeypatch.setenv('OUT', str(tmp_path))
    with pytest.raises(ValueError, match='expected one model log'):
        t.register_value('p1.t_Ingress.outcomes', 2)


E_LOG = """\
:10-25 20:37:01.000001:        :-:0x1:<0,0,4>:	Destination:
:10-25 20:37:01.000002:        :-:0x1:<0,0,4>:	m.result[7:0] = 0xC
:10-25 20:37:01.000003:        :-:0x1:<0,0,8>:	m.result[7:0] = 0x1
:10-25 20:37:01.000004:        :-:0x2:<0,0,7>:	Destination:
:10-25 20:37:01.000005:        :-:0x2:<0,0,7>:	m.result[7:0] = 0x4
:10-25 20:37:01.000006:        :-:0x3:<0,0,1>:Egress : Table r_Egress.conn is hit
:10-25 20:37:01.000007:        :-:0x9:<0,1,1>:	Destination:
:10-25 20:37:01.000008:        :-:0x9:<0,1,1>:	m.result[7:0] = 0x1
"""


def test_e_counter_one_packet_per_pipe0_egress_pass_by_last_write(tmp_path):
    log = tmp_path / 'model_e.log'
    log.write_text(E_LOG)
    counts = t.counts(log, t.action_map())
    assert counts[(t.E_COUNTER, 12)] == 1       # pass 0x1: written 0xC; the later key read of 0x1 is not a write
    assert counts[(t.E_COUNTER, 4)] == 1        # pass 0x2: replay
    assert counts[(t.E_COUNTER, 0)] == 1        # pass 0x3: never written, counted at 0
    assert counts.get((t.E_COUNTER, 1), 0) == 0  # pipe 1 egress is not E

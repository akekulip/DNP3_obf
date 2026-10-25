"""(c) Local kernel integration test of identity-targeted loss (netns_identity_scenario.py), three modes: a request
SEQ on OUTPUT (after a forced earlier retransmission), a response SEQ on INPUT (relay ISN + tcpi_bytes_received)
and the master's pure-ACK ACK on OUTPUT. Each asserts the intended segment was dropped exactly once and its
retransmission (or the next cumulative ACK) passed within one RTO.

Privileged mode (root, or `sudo -n true` succeeds): the scenario runs under `sudo -n unshare -nm` with
net.netfilter.nf_log_all_netns temporarily 1 (restored afterwards), so the kernel LOG line of the identity rule
reaches dmesg exactly as on Vision, and the full RelayLoss report must be exact. Without sudo this test is SKIPPED.

Run it with:  sudo -v && python3 -m pytest -q -rs tests/test_loss_identity_netns.py

The unprivileged variant (user namespace, `unshare -Urnm`) runs the same scenario where the kernel allows it. The
kernel does not log LOG-target packets from a non-initial network namespace unless nf_log_all_netns=1, which an
unprivileged user cannot set, so that variant asserts the rule counters, the capture and the round trips instead
of the dmesg line."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
SCENARIO = str(HERE / 'netns_identity_scenario.py')


def _sudo_ok():
    if os.geteuid() == 0:
        return True
    try:
        return subprocess.run(['sudo', '-n', 'true'], capture_output=True, timeout=10).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _userns_ok():
    try:
        r = subprocess.run(['unshare', '-Urnm', 'sh', '-c', 'mount -t tmpfs none /run && iptables -w -S OUTPUT && '
                            'ip link add va type veth peer name vb'],
                           capture_output=True, text=True, timeout=20)
        return r.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _run(argv):
    r = subprocess.run(argv, capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr[-3000:]
    return json.loads(r.stdout.strip().splitlines()[-1])


ONE_RTO_MS = (150, 400)            # dropped once and recovered by ONE retransmission (min RTO 200 ms); two RTOs fail
MODES = ('request', 'response', 'response_ack')
IP_LEN = {'request': 79, 'response': 40 + 12 + 158, 'response_ack': 52}


def _check(out):
    """-> the dropped segment's identity (key, value). Per mode: exactly the intended segment dropped once, its
    retransmission (or, for a pure ACK, the next cumulative ACK) passed, and nothing else was dropped."""
    assert out['error'] is None, out
    mode, rep, rtt = out['mode'], out['report'], out['rtt_ms']
    m0, r0 = out['isns']
    assert len(rtt) == 3, rtt
    identity = rep['identity']
    assert identity['armed'] and identity['error'] is None and type(identity['arm_ns']) is int
    by_target = {c['target']: c for c in rep['counters'][:2]}
    assert (by_target['LOG']['pkts'], by_target['DROP']['pkts']) == (1, 1), rep['counters']
    assert by_target['DROP']['bytes'] == IP_LEN[mode]
    assert rep['restoration']['restored'], rep['restoration']
    assert rep['iptables_version'].startswith('iptables v')
    requests = [x['seq'] for x in out['out'] if x['src'] == '192.168.10.1' and x['len'] == 27]
    responses = [x['seq'] for x in out['into'] if x['src'] == '192.168.10.7' and x['len'] == 158]
    want_req = [m0 + 1, m0 + 28, m0 + 55]
    want_resp = [r0 + 1, r0 + 159, r0 + 317]
    if mode == 'request':
        # request 1: first copy dropped by the u32 forcing rule, its retransmission passed; request 2 passed;
        # request 3: first copy dropped by the identity rule, its own retransmission passed. The TX tap is after
        # OUTPUT, so each request appears exactly once, in order; a second drop of either shows in the RTT bound.
        assert identity == dict(identity, key='SEQ', value=want_req[2])
        assert requests == want_req, (requests, want_req)
        assert responses == want_resp, responses
        force = [row for row in out['force_counters'] if row[2] == 'DROP' and '1/min' in row]
        assert len(force) == 1 and force[0][:2] == ['1', '79'], out['force_counters']
        assert ONE_RTO_MS[0] <= rtt[0] < ONE_RTO_MS[1] and rtt[1] < 100, rtt
        assert ONE_RTO_MS[0] <= rtt[2] < ONE_RTO_MS[1], rtt
    elif mode == 'response':
        # response 2 arrives twice on the RX tap (before INPUT): the first copy dropped, the retransmission passed
        assert identity == dict(identity, key='SEQ', value=want_resp[1])
        assert responses == [want_resp[0], want_resp[1], want_resp[1], want_resp[2]], responses
        assert sorted(set(requests)) == want_req          # request 2 may be retransmitted (its ACK rode on resp 2)
        assert ONE_RTO_MS[0] <= rtt[1] < ONE_RTO_MS[1] and rtt[0] < 100 and rtt[2] < 100, rtt
    else:
        # the master's pure ACK of response 2 (ACK = response 2 SEQ + 158) never left; request 3 carried the same
        # cumulative ACK and passed, so the relay never needed to retransmit response 2
        value = want_resp[1] + 158
        assert identity == dict(identity, key='ACK', value=value)
        pure = [x for x in out['out'] if x['len'] == 0 and x['flags'] & 0x1F == 0x10 and x['ack'] == value]
        assert pure == [], pure
        assert [x['ack'] for x in out['out'] if x['len'] == 27 and x['seq'] == want_req[2]] == [value]
        assert requests == want_req and responses == want_resp, (requests, responses)
        assert max(rtt) < 100, rtt
    return identity['key'], identity['value']


@pytest.mark.privileged
@pytest.mark.skipif(not _sudo_ok(), reason='needs root or passwordless sudo (`sudo -n true` failed); run: '
                                           'sudo -v && python3 -m pytest -q -rs tests/test_loss_identity_netns.py')
@pytest.mark.parametrize('mode', MODES)
def test_identity_rule_on_a_real_kernel_root(mode):
    script = ('old=$(cat /proc/sys/net/netfilter/nf_log_all_netns); echo 1 > /proc/sys/net/netfilter/nf_log_all_netns; '
              'unshare -nm %s %s %s; rc=$?; echo "$old" > /proc/sys/net/netfilter/nf_log_all_netns; exit $rc'
              % (sys.executable, SCENARIO, mode))
    out = _run((['sh', '-c'] if os.geteuid() == 0 else ['sudo', '-n', 'sh', '-c']) + [script])
    key, value = _check(out)
    rep = out['report']
    assert rep['exact'], rep
    assert len(rep['kernel_log']) == 1 and rep['kernel_packet'][key] == value
    assert rep['kernel_packet']['LEN'] == IP_LEN[mode]


@pytest.mark.skipif(not _userns_ok(), reason='unprivileged user+network namespaces (unshare -Urnm) unavailable')
@pytest.mark.parametrize('mode', MODES)
def test_identity_rule_on_a_real_kernel_userns(mode):
    out = _run(['unshare', '-Urnm', sys.executable, SCENARIO, mode])
    _check(out)
    rep = out['report']
    # no dmesg line from a non-initial netns without nf_log_all_netns: the report is honestly not exact
    assert rep['kernel_log'] == [] and rep['kernel_packet'] is None and not rep['exact']

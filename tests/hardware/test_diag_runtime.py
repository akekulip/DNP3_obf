"""Offline gates for the c72_diag_mirror runtime path (plan D3/E1/E2). No socket, SSH, BFRT client or process.

Golden values were recorded from the code before the diagnostic path existed (commit a7de5b039): with no
diag_mirror in the config and no --diag-mirror / --mirror-iface, every plan, command and file must stay identical.
"""
import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import re
import sys
from types import ModuleType, SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'scripts/hardware'), str(ROOT / 'scripts/checks')]
import bringup_teardown  # noqa: E402
import campaign  # noqa: E402
import campaign_base  # noqa: E402
import capture_observation  # noqa: E402
import diag_mirror_sessions  # noqa: E402
import relay_master  # noqa: E402
import rows  # noqa: E402
import vision_run  # noqa: E402

SCHEMAS = Path(os.environ.get('SDE_INSTALL', '/home/philip/bf-sde-9.13.2/install')) / 'share/bf_rt_shared'
DIAG_SHA = 'a46cc55a73a77dfa5691e292451d18d4ec663a04fb5f07b39c6e91915010d437'
C72_SHA = '97812585d64146dd5de65b8fd42d19c1471e2c5d80da85dacaae68b4083d887e'
C72_CONFIG = ROOT / 'results/hardware/campaigns/rc01_hw_c72_20261027_02/configs/02_d5_reference.json'
MIRROR_IFACE = 'enp59s0f1np1'

# Recorded before the change (see the module docstring).
GOLDEN_PLAN_SHA = '0371470f967731ab2104b7acfd81701da5a04786e005cac0c545045b750d6543'
GOLDEN_C72_DRY_RUN_STDOUT_SHA = 'adad1ecf222e067963f7890531eafdb744cf4dd452f6804dd5b4f10e56167d5f'
GOLDEN_UNIT_CALLS_SHA = {'Campaign': '483e5b14cf489ca4392af7f70005817164eb245e0acfccd507ba87c0ca221a78',
                         'CandidateCampaign': '1bf3e5bfbf17c60219f06947d56bc1deeab2dfe16c5842d126c03517538ef517'}
GOLDEN_INSTALLER_CMD = (
    'python3 /home/decps/Philip_repo/dnp3-defense4/response_only_composite/src/scripts/hardware/bringup_composite.py'
    ' --build-out /remote/out_current'
    ' --expect bfrt.json=cc8a72d2001a1c8d4240f8731f8afe37e25ddbea533bcd2f02c5dc7f85a2ca3c'
    ' --expect p0/tofino.bin=207603d71ea720ccfd2e54a612c22e830df63f25f1e28547645dbd3e3971170d'
    ' --expect p1/response_only.bfa=e2f405166c8b27b3770861de9a0a7aded59c530329525c6013f7b45de68f81e8'
    ' --expect p1/tofino.bin=f333a4307230d21d680ebd0bd8b40b137bf690b865f4fffb73675cebd844a154'
    ' --master-ip 192.168.10.1 --master-port 60000 --master-dev 9 --relay-ip 192.168.10.7 --relay-port 20000'
    ' --relay-dev 64 --read-dst 0x0000 --read-src 0x0100 --t-gap 5000000 --t-budget 240000 --t-enabled 1 --k 2'
    ' --shape-ack-pps 59570 --shape-resp-pps 59570 --shape-ack-blk-pps 59570 --shape-resp-blk-pps 59570'
    ' --block-burst 64 --pad-enable 1')
GOLDEN_VISION_CMD = (
    'sudo -n /usr/bin/python3 /home/decps/sel751_guarded_20261024/vision_run.py run'
    ' offline_fixture_physical_relay_off_t0'
    ' --master-port 60000 --reads 65 --range 8 --gap-ms 0 --start-delay-ms 50 --start-seed 57101'
    ' --endpoint-profile sel751 --apply --read-pause-ms 25 --run-sbo 1 --close-grace-ms 0 --sbo-cycles 64'
    ' --read-schedule mixed_full --relay-padding 0')
FILTER = 'tcp and host 192.168.10.1 and host 192.168.10.7 and port 20000'
NS_SYSCTL = ['sysctl', 'net.ipv4.tcp_timestamps', 'net.ipv4.tcp_sack', 'net.ipv4.tcp_window_scaling',
             'net.ipv4.ip_local_port_range']
WORKLOAD_KWARGS = ['close_grace_ms', 'close_mode', 'gap_ms', 'loss_target', 'read_pause_ms', 'run_sbo', 'sbo_cycles',
                   'schedule']
GOLDEN_VISION_LOG = [
    ['vr_sh', 'ethtool', '--show-priv-flags', 'enp59s0f0np0'],
    ['vr_sh', 'ip', 'netns', 'exec', 'ns_vepa_a'] + NS_SYSCTL,
    ['vr_sh', 'ip', 'netns', 'exec', 'ns_vepa_b'] + NS_SYSCTL,
    ['vr_sh', 'ip', 'netns', 'exec', 'ns_vepa_b', 'ip', 'route', 'show', '192.168.10.0/24'],
    ['vr_sh', 'ip', 'netns', 'exec', 'ns_vepa_b', 'tc', 'qdisc', 'show', 'dev', 'mvB'],
    ['offload_context', 'run', ['interface', 'run']],
    ['co_sh', 'ethtool', '-k', 'enp59s0f0np0'],
    ['co_sh', 'ethtool', '-K', 'enp59s0f0np0', 'gro', 'off'],
    ['co_sh', 'ethtool', '-k', 'enp59s0f0np0'],
    ['vr_sh', 'ss', '-tan'],
    ['popen', 'tcpdump', '--immediate-mode', '-i', 'enp59s0f0np0', '-Q', 'out', '-s0', '-U', '-n', '-w',
     '<D>/run/out.pcap', FILTER],
    ['popen', 'tcpdump', '--immediate-mode', '-i', 'enp59s0f0np0', '-Q', 'in', '-s0', '-U', '-n', '-w',
     '<D>/run/in.pcap', FILTER],
    ['sleep', 2],
    ['sleep', 0.0],
    ['workload', [60000, 3], WORKLOAD_KWARGS],
    ['close'],
    ['terminate', 'out.pcap'],
    ['terminate', 'in.pcap'],
    ['co_sh', 'ethtool', '-K', 'enp59s0f0np0', 'gro', 'on'],
    ['co_sh', 'ethtool', '-k', 'enp59s0f0np0'],
]


# ----------------------------------------------------------------------------------------------- installer
@pytest.fixture
def composite(monkeypatch):
    """bringup_composite loaded fresh; its module-level injection into the shared `rows` module is undone after."""
    monkeypatch.setattr(rows, 'cp', rows.cp)
    monkeypatch.setattr(rows, 'build', rows.build)
    sys.modules.pop('bringup_composite', None)
    import bringup_composite
    yield bringup_composite
    sys.modules.pop('bringup_composite', None)


def build_out(build):
    return ROOT / 'results/builds' / build / 'compile_local/out'


def installer_argv(build, *extra):
    pins = json.loads((ROOT / 'results/builds' / build / 'compile_local/manifest.json').read_text())['artifact_sha256']
    argv = ['--build-out', str(build_out(build))]
    for rel in ('bfrt.json', 'p0/tofino.bin', 'p1/tofino.bin', 'p1/response_only.bfa'):
        argv += ['--expect', '%s=%s' % (rel, pins[rel])]
    return argv + ['--master-ip', '192.168.10.1', '--master-port', '60000', '--master-dev', '9',
                   '--relay-ip', '192.168.10.7', '--relay-port', '20000', '--relay-dev', '64',
                   '--read-dst', '0x0000', '--read-src', '0x0100', '--t-gap', '20000000', '--t-budget', '240000',
                   '--t-enabled', '1', '--k', '2', '--shape-ack-pps', '59570', '--shape-resp-pps', '59570',
                   '--shape-ack-blk-pps', '59570', '--shape-resp-blk-pps', '59570', '--block-burst', '64',
                   '--pad-enable', '1', '--fixed-schema-dir', str(SCHEMAS)] + list(extra)


def planned(bc, build, *extra):
    bc.configure(str(build_out(build)))
    a = bc.installer.parse(installer_argv(build, *extra))
    with contextlib.redirect_stdout(io.StringIO()):
        ports, errors = bc.installer.build_ports_for(a)
    assert errors == []
    return a, ports, bc.installer.plan(a, ports)


def ops_sha(bc, ops):
    return hashlib.sha256(json.dumps(ops, default=bc.installer.encode, sort_keys=True).encode()).hexdigest()


def dry_run(bc, build, *extra):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = bc.main(installer_argv(build, *extra))
    return rc, out.getvalue().replace(str(ROOT), '<ROOT>').replace(str(SCHEMAS), '<SCHEMAS>')


def test_absent_plan_is_byte_identical_to_the_plan_before_the_diagnostic_path(composite):
    for build in ('c72', 'c72_diag_mirror'):
        _a, _p, default = planned(composite, build)
        _a, _p, absent = planned(composite, build, '--diag-mirror', 'absent')
        assert ops_sha(composite, default) == ops_sha(composite, absent) == GOLDEN_PLAN_SHA


def test_absent_plan_imports_and_reads_no_diagnostic_constants(composite, monkeypatch):
    def refuse(*_args):
        raise AssertionError('absent must not read the diagnostic constants')
    monkeypatch.setattr(diag_mirror_sessions, 'load', refuse)
    _a, _p, ops = planned(composite, 'c72')
    assert ops_sha(composite, ops) == GOLDEN_PLAN_SHA


def test_absent_dry_run_output_is_byte_identical_to_the_output_before_the_diagnostic_path(composite):
    for extra in ((), ('--diag-mirror', 'absent')):
        rc, stdout = dry_run(composite, 'c72', *extra)
        assert rc == 0
        assert hashlib.sha256(stdout.encode()).hexdigest() == GOLDEN_C72_DRY_RUN_STDOUT_SHA


@pytest.mark.parametrize('state', ['on', 'off'])
def test_diag_sessions_are_appended_right_after_the_clone_session(composite, state):
    _a, _p, absent = planned(composite, 'c72_diag_mirror')
    _a, ports, ops = planned(composite, 'c72_diag_mirror', '--diag-mirror', state)
    clone = next(i for i, op in enumerate(absent) if op['kind'] == 'mirror')
    assert absent[clone]['key'] == [('$sid', ports['clone_session'], None)] and ports['clone_session'] == 7
    diag = ops[clone + 1:clone + 3]
    assert ops == absent[:clone + 1] + diag + absent[clone + 1:]
    assert ops[clone] == absent[clone]                     # session 7 untouched
    enabled = state == 'on'
    assert diag == [
        dict(kind='mirror', table='$mirror.cfg', pipe=0xffff, label='relay_rx_ingress_copy',
             key=[('$sid', 101, None)], action='$normal',
             data=[('$direction', 'INGRESS'), ('$ucast_egress_port', 10), ('$ucast_egress_port_valid', True),
                   ('$session_enable', enabled), ('$max_pkt_len', 16384)]),
        dict(kind='mirror', table='$mirror.cfg', pipe=0xffff, label='relay_tx_egress_copy',
             key=[('$sid', 102, None)], action='$normal',
             data=[('$direction', 'EGRESS'), ('$ucast_egress_port', 10), ('$ucast_egress_port_valid', True),
                   ('$session_enable', enabled), ('$max_pkt_len', 16384)])]


def test_offline_name_check_covers_the_diag_sessions(composite, monkeypatch):
    seen = []
    monkeypatch.setattr(composite.installer.check_names, 'load', lambda *_args: {})
    monkeypatch.setattr(composite.installer.check_names, 'check', lambda ops, _tables: seen.extend(ops) or [])
    monkeypatch.setattr(composite.installer.check_names, 'check_registers', lambda *_args: [])
    monkeypatch.setattr(composite.installer.check_names, 'check_reads', lambda *_args: [])
    rc, _stdout = dry_run(composite, 'c72_diag_mirror', '--diag-mirror', 'on')
    assert rc == 0
    assert [op['key'][0][1] for op in seen if op['kind'] == 'mirror'] == [7, 101, 102]


@pytest.mark.parametrize('state', ['on', 'off'])
def test_diag_dry_run_passes_the_real_name_check(composite, state):
    rc, stdout = dry_run(composite, 'c72_diag_mirror', '--diag-mirror', state)
    assert rc == 0, stdout
    assert 'PASS: every table, key, action, data field and register validated' in stdout
    assert '[$sid=101]' in stdout and '[$sid=102]' in stdout


def test_diag_mirror_on_a_build_without_the_diag_constants_is_refused(composite):
    rc, stdout = dry_run(composite, 'c72', '--diag-mirror', 'on')
    assert rc == 1
    assert 'REFUSED' in stdout and 'n_DIAG_SESSION_RX' in stdout
    assert 'PLAN:' not in stdout and 'DRY-RUN' not in stdout


@pytest.mark.parametrize('field,value,reason', [('copy_port', 64, 'relay port'), ('session_rx', 7, "T's clone session"),
                                                ('session_tx', 101, 'must differ'),
                                                ('egress_parsed_ports', [9, 10, 48, 64], 'parsed by r_EgParser')])
def test_invalid_diag_constants_are_refused_before_any_plan(composite, monkeypatch, field, value, reason):
    real = diag_mirror_sessions.load

    def bad(path):
        constants = real(path)
        constants[field] = value
        return constants
    monkeypatch.setattr(diag_mirror_sessions, 'load', bad)
    rc, stdout = dry_run(composite, 'c72_diag_mirror', '--diag-mirror', 'on')
    assert rc == 1 and 'REFUSED' in stdout and reason in stdout and 'PLAN:' not in stdout


class FakeSwitch:
    """Records every write; `existing` mirror sessions are present before bring-up."""

    def __init__(self, existing=()):
        self.mirror = {sid: {'action_name': '$normal'} for sid in existing}
        self.writes, self.deleted, self.sw_read = [], [], set()

    def get(self, table, pipe, key, priority=None):
        if table == '$PORT':
            return {'$PORT_ENABLE': True, '$PORT_UP': False, '$LOOPBACK_MODE': 'BF_LPBK_NONE',
                    '$MEDIA_TYPE': 'BF_MEDIA_TYPE_UNKNOWN'}
        if table == '$mirror.cfg':
            return self.mirror.get(key[0][1])
        return None

    def count(self, table, pipe):
        return 0

    def resolve_queue(self, dev_port, qid, pipe):
        return 0, qid, None

    def write(self, op):
        self.writes.append(op)
        if op['kind'] == 'mirror':
            self.mirror[op['key'][0][1]] = {'action_name': op['action']}
        if op['kind'] in ('p4', 'mirror'):
            return dict(undo='delete')
        if op['kind'] == 'default':
            return dict(undo='default_reset', before={})
        return dict(undo='restore', before={})

    def table(self, name):
        return SimpleNamespace(entry_del=lambda _target, keys: self.entry_del(name, keys))

    def entry_del(self, table, keys):
        for key in keys:
            self.deleted.append((table, key))
            if table == '$mirror.cfg':
                self.mirror.pop(key[0][1], None)

    def target(self, pipe):
        return pipe

    def key(self, table, key, priority=None):
        return tuple(tuple(k) for k in key)

    def close(self):
        pass


def install(bc, monkeypatch, tmp_path, switch, *extra, sink=None):
    a, ports, ops = planned(bc, 'c72_diag_mirror', *extra)
    a.manifest_out = str(tmp_path / 'bringup_manifest.json')
    fake = ModuleType('switch')
    fake.Switch = lambda *_args: switch
    monkeypatch.setitem(sys.modules, 'switch', fake)
    for name, value in (('verify', lambda sw, op: []), ('registers', lambda sw: {}),
                        ('register_errors', lambda regs: []), ('snapshot', lambda *args, **kwargs: {})):
        monkeypatch.setattr(bc.installer.readback, name, value)
    monkeypatch.setattr(bc.installer, 'wait_link_up', lambda *_args: True)
    before = copy.deepcopy(ops)                     # apply() resolves queue keys in place
    out = io.StringIO() if sink is None else sink
    with contextlib.redirect_stdout(out):
        bc.installer.apply(ops, a, ports)
    return before, out.getvalue()


@pytest.mark.parametrize('present', [101, 102])
def test_pre_check_refuses_an_existing_diag_session_and_writes_nothing(composite, monkeypatch, tmp_path, present):
    switch, out = FakeSwitch(existing=(present,)), io.StringIO()
    with pytest.raises(SystemExit) as stopped:
        install(composite, monkeypatch, tmp_path, switch, '--diag-mirror', 'on', sink=out)
    assert stopped.value.code == 2
    assert 'FAIL-CLOSED: mirror session %d already exists' % present in out.getvalue()
    assert switch.writes == [] and not (tmp_path / 'bringup_manifest.json').exists()


def test_absent_install_never_asks_for_the_diag_sessions(composite, monkeypatch, tmp_path):
    switch = FakeSwitch(existing=(101, 102))         # left over or not: absent neither reads nor writes them
    ops, _out = install(composite, monkeypatch, tmp_path, switch)
    assert [op['key'][0][1] for op in switch.writes if op['kind'] == 'mirror'] == [7]
    assert ops_sha(composite, ops) == GOLDEN_PLAN_SHA


def test_manifest_undo_records_make_teardown_delete_both_diag_sessions(composite, monkeypatch, tmp_path):
    switch = FakeSwitch()
    install(composite, monkeypatch, tmp_path, switch, '--diag-mirror', 'on')
    manifest = bringup_teardown.load(tmp_path / 'bringup_manifest.json')
    order = [op for op in bringup_teardown.steps(manifest['installed']) if op['kind'] == 'mirror']
    assert [(op['key'][0][1], op['undo']) for op in order] == [(102, 'delete'), (101, 'delete'), (7, 'delete')]
    assert set(switch.mirror) == {7, 101, 102}
    for op in order:
        assert bringup_teardown.undo(switch, op) == []
    assert switch.mirror == {}
    assert [key[0][1] for table, key in switch.deleted if table == '$mirror.cfg'] == [102, 101, 7]


def test_teardown_dry_run_lists_both_diag_session_deletes(composite, monkeypatch, tmp_path):
    install(composite, monkeypatch, tmp_path, FakeSwitch(), '--diag-mirror', 'off')
    with contextlib.redirect_stdout(io.StringIO()) as out:
        assert bringup_teardown.main(['--manifest', str(tmp_path / 'bringup_manifest.json')]) == 0
    lines = [line.split() for line in out.getvalue().splitlines() if '$mirror.cfg' in line]
    assert lines == [['delete', '$mirror.cfg', 'relay_tx_egress_copy'],
                     ['delete', '$mirror.cfg', 'relay_rx_ingress_copy'], ['delete', '$mirror.cfg', '[7]']]


def test_diag_mirror_sessions_is_in_the_installer_source_set_copied_and_verified_on_the_switch():
    path = str(ROOT / 'scripts/hardware/diag_mirror_sessions.py')
    assert path in campaign_base.installer_hw_files()
    cfg = json.loads(C72_CONFIG.read_text())
    rn = campaign_base.DryRunner()
    with contextlib.redirect_stdout(io.StringIO()):
        campaign_base.Campaign(cfg, rn, 'offline_fixture').deploy_switch()
    verify = [cmd for where, cmd in rn.calls if where == 'switch' and cmd.startswith('sha256sum ')]
    copy_step = [cmd for where, cmd in rn.calls if where == 'local' and cmd.startswith('rsync -aR')]
    assert any(cfg['hosts']['switch_remote_dir'] + '/src/scripts/hardware/diag_mirror_sessions.py' in cmd
               for cmd in verify)
    assert any(' scripts/hardware ' in cmd for cmd in copy_step)


# ------------------------------------------------------------------------------------------------ campaign
def c72_config():
    return json.loads(C72_CONFIG.read_text())


def diag_config(state='on'):
    cfg = c72_config()
    pins = json.loads((ROOT / 'results/builds/c72_diag_mirror/compile_local/manifest.json').read_text())
    build = cfg['builds']['current']
    build.update(source_sha256=DIAG_SHA, manifest='results/builds/c72_diag_mirror/compile_local/manifest.json',
                 out_dir='results/builds/c72_diag_mirror/compile_local/out',
                 hashes={rel: pins['artifact_sha256'][rel] for rel in campaign_base.BUILD_HASHED})
    cfg['purpose'] = 'diagnostic'
    cfg['diag_mirror'] = dict(state=state, copy_port=10, capture_interface=MIRROR_IFACE, build_label='c72_diag_mirror',
                              source_sha256=DIAG_SHA)
    cfg['ports_map']['stat_ports'] = '9,64,10'
    return cfg


def dry_unit(cls, cfg):
    rn = campaign_base.DryRunner()
    c = cls(copy.deepcopy(cfg), rn, 'offline_fixture')
    c.bound = {'current': dict(cfg['builds']['current']['hashes'])}
    with contextlib.redirect_stdout(io.StringIO()):
        c.run_unit(c.units()[0], c.ports()[0])
    return c, rn.calls


@pytest.mark.parametrize('cls', [campaign_base.Campaign, campaign.CandidateCampaign])
def test_installer_cmd_is_unchanged_without_diag_mirror_and_flagged_with_it(cls):
    plain = cls(c72_config(), campaign_base.DryRunner(), 'offline_fixture')
    plain.bound = {'current': dict(c72_config()['builds']['current']['hashes'])}
    assert plain.installer_cmd('current', 1, '/remote/out_current', 60000) == GOLDEN_INSTALLER_CMD
    for state in ('on', 'off'):
        cfg = diag_config(state)
        diag = cls(cfg, campaign_base.DryRunner(), 'offline_fixture')
        diag.bound = {'current': dict(c72_config()['builds']['current']['hashes'])}
        assert diag.installer_cmd('current', 1, '/remote/out_current', 60000) == \
            GOLDEN_INSTALLER_CMD + ' --diag-mirror ' + state


@pytest.mark.parametrize('cls', [campaign_base.Campaign, campaign.CandidateCampaign])
def test_unit_commands_are_unchanged_without_diag_mirror(cls):
    c, calls = dry_unit(cls, c72_config())
    assert hashlib.sha256(json.dumps(calls).encode()).hexdigest() == GOLDEN_UNIT_CALLS_SHA[cls.__name__]
    assert [cmd for where, cmd in calls if where == 'vision'] == [GOLDEN_VISION_CMD]
    trial = c.record['arms'][0]['trials'][0]
    assert 'diag_mirror' not in trial and 'diag_mirror' not in c.record and 'purpose' not in c.record


@pytest.mark.parametrize('cls', [campaign_base.Campaign, campaign.CandidateCampaign])
def test_diag_unit_adds_only_the_installer_flag_and_the_capture_interface(cls):
    _c, plain = dry_unit(cls, c72_config())
    c, diag = dry_unit(cls, diag_config('on'))
    assert len(diag) == len(plain)
    c72_pins, diag_pins = (c72_config()['builds']['current']['hashes'], diag_config()['builds']['current']['hashes'])
    for (where, before), (where_after, after) in zip(plain, diag):
        assert where == where_after
        if 'vision_run.py run ' in before:
            assert after == before + ' --mirror-iface ' + MIRROR_IFACE
        elif 'bringup_composite.py' in before:
            for rel in campaign_base.BUILD_HASHED:      # the diagnostic build's own pins, then the flag
                before = before.replace(c72_pins[rel], diag_pins[rel])
            assert after == re.sub(r'( --pad-enable [01])', r'\1 --diag-mirror on', before, count=1)
        elif 'snapshot_counters.py' in before:                # the config's stat_ports add the copy port
            assert after == before.replace(' --ports 9,64 ', ' --ports 9,64,10 ')
        else:
            assert after == before
    assert sum('--mirror-iface' in cmd for _w, cmd in diag) == 1
    assert sum('--diag-mirror on' in cmd for _w, cmd in diag) == 2       # install dry-run and apply
    trial = c.record['arms'][0]['trials'][0]
    label = dict(build_label='c72_diag_mirror', source_sha256=DIAG_SHA, state='on', copy_port=10,
                 capture_interface=MIRROR_IFACE)
    assert trial['diag_mirror'] == label
    assert c.record['purpose'] == 'diagnostic' and c.record['diag_mirror'] == label


@pytest.mark.parametrize('purpose', [None, 'relay-native-baseline', 'evaluation'])
def test_diagnostic_block_without_diagnostic_purpose_is_refused(purpose):
    cfg = diag_config()
    if purpose is None:
        del cfg['purpose']
    else:
        cfg['purpose'] = purpose
    with pytest.raises(ValueError, match='purpose'):
        campaign.CandidateCampaign(cfg, campaign_base.DryRunner(), 'offline_fixture')


@pytest.mark.parametrize('change,match', [
    (lambda c: c['diag_mirror'].update(state='absent'), 'state'),
    (lambda c: c['diag_mirror'].pop('build_label'), 'build_label'),
    (lambda c: c['diag_mirror'].update(capture_interface='enp59s0f0np0'), 'capture_interface'),
    (lambda c: c['diag_mirror'].update(capture_interface='x; reboot'), 'capture_interface'),
    (lambda c: c['diag_mirror'].update(source_sha256=C72_SHA), 'source_sha256'),
    (lambda c: c['diag_mirror'].update(copy_port=11), 'copy port'),
    (lambda c: c['ports_map'].update(stat_ports='9,64'), 'stat_ports'),
])
def test_diagnostic_block_with_an_inconsistent_label_is_refused(change, match):
    cfg = diag_config()
    change(cfg)
    with pytest.raises(ValueError, match=match):
        campaign.CandidateCampaign(cfg, campaign_base.DryRunner(), 'offline_fixture')


@pytest.mark.parametrize('kwargs', [dict(loss='x'), dict(scenario='reconnect'), dict(paired='p')])
def test_diagnostic_block_runs_plain_trials_only(kwargs):
    cfg = diag_config()
    cfg['loss']['presets'] = {'x': [{'class': 'select_resp_padded', 'n': 1, 'target': 'identity'}]}
    cfg['scenarios'] = {'reconnect': {'arm': 'off', 'fixture': 'physical_relay', 'reconnect_port_offset': 1}}
    cfg['paired_blocks'] = {'p': {}}
    with pytest.raises(ValueError, match='plain trials'):
        campaign_base.Campaign(cfg, campaign_base.DryRunner(), 'offline_fixture', **kwargs)


def relay_verdict_fixture(monkeypatch, tmp_path, cfg, mirror_files):
    c = campaign_base.Campaign(cfg, campaign_base.ShellRunner(cfg['hosts']), 'offline_fixture')
    dest = tmp_path / 'trial'
    (dest / 'snapshots').mkdir(parents=True)
    sbo = campaign_base.checks.sbo_count(cfg['traffic'])
    (dest / 'master.json').write_text(json.dumps(dict(ok=True, counts=dict(READ=65, SELECT=sbo, OPERATE=sbo),
                                                      records=[])))
    for name, content in mirror_files.items():
        (dest / name).write_bytes(content)
    import relay_check
    monkeypatch.setattr(relay_check, 'analyze', lambda *_args: dict(packets={}, failures=[], exchanges=[]))
    monkeypatch.setattr(relay_check, 'visible_clrt', lambda _report: {})
    monkeypatch.setattr(c, 'validate_standards_file', lambda *_args, **_kwargs: [])
    monkeypatch.setattr(campaign_base.checks, 'load_evidence_files', lambda **_kwargs: {})
    monkeypatch.setattr(campaign_base.checks, 'evaluate_switch', lambda *_args, **_kwargs: ([], {}))
    arm = c.arms[0]
    trial = dict(label='t', master_port=60000, reads=65, failures=[], ok=False)
    if 'diag_mirror' in cfg:
        trial['diag_mirror'] = dict(build_label='c72_diag_mirror')
    return c, trial, arm, dest


def mirror_evidence(ok=True):
    files = {name: b'{}' for name in vision_run.MIRROR_FILES}
    files['mirror.pcap'] = b'\xd4\xc3\xb2\xa1' + bytes(20)
    failures = [] if ok else ['mirror tcpdump exited early']
    files['mirror_capture.json'] = json.dumps(dict(ok=ok, failures=failures)).encode()
    return files


def test_collected_mirror_evidence_is_hashed_into_the_trial_record(monkeypatch, tmp_path):
    files = mirror_evidence()
    c, trial, arm, dest = relay_verdict_fixture(monkeypatch, tmp_path, diag_config(), files)
    c.relay_verdict(trial, {}, 't', str(dest), Result(0), arm, 'physical_relay')
    assert trial['ok'] is True and trial['dimension_verdicts']['diag_mirror'] is True
    assert trial['diag_mirror']['files'] == {name: hashlib.sha256(content).hexdigest()
                                             for name, content in files.items()}
    assert json.loads((dest / 'trial.json').read_text())['diag_mirror']['build_label'] == 'c72_diag_mirror'


@pytest.mark.parametrize('missing', ['mirror.pcap', 'mirror_iface_before.json', 'mirror_iface_after.json',
                                     'mirror_offloads.json', 'mirror_capture.json'])
def test_missing_mirror_evidence_fails_the_trial_loudly(monkeypatch, tmp_path, missing):
    files = mirror_evidence()
    del files[missing]
    c, trial, arm, dest = relay_verdict_fixture(monkeypatch, tmp_path, diag_config(), files)
    with pytest.raises(campaign_base.StepFailed):
        c.relay_verdict(trial, {}, 't', str(dest), Result(0), arm, 'physical_relay')
    assert trial['ok'] is False and any(missing in failure for failure in trial['failures'])


def test_a_failed_mirror_capture_fails_the_trial(monkeypatch, tmp_path):
    c, trial, arm, dest = relay_verdict_fixture(monkeypatch, tmp_path, diag_config(), mirror_evidence(ok=False))
    with pytest.raises(campaign_base.StepFailed):
        c.relay_verdict(trial, {}, 't', str(dest), Result(0), arm, 'physical_relay')
    assert any('exited early' in failure for failure in trial['failures'])


def test_plain_verdict_does_not_look_for_mirror_evidence(monkeypatch, tmp_path):
    c, trial, arm, dest = relay_verdict_fixture(monkeypatch, tmp_path, c72_config(), {})
    c.relay_verdict(trial, {}, 't', str(dest), Result(0), arm, 'physical_relay')
    assert trial['ok'] is True and 'diag_mirror' not in trial and 'diag_mirror' not in trial['dimension_verdicts']


def Result(rc):
    return campaign_base.Result(rc, '', '')


# ---------------------------------------------------------------------------------------------- vision_run
class VisionFakes:
    """Every process boundary of vision_run.run_relay_connection, recorded; nothing is executed."""

    def __init__(self, monkeypatch, run_dir, mirror='ok', restore_fail=None, workload_error=None):
        self.log, self.run_dir, self.mirror, self.restore_fail = [], run_dir, mirror, restore_fail
        self.features, self.rx = {}, {}
        fakes = self
        original = capture_observation.offload_capture_context

        def context(*args, **kwargs):
            kwargs.setdefault('run', fakes.co_sh)
            fakes.log.append(['offload_context', str(args[0]).rsplit('/', 1)[-1], sorted(kwargs)])
            return original(*args, **kwargs)

        class Popen:
            def __init__(self, argv, **_kwargs):
                fakes.log.append(['popen'] + list(argv))
                self.argv, self.mirror = argv, MIRROR_IFACE in argv
                self.polls = 0
                if not (self.mirror and fakes.mirror in ('no_header', 'exit_at_start')):
                    Path(argv[argv.index('-w') + 1]).write_bytes(b'\xd4\xc3\xb2\xa1' + bytes(20))

            def poll(self):
                self.polls += 1
                exited = fakes.mirror == 'exit_at_start' or fakes.mirror == 'exit_during' and self.polls > 1
                if self.mirror and exited:
                    return 1
                return None

            def terminate(self):
                fakes.log.append(['terminate', self.argv[self.argv.index('-w') + 1].rsplit('/', 1)[1]])

            def communicate(self, timeout=None):
                if self.mirror:
                    return '', '13 packets captured\n14 packets received by filter\n0 packets dropped by kernel\n'
                return '', '5 packets captured\n6 packets received by filter\n0 packets dropped by kernel\n'

        def workload(*args, **kwargs):
            fakes.log.append(['workload', list(args), sorted(kwargs)])
            if workload_error:
                raise RuntimeError(workload_error)
            return dict(ok=True, records=[])

        self.baseline = run_dir.parent / 'mirror_offload_baseline.json'
        monkeypatch.setattr(vision_run, 'MIRROR_OFFLOAD_BASELINE', str(self.baseline), raising=False)
        monkeypatch.setattr(vision_run, 'HOME', str(run_dir.parent))
        monkeypatch.setattr(capture_observation, 'sh', self.co_sh)
        monkeypatch.setattr(capture_observation, 'offload_capture_context', context)
        monkeypatch.setattr(vision_run, 'sh', self.vr_sh)
        monkeypatch.setattr(vision_run.subprocess, 'Popen', Popen)
        monkeypatch.setattr(vision_run.time, 'sleep', lambda seconds: self.log.append(['sleep', seconds]))
        monkeypatch.setattr(relay_master, 'workload', workload)
        monkeypatch.setattr(vision_run, 'wait_relay_close', lambda *_args: (self.log.append(['close']),
                                                                             dict(complete=True))[1])

    def co_sh(self, argv, **_kwargs):
        argv = list(argv)
        self.log.append(['co_sh'] + argv)
        ok = SimpleNamespace(returncode=0, stdout='', stderr='')
        if argv[:2] == ['ethtool', '-k']:
            f = self.features.setdefault(argv[2], {'generic-receive-offload': 'on',
                                                   'large-receive-offload': 'off [fixed]',
                                                   'rx-gro-hw': 'off [fixed]', 'rx-gro-list': 'off'})
            return SimpleNamespace(returncode=0, stdout=''.join('%s: %s\n' % kv for kv in f.items()), stderr='')
        if argv[:2] == ['ethtool', '-K']:
            if self.restore_fail == argv[2] and argv[4] == 'on':
                return SimpleNamespace(returncode=1, stdout='', stderr='Cannot change generic-receive-offload')
            self.features[argv[2]][{'gro': 'generic-receive-offload'}.get(argv[3], argv[3])] = argv[4]
            return ok
        if argv[:2] == ['ethtool', '-i']:
            return SimpleNamespace(returncode=0, stdout='driver: i40e\nversion: 2.8.20-k\nbus-info: 0000:3b:00.1\n',
                                   stderr='')
        if argv[:2] == ['ethtool', '-S']:
            self.rx[argv[2]] = self.rx.get(argv[2], 100) + 13
            return SimpleNamespace(returncode=0, stdout='NIC statistics:\n     rx_packets: %d\n     tx_packets: 5\n'
                                   '     rx_dropped: 0\n' % self.rx[argv[2]], stderr='')
        if argv[:3] == ['ip', '-j', '-s']:
            return SimpleNamespace(returncode=0, stdout=json.dumps([dict(ifname=argv[-1], stats64=dict(
                rx=dict(packets=self.rx.get(argv[-1], 100))))]), stderr='')
        return ok

    def vr_sh(self, *cmd, **_kwargs):
        self.log.append(['vr_sh'] + list(cmd))
        flags = 'disable-source-pruning : on\n' if cmd[:2] == ('ethtool', '--show-priv-flags') else ''
        return SimpleNamespace(returncode=0, stdout=flags, stderr='')

    def normalized(self):
        return [[x.replace(str(self.run_dir.parent), '<D>') if isinstance(x, str) else x for x in entry]
                for entry in self.log]


def run_vision(monkeypatch, tmp_path, mirror_iface=None, **fake_kwargs):
    fakes = VisionFakes(monkeypatch, tmp_path / 'run', **fake_kwargs)
    kwargs = {} if mirror_iface is None else dict(mirror_iface=mirror_iface)
    result = vision_run.run_relay_connection(str(tmp_path / 'run'), 'fixture', 60000, 3, run_sbo=False,
                                             read_schedule='mixed_full', **kwargs)
    return fakes, result


MIRROR_TCPDUMP = ['popen', 'tcpdump', '-i', MIRROR_IFACE, '-Q', 'in', '-s0', '-U', '-n', '--immediate-mode', '-w',
                  '<D>/run/mirror.pcap']


def test_vision_commands_are_unchanged_without_mirror_iface(monkeypatch, tmp_path):
    fakes, result = run_vision(monkeypatch, tmp_path)
    assert fakes.normalized() == GOLDEN_VISION_LOG
    assert result['ok'] is True and 'mirror' not in result
    assert sorted(os.listdir(tmp_path / 'run')) == ['capture_offloads.json', 'in.pcap', 'master.json', 'out.pcap',
                                                   'result.json', 'state.txt']


def test_mirror_capture_is_started_verified_stopped_and_restored(monkeypatch, tmp_path):
    fakes, result = run_vision(monkeypatch, tmp_path, mirror_iface=MIRROR_IFACE)
    log = fakes.normalized()
    assert result['ok'] is True, result
    # the master's commands are exactly today's, with the mirror steps between capture start and stop
    master = [entry for entry in log if MIRROR_IFACE not in ' '.join(map(str, entry))
              and entry != ['terminate', 'mirror.pcap'] and entry[:2] != ['offload_context', 'run'] or
              entry == ['offload_context', 'run', ['interface', 'run']]]
    sleeps = [i for i, entry in enumerate(master) if entry == ['sleep', 2]]
    assert master[:sleeps[0] + 1] + master[sleeps[1] + 1:] == GOLDEN_VISION_LOG
    order = {name: log.index(entry) for name, entry in (
        ('identity_before', ['co_sh', 'ethtool', '-i', MIRROR_IFACE]),
        ('gro_off', ['co_sh', 'ethtool', '-K', MIRROR_IFACE, 'gro', 'off']),
        ('tcpdump', MIRROR_TCPDUMP),
        ('workload', ['workload', [60000, 3], WORKLOAD_KWARGS]),
        ('master_stopped', ['terminate', 'in.pcap']),
        ('mirror_stopped', ['terminate', 'mirror.pcap']),
        ('gro_on', ['co_sh', 'ethtool', '-K', MIRROR_IFACE, 'gro', 'on']))}
    assert list(order) == sorted(order, key=order.get)
    assert ['co_sh', 'ip', '-j', '-s', 'link', 'show', MIRROR_IFACE] in log
    assert log.count(['co_sh', 'ethtool', '-S', MIRROR_IFACE]) == 2
    run_dir = tmp_path / 'run'
    for name in vision_run.MIRROR_FILES:
        assert (run_dir / name).is_file(), name
    before = json.loads((run_dir / 'mirror_iface_before.json').read_text())
    after = json.loads((run_dir / 'mirror_iface_after.json').read_text())
    assert before['driver']['driver'] == 'i40e' and before['driver']['bus-info'] == '0000:3b:00.1'
    assert before['rx_counters']['rx_packets'] == 113 and after['rx_counters']['rx_packets'] == 126
    assert before['link'][0]['ifname'] == MIRROR_IFACE
    offloads = json.loads((run_dir / 'mirror_offloads.json').read_text())
    assert offloads['interface'] == MIRROR_IFACE and offloads['restore_ok'] is True
    assert offloads['during']['features']['gro'] is False and offloads['after']['features']['gro'] is True
    assert json.loads((run_dir / 'capture_offloads.json').read_text())['interface'] == 'enp59s0f0np0'
    capture = json.loads((run_dir / 'mirror_capture.json').read_text())
    assert capture['ok'] is True and capture['failures'] == [] and capture['offload_restore_ok'] is True
    assert capture['tcpdump'] == dict(captured=13, received=14, dropped_kernel=0)
    assert capture['command'] == MIRROR_TCPDUMP[1:-1] + [str(run_dir / 'mirror.pcap')]
    assert result['mirror'] == capture
    assert json.loads((run_dir / 'result.json').read_text())['mirror']['ok'] is True


@pytest.mark.parametrize('mode,text', [('exit_at_start', 'before traffic'), ('no_header', 'before traffic')])
def test_mirror_start_failure_fails_the_trial_before_traffic_and_restores(monkeypatch, tmp_path, mode, text):
    fakes, result = run_vision(monkeypatch, tmp_path, mirror_iface=MIRROR_IFACE, mirror=mode)
    log = fakes.normalized()
    assert result['ok'] is False and text in result['error']
    assert not any(entry[0] == 'workload' for entry in log)
    assert ['co_sh', 'ethtool', '-K', MIRROR_IFACE, 'gro', 'on'] in log
    capture = json.loads((tmp_path / 'run/mirror_capture.json').read_text())
    assert capture['ok'] is False and capture['offload_restore_ok'] is True
    assert json.loads((tmp_path / 'run/result.json').read_text())['ok'] is False


def test_mirror_tcpdump_exit_during_traffic_fails_the_trial(monkeypatch, tmp_path):
    _fakes, result = run_vision(monkeypatch, tmp_path, mirror_iface=MIRROR_IFACE, mirror='exit_during')
    assert result['ok'] is False
    assert any('exited early' in failure for failure in result['mirror']['failures'])
    assert 'diagnostic mirror' in result['error']


def test_mirror_offload_restore_failure_fails_the_trial(monkeypatch, tmp_path):
    _fakes, result = run_vision(monkeypatch, tmp_path, mirror_iface=MIRROR_IFACE, restore_fail=MIRROR_IFACE)
    assert result['ok'] is False
    assert any('restore' in failure for failure in result['mirror']['failures'])
    assert json.loads((tmp_path / 'run/mirror_offloads.json').read_text())['restore_ok'] is False
    assert result['mirror']['offload_restore_ok'] is False


def test_mirror_is_stopped_and_restored_when_the_workload_raises(monkeypatch, tmp_path):
    fakes, result = run_vision(monkeypatch, tmp_path, mirror_iface=MIRROR_IFACE, workload_error='relay gone')
    log = fakes.normalized()
    assert result['ok'] is False and result['error'] == 'relay gone'
    assert ['terminate', 'mirror.pcap'] in log
    assert log.index(['terminate', 'mirror.pcap']) < log.index(['co_sh', 'ethtool', '-K', MIRROR_IFACE, 'gro', 'on'])
    assert result['mirror']['offload_restore_ok'] is True
    for name in vision_run.MIRROR_FILES:
        assert (tmp_path / 'run' / name).is_file(), name


@pytest.mark.parametrize('argv', [
    ['setup', '--mirror-iface', MIRROR_IFACE],
    ['run', 'lbl', '--master-port', '60000', '--mirror-iface', 'enp59s0f0np0'],
    ['run', 'lbl', '--master-port', '60000', '--mirror-iface', 'bad;name'],
    ['run', 'lbl', '--master-port', '60000', '--mirror-iface', MIRROR_IFACE, '--scenario', 'persistence'],
    ['run', 'lbl', '--master-port', '60000', '--mirror-iface', MIRROR_IFACE, '--drop', 'select_resp_padded:1'],
    ['run', 'lbl', '--master-port', '60000', '--mirror-iface', MIRROR_IFACE, '--event-clear'],
])
def test_vision_main_refuses_mirror_iface_outside_one_plain_run(monkeypatch, argv):
    monkeypatch.setattr(vision_run, 'authorize_relay_run', lambda _a: pytest.fail('authorized before refusal'))
    monkeypatch.setattr(sys, 'argv', ['vision_run.py'] + argv)
    with pytest.raises(SystemExit) as refused:
        vision_run.main()
    assert '--mirror-iface' in str(refused.value.code)


@pytest.mark.parametrize('extra,expected', [([], None), (['--mirror-iface', MIRROR_IFACE], MIRROR_IFACE)])
def test_vision_main_passes_the_mirror_interface_only_when_given(monkeypatch, extra, expected):
    seen = {}
    monkeypatch.setattr(vision_run, 'authorize_relay_run', lambda _a: None)
    monkeypatch.setattr(vision_run, 'run_connection', lambda *args, **kwargs: seen.update(kwargs) or dict(ok=True))
    monkeypatch.setattr(sys, 'argv', ['vision_run.py', 'run', 'lbl', '--master-port', '60000'] + extra)
    with contextlib.redirect_stdout(io.StringIO()), pytest.raises(SystemExit) as done:
        vision_run.main()
    assert done.value.code == 0
    assert seen.get('mirror_iface') == expected


# ------------------------------------------------- campaign restore repairs the mirror interface (interaction 4)
def master_baseline(fakes, tmp_path):
    path = tmp_path / 'offload_baseline.json'
    capture_observation.record_offload_baseline(path, vision_run.PARENT, run=fakes.co_sh)
    return path


def mirror_gro(fakes):
    return fakes.features[MIRROR_IFACE]['generic-receive-offload']


def test_restore_repairs_the_mirror_interface_after_a_killed_run(monkeypatch, tmp_path):
    fakes = VisionFakes(monkeypatch, tmp_path / 'run')
    (tmp_path / 'run').mkdir()
    killed = vision_run.MirrorCapture(str(tmp_path / 'run'), MIRROR_IFACE)
    killed.start()                                   # SIGKILL here: stop() and the context's finally never run
    assert mirror_gro(fakes) == 'off' and fakes.baseline.is_file()
    assert json.loads(fakes.baseline.read_text())['interface'] == MIRROR_IFACE
    result = vision_run.relay_offload_lifecycle('restore', baseline_path=master_baseline(fakes, tmp_path),
                                                run=fakes.co_sh)
    assert mirror_gro(fakes) == 'on' and not fakes.baseline.exists()
    assert result['errors'] == [] and result['restored'] is True
    assert result['mirror'] == dict(interface=MIRROR_IFACE, errors=[], restored=True)
    killed.offloads.close()                          # end the simulated process deterministically (no GC finalizer)


def test_restore_reports_a_mirror_restore_failure_and_keeps_the_baseline(monkeypatch, tmp_path):
    fakes = VisionFakes(monkeypatch, tmp_path / 'run', restore_fail=MIRROR_IFACE)
    (tmp_path / 'run').mkdir()
    killed = vision_run.MirrorCapture(str(tmp_path / 'run'), MIRROR_IFACE)
    killed.start()
    result = vision_run.relay_offload_lifecycle('restore', baseline_path=master_baseline(fakes, tmp_path),
                                                run=fakes.co_sh)
    assert result['restored'] is False and result['mirror']['restored'] is False
    assert any(MIRROR_IFACE in error for error in result['errors'])
    assert fakes.baseline.is_file() and mirror_gro(fakes) == 'off'
    with pytest.raises(RuntimeError, match='receive offload restore failed'):
        killed.offloads.close()                      # end the simulated process deterministically (no GC finalizer)


def test_restore_without_a_mirror_baseline_returns_exactly_todays_record(monkeypatch, tmp_path):
    fakes = VisionFakes(monkeypatch, tmp_path / 'run')
    path = master_baseline(fakes, tmp_path)
    fakes.log.clear()
    result = vision_run.relay_offload_lifecycle('restore', baseline_path=path, run=fakes.co_sh)
    assert result == dict(errors=[], restored=True, loss=dict(applied=False, errors=[], restored=True))
    assert fakes.normalized() == [['co_sh', 'ethtool', '-k', 'enp59s0f0np0']] * 2   # current, then verified after


def test_a_completed_mirror_run_leaves_no_pending_baseline(monkeypatch, tmp_path):
    fakes, result = run_vision(monkeypatch, tmp_path, mirror_iface=MIRROR_IFACE)
    assert result['ok'] is True and not fakes.baseline.exists()
    assert fakes.normalized().count(['co_sh', 'ethtool', '-k', MIRROR_IFACE]) >= 4   # baseline, context, verify


def test_a_failed_in_run_restore_keeps_the_baseline_for_the_campaign_restore(monkeypatch, tmp_path):
    fakes, result = run_vision(monkeypatch, tmp_path, mirror_iface=MIRROR_IFACE, restore_fail=MIRROR_IFACE)
    assert result['ok'] is False and fakes.baseline.is_file()


def test_mirror_start_refuses_while_a_mirror_baseline_is_pending(monkeypatch, tmp_path):
    pending = tmp_path / 'mirror_offload_baseline.json'
    pending.write_text(json.dumps(dict(interface=MIRROR_IFACE, features=dict(gro=True), raw='')))
    fakes, result = run_vision(monkeypatch, tmp_path, mirror_iface=MIRROR_IFACE)
    log = fakes.normalized()
    assert result['ok'] is False and 'restore first' in result['error']
    assert not any(entry[:3] == ['co_sh', 'ethtool', '-K'] and MIRROR_IFACE in entry for entry in log)
    assert not any(entry[0] == 'workload' for entry in log)
    assert json.loads(pending.read_text()) == dict(interface=MIRROR_IFACE, features=dict(gro=True), raw='')

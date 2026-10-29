"""c72_diag_mirror: generator, session script and static compile checks (offline; no switch, no model)."""
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / 'results/builds/c72_diag_mirror'
C72_SOURCE_SHA256 = '97812585d64146dd5de65b8fd42d19c1471e2c5d80da85dacaae68b4083d887e'
needs_build = pytest.mark.skipif(not (BUILD / 'compile_local/out/response_only.p4pp').is_file(),
                                 reason='compiled c72_diag_mirror build not present')


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope='module')
def gen():
    return load('diag_generator', ROOT / 'scripts/build_diag_mirror.py')


@pytest.fixture(scope='module')
def sessions():
    return load('diag_sessions', ROOT / 'scripts/hardware/diag_mirror_sessions.py')


@pytest.fixture(scope='module')
def texts(gen):
    canonical = (ROOT / 'p4/response_only.p4').read_text()
    derived, points = gen.derive(canonical)
    return canonical, derived, points


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def test_canonical_source_is_still_c72(texts):
    canonical, _derived, _points = texts
    assert sha(canonical) == C72_SOURCE_SHA256
    assert hashlib.sha256((ROOT / 'results/builds/c72/response_only.p4').read_bytes()).hexdigest() == C72_SOURCE_SHA256


def test_derived_source_is_canonical_plus_declared_insertions_only(gen, texts):
    canonical, derived, points = texts
    found = gen.insertions(canonical, derived)                 # independent line+character diff; raises on any deletion
    declared = [text for _name, _anchor, _where, text in gen.HUNKS]
    assert len(found) == len(gen.HUNKS) == len(points)
    assert sorted(text for _line, text in found) == sorted(declared)
    assert all(gen.TAG in text or 'MirrorId_t diag_ses;' == text or 'diag_mirror' in text for text in declared)
    stripped = derived
    for _name, offset, text in sorted(points, key=lambda p: p[1], reverse=True):
        shifted = offset + sum(len(t) for _n, o, t in points if o < offset)
        assert stripped[shifted:shifted + len(text)] == text
        stripped = stripped[:shifted] + stripped[shifted + len(text):]
    assert stripped == canonical


def test_insertion_check_rejects_deletion_and_replacement(gen, texts):
    canonical, derived, _points = texts
    target = 'const MirrorId_t t_CLONE_SESSION_ID = 10w7;'
    with pytest.raises(ValueError):
        gen.insertions(canonical, derived.replace(target, target.replace('10w7', '10w8')))
    with pytest.raises(ValueError):
        gen.insertions(canonical, derived.replace('md.drop_ctl = 3w1; }', 'md.drop_ctl = 3w5; }', 1))
    with pytest.raises(ValueError):
        gen.insertions(canonical, derived.replace('\nconst bit<32> r_IMAGE_LEN = 61;\n', '\n', 1))


def test_ambiguous_anchor_is_refused(gen, texts):
    canonical, _derived, _points = texts
    anchor = gen.HUNKS[0][1]
    with pytest.raises(ValueError, match='occurs 2 times'):
        gen.derive(canonical + '\n' + anchor)


def test_t_pipe_segment_and_clone_session_are_untouched(gen, texts):
    canonical, derived, _points = texts
    profile = load('diag_profile', ROOT / 'scripts/profile.py')
    a, b = profile.role_hashes(canonical), profile.role_hashes(derived)
    assert a['T'] == b['T']                                     # the whole T/x (pipe 1) source text
    assert a['N'] != b['N'] and a['E'] != b['E']
    assert derived.count('const MirrorId_t t_CLONE_SESSION_ID = 10w7;') == 1


def test_session_ids_and_copy_port(gen, texts):
    _canonical, derived, _points = texts
    c = gen.constants(derived)
    assert c['n_DIAG_SESSION_RX'] == gen.SESSION_RX and c['r_DIAG_SESSION_TX'] == gen.SESSION_TX
    assert 7 not in (c['n_DIAG_SESSION_RX'], c['r_DIAG_SESSION_TX'])
    assert c['n_DIAG_SESSION_RX'] != c['r_DIAG_SESSION_TX']
    assert c['n_DIAG_NO_SESSION'] == c['r_DIAG_NO_SESSION'] == 0
    assert c['n_DIAG_RELAY_PORT'] == c['r_DIAG_RELAY_PORT'] == 64 and c['r_DIAG_COPY_PORT'] == 10


def test_copy_port_is_never_a_loop_recirculation_or_parsed_port(gen, texts):
    _canonical, derived, _points = texts
    build_ports = load('diag_build_ports', ROOT / 'scripts/hardware/build_ports.py')
    copy = gen.constants(derived)['r_DIAG_COPY_PORT']
    assert copy in build_ports.NEVER_LOOP
    for name in ('n_RETURN_PORT', 'n_N_ACK_RETURN', 'n_READ_HANDOFF_PORT', 't_PKTGEN_RETURN', 't_T_IN',
                 't_HELD_RETURN', 't_N_RETURN', 't_FORWARD_PORT', 't_RELAY_PORT'):
        assert ('const PortId_t %s' % name) in derived
        assert ('9w%d;' % copy) not in derived.split('const PortId_t %s' % name, 1)[1].split('\n', 1)[0].replace(' ', '')
    profile = json.loads((ROOT / 'p4/profile_template.json').read_text())['supported_profile']['ports']
    assert copy not in [v for k, v in profile.items() if isinstance(v, int)]


def test_packaged_build_matches_generator(gen, texts):
    _canonical, derived, _points = texts
    if not BUILD.is_dir():
        pytest.skip('c72_diag_mirror build not present')
    assert (BUILD / 'response_only.p4').read_text() == derived
    meta = json.loads((BUILD / 'diag_mirror.json').read_text())
    assert meta['source_sha256'] == sha(derived) and meta['canonical_sha256'] == C72_SOURCE_SHA256
    assert meta['deleted_or_replaced'] == 0 and meta['hunks'] == [h[0] for h in gen.HUNKS]
    assert (BUILD / 'diag_mirror.diff').read_text() == gen.unified_diff((ROOT / 'p4/response_only.p4').read_text(), derived)
    inputs = json.loads((BUILD / 'response_only.inputs.json').read_text())
    assert inputs['supported_profile']['candidate']['build'] == 'c72_diag_mirror'
    assert inputs['source_sha256'] == sha(derived)


@needs_build
def test_session_script_reads_the_compiled_constants(sessions):
    c = sessions.load(BUILD)
    assert (c['session_rx'], c['session_tx'], c['copy_port'], c['t_clone']) == (101, 102, 10, 7)
    assert c['egress_parsed_ports'] == [9, 48, 64]
    assert sessions.validate(c) == []


def good():
    return dict(session_rx=101, session_tx=102, copy_port=10, relay_in=64, relay_out=64, t_clone=7,
                internal_ports=dict(n_RETURN_PORT=68, n_N_ACK_RETURN=48, n_READ_HANDOFF_PORT=180, t_PKTGEN_RETURN=196,
                                    t_T_IN=180, t_HELD_RETURN=182, t_N_RETURN=68, t_FORWARD_PORT=9, t_RELAY_PORT=64),
                egress_parsed_ports=[9, 48, 64])


@pytest.mark.parametrize('change, words', [
    (dict(session_rx=7), "T's clone session"), (dict(session_tx=7), "T's clone session"),
    (dict(session_tx=101), 'must differ'), (dict(session_rx=0), '1-1015'), (dict(session_tx=1016), '1-1015'),
    (dict(copy_port=64), 'relay port'), (dict(copy_port=68), 'recirculation'), (dict(copy_port=48), 'parsed by r_EgParser'),
    (dict(copy_port=9), 'parsed by r_EgParser'), (dict(copy_port=138), 'pipe-0 front-panel'),
    (dict(copy_port=196), 'pipe-0 front-panel'), (dict(relay_out=65), 'disagree')])
def test_session_validation_refuses_unsafe_values(sessions, change, words):
    c = dict(good(), **change)
    errors = sessions.validate(c)
    assert errors and any(words in e for e in errors), errors


def test_session_ops_on_and_off(sessions):
    for state, enabled in (('on', True), ('off', False)):
        ops = sessions.ops(good(), state)
        assert [op['key'] for op in ops] == [[('$sid', 101, None)], [('$sid', 102, None)]]
        assert all(op['kind'] == 'mirror' and op['table'] == '$mirror.cfg' and op['action'] == '$normal' for op in ops)
        data = [dict(op['data']) for op in ops]
        assert [d['$direction'] for d in data] == ['INGRESS', 'EGRESS']
        assert all(d['$ucast_egress_port'] == 10 and d['$ucast_egress_port_valid'] is True and
                   d['$max_pkt_len'] == 16384 and d['$session_enable'] is enabled for d in data)
    with pytest.raises(ValueError):
        sessions.ops(good(), 'absent')


class FakeSwitch:
    """The subset of switch.Switch that apply() uses, over a dict of $mirror.cfg entries."""

    def __init__(self, entries=None, corrupt=None):
        self.entries, self.corrupt, self.log = dict(entries or {}), corrupt, []

    def table(self, name):
        assert name == '$mirror.cfg'
        return self

    def target(self, pipe):
        return pipe

    def key(self, _table, key):
        return key[0][1]

    def entry_del(self, _target, keys):
        for sid in keys:
            self.log.append(('del', sid))
            del self.entries[sid]

    def get(self, _table, _pipe, key):
        return self.entries.get(key[0][1])

    def write(self, op):
        sid = op['key'][0][1]
        self.log.append(('add', sid))
        self.entries[sid] = dict(op['data'], **(self.corrupt or {}))


def test_apply_states_and_readback(sessions):
    sw = FakeSwitch({101: {'$session_enable': True}, 7: {'$session_enable': True}})
    result = sessions.apply(sw, good(), 'off')
    assert sw.log == [('del', 101), ('add', 101), ('add', 102)]
    assert sw.entries[101]['$session_enable'] is False and sw.entries[102]['$direction'] == 'EGRESS'
    assert 7 in sw.entries and len(result['ops']) == 2           # T's session is never touched
    sessions.apply(sw, good(), 'on')
    assert sw.entries[101]['$session_enable'] is True and sw.entries[102]['$session_enable'] is True
    sessions.apply(sw, good(), 'absent')
    assert set(sw.entries) == {7}


def test_apply_refuses_unsafe_config_and_detects_bad_readback(sessions):
    sw = FakeSwitch()
    with pytest.raises(ValueError):
        sessions.apply(sw, dict(good(), session_tx=7), 'on')
    assert sw.log == []
    with pytest.raises(RuntimeError, match='read back differently'):
        sessions.apply(FakeSwitch(corrupt={'$max_pkt_len': 2048}), good(), 'on')


@needs_build
def test_compiled_mirror_guard_and_pipe1_equivalence():
    checks = load('diag_checks', ROOT / 'scripts/diag_mirror_checks.py')
    ok, report = checks.guard_pipe0(BUILD / 'compile_local/out', dict(ingress=101, egress=102))
    assert ok, report
    assert report['gress']['ingress']['unconditional_mirror_type_setters']
    ok, eq = checks.pipe1_equivalence(ROOT / 'results/builds/c72/compile_local/out', BUILD / 'compile_local/out')
    assert ok and not eq['other_differing_lines'], eq


def test_mirror_guard_rejects_a_shared_session_container(tmp_path):
    checks = load('diag_checks', ROOT / 'scripts/diag_mirror_checks.py')
    bfa = '\n'.join([
        'phv ingress:', '    B3:', '    - { name : ig_intr_md_for_dprsr.mirror_type, live_start : 1 }',
        '    H7:', '    - { name : m.diag_ses, live_start : 1 }', '    - { name : m.other, live_start : 2 }',
        'phv egress:', '    B16:', '    - { name : eg_intr_md_for_dprsr.mirror_type, live_start : 1 }',
        '    H21:', '    - { name : m.diag_ses, live_start : 1 }',
        'parser ingress:', '  init_zero: [ B3, H7 ]', 'deparser ingress:', '  dictionary: []', '  mirror:',
        '    select: B3(0..2)  # bit[2..0]: ingress::ig_intr_md_for_dprsr.mirror_type',
        '    1:', '      - H7(0..9)  # bit[9..0]: ingress::m.diag_ses',
        'parser egress:', '  init_zero: [ H21 ]', 'deparser egress:', '  dictionary: []', '  mirror:',
        '    select: B16(0..2)  # bit[2..0]: egress::eg_intr_md_for_dprsr.mirror_type',
        '    1:', '      - H21(0..9)  # bit[9..0]: egress::m.diag_ses', ''])
    (tmp_path / 'p0').mkdir()
    (tmp_path / 'p0/response_only.bfa').write_text(bfa)
    ok, report = checks.guard_pipe0(tmp_path, dict(ingress=101, egress=102))
    assert not ok
    assert report['gress']['ingress']['checks']['session_container_solitary'] is False

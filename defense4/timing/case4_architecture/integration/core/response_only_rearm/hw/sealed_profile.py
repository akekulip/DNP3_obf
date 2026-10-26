"""Pinned sealed-epoch profile; sparse counters retain the original stale sum."""
import hashlib
import json
import re
from pathlib import Path

# Actual complete compiler artifacts, not a register-size heuristic.
PROFILES = {
    # ctl_timing_01 m10 (m10_03: m9 + the N stage-1 RST restart; source d9b84fcc): SDK 9.13.2, then 9.13.1.
    'df6b191450db62c1f17f56be5320032aca80a50eec09ee91540f55b7104b4a2c': {
        '4d2dd07a56f1071f37b32b735d50ed33aaa04c0fcff438ddae1abdce0b405be3',
    },
    '1124d21138570d1d2af4c16bafe9bea3a20049bd79fa94497340626379f981f1': {
        '87c9013b1da973c1161cd6b231201b1cd672e45e3c1cf5e94b8c23486f4e13c1',
    },
    # DIAGNOSTIC ctl_timing_01 m9d (m9d_01: m9 + E egress timestamps; source 74c9cdcd): SDK 9.13.2, then 9.13.1.
    '79fcd80131ddeda99eda252f59637679ea4285cda81f5f9f069ef0f9eedd4f46': {
        'cfd9363340368bb3b121e789c71c68f404385a2d028da18460f2ad1d594491fd',
    },
    '5a7034d4787ef1fc9e1c574156d28864078344e5dc4be1426ff30f2dcc280a1a': {
        '68e3f8bd99cd7e290429a8d283ec702ab410f72c89b91904e921263e1d1dcb3a',
    },
    # ctl_timing_01 m9 (m9_01: m8 + the N reset wait; source 6590141f): one bfrt.json from both SDKs, p4pp 9.13.2
    # then 9.13.1.
    'f54acf2e7d598c2b3ad0bad4871f60cd3c6c83e96319d0d66e9c88ac82e42369': {
        '7c15b3097935d40326a04d21d2a9b146adf38cf2dd42987791fd6396b43462bf',
        'c74a92c764494fe9cbca2cb3b8afac1545121e901e90083e47884cc74726f9e8',
    },
    # ctl_timing_01 m5 (m5_10: m4 + bounded, validated busy-retry for responses in N; E and T identical to m4):
    # SDK 9.13.2, then 9.13.1.
    'b5b01ee99142b02df66bad8bc180e77859d0e829fd136bde905f9e6deda1977c': {
        '7acdc0e6ee9ec7d609de4b253a29cc4127b96c3051a229acb6a6913d47929be9',
    },
    '94370bf35141f4dfd766e546567b435f1faf77d587c60ca1c303a7642cf16674': {
        '2fd4129a567d848f9121ebea1cf57179375af70973d754c19a0fce73a733dfff',
    },
    # ctl_timing_01 m4 (m3 + Table 4-9 selection lifecycle in N, fail-closed OPERATE lane exhaustion in T; E
    # identical): SDK 9.13.2, then 9.13.1.
    'cdadfef1375f605ec27b24489677600f28aa021f26c385d2134291d94a0585c4': {
        '10674c46e60aaefc498801389f931fc128d83e4f5716c2b372cf85efc477d77c',
    },
    '3e9d933e970c3accc5b51d14f0c84ab5301d99b9c5ed79b3dabaf4b699ab6a61': {
        'b4e7a61a4873f9a842596803d84566dd2a8b6273b8683f689900347c6c585302',
    },
    # ctl_timing_01 m3 (control timing + piggyback bound; E identical to candidate61): SDK 9.13.2, then 9.13.1.
    '57123e535817a26aa7a305535de928fbe9b65a6c6d0dc05594141f767c611e84': {
        '258d12bb39806f70c6a8530ba876604e016f18c1444543dfb5a4c0b1903be0c5',
    },
    '133c1accd068c45d8b8ade52b8b4a3d4ea768ee7b006b38fe9a0e9ed67b85b5f': {
        'f6525046cac2374c0e5c80d387ca05e950fa51f23638fd42c98bac66fb6f382a',
    },
    # candidate61 seg61_02 full_04: complete installed SDK 9.13.2 artifacts.
    'e32df20459c0dc15b9a64cabc7f64d43e53f90434c51698d5b8a58aa43de0311': {
        '3306c394ef3f447cb48e62f25e2df609acc72e02085f83f6096ccbb9d7287a43',
    },
    '4c1bfc92eb746d5df80cb6464e777c3b244fb7f792b17c76eb31bb461e1170da': {
        '6dab48d4ad2bdc9db993825fe57117e0fd27c57951e8c1b1578333ee37b256dc',
        '25244d805cfbc05c39c14a7f3f947ec049826a6108ea0737ed717df3e4634fb1',
    },
    # retx_passthrough_01 (candidate56 + retransmission pass-through): installed SDK 9.13.2, then local 9.13.1.
    'fbb1f2c0111342dd6808381e32a22df04e3ad2cfde3d7d340a113a2acc4e899e': {
        '62de2c19001b2fbb42742974b8a5e61813037be3a5efb06f0acc6dac5c37d6c6',
    },
    '21275f3befdf6260ad24253b5432b8005743e5cc78f0266d87251f80d2c959bf': {
        '095db5023e7a011de7a48994cabe1208bc441d352bc2d6a50334f2c3c4dde36a',
    },
    # rearm_57s (dup_hold_01 full_02_strict: conforming READ re-encoding, strict controls, duplicate-OPERATE
    # hold): installed SDK 9.13.2, then local 9.13.1.
    '22d666b23d2d63bf76d62b7d2b6643a5aac6e303abe9ac6b4f1392ed38f437f6': {
        '2052c564cc77938f3b13001ed94abe089b93e0cdb040c0b259161270dcf3c0d9',
        # rearm_57a (dup_hold_01 full_01, all-58 profile): same table schema, so the same bfrt.json.
        '4ea609f6faab5dc2acf7f24b016054ccdb4063133f2fca88b1d1575bc4d11cd4',
    },
    '029f9e18e4c5473484d74b7cb126186332876ed9d935f908d413b19d3b800adb': {
        '9369d239a9093534d9f43c80c1196730d97ba3a5791e21d18b37f43a976dee56',
    },
    '2a22b713f5f0e767d4f635aaf908fc4e9bf5ccb9a5aa247a39f49fe893f5f92a': {
        'e784485bfbde211d74929ea8e4d514bd219714798c55afaf6237b6cdb26d8480',
    },
}


def _legacy_select(build_out):
    out = Path(build_out)
    raw = (out/'bfrt.json').read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest in PROFILES:
        if hashlib.sha256((out/'response_only.p4pp').read_bytes()).hexdigest() not in PROFILES[digest]:
            raise ValueError('sealed profile compiled source differs from its pinned artifact')
        return True
    tables = {item['name']: item for item in json.loads(raw)['tables']}
    if tables.get('p1.t_Ingress.outcomes', {}).get('size') == 16 and \
            'p1.t_Ingress.quarantine_reg' in tables:
        return False
    raise ValueError('unsupported candidate epoch/counter profile')



def child_registers(descriptor):
    count = descriptor.get('t_child_count')
    if type(count) is not int or count not in (1, 2, 3):
        raise ValueError('unsupported T child count')
    return tuple('child_seen%d_reg' % index for index in range(count))


def validate_timing_contract(supported, text):
    """Reject a source/profile ABI mismatch before choosing any hardware writes."""
    contract = supported.get('timing_contract')
    declared = re.findall(r'timing_contract:\s*(\w+)', text)
    if declared and any(value != contract for value in declared):
        raise ValueError('source timing ABI differs from supported profile contract')
    actions = re.findall(r'action\s+set_params\s*\(([^)]*)\)', text, re.S)
    keys = tuple(re.findall(r'bit\s*<\s*\d+\s*>\s+(\w+)', actions[0])) if len(actions) == 1 else ()
    if contract == 'response_ready_ack_d_no_j_v3':
        if supported.get('timing_ns') != dict(D_release_budget=5000000):
            raise ValueError('no-J response-ready profile timing must bind only D')
        expected = ('gap', 'budget', 'enabled')
    elif contract == 'response_ready_ack_d_v2':
        if supported.get('timing_ns') != dict(D_release_budget=5000000, J_operate_hold=2400000):
            raise ValueError('response-ready profile timing must bind only D and J')
        expected = ('gap', 'op_j', 'budget', 'enabled')
    else:
        if keys in (('gap', 'op_j', 'budget', 'enabled'), ('gap', 'budget', 'enabled')) or \
                'response_wait_timeout' in text or contract is not None:
            raise ValueError('source timing ABI differs from supported profile')
        return None
    if keys != expected or \
            'md.now = ig_prsr_md.global_tstamp[39:8] & 32w0xfffffffe;' not in text:
        raise ValueError('response-ready compiled source ABI/clock mismatch')
    return contract



def _source_profile(out):
    """Locate unchanged build metadata locally or in the deployed out/profile copy."""
    if (out / 'profile').is_dir():
        directory = out / 'profile'
        names = [name for name in ('compile_local', 'compile_switch_9132')
                 if (directory / name / 'manifest.json').is_file()]
        if len(names) != 1:
            raise ValueError('deployed profile requires one selected compile manifest')
        compile_name = names[0]
    else:
        directory, compile_name = out.parent.parent, out.parent.name
    inputs_path = directory / 'response_only.inputs.json'
    if not inputs_path.is_file():
        if directory == out / 'profile':
            raise ValueError('deployed supported profile inputs are missing')
        return None
    inputs = json.loads(inputs_path.read_text())
    if not isinstance(inputs, dict):
        raise ValueError('supported profile inputs must be an object')
    supported = inputs.get('supported_profile')
    if supported is None:
        return None
    if not isinstance(supported, dict) or supported.get('reset_restart_required') is not True:
        raise ValueError('successor supported profile must require reset restart coverage')
    child_registers(supported)
    candidate = supported.get('candidate')
    if not isinstance(candidate, dict):
        raise ValueError('supported profile candidate identity is missing')
    source = directory / 'response_only.p4'
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    if inputs.get('source_sha256') != digest or candidate.get('source_sha256') != digest:
        raise ValueError('supported profile source/input hashes differ')
    separate = directory / 'supported_profile.json'
    if separate.is_file() and json.loads(separate.read_text()) != supported:
        raise ValueError('supported profile file differs from its build inputs')
    contract = validate_timing_contract(supported, source.read_text())
    compiles = candidate.get('artifact_sha256')
    if not isinstance(compiles, dict):
        raise ValueError('supported profile requires artifact hashes for both SDK compiles')
    required = {'bfrt.json', 'response_only.p4pp', 'p0/context.json', 'p1/context.json',
                'p0/tofino.bin', 'p1/tofino.bin'}
    # one SDK (since 2026-10-23): a build whose local compile is 9.13.2 pins compile_local alone; otherwise both
    local_manifest = directory / 'compile_local' / 'manifest.json'
    one_sdk = local_manifest.is_file() and re.match(
        r'^p4c\s+9\.13\.2(?:\s|$)', json.loads(local_manifest.read_text()).get('compiler', '')) is not None
    for name in (('compile_local',) if one_sdk else ('compile_local', 'compile_switch_9132')):
        pins = compiles.get(name)
        if not isinstance(pins, dict) or not required.issubset(pins) or \
                any(not isinstance(value, str) or re.fullmatch('[0-9a-f]{64}', value) is None
                    for value in pins.values()):
            raise ValueError('supported profile requires complete artifact hashes for both SDK compiles')
    if compile_name not in compiles:
        raise ValueError('unsupported selected SDK compile')
    manifest = json.loads((directory / compile_name / 'manifest.json').read_text())
    if manifest.get('source_sha256') != digest or manifest.get('exit_code') != 0:
        raise ValueError('compile manifest does not bind a successful build of this source')
    pins = compiles[compile_name]
    artifacts = manifest.get('artifact_sha256')
    if not isinstance(artifacts, dict) or not artifacts or \
            any(pins.get(name) != value for name, value in artifacts.items()):
        raise ValueError('compile manifest artifact hashes differ from the supported profile')
    for name, expected in pins.items():
        relative = Path(name)
        if relative.is_absolute() or '..' in relative.parts:
            raise ValueError('invalid supported profile artifact path')
        path = out / relative
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError('supported profile artifact differs or is missing: ' + name)
    return dict(sealed=True, t_child_count=supported['t_child_count'], source_sha256=digest,
                compile_name=compile_name, timing_contract=contract)


def describe(build_out):
    """Select a source/artifact-bound T schema; historical pins remain unchanged."""
    out = Path(build_out)
    descriptor = _source_profile(out)
    if descriptor is None:
        descriptor = dict(sealed=_legacy_select(out), t_child_count=3)
    tables = json.loads((out / 'bfrt.json').read_bytes())['tables']
    if descriptor.get('timing_contract') is not None:
        validate_timing_contract(dict(timing_contract=descriptor['timing_contract'],
            timing_ns=(dict(D_release_budget=5000000) if descriptor['timing_contract'] ==
                       'response_ready_ack_d_no_j_v3' else dict(D_release_budget=5000000, J_operate_hold=2400000))),
            (out / 'response_only.p4pp').read_text())
    if descriptor.get('timing_contract') == 'response_ready_ack_d_no_j_v3':
        params = next((table for table in tables if table['name'] == 'p1.t_Ingress.params'), {})
        actions = [action for action in params.get('action_specs', [])
                   if action.get('name') == 't_Ingress.set_params']
        if len(actions) != 1 or tuple(field['name'] for field in actions[0].get('data', [])) != \
                ('gap', 'budget', 'enabled'):
            raise ValueError('no-J compiled BFRT parameter ABI mismatch')
        retired = {'op_gen_alloc_reg', 'op_t0_reg', 'op_done_reg', 'operate_generation_access',
                   'operate_anchor_access', 'op_go_check', 'operate_completion_access', 'hb_verdict'}
        observed_retired = {item['name'] for item in tables
                            if item['name'].startswith('p1.t_Ingress.') and item['name'].split('.')[-1] in retired}
        if observed_retired:
            raise ValueError('no-J compiled ABI retains OPERATE hold resources: %s' % sorted(observed_retired))
    observed = {item['name'] for item in tables
                if re.fullmatch(r'p1\.t_Ingress\.child_seen[0-9]+_reg', item['name'])}
    expected = {'p1.t_Ingress.' + name for name in child_registers(descriptor)}
    if observed != expected:
        raise ValueError('compiled T child banks differ from the selected profile: expected %s, observed %s'
                         % (sorted(expected), sorted(observed)))
    return descriptor


def select(build_out):
    """Compatibility wrapper for callers that only need the sealed-layout boolean."""
    return describe(build_out)['sealed']

def read_diagnostics(read_outcome, outcomes, expected=False):
    blocker = outcomes.get('OUT_TOKEN_STALE')
    op, read = read_outcome(23), read_outcome(24)
    if all(value is None for value in list(outcomes.values()) + [op, read]):
        # c68: the build has no T outcomes register at all (write-only measurement state removed); a build that
        # has it and reads back partly None still fails below, and evaluate_switch refuses absent counters
        return dict(present=False, layout='no_switch_telemetry', rewait={}, blocker_laps={}, stale={},
                    read_errors=[], stale_sources={}, stale_total=None)
    if any(type(value) is not int or value < 0 for value in (blocker, op, read)):
        raise ValueError('missing or malformed raw timer/blocker rejection counters')
    outcomes.update(STALE_BLOCKER=blocker, RAW_OPERATE_TIMER_STALE=op, RAW_READ_TIMER_STALE=read,
                    OUT_TOKEN_STALE=blocker+op+read)
    # dup_hold_01 builds count an early duplicate OPERATE dropped while its original is held at index 16
    # (t_OUT_OP_DUP_DROP). Recorded only; it is not stale and never enters stale_total. Older sealed builds
    # leave index 16 unused (0).
    dup = read_outcome(16)
    outcomes.update(OUT_OP_DUP_DROP=dup if type(dup) is int and dup >= 0 else None)
    # This is not make_diag_t's layout: index14/15 remain lifecycle/exhaustion,
    # and a readable unused index16 must not switch to legacy stale accounting.
    return dict(present=False, layout='split_raw_timer_23_24',
                rewait={'OPERATE': outcomes.get('OUT_HELD_REWAIT')}, blocker_laps={},
                stale={}, read_errors=[], stale_sources={'6': 'STALE_BLOCKER',
                '23': 'RAW_OPERATE_TIMER_STALE', '24': 'RAW_READ_TIMER_STALE'},
                stale_total=blocker+op+read)

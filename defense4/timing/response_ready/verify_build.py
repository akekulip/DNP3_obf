#!/usr/bin/env python3
"""Offline source/artifact consistency gate; passing never authorizes deployment."""
from __future__ import annotations
import argparse
import gzip
import hashlib
import json
import re
from pathlib import Path
import sys

if __package__ in (None, ''):
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from defense4.timing.stage_reduction.build import context_stages, final_allocation


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _artifact(build, paths, expected_hash):
    """Check every retained copy; gz hashes refer to the original compiler bytes."""
    found = []
    payload = None
    for relative in paths:
        path = build / relative
        if not path.exists():
            continue
        data = gzip.decompress(path.read_bytes()) if path.suffix == '.gz' else path.read_bytes()
        _require(_sha(data) == expected_hash, 'artifact hash mismatch: ' + relative)
        found.append(relative)
        payload = data
    _require(bool(found), 'missing artifact: ' + ' or '.join(paths))
    return payload, found


def _command_value(command, option, expected):
    indices = [i for i, value in enumerate(command) if value == option]
    _require(len(indices) == 1 and indices[0] + 1 < len(command)
             and command[indices[0] + 1] == expected
             and not any(value.startswith(option + '=') for value in command),
             'compiler command must select exactly ' + option + ' ' + expected)


def _compiler_identity(text):
    version = re.search(r'\b(9\.13\.[12])\b', text)
    _require(version is not None, 'Case 4 requires identified SDE 9.13.1 or 9.13.2 compiler')
    revision = re.search(r'\((?:SHA:\s*)?([0-9a-fA-F]{6,64})\)', text)
    _require(revision is not None, 'Case 4 compiler identity must include its revision')
    return version.group(1), revision.group(1).lower()


def _source_capacities(source):
    text = re.sub(r'/\*.*?\*/|//[^\n]*', '', source, flags=re.S)
    constants = {name: int(value, 0) for name, value in re.findall(
        r'const\s+bit<\d+>\s+(\w+)\s*=\s*(?:\d+w)?(0x[0-9a-fA-F]+|\d+)\s*;', text)}
    capacities = {}
    for width, index_width, value, name in re.findall(
            r'Register<\s*bit<(\d+)>\s*,\s*bit<(\d+)>\s*>\s*\(\s*(\w+)\s*,[^)]*\)\s+(\w+)\s*;', text):
        size = int(value) if value.isdecimal() else constants.get(value)
        _require(isinstance(size, int) and 0 < size <= (1 << int(index_width)),
                 'unresolved or invalid source register capacity: ' + name)
        _require(name not in capacities or capacities[name] == size,
                 'ambiguous source register capacity: ' + name)
        capacities[name] = size
    return constants, capacities


def _resource_file(build, manifest, name, compiler_copy=None):
    data = (build / name).read_bytes()
    hashes = manifest.get('resource_report_sha256', {})
    if name in hashes:
        _require(_sha(data) == hashes[name], 'resource report hash mismatch: ' + name)
    else:
        _require(compiler_copy is not None and compiler_copy.exists(),
                 'resource report lacks manifest hash or retained compiler copy: ' + name)
        _require(data == compiler_copy.read_bytes(), 'resource report differs from compiler copy: ' + name)
    if compiler_copy is not None and compiler_copy.is_file():
        _require(data == compiler_copy.read_bytes(), 'resource report differs from compiler copy: ' + name)
    return data


def _const_capacity(context, bfrt):
    schema = {(t['name'][5:] if t['name'].startswith('pipe.') else t['name']): t for t in bfrt['tables']}
    capacities = {}
    for table in context['tables']:
        entries = table.get('static_entries', [])
        _require(isinstance(entries, list), 'constant entries must be a list: ' + table['name'])
        count = sum(1 for entry in entries if entry.get('is_default_entry') is not True)
        if not count:
            continue
        size = table.get('size')
        _require(type(size) is int and count <= size, 'constant entries exceed table capacity: ' + table['name'])
        logical = schema.get(table['name'])
        if logical is not None:
            _require(logical.get('size') == size, 'constant table BFRT/context capacity mismatch: ' + table['name'])
        capacities[table['name']] = {'capacity': size, 'constant_entries': count}
    return capacities


def _case4_resources(source_text, build, manifest, context, bfrt, command):
    _command_value(command, '--target', 'tofino')
    _command_value(command, '--arch', 'tna')
    _require(context.get('target') == 'tofino', 'compiled context target must be Tofino-1')
    identity = _compiler_identity(manifest['compiler'])
    _require(_compiler_identity(context.get('compiler_version', '')) == identity,
             'context compiler identity disagrees with build manifest')
    run_id = context.get('run_id')
    _require(isinstance(run_id, str) and bool(run_id), 'missing compiler run identity')
    constants, capacities = _source_capacities(source_text)
    constant_tables = _const_capacity(context, bfrt)
    schema_regs = {(t['name'][5:] if t['name'].startswith('pipe.') else t['name']): t for t in bfrt['tables'] if t.get('table_type') == 'Register'}
    _require('Ingress.reg_owner' in schema_regs and 'Ingress.reg_app_seq' in schema_regs,
             'Case 4 association register schema is unavailable')
    for name, table in schema_regs.items():
        size = table.get('size')
        _require(type(size) is int and size == capacities.get(name.rsplit('.', 1)[-1]),
                 'compiled register capacity disagrees with source: ' + name)
    _require(schema_regs['Ingress.reg_owner']['size'] == 1 and schema_regs['Ingress.reg_app_seq']['size'] == 1,
             'Case 4 association requires one active slot')
    salus = {}
    for table in context['tables']:
        if table.get('table_type') != 'stateful':
            continue
        name = table['name']
        _require(name in schema_regs and table.get('size') == schema_regs[name]['size'],
                 'stateful context capacity disagrees with BFRT: ' + name)
        locations = []
        for stage in table.get('stage_tables', []):
            number, index = stage.get('stage_number'), stage.get('meter_alu_index')
            _require(type(number) is int and 0 <= number < 12 and type(index) is int and 0 <= index < 4,
                     'invalid Tofino-1 stateful ALU placement: ' + name)
            locations.append({'stage': number, 'meter_alu_index': index})
        _require(bool(locations), 'missing stateful ALU placement: ' + name)
        salus[name] = locations
    _require('Ingress.reg_owner' in salus and 'Ingress.reg_app_seq' in salus,
             'association stateful ALUs missing from compiled context')
    logs = build / 'out/pipe/logs'
    phv_copy = logs / manifest.get('final_phv_report', '')
    phv = _resource_file(build, manifest, 'phv_allocation_summary.log', phv_copy).decode()
    _require(bool(phv.splitlines()) and phv.splitlines()[0].strip() == 'PHV ALLOCATION SUCCESSFUL', 'PHV allocation did not succeed')
    mau = _resource_file(build, manifest, 'mau.resources.log', logs / 'mau.resources.log').decode()
    _require(re.search(r'Compiler version:\s*' + re.escape(identity[0]) + r'\b', mau) is not None,
             'MAU resource compiler version mismatch')
    _require(re.search(r'Run ID:\s*' + re.escape(run_id) + r'\b', mau) is not None,
             'MAU resource run identity mismatch')
    _require('Meter ALU' in mau, 'missing MAU/SALU resource report')
    assembly_copy = build / 'out/pipe/defense4_timing.bfa'
    assembly_name = 'assembly.bfa' if (build / 'assembly.bfa').exists() else 'out/pipe/defense4_timing.bfa'
    assembly = _resource_file(build, manifest, assembly_name, assembly_copy).decode()
    _require('run_id: "' + run_id + '"' in assembly, 'SALU assembly run identity mismatch')
    for name in salus:
        _require(re.search(r'^\s+stateful\s+[^\n]*\.' + re.escape(name) + r':', assembly, re.M) is not None,
                 'missing stateful ALU assembly: ' + name)
    binary, binary_paths = _artifact(build, ('tofino.bin', 'out/pipe/tofino.bin'), manifest['artifact_sha256']['pipe/tofino.bin'])
    report_names = ('phv_allocation_summary.log', 'mau.resources.log', assembly_name)
    return {'constants': constants, 'constant_table_capacity': constant_tables, 'register_capacity': {name: t['size'] for name, t in schema_regs.items()},
            'stateful_alu_locations': salus, 'compiler_run_id': run_id,
            'report_sha256': {name: _sha((build / name).read_bytes()) for name in report_names},
            'binary_paths': binary_paths, 'binary_sha256': _sha(binary)}, identity[0]


def verify_build(source, build_dir, *, profile="current"):
    source, build = Path(source), Path(build_dir)
    result = {'passed': False, 'deployment_authorized': False,
              'scope': 'Offline current-source/compiler-artifact consistency and stage limit only.',
              'source': str(source), 'build_dir': str(build), 'errors': [], 'profile': profile,
              'deployment_build_eligible': False, 'joint_mechanism_verified': False}
    try:
        _require(profile in ('current', 'case4'), 'unknown verification profile')
        manifest = json.loads((build / 'manifest.json').read_text())
        expected_source = manifest['source_sha256']
        current_hash = _sha(source.read_bytes())
        snapshot_hash = _sha((build / 'defense4_timing.p4').read_bytes())
        result['source_sha256'] = current_hash
        _require(current_hash == snapshot_hash == expected_source,
                 'current source, immutable build snapshot, and manifest source hash must match')
        _require(type(manifest['exit_code']) is int and manifest['exit_code'] == 0,
                 'compiler did not exit successfully')
        _require(isinstance(manifest.get('compiler'), str) and bool(manifest['compiler'].strip()),
                 'missing compiler identity')
        command = manifest['command']
        _require(isinstance(command, list) and all(isinstance(x,str) for x in command),
                 'compiler command must be an argument array')
        _require('-DU_BOR' in command or '-DU_BOR=1' in command,
                 'compiler command missing enabled U_BOR flag')
        _require(not any(x.startswith('-UU_BOR') for x in command) and
                 not any(x.startswith('-DU_BOR=') and x != '-DU_BOR=1' for x in command) and
                 not any(command[i] in ('-U','-D') and command[i+1].split('=')[0] == 'U_BOR' for i in range(len(command)-1)),
                 'ambiguous or disabled U_BOR command flags')
        _require(bool(command) and Path(command[-1]).name == 'defense4_timing.p4',
                 'compiler command must compile the immutable source snapshot')
        hashes = manifest['artifact_sha256']
        context_bytes, context_paths = _artifact(build, ('context.json.gz','context.json','out/pipe/context.json'), hashes['pipe/context.json'])
        bfrt_bytes, bfrt_paths = _artifact(build, ('bfrt.json','out/bfrt.json'), hashes['bfrt.json'])
        context = json.loads(context_bytes)
        bfrt = json.loads(bfrt_bytes)
        _require(isinstance(context.get('tables'),list) and isinstance(bfrt.get('tables'),list),
                 'context and BFRT must contain table arrays')
        actual = context_stages(context)
        result['context_stages'] = actual
        _require(manifest['context_stages'] == actual,
                 'manifest context-stage count disagrees with retained context')
        summaries = [p for p in (build/'table_summary.log',build/'out/pipe/logs/table_summary.log') if p.exists()]
        _require(bool(summaries), 'missing final table allocation report')
        for summary in summaries:
            final = final_allocation(summary.read_text())
            _require(all(manifest.get(k) == v for k,v in final.items()),
                     'manifest disagrees with final allocation report: ' + str(summary))
            _require(all(final[k] == v for k,v in actual.items()),
                     'final allocation report disagrees with context stages')
        if profile == 'current':
            _require(0 < actual['ingress_stages'] <= 7 and actual['egress_stages'] == 0,
                     'stage limit requires at most 7 ingress and exactly 0 egress stages')
        else:
            _require(0 < actual['ingress_stages'] <= 12 and 0 <= actual['egress_stages'] <= 12,
                     'Case 4 stage limit requires at most 12 ingress and 12 egress stages')
            resources, version = _case4_resources(source.read_text(), build, manifest, context, bfrt, command)
            result.update(resource_evidence=resources, deployment_build_eligible=version == '9.13.2',
                          switch_sde_requirement='9.13.2',
                          scope='Offline Case 4 source/artifact identity, target resources and association capacity; joint size/translation behavior and deployment remain unverified.')
            if version != '9.13.2':
                result['deployment_build_blocker'] = 'SDE 9.13.1 is offline evidence; switch artifacts require SDE 9.13.2'
        result.update(passed=True, compiler=manifest['compiler'],
                      verified_artifacts={'context': context_paths, 'bfrt': bfrt_paths},
                      artifact_sha256={k: hashes[k] for k in ('pipe/context.json','bfrt.json')})
    except (OSError, ValueError, KeyError, TypeError, AttributeError, EOFError) as exc:
        result['errors'].append(str(exc))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('build_dir', type=Path)
    parser.add_argument('--profile', choices=('current', 'case4'), default='current')
    args = parser.parse_args(argv)
    report = verify_build(args.source, args.build_dir, profile=args.profile)
    print(json.dumps(report, sort_keys=True))
    return 0 if report['passed'] else 1

if __name__ == '__main__':
    raise SystemExit(main())

#!/usr/bin/env python3
"""Validate the separate working draft without changing the frozen writing gate."""
import hashlib
import importlib.util
import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]


def check():
    frozen = ROOT / 'paper/rewrite/sections/01_introduction.tex'
    prefix = frozen.read_text().split('In this paper, we ', 1)[0]
    intro = (HERE / 'introduction.tex').read_text()
    expected = (HERE / 'protected_intro.sha256').read_text().strip()
    assert hashlib.sha256(prefix.encode()).hexdigest() == expected, 'protected reference changed'
    assert intro.startswith(prefix), 'working Introduction changes protected bytes'
    spec = importlib.util.spec_from_file_location('lin_reference',
            ROOT / 'paper/rewrite/pipeline/check_lin_intro_verbatim.py')
    lin = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(lin)
    paragraphs = prefix.split('\\label{sec:intro}', 1)[1].strip().split('\n\n')
    assert len(paragraphs) == len(lin.REFERENCE)
    for actual, reference in zip(paragraphs, lin.REFERENCE):
        assert lin.normalize(actual) == lin.normalize(reference), 'protected author words differ'

    sources = {p.name: p.read_text() for p in HERE.glob('*.tex')}
    proposed = '\n'.join(sources.values()).replace(prefix, '')
    assert 'CLRT_target' not in proposed, 'withdrawn notation'
    assert '\u2014' not in proposed, 'em dash in proposed prose'
    for heading in ('Framework Design', 'Implementation', 'Evaluation', 'Limitations'):
        assert '{' + heading + '}' in proposed, 'missing section: ' + heading
    assert 'not a complete joint fit' in proposed, 'joint resource limitation missing'
    bib = (ROOT / 'paper/rewrite/References.bib').read_text() + (HERE / 'case4_refs.bib').read_text()
    keys = set(re.findall(r'@\w+\s*\{\s*([^,\s]+)', bib))
    cited = {key.strip() for body in re.findall(r'\\cite\{([^}]+)\}', '\n'.join(sources.values()))
             for key in body.split(',')}
    assert cited <= keys, 'undefined citations: ' + str(sorted(cited - keys))

    manifest = json.loads((ROOT / 'defense4/timing/audit_current/framework_20261005/PROTECTED_EXECUTION_BASE.json').read_text())
    for item in manifest['files']:
        path = ROOT / item['path']
        assert hashlib.sha256(path.read_bytes()).hexdigest() == item['sha256'], 'protected change: ' + item['path']
    return {'passed': True, 'protected_files': len(manifest['files']),
            'protected_intro_sha256': expected, 'citation_keys': sorted(cited),
            'scope': 'Separate working candidate; no frozen-source promotion or submission authorization'}


if __name__ == '__main__':
    print(json.dumps(check(), indent=2))

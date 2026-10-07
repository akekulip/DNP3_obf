#!/usr/bin/env python3
"""Compile-only separate-pipe wire-role experiment; never configures ports."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import compose


def namespace(source, prefix):
    source = re.sub(r'^#include.*\n', '', source, flags=re.M)
    source = source[:source.index('Pipeline(')]
    names = set(re.findall(r'\b(?:header|struct|parser|control)\s+(\w+)', source))
    for name in sorted(names, key=len, reverse=True):
        source = re.sub(r'\b'+name+r'\b', prefix+name, source)
    return source


def generate():
    authority = namespace(compose.generate(['padding','forward','reverse','replay'], True), 'authority_')
    renderer = namespace(compose.generate(['carving']), 'renderer_')
    # Pipe1's provisional ingress; no actual port availability is asserted.
    renderer = renderer.replace('(9w64,16w97)', '(9w136,16w97)')
    source = '/* Two-pipe capability experiment. NEVER DEPLOY. */\n#include <core.p4>\n#include <tna.p4>\n'
    source += authority+renderer
    for name in ('authority','renderer'):
        source += f'Pipeline({name}_IgParser(),{name}_Ingress(),{name}_IgDeparser(),{name}_EgParser(),{name}_Egress(),{name}_EgDeparser()) {name}_pipe;\n'
    return source+'Switch(authority_pipe,renderer_pipe) main;\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output',type=Path)
    args = parser.parse_args()
    args.output.write_text(generate())
    inputs = {name:hashlib.sha256((compose.ROOT/'protocol'/file).read_bytes()).hexdigest()
              for name,file in compose.ROLE_FILES.items()}
    inputs['compose.py'] = hashlib.sha256(Path(compose.__file__).read_bytes()).hexdigest()
    args.output.with_suffix('.inputs.json').write_text(json.dumps(inputs,indent=2)+'\n')


if __name__=='__main__':
    main()

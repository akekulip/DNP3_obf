"""Combine immutable, independent N and T stage experiments with frozen E."""
import hashlib
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CANDIDATE = HERE.parents[1]
BASE = CANDIDATE / 'evidence/incremental_55/response_only.p4'
N_SOURCE = HERE.parent / 'n_crc_residue/evidence/response_only_residue.p4'
T_SOURCE = HERE.parent / 't_sealed_lifetime/evidence/full_02/response_only.p4'
INPUTS = {
    'baseline': (BASE, '628af1c66da5b61a7b4062dfae40b3e14320bc5d370d20219d893fef3862b261'),
    'N': (N_SOURCE, '0b03e15ab900928c67ed57773b6596517ed8767571e84718f9032cfef331dd8c'),
    'T': (T_SOURCE, '400caaad2407a1afe1274135acf21846ec10738395583862e4f1a8fcfa86a7bd'),
}
MARKERS = {'N': '/* Generated isolated N protected reconnect candidate. */',
           'E': '/* Generated isolated E protected reconnect candidate. */',
           'T': '/* Generated isolated T reconnect candidate. */'}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def checked(name):
    path, expected = INPUTS[name]
    raw = path.read_bytes()
    assert digest(raw) == expected, (name, 'input changed')
    return raw.decode()


def segment(text, name):
    assert text.count(MARKERS[name]) == 1
    start = text.index(MARKERS[name])
    end = text.index(MARKERS[{'N': 'E', 'E': 'T'}[name]]) if name != 'T' else text.index('\nPipeline(')
    return text[start:end]


def full_source():
    base, n, t = (checked(name) for name in ('baseline', 'N', 'T'))
    for name in ('E', 'T'):
        assert segment(n, name) == segment(base, name), ('N experiment changed', name)
    for name in ('N', 'E'):
        assert segment(t, name) == segment(base, name), ('T experiment changed', name)
    # Check everything outside the one changed role as well as role identities.
    assert n.replace(segment(n, 'N'), segment(base, 'N'), 1) == base
    assert t.replace(segment(t, 'T'), segment(base, 'T'), 1) == base
    combined = base.replace(segment(base, 'N'), segment(n, 'N'), 1)
    combined = combined.replace(segment(base, 'T'), segment(t, 'T'), 1)
    assert segment(combined, 'N') == segment(n, 'N')
    assert segment(combined, 'E') == segment(base, 'E')
    assert segment(combined, 'T') == segment(t, 'T')
    assert combined.replace(segment(n, 'N'), segment(base, 'N'), 1).replace(
        segment(t, 'T'), segment(base, 'T'), 1) == base
    return combined


def source_role(name):
    """Only standalone identifiers/ports for the retained actual-source harness."""
    text = segment(full_source(), name)
    prefix = {'N': 'n', 'E': 'r', 'T': 't'}[name]
    text = re.sub(r'\b' + prefix + r'_(\w+)', r'\1', text)
    if name == 'N':
        text = text.replace('N_ACK_RETURN=9w48;', 'N_ACK_RETURN=9w70;')
        text = text.replace('READ_HANDOFF_PORT=9w180;', 'READ_HANDOFF_PORT=9w197;')
    elif name == 'E':
        text = text.replace('9w48: provenance;', '9w70: provenance; 9w64: provenance;')
        text += '\nPipeline() source_adapter_marker;\n'
    else:
        for key, old, new in (('T_IN', 180, 197), ('HB_RETURN', 181, 198),
                              ('HELD_RETURN', 182, 199), ('RELAY_PORT', 9, 64)):
            text, count = re.subn(r'(const PortId_t ' + key + r'\s*=\s*)9w' + str(old) + r';',
                                  r'\g<1>9w' + str(new) + ';', text)
            assert count == 1, key
    return '#include <core.p4>\n#include <tna.p4>\n' + text


def write(directory):
    directory = Path(directory)
    text = full_source()  # Validate before creating any output.
    directory.mkdir(parents=True, exist_ok=False)
    (directory / 'response_only.p4').write_text(text)
    metadata = json.loads(BASE.with_suffix('.inputs.json').read_text())
    metadata.update(experiment='combined_nt_01', source_sha256=digest(text.encode()),
                    inputs={name: {'path': str(path), 'sha256': sha}
                            for name, (path, sha) in INPUTS.items()},
                    segment_sha256={name: digest(segment(text, name).encode())
                                    for name in MARKERS})
    (directory / 'response_only.inputs.json').write_text(json.dumps(metadata, indent=2) + '\n')


if __name__ == '__main__':
    write(sys.argv[1])

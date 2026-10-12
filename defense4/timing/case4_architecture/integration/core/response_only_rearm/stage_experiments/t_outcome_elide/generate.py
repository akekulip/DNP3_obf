"""Expose the T outcome-counter elision experiment to source tests."""
import hashlib
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
CANDIDATE = HERE.parents[1]
SOURCE = HERE / 'evidence/full_01/response_only.p4'
SOURCE_SHA256 = 'b5bd2a395baa1ee1299ff6f33a2b2d8b5e2d328a96921e6fe2f0d11454b1ce28'
MARKERS = {'N': '/* Generated isolated N protected reconnect candidate. */',
           'E': '/* Generated isolated E protected reconnect candidate. */',
           'T': '/* Generated isolated T reconnect candidate. */'}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def segment(text, name):
    assert text.count(MARKERS[name]) == 1
    start = text.index(MARKERS[name])
    end = text.index(MARKERS[{'N': 'E', 'E': 'T'}[name]]) if name != 'T' else text.index('\nPipeline(')
    return text[start:end]


def full_source():
    raw = SOURCE.read_bytes()
    assert digest(raw) == SOURCE_SHA256, 'source changed'
    return raw.decode()


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


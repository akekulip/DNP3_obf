"""Shared fragment-evaluator setup for the read_timing.p4 source tests (not a target model)."""
import re
import sys
from pathlib import Path

ARCH = Path(__file__).resolve().parents[3]
READ = ARCH / 'integration/read'
sys.path[:0] = [str(ARCH / 'protocol'), str(ARCH / 'tests')]
from source_control import Source  # noqa: E402  (frozen evaluator with explicit else-if handling)

TEXT = (READ / 'read_timing.p4').read_text()
PORTS = {name: int(value) for name, value in
         re.findall(r'const\s+PortId_t\s+(\w+)\s*=\s*9w(\d+)', (READ / 'ports.p4').read_text())}
MASK = 0xFFFFFFFF


def fragment_text(text):
    """Rewrite P4 text into the dialect the frozen fragment evaluator reads (no semantics change).

    Renames only: struct names, md./ig_intr_md. prefixes, register-action parameters, port constants,
    compact spacing, and `_` wildcards as zero masks.
    """
    text = re.sub(r'/\*.*?\*/|//[^\n]*', '', text, flags=re.S)
    text = text.replace('struct header_t', 'struct headers_t').replace('struct metadata_t', 'struct meta_t')
    text = text.replace('pktgen_timer_header_t timer;', '')
    text = re.sub(r'\bmd\.(?!drop_ctl)', 'm.', text)
    text = text.replace('ig_intr_md.ingress_port', 'm.ingress_port')
    for name, value in PORTS.items():
        text = re.sub(r'\b%s\b' % name, '9w%d' % value, text)
    text = re.sub(r'\bout_value\b', 'rv', text)
    text = re.sub(r'\bvalue\b', 'v', text)
    text = re.sub(r'\s*([{}=:;,()+&|])\s*', r'\1', text)
    text = re.sub(r'(?<![\w&])_(?![\w&])', '0&&&0', text)
    # one-key const rows `{1:act();}` become the evaluator's `(1):act();`
    text = re.sub(r'(?<=[{;])(\w+):(\w+\(\);)', r'(\1):\2', text)
    return text


def source(values=None, runtime=None, registers=None):
    return Source(fragment_text(TEXT), values, runtime=runtime, registers=registers)

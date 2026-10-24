"""Shared paths, the pinned m11_09 base source, and the anchored-edit helpers every transform uses."""
import importlib.util
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent          # m12_fullsize
STAGE = HERE.parent
M11_09 = STAGE / 'ctl_timing_01/evidence/m11_09/response_only.p4'
M11_09_SHA = 'f1de2b30e9f00fb93b20df51c3ddfafd3fcfd18e9b6dfcaadd62146dddbe5af8'
M11_09_PROFILE = STAGE / 'ctl_timing_01/evidence/m11_09/supported_profile.json'
CONSTANTS = STAGE / 'read_complete_01/vectors/constants.json'
CONSTANTS_TWO = STAGE / 'read_complete_01/vectors/constants_two_read.json'
CONSTANTS_TWO_RELAY = STAGE / 'read_complete_01/vectors/constants_two_read_relay.json'
CONSTANTS_SEG = STAGE / 'read_complete_01/vectors/constants_segmented.json'

sys.path.insert(0, str(HERE / 'probe'))
from make_classify_rev_probe import rev_entries  # noqa: E402,F401

_spec = importlib.util.spec_from_file_location('m12_combined', STAGE / 'combined_nt_01/generate.py')
combined = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(combined)


def once(text, old, new):
    n = text.count(old)
    if n != 1:
        raise SystemExit('anchor %r found %d times (need 1)' % (old[:80], n))
    return text.replace(old, new, 1)


def neg(n):
    return '32w0x%08x' % ((0x100000000 - n) & 0xFFFFFFFF)


__all__ = ['HERE', 'STAGE', 'M11_09', 'M11_09_SHA', 'M11_09_PROFILE', 'CONSTANTS', 'CONSTANTS_TWO', 'CONSTANTS_TWO_RELAY', 'CONSTANTS_SEG',
           'rev_entries', 'combined', 'once', 'neg']

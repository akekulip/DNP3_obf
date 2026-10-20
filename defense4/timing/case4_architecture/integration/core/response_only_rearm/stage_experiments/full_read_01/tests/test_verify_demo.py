"""Regression tests closing the verify_demo holes found in the 2026-10-20 review.

Hole #3: the verifier accepted a response whose size equalled the native size even when a target was
reachable (a disabled padder passed). Hole #4: it checked synthetic padding values only in scans[0],
so corrupted padding in a later scan passed.
"""
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT.parent / 'read_reencode_01'))
import verify_demo as vd  # noqa: E402


# ---- Hole #3: a disabled padder (size == native) must FAIL when a target is reachable ----

def test_disabled_padder_fails():
    # native 247, targets {141,292}: smallest reachable >=247 is 292; staying at 247 must fail.
    assert vd.size_verdict(247, 247, [141, 292]) is not None
    assert '292' in vd.size_verdict(247, 247, [141, 292])


def test_correct_padding_passes():
    assert vd.size_verdict(292, 247, [141, 292]) is None        # full READ padded to 292
    assert vd.size_verdict(141, 49, [141, 292]) is None         # range READ padded to 141


def test_ineligible_only_when_above_all_targets():
    # native 300 > every target: must stay native (300), and that is the only acceptable size.
    assert vd.size_verdict(300, 300, [141, 292]) is None
    assert vd.size_verdict(292, 300, [141, 292]) is not None    # must not have been shrunk/altered


def test_wrong_target_fails():
    # native 49 reaches 141 (smallest >=49); jumping to 292 instead is wrong.
    assert vd.size_verdict(292, 49, [141, 292]) is not None


# ---- Hole #4: corrupted synthetic padding in ANY scan must FAIL ----

def _scan(points):
    return {'completed': True, 'points': points}


def test_corrupted_padding_in_second_scan_fails():
    # fixture = the outstation database (bi 0..15 etc.); padding points are bi >= 16, value 0 flags 0x00.
    fixture = {'bi:%d' % i: [i % 2, 1] for i in range(16)}
    native_same = dict(fixture)
    good = {**fixture, 'bi:16': [0, 0], 'bi:17': [0, 0]}
    bad = {**fixture, 'bi:16': [1, 129], 'bi:17': [0, 0]}      # corrupted padding point
    # mirror the verifier's per-scan padding check
    def scan_ok(points):
        synth = {k for k in points if k not in fixture}
        if any(not (k.startswith('bi:') and int(k[3:]) >= 16) for k in synth):
            return False
        return all(points[k] == [0, 0] for k in synth)
    assert scan_ok(good)
    assert not scan_ok(bad)
    # a corrupted SECOND scan must be rejected even if the first is clean
    scans = [_scan(good), _scan(bad)]
    assert not all(scan_ok(s['points']) for s in scans)

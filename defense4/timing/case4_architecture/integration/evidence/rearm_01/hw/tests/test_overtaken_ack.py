"""vision_candidate.overtaken_handshake_acks and candidate_series.read_handshake_build (2026-10-23): on a build whose
N admits a READ that overtakes the final handshake ACK (m12p_c28+), the late pure ACK is dropped by design and is
excused from the wire mapping -- only that frame, only when the overtaking READ itself crossed."""
import glob
import json
from pathlib import Path
import sys

import pytest

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
import candidate_series as cs  # noqa: E402
import vision_candidate as vc  # noqa: E402

BLOCKS = HERE.parents[2] / 'core/response_only_rearm/stage_experiments/read_complete_01/evidence/hw_blocks'
CONFIGS = HERE.parents[2] / 'core/response_only_rearm/stage_experiments/read_complete_01/hw/config'


def trial(block, cn):
    t = glob.glob(str(BLOCKS / block / 'separate_ack/combined/*_t0'))
    if not t:
        pytest.skip('retained capture absent: ' + block)
    t = Path(t[0]) / cn
    return t / 'out.pcap', t / 'in.pcap', json.loads((t / 'wire.json').read_text())['unmatched_sent']


def test_c28_overtaken_final_ack_is_the_only_excused_frame():
    out, inp, unmatched = trial('rc01_hw_c28_20261023_07_held_operate_350', 'c3')
    excused, remaining = vc.overtaken_handshake_acks(out, inp, unmatched)
    assert [e['sent_index'] for e in excused] == [2]
    assert [r['sent_index'] for r in remaining] == [68]          # the held OPERATE stays for its own excusal


def test_a_dropped_read_is_never_excused():
    out, inp, unmatched = trial('rc01_hw_c26_20261023_14_held_operate_350', 'c2')
    excused, remaining = vc.overtaken_handshake_acks(out, inp, unmatched)
    assert excused == [] and [r['sent_index'] for r in remaining] == [4, 69]


def test_a_later_pure_ack_or_an_unknown_index_is_not_excused():
    out, inp, _ = trial('rc01_hw_c28_20261023_07_held_operate_350', 'c3')
    # index 6: a later master pure ACK (not the first after the SYN-ACK); 99999: no such frame
    excused, remaining = vc.overtaken_handshake_acks(out, inp, [{'sent_index': 6}, {'sent_index': 99999}])
    assert excused == [] and len(remaining) == 2


def test_build_detection_reads_the_recorded_transforms():
    c28 = json.loads((CONFIGS / 'rc01_m12p_c28_held_operate_350.json').read_text())
    c26 = json.loads((CONFIGS / 'rc01_m12p_c26_held_operate_350.json').read_text())
    assert cs.read_handshake_build(next(iter(c28['builds'].values()))) is True
    assert cs.read_handshake_build(next(iter(c26['builds'].values()))) is False
    assert cs.read_handshake_build({'manifest': 'no/such/build/compile_switch_9132/manifest.json'}) is False

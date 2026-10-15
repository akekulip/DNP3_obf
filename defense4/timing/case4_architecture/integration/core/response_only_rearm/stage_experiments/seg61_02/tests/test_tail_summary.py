"""tail_summary.py on retained tail runs: the 127/255/~275 signature in a control run and in a tx-frames-irq=64
run, an event-free run counted as such, and each factor record restored."""
import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE / 'analysis'))
import tail_summary as ts  # noqa: E402

RUNS = HERE / 'evidence/hw_campaigns'
NAMES = ('candidate61_tail_ctl_03', 'candidate61_tail_ctl_01', 'candidate61_tail_txirq64_07')
pytestmark = pytest.mark.skipif(not all(any((RUNS / n).glob('separate_ack/off/*_t0/in.pcap')) for n in NAMES),
                                reason='retained tail captures absent')


def test_signature_survives_tx_frames_irq_64(tmp_path):
    out = tmp_path / 'tails.json'
    assert ts.main(['--condition', 'control', str(RUNS / NAMES[0]), str(RUNS / NAMES[1]),
                    '--condition', 'tx-frames-irq=64', str(RUNS / NAMES[2]), '-o', str(out)]) == 0
    d = json.loads(out.read_text())
    assert d['control']['runs'] == 2 and d['control']['runs_with_events'] == 1
    for cond, run in (('control', 0), ('tx-frames-irq=64', 0)):
        row = d[cond]['rows'][run]
        assert row['requests'] == 502 and row['restore_ok'] is True
        assert [p for _leg, p, _us in row['events']] == [127, 255, 275]
        assert all(1000 < us < 1600 for _leg, _p, us in row['events'])
    assert d['control']['rows'][0]['applied']['tx-frames-irq'] == '256'
    assert d['tx-frames-irq=64']['rows'][0]['applied']['tx-frames-irq'] == '64'
    assert d['control']['rows'][1]['events'] == []

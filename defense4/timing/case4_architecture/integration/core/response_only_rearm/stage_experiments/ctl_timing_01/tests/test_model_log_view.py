"""model_log_view.py: the driver's reading of the running model's log (harness fixes, 2026-10-17)."""
import glob
import importlib.util
import sys
import threading
import time
from pathlib import Path

import pytest

CT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CT))
spec = importlib.util.spec_from_file_location('model_log_view', CT / 'model_log_view.py')
view = importlib.util.module_from_spec(spec)
spec.loader.exec_module(view)

LOG = """\
:10-17 12:45:20.857867:    :0xd7d:0xd7c:<0,1,0>:========== Ingress Pkt from port 182 (103 bytes)  ==========
:10-17 12:45:20.857879:    :0xd7d:0xd7c:<0,1,0>:Packet :
:10-17 12:45:20.857888:        :0xd7d:0xd7c:<0,1,0>:0f 00 00 a9 00 08 77 f9 00 11
:10-17 12:45:20.858100:    :0xd7d:0xd7c:<0,1,0>:Execute Action: t_Ingress.release_response_counted
:10-17 12:45:20.900000:    :0xd7e:-:<0,1,0>:========== Ingress Pkt from port 180 (80 bytes)  ==========
:10-17 12:45:20.900010:    :0xd7e:-:<0,1,0>:Packet :
:10-17 12:45:20.900020:        :0xd7e:-:<0,1,0>:0f 00 00 a9 00 08 77 f9 00 22
:10-17 12:45:20.900100:    :0xd7e:-:<0,1,0>:Execute Action: t_Ingress.close_epoch
:10-17 12:45:20.900110:    :0xd7e:-:<0,1,0>:Execute Action: t_Ingress.live_reset_gen
"""


def test_release_then_application_orders_as_pass(tmp_path):
    log = tmp_path / 'model_1.log'
    log.write_text(LOG)
    d = view.connection_order(view.records_since(log, 0), '000877f9', 1, 1)
    assert d['verdict'] == 'PASS' and len(d['released_before']) == 1


def test_reading_from_an_offset_drops_the_partial_line_and_earlier_records(tmp_path):
    log = tmp_path / 'model_1.log'
    log.write_text(LOG)
    offset = LOG.index('Ingress Pkt from port 180') - 10            # inside the line that starts record two
    recs = view.records_since(log, offset)
    assert all('release_response_counted' not in r['actions'] for r in recs)


def test_wait_for_sees_a_line_appended_while_waiting(tmp_path):
    log = tmp_path / 'model_1.log'
    log.write_text(LOG)
    start = log.stat().st_size

    def append():
        time.sleep(0.05)
        with open(log, 'a') as f:
            f.write(':10-17 12:45:21.000000:    :0x1:-:<0,0,0>:Execute Action: n_Ingress.first_close\n')
    threading.Thread(target=append).start()
    line, waited, _end = view.wait_for(log, start, r'n_Ingress\.first_close', timeout=2.0)
    assert line is not None and 0.03 < waited < 1.0
    assert view.wait_for(log, log.stat().st_size, r'never', timeout=0.05)[0] is None


def test_log_path_requires_exactly_one_log(tmp_path):
    assert view.log_path(tmp_path) is None
    (tmp_path / 'model_1.log').write_text('')
    assert view.log_path(tmp_path).name == 'model_1.log'
    (tmp_path / 'model_2.log').write_text('')
    assert view.log_path(tmp_path) is None


EV = CT / 'evidence' / 'model_contention_m10_03_06'


@pytest.mark.skipif(not list(EV.glob('model_*.log')), reason='the model log is over 50 MiB and untracked')
def test_attempt_06_abort_held_read_released_before_t_applied_the_reset():
    """Attempt 06's inconclusive abort: T released the response (36.972) before applying the reset (37.016)."""
    log = Path(glob.glob(str(EV / 'model_*.log'))[0])
    d = view.connection_order(view.records_since(log, 0), '%08x' % 360021, 1, 1)
    assert d['verdict'] == 'PASS' and d['released_before'] == ['20:12:36.972180']


def test_wait_for_returns_the_offset_after_the_match_so_a_second_wait_sees_only_later_lines(tmp_path):
    """Diagnostic 02: the trigger is 'this RST's ingress, then first_close after it'; a first_close logged before the
    ingress must not count."""
    log = tmp_path / 'model_1.log'
    text = ('x Execute Action: n_Ingress.first_close\n'          # stale, from an earlier RST
            'y ========== Ingress Pkt from port 9 (64 bytes) ==========\n'
            'z Execute Action: n_Ingress.first_close_ack\n'
            'w Execute Action: n_Ingress.first_close\n')
    log.write_text(text)
    line, _w, after = view.wait_for(log, 0, r'Ingress Pkt from port 9 ', 0.5)
    assert after == text.index('z ')
    line2, _w2, end = view.wait_for(log, after, r'n_Ingress\.first_close\b', 0.5)
    assert line2.startswith('w ') and end == len(text)


def test_wait_idle_returns_once_the_log_stops_growing(tmp_path):
    log = tmp_path / 'model_1.log'
    log.write_text('a\n')

    def grow():
        for _ in range(5):
            time.sleep(0.01)
            with open(log, 'a') as f:
                f.write('b\n')
    t = threading.Thread(target=grow)
    t.start()
    size, idle = view.wait_idle(log, quiet=0.05, timeout=2.0)
    t.join()
    assert idle and size == log.stat().st_size == 2 + 5 * 2


def test_wait_idle_reports_a_timeout_on_a_busy_log(tmp_path):
    log = tmp_path / 'model_1.log'
    log.write_text('a\n')
    stop = threading.Event()

    def grow():
        while not stop.is_set():
            with open(log, 'a') as f:
                f.write('b\n')
            time.sleep(0.01)
    t = threading.Thread(target=grow)
    t.start()
    _size, idle = view.wait_idle(log, quiet=0.05, timeout=0.3)
    stop.set()
    t.join()
    assert idle is False

"""timeline_wrapper.py: logging is transparent and the packet-path stop rule fires only on a fresh SYN with 0 frames."""
import importlib
import json
import os
import sys
from pathlib import Path

import pytest

CT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CT))


@pytest.fixture
def tw(tmp_path, monkeypatch):
    monkeypatch.setenv('CONTENTION_TIMELINE', str(tmp_path / 'timeline.jsonl'))
    import timeline_wrapper
    mod = importlib.reload(timeline_wrapper)
    md = mod.model_driver
    saved = (md.Model.send, md.Model.capture, md.Report.add)
    calls = {}
    monkeypatch.setattr(md.Model, 'send', lambda self, port, frame: calls.setdefault('sent', []).append((port, frame)))
    monkeypatch.setattr(md.Model, 'capture', lambda self, ports, timeout=1.0, quiet=0.3: {p: [b'x'] for p in ports})
    mod.instrument()
    yield mod, md, calls, tmp_path / 'timeline.jsonl'
    md.Model.send, md.Model.capture, md.Report.add = saved


def events(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_send_capture_and_cases_are_logged_and_pass_through(tw):
    mod, md, calls, log = tw
    m = md.Model.__new__(md.Model)
    m.send(9, b'frame')
    got = m.capture([9, 68], 0.0, 0.0)
    r = md.Report('p')
    r.add('x_request_relayed', True, True)
    assert calls['sent'] == [(9, b'frame')] and got == {9: [b'x'], 68: [b'x']} and r.record['cases'][0]['ok'] is True
    kinds = [e['event'] for e in events(log)]
    assert kinds == ['send_attempt', 'send_result', 'capture_entry', 'capture_exit', 'case']
    assert all('mono' in e and 'wall' in e for e in events(log))
    assert events(log)[3]['frames'] == 2


def test_a_fresh_syn_with_zero_frames_stops_the_sequence(tw, monkeypatch):
    mod, md, calls, log = tw
    monkeypatch.setattr(mod, 'sample', lambda: {'stub': True})
    monkeypatch.setattr(mod, 'model_log_size', lambda: 100)                   # the model logs nothing more
    md.Model.__new__(md.Model).send(9, b'syn')
    r = md.Report('p')
    r.add('dup_SELECT_final_ACK', 'one exact frame', '0 frames', ok=False)      # not a SYN: no stop
    with pytest.raises(mod.PacketPathStop):
        r.add('second_connection_READ_SYN', 'one exact frame', '0 frames', ok=False)
    stop = [e for e in events(log) if e['event'] == 'packet_path_stop']
    assert len(stop) == 1 and stop[0]['case'] == 'second_connection_READ_SYN'
    assert r.record['cases'][-1]['name'] == 'second_connection_READ_SYN'    # the case itself is still recorded


def test_the_stop_is_an_exception_so_the_driver_still_writes_results(tw):
    mod = tw[0]
    assert issubclass(mod.PacketPathStop, Exception)


def test_the_driver_timeline_hook_is_a_no_op_when_unset(tmp_path, monkeypatch):
    monkeypatch.delenv('CONTENTION_TIMELINE', raising=False)
    text = (CT / 'model_contention.py').read_text()
    assert "_TIMELINE = os.environ.get('CONTENTION_TIMELINE')" in text and 'if _TIMELINE:' in text


def test_a_zero_frame_syn_with_model_activity_does_not_stop(tw, monkeypatch):
    """Code review: N refusing a same-tuple SYN still appears in the model log; only a silent model stops the run."""
    mod, md, calls, log = tw
    sizes = iter([100, 200])                          # at the send, then at the case: the log grew
    monkeypatch.setattr(mod, 'model_log_size', lambda: next(sizes))
    m = md.Model.__new__(md.Model)
    m.send(9, b'syn')
    r = md.Report('p')
    r.add('second_connection_READ_SYN', 'one exact frame', '0 frames', ok=False)        # no exception
    rec = [e for e in events(log) if e['event'] == 'syn_zero_frames']
    assert rec and rec[0]['model_log_grew'] is True


def test_a_zero_frame_syn_with_a_silent_model_stops(tw, monkeypatch):
    mod, md, calls, log = tw
    monkeypatch.setattr(mod, 'model_log_size', lambda: 100)
    monkeypatch.setattr(mod, 'sample', lambda: {'stub': True})
    m = md.Model.__new__(md.Model)
    m.send(9, b'syn')
    with pytest.raises(mod.PacketPathStop):
        md.Report('p').add('x_SYN', 'one exact frame', '0 frames', ok=False)


def test_an_early_zero_frame_capture_is_labelled_not_quiet(tw, monkeypatch):
    mod, md, calls, log = tw
    m = md.Model.__new__(md.Model)
    monkeypatch.setattr(md.Model, 'capture', lambda self, ports, timeout=1.0, quiet=0.3: {p: [] for p in ports})
    mod.instrument()
    m.capture([9], 5.0, 0.15)
    exits = [e for e in events(log) if e['event'] == 'capture_exit']
    assert exits[-1]['reason'] == 'early_exit_no_frames' and 'elapsed_wall' in exits[-1]

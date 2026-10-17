"""Run model_contention.py unchanged in behaviour, with a diagnostic timeline and a packet-path stop rule.

  run_model.py BUILD contention N --milestone m10 --timeline     (one instrumented attempt; Philip, 2026-10-17)

Records, to $OUT/timeline.jsonl (monotonic and wall time on every line):
- every case boundary (Report.add: name, ok, observed, abbreviated);
- every model_driver send (port, length, before/after, any exception);
- every model_driver capture (entry; exit with reason 'quiet' or 'timeout' and the received-frame count). The
  driver's own capture() records the same through model_contention.timeline.
It also samples once a second, in the launcher's namespace, the veths (with RX/TX packet counts of the master-port
pair) and whether tofino-model and bf_switchd are alive ($OUT/health.jsonl, health_wrapper.sample).

Packet contents, test order, timeouts and acceptance are unchanged.

The stop rule: a fresh-connection SYN that gets 0 frames back while the model logged nothing since it was sent means
the packet path itself failed (a SYN the dataplane refuses still appears in the model log). Every 0-frame SYN is
recorded with whether the model log grew. On a stop the wrapper records the diagnostic state (interface counters, process list, a
health sample) and raises PacketPathStop. The driver records it as its 'exception' case, writes its results and
stops, instead of producing another cascade of uninformative failures.
"""
import json
import os
import runpy
import subprocess
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[2]))          # integration/core: model_driver, as the drivers import it
sys.path.insert(0, str(HERE))
import health_wrapper  # noqa: E402
import model_driver  # noqa: E402

TIMELINE = os.environ['CONTENTION_TIMELINE']
MASTER_VETHS = ('veth18', 'veth19')                # dev port 9 = veth18, its test-side peer veth19 (launch_model.sh)


class PacketPathStop(Exception):
    """The packet path failed (a fresh SYN got nothing back); the remaining sequence is not run."""


def write(event, **fields):
    with open(TIMELINE, 'a') as out:
        out.write(json.dumps(dict(fields, event=event, mono=time.monotonic(), wall=time.time()), default=str) + '\n')


def parse_counters(text):
    """RX/TX packet counts from `ip -s link show` output, located by the label row ('RX: bytes packets ...'), so the
    iproute column set does not matter."""
    tokens, out = text.split(), {}
    for key in ('RX:', 'TX:'):
        i = tokens.index(key) + 1
        labels = []
        while i < len(tokens) and not tokens[i].isdigit():
            labels.append(tokens[i])
            i += 1
        out[key[:2].lower() + '_packets'] = int(tokens[i + labels.index('packets')])
    return out


def veth_counters():
    out = {}
    for name in MASTER_VETHS:
        text = subprocess.run(['ip', '-s', 'link', 'show', name], capture_output=True, text=True).stdout
        try:
            out[name] = parse_counters(text)
        except (ValueError, IndexError):
            out[name] = 'unreadable'
    return out


def sample():
    return dict(health_wrapper.sample(), mono=time.monotonic(), counters=veth_counters())


def model_log_size():
    """Size of the run's model log ($OUT/model_*.log), or None. A refused SYN still appears in the model log; during
    the attempt-04 stall the model logged nothing at all (code review), so growth separates the two."""
    logs = sorted(Path(os.environ.get('OUT', '.')).glob('model_*.log'))
    return logs[-1].stat().st_size if logs else None


def monitor(stop):
    with open(os.environ['HEALTH_LOG'], 'a') as log:
        while not stop.is_set():
            try:
                log.write(json.dumps(sample()) + '\n')
            except Exception as e:
                log.write(json.dumps(dict(t=round(time.time(), 3), sample_error=repr(e))) + '\n')
            log.flush()
            stop.wait(1.0)


def instrument():
    send, capture, add = model_driver.Model.send, model_driver.Model.capture, model_driver.Report.add
    last_send = {}

    def send_logged(self, port, frame):
        last_send['log_size'] = model_log_size()
        write('send_attempt', port=port, length=len(frame), model_log_size=last_send['log_size'])
        try:
            send(self, port, frame)
        except Exception as e:
            write('send_result', port=port, ok=False, error=repr(e))
            raise
        write('send_result', port=port, ok=True)

    def capture_logged(self, ports, timeout=1.0, quiet=0.3):
        write('capture_entry', ports=list(ports), timeout=timeout, quiet=quiet)
        mono0, wall0 = time.monotonic(), time.time()
        got = capture(self, ports, timeout, quiet)
        n = sum(len(v) for v in got.values())
        el_m, el_w = time.monotonic() - mono0, time.time() - wall0
        # model_driver.capture bounds its loop by wall time: both elapsed times are kept, and a 0-frame return before
        # the timeout (impossible for a correct capture) is labelled as such, never 'quiet' (code review)
        write('capture_exit', frames=n, elapsed_mono=el_m, elapsed_wall=el_w,
              reason='timeout' if el_m >= timeout else ('quiet' if n else 'early_exit_no_frames'))
        return got

    def add_logged(self, name, expected, observed, ok=None, **fields):
        result = add(self, name, expected, observed, ok, **fields)
        row = self.record['cases'][-1]
        write('case', name=name, ok=row.get('ok'), observed=str(observed)[:80])
        if name.endswith('_SYN') and str(observed) == '0 frames':
            size = model_log_size()
            grew = None if size is None or last_send.get('log_size') is None else size > last_send['log_size']
            write('syn_zero_frames', case=name, model_log_grew=grew)
            if grew is not False:
                return result         # the model processed something (e.g. N refusing a same-tuple SYN): no stop
            state = dict(health=sample(), ip_link=subprocess.run(['ip', '-s', 'link'], capture_output=True,
                                                                 text=True).stdout[-6000:],
                         processes=subprocess.run(['ps', '-eo', 'pid,stat,etime,cmd'], capture_output=True,
                                                  text=True).stdout[-4000:])
            write('packet_path_stop', case=name, state=state)
            raise PacketPathStop('a fresh SYN got 0 frames at %s and the model logged nothing since it was sent; '
                                 'the remaining sequence is not run' % name)
        return result

    model_driver.Model.send, model_driver.Model.capture = send_logged, capture_logged
    model_driver.Report.add = add_logged


def main():
    target = Path(os.environ['TIMELINE_TARGET']).resolve()
    instrument()
    stop = threading.Event()
    threading.Thread(target=monitor, args=(stop,), daemon=True).start()
    write('run_start', target=str(target))
    sys.argv = [str(target)] + sys.argv[1:]
    sys.path[0] = str(target.parent)
    try:
        runpy.run_path(str(target), run_name='__main__')
    finally:
        write('run_end')
        stop.set()


if __name__ == '__main__':
    main()

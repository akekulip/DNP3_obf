"""
Bounded physical-SEL-751 CLRT experiment: 300 sequential Class-0 READs over ONE persistent TCP
session, one outstanding request at a time, 1 s idle after each completed response.

Safety: NO auto-retry / NO auto-reconnect (ChannelRetry min=max=3600 s => a drop cannot reconnect
within the run), NO controls/writes/time-sync/unsolicited (every automatic stack behaviour pinned
off; ignoreRestartIIN=True). READ-only. The experiment HARD-STOPS (no reconnect, no retry) on any:
task failure, response timeout, IIN request-error, or channel close.

Per-poll app-side metadata is written to a JSONL file; the pcap (captured separately) is the
authoritative source for wire timing (separate ACK, CLRT) and is merged in analysis by poll order.
"""
import os
import sys
import json
import time
import threading

HARN = "/home/decps/Projects/DNP3/dnp3_split_harness"
sys.path.insert(0, HARN)
from pydnp3 import opendnp3, openpal, asiopal, asiodnp3  # noqa: E402
import run_master as rm  # noqa: E402  (reuse the proven SOE visitor dispatch)

HOST = "192.168.10.7"
LOCAL = "192.168.10.1"           # relay-allowlisted master (DNPIP1)
PORT = 20000
MASTER_ADDR = 1
OUT_ADDR = 0
N_POLLS = 300
INTER_POLL_SLEEP = 1.0           # seconds AFTER each completed response
RESP_TIMEOUT_SEC = 5             # DNP3 application response timeout (bounded)
TASK_WAIT_SEC = 10               # hard ceiling waiting for OnTaskComplete
OUT_JSONL = "/tmp/clrt_app_metadata.jsonl"

FILTERS = opendnp3.levels.NORMAL  # keep the console log small; the pcap is the wire truth


def stamp(m):
    print("[%s] %s" % (time.strftime("%H:%M:%S"), m), flush=True)


class State:
    def __init__(self):
        self.task_done = threading.Event()
        self.task_result = None
        self.channel_closed = False
        self.last_iin = None
        self.iin_reqerr = False
        self.poll_points = 0


state = State()


class CountSOE(opendnp3.ISOEHandler):
    """Counts decoded measurement points for the current response (Start->Process*->End)."""
    def Start(self):
        state.poll_points = 0

    def Process(self, info, values):
        vc = rm._VISITOR_CLASS_TYPES.get(type(values))
        if vc is not None:
            v = vc()
            values.Foreach(v)
            state.poll_points += len(v.index_and_value)

    def End(self):
        pass


class App(opendnp3.IMasterApplication):
    def AssignClassDuringStartup(self):
        return False

    def OnClose(self):
        state.channel_closed = True

    def OnOpen(self):
        pass

    def OnReceiveIIN(self, iin):
        state.last_iin = (int(iin.LSB), int(iin.MSB))
        if iin.HasRequestError():
            state.iin_reqerr = True

    def OnTaskComplete(self, info):
        if info.type == opendnp3.MasterTaskType.USER_TASK:
            state.task_result = info.result
            state.task_done.set()

    def OnTaskStart(self, task_type, task_id):
        pass


def main():
    stamp("CLRT EXPERIMENT START  %s -> %s:%s  master=%s out=%s  N=%d  idle=%.1fs"
          % (LOCAL, HOST, PORT, MASTER_ADDR, OUT_ADDR, N_POLLS, INTER_POLL_SLEEP))

    manager = asiodnp3.DNP3Manager(1, asiodnp3.ConsoleLogger().Create())
    # NO-RECONNECT: min=max=1 hour, so a close cannot trigger reconnection within the run.
    retry = asiopal.ChannelRetry(openpal.TimeDuration().Seconds(3600),
                                 openpal.TimeDuration().Seconds(3600))
    listener = asiodnp3.PrintingChannelListener().Create()
    channel = manager.AddTCPClient("tcp", FILTERS, retry, HOST, LOCAL, PORT, listener)

    stack = asiodnp3.MasterStackConfig()
    stack.master.responseTimeout = openpal.TimeDuration().Seconds(RESP_TIMEOUT_SEC)
    stack.master.startupIntegrityClassMask = opendnp3.ClassField()   # no startup poll
    stack.master.unsolClassMask = opendnp3.ClassField()              # no ENABLE_UNSOLICITED
    stack.master.disableUnsolOnStartup = False                       # no DISABLE_UNSOLICITED
    stack.master.ignoreRestartIIN = True                             # no restart-IIN WRITE
    stack.master.timeSyncMode = getattr(opendnp3.TimeSyncMode, "None")  # no time-sync WRITE
    stack.link.LocalAddr = MASTER_ADDR
    stack.link.RemoteAddr = OUT_ADDR

    soe = CountSOE()
    app = App()
    master = channel.AddMaster("m", soe, app, stack)

    fout = open(OUT_JSONL, "w")
    stamp("ENABLE (single persistent TCP session)")
    master.Enable()
    time.sleep(3)  # settle TCP + link before the first request

    completed = 0
    stop_reason = None
    for poll in range(1, N_POLLS + 1):
        if state.channel_closed:
            stop_reason = "channel_closed_before_poll_%d" % poll
            break
        state.task_done.clear()
        state.task_result = None
        state.poll_points = 0
        state.last_iin = None
        state.iin_reqerr = False

        t_issue = time.time()
        master.ScanClasses(opendnp3.ClassField(opendnp3.ClassField.CLASS_0),
                           opendnp3.TaskConfig().Default())
        got = state.task_done.wait(timeout=TASK_WAIT_SEC)
        t_done = time.time()

        result = state.task_result.name if state.task_result is not None else "NO_COMPLETION"
        rec = dict(poll_number=poll, t_issue=t_issue, t_done=t_done, completion=result,
                   decoded_point_count=state.poll_points,
                   iin_lsb=(state.last_iin[0] if state.last_iin else None),
                   iin_msb=(state.last_iin[1] if state.last_iin else None),
                   iin_request_error=bool(state.iin_reqerr),
                   channel_closed=bool(state.channel_closed), error=None)

        # ---- hard stop conditions (no retry, no reconnect) ----
        if not got:
            rec["error"] = "task_wait_timeout"
            fout.write(json.dumps(rec) + "\n"); fout.flush()
            stop_reason = "task_wait_timeout_poll_%d" % poll
            break
        if state.task_result != opendnp3.TaskCompletion.SUCCESS:
            rec["error"] = "completion_" + result
            fout.write(json.dumps(rec) + "\n"); fout.flush()
            stop_reason = "completion_%s_poll_%d" % (result, poll)
            break
        if state.iin_reqerr:
            rec["error"] = "iin_request_error"
            fout.write(json.dumps(rec) + "\n"); fout.flush()
            stop_reason = "iin_request_error_poll_%d" % poll
            break
        if state.channel_closed:
            rec["error"] = "channel_closed"
            fout.write(json.dumps(rec) + "\n"); fout.flush()
            stop_reason = "channel_closed_poll_%d" % poll
            break

        fout.write(json.dumps(rec) + "\n"); fout.flush()
        completed += 1
        if poll < N_POLLS:
            time.sleep(INTER_POLL_SLEEP)

    fout.close()
    stamp("DONE  completed=%d/%d  stop_reason=%s" % (completed, N_POLLS, stop_reason))
    print("SUMMARY " + json.dumps(dict(completed=completed, requested=N_POLLS,
          stop_reason=stop_reason, channel_closed=bool(state.channel_closed))), flush=True)

    try:
        del master
        del channel
        manager.Shutdown()
    except Exception as exc:  # pragma: no cover
        stamp("shutdown warning: %r" % exc)
    sys.stdout.flush(); sys.stderr.flush()
    os._exit(0)


if __name__ == "__main__":
    main()

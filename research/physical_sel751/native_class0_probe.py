"""
Tightly-controlled native Class-0 integrity poll to the physical SEL-751.
ONE TCP session, ONE Class-0 READ, no controls/writes/time-sync/unsolicited.
Every safety-relevant stack parameter is pinned explicitly (defaults are unsafe:
disableUnsolOnStartup=True and ignoreRestartIIN=False would emit DISABLE_UNSOLICITED
and a restart-IIN clearing WRITE). Reuses the proven SOE handler + application from
run_master.py. Prints timestamped milestones; ALL_COMMS log gives raw frame bytes.
"""
import os
import sys
import time

HARN = "/home/decps/Projects/DNP3/dnp3_split_harness"
sys.path.insert(0, HARN)  # import the proven run_master classes + lab_config

from pydnp3 import opendnp3, openpal, asiopal, asiodnp3  # noqa: E402
import run_master as rm  # noqa: E402

HOST = "192.168.10.7"
LOCAL = "192.168.10.1"          # relay's configured DNP3 master (DNPIP1); was .100 (rejected)
PORT = 20000
MASTER_ADDR = 1
OUT_ADDR = 0                    # relay's DNP3 outstation address (per QuickSet); was 10 (from old pcap)
RESP_TIMEOUT_SEC = 5

FILTERS = opendnp3.levels.NORMAL | opendnp3.levels.ALL_COMMS


def stamp(msg):
    print("[%s] %s" % (time.strftime("%H:%M:%S"), msg), flush=True)


def main():
    stamp("PROBE START  host=%s local=%s port=%s master=%s outstation=%s"
          % (HOST, LOCAL, PORT, MASTER_ADDR, OUT_ADDR))

    manager = asiodnp3.DNP3Manager(1, asiodnp3.ConsoleLogger().Create())
    # NO-RETRY: initial connect happens immediately; on any close the next attempt is 1 hour out,
    # so a relay-side drop cannot trigger reconnection within the capture window (one TCP session).
    retry = asiopal.ChannelRetry(openpal.TimeDuration().Seconds(3600),
                                 openpal.TimeDuration().Seconds(3600))
    listener = asiodnp3.PrintingChannelListener().Create()
    channel = manager.AddTCPClient("tcpclient", FILTERS, retry, HOST, LOCAL, PORT, listener)

    stack = asiodnp3.MasterStackConfig()
    stack.master.responseTimeout = openpal.TimeDuration().Seconds(RESP_TIMEOUT_SEC)
    # --- pin every automatic behaviour OFF (defaults are not safe for this test) ---
    stack.master.startupIntegrityClassMask = opendnp3.ClassField()          # no startup integrity poll
    stack.master.unsolClassMask = opendnp3.ClassField()                     # no ENABLE_UNSOLICITED (0x14)
    stack.master.disableUnsolOnStartup = False                              # no DISABLE_UNSOLICITED
    stack.master.ignoreRestartIIN = True                                    # no WRITE to clear restart IIN
    stack.master.timeSyncMode = getattr(opendnp3.TimeSyncMode, "None")      # no time-sync WRITE
    stack.link.LocalAddr = MASTER_ADDR
    stack.link.RemoteAddr = OUT_ADDR

    soe = rm.CSVSOEHandler("/tmp/native_class0_v2_soe.csv")
    app = rm.ExperimentMasterApplication()
    master = channel.AddMaster("master", soe, app, stack)
    master.SetLogFilters(openpal.LogFilters(opendnp3.levels.ALL_COMMS))
    channel.SetLogFilters(openpal.LogFilters(opendnp3.levels.ALL_COMMS))

    stamp("ENABLE (opens the single TCP session)")
    master.Enable()
    time.sleep(3)  # let TCP + link layer settle before the one request

    stamp("SEND one Class-0 integrity READ")
    master.ScanClasses(opendnp3.ClassField(opendnp3.ClassField.CLASS_0),
                       opendnp3.TaskConfig().Default())
    time.sleep(5)  # bounded wait for pure-ACK + response (+ app-confirm iff CON set)

    stamp("DECODED points = %d" % len(soe.received))
    stamp("SHUTDOWN")
    try:
        del master
        del channel
        manager.Shutdown()
    except Exception as exc:  # pragma: no cover
        stamp("shutdown warning: %r" % exc)
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(0)  # avoid pydnp3 double-free at interpreter teardown


if __name__ == "__main__":
    main()

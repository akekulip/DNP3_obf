
import argparse
import csv
import json
import logging
import os
import re
import sys
import threading
import time

from collections import OrderedDict, defaultdict
from datetime import datetime

from pydnp3 import opendnp3, openpal, asiopal, asiodnp3

HARNESS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HARNESS_DIR)  # so 'lab_config' imports regardless of cwd

import lab_config as cfg

# Single source of truth: every lab setting comes from lab_config.py.
OUTSTATION_IP = cfg.OUTSTATION_IP        # master connects here (split server uses the same addr)
BIND_IP = cfg.BIND_IP                    # local interface to bind the client socket
DNP3_PORT = cfg.DNP3_PORT
MASTER_LINK_ADDR = cfg.MASTER_LINK_ADDR
OUTSTATION_LINK_ADDR = cfg.OUTSTATION_LINK_ADDR
DEFAULT_RESPONSE_TIMEOUT_SEC = cfg.DEFAULT_RESPONSE_TIMEOUT_SEC
DEFAULT_WAIT_AFTER_ACTION_SEC = cfg.DEFAULT_WAIT_AFTER_ACTION_SEC
LOG_DIR = cfg.LOG_DIR

# Keep the same log-filter level the original master used.
FILTERS = opendnp3.levels.NORMAL | opendnp3.levels.ALL_COMMS

stdout_stream = logging.StreamHandler(sys.stdout)
stdout_stream.setFormatter(logging.Formatter('%(asctime)s\t%(name)s\t%(levelname)s\t%(message)s'))

_log = logging.getLogger(__name__)
_log.addHandler(stdout_stream)
_log.setLevel(logging.DEBUG)

# Message logged before every control/restart helper. Controls are NOT part of
# baseline READ/RESPONSE experiments and must only be used deliberately.
UNSAFE_CONTROL_WARNING = (
    'This control command is unsafe for baseline experiments and should not be '
    'used unless explicitly required.'
)

# READ/RESPONSE-only actions. Control commands (DirectOperate/SelectAndOperate)
# are intentionally NOT exposed by this CLI for baseline experiments.
SAFE_ACTIONS = [
    'connect-only',
    'scan-class0',
    'scan-all-classes',
    'scan-range',
    'scan-all-objects',
    'disable-unsolicited',
]

CSV_COLUMNS = ['timestamp', 'header_index', 'group_variation', 'data_type', 'index', 'value']

# The multi-CROB Select-Before-Operate control-test action (software-only). Kept
# separate from SAFE_ACTIONS because it issues SELECT/OPERATE controls, not READs.
# A CROB (Control Relay Output Block) is DNP3 Group 12 Variation 1: an output
# point index plus a control code (LATCH_ON / LATCH_OFF).
MULTI_CROB_ACTION = 'multi-crob-sbo'

# Staged control tests (see docs/multi_crob_validation.md). Each is run against a
# freshly (re)started `--control-test` outstation (initial state index 0=False,
# index 1=True), so each test's expected end-state is deterministic. CROBs are
# (index, control_code_name); the name resolves to opendnp3.ControlCode at send
# time. Test C is the headline: ONE command set carrying two CROBs.
CROB_TESTS = {
    'A': {
        'label': 'Test A: single-CROB baseline (index 0 LATCH_ON)',
        'crobs': [(0, 'LATCH_ON')],
        'expected_states': {0: True},
        'summary_file': 'multi_crob_test_a_summary.txt',
    },
    'B': {
        'label': 'Test B: single-CROB baseline (index 1 LATCH_OFF)',
        'crobs': [(1, 'LATCH_OFF')],
        'expected_states': {1: False},
        'summary_file': 'multi_crob_test_b_summary.txt',
    },
    'C': {
        'label': 'Test C: multi-CROB command set (index 0 LATCH_ON, index 1 LATCH_OFF)',
        'crobs': [(0, 'LATCH_ON'), (1, 'LATCH_OFF')],
        'expected_states': {0: True, 1: False},
        'summary_file': 'multi_crob_sbo_summary.txt',
    },
}

# Optional negative test (Test D), only via --control-test-negative: one valid
# CROB plus one unsupported index. Its outcome (partial vs whole-command) is
# recorded exactly as observed, never assumed.
CROB_NEGATIVE_TEST = {
    'label': 'Test D: negative (index 0 LATCH_ON + unsupported index 99 LATCH_ON)',
    'crobs': [(0, 'LATCH_ON'), (99, 'LATCH_ON')],
    'expected_states': {0: True},
    'summary_file': 'multi_crob_negative_summary.txt',
    'negative': True,
}


def _noop_command_callback(result=None):
    """Command-result callback used on older pydnp3 builds (Python < 3.12).

    Deliberately ignores the ICommandTaskResult -- the multi-CROB result is
    captured task-level via the master OnTaskComplete callback instead. Reading
    the non-copyable result here aborts on the rig's newer pybind11, but this
    callback is only selected on the older build where a plain Python callable is
    handled cleanly.
    """
    return None


# ------------------------------------------------------------------ #
# SOE value visitors (one per DNP3 measurement type)
# ------------------------------------------------------------------ #

class VisitorIndexedBinary(opendnp3.IVisitorIndexedBinary):
    def __init__(self):
        super(VisitorIndexedBinary, self).__init__()
        self.index_and_value = []

    def OnValue(self, indexed_instance):
        self.index_and_value.append((indexed_instance.index, indexed_instance.value.value))


class VisitorIndexedDoubleBitBinary(opendnp3.IVisitorIndexedDoubleBitBinary):
    def __init__(self):
        super(VisitorIndexedDoubleBitBinary, self).__init__()
        self.index_and_value = []

    def OnValue(self, indexed_instance):
        self.index_and_value.append((indexed_instance.index, indexed_instance.value.value))


class VisitorIndexedCounter(opendnp3.IVisitorIndexedCounter):
    def __init__(self):
        super(VisitorIndexedCounter, self).__init__()
        self.index_and_value = []

    def OnValue(self, indexed_instance):
        self.index_and_value.append((indexed_instance.index, indexed_instance.value.value))


class VisitorIndexedFrozenCounter(opendnp3.IVisitorIndexedFrozenCounter):
    def __init__(self):
        super(VisitorIndexedFrozenCounter, self).__init__()
        self.index_and_value = []

    def OnValue(self, indexed_instance):
        self.index_and_value.append((indexed_instance.index, indexed_instance.value.value))


class VisitorIndexedAnalog(opendnp3.IVisitorIndexedAnalog):
    def __init__(self):
        super(VisitorIndexedAnalog, self).__init__()
        self.index_and_value = []

    def OnValue(self, indexed_instance):
        self.index_and_value.append((indexed_instance.index, indexed_instance.value.value))


class VisitorIndexedBinaryOutputStatus(opendnp3.IVisitorIndexedBinaryOutputStatus):
    def __init__(self):
        super(VisitorIndexedBinaryOutputStatus, self).__init__()
        self.index_and_value = []

    def OnValue(self, indexed_instance):
        self.index_and_value.append((indexed_instance.index, indexed_instance.value.value))


class VisitorIndexedAnalogOutputStatus(opendnp3.IVisitorIndexedAnalogOutputStatus):
    def __init__(self):
        super(VisitorIndexedAnalogOutputStatus, self).__init__()
        self.index_and_value = []

    def OnValue(self, indexed_instance):
        self.index_and_value.append((indexed_instance.index, indexed_instance.value.value))


class VisitorIndexedTimeAndInterval(opendnp3.IVisitorIndexedTimeAndInterval):
    def __init__(self):
        super(VisitorIndexedTimeAndInterval, self).__init__()
        self.index_and_value = []

    def OnValue(self, indexed_instance):
        # The TimeAndInterval class is a special case, because it doesn't have a "value" per se.
        ti_instance = indexed_instance.value
        ti_dnptime = ti_instance.time
        ti_interval = ti_instance.interval
        self.index_and_value.append((indexed_instance.index, (ti_dnptime.value, ti_interval)))


# Shared visitor dispatch table used by both SOE handlers below.
_VISITOR_CLASS_TYPES = {
    opendnp3.ICollectionIndexedBinary: VisitorIndexedBinary,
    opendnp3.ICollectionIndexedDoubleBitBinary: VisitorIndexedDoubleBitBinary,
    opendnp3.ICollectionIndexedCounter: VisitorIndexedCounter,
    opendnp3.ICollectionIndexedFrozenCounter: VisitorIndexedFrozenCounter,
    opendnp3.ICollectionIndexedAnalog: VisitorIndexedAnalog,
    opendnp3.ICollectionIndexedBinaryOutputStatus: VisitorIndexedBinaryOutputStatus,
    opendnp3.ICollectionIndexedAnalogOutputStatus: VisitorIndexedAnalogOutputStatus,
    opendnp3.ICollectionIndexedTimeAndInterval: VisitorIndexedTimeAndInterval,
}


# ------------------------------------------------------------------ #
# Reusable DNP3 master
# ------------------------------------------------------------------ #

class ExperimentMaster:

    def __init__(self,
                 host='127.0.0.1',
                 local='0.0.0.0',
                 port=20000,
                 master_addr=1,
                 outstation_addr=10,
                 response_timeout_sec=2,
                 log_handler=None,
                 listener=None,
                 soe_handler=None,
                 master_application=None,
                 enable_periodic_scans=False,
                 fast_scan_sec=60,
                 slow_scan_sec=1800):
       
        self.host = host
        self.local = local
        self.port = port
        self.master_addr = master_addr
        self.outstation_addr = outstation_addr
        self.enable_periodic_scans = enable_periodic_scans
        self.slow_scan = None
        self.fast_scan = None

        _log.debug('Creating a DNP3Manager.')
        self.log_handler = log_handler or asiodnp3.ConsoleLogger().Create()
        self.manager = asiodnp3.DNP3Manager(1, self.log_handler)

        _log.debug('Creating the DNP3 channel, a TCP client to %s:%s (local %s).',
                   self.host, self.port, self.local)
        self.retry = asiopal.ChannelRetry().Default()
        self.listener = listener or asiodnp3.PrintingChannelListener().Create()
        self.channel = self.manager.AddTCPClient("tcpclient",
                                                 FILTERS,
                                                 self.retry,
                                                 self.host,
                                                 self.local,
                                                 self.port,
                                                 self.listener)

        _log.debug('Configuring the DNP3 stack (master_addr=%s, outstation_addr=%s, '
                   'response_timeout=%ss).', master_addr, outstation_addr, response_timeout_sec)
        self.stack_config = asiodnp3.MasterStackConfig()
        self.stack_config.master.responseTimeout = openpal.TimeDuration().Seconds(response_timeout_sec)
        # Suppress OpenDNP3's automatic startup traffic (integrity poll +
        # disable-unsolicited) so captures contain only the scans we issue.
        self.stack_config.master.startupIntegrityClassMask = opendnp3.ClassField()
        self.stack_config.master.disableUnsolOnStartup = False
        # Local address = this master; Remote address = the outstation.
        self.stack_config.link.LocalAddr = master_addr
        self.stack_config.link.RemoteAddr = outstation_addr

        _log.debug('Adding the master to the channel (using the supplied SOE handler).')
        self.soe_handler = soe_handler or DebugSOEHandler()
        self.master_application = master_application or ExperimentMasterApplication()
        # IMPORTANT: pass self.soe_handler here. The original master.py passed a
        # fresh PrintingSOEHandler and silently ignored the caller's handler.
        self.master = self.channel.AddMaster("master",
                                             self.soe_handler,
                                             self.master_application,
                                             self.stack_config)

        if self.enable_periodic_scans:
            _log.debug('Configuring periodic scans (slow=%ss all-classes, fast=%ss class-1).',
                       slow_scan_sec, fast_scan_sec)
            self.slow_scan = self.master.AddClassScan(opendnp3.ClassField().AllClasses(),
                                                      openpal.TimeDuration().Seconds(slow_scan_sec),
                                                      opendnp3.TaskConfig().Default())
            self.fast_scan = self.master.AddClassScan(opendnp3.ClassField(opendnp3.ClassField.CLASS_1),
                                                      openpal.TimeDuration().Seconds(fast_scan_sec),
                                                      opendnp3.TaskConfig().Default())
        else:
            _log.debug('Periodic scans disabled (clean READ/RESPONSE mode).')

        self.channel.SetLogFilters(openpal.LogFilters(opendnp3.levels.ALL_COMMS))
        self.master.SetLogFilters(openpal.LogFilters(opendnp3.levels.ALL_COMMS))

        _log.debug('Enabling the master. Traffic will start to flow between Master and Outstation.')
        self.master.Enable()
        # Allow the TCP connection / link layer to come up before issuing reads.
        time.sleep(2)

    # ------------------------------------------------------------------ #
    # READ / RESPONSE actions (safe for baseline experiments)
    # ------------------------------------------------------------------ #

    def scan_class0(self):
        """Perform a one-shot Class 0 integrity poll (all static data)."""
        _log.info('Scanning Class 0 (static data integrity poll).')
        self.master.ScanClasses(opendnp3.ClassField(opendnp3.ClassField.CLASS_0),
                                opendnp3.TaskConfig().Default())

    def scan_all_classes(self):
        """Perform a one-shot all-classes integrity poll (events + static)."""
        _log.info('Scanning all classes (events + static).')
        self.master.ScanClasses(opendnp3.ClassField().AllClasses(),
                                opendnp3.TaskConfig().Default())

    def scan_range(self, group, variation, start, stop):
    
        _log.info('Scanning range g%sv%s indexes %s..%s.', group, variation, start, stop)
        self.master.ScanRange(opendnp3.GroupVariationID(group, variation),
                              start, stop, opendnp3.TaskConfig().Default())

    def scan_all_objects(self, group, variation):
        """
            Read all objects of a given group/variation (no index bounds).

        :param group: DNP3 object group.
        :param variation: object variation within the group.
        """
        _log.info('Scanning all objects g%sv%s.', group, variation)
        self.master.ScanAllObjects(opendnp3.GroupVariationID(group, variation),
                                   opendnp3.TaskConfig().Default())

    def disable_unsolicited(self):
        """
            Send DISABLE_UNSOLICITED for classes 1/2/3.

            Useful to silence an outstation that was started with unsolicited
            responses enabled, so subsequent captures stay clean.
        """
        _log.info('Sending DISABLE_UNSOLICITED for classes 1/2/3.')
        headers = [opendnp3.Header().AllObjects(60, 2),
                   opendnp3.Header().AllObjects(60, 3),
                   opendnp3.Header().AllObjects(60, 4)]
        self.master.PerformFunction("disable unsolicited",
                                    opendnp3.FunctionCode.DISABLE_UNSOLICITED,
                                    headers,
                                    opendnp3.TaskConfig().Default())

    # ------------------------------------------------------------------ #
    # Control commands (UNSAFE for baseline; preserved for compatibility)
    # ------------------------------------------------------------------ #

    def send_direct_operate_command(self, command, index,
                                    callback=None,
                                    config=None):
        """Direct operate a single command. UNSAFE for baseline experiments."""
        _log.warning(UNSAFE_CONTROL_WARNING)
        callback = callback or asiodnp3.PrintingCommandCallback.Get()
        config = config or opendnp3.TaskConfig().Default()
        self.master.DirectOperate(command, index, callback, config)

    def send_direct_operate_command_set(self, command_set,
                                        callback=None,
                                        config=None):
        """Direct operate a set of commands. UNSAFE for baseline experiments."""
        _log.warning(UNSAFE_CONTROL_WARNING)
        callback = callback or asiodnp3.PrintingCommandCallback.Get()
        config = config or opendnp3.TaskConfig().Default()
        self.master.DirectOperate(command_set, callback, config)

    def send_select_and_operate_command(self, command, index,
                                        callback=None,
                                        config=None):
        """Select-and-operate a single command. UNSAFE for baseline experiments."""
        _log.warning(UNSAFE_CONTROL_WARNING)
        callback = callback or asiodnp3.PrintingCommandCallback.Get()
        config = config or opendnp3.TaskConfig().Default()
        self.master.SelectAndOperate(command, index, callback, config)

    def send_select_and_operate_command_set(self, command_set,
                                            callback=None,
                                            config=None):
        """Select-and-operate a set of commands. UNSAFE for baseline experiments."""
        _log.warning(UNSAFE_CONTROL_WARNING)
        callback = callback or asiodnp3.PrintingCommandCallback.Get()
        config = config or opendnp3.TaskConfig().Default()
        self.master.SelectAndOperate(command_set, callback, config)

    # ------------------------------------------------------------------ #
    # Multi-CROB Select-Before-Operate control test (software-only)
    # ------------------------------------------------------------------ #

    def select_and_operate_command_set(self, crobs):
        """
            Build ONE CommandSet carrying the given CROBs and issue a single
            Select-Before-Operate transaction for it (one SELECT then one OPERATE,
            each carrying all the CROBs -- not independent per-CROB transactions).

            The command result is delivered to a C++ PrintingCommandCallback rather
            than a Python callback: on the rig's pybind11 (Python 3.12) the
            non-copyable ``ICommandTaskResult`` cannot be marshalled into a Python
            callback and aborts the process. The harness therefore captures the
            task-level completion from the master application's ``OnTaskComplete``
            (see ``MultiCrobMasterApplication``) and takes authoritative per-index
            SELECT/OPERATE evidence from the outstation log + PCAP (guide s.6/s.12).

        :param crobs: list of (index, control_code_name), e.g.
                      ``[(0, 'LATCH_ON'), (1, 'LATCH_OFF')]``.
        """
        # Keep the CommandSet alive on the instance: SelectAndOperate is
        # asynchronous and the pydnp3/C++ task keeps referencing this object after
        # this method returns. Letting it fall out of scope (garbage-collected)
        # leaves the task with a dangling reference and hangs the DNP3 thread.
        self._active_command_set = opendnp3.CommandSet([
            opendnp3.WithIndex(
                opendnp3.ControlRelayOutputBlock(getattr(opendnp3.ControlCode, code_name)), index)
            for index, code_name in crobs
        ])
        command_set = self._active_command_set
        _log.info('Multi-CROB Select-Before-Operate: one CommandSet with %s CROB(s): %s',
                  len(crobs), crobs)
        # The SBO command result is a non-copyable ICommandTaskResult. Its delivery
        # to a callback misbehaves in opposite ways across pydnp3 builds: on the
        # rig (Python 3.12 / pybind11 2.13) a Python callback aborts the process,
        # while the C++ PrintingCommandCallback lets OnTaskComplete fire first; on
        # the older build (Python < 3.12) the C++ callback instead hangs on delivery
        # while a trivial Python callback is handled cleanly. Pick per platform --
        # either way the summary is written from OnTaskComplete (see
        # MultiCrobMasterApplication) before the result is (fully) delivered.
        if sys.version_info[:2] >= (3, 12):
            command_callback = asiodnp3.PrintingCommandCallback.Get()
        else:
            command_callback = _noop_command_callback
        self.master.SelectAndOperate(command_set, command_callback, opendnp3.TaskConfig().Default())

    def shutdown(self):
        """Tear down scans, master, channel, and the manager in order."""
        _log.debug('Shutting down master.')
        if self.slow_scan is not None:
            del self.slow_scan
        if self.fast_scan is not None:
            del self.fast_scan
        del self.master
        del self.channel
        self.manager.Shutdown()


class DebugSOEHandler(opendnp3.ISOEHandler):

    def __init__(self):
        super(DebugSOEHandler, self).__init__()

    def Process(self, info, values):
        """
            Process a received measurement collection.

        :param info: HeaderInfo (group/variation, header index, qualifier...).
        :param values: a typed collection of indexed measurement values.
        """
        visitor_class = _VISITOR_CLASS_TYPES[type(values)]
        visitor = visitor_class()
        values.Foreach(visitor)
        for index, value in visitor.index_and_value:
            log_string = 'SOEHandler.Process {0}\theaderIndex={1}\tdata_type={2}\tindex={3}\tvalue={4}'
            _log.debug(log_string.format(info.gv, info.headerIndex, type(values).__name__, index, value))

    def Start(self):
        _log.debug('In DebugSOEHandler.Start')

    def End(self):
        _log.debug('In DebugSOEHandler.End')


class CSVSOEHandler(opendnp3.ISOEHandler):

    def __init__(self, csv_path):
        """
        :param csv_path: path to the CSV file to create/append. Parent
                         directories are created as needed.
        """
        super(CSVSOEHandler, self).__init__()
        self.csv_path = csv_path
        self._lock = threading.Lock()
        # In-memory record of every decoded measurement, keyed by
        # (group_variation, data_type, index) -> value. Used to build the
        # human-readable receipt and the baseline comparison after the scan.
        self.received = OrderedDict()
        self.duplicate_count = 0

        parent = os.path.dirname(os.path.abspath(csv_path))
        if parent:
            os.makedirs(parent, exist_ok=True)

        # Write the header row only when creating a new (or empty) file.
        write_header = (not os.path.exists(csv_path)) or os.path.getsize(csv_path) == 0
        if write_header:
            with open(self.csv_path, 'a', newline='') as fh:
                writer = csv.writer(fh)
                writer.writerow(CSV_COLUMNS)
            _log.debug('Created SOE CSV with header: %s', csv_path)
        else:
            _log.debug('Appending SOE rows to existing CSV: %s', csv_path)

    def Process(self, info, values):
        """
            Extract and persist a received measurement collection.

        :param info: HeaderInfo (group/variation, header index, ...).
        :param values: typed collection of indexed measurement values.
        """
        visitor_class = _VISITOR_CLASS_TYPES[type(values)]
        visitor = visitor_class()
        values.Foreach(visitor)

        data_type = type(values).__name__
        group_variation = str(info.gv)
        header_index = info.headerIndex
        timestamp = datetime.now().isoformat()

        rows = []
        for index, value in visitor.index_and_value:
            _log.debug('CSVSOEHandler.Process %s\theaderIndex=%s\tdata_type=%s\tindex=%s\tvalue=%s',
                       group_variation, header_index, data_type, index, value)
            rows.append([timestamp, header_index, group_variation, data_type, index, value])
            # Accumulate for the receipt. A repeated key (same gv/type/index in
            # one run) signals a duplicate/extra scan, which the receipt reports.
            key = (group_variation, data_type, str(index))
            with self._lock:
                if key in self.received:
                    self.duplicate_count += 1
                self.received[key] = str(value)

        if rows:
            with self._lock:
                with open(self.csv_path, 'a', newline='') as fh:
                    writer = csv.writer(fh)
                    writer.writerows(rows)

    def Start(self):
        _log.debug('In CSVSOEHandler.Start')

    def End(self):
        _log.debug('In CSVSOEHandler.End')


# ------------------------------------------------------------------ #
# Measurement receipt (human-readable summary of decoded SOE values)
# ------------------------------------------------------------------ #

# Friendly labels for the opendnp3 collection type names.
_TYPE_LABELS = {
    'ICollectionIndexedAnalog': 'Analog Inputs',
    'ICollectionIndexedBinary': 'Binary Inputs',
    'ICollectionIndexedDoubleBitBinary': 'Double-Bit Binary Inputs',
    'ICollectionIndexedCounter': 'Counters',
    'ICollectionIndexedFrozenCounter': 'Frozen Counters',
    'ICollectionIndexedAnalogOutputStatus': 'Analog Output Status',
    'ICollectionIndexedBinaryOutputStatus': 'Binary Output Status',
    'ICollectionIndexedTimeAndInterval': 'Time And Interval',
}

_RECEIPT_BAR = '=' * 52


def _friendly_type(data_type):
    """Map an opendnp3 collection type name to a readable label."""
    return _TYPE_LABELS.get(data_type, data_type)


def _friendly_gv(group_variation):
    """Render 'GroupVariation.Group30Var1' as 'Group 30 Variation 1'."""
    match = re.search(r'Group(\d+)Var(\d+)', group_variation or '')
    if match:
        return 'Group {} Variation {}'.format(match.group(1), match.group(2))
    return group_variation or 'unknown'


def build_receipt(received, duplicates, run_label, rows_per_group=0):
    """Render a readable receipt of the measurements the master decoded.

    :param received: dict {(group_variation, data_type, index): value}.
    :param duplicates: count of repeated (gv, type, index) keys seen this run.
    :param run_label: short label for the run (e.g. the phase name).
    :param rows_per_group: max index rows to list per group; 0/None = all.
    :returns: the formatted receipt as a single string.
    """
    lines = [_RECEIPT_BAR, 'DNP3 Measurement Receipt Summary', _RECEIPT_BAR,
             'Run: {}'.format(run_label),
             'Measurements decoded: {}'.format(len(received)),
             'Duplicate points: {}'.format(duplicates), '']

    groups = defaultdict(list)
    for (group_variation, data_type, index), value in received.items():
        groups[(data_type, group_variation)].append((int(index), value))

    show_all = not rows_per_group or rows_per_group < 0
    for data_type, group_variation in sorted(groups, key=lambda k: (_friendly_type(k[0]), k[1])):
        items = sorted(groups[(data_type, group_variation)])
        lines.append('{} - {}'.format(_friendly_type(data_type), _friendly_gv(group_variation)))
        shown = items if show_all else items[:rows_per_group]
        width = max((len(str(idx)) for idx, _ in shown), default=1)
        for idx, value in shown:
            lines.append('  Index {:<{w}} = {}'.format(idx, value, w=width))
        if len(shown) < len(items):
            lines.append('  ... ({} more)'.format(len(items) - len(shown)))
        lines.append('')

    lines.append('Result: Master decoded {} measurement(s).'.format(len(received)))
    lines.append(_RECEIPT_BAR)
    return '\n'.join(lines)


def load_soe_values(csv_path):
    """Load {(group_variation, data_type, index): value} from an SOE CSV."""
    expected = {}
    with open(csv_path, newline='') as fh:
        for row in csv.DictReader(fh):
            expected[(row['group_variation'], row['data_type'], row['index'])] = row['value']
    return expected


def compare_to_baseline(received, expected):
    """Compare decoded measurements against a baseline SOE set.

    Compares only (group_variation, data_type, index, value) -- the fields that
    must match -- and reports missing/extra/changed points.

    :returns: (report_text, passed) where passed is True iff the sets are equal.
    """
    received_keys, expected_keys = set(received), set(expected)
    missing = sorted(expected_keys - received_keys)
    extra = sorted(received_keys - expected_keys)
    changed = sorted(k for k in (received_keys & expected_keys) if received[k] != expected[k])
    passed = not (missing or extra or changed)

    lines = ['Baseline comparison:',
             '  Expected points: {}'.format(len(expected)),
             '  Received points: {}'.format(len(received)),
             '  Missing points: {}'.format(len(missing)),
             '  Extra points: {}'.format(len(extra)),
             '  Changed values: {}'.format(len(changed)),
             '  Status: {}'.format('PASS' if passed else 'FAIL')]
    for key in missing[:5]:
        lines.append('    missing: {}'.format(key))
    for key in extra[:5]:
        lines.append('    extra: {}'.format(key))
    for key in changed[:5]:
        lines.append('    changed: {} expected={} received={}'.format(key, expected[key], received[key]))
    return '\n'.join(lines), passed


def _default_summary_path(csv_path):
    """Derive the receipt .txt path from the SOE CSV path."""
    if csv_path.endswith('_soe.csv'):
        return csv_path[:-len('_soe.csv')] + '_summary.txt'
    base, _ = os.path.splitext(csv_path)
    return base + '_summary.txt'


def emit_receipt(soe_handler, run_label, csv_path, summary_path=None,
                 receipt_rows=8, baseline_csv=None):
    """Print the measurement receipt and write the full receipt to a .txt file.

    Console output is truncated to ``receipt_rows`` per group; the .txt file
    always lists every point. When ``baseline_csv`` is given, a PASS/FAIL
    baseline comparison block is appended to both.

    :returns: the comparison ``passed`` flag, or None when no baseline given.
    """
    received = soe_handler.received
    console = build_receipt(received, soe_handler.duplicate_count, run_label, receipt_rows)
    full = build_receipt(received, soe_handler.duplicate_count, run_label, rows_per_group=0)

    compare_block, passed = None, None
    if baseline_csv:
        if os.path.exists(baseline_csv):
            compare_block, passed = compare_to_baseline(received, load_soe_values(baseline_csv))
        else:
            _log.warning('Baseline CSV not found, skipping comparison: %s', baseline_csv)

    print('\n' + console)
    if compare_block:
        print('\n' + compare_block)

    summary_path = summary_path or _default_summary_path(csv_path)
    parent = os.path.dirname(os.path.abspath(summary_path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(summary_path, 'w') as fh:
        fh.write(full + '\n')
        if compare_block:
            fh.write('\n' + compare_block + '\n')
    _log.info('Wrote measurement receipt -> %s', summary_path)
    return passed


# ------------------------------------------------------------------ #
# Multi-CROB Select-Before-Operate result summary
# ------------------------------------------------------------------ #

_CROB_BAR = '=' * 52

_CROB_LIMITATION_NOTE = (
    'Note:\n'
    '  On this pydnp3/pybind11 build the non-copyable command result cannot be\n'
    '  marshalled into a Python callback, so the master captures only the\n'
    '  task-level completion shown above (via the master OnTaskComplete callback).\n'
    '  Authoritative per-index SELECT and OPERATE status and the final simulated\n'
    '  states are in the outstation log and the PCAP: the SELECT request/response\n'
    '  and the OPERATE request/response are distinct DNP3 messages on the wire.\n'
    '  A task completion of SUCCESS means the SBO transaction completed at the\n'
    '  protocol level; it does not by itself prove both outputs changed, nor that\n'
    '  they changed simultaneously -- confirm the final states from the outstation\n'
    '  state report.')


def build_multi_crob_summary(label, crobs, task_result, elapsed_sec, expected_states,
                             start_iso, negative=False, requested_n=None):
    """Render the human-readable multi-CROB Select-Before-Operate result.

    :param label: test label (e.g. the Test A/B/C/D description).
    :param crobs: list of (index, control_code_name) that were requested.
    :param task_result: task-level TaskCompletion string from OnTaskComplete, or
                        None if the SBO USER_TASK never completed (timeout).
    :param elapsed_sec: SBO round-trip seconds, measured from issuing SelectAndOperate
                        to task completion -- NOT including channel bring-up.
    :param expected_states: dict {index: expected_final_state} for the run.
    :param start_iso: ISO timestamp of the moment SelectAndOperate was issued.
    :param negative: True for the optional negative test (status is OBSERVED, not
                     PASS/FAIL, and no assumption is made about partial success).
    :param requested_n: number of CROBs in the command set (len(crobs)).
    :returns: (summary_text, passed) where ``passed`` is None for a negative test.
    """
    completed = task_result == 'SUCCESS'
    n = requested_n if requested_n is not None else len(crobs)

    lines = [_CROB_BAR, 'Multi-CROB Select-Before-Operate Result', _CROB_BAR,
             'Test: {}'.format(label),
             'Requested N (CROBs in one command set): {}'.format(n),
             'SBO issued at: {}'.format(start_iso),
             'SBO round-trip: {:.3f} s (excludes channel bring-up)'.format(elapsed_sec),
             '',
             'Requested controls:']
    # For large N, list only the first few requested controls (full plan is in the JSON).
    for index, code_name in (crobs if len(crobs) <= 8 else crobs[:8]):
        lines.append('  Index {}: {}'.format(index, code_name))
    if len(crobs) > 8:
        lines.append('  ... ({} more; full plan in the JSON summary)'.format(len(crobs) - 8))
    lines.append('')

    lines.append('DNP3 SelectAndOperate task completion: {}'.format(
        task_result if task_result is not None else 'NO COMPLETION (timed out)'))
    lines.append('')

    if negative:
        # Do NOT print an "expected" state for the negative test: the outcome
        # (partial vs whole-command failure) must be read as observed, not assumed.
        lines.append('Observed behavior (not assumed):')
        lines.append('  A SELECT failure on any CROB may prevent the OPERATE for ALL CROBs, so')
        lines.append('  the valid control may not execute. Read the actual per-index SELECT/')
        lines.append('  OPERATE status and the final simulated output state from the outstation')
        lines.append('  state report -- do not infer them from here.')
    else:
        lines.append('Expected final simulated states (confirm on the outstation):')
        for index in sorted(expected_states):
            lines.append('  Index {}: {}'.format(index, expected_states[index]))
    lines.append('')

    # The negative test is reported as OBSERVED. For A/B/C, "COMPLETED" means the
    # SBO task finished at the protocol level; the authoritative per-index outcome
    # and final states are on the outstation (see the note).
    passed = None
    if negative:
        lines.append('Status: OBSERVED (negative test -- see outstation log for actual behavior)')
    else:
        passed = bool(completed)
        lines.append('Status: {}'.format(
            'TRANSACTION COMPLETED (task SUCCESS)' if completed
            else 'INCOMPLETE (task result: {})'.format(task_result)))

    lines.append('')
    lines.append(_CROB_LIMITATION_NOTE)
    lines.append(_CROB_BAR)
    return '\n'.join(lines), passed


class MasterLogHandler(openpal.ILogHandler):
    """Application-specific log handler mirroring the original ``MyLogger``."""

    def __init__(self):
        super(MasterLogHandler, self).__init__()

    def Log(self, entry):
        flag = opendnp3.LogFlagToString(entry.filters.GetBitfield())
        filters = entry.filters.GetBitfield()
        location = entry.location.rsplit('/')[-1] if entry.location else ''
        message = entry.message
        _log.debug('LOG\t\t{:<10}\tfilters={:<5}\tlocation={:<25}\tentry={}'.format(
            flag, filters, location, message))


class MasterChannelListener(asiodnp3.IChannelListener):
    """Application-specific channel listener mirroring the original ``AppChannelListener``."""

    def __init__(self):
        super(MasterChannelListener, self).__init__()

    def OnStateChange(self, state):
        _log.debug('In MasterChannelListener.OnStateChange: state={}'.format(
            opendnp3.ChannelStateToString(state)))


class ExperimentMasterApplication(opendnp3.IMasterApplication):
    """Application callbacks mirroring the original ``MasterApplication``."""

    def __init__(self):
        super(ExperimentMasterApplication, self).__init__()

    def AssignClassDuringStartup(self):
        _log.debug('In ExperimentMasterApplication.AssignClassDuringStartup')
        return False

    def OnClose(self):
        _log.debug('In ExperimentMasterApplication.OnClose')

    def OnOpen(self):
        _log.debug('In ExperimentMasterApplication.OnOpen')

    def OnReceiveIIN(self, iin):
        _log.debug('In ExperimentMasterApplication.OnReceiveIIN')

    def OnTaskComplete(self, info):
        _log.debug('In ExperimentMasterApplication.OnTaskComplete')

    def OnTaskStart(self, type, id):
        _log.debug('In ExperimentMasterApplication.OnTaskStart')


class MultiCrobMasterApplication(opendnp3.IMasterApplication):
    """
        Master application for the multi-CROB Select-Before-Operate control test.

        On the rig's pybind11 (Python 3.12) the non-copyable ``ICommandTaskResult``
        delivered to the command-result callback cannot be marshalled into Python
        and aborts the process (pybind11 cast_error) right after the OPERATE
        response. ``OnTaskComplete(info)`` fires just BEFORE that delivery and its
        ``TaskInfo`` marshals fine, so this hands the SBO task-level completion to
        ``on_user_task_complete``. That callback captures the result, signals the
        main thread, and then BLOCKS (never returns) -- since the DNP3 manager runs
        a single thread, blocking here freezes all further DNP3 processing, so the
        aborting command result is never delivered and the main thread can write the
        summary and hard-exit. (File I/O must NOT be done on this callback thread --
        it deadlocks against pydnp3's C++.) Authoritative per-index SELECT/OPERATE
        evidence is the outstation log + PCAP (guide sections 6 and 12).
    """

    def __init__(self, on_user_task_complete):
        super(MultiCrobMasterApplication, self).__init__()
        self._on_user_task_complete = on_user_task_complete
        self._fired = False

    def OnTaskComplete(self, info):
        try:
            if info.type == opendnp3.MasterTaskType.USER_TASK and not self._fired:
                self._fired = True
                self._on_user_task_complete(opendnp3.TaskCompletionToString(info.result))
        except Exception:  # defensive: never let a callback exception escape
            pass

    def AssignClassDuringStartup(self):
        return False

    def OnClose(self):
        _log.debug('In MultiCrobMasterApplication.OnClose')

    def OnOpen(self):
        _log.debug('In MultiCrobMasterApplication.OnOpen')

    def OnReceiveIIN(self, iin):
        _log.debug('In MultiCrobMasterApplication.OnReceiveIIN')

    def OnTaskStart(self, type, id):
        _log.debug('In MultiCrobMasterApplication.OnTaskStart')


# ------------------------------------------------------------------ #
# Command-line entry point (defaults sourced from the inline lab config above)
# ------------------------------------------------------------------ #

def build_parser():
    """Build the argument parser; every default comes from the inline lab config."""
    default_log_dir = os.path.join(LOG_DIR, 'master')
    parser = argparse.ArgumentParser(
        description='Self-contained DNP3 master for reproducible READ/RESPONSE experiments.')
    parser.add_argument('--host', default=OUTSTATION_IP,
                        help='Outstation / replay-server IP to connect to (default from lab_config).')
    parser.add_argument('--local', default=BIND_IP,
                        help='Local interface address to bind the client socket.')
    parser.add_argument('--port', type=int, default=DNP3_PORT, help='TCP port (DNP3 default 20000).')
    parser.add_argument('--master-addr', type=int, default=MASTER_LINK_ADDR,
                        help='DNP3 link-layer address of this master.')
    parser.add_argument('--outstation-addr', type=int, default=OUTSTATION_LINK_ADDR,
                        help='DNP3 link-layer address of the remote outstation.')
    parser.add_argument('--response-timeout-sec', type=int, default=DEFAULT_RESPONSE_TIMEOUT_SEC,
                        help='Application response timeout, seconds.')
    parser.add_argument('--action', choices=SAFE_ACTIONS + [MULTI_CROB_ACTION],
                        default='scan-all-classes',
                        help='READ/RESPONSE action to perform, or "%s" for the software-only '
                             'multi-CROB Select-Before-Operate control test.' % MULTI_CROB_ACTION)
    parser.add_argument('--crob-test', choices=sorted(CROB_TESTS), default='C',
                        help='Which staged control test to run with --action %s: '
                             'A/B are single-CROB baselines, C is the two-CROB command set '
                             '(default). Run each against a freshly restarted --control-test '
                             'outstation.' % MULTI_CROB_ACTION)
    parser.add_argument('--control-test-negative', dest='control_test_negative',
                        action='store_true',
                        help='With --action %s, run the optional negative test (one valid CROB '
                             'plus unsupported index 99). Off by default; behavior is recorded '
                             'as observed.' % MULTI_CROB_ACTION)
    parser.add_argument('--crob-count', dest='crob_count', type=int, default=None,
                        help='With --action %s, build ONE command set of N CROBs over indexes '
                             '0..N-1 (even -> LATCH_ON, odd -> LATCH_OFF). Overrides --crob-test. '
                             'This is the primary highest-N control path.' % MULTI_CROB_ACTION)
    parser.add_argument('--crob-plan', dest='crob_plan', default=None,
                        help='With --action %s, build ONE command set from an explicit, ordered '
                             'CROB plan "idx:CODE,idx:CODE,..." (CODE in LATCH_ON/LATCH_OFF). '
                             'Preserves transmitted order; rejects duplicate indexes and malformed '
                             'entries. Overrides --crob-count and --crob-test. Used to place invalid '
                             '(nonexistent) indexes at chosen positions.' % MULTI_CROB_ACTION)
    parser.add_argument('--run-id', dest='run_id', default=None,
                        help='Opaque run identifier recorded in the master JSON summary and used '
                             'to name the default JSON/summary files.')
    parser.add_argument('--hold-open-ms', dest='hold_open_ms', type=int, default=0,
                        help='With --action %s, hold the TCP connection open for this many '
                             'milliseconds AFTER the SBO task completes, before the hard exit. '
                             'Default 0 = current behaviour (the FIN carries the response ACK). '
                             'Set e.g. 300 so the kernel emits a standalone pure ACK of the '
                             'OPERATE-response (the real DNP3 final ACK / slot 5) BEFORE teardown, '
                             'making the capture behave like a persistent connection for that '
                             'transaction.' % MULTI_CROB_ACTION)
    parser.add_argument('--group', type=int, default=30,
                        help='Object group for scan-range / scan-all-objects.')
    parser.add_argument('--variation', type=int, default=1,
                        help='Object variation for scan-range / scan-all-objects.')
    parser.add_argument('--start', type=int, default=0, help='First index for scan-range.')
    parser.add_argument('--stop', type=int, default=9, help='Last index (inclusive) for scan-range.')
    parser.add_argument('--repeat', type=int, default=1, help='Number of times to repeat the action.')
    parser.add_argument('--delay-between', type=float, default=1.0,
                        help='Seconds to wait between repeated actions.')
    parser.add_argument('--wait-after-action', type=float, default=DEFAULT_WAIT_AFTER_ACTION_SEC,
                        help='Seconds to keep the master running after the last action.')
    parser.add_argument('--log-dir', default=default_log_dir,
                        help='Directory for a per-run master log file.')
    parser.add_argument('--phase', choices=['baseline', 'exact-replay', 'crc-split', 'custom'],
                        default='baseline',
                        help='Experiment phase; selects the per-phase SOE CSV '
                             '(logs/master/<phase>_soe.csv) so runs are not mixed in one file.')
    parser.add_argument('--csv', default=None,
                        help='Explicit SOE CSV path (overrides the per-phase default).')
    parser.add_argument('--no-csv', action='store_true',
                        help='Disable SOE CSV output entirely.')
    parser.add_argument('--summary', default=None,
                        help='Path for the readable measurement receipt .txt '
                             '(default: alongside the CSV, <phase>_summary.txt).')
    parser.add_argument('--no-summary', action='store_true',
                        help='Do not print or write the measurement receipt.')
    parser.add_argument('--receipt-rows', type=int, default=8,
                        help='Max index rows per group printed to the console '
                             '(0 = all; the .txt file always lists every point).')
    parser.add_argument('--baseline', default=None,
                        help='Baseline SOE CSV to compare decoded measurements against '
                             '(adds a PASS/FAIL block on gv+type+index+value).')
    parser.add_argument('--enable-periodic-scans', action='store_true',
                        help='Register background periodic scans (off by default for clean captures).')
    return parser


def _configure_file_logging(log_dir):
    """Add a timestamped file handler under ``log_dir`` for this run, if given."""
    if not log_dir:
        return
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, 'experiment_master_{}.log'.format(int(time.time())))
    file_handler = logging.FileHandler(log_path)
    file_handler.setFormatter(logging.Formatter('%(asctime)s\t%(name)s\t%(levelname)s\t%(message)s'))
    logging.getLogger().addHandler(file_handler)
    logging.getLogger().setLevel(logging.DEBUG)
    _log.info('Writing master log to %s', log_path)


def _hard_exit(code=0):
    """
        Flush logs and terminate the process via os._exit.

        pydnp3's C++ objects can double-free during normal interpreter teardown
        (a known pydnp3 issue) even after the DNP3Manager has been shut down
        cleanly. Since all experiment work and the orderly shutdown are already
        complete at this point, we bypass Python's object cleanup so the process
        exits with a clean status instead of aborting (exit 134).
    """
    for handler in logging.getLogger().handlers + _log.handlers:
        try:
            handler.flush()
        except Exception:
            pass
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(code)


def _perform_action(master, args):
    """Dispatch a single READ/RESPONSE action against the master."""
    if args.action == 'connect-only':
        _log.info('connect-only: no request issued.')
    elif args.action == 'scan-class0':
        master.scan_class0()
    elif args.action == 'scan-all-classes':
        master.scan_all_classes()
    elif args.action == 'scan-range':
        master.scan_range(args.group, args.variation, args.start, args.stop)
    elif args.action == 'scan-all-objects':
        master.scan_all_objects(args.group, args.variation)
    elif args.action == 'disable-unsolicited':
        master.disable_unsolicited()
    else:  # Defensive: argparse choices should prevent this.
        _log.error('Unknown action: %s', args.action)


def _hard_exit_master(code=0):
    """Flush logs, then terminate via os._exit.

    The DNP3 callback thread is intentionally blocked in ``on_user_task_complete``
    (the temporary pybind11 workaround), so a normal return is not possible; this
    flushes handlers first so nothing is lost, unlike a bare os._exit(0).
    """
    for handler in logging.getLogger().handlers + _log.handlers:
        try:
            handler.flush()
        except Exception:
            pass
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(code)


def _build_crob_plan_for_count(n):
    """Generate one command set of N CROBs: even index -> LATCH_ON, odd -> LATCH_OFF.

    Returns a plan dict compatible with the staged CROB_TESTS entries. Raises
    ValueError on N < 1 or on duplicate indexes (defensive; generated indexes are
    distinct by construction).
    """
    if n < 1:
        raise ValueError('--crob-count must be >= 1, got {}'.format(n))
    crobs = [(i, 'LATCH_ON' if i % 2 == 0 else 'LATCH_OFF') for i in range(n)]
    indexes = [i for i, _ in crobs]
    if len(set(indexes)) != len(indexes):
        raise ValueError('duplicate indexes in generated plan: {}'.format(indexes))
    expected = {i: (i % 2 == 0) for i in range(n)}
    return {
        'label': 'Generated multi-CROB command set (N={}, even->LATCH_ON / odd->LATCH_OFF)'.format(n),
        'crobs': crobs,
        'expected_states': expected,
        'summary_file': 'multicrob_n{}_summary.txt'.format(n),
    }


CROB_PLAN_SUPPORTED_CODES = ('LATCH_ON', 'LATCH_OFF')


def _build_crob_plan_from_spec(spec):
    """Parse a custom CROB plan 'idx:CODE,idx:CODE,...' into a plan dict.

    Preserves transmitted order; the master JSON records this exact order. Rejects
    an empty plan, malformed entries, negative or duplicate indexes, and control
    codes outside LATCH_ON/LATCH_OFF. Still produces ONE command set -> one
    SelectAndOperate task. An index may be nonexistent on the outstation (that is the
    point of the invalid-index tests); validity is characterised from the response,
    not enforced here.
    """
    entries = [e.strip() for e in spec.split(',') if e.strip()]
    if not entries:
        raise ValueError('--crob-plan is empty')
    crobs = []
    seen = set()
    for e in entries:
        if e.count(':') != 1:
            raise ValueError('malformed --crob-plan entry {!r} (expected index:CODE)'.format(e))
        idx_s, code = (part.strip() for part in e.split(':'))
        try:
            idx = int(idx_s)
        except ValueError:
            raise ValueError('malformed index in --crob-plan entry {!r}'.format(e))
        if idx < 0:
            raise ValueError('negative index in --crob-plan entry {!r}'.format(e))
        code = code.upper()
        if code not in CROB_PLAN_SUPPORTED_CODES:
            raise ValueError('unsupported control code {!r} in --crob-plan (supported: {})'.format(
                code, ', '.join(CROB_PLAN_SUPPORTED_CODES)))
        if idx in seen:
            raise ValueError('duplicate index {} in --crob-plan'.format(idx))
        seen.add(idx)
        crobs.append((idx, code))
    expected = {idx: (code == 'LATCH_ON') for idx, code in crobs}
    return {
        'label': 'Custom multi-CROB plan (N={}, transmitted order {})'.format(
            len(crobs), [i for i, _ in crobs]),
        'crobs': crobs,
        'expected_states': expected,
        'summary_file': 'multicrob_customplan_summary.txt',
    }


def _resolve_crob_plan(args):
    """Pick the CROB plan: --crob-plan (highest) > --crob-count > --control-test-negative > --crob-test."""
    if getattr(args, 'crob_plan', None):
        return _build_crob_plan_from_spec(args.crob_plan)
    if args.crob_count is not None:
        return _build_crob_plan_for_count(args.crob_count)
    if args.control_test_negative:
        return CROB_NEGATIVE_TEST
    return CROB_TESTS[args.crob_test]


def _multicrob_paths(args, plan):
    """Resolve (summary_txt_path, json_path) for this run, honouring --run-id/--summary."""
    if args.run_id:
        summary_rel = args.summary or os.path.join(LOG_DIR, 'master',
                                                    'multicrob_{}_summary.txt'.format(args.run_id))
        json_rel = os.path.join(LOG_DIR, 'master', 'multicrob_master_{}.json'.format(args.run_id))
    else:
        summary_rel = args.summary or os.path.join(LOG_DIR, 'master', plan['summary_file'])
        json_rel = os.path.join(LOG_DIR, 'master',
                                plan['summary_file'].replace('_summary.txt', '_master.json'))
    absol = lambda p: p if os.path.isabs(p) else os.path.join(HARNESS_DIR, p)
    return absol(summary_rel), absol(json_rel)


def _run_multi_crob_action(args):
    """Run one multi-CROB Select-Before-Operate transaction and write summary + JSON.

    Uses a control path separate from the READ/RESPONSE flow (no SOE CSV). The plan
    is one command set of N CROBs (``--crob-count N``; or a staged A/B/C regression
    alias, or the negative test). Run against a freshly (re)started ``--control-test``
    outstation so the initial alternating state is deterministic.

    TEMPORARY pybind11 workaround (do NOT promote to a production architecture): the
    SBO task-level completion is captured on the DNP3 thread in ``OnTaskComplete``
    (via ``on_user_task_complete``), which then BLOCKS that single thread so pydnp3
    never delivers the non-copyable command result that would abort/hang the process.
    The MAIN thread writes the summary + JSON and hard-exits. Authoritative per-index
    evidence is the outstation JSON + PCAP (task-level SUCCESS is NOT proof that every
    output changed).
    """
    try:
        plan = _resolve_crob_plan(args)
    except ValueError as exc:
        _log.error('Invalid multi-CROB plan: %s', exc)
        _hard_exit_master(2)
    requested_n = len(plan['crobs'])
    negative = bool(plan.get('negative', False))
    _log.info('Multi-CROB control plan: %s (N=%s)', plan['label'], requested_n)
    _log.info('Master transmits this CROB plan verbatim (indexes + order as given); it does NOT '
              'validate index existence and does NOT infer the response CommandStatus -- the status '
              'is decided by the outstation application and observed from the outstation JSON + PCAP.')

    summary_path, json_path = _multicrob_paths(args, plan)

    result_box = {'task_result': None}
    result_ready = threading.Event()
    block_forever = threading.Event()  # deliberately never set

    def on_user_task_complete(task_result):
        """Runs on pydnp3's single DNP3 thread when the SBO USER_TASK completes.

        Hand the task-level result to the main thread, then BLOCK here forever
        (releasing the GIL). Because the DNP3 manager runs one thread, blocking it
        freezes all further DNP3 work -- so the non-marshallable command result is
        never delivered (no pybind11 abort) and the main thread is free to do the
        file I/O + exit (which must NOT happen on this callback thread).
        """
        result_box['task_result'] = task_result
        result_ready.set()
        block_forever.wait()

    application = MultiCrobMasterApplication(on_user_task_complete)
    _log.info('Connecting master -> %s:%s for the multi-CROB control test -- settings from lab_config.py.',
              args.host, args.port)
    master = ExperimentMaster(host=args.host,
                              local=args.local,
                              port=args.port,
                              master_addr=args.master_addr,
                              outstation_addr=args.outstation_addr,
                              response_timeout_sec=args.response_timeout_sec,
                              soe_handler=None,
                              master_application=application,
                              enable_periodic_scans=False)

    # Measure ONLY the SBO round-trip, not the channel bring-up (~2 s). The timestamp
    # and clock are taken immediately before SelectAndOperate.
    sbo_iso = datetime.now().isoformat()
    sbo_started = time.monotonic()
    master.select_and_operate_command_set(plan['crobs'])

    got = result_ready.wait(max(8.0, args.wait_after_action + 5))
    sbo_elapsed = time.monotonic() - sbo_started
    task_result = result_box['task_result'] if got else None
    timed_out = not got
    if timed_out:
        _log.warning('SBO USER_TASK did not complete within the timeout.')

    # Write the summary + JSON on the MAIN thread (file I/O on the DNP3 thread deadlocks).
    text, _ = build_multi_crob_summary(plan['label'], plan['crobs'], task_result,
                                       sbo_elapsed, plan['expected_states'], sbo_iso,
                                       negative=negative, requested_n=requested_n)
    master_json = {
        'run_id': args.run_id,
        'requested_n': requested_n,
        'crob_plan': [{'index': i, 'code': c} for i, c in plan['crobs']],
        'task_completion': task_result,
        'timed_out': timed_out,
        'sbo_issued_at': sbo_iso,
        'sbo_round_trip_sec': round(sbo_elapsed, 4),
        'negative_test': negative,
        'note': 'task-level SUCCESS is NOT proof that every output changed; '
                'confirm per-index from the outstation JSON + PCAP.',
    }
    try:
        os.makedirs(os.path.dirname(summary_path), exist_ok=True)
        with open(summary_path, 'w') as fh:
            fh.write(text + '\n')
        with open(json_path, 'w') as fh:
            json.dump(master_json, fh, indent=2)
            fh.write('\n')
    except OSError as exc:
        _log.error('Could not write multi-CROB outputs: %r', exc)
    print('\n' + text, flush=True)
    _log.info('Wrote multi-CROB summary -> %s ; JSON -> %s', summary_path, json_path)

    # Exit code: a timeout or a non-SUCCESS task completion must be non-zero.
    success = (not timed_out) and (task_result == 'SUCCESS')
    exit_code = 0 if success else 3
    if not success:
        _log.warning('Multi-CROB %s did NOT complete cleanly (timed_out=%s task=%s) -> exit %s.',
                     plan['label'], timed_out, task_result, exit_code)
    # Hold the connection open so the kernel emits a standalone pure ACK of the terminal
    # (OPERATE) response before the process exit closes the socket. This captures the real
    # DNP3 final ACK (slot 5) instead of letting the FIN carry the response ACK.
    hold_ms = getattr(args, 'hold_open_ms', 0) or 0
    if hold_ms > 0:
        _log.info('Holding the connection open %d ms before teardown (persistent-slot-5 capture).',
                  hold_ms)
        time.sleep(hold_ms / 1000.0)
    _hard_exit_master(exit_code)


def main():
    args = build_parser().parse_args()
    # Anchor relative log/csv paths to the harness directory so the runner works
    # from any cwd (the no-IP convention is to run it from the harness dir).
    log_dir = args.log_dir if os.path.isabs(args.log_dir) else os.path.join(HARNESS_DIR, args.log_dir)
    _configure_file_logging(log_dir)

    if args.action == MULTI_CROB_ACTION:
        _run_multi_crob_action(args)
        return  # _run_multi_crob_action hard-exits; never reached.

    soe_handler = None
    csv_path = None
    if not args.no_csv:
        # Per-phase CSV keeps baseline / exact-replay / crc-split runs in separate
        # files; the first quantitative proof is that all three deliver the same
        # measurement count. An explicit --csv overrides the per-phase default.
        csv_rel = args.csv or os.path.join(LOG_DIR, 'master', '{}_soe.csv'.format(args.phase))
        csv_path = csv_rel if os.path.isabs(csv_rel) else os.path.join(HARNESS_DIR, csv_rel)
        soe_handler = CSVSOEHandler(csv_path)
        _log.info('Using CSVSOEHandler (phase=%s) -> %s', args.phase, csv_path)

    _log.info('Connecting master -> %s:%s (action=%s repeat=%s) -- settings from lab_config.py.',
              args.host, args.port, args.action, args.repeat)
    master = ExperimentMaster(host=args.host,
                              local=args.local,
                              port=args.port,
                              master_addr=args.master_addr,
                              outstation_addr=args.outstation_addr,
                              response_timeout_sec=args.response_timeout_sec,
                              soe_handler=soe_handler,
                              enable_periodic_scans=args.enable_periodic_scans)
    try:
        for i in range(max(1, args.repeat)):
            _log.info('Action iteration %s/%s: %s', i + 1, args.repeat, args.action)
            _perform_action(master, args)
            if i < args.repeat - 1:
                time.sleep(args.delay_between)
        _log.info('Waiting %ss after action for responses to settle.', args.wait_after_action)
        time.sleep(args.wait_after_action)
        # Emit the human-readable measurement receipt (and optional baseline
        # comparison) once the scan's responses have been decoded.
        if soe_handler is not None and not args.no_summary:
            baseline = None
            if args.baseline:
                baseline = (args.baseline if os.path.isabs(args.baseline)
                            else os.path.join(HARNESS_DIR, args.baseline))
            summary = None
            if args.summary:
                summary = (args.summary if os.path.isabs(args.summary)
                           else os.path.join(HARNESS_DIR, args.summary))
            passed = emit_receipt(soe_handler, args.phase, csv_path,
                                  summary_path=summary, receipt_rows=args.receipt_rows,
                                  baseline_csv=baseline)
            if passed is False:
                _log.warning('Baseline comparison FAILED for phase=%s.', args.phase)
    finally:
        master.shutdown()
        _log.info('Master shut down. Exiting.')
    # Hard-exit to avoid pydnp3's double-free during interpreter teardown.
    _hard_exit(0)


if __name__ == '__main__':
    main()

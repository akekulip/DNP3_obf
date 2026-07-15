
import argparse
import csv
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
    parser.add_argument('--action', choices=SAFE_ACTIONS,
                        default='scan-all-classes',
                        help='READ/RESPONSE action to perform.')
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



def main():
    args = build_parser().parse_args()
    # Anchor relative log/csv paths to the harness directory so the runner works
    # from any cwd (the no-IP convention is to run it from the harness dir).
    log_dir = args.log_dir if os.path.isabs(args.log_dir) else os.path.join(HARNESS_DIR, args.log_dir)
    _configure_file_logging(log_dir)

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

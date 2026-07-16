"""
run_outstation.py -- self-contained DNP3 outstation (TCP server) for baseline.

Run it with no arguments:

    python run_outstation.py

It reads the lab settings from lab_config.py, binds 0.0.0.0:20000 (link address
10, expecting master 1), builds a large configurable database (default 200 analog
/ 50 binary / 50 counter), keeps unsolicited responses and controls OFF, applies
deterministic initial values, and holds until Ctrl+C. Used in the baseline phase.

Everything the outstation needs lives in this one file: the reusable
``ExperimentOutstation`` plus its command handler and listeners. At runtime only
this file and lab_config.py are loaded from the harness. pydnp3 is imported at
module load, so the native extension must be installed.

Power users may pass any of the flags below to override the lab_config defaults
(e.g. ``python run_outstation.py --db-size 600 --num-analog 500 --no-hold``).
"""

import argparse
import logging
import os
import sys
import time

from pydnp3 import opendnp3, openpal, asiopal, asiodnp3

HARNESS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HARNESS_DIR)  # so 'lab_config' imports regardless of cwd

import lab_config as cfg

# Single source of truth: every lab setting comes from lab_config.py.
BIND_IP = cfg.BIND_IP                    # local interface to bind the TCP server
DNP3_PORT = cfg.DNP3_PORT
MASTER_LINK_ADDR = cfg.MASTER_LINK_ADDR
OUTSTATION_LINK_ADDR = cfg.OUTSTATION_LINK_ADDR
DEFAULT_DB_SIZE = cfg.DEFAULT_DB_SIZE
DEFAULT_NUM_ANALOG = cfg.DEFAULT_NUM_ANALOG
DEFAULT_NUM_BINARY = cfg.DEFAULT_NUM_BINARY
DEFAULT_NUM_COUNTER = cfg.DEFAULT_NUM_COUNTER
LOG_DIR = cfg.LOG_DIR

LOG_LEVELS = opendnp3.levels.NORMAL | opendnp3.levels.ALL_COMMS

stdout_stream = logging.StreamHandler(sys.stdout)
stdout_stream.setFormatter(logging.Formatter('%(asctime)s\t%(name)s\t%(levelname)s\t%(message)s'))

_log = logging.getLogger(__name__)
_log.addHandler(stdout_stream)
_log.setLevel(logging.DEBUG)


# ------------------------------------------------------------------ #
# Reusable DNP3 outstation
# ------------------------------------------------------------------ #

class ExperimentOutstation(opendnp3.IOutstationApplication):
    """
        Configurable DNP3 outstation (TCP server) for the experiment harness.

        Preserves the structure of the original ``OutstationApplication`` but
        parameterizes the database size and the number of analog / binary /
        counter points so the response size can be scaled up to study DNP3 frame
        and TCP segmentation behavior.

        Two safety-relevant defaults differ from the original on purpose:
          * ``allow_unsolicited`` defaults to False so baseline captures contain
            only solicited READ/RESPONSE traffic (no background events).
          * ``allow_controls`` defaults to False; the command handler returns
            NOT_SUPPORTED for Select/Operate unless controls are explicitly
            enabled. Baseline experiments are READ-only.
    """

    outstation = None

    def __init__(self,
                 host='0.0.0.0',
                 port=20000,
                 local_addr=10,
                 remote_addr=1,
                 db_size=10,
                 num_analog=2,
                 num_binary=2,
                 num_counter=0,
                 pad_analog=0,
                 pad_binary=0,
                 pad_counter=0,
                 allow_unsolicited=False,
                 allow_controls=False,
                 log_handler=None,
                 listener=None):
        """
            Build and enable a configurable outstation.

        :param host: local interface address to bind the TCP server.
        :param port: TCP port (DNP3 default 20000).
        :param local_addr: DNP3 link-layer address of this outstation.
        :param remote_addr: DNP3 link-layer address of the master.
        :param db_size: AllTypes database size (per type). Must be >= the largest
                        of num_analog / num_binary / num_counter.
        :param num_analog: number of analog input points to configure.
        :param num_binary: number of binary input points to configure.
        :param num_counter: number of counter points to configure.
        :param allow_unsolicited: enable unsolicited responses (default False for
                                  clean baseline captures).
        :param allow_controls: accept Select/Operate controls (default False so
                               the command handler returns NOT_SUPPORTED).
        :param log_handler: openpal.ILogHandler; defaults to ConsoleLogger.
        :param listener: asiodnp3.IChannelListener; defaults to a debug listener.
        """
        super(ExperimentOutstation, self).__init__()

        # Response-size padding (obfuscation): pad_* are real, valid Class0 input
        # points added ON TOP of the function points to normalize the on-wire
        # response size. They report deterministic values like any other point but
        # represent no physical I/O -- a byte-legitimate size pad (OpenDNP3 builds
        # the larger response and its CRCs natively; no forged bytes, no field edit).
        self.real_analog, self.real_binary, self.real_counter = num_analog, num_binary, num_counter
        self.pad_analog, self.pad_binary, self.pad_counter = pad_analog, pad_binary, pad_counter
        num_analog = num_analog + pad_analog
        num_binary = num_binary + pad_binary
        num_counter = num_counter + pad_counter

        max_points = max(num_analog, num_binary, num_counter)
        if max_points > db_size:
            _log.warning('Requested %s points exceeds db_size=%s; raising db_size to %s.',
                         max_points, db_size, max_points)
            db_size = max_points

        self.host = host
        self.port = port
        self.local_addr = local_addr
        self.remote_addr = remote_addr
        self.db_size = db_size
        self.num_analog = num_analog
        self.num_binary = num_binary
        self.num_counter = num_counter
        self.allow_unsolicited = allow_unsolicited
        self.allow_controls = allow_controls

        if (pad_analog or pad_binary or pad_counter):
            _log.info('Response-size padding ON: analog %s(+%s) binary %s(+%s) counter %s(+%s) '
                      '-> totals a=%s b=%s c=%s.',
                      self.real_analog, pad_analog, self.real_binary, pad_binary,
                      self.real_counter, pad_counter, num_analog, num_binary, num_counter)

        _log.debug('Configuring the DNP3 stack (db_size=%s, analog=%s, binary=%s, counter=%s, '
                   'unsolicited=%s).', db_size, num_analog, num_binary, num_counter, allow_unsolicited)
        self.stack_config = self.configure_stack()

        _log.debug('Configuring the outstation database.')
        self.configure_database(self.stack_config.dbConfig)

        _log.debug('Creating a DNP3Manager.')
        self.log_handler = log_handler or asiodnp3.ConsoleLogger().Create()
        self.manager = asiodnp3.DNP3Manager(1, self.log_handler)

        _log.debug('Creating the DNP3 channel, a TCP server on %s:%s.', host, port)
        self.retry_parameters = asiopal.ChannelRetry().Default()
        self.listener = listener or OutstationChannelListener()
        self.channel = self.manager.AddTCPServer("server",
                                                 LOG_LEVELS,
                                                 self.retry_parameters,
                                                 self.host,
                                                 self.port,
                                                 self.listener)

        _log.debug('Adding the outstation to the channel (allow_controls=%s).',
                   allow_controls)
        self.command_handler = ExperimentCommandHandler(allow_controls=allow_controls)
        self.outstation = self.channel.AddOutstation("outstation",
                                                     self.command_handler,
                                                     self,
                                                     self.stack_config)

        # Keep the singleton reference like the original code so updates can be
        # applied from helper methods / external callers.
        ExperimentOutstation.set_outstation(self.outstation)

        _log.debug('Enabling the outstation. Traffic will now start to flow.')
        self.outstation.Enable()

    def configure_stack(self):
        """Build the OutstationStackConfig with the configured sizes and safety flags.

        Uses PER-TYPE DatabaseSizes so a Class-0 integrity poll returns EXACTLY the
        configured points (num_* incl. any size padding) and no stray default slots.
        (AllTypes(N) would allocate N of every type and return all of them, making the
        response size a function of db_size rather than the configured point counts --
        which defeats precise size control / padding.)
        """
        db_sizes = opendnp3.DatabaseSizes(
            self.num_binary,   # numBinary
            0,                 # numDoubleBinary
            self.num_analog,   # numAnalog
            self.num_counter,  # numCounter
            0, 0, 0, 0)        # frozenCounter, binaryOutStatus, analogOutStatus, timeAndInterval
        stack_config = asiodnp3.OutstationStackConfig(db_sizes)
        stack_config.outstation.eventBufferConfig = opendnp3.EventBufferConfig().AllTypes(
            max(self.num_analog, self.num_binary, self.num_counter, 1))
        # Safety default: unsolicited OFF unless explicitly requested.
        stack_config.outstation.params.allowUnsolicited = self.allow_unsolicited
        stack_config.link.LocalAddr = self.local_addr
        stack_config.link.RemoteAddr = self.remote_addr
        stack_config.link.KeepAliveTimeout = openpal.TimeDuration().Max()
        return stack_config

    def configure_database(self, db_config):
        """
            Configure analog / binary / counter input points in loops.

            Points are Class0 so a Class 0 integrity poll returns them as static
            data. Variations match the original example where applicable.
        """
        for index in range(self.num_analog):
            db_config.analog[index].clazz = opendnp3.PointClass.Class0
            db_config.analog[index].svariation = opendnp3.StaticAnalogVariation.Group30Var1
            db_config.analog[index].evariation = opendnp3.EventAnalogVariation.Group32Var7

        for index in range(self.num_binary):
            db_config.binary[index].clazz = opendnp3.PointClass.Class0
            db_config.binary[index].svariation = opendnp3.StaticBinaryVariation.Group1Var2
            db_config.binary[index].evariation = opendnp3.EventBinaryVariation.Group2Var2

        for index in range(self.num_counter):
            db_config.counter[index].clazz = opendnp3.PointClass.Class0
            db_config.counter[index].svariation = opendnp3.StaticCounterVariation.Group20Var1
            db_config.counter[index].evariation = opendnp3.EventCounterVariation.Group22Var1

    # ------------------------------------------------------------------ #
    # Measurement update helpers
    # ------------------------------------------------------------------ #

    def apply_update(self, value, index):
        """
            Record one opendnp3 measurement value in the database (side-effect:
            the value becomes available to the master and may generate an event).

        :param value: an opendnp3 measurement (Analog, Binary, Counter, ...).
        :param index: database index of the point.
        """
        _log.debug('Recording %s measurement, index=%s, value=%s',
                   type(value).__name__, index, value.value)
        builder = asiodnp3.UpdateBuilder()
        builder.Update(value, index)
        update = builder.Build()
        ExperimentOutstation.get_outstation().Apply(update)

    def apply_initial_values(self):
        """
            Apply deterministic initial values to every configured point.

            analog[i]  = 100.0 + i
            binary[i]  = True if i is even else False
            counter[i] = i
        """
        _log.info('Applying initial values (analog=%s, binary=%s, counter=%s).',
                  self.num_analog, self.num_binary, self.num_counter)
        for index in range(self.num_analog):
            self.apply_update(opendnp3.Analog(100.0 + index), index)
        for index in range(self.num_binary):
            self.apply_update(opendnp3.Binary(index % 2 == 0), index)
        for index in range(self.num_counter):
            self.apply_update(opendnp3.Counter(index), index)

    def apply_bulk_updates(self):
        """
            Push the deterministic values for every point in a single batch.

            Uses one UpdateBuilder so all points are applied together. Useful to
            force a large static dataset / many events for segmentation tests.
        """
        _log.info('Applying bulk updates for all configured points.')
        builder = asiodnp3.UpdateBuilder()
        for index in range(self.num_analog):
            builder.Update(opendnp3.Analog(100.0 + index), index)
        for index in range(self.num_binary):
            builder.Update(opendnp3.Binary(index % 2 == 0), index)
        for index in range(self.num_counter):
            builder.Update(opendnp3.Counter(index), index)
        ExperimentOutstation.get_outstation().Apply(builder.Build())

    def shutdown(self):
        """Execute an orderly shutdown of the outstation manager."""
        _log.debug('Shutting down outstation.')
        self.manager.Shutdown()

    @classmethod
    def get_outstation(cls):
        """Return the singleton IOutstation instance."""
        return cls.outstation

    @classmethod
    def set_outstation(cls, outstn):
        """Store the singleton IOutstation instance returned by AddOutstation."""
        cls.outstation = outstn

    # ------------------------------------------------------------------ #
    # IOutstationApplication overrides (mirror the original defaults)
    # ------------------------------------------------------------------ #

    def ColdRestartSupport(self):
        _log.debug('In ExperimentOutstation.ColdRestartSupport')
        return opendnp3.RestartMode.UNSUPPORTED

    def GetApplicationIIN(self):
        application_iin = opendnp3.ApplicationIIN()
        application_iin.configCorrupt = False
        application_iin.deviceTrouble = False
        application_iin.localControl = False
        application_iin.needTime = False
        return application_iin

    def SupportsAssignClass(self):
        _log.debug('In ExperimentOutstation.SupportsAssignClass')
        return False

    def SupportsWriteAbsoluteTime(self):
        _log.debug('In ExperimentOutstation.SupportsWriteAbsoluteTime')
        return False

    def SupportsWriteTimeAndInterval(self):
        _log.debug('In ExperimentOutstation.SupportsWriteTimeAndInterval')
        return False

    def WarmRestartSupport(self):
        _log.debug('In ExperimentOutstation.WarmRestartSupport')
        return opendnp3.RestartMode.UNSUPPORTED


class ExperimentCommandHandler(opendnp3.ICommandHandler):
    """
        Command handler that rejects controls by default.

        For baseline READ experiments ``allow_controls`` is False and both
        Select and Operate return ``CommandStatus.NOT_SUPPORTED``. When
        ``allow_controls`` is True it logs the request and returns SUCCESS,
        matching the permissive behavior of the original code (manual testing
        only).
    """

    def __init__(self, allow_controls=False):
        super(ExperimentCommandHandler, self).__init__()
        self.allow_controls = allow_controls

    def Start(self):
        _log.debug('In ExperimentCommandHandler.Start')

    def End(self):
        _log.debug('In ExperimentCommandHandler.End')

    def Select(self, command, index):
        """Handle a Select. Returns NOT_SUPPORTED unless controls are allowed."""
        if not self.allow_controls:
            _log.warning('Select rejected (controls disabled) index=%s: %s', index, command)
            return opendnp3.CommandStatus.NOT_SUPPORTED
        _log.warning('Select accepted (controls ENABLED) index=%s: %s', index, command)
        return opendnp3.CommandStatus.SUCCESS

    def Operate(self, command, index, op_type):
        """Handle an Operate. Returns NOT_SUPPORTED unless controls are allowed."""
        if not self.allow_controls:
            _log.warning('Operate rejected (controls disabled) index=%s: %s', index, command)
            return opendnp3.CommandStatus.NOT_SUPPORTED
        _log.warning('Operate accepted (controls ENABLED) index=%s: %s', index, command)
        return opendnp3.CommandStatus.SUCCESS


class OutstationChannelListener(asiodnp3.IChannelListener):
    """Application-specific channel listener mirroring the original ``AppChannelListener``."""

    def __init__(self):
        super(OutstationChannelListener, self).__init__()

    def OnStateChange(self, state):
        _log.debug('In OutstationChannelListener.OnStateChange: state={}'.format(state))


class OutstationLogHandler(openpal.ILogHandler):
    """Application-specific log handler mirroring the original ``MyLogger``."""

    def __init__(self):
        super(OutstationLogHandler, self).__init__()

    def Log(self, entry):
        filters = entry.filters.GetBitfield()
        location = entry.location.rsplit('/')[-1] if entry.location else ''
        message = entry.message
        _log.debug('Log\tfilters={}\tlocation={}\tentry={}'.format(filters, location, message))


# ------------------------------------------------------------------ #
# Command-line entry point (defaults sourced from the inline lab config above)
# ------------------------------------------------------------------ #

def build_parser():
    """Build the argument parser; every default comes from the inline lab config."""
    parser = argparse.ArgumentParser(
        description='Self-contained DNP3 outstation for READ/RESPONSE segmentation experiments.')
    parser.add_argument('--host', default=BIND_IP,
                        help='Local interface address to bind the TCP server.')
    parser.add_argument('--port', type=int, default=DNP3_PORT, help='TCP port (DNP3 default 20000).')
    parser.add_argument('--local-addr', type=int, default=OUTSTATION_LINK_ADDR,
                        help='DNP3 link-layer address of this outstation.')
    parser.add_argument('--remote-addr', type=int, default=MASTER_LINK_ADDR,
                        help='DNP3 link-layer address of the master.')
    parser.add_argument('--db-size', type=int, default=DEFAULT_DB_SIZE,
                        help='AllTypes database size per type.')
    parser.add_argument('--num-analog', type=int, default=DEFAULT_NUM_ANALOG,
                        help='Number of analog input points.')
    parser.add_argument('--num-binary', type=int, default=DEFAULT_NUM_BINARY,
                        help='Number of binary input points.')
    parser.add_argument('--num-counter', type=int, default=DEFAULT_NUM_COUNTER,
                        help='Number of counter points.')
    parser.add_argument('--pad-analog', type=int, default=0,
                        help='Response-size padding: extra inert analog input points (Group30Var1, '
                             '~5 B each) added on top of --num-analog to normalize response size.')
    parser.add_argument('--pad-binary', type=int, default=0,
                        help='Response-size padding: extra inert binary input points (Group1Var2, '
                             '~1 B each, finest granularity) added on top of --num-binary.')
    parser.add_argument('--pad-counter', type=int, default=0,
                        help='Response-size padding: extra inert counter points (Group20Var1, ~5 B each).')
    parser.add_argument('--allow-unsolicited', action='store_true',
                        help='Enable unsolicited responses (OFF by default for clean captures).')
    parser.add_argument('--allow-controls', action='store_true',
                        help='Accept Select/Operate controls (OFF by default; baseline is READ-only).')
    # Default behaviour for a no-arg run is: apply initial values, then hold.
    parser.add_argument('--apply-initial-values', dest='apply_initial_values',
                        action='store_true', default=True,
                        help='Apply deterministic initial values to all points (default ON).')
    parser.add_argument('--no-apply-initial-values', dest='apply_initial_values',
                        action='store_false',
                        help='Skip applying initial values.')
    parser.add_argument('--hold', dest='hold', action='store_true', default=True,
                        help='Keep the outstation running until Ctrl+C (default ON).')
    parser.add_argument('--no-hold', dest='hold', action='store_false',
                        help='Shut down immediately after setup instead of holding.')
    parser.add_argument('--log-dir', default=os.path.join(LOG_DIR, 'outstation'),
                        help='Directory for a per-run outstation log file.')
    return parser


def _hard_exit(code=0):
    """
        Flush logs and terminate via os._exit.

        pydnp3 can double-free its C++ objects during interpreter teardown even
        after a clean DNP3Manager shutdown. Hard-exiting after the orderly
        shutdown avoids the resulting abort (exit 134).
    """
    for handler in logging.getLogger().handlers + _log.handlers:
        try:
            handler.flush()
        except Exception:
            pass
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(code)


def _configure_file_logging(log_dir):
    """Add a timestamped file handler under ``log_dir`` for this run, if given."""
    if not log_dir:
        return
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, 'experiment_outstation_{}.log'.format(int(time.time())))
    file_handler = logging.FileHandler(log_path)
    file_handler.setFormatter(logging.Formatter('%(asctime)s\t%(name)s\t%(levelname)s\t%(message)s'))
    logging.getLogger().addHandler(file_handler)
    logging.getLogger().setLevel(logging.DEBUG)
    _log.info('Writing outstation log to %s', log_path)


def main():
    args = build_parser().parse_args()
    # Anchor a relative log dir to the harness directory (run from anywhere).
    log_dir = args.log_dir if os.path.isabs(args.log_dir) else os.path.join(HARNESS_DIR, args.log_dir)
    _configure_file_logging(log_dir)

    if args.allow_unsolicited:
        _log.warning('Unsolicited responses ENABLED; baseline captures will not be clean.')
    if args.allow_controls:
        _log.warning('Controls ENABLED; outstation will accept Select/Operate. Not for baseline.')

    _log.info('Starting outstation on %s:%s (db_size=%s analog=%s binary=%s counter=%s) -- '
              'settings from lab_config.py.',
              args.host, args.port, args.db_size, args.num_analog, args.num_binary, args.num_counter)
    app = ExperimentOutstation(host=args.host,
                               port=args.port,
                               local_addr=args.local_addr,
                               remote_addr=args.remote_addr,
                               db_size=args.db_size,
                               num_analog=args.num_analog,
                               num_binary=args.num_binary,
                               num_counter=args.num_counter,
                               pad_analog=args.pad_analog,
                               pad_binary=args.pad_binary,
                               pad_counter=args.pad_counter,
                               allow_unsolicited=args.allow_unsolicited,
                               allow_controls=args.allow_controls)

    if args.apply_initial_values:
        app.apply_initial_values()

    try:
        if args.hold:
            _log.info('Outstation running. Press Ctrl+C to shut down.')
            while True:
                time.sleep(1)
        else:
            _log.info('No hold requested; shutting down immediately after setup.')
    except KeyboardInterrupt:
        _log.info('Ctrl+C received; shutting down.')
    finally:
        app.shutdown()
        _log.info('Outstation shut down. Exiting.')
    # Hard-exit to avoid pydnp3's double-free during interpreter teardown.
    _hard_exit(0)


if __name__ == '__main__':
    main()

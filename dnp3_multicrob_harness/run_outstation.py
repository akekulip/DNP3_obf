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

Where a CROB CommandStatus comes from (multi-CROB ``--control-test`` mode):
OpenDNP3's protocol stack does NOT natively validate a Group 12 Var 1 control
index against the configured database. Verified empirically against this build:
with a pass-through command handler (``SuccessCommandHandler``) and a database
sized to K binary-output points, a SELECT/OPERATE to index K (out of range) is
delivered to the application handler and returns SUCCESS on the wire. The stack
cannot infer whether an application-level control point exists; per IEEE 1815 the
``ICommandHandler.Select()/Operate()`` return value is the CommandStatus. This
harness therefore places the control-point data model in a dedicated
``ControlPointBackend`` (the outstation application), which returns the native
``opendnp3.CommandStatus`` for each requested index. The status is produced by the
application backend -- it is neither manufactured by the experiment/test code nor
decided by the DNP3 stack. Software-only: no index maps to a physical device.
"""

import argparse
import json
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
                 allow_unsolicited=False,
                 allow_controls=False,
                 control_test=False,
                 control_point_count=2,        # CLI default from DEFAULT_CONTROL_POINT_COUNT
                 select_timeout_sec=5.0,       # CLI default from DEFAULT_SELECT_TIMEOUT_SEC
                 run_id=None,
                 control_json_path=None,
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
        :param control_test: enable the software-only multi-CROB Select-Before-
                             Operate experiment. Swaps in ControlTestCommandHandler
                             backed by ``control_point_count`` simulated binary output
                             points (indexes 0..N-1). Software-only; no physical device.
        :param control_point_count: N simulated control points (indexes 0..N-1) when
                             control_test is on; initial state alternates even=False/odd=True.
        :param select_timeout_sec: monotonic SELECT lifetime; an OPERATE after expiry
                             returns NO_SELECT.
        :param run_id: opaque run identifier recorded in the JSON evidence.
        :param control_json_path: where to write the outstation JSON evidence after the
                             OPERATE batch (None -> log it only).
        :param log_handler: openpal.ILogHandler; defaults to ConsoleLogger.
        :param listener: asiodnp3.IChannelListener; defaults to a debug listener.
        """
        super(ExperimentOutstation, self).__init__()

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
        self.control_test = control_test
        self.control_point_count = int(control_point_count)
        self.select_timeout_sec = float(select_timeout_sec)
        self.run_id = run_id
        self.control_json_path = control_json_path
        self.control_state = None

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

        _log.debug('Adding the outstation to the channel (allow_controls=%s, control_test=%s).',
                   allow_controls, control_test)
        if control_test:
            # Software-only multi-CROB Select-Before-Operate experiment: swap in a
            # command handler backed by N simulated binary output points (indexes
            # 0..N-1). Normal outstation behavior (controls rejected) is unchanged
            # without the flag.
            self.control_state = ControlTestState(control_point_count=self.control_point_count,
                                                  select_timeout_sec=self.select_timeout_sec)
            self.command_handler = ControlTestCommandHandler(self.control_state,
                                                             run_id=self.run_id,
                                                             json_path=self.control_json_path)
        else:
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

        if self.control_test:
            backend = self.control_state.backend
            _log.info('CONTROL-TEST mode ENABLED: %s SOFTWARE-ONLY simulated binary output '
                      'point(s) (no physical device is operated).', backend.control_point_count)
            _log.info('CONTROL-TEST configured control indexes: %s (codes %s).',
                      list(backend.configured_indexes), list(backend.supported_codes))
            _log.info('CONTROL-TEST command-status source: %s. OpenDNP3 does NOT validate a CROB '
                      'index natively; the returned CommandStatus (incl. OUT_OF_RANGE for a '
                      'nonexistent index) is decided by the outstation application backend, not by '
                      'the DNP3 stack and not assumed by the test code.', backend.describe())
            _log.info('%s', self.control_state.state_block())

    def configure_stack(self):
        """Build the OutstationStackConfig with the configured sizes and safety flags."""
        stack_config = asiodnp3.OutstationStackConfig(opendnp3.DatabaseSizes.AllTypes(self.db_size))
        stack_config.outstation.eventBufferConfig = opendnp3.EventBufferConfig().AllTypes(self.db_size)
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


# ------------------------------------------------------------------ #
# Multi-CROB Select-Before-Operate control-test (software-only)
# ------------------------------------------------------------------ #

# The two simulated binary output/control points and their initial state. These
# are in-memory ONLY -- no index is mapped to any physical GPIO, relay, breaker,
# PLC, or external device.
CONTROL_TEST_SUPPORTED_CODES = ('LATCH_ON', 'LATCH_OFF')
DEFAULT_CONTROL_POINT_COUNT = 2
DEFAULT_SELECT_TIMEOUT_SEC = 5.0

# Application-level encoding of the two invalid-request outcomes, made explicit and
# single-source here so the choice is attributable, not buried in a conditional.
#
# STANDARDS NOTE (IEEE 1815-2012, reviewed 2026-07-14): the strictly standard-aligned
# CommandStatus for a control addressed to a *nonexistent* output point is
# NOT_SUPPORTED (4) -- "control operation not supported for this point" -- and the
# response should also set IIN2.2 (PARAMETER_ERROR). OUT_OF_RANGE (12) is defined over
# the requested VALUE ("value outside the range permitted for this point") and
# presupposes the point exists, so it is not the protocol-native code for a missing
# index. This harness deliberately RETAINS OUT_OF_RANGE (12) for a nonexistent index to
# stay byte-comparable with the prior (week8) rig captures; it is therefore an explicit
# APPLICATION mapping choice, not a protocol mandate. Change the constant below (and
# re-baseline) to switch to the standard-aligned NOT_SUPPORTED. Either way the decision
# is the outstation application's, returned as a native opendnp3.CommandStatus.
NONEXISTENT_INDEX_COMMAND_STATUS = opendnp3.CommandStatus.OUT_OF_RANGE
UNSUPPORTED_CODE_COMMAND_STATUS = opendnp3.CommandStatus.NOT_SUPPORTED


def build_alternating_state(n):
    """Initial simulated state for N points: even index = False, odd index = True."""
    return {i: bool(i % 2) for i in range(n)}


def expected_operated_state(n):
    """Expected final state after the standard plan (even -> LATCH_ON = True, odd -> LATCH_OFF = False)."""
    return {i: (i % 2 == 0) for i in range(n)}


class ControlPointBackend(object):
    """
        Outstation application control-point data model -- the AUTHORITY for the
        CROB command status.

        OpenDNP3's protocol stack does not validate a Group 12 Var 1 output index
        against the configured database (verified empirically: a pass-through
        command handler returns SUCCESS on the wire for an out-of-range index). The
        stack cannot infer whether an application-level control point exists, so per
        IEEE 1815 the ``ICommandHandler`` return value is the CommandStatus. This
        backend is that application authority: it models which binary-output control
        points the outstation actually has (indexes ``0..count-1``) and which control
        codes it accepts, and returns the NATIVE ``opendnp3.CommandStatus`` for a
        requested ``(index, control_code)``, via the single-source encoding constants
        ``NONEXISTENT_INDEX_COMMAND_STATUS`` / ``UNSUPPORTED_CODE_COMMAND_STATUS``:

          * index outside ``0..count-1``  -> NONEXISTENT_INDEX_COMMAND_STATUS
                                             (this harness: OUT_OF_RANGE -- see note)
          * unsupported control code       -> UNSUPPORTED_CODE_COMMAND_STATUS (NOT_SUPPORTED)
          * otherwise                      -> ``opendnp3.CommandStatus.SUCCESS``

        The status is decided HERE, in the outstation application, and returned as an
        ``opendnp3.CommandStatus`` value -- it is not manufactured or assumed by the
        experiment/test code, and it is not decided by the DNP3 protocol stack (the
        stack validates only message SYNTAX; point existence is an application property
        of the device's control-point data model).

        STANDARDS NOTE: per IEEE 1815-2012 the protocol-native code for a *nonexistent*
        point is NOT_SUPPORTED (4), not OUT_OF_RANGE (12) -- OUT_OF_RANGE is value-scoped
        and assumes the point exists. This harness retains OUT_OF_RANGE for continuity
        with prior rig captures as an explicit application mapping choice (see the module
        constant). Software-only: no index maps to a physical device.
    """

    def __init__(self, control_point_count, supported_codes=CONTROL_TEST_SUPPORTED_CODES):
        if int(control_point_count) < 1:
            raise ValueError('control_point_count must be >= 1, got {}'.format(control_point_count))
        self.control_point_count = int(control_point_count)
        self.supported_codes = tuple(supported_codes)

    @property
    def configured_indexes(self):
        """Tuple of the control-point indexes this outstation application has."""
        return tuple(range(self.control_point_count))

    def has_point(self, index):
        """True iff the outstation application has a control point at ``index``."""
        return 0 <= index < self.control_point_count

    def supports_code(self, control_code):
        """True iff the outstation application accepts ``control_code``."""
        return control_code in self.supported_codes

    def command_status(self, index, control_code):
        """Return the native ``opendnp3.CommandStatus`` for one CROB request.

        This is the outstation application's decision, not the DNP3 stack's and not
        the test harness's: a nonexistent index yields OUT_OF_RANGE, an unsupported
        code yields NOT_SUPPORTED, and a configured (index, code) yields SUCCESS.
        """
        if not self.has_point(index):
            return NONEXISTENT_INDEX_COMMAND_STATUS
        if not self.supports_code(control_code):
            return UNSUPPORTED_CODE_COMMAND_STATUS
        return opendnp3.CommandStatus.SUCCESS

    @staticmethod
    def status_name(status):
        """Readable name of an ``opendnp3.CommandStatus`` (e.g. 'OUT_OF_RANGE')."""
        return opendnp3.CommandStatusToString(status)

    def describe(self):
        """One-line description of the configured control-point model + status source."""
        return ('control-point backend: {} configured binary-output point(s), indexes '
                '{}..{}, codes {}; command status decided by the outstation application '
                '(OpenDNP3 does not validate control indexes natively)'.format(
                    self.control_point_count, 0, self.control_point_count - 1,
                    list(self.supported_codes)))


class ControlTestState(object):
    """
        In-memory Select-Before-Operate lifecycle for the ``--control-test`` multi-CROB
        experiment, over the outstation application's configured control points.

        Point existence / control-code support is NOT decided here: that is the job of
        the ``ControlPointBackend`` (the outstation application data model), which
        returns the native ``opendnp3.CommandStatus``. This class owns only the SBO
        lifecycle for a requested (index, code): recording a SELECT, enforcing the
        selection timeout and SELECT/OPERATE parameter match, consuming a pending
        SELECT on OPERATE, and flipping the simulated output. It therefore never
        manufactures OUT_OF_RANGE/NOT_SUPPORTED -- it delegates that to the backend and
        merely reports whatever status the backend produced. SOFTWARE-ONLY: an index is
        never mapped to a physical device.

        A CROB (Control Relay Output Block, DNP3 Group 12 Variation 1) carries an
        output point index and a control code (here LATCH_ON / LATCH_OFF). SELECT
        validates (via the backend) and records the request; OPERATE applies it only if
        a matching, unexpired SELECT is still pending.
    """

    def __init__(self, control_point_count=DEFAULT_CONTROL_POINT_COUNT,
                 supported_codes=CONTROL_TEST_SUPPORTED_CODES,
                 select_timeout_sec=DEFAULT_SELECT_TIMEOUT_SEC,
                 monotonic=None,
                 backend=None):
        # The control-point backend is the authority for index existence + code
        # support and returns the native opendnp3.CommandStatus. Injectable for tests.
        self.backend = backend or ControlPointBackend(control_point_count, supported_codes)
        self.control_point_count = self.backend.control_point_count
        self.supported_codes = self.backend.supported_codes
        self.select_timeout_sec = float(select_timeout_sec)
        # injectable clock for tests; monotonic so it is immune to wall-clock jumps
        self._now = monotonic or time.monotonic
        self._initial_state = build_alternating_state(self.control_point_count)
        # index -> current simulated output state (bool)
        self.simulated_output_state = dict(self._initial_state)
        # index -> dict(control_code, count, on_ms, off_ms, selected_at) recorded at SELECT
        self.selected_commands = {}

    def reset(self):
        """Restore the initial simulated state and drop any pending selections."""
        self.simulated_output_state = dict(self._initial_state)
        self.selected_commands = {}

    def _validate(self, index, control_code):
        """Return (opendnp3.CommandStatus, reason) for one CROB, delegating the
        existence/support decision to the control-point backend. This state object no
        longer decides OUT_OF_RANGE/NOT_SUPPORTED itself -- it reports the backend's
        native status."""
        status = self.backend.command_status(index, control_code)
        if status == opendnp3.CommandStatus.SUCCESS:
            return status, None
        if not self.backend.has_point(index):
            reason = 'index {} is not a configured control point (backend indexes {})'.format(
                index, list(self.backend.configured_indexes))
        else:
            reason = 'control code {} not accepted by backend {}'.format(
                control_code, list(self.backend.supported_codes))
        return status, reason

    def select(self, index, control_code, count, on_ms, off_ms):
        """
            Validate (via the backend) and record a SELECT for one CROB. Does NOT
            change output state.

            Returns (status, reason) where ``status`` is a native
            ``opendnp3.CommandStatus`` produced by the control-point backend: SUCCESS
            for a configured (index, code) -- the selection is recorded, stamped with a
            monotonic time so a later OPERATE can enforce the selection timeout -- else
            the backend's OUT_OF_RANGE / NOT_SUPPORTED.
        """
        status, reason = self._validate(index, control_code)
        if status != opendnp3.CommandStatus.SUCCESS:
            return status, reason
        self.selected_commands[index] = {
            'control_code': control_code,
            'count': count,
            'on_ms': on_ms,
            'off_ms': off_ms,
            'selected_at': self._now(),
        }
        return status, None

    def discard_selections(self, indexes):
        """Drop pending selections for the given indexes; return the ones actually dropped.

        Used to abandon a whole SELECT batch when any object in it failed, so a
        partially-failed SELECT never leaves valid controls armed.
        """
        return [i for i in indexes if self.selected_commands.pop(i, None) is not None]

    def operate(self, index, control_code, count, on_ms, off_ms):
        """
            Execute an OPERATE for one CROB, requiring a matching, unexpired SELECT.

            A pending selection for the index is CONSUMED (removed) on every operate
            attempt so a stale SELECT cannot be reused. A selection older than
            ``select_timeout_sec`` is rejected with NO_SELECT. On a match the output
            flips (LATCH_ON -> True, LATCH_OFF -> False).

            ``status`` is a native ``opendnp3.CommandStatus``: the backend's
            OUT_OF_RANGE / NOT_SUPPORTED for an invalid point, ``NO_SELECT`` for an SBO
            lifecycle failure, or ``SUCCESS``. Returns a dict: status, reason,
            prev_state, new_state, changed.
        """
        selection = self.selected_commands.pop(index, None)  # consume regardless of outcome
        prev_state = self.simulated_output_state.get(index)

        def rejected(status, reason):
            return {'status': status, 'reason': reason,
                    'prev_state': prev_state, 'new_state': prev_state, 'changed': False}

        status, reason = self._validate(index, control_code)
        if status != opendnp3.CommandStatus.SUCCESS:
            return rejected(status, reason)
        if selection is None:
            return rejected(opendnp3.CommandStatus.NO_SELECT, 'no matching prior SELECT for this index')

        age = self._now() - selection['selected_at']
        if age > self.select_timeout_sec:
            return rejected(opendnp3.CommandStatus.NO_SELECT,
                            'SELECT expired {:.3f}s ago (> {:.1f}s timeout)'.format(
                                age, self.select_timeout_sec))

        requested = {'control_code': control_code, 'count': count, 'on_ms': on_ms, 'off_ms': off_ms}
        selected = {k: selection[k] for k in ('control_code', 'count', 'on_ms', 'off_ms')}
        if selected != requested:
            return rejected(opendnp3.CommandStatus.NO_SELECT,
                            'OPERATE parameters {} differ from SELECT {}'.format(requested, selected))

        new_state = (control_code == 'LATCH_ON')
        self.simulated_output_state[index] = new_state
        return {'status': opendnp3.CommandStatus.SUCCESS, 'reason': None,
                'prev_state': prev_state, 'new_state': new_state, 'changed': new_state != prev_state}

    def pending_selection_count(self):
        """Number of selections still armed (should be 0 after a clean OPERATE batch)."""
        return len(self.selected_commands)

    def final_state_matches_expected(self):
        """True iff the simulated state equals the standard plan's expected result."""
        return self.simulated_output_state == expected_operated_state(self.control_point_count)

    def state_block(self, max_lines=16):
        """Return the readable 'Simulated CROB Output State' block (truncated for large N)."""
        lines = ['Simulated CROB Output State ({} point(s))'.format(self.control_point_count)]
        indexes = sorted(self.simulated_output_state)
        shown = indexes if len(indexes) <= max_lines else indexes[:max_lines]
        for index in shown:
            lines.append('  Index {}: {}'.format(index, self.simulated_output_state[index]))
        if len(indexes) > max_lines:
            lines.append('  ... ({} more; full state in the JSON evidence)'.format(len(indexes) - max_lines))
        return '\n'.join(lines)


class ControlTestCommandHandler(opendnp3.ICommandHandler):
    """
        Command handler for the ``--control-test`` multi-CROB Select-Before-Operate
        experiment. Delegates all matching/state logic to a ``ControlTestState`` and
        maps its status strings to ``opendnp3.CommandStatus`` values.

        Only indexes 0/1 and control codes LATCH_ON/LATCH_OFF are accepted; every
        OPERATE requires a matching prior SELECT. SELECT never changes state;
        OPERATE flips the addressed point and clears the consumed selection. This is
        software-only -- no physical device is ever operated.
    """

    def __init__(self, state, run_id=None, json_path=None):
        super(ControlTestCommandHandler, self).__init__()
        self.state = state
        self.backend = state.backend      # the application authority for command status
        self.run_id = run_id
        self.json_path = json_path
        # No status-string -> CommandStatus map: the status is a native
        # opendnp3.CommandStatus produced by the control-point backend (Select/Operate
        # return it directly). This handler never maps a hardcoded 'OUT_OF_RANGE'.
        # per-transaction evidence, accumulated across the SELECT and OPERATE batches
        self.select_seen = 0
        self.select_success = 0
        self.operate_seen = 0
        self.operate_success = 0
        self.rejected_indexes = []
        # per-batch tracking (reset on each Start; ICommandHandler brackets one
        # control request batch with Start()/End())
        self._batch_kind = None            # 'SELECT' | 'OPERATE' | None
        self._batch_select_indexes = []
        self._batch_select_failed = False

    def _code_name(self, command):
        """Readable control-code name for a CROB (falls back to the raw code)."""
        try:
            return opendnp3.ControlCodeToString(command.functionCode)
        except Exception:
            return 'RAW_0x{:02x}'.format(command.rawCode)

    def _op_type_name(self, op_type):
        """Readable OperateType name if the binding exposes the helper."""
        if hasattr(opendnp3, 'OperateTypeToString'):
            return opendnp3.OperateTypeToString(op_type)
        return str(op_type)

    def Start(self):
        # ICommandHandler.Start()/End() bracket exactly one control request batch.
        _log.debug('In ControlTestCommandHandler.Start (batch begin)')
        self._batch_kind = None
        self._batch_select_indexes = []
        self._batch_select_failed = False

    def End(self):
        kind = self._batch_kind
        _log.info('CONTROL-TEST batch END kind=%s (select_indexes=%s any_fail=%s)',
                  kind, self._batch_select_indexes, self._batch_select_failed)
        # Discard a partially-failed SELECT batch so valid controls are not left armed.
        if kind == 'SELECT' and self._batch_select_failed:
            dropped = self.state.discard_selections(self._batch_select_indexes)
            _log.warning('CONTROL-TEST SELECT batch had a failure; discarding pending selections %s '
                         '(partial SELECT must not leave valid controls armed)', dropped)
        # Record evidence at the end of every SELECT or OPERATE batch. A normal SBO
        # writes after SELECT and then again (authoritatively) after OPERATE. Writing
        # after SELECT also captures runs where no OPERATE follows -- e.g. a stack-level
        # TOO_MANY_OPS rejection when every op the handler actually saw succeeded (no
        # per-index SELECT failure, no OPERATE batch), which would otherwise leave no
        # JSON evidence at all.
        if kind in ('SELECT', 'OPERATE'):
            _log.info('%s', self.state.state_block())
            self._write_evidence()
        self._batch_kind = None

    def Select(self, command, index):
        """Validate (via the control-point backend) + record a SELECT for one CROB.

        The returned CommandStatus is the native ``opendnp3.CommandStatus`` produced by
        the outstation application backend; this handler does not assume or rewrite it.
        """
        self._batch_kind = 'SELECT'
        self.select_seen += 1
        self._batch_select_indexes.append(index)
        code = self._code_name(command)
        status, reason = self.state.select(index, code, command.count,
                                           command.onTimeMS, command.offTimeMS)
        if status == opendnp3.CommandStatus.SUCCESS:
            self.select_success += 1
            _log.info('CONTROL-TEST SELECT  index=%s code=%s count=%s on=%sms off=%sms -> SUCCESS '
                      '(status source: application control-point backend)',
                      index, code, command.count, command.onTimeMS, command.offTimeMS)
        else:
            self._batch_select_failed = True
            if index not in self.rejected_indexes:
                self.rejected_indexes.append(index)
            _log.warning('CONTROL-TEST SELECT  index=%s code=%s -> %s (%s) '
                         '[status source: application control-point backend; OpenDNP3 does not '
                         'validate control indexes natively]',
                         index, code, self.backend.status_name(status), reason)
        return status

    def Operate(self, command, index, op_type):
        """Execute an OPERATE for one CROB, requiring a matching prior SELECT.

        The returned CommandStatus is native ``opendnp3.CommandStatus``: the backend's
        status for an invalid point, else the SBO lifecycle result (SUCCESS/NO_SELECT).
        """
        self._batch_kind = 'OPERATE'
        self.operate_seen += 1
        code = self._code_name(command)
        result = self.state.operate(index, code, command.count,
                                    command.onTimeMS, command.offTimeMS)
        status = result['status']
        if status == opendnp3.CommandStatus.SUCCESS:
            self.operate_success += 1
            _log.info('CONTROL-TEST OPERATE index=%s code=%s prev=%s -> new=%s SUCCESS (op_type=%s)',
                      index, code, result['prev_state'], result['new_state'], self._op_type_name(op_type))
        else:
            if index not in self.rejected_indexes:
                self.rejected_indexes.append(index)
            _log.warning('CONTROL-TEST OPERATE index=%s code=%s REJECTED status=%s (%s) '
                         '[status source: application control-point backend / SBO lifecycle]',
                         index, code, self.backend.status_name(status), result['reason'])
        return status

    def _write_evidence(self):
        """Write one JSON evidence file after the OPERATE batch (authoritative per-index)."""
        evidence = {
            'run_id': self.run_id,
            'requested_n': self.state.control_point_count,
            'select_seen': self.select_seen,
            'select_success': self.select_success,
            'operate_seen': self.operate_seen,
            'operate_success': self.operate_success,
            'rejected_indexes': sorted(set(self.rejected_indexes)),
            'pending_selection_count': self.state.pending_selection_count(),
            'final_state_matches_expected': self.state.final_state_matches_expected(),
            'final_state': {str(k): v for k, v in sorted(self.state.simulated_output_state.items())},
        }
        if not self.json_path:
            _log.info('CONTROL-TEST evidence (no --run-id/json path set): %s', json.dumps(evidence))
            return
        try:
            os.makedirs(os.path.dirname(os.path.abspath(self.json_path)), exist_ok=True)
            with open(self.json_path, 'w') as fh:
                json.dump(evidence, fh, indent=2)
                fh.write('\n')
            _log.info('Wrote outstation multi-CROB evidence -> %s', self.json_path)
        except OSError as exc:
            _log.error('Could not write evidence JSON %s: %r', self.json_path, exc)


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
    parser.add_argument('--allow-unsolicited', action='store_true',
                        help='Enable unsolicited responses (OFF by default for clean captures).')
    parser.add_argument('--allow-controls', action='store_true',
                        help='Accept Select/Operate controls (OFF by default; baseline is READ-only).')
    parser.add_argument('--control-test', dest='control_test', action='store_true',
                        help='Enable the software-only multi-CROB Select-Before-Operate experiment: '
                             'N simulated binary output points (indexes 0..N-1, initial state '
                             'even=False/odd=True), accepting LATCH_ON/LATCH_OFF via SELECT then '
                             'OPERATE. No physical device is operated. Normal outstation behavior '
                             'is unchanged without this flag.')
    parser.add_argument('--control-point-count', dest='control_point_count', type=int,
                        default=DEFAULT_CONTROL_POINT_COUNT,
                        help='Number of simulated control points N for --control-test (indexes '
                             '0..N-1; default %(default)s). Must be >= 1.')
    parser.add_argument('--select-timeout-sec', dest='select_timeout_sec', type=float,
                        default=DEFAULT_SELECT_TIMEOUT_SEC,
                        help='Selection lifetime in seconds; an OPERATE after expiry returns '
                             'NO_SELECT (default %(default)s).')
    parser.add_argument('--run-id', dest='run_id', default=None,
                        help='Opaque run identifier recorded in the JSON evidence; also names the '
                             'default evidence file logs/outstation/multicrob_<run-id>.json.')
    parser.add_argument('--control-json', dest='control_json', default=None,
                        help='Explicit path for the outstation JSON evidence (overrides the '
                             '--run-id-derived default).')
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
    control_json = None
    if args.control_test:
        if args.control_point_count < 1:
            _log.error('--control-point-count must be >= 1, got %s.', args.control_point_count)
            _hard_exit(2)
        control_json = args.control_json
        if control_json is None and args.run_id:
            control_json = os.path.join(HARNESS_DIR, 'logs', 'outstation',
                                        'multicrob_{}.json'.format(args.run_id))
        elif control_json is not None and not os.path.isabs(control_json):
            control_json = os.path.join(HARNESS_DIR, control_json)
        _log.warning('CONTROL-TEST ENABLED; outstation runs the software-only multi-CROB '
                     'Select-Before-Operate experiment (N=%s simulated points, indexes 0..%s, '
                     'select-timeout=%ss, no physical device).',
                     args.control_point_count, args.control_point_count - 1, args.select_timeout_sec)

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
                               allow_unsolicited=args.allow_unsolicited,
                               allow_controls=args.allow_controls,
                               control_test=args.control_test,
                               control_point_count=args.control_point_count,
                               select_timeout_sec=args.select_timeout_sec,
                               run_id=args.run_id,
                               control_json_path=control_json)

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
